//! Organizations: `/api/v1/organizations` and the read-only administrator view.

mod common;

use axum::http::StatusCode;
use common::{PASSWORD, TestApp, access_token, grant_admin_role, user_id};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// Registers an account and returns (its id, an access token).
async fn account(app: &TestApp, email: &str) -> (Uuid, String) {
    let (status, user) = app.register(email, PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED, "{user}");

    let (status, session) = app.login(email, PASSWORD).await;
    assert_eq!(status, StatusCode::OK);

    (user_id(&user), access_token(&session))
}

/// Registers an account, grants it the instance administrator role, and signs it in.
async fn administrator(app: &TestApp, pool: &PgPool, email: &str) -> String {
    let (id, _) = account(app, email).await;
    grant_admin_role(pool, id).await;

    let (_, session) = app.login(email, PASSWORD).await;
    access_token(&session)
}

async fn create_organization(app: &TestApp, token: &str, name: &str) -> Uuid {
    let (status, body) = app
        .post_json_auth("/api/v1/organizations", json!({ "name": name }), token)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    body["id"].as_str().unwrap().parse().unwrap()
}

fn path(organization_id: Uuid) -> String {
    format!("/api/v1/organizations/{organization_id}")
}

#[sqlx::test(migrations = "./migrations")]
async fn creating_an_organization_makes_the_caller_its_owner(pool: PgPool) {
    let app = TestApp::new(pool);
    let (id, token) = account(&app, "owner@example.com").await;

    let (status, body) = app
        .post_json_auth(
            "/api/v1/organizations",
            json!({ "name": "  Acme Receiving  " }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["name"], "Acme Receiving", "the name is trimmed");
    assert_eq!(body["role"], "owner");
    assert_eq!(body["member_count"], 1);

    // The listing shows it, with the caller's role.
    let (status, body) = app.get_auth("/api/v1/organizations", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["organizations"][0]["role"], "owner");

    let organization_id: Uuid = body["organizations"][0]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let (status, body) = app.get_auth(&path(organization_id), &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["member_count"], 1);

    // A member list of one, which is the creator.
    let (status, body) = app
        .get_auth(&format!("{}/members", path(organization_id)), &token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["members"][0]["email"], "owner@example.com");
    assert_eq!(body["members"][0]["role"], "owner");
    assert_eq!(body["members"][0]["user_id"], id.to_string());
}

#[sqlx::test(migrations = "./migrations")]
async fn an_account_may_belong_to_many_organizations_and_sees_only_its_own(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, alice) = account(&app, "alice@example.com").await;
    let (_, bob) = account(&app, "bob@example.com").await;

    create_organization(&app, &alice, "Alice One").await;
    create_organization(&app, &alice, "Alice Two").await;
    let bob_only = create_organization(&app, &bob, "Bob Only").await;

    let (_, body) = app.get_auth("/api/v1/organizations", &alice).await;
    assert_eq!(body["total"], 2);

    let (status, body) = app.get_auth(&path(bob_only), &alice).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "forbidden");
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_organizations_are_not_found(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, token) = account(&app, "owner@example.com").await;

    let (status, body) = app.get_auth(&path(Uuid::new_v4()), &token).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn renaming_needs_manager_and_deleting_needs_ownership(pool: PgPool) {
    let app = TestApp::new(pool);
    let (owner_id, owner) = account(&app, "owner@example.com").await;
    let (_, member) = account(&app, "member@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;

    let (status, _) = app
        .post_json_auth(
            &format!("{}/members", path(organization_id)),
            json!({ "email": "member@example.com", "role": "member" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    // A plain member can read but not write.
    let (status, _) = app
        .patch_json_auth(
            &path(organization_id),
            json!({ "name": "Renamed" }),
            &member,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app.delete_auth(&path(organization_id), &member).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // An owner can do both.
    let (status, body) = app
        .patch_json_auth(&path(organization_id), json!({ "name": "Renamed" }), &owner)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Renamed");

    // An admin may rename but not delete.
    let (_, admin_token) = account(&app, "admin@example.com").await;
    let admin_id =
        grant_org_role(&app, &owner, organization_id, "admin@example.com", "admin").await;
    let (status, _) = app
        .patch_json_auth(
            &path(organization_id),
            json!({ "name": "Renamed Again" }),
            &admin_token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app.delete_auth(&path(organization_id), &admin_token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // The owner can, and the memberships go with it.
    assert_ne!(admin_id, owner_id);
    assert_eq!(
        app.delete_auth(&path(organization_id), &owner).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.get_auth(&path(organization_id), &owner).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.get_auth(&path(organization_id), &admin_token).await.0,
        StatusCode::NOT_FOUND
    );
}

/// Adds an account to an organization by address and returns the result.
async fn grant_org_role(
    app: &TestApp,
    owner_token: &str,
    organization_id: Uuid,
    email: &str,
    role: &str,
) -> Uuid {
    let (status, body) = app
        .post_json_auth(
            &format!("{}/members", path(organization_id)),
            json!({ "email": email, "role": role }),
            owner_token,
        )
        .await;
    assert!(
        status == StatusCode::CREATED || status == StatusCode::OK,
        "{body}"
    );

    body["user_id"].as_str().unwrap().parse().unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn members_are_invited_by_address(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let (expected_id, _) = account(&app, "member@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;

    let (status, body) = app
        .post_json_auth(
            &format!("{}/members", path(organization_id)),
            json!({ "email": " Member@Example.com ", "role": "member" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["user_id"], expected_id.to_string());
    assert_eq!(body["email"], "member@example.com");

    // Adding the same account again with a different role updates it rather than failing.
    let (status, body) = app
        .post_json_auth(
            &format!("{}/members", path(organization_id)),
            json!({ "email": "member@example.com", "role": "admin" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], "admin");

    // The same role again changes nothing.
    let (status, _) = app
        .post_json_auth(
            &format!("{}/members", path(organization_id)),
            json!({ "email": "member@example.com", "role": "admin" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // An address with no account is reported.
    let (status, body) = app
        .post_json_auth(
            &format!("{}/members", path(organization_id)),
            json!({ "email": "nobody@example.com", "role": "member" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");

    let (_, body) = app
        .get_auth(&format!("{}/members", path(organization_id)), &owner)
        .await;
    assert_eq!(body["total"], 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_admin_cannot_create_or_act_on_an_owner(pool: PgPool) {
    let app = TestApp::new(pool);
    let (owner_id, owner) = account(&app, "owner@example.com").await;
    let (_, admin) = account(&app, "admin@example.com").await;
    account(&app, "third@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;

    grant_org_role(&app, &owner, organization_id, "admin@example.com", "admin").await;

    // Promoting somebody to owner is an owner's prerogative.
    let (status, body) = app
        .post_json_auth(
            &format!("{}/members", path(organization_id)),
            json!({ "email": "third@example.com", "role": "owner" }),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Nor may an admin touch the existing owner.
    let (status, _) = app
        .put_json_auth(
            &format!("{}/members/{owner_id}", path(organization_id)),
            json!({ "role": "member" }),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app
        .delete_auth(
            &format!("{}/members/{owner_id}", path(organization_id)),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // A peer, on the other hand, is within reach.
    let third = grant_org_role(&app, &owner, organization_id, "third@example.com", "member").await;
    let (status, body) = app
        .put_json_auth(
            &format!("{}/members/{third}", path(organization_id)),
            json!({ "role": "admin" }),
            &admin,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], "admin");
}

#[sqlx::test(migrations = "./migrations")]
async fn the_last_owner_can_be_neither_demoted_nor_removed(pool: PgPool) {
    let app = TestApp::new(pool);
    let (owner_id, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;

    let (status, body) = app
        .put_json_auth(
            &format!("{}/members/{owner_id}", path(organization_id)),
            json!({ "role": "member" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap_or_default().contains("owner"),
        "{body}"
    );

    let (status, body) = app
        .delete_auth(
            &format!("{}/members/{owner_id}", path(organization_id)),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // With a second owner in place, both are allowed.
    let (second_id, second) = account(&app, "second@example.com").await;
    grant_org_role(&app, &owner, organization_id, "second@example.com", "owner").await;
    let _ = second;

    let (status, _) = app
        .delete_auth(
            &format!("{}/members/{owner_id}", path(organization_id)),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // Removing the other owner worked, which means the caller was free to leave because
    // somebody else owned the organization at the time.
    //
    // The account that is left is now the last owner, so it may not leave in turn.
    let (status, body) = app
        .delete_auth(
            &format!("{}/members/{second_id}", path(organization_id)),
            &second,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().unwrap_or_default().contains("owner"),
        "{body}"
    );

    let (_, body) = app
        .get_auth(&format!("{}/members", path(organization_id)), &second)
        .await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["members"][0]["role"], "owner");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_member_may_leave_and_an_admin_may_remove_them(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let (member_id, member) = account(&app, "member@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    grant_org_role(
        &app,
        &owner,
        organization_id,
        "member@example.com",
        "member",
    )
    .await;

    // A plain member may leave under their own steam.
    let (status, _) = app
        .delete_auth(
            &format!("{}/members/{member_id}", path(organization_id)),
            &member,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    assert_eq!(
        app.get_auth(&path(organization_id), &member).await.0,
        StatusCode::FORBIDDEN,
        "they are no longer a member"
    );

    // Removing somebody who is not a member is a miss, not a silent success.
    let (status, _) = app
        .delete_auth(
            &format!("{}/members/{member_id}", path(organization_id)),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_instance_administrator_may_read_but_not_touch(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (member_id, _) = account(&app, "member@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    grant_org_role(
        &app,
        &owner,
        organization_id,
        "member@example.com",
        "member",
    )
    .await;

    let administrator = administrator(&app, &pool, "root@example.com").await;

    // Read: allowed, with no role reported because they are not a member.
    let (status, body) = app
        .get_auth("/api/v1/admin/organizations", &administrator)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["organizations"][0]["name"], "Acme");
    assert!(body["organizations"][0].get("role").is_none());

    let (status, body) = app
        .get_auth(
            &format!("/api/v1/admin/organizations/{organization_id}"),
            &administrator,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["member_count"], 2);

    // Write: refused, because membership is what authorizes changes.
    let (status, _) = app
        .patch_json_auth(
            &path(organization_id),
            json!({ "name": "Hijacked" }),
            &administrator,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app
        .delete_auth(&path(organization_id), &administrator)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app
        .post_json_auth(
            &format!("{}/members", path(organization_id)),
            json!({ "email": "root@example.com", "role": "owner" }),
            &administrator,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app
        .delete_auth(
            &format!("{}/members/{member_id}", path(organization_id)),
            &administrator,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Nothing changed.
    let (_, body) = app.get_auth(&path(organization_id), &owner).await;
    assert_eq!(body["name"], "Acme");
    assert_eq!(body["member_count"], 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn every_membership_change_is_audited_with_its_organization_and_actor(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (owner_id, owner) = account(&app, "owner@example.com").await;
    let (member_id, _) = account(&app, "member@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    grant_org_role(
        &app,
        &owner,
        organization_id,
        "member@example.com",
        "member",
    )
    .await;
    app.put_json_auth(
        &format!("{}/members/{member_id}", path(organization_id)),
        json!({ "role": "admin" }),
        &owner,
    )
    .await;
    app.delete_auth(
        &format!("{}/members/{member_id}", path(organization_id)),
        &owner,
    )
    .await;

    let administrator = administrator(&app, &pool, "root@example.com").await;
    let (status, body) = app
        .get_auth(
            &format!("/api/v1/admin/audit-events?organization_id={organization_id}"),
            &administrator,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let events = body["events"].as_array().expect("events is a list");
    let kinds: Vec<&str> = events
        .iter()
        .map(|event| event["event_type"].as_str().unwrap_or_default())
        .collect();

    for expected in [
        "organization_created",
        "organization_member_added",
        "organization_member_role_changed",
        "organization_member_removed",
    ] {
        assert!(kinds.contains(&expected), "missing {expected} in {kinds:?}");
    }

    // The actor is recorded, which is the point of the trail.
    assert!(
        events
            .iter()
            .all(|event| event["actor_user_id"] == owner_id.to_string()),
        "{body}"
    );
    assert!(
        events
            .iter()
            .all(|event| event["organization_id"] == organization_id.to_string()),
        "{body}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn members_are_paginated(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;

    for index in 0..3 {
        let email = format!("member{index}@example.com");
        account(&app, &email).await;
        grant_org_role(&app, &owner, organization_id, &email, "member").await;
    }

    let (status, body) = app
        .get_auth(
            &format!("{}/members?limit=2&offset=0", path(organization_id)),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 4, "the total counts every member");
    assert_eq!(body["members"].as_array().unwrap().len(), 2);

    let (_, second) = app
        .get_auth(
            &format!("{}/members?limit=2&offset=2", path(organization_id)),
            &owner,
        )
        .await;
    assert_eq!(second["members"].as_array().unwrap().len(), 2);

    // The two pages do not overlap.
    let first_ids: Vec<&Value> = body["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| &member["user_id"])
        .collect();
    assert!(
        second["members"]
            .as_array()
            .unwrap()
            .iter()
            .all(|member| !first_ids.contains(&&member["user_id"]))
    );
}
