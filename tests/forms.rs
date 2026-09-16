//! Forms, and the public endpoint that accepts their submissions.

mod common;

use axum::http::StatusCode;
use common::{PASSWORD, TestApp, access_token, user_id};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

/// A minimal but complete definition: one required email and one optional message.
fn contact_schema() -> Value {
    json!({
        "title": "Contact us",
        "description": "We reply within one business day.",
        "fields": [
            { "key": "email", "type": "email", "label": "Email", "required": true },
            { "key": "message", "type": "textarea", "label": "Message", "max_length": 2000 }
        ]
    })
}

/// Registers an account and returns (its id, an access token).
async fn account(app: &TestApp, email: &str) -> (Uuid, String) {
    let (status, user) = app.register(email, PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED, "{user}");

    let (_, session) = app.login(email, PASSWORD).await;
    (user_id(&user), access_token(&session))
}

async fn create_organization(app: &TestApp, token: &str, name: &str) -> Uuid {
    let (status, body) = app
        .post_json_auth("/api/v1/organizations", json!({ "name": name }), token)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    body["id"].as_str().unwrap().parse().unwrap()
}

async fn create_form(app: &TestApp, token: &str, organization_id: Uuid, name: &str) -> Value {
    let (status, body) = app
        .post_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms"),
            json!({ "name": name, "schema": contact_schema() }),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    body
}

async fn publish(
    app: &TestApp,
    token: &str,
    organization_id: Uuid,
    form_id: &str,
) -> (StatusCode, Value) {
    app.post_auth(
        &format!("/api/v1/organizations/{organization_id}/forms/{form_id}/publish"),
        token,
    )
    .await
}

#[sqlx::test(migrations = "./migrations")]
async fn a_form_starts_as_a_draft_and_is_not_public_until_published(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;

    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    assert_eq!(form["status"], "draft");
    assert_eq!(form["schema_version"], 1);
    assert_eq!(form["name"], "Contact us");
    assert!(form["public_id"].is_string());

    let public_id = form["public_id"].as_str().unwrap();

    // A draft is invisible to strangers rather than merely read-only.
    let (status, _) = app.get_auth(&format!("/f/{public_id}"), &owner).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body) = publish(&app, &owner, organization_id, form["id"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "published");
    assert!(body["published_at"].is_string());

    // Now it renders for anybody.
    let (status, body) = app.get_auth(&format!("/f/{public_id}"), &owner).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["title"], "Contact us");
    assert_eq!(body["honeypot_field"], "_gotcha");
    assert_eq!(body["fields"].as_array().unwrap().len(), 2);
    // Nothing about the tenant leaks.
    assert!(body.get("organization_id").is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_published_form_accepts_a_submission(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    let public_id = form["public_id"].as_str().unwrap().to_owned();
    publish(&app, &owner, organization_id, form["id"].as_str().unwrap()).await;

    let (status, body) = app
        .post_json_auth(
            &format!("/f/{public_id}"),
            json!({ "email": "person@example.com", "message": "Hello there" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert!(body["id"].is_string());

    // It landed, unread, with the answers intact and the version they were written against.
    let (email, version, status): (String, i32, String) = sqlx::query_as(
        "SELECT data->>'email', schema_version, status::text FROM submissions WHERE form_id = $1",
    )
    .bind(Uuid::parse_str(form["id"].as_str().unwrap()).unwrap())
    .fetch_one(&pool)
    .await
    .expect("the submission is readable");

    assert_eq!(email, "person@example.com");
    assert_eq!(version, 1);
    assert_eq!(status, "unread");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_closed_form_says_so_rather_than_disappearing(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    let form_id = form["id"].as_str().unwrap();
    let public_id = form["public_id"].as_str().unwrap().to_owned();
    publish(&app, &owner, organization_id, form_id).await;

    let (status, _) = app
        .post_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}/close"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app.get_auth(&format!("/f/{public_id}"), &owner).await;
    assert_eq!(status, StatusCode::GONE, "a closed form explains itself");

    let (status, _) = app
        .post_json_auth(
            &format!("/f/{public_id}"),
            json!({ "email": "a@b.co" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::GONE);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_invalid_submission_lists_every_problem(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    let public_id = form["public_id"].as_str().unwrap().to_owned();
    publish(&app, &owner, organization_id, form["id"].as_str().unwrap()).await;

    let (status, body) = app
        .post_json_auth(
            &format!("/f/{public_id}"),
            json!({ "email": "not-an-address", "unknown": 1 }),
            &owner,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"].as_str().unwrap_or_default();
    assert!(message.contains("valid email"), "{message}");
    assert!(message.contains("not a field"), "{message}");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_honeypot_submission_is_accepted_but_filed_as_spam(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    let form_id = Uuid::parse_str(form["id"].as_str().unwrap()).unwrap();
    let public_id = form["public_id"].as_str().unwrap().to_owned();
    publish(&app, &owner, organization_id, form["id"].as_str().unwrap()).await;

    // A bot that fills every input gets the ordinary success response and learns nothing.
    let (status, _) = app
        .post_json_auth(
            &format!("/f/{public_id}"),
            json!({ "email": "bot@example.com", "_gotcha": "filled in" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);

    let status: String =
        sqlx::query_scalar("SELECT status::text FROM submissions WHERE form_id = $1")
            .bind(form_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(status, "spam");
}

#[sqlx::test(migrations = "./migrations")]
async fn rotating_the_public_id_invalidates_the_old_link(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    let form_id = form["id"].as_str().unwrap();
    let old_public_id = form["public_id"].as_str().unwrap().to_owned();
    publish(&app, &owner, organization_id, form_id).await;

    let (status, body) = app
        .post_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}/public-id"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let new_public_id = body["public_id"].as_str().unwrap().to_owned();
    assert_ne!(new_public_id, old_public_id);

    assert_eq!(
        app.get_auth(&format!("/f/{old_public_id}"), &owner).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.get_auth(&format!("/f/{new_public_id}"), &owner).await.0,
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_broken_definition_is_refused_with_every_problem(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;

    let (status, body) = app
        .post_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms"),
            json!({
                "name": "Broken",
                "schema": {
                    "title": "Broken",
                    "fields": [
                        { "key": "Email", "type": "email", "label": "Email" },
                        { "key": "topic", "type": "select", "label": "Topic" }
                    ]
                }
            }),
            &owner,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"].as_str().unwrap_or_default();
    assert!(message.contains("lowercase letter"), "{message}");
    assert!(message.contains("needs options"), "{message}");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_file_field_cannot_be_published_without_storage(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;

    // Storage is optional, so the definition is storable as a draft.
    let (status, form) = app
        .post_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms"),
            json!({
                "name": "With an upload",
                "schema": {
                    "title": "With an upload",
                    "fields": [
                        { "key": "invoice", "type": "file", "label": "Invoice",
                          "max_bytes": 1048576 }
                    ]
                }
            }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{form}");

    let (status, body) = publish(&app, &owner, organization_id, form["id"].as_str().unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("file uploads"),
        "{body}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn editing_the_fields_bumps_the_schema_version(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    let form_id = form["id"].as_str().unwrap();

    // Renaming leaves the field set alone.
    let (status, body) = app
        .patch_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}"),
            json!({ "name": "Get in touch" }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "Get in touch");
    assert_eq!(body["schema_version"], 1);

    // Changing a field does not.
    let (status, body) = app
        .patch_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}"),
            json!({
                "schema": {
                    "title": "Contact us",
                    "fields": [
                        { "key": "email", "type": "email", "label": "Email", "required": true },
                        { "key": "phone", "type": "text", "label": "Phone" }
                    ]
                }
            }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["schema_version"], 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn forms_are_scoped_to_their_organization(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let (_, outsider) = account(&app, "outsider@example.com").await;

    let organization_id = create_organization(&app, &owner, "Acme").await;
    let other = create_organization(&app, &outsider, "Other").await;
    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    let form_id = form["id"].as_str().unwrap();

    // A non-member cannot see the form at all.
    let (status, _) = app
        .get_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}"),
            &outsider,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Nor can the form be reached by pairing it with an organization the caller does belong to.
    let (status, _) = app
        .get_auth(
            &format!("/api/v1/organizations/{other}/forms/{form_id}"),
            &outsider,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_plain_member_may_read_but_not_change_a_form(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let (member_id, member) = account(&app, "member@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    let form_id = form["id"].as_str().unwrap();

    app.post_json_auth(
        &format!("/api/v1/organizations/{organization_id}/members"),
        json!({ "email": "member@example.com", "role": "member" }),
        &owner,
    )
    .await;
    let _ = member_id;

    // Reading is allowed.
    let (status, _) = app
        .get_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}"),
            &member,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // Changing is not.
    for attempt in [
        app.patch_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}"),
            json!({ "name": "Renamed" }),
            &member,
        )
        .await
        .0,
        publish(&app, &member, organization_id, form_id).await.0,
        app.delete_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}"),
            &member,
        )
        .await
        .0,
    ] {
        assert_eq!(attempt, StatusCode::FORBIDDEN);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn deleting_a_form_takes_its_submissions_with_it(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = create_organization(&app, &owner, "Acme").await;
    let form = create_form(&app, &owner, organization_id, "Contact us").await;
    let form_id = Uuid::parse_str(form["id"].as_str().unwrap()).unwrap();
    let public_id = form["public_id"].as_str().unwrap().to_owned();
    publish(&app, &owner, organization_id, form["id"].as_str().unwrap()).await;

    app.post_json_auth(
        &format!("/f/{public_id}"),
        json!({ "email": "person@example.com" }),
        &owner,
    )
    .await;

    let (status, _) = app
        .delete_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM submissions WHERE form_id = $1")
        .bind(form_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0, "submissions cascade with the form");
}
