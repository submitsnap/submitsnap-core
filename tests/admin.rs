//! The administrator surface: `/api/v1/admin`.

mod common;

use axum::http::StatusCode;
use common::{
    PASSWORD, TestApp, access_token, grant_admin_role, identity_service, preflight, user_id,
};
use serde_json::{Value, json};
use sqlx::PgPool;
use submitsnap_core::{modules::rbac::RoleName, shared::request::ClientInfo};
use uuid::Uuid;

/// Registers an account, grants it the administrator role, and signs it in.
async fn signed_in_admin(app: &TestApp, pool: &PgPool, email: &str) -> (String, Uuid) {
    let (_, user) = app.register(email, PASSWORD).await;
    let id = user_id(&user);
    grant_admin_role(pool, id).await;

    let (status, session) = app.login(email, PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "the new administrator can sign in");

    (access_token(&session), id)
}

fn roles(body: &Value) -> Vec<String> {
    let mut roles: Vec<String> = body["roles"]
        .as_array()
        .expect("roles is a list")
        .iter()
        .map(|role| role.as_str().unwrap_or_default().to_owned())
        .collect();
    roles.sort();
    roles
}

#[sqlx::test(migrations = "./migrations")]
async fn accounts_can_be_searched_and_filtered(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (token, _) = signed_in_admin(&app, &pool, "admin@example.com").await;

    app.register("alice@example.com", PASSWORD).await;
    app.register("bob@other.test", PASSWORD).await;
    let (_, carol) = app.register("carol@example.com", PASSWORD).await;
    app.patch_json_auth(
        &format!("/api/v1/admin/users/{}/status", user_id(&carol)),
        json!({ "status": "disabled" }),
        &token,
    )
    .await;

    let (status, body) = app.get_auth("/api/v1/admin/users", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 4);

    let (_, body) = app
        .get_auth("/api/v1/admin/users?search=example.com", &token)
        .await;
    assert_eq!(body["total"], 3, "the search term filters by address");

    let (_, body) = app
        .get_auth("/api/v1/admin/users?status=disabled", &token)
        .await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["users"][0]["email"], "carol@example.com");

    let (_, body) = app.get_auth("/api/v1/admin/users?role=admin", &token).await;
    assert_eq!(body["total"], 1);
    assert_eq!(body["users"][0]["email"], "admin@example.com");

    // A `%` in the term is matched literally rather than widening the search.
    let (_, body) = app.get_auth("/api/v1/admin/users?search=%25", &token).await;
    assert_eq!(body["total"], 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn account_detail_exposes_operational_state(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (token, _) = signed_in_admin(&app, &pool, "admin@example.com").await;
    let (_, member) = app.register("member@example.com", PASSWORD).await;
    let member_id = user_id(&member);
    app.login("member@example.com", PASSWORD).await;

    let (status, body) = app
        .get_auth(&format!("/api/v1/admin/users/{member_id}"), &token)
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "member@example.com");
    assert_eq!(body["failed_login_attempts"], 0);
    assert_eq!(body["locked_until"], Value::Null);
    assert!(
        body["last_login_at"].is_string(),
        "the sign-in was recorded"
    );
    assert_eq!(roles(&body), vec!["user"]);

    let (status, body) = app
        .get_auth(&format!("/api/v1/admin/users/{}", Uuid::new_v4()), &token)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
}

#[sqlx::test(migrations = "./migrations")]
async fn roles_can_be_granted_and_revoked(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (token, _) = signed_in_admin(&app, &pool, "admin@example.com").await;
    let (_, member) = app.register("member@example.com", PASSWORD).await;
    let member_id = user_id(&member);

    let (status, body) = app
        .put_json_auth(
            &format!("/api/v1/admin/users/{member_id}/roles"),
            json!({ "roles": ["user", "admin"] }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(roles(&body), vec!["admin", "user"]);

    // A mixed-case role name is not a role.
    let (status, body) = app
        .put_json_auth(
            &format!("/api/v1/admin/users/{member_id}/roles"),
            json!({ "roles": ["superuser"] }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("superuser"),
        "the message names the unknown role: {body}"
    );

    let (status, body) = app
        .put_json_auth(
            &format!("/api/v1/admin/users/{member_id}/roles"),
            json!({ "roles": ["user"] }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(roles(&body), vec!["user"]);

    // Both directions were audited.
    let (_, body) = app
        .get_auth("/api/v1/admin/audit-events?event_type=role_granted", &token)
        .await;
    assert_eq!(body["total"], 1);
    let (_, body) = app
        .get_auth("/api/v1/admin/audit-events?event_type=role_revoked", &token)
        .await;
    assert_eq!(body["total"], 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_administrator_may_step_down_only_when_replaced(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (lonely_token, lonely_id) = signed_in_admin(&app, &pool, "lonely@example.com").await;

    // Alone, stepping down would leave nobody in charge.
    let (status, body) = app
        .put_json_auth(
            &format!("/api/v1/admin/users/{lonely_id}/roles"),
            json!({ "roles": ["user"] }),
            &lonely_token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("administrator"),
        "the message explains the refusal: {body}"
    );

    // With a successor, the same request is allowed.
    let (_, second) = app.register("successor@example.com", PASSWORD).await;
    grant_admin_role(&pool, user_id(&second)).await;

    let (status, body) = app
        .put_json_auth(
            &format!("/api/v1/admin/users/{lonely_id}/roles"),
            json!({ "roles": ["user"] }),
            &lonely_token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(roles(&body), vec!["user"]);

    // The token is still valid, but it no longer carries the role.
    let (status, _) = app.get_auth("/api/v1/admin/users", &lonely_token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_administrator_cannot_disable_or_delete_themselves(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (token, id) = signed_in_admin(&app, &pool, "admin@example.com").await;

    let (status, _) = app
        .patch_json_auth(
            &format!("/api/v1/admin/users/{id}/status"),
            json!({ "status": "disabled" }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app
        .delete_json_auth(
            &format!("/api/v1/admin/users/{id}"),
            json!({ "confirm_email": "admin@example.com" }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_locked_account_can_be_unlocked(pool: PgPool) {
    let app = TestApp::with_config(
        vec![("max_failed_login_attempts", "2".to_owned())],
        pool.clone(),
    );
    let (token, _) = signed_in_admin(&app, &pool, "admin@example.com").await;
    let (_, member) = app.register("member@example.com", PASSWORD).await;
    let member_id = user_id(&member);

    for _ in 0..2 {
        app.login("member@example.com", "wrong-password-here").await;
    }
    let (status, _) = app.login("member@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::LOCKED);

    let (status, body) = app
        .post_auth(&format!("/api/v1/admin/users/{member_id}/unlock"), &token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["failed_login_attempts"], 0);
    assert_eq!(body["locked_until"], Value::Null);

    let (status, _) = app.login("member@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn sessions_can_be_revoked_without_changing_the_account(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (token, _) = signed_in_admin(&app, &pool, "admin@example.com").await;
    let (_, member) = app.register("member@example.com", PASSWORD).await;
    let member_id = user_id(&member);
    let (_, member_session) = app.login("member@example.com", PASSWORD).await;
    let member_token = access_token(&member_session);

    assert_eq!(
        app.get_auth("/api/v1/auth/me", &member_token).await.0,
        StatusCode::OK
    );

    let (status, body) = app
        .delete_auth(&format!("/api/v1/admin/users/{member_id}/sessions"), &token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], 1);

    assert_eq!(
        app.get_auth("/api/v1/auth/me", &member_token).await.0,
        StatusCode::UNAUTHORIZED
    );

    // The account itself is untouched.
    let (status, body) = app
        .get_auth(&format!("/api/v1/admin/users/{member_id}"), &token)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "active");
    assert_eq!(
        app.login("member@example.com", PASSWORD).await.0,
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn deleting_an_account_requires_the_matching_address(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (token, _) = signed_in_admin(&app, &pool, "admin@example.com").await;
    let (_, member) = app.register("member@example.com", PASSWORD).await;
    let member_id = user_id(&member);

    let (status, _) = app
        .delete_json_auth(
            &format!("/api/v1/admin/users/{member_id}"),
            json!({ "confirm_email": "someone-else@example.com" }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // The account is still there after the refused attempt.
    assert_eq!(
        app.get_auth(&format!("/api/v1/admin/users/{member_id}"), &token)
            .await
            .0,
        StatusCode::OK
    );

    // Case and surrounding whitespace are normalized before the comparison.
    let (status, _) = app
        .delete_json_auth(
            &format!("/api/v1/admin/users/{member_id}"),
            json!({ "confirm_email": " Member@Example.com " }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .get_auth(&format!("/api/v1/admin/users/{member_id}"), &token)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn deleting_an_account_removes_its_sessions_but_keeps_the_audit_trail(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (token, _) = signed_in_admin(&app, &pool, "admin@example.com").await;
    let (_, member) = app.register("member@example.com", PASSWORD).await;
    let member_id = user_id(&member);
    let (_, member_session) = app.login("member@example.com", PASSWORD).await;

    let (status, _) = app
        .delete_json_auth(
            &format!("/api/v1/admin/users/{member_id}"),
            json!({ "confirm_email": "member@example.com" }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // The session went with the account.
    assert_eq!(
        app.get_auth("/api/v1/auth/me", &access_token(&member_session))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // The history survives, with the account reference cleared and the address retained.
    let (_, body) = app
        .get_auth(
            "/api/v1/admin/audit-events?email=member@example.com",
            &token,
        )
        .await;
    let events = body["events"].as_array().expect("events is a list");
    assert!(!events.is_empty(), "the account's history was retained");
    assert!(
        events.iter().all(|event| event["user_id"].is_null()),
        "the account reference was cleared: {body}"
    );
    assert!(
        events
            .iter()
            .any(|event| event["event_type"] == "account_deleted")
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_events_are_readable_and_filterable(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (token, admin_id) = signed_in_admin(&app, &pool, "admin@example.com").await;

    app.register("person@example.com", PASSWORD).await;
    app.login("person@example.com", "wrong-password-here").await;

    let (status, body) = app.get_auth("/api/v1/admin/audit-events", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["total"].as_i64().unwrap_or_default() > 0);
    assert_eq!(body["events"][0]["event_type"], "login_failed");
    assert!(body["events"][0]["created_at"].is_string());
    assert!(body["events"][0]["ip_address"].is_string());

    let (_, body) = app
        .get_auth("/api/v1/admin/audit-events?event_type=login_failed", &token)
        .await;
    assert!(
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["event_type"] == "login_failed"),
        "{body}"
    );

    let (_, body) = app
        .get_auth(
            &format!("/api/v1/admin/audit-events?user_id={admin_id}"),
            &token,
        )
        .await;
    assert!(
        body["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["user_id"] == admin_id.to_string()),
        "{body}"
    );

    // A bound in the future excludes everything that has happened so far.
    let (_, body) = app
        .get_auth(
            "/api/v1/admin/audit-events?since=2999-01-01T00:00:00Z",
            &token,
        )
        .await;
    assert_eq!(body["total"], 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn the_admin_surface_requires_the_role(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    app.register("member@example.com", PASSWORD).await;
    let (_, session) = app.login("member@example.com", PASSWORD).await;
    let token = access_token(&session);

    for (method, path) in [
        ("GET", "/api/v1/admin/users"),
        ("GET", "/api/v1/admin/audit-events"),
    ] {
        let (status, _) = app.get_auth(path, &token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
    }

    let (status, _) = app
        .patch_json_auth(
            &format!("/api/v1/admin/users/{}/status", Uuid::new_v4()),
            json!({ "status": "disabled" }),
            &token,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn cors_preflight_advertises_the_methods_the_admin_api_uses(pool: PgPool) {
    let app = TestApp::with_config(
        vec![("cors_allowed_origins", "https://app.example.com".to_owned())],
        pool,
    );

    let response = app.send(preflight("https://app.example.com")).await;
    let methods = response
        .headers()
        .get("access-control-allow-methods")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();

    for method in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
        assert!(
            methods.contains(method),
            "a browser must be allowed to send {method}: {methods}"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn the_bootstrap_command_grants_a_role_without_a_session(pool: PgPool) {
    let config = common::test_config();
    let service = identity_service(&config, pool.clone());
    let client = ClientInfo::default();

    service
        .register("owner@example.com", PASSWORD, &client)
        .await
        .expect("registration succeeds");

    let id = service
        .grant_role_by_email("owner@example.com", &RoleName::admin())
        .await
        .expect("the role is granted");
    assert_eq!(service.roles_for(id).await.unwrap().len(), 2);

    // Safe to run twice, and the address is normalized like everywhere else.
    service
        .grant_role_by_email(" OWNER@example.com ", &RoleName::admin())
        .await
        .expect("a repeat grant is a no-op");
    assert_eq!(service.roles_for(id).await.unwrap().len(), 2);

    assert!(
        service
            .grant_role_by_email("nobody@example.com", &RoleName::admin())
            .await
            .is_err(),
        "an unknown address is reported rather than ignored"
    );
}
