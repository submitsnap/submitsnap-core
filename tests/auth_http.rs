mod common;

use axum::http::{Method, StatusCode};
use common::{PASSWORD, TestApp, access_token, cookie_header, cookie_request, read, refresh_token};
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn register_then_login_then_me(pool: PgPool) {
    let app = TestApp::new(pool);

    let (status, user) = app.register("person@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(user["email"], "person@example.com");
    assert_eq!(user["email_verified"], false);
    assert_eq!(user["roles"], json!(["user"]));
    assert!(user.get("password_hash").is_none());

    let (status, session) = app.login("person@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(session["token_type"], "Bearer");

    let (status, me) = app
        .get_auth("/api/v1/auth/me", &access_token(&session))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["email"], "person@example.com");
}

#[sqlx::test(migrations = "./migrations")]
async fn email_addresses_are_matched_case_insensitively(pool: PgPool) {
    let app = TestApp::new(pool);

    let (status, user) = app.register("  Person@Example.COM ", PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(user["email"], "person@example.com");

    let (status, _) = app.login("PERSON@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn duplicate_registration_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);

    assert_eq!(
        app.register("person@example.com", PASSWORD).await.0,
        StatusCode::CREATED
    );

    let (status, body) = app.register("PERSON@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "conflict");
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_rejects_invalid_input(pool: PgPool) {
    let app = TestApp::new(pool);

    let (status, _) = app.register("not-an-email", PASSWORD).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, _) = app.register("person@example.com", "short").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_email_and_wrong_password_are_indistinguishable(pool: PgPool) {
    let app = TestApp::new(pool);
    app.register("person@example.com", PASSWORD).await;

    let (unknown_status, unknown_body) = app.login("nobody@example.com", PASSWORD).await;
    let (wrong_status, wrong_body) = app.login("person@example.com", "definitely-wrong").await;

    assert_eq!(unknown_status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_body["code"], "authentication_failed");
    assert_eq!(unknown_body["error"], wrong_body["error"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn accounts_lock_after_repeated_failures(pool: PgPool) {
    let app = TestApp::with_config(vec![("max_failed_login_attempts", "3".to_owned())], pool);
    app.register("person@example.com", PASSWORD).await;

    for _ in 0..2 {
        let (status, _) = app.login("person@example.com", "definitely-wrong").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    let (status, body) = app.login("person@example.com", "definitely-wrong").await;
    assert_eq!(status, StatusCode::LOCKED);
    assert_eq!(body["code"], "account_locked");

    // Even the correct password is refused while the lock holds.
    let (status, _) = app.login("person@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::LOCKED);
}

#[sqlx::test(migrations = "./migrations")]
async fn refresh_rotates_and_replaying_the_old_token_revokes_the_session(pool: PgPool) {
    let app = TestApp::new(pool);
    app.register("person@example.com", PASSWORD).await;
    let (_, session) = app.login("person@example.com", PASSWORD).await;
    let first_refresh = refresh_token(&session);

    let (status, rotated) = app
        .post_json(
            "/api/v1/auth/refresh",
            json!({ "refresh_token": first_refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let rotated_access = access_token(&rotated);
    assert_ne!(refresh_token(&rotated), first_refresh);

    // Replaying the consumed token must fail and must invalidate the whole session family.
    let (status, body) = app
        .post_json(
            "/api/v1/auth/refresh",
            json!({ "refresh_token": first_refresh }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "authentication_failed");

    let (status, _) = app.get_auth("/api/v1/auth/me", &rotated_access).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = app
        .post_json(
            "/api/v1/auth/refresh",
            json!({ "refresh_token": refresh_token(&rotated) }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn refresh_without_a_token_is_rejected(pool: PgPool) {
    let app = TestApp::new(pool);

    let (status, _) = app.post_json("/api/v1/auth/refresh", json!({})).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn logout_revokes_the_session_immediately(pool: PgPool) {
    let app = TestApp::new(pool);
    app.register("person@example.com", PASSWORD).await;
    let (_, session) = app.login("person@example.com", PASSWORD).await;
    let token = access_token(&session);

    assert_eq!(
        app.get_auth("/api/v1/auth/me", &token).await.0,
        StatusCode::OK
    );

    let (status, _) = app.post_auth("/api/v1/auth/logout", &token).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app.get_auth("/api/v1/auth/me", &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = app
        .post_json(
            "/api/v1/auth/refresh",
            json!({ "refresh_token": refresh_token(&session) }),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn logout_all_revokes_every_session(pool: PgPool) {
    let app = TestApp::new(pool);
    app.register("person@example.com", PASSWORD).await;
    let (_, first) = app.login("person@example.com", PASSWORD).await;
    let (_, second) = app.login("person@example.com", PASSWORD).await;

    let (status, _) = app
        .post_auth("/api/v1/auth/logout-all", &access_token(&first))
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = app
        .get_auth("/api/v1/auth/me", &access_token(&second))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn unauthenticated_and_malformed_tokens_are_rejected(pool: PgPool) {
    let app = TestApp::new(pool);

    let response = app
        .send(common::json_request(
            Method::GET,
            "/api/v1/auth/me",
            None,
            None,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let (status, _) = app.get_auth("/api/v1/auth/me", "not-a-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test(migrations = "./migrations")]
async fn dashboard_login_uses_cookies_and_refreshes_through_them(pool: PgPool) {
    let app = TestApp::new(pool);
    app.register("person@example.com", PASSWORD).await;

    let response = app
        .send(common::json_request(
            Method::POST,
            "/api/v1/auth/dashboard/login",
            Some(json!({ "email": "person@example.com", "password": PASSWORD })),
            None,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let cookies = cookie_header(&response);
    assert!(cookies.contains("access_token="));
    assert!(cookies.contains("refresh_token="));

    let (_, body) = read(response).await;
    assert!(body.get("access_token").is_none());
    assert_eq!(body["user"]["email"], "person@example.com");

    let response = app
        .send(cookie_request(
            Method::POST,
            "/api/v1/auth/refresh",
            Some(json!({})),
            &cookies,
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let refreshed_cookies = cookie_header(&response);
    let (_, body) = read(response).await;
    assert!(body.get("access_token").is_none());
    assert!(refreshed_cookies.contains("access_token="));

    // The rotated cookie authenticates subsequent requests.
    let (status, body) = read(
        app.send(cookie_request(
            Method::GET,
            "/api/v1/auth/me",
            None,
            &refreshed_cookies,
        ))
        .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["email"], "person@example.com");
}

#[sqlx::test(migrations = "./migrations")]
async fn changing_a_password_keeps_the_current_session_and_drops_the_others(pool: PgPool) {
    let app = TestApp::new(pool);
    app.register("person@example.com", PASSWORD).await;
    let (_, current) = app.login("person@example.com", PASSWORD).await;
    let (_, other) = app.login("person@example.com", PASSWORD).await;

    let (status, _) = app
        .post_json_auth(
            "/api/v1/auth/password/change",
            json!({ "current_password": "definitely-wrong", "new_password": "a-brand-new-password" }),
            &access_token(&current),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = app
        .post_json_auth(
            "/api/v1/auth/password/change",
            json!({ "current_password": PASSWORD, "new_password": "a-brand-new-password" }),
            &access_token(&current),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    assert_eq!(
        app.get_auth("/api/v1/auth/me", &access_token(&other))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.get_auth("/api/v1/auth/me", &access_token(&current))
            .await
            .0,
        StatusCode::OK
    );

    assert_eq!(
        app.login("person@example.com", PASSWORD).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.login("person@example.com", "a-brand-new-password")
            .await
            .0,
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn admin_routes_require_the_admin_role(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (_, user) = app.register("person@example.com", PASSWORD).await;
    let (_, session) = app.login("person@example.com", PASSWORD).await;
    let token = access_token(&session);

    let (status, body) = app.get_auth("/api/v1/admin/users", &token).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "forbidden");

    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'admin'",
    )
    .bind(common::user_id(&user))
    .execute(&pool)
    .await
    .expect("role is granted");

    let (status, body) = app.get_auth("/api/v1/admin/users", &token).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["users"][0]["email"], "person@example.com");
    assert_eq!(body["users"][0]["roles"], json!(["admin", "user"]));
}

#[sqlx::test(migrations = "./migrations")]
async fn admin_pagination_is_bounded(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let (_, user) = app.register("person@example.com", PASSWORD).await;
    let (_, session) = app.login("person@example.com", PASSWORD).await;

    sqlx::query(
        "INSERT INTO user_roles (user_id, role_id) SELECT $1, id FROM roles WHERE name = 'admin'",
    )
    .bind(common::user_id(&user))
    .execute(&pool)
    .await
    .expect("role is granted");

    let (status, _) = app
        .get_auth(
            "/api/v1/admin/users?limit=5000&offset=0",
            &access_token(&session),
        )
        .await;

    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn registration_is_rate_limited(pool: PgPool) {
    let app = TestApp::with_config(vec![("register_rate_limit_per_hour", "1".to_owned())], pool);

    assert_eq!(
        app.register("first@example.com", PASSWORD).await.0,
        StatusCode::CREATED
    );

    let (status, body) = app.register("second@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["code"], "too_many_requests");
}

#[sqlx::test(migrations = "./migrations")]
async fn auth_responses_are_not_cacheable(pool: PgPool) {
    let app = TestApp::new(pool);
    app.register("person@example.com", PASSWORD).await;

    let response = app
        .send(common::json_request(
            Method::POST,
            "/api/v1/auth/login",
            Some(json!({ "email": "person@example.com", "password": PASSWORD })),
            None,
        ))
        .await;

    assert_eq!(
        response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}
