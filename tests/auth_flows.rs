mod common;

use std::sync::Arc;

use axum::http::StatusCode;
use common::{PASSWORD, TestApp, access_token, config_with, identity_service};
use serde_json::json;
use sqlx::PgPool;
use submitsnap_core::shared::request::ClientInfo;

const NEW_PASSWORD: &str = "a-brand-new-password";

#[sqlx::test(migrations = "./migrations")]
async fn email_verification_confirms_the_account_once(pool: PgPool) {
    let config = common::test_config();
    let service = identity_service(&config, pool.clone());
    let client = ClientInfo::default();

    let registration = service
        .register("person@example.com", PASSWORD, &client)
        .await
        .expect("registration succeeds");

    let user = service
        .user_by_id(registration.user.id)
        .await
        .unwrap()
        .expect("account exists");
    assert!(!user.is_email_verified());

    let app = TestApp::new(pool);
    let (status, _) = app
        .post_json(
            "/api/v1/identity/email/verify",
            json!({ "token": registration.verification_token }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let user = service
        .user_by_id(registration.user.id)
        .await
        .unwrap()
        .expect("account exists");
    assert!(user.is_email_verified());

    // The token is single use.
    let (status, body) = app
        .post_json(
            "/api/v1/identity/email/verify",
            json!({ "token": registration.verification_token }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_token");
}

#[sqlx::test(migrations = "./migrations")]
async fn unknown_verification_tokens_are_rejected(pool: PgPool) {
    let app = TestApp::new(pool);

    let (status, body) = app
        .post_json(
            "/api/v1/identity/email/verify",
            json!({ "token": "not-a-real-token" }),
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_token");
}

#[sqlx::test(migrations = "./migrations")]
async fn required_verification_blocks_sign_in_until_confirmed(pool: PgPool) {
    let extra = vec![("require_email_verification", "true".to_owned())];
    let config = Arc::new(config_with(extra.clone()));
    let service = identity_service(&config, pool.clone());
    let client = ClientInfo::default();

    let registration = service
        .register("person@example.com", PASSWORD, &client)
        .await
        .expect("registration succeeds");

    let app = TestApp::with_config(extra, pool);

    let (status, body) = app.login("person@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "forbidden");

    service
        .verify_email(&registration.verification_token, &client)
        .await
        .expect("verification succeeds");

    let (status, _) = app.login("person@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::OK);
}

#[sqlx::test(migrations = "./migrations")]
async fn password_reset_is_single_use_and_signs_out_every_session(pool: PgPool) {
    let config = common::test_config();
    let service = identity_service(&config, pool.clone());
    let client = ClientInfo::default();
    let app = TestApp::new(pool);

    service
        .register("person@example.com", PASSWORD, &client)
        .await
        .expect("registration succeeds");
    let (_, session) = app.login("person@example.com", PASSWORD).await;

    let token = service
        .request_password_reset("person@example.com", &client)
        .await
        .expect("reset request succeeds")
        .expect("an account exists so a token is issued");

    let (status, _) = app
        .post_json(
            "/api/v1/identity/password/reset",
            json!({ "token": token, "password": NEW_PASSWORD }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    // A reset is a recovery action: existing sessions must not survive it.
    assert_eq!(
        app.get_auth("/api/v1/auth/me", &access_token(&session))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // Nor may the link be replayed.
    let (status, body) = app
        .post_json(
            "/api/v1/identity/password/reset",
            json!({ "token": token, "password": "yet-another-password" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_token");

    assert_eq!(
        app.login("person@example.com", PASSWORD).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.login("person@example.com", NEW_PASSWORD).await.0,
        StatusCode::OK
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn issuing_a_new_reset_link_invalidates_the_previous_one(pool: PgPool) {
    let config = common::test_config();
    let service = identity_service(&config, pool.clone());
    let client = ClientInfo::default();

    service
        .register("person@example.com", PASSWORD, &client)
        .await
        .expect("registration succeeds");

    let first = service
        .request_password_reset("person@example.com", &client)
        .await
        .unwrap()
        .expect("token issued");
    let second = service
        .request_password_reset("person@example.com", &client)
        .await
        .unwrap()
        .expect("token issued");

    assert_ne!(first, second);
    assert!(
        service
            .reset_password(&first, NEW_PASSWORD, &client)
            .await
            .is_err()
    );
    assert!(
        service
            .reset_password(&second, NEW_PASSWORD, &client)
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn password_recovery_never_reveals_whether_an_account_exists(pool: PgPool) {
    let app = TestApp::new(pool);

    for email in ["nobody@example.com", "somebody@example.com"] {
        let (status, body) = app
            .post_json(
                "/api/v1/identity/password/forgot",
                json!({ "email": email }),
            )
            .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(
            body["message"],
            "If an account exists for that address, a reset link has been sent."
        );
    }

    let (status, body) = app
        .post_json(
            "/api/v1/identity/email/verification",
            json!({ "email": "nobody@example.com" }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert!(body["message"].as_str().is_some());
}
