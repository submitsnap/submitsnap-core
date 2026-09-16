//! The submission inbox, and the export.

mod common;

use axum::http::{Method, StatusCode};
use common::{PASSWORD, TestApp, access_token, json_request, user_id};
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

fn schema() -> Value {
    json!({
        "title": "Contact us",
        "fields": [
            { "key": "email", "type": "email", "label": "Email", "required": true },
            { "key": "topic", "type": "select", "label": "Topic", "options": ["Sales", "Support"] }
        ]
    })
}

async fn account(app: &TestApp, email: &str) -> (Uuid, String) {
    let (status, user) = app.register(email, PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED, "{user}");

    let (_, session) = app.login(email, PASSWORD).await;
    (user_id(&user), access_token(&session))
}

async fn organization(app: &TestApp, token: &str, name: &str) -> Uuid {
    let (status, body) = app
        .post_json_auth("/api/v1/organizations", json!({ "name": name }), token)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    body["id"].as_str().unwrap().parse().unwrap()
}

/// A published form ready to receive submissions. Returns (form id, public id).
async fn published_form(app: &TestApp, token: &str, organization_id: Uuid) -> (Uuid, String) {
    let (status, form) = app
        .post_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms"),
            json!({ "name": "Contact us", "schema": schema() }),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{form}");

    let form_id = form["id"].as_str().unwrap().to_owned();
    app.post_auth(
        &format!("/api/v1/organizations/{organization_id}/forms/{form_id}/publish"),
        token,
    )
    .await;

    (
        Uuid::parse_str(&form_id).unwrap(),
        form["public_id"].as_str().unwrap().to_owned(),
    )
}

async fn submit(app: &TestApp, public_id: &str, body: Value) {
    let (status, response) = app
        .post_json_auth(&format!("/f/{public_id}"), body, "")
        .await;
    assert_eq!(status, StatusCode::CREATED, "{response}");
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("the body is readable");
    String::from_utf8(bytes.to_vec()).expect("the body is text")
}

#[sqlx::test(migrations = "./migrations")]
async fn the_inbox_lists_newest_first_and_paginates(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = organization(&app, &owner, "Acme").await;
    let (_, public_id) = published_form(&app, &owner, organization_id).await;

    for index in 0..3 {
        submit(
            &app,
            &public_id,
            json!({ "email": format!("person{index}@example.com"), "topic": "Sales" }),
        )
        .await;
    }

    let (status, body) = app
        .get_auth(
            &format!("/api/v1/organizations/{organization_id}/submissions?limit=2"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 3);
    assert_eq!(body["submissions"].as_array().unwrap().len(), 2);

    // Newest first: the last one submitted leads.
    assert_eq!(
        body["submissions"][0]["data"]["email"],
        "person2@example.com"
    );
    assert_eq!(body["submissions"][0]["status"], "unread");
    assert_eq!(body["submissions"][0]["schema_version"], 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn submissions_can_be_filtered_by_status_and_by_an_answer(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = organization(&app, &owner, "Acme").await;
    let (_, public_id) = published_form(&app, &owner, organization_id).await;

    submit(
        &app,
        &public_id,
        json!({ "email": "sales@example.com", "topic": "Sales" }),
    )
    .await;
    submit(
        &app,
        &public_id,
        json!({ "email": "support@example.com", "topic": "Support" }),
    )
    .await;
    submit(
        &app,
        &public_id,
        json!({ "email": "bot@example.com", "_gotcha": "x" }),
    )
    .await;

    // By status, which is how an organization hides what its honeypot caught.
    let (status, body) = app
        .get_auth(
            &format!("/api/v1/organizations/{organization_id}/submissions?status=spam"),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["submissions"][0]["data"]["email"], "bot@example.com");

    // By an answer, which is the containment query the GIN index serves.
    let (status, body) = app
        .get_auth(
            &format!(
                "/api/v1/organizations/{organization_id}/submissions?field=topic&value=Support"
            ),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(
        body["submissions"][0]["data"]["email"],
        "support@example.com"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_submission_can_be_read_marked_and_deleted(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = organization(&app, &owner, "Acme").await;
    let (_, public_id) = published_form(&app, &owner, organization_id).await;
    submit(&app, &public_id, json!({ "email": "person@example.com" })).await;

    let submission_id = app
        .get_auth(
            &format!("/api/v1/organizations/{organization_id}/submissions"),
            &owner,
        )
        .await
        .1["submissions"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let base = format!("/api/v1/organizations/{organization_id}/submissions/{submission_id}");

    let (status, body) = app.get_auth(&base, &owner).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["email"], "person@example.com");

    let (status, body) = app
        .patch_json_auth(&base, json!({ "status": "read" }), &owner)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "read");

    let (status, _) = app.delete_auth(&base, &owner).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(app.get_auth(&base, &owner).await.0, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn submissions_are_scoped_to_their_organization(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let (_, outsider) = account(&app, "outsider@example.com").await;
    let organization_id = organization(&app, &owner, "Acme").await;
    let (_, public_id) = published_form(&app, &owner, organization_id).await;
    submit(&app, &public_id, json!({ "email": "person@example.com" })).await;

    let submission_id = app
        .get_auth(
            &format!("/api/v1/organizations/{organization_id}/submissions"),
            &owner,
        )
        .await
        .1["submissions"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // A non-member sees neither the inbox nor a submission in it.
    let (status, _) = app
        .get_auth(
            &format!("/api/v1/organizations/{organization_id}/submissions"),
            &outsider,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = app
        .get_auth(
            &format!("/api/v1/organizations/{organization_id}/submissions/{submission_id}"),
            &outsider,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // And their own organization cannot reach it either, because the id only resolves within
    // the organization that owns it.
    let other = organization(&app, &outsider, "Other").await;
    let (status, _) = app
        .get_auth(
            &format!("/api/v1/organizations/{other}/submissions/{submission_id}"),
            &outsider,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_member_may_read_but_not_change_a_submission(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let (_, member) = account(&app, "member@example.com").await;
    let organization_id = organization(&app, &owner, "Acme").await;
    let (_, public_id) = published_form(&app, &owner, organization_id).await;
    submit(&app, &public_id, json!({ "email": "person@example.com" })).await;

    app.post_json_auth(
        &format!("/api/v1/organizations/{organization_id}/members"),
        json!({ "email": "member@example.com", "role": "member" }),
        &owner,
    )
    .await;

    let submission_id = app
        .get_auth(
            &format!("/api/v1/organizations/{organization_id}/submissions"),
            &owner,
        )
        .await
        .1["submissions"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let base = format!("/api/v1/organizations/{organization_id}/submissions/{submission_id}");

    assert_eq!(app.get_auth(&base, &member).await.0, StatusCode::OK);
    assert_eq!(
        app.patch_json_auth(&base, json!({ "status": "read" }), &member)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        app.delete_auth(&base, &member).await.0,
        StatusCode::FORBIDDEN
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn an_export_streams_every_answer_including_retired_fields(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = organization(&app, &owner, "Acme").await;
    let (form_id, public_id) = published_form(&app, &owner, organization_id).await;

    submit(
        &app,
        &public_id,
        json!({ "email": "first@example.com", "topic": "Sales" }),
    )
    .await;

    // The definition changes: `topic` goes away and `phone` arrives.
    let (status, _) = app
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
    assert_eq!(status, StatusCode::OK);

    submit(
        &app,
        &public_id,
        json!({ "email": "second@example.com", "phone": "123" }),
    )
    .await;

    let response = app
        .send(json_request(
            Method::GET,
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}/submissions/export"),
            None,
            Some(&owner),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("text/csv; charset=utf-8")
    );
    assert!(
        response
            .headers()
            .get("content-disposition")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("attachment;"))
    );

    let csv = body_text(response).await;
    let mut lines = csv.lines();

    let header = lines.next().expect("a header");
    assert!(header.starts_with("id,created_at,status"), "{header}");
    // The retired key is still a column, so nothing that was collected is lost.
    assert!(header.contains("email"), "{header}");
    assert!(header.contains("topic"), "{header}");
    assert!(header.contains("phone"), "{header}");

    let rows: Vec<&str> = lines.collect();
    assert_eq!(rows.len(), 2);
    // Oldest first, so an export reads chronologically.
    assert!(rows[0].contains("first@example.com"), "{}", rows[0]);
    assert!(rows[0].contains("Sales"), "{}", rows[0]);
    assert!(rows[1].contains("second@example.com"), "{}", rows[1]);
}

#[sqlx::test(migrations = "./migrations")]
async fn an_export_can_be_json(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = organization(&app, &owner, "Acme").await;
    let (form_id, public_id) = published_form(&app, &owner, organization_id).await;
    submit(&app, &public_id, json!({ "email": "person@example.com" })).await;

    let response = app
        .send(json_request(
            Method::GET,
            &format!(
                "/api/v1/organizations/{organization_id}/forms/{form_id}/submissions/export?format=json"
            ),
            None,
            Some(&owner),
        ))
        .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = body_text(response).await;
    let parsed: Value = serde_json::from_str(&body).expect("the export is valid JSON");
    let rows = parsed.as_array().expect("an array");

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["data"]["email"], "person@example.com");
    assert_eq!(rows[0]["status"], "unread");
}

#[sqlx::test(migrations = "./migrations")]
async fn an_empty_export_is_still_well_formed(pool: PgPool) {
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let organization_id = organization(&app, &owner, "Acme").await;
    let (form_id, _) = published_form(&app, &owner, organization_id).await;

    let base =
        format!("/api/v1/organizations/{organization_id}/forms/{form_id}/submissions/export");

    let csv = body_text(
        app.send(json_request(Method::GET, &base, None, Some(&owner)))
            .await,
    )
    .await;
    assert!(csv.starts_with("id,created_at,status"), "{csv}");
    assert_eq!(csv.lines().count(), 1, "just the header: {csv}");

    let json = body_text(
        app.send(json_request(
            Method::GET,
            &format!("{base}?format=json"),
            None,
            Some(&owner),
        ))
        .await,
    )
    .await;
    assert_eq!(json.trim(), "[]", "an empty array, not an unterminated one");
}
