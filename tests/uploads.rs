//! File uploads: the ledger, the streaming enforcement, and streaming the file back out.
//!
//! These tests talk to the MinIO from `compose.yaml`, the same way the dispatch tests talk to the
//! Redis from it. Storage behaviour has to be exercised against a real bucket: the two claims
//! worth protecting — that a refused upload leaves nothing behind, and that an abandoned one can
//! be found again — are both claims about the bucket rather than about the database.

mod common;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request, StatusCode, header},
};
use common::{PASSWORD, TestApp, access_token, read, user_id};
use futures_util::StreamExt as _;
use object_store::{ObjectStore, ObjectStoreExt, aws::AmazonS3Builder, path::Path as ObjectPath};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::net::SocketAddr;
use uuid::Uuid;

const BUCKET: &str = "submitsnap-uploads";
const ENDPOINT: &str = "http://127.0.0.1:9499";
const ACCESS_KEY: &str = "submitsnap";
const SECRET_KEY: &str = "submitsnap-dev-secret";
const TEST_IP: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 12345);

/// A PNG signature followed by a little content. Only the signature is inspected, and the
/// download test requires no more than that the bytes come back unchanged.
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01";

/// A PDF signature, used as bytes that contradict a declared `image/png`.
const PDF: &[u8] = b"%PDF-1.7\n%\xaa\xbb\xcc\xdd\n";

fn storage_settings(extra: Vec<(&str, String)>) -> Vec<(&str, String)> {
    let mut settings = vec![
        ("s3_bucket", BUCKET.to_owned()),
        ("s3_region", "auto".to_owned()),
        ("s3_endpoint", ENDPOINT.to_owned()),
        ("s3_access_key_id", ACCESS_KEY.to_owned()),
        ("s3_secret_access_key", SECRET_KEY.to_owned()),
        ("s3_force_path_style", "true".to_owned()),
        ("rate_limit_per_minute", "100000".to_owned()),
        ("submission_rate_limit_per_minute", "100000".to_owned()),
        (
            "submission_per_form_rate_limit_per_minute",
            "100000".to_owned(),
        ),
    ];
    settings.extend(extra);
    settings
}

fn storage_app(pool: PgPool) -> TestApp {
    TestApp::with_config(storage_settings(Vec::new()), pool)
}

/// One file field capped at 1 KiB accepting only PNG, plus a text field, so the same form can
/// exercise the size limit, the type allowlist, and an ordinary answer.
fn upload_schema() -> Value {
    json!({
        "title": "Expenses",
        "fields": [
            { "key": "note", "type": "text", "label": "Note" },
            {
                "key": "receipt",
                "type": "file",
                "label": "Receipt",
                "max_bytes": 1024,
                "accept": ["image/png"]
            }
        ]
    })
}

/// Deletes everything a test wrote, when the test ends however it ends.
///
/// `#[sqlx::test]` drops the database but not the bucket, and object keys are derived from ids
/// that live in that database. Without this, every run would leave objects behind that no ledger
/// row could ever name again — precisely the leak the ledger exists to prevent, caused by the
/// tests themselves. A guard rather than a call at the end, because a failing test leaves the
/// most debris and is exactly when a teardown line would be skipped.
struct BucketCleanup {
    organization_id: Uuid,
}

impl Drop for BucketCleanup {
    fn drop(&mut self) {
        let organization_id = self.organization_id;

        tokio::spawn(async move {
            let prefix = ObjectPath::from(organization_id.to_string());
            let store = bucket();
            let mut listing = store.list(Some(&prefix));

            while let Some(Ok(item)) = listing.next().await {
                let _ = store.delete(&item.location).await;
            }
        });
    }
}

async fn account(app: &TestApp, email: &str) -> (Uuid, String) {
    let (status, user) = app.register(email, PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED, "{user}");

    let (_, session) = app.login(email, PASSWORD).await;
    (user_id(&user), access_token(&session))
}

/// Creates the organization and hands back a guard that clears this test's objects afterwards.
/// Bind it as `_cleanup`, not `_`: a bare `_` would drop it immediately and clean up nothing.
async fn create_organization(app: &TestApp, token: &str, name: &str) -> (Uuid, BucketCleanup) {
    let (status, body) = app
        .post_json_auth("/api/v1/organizations", json!({ "name": name }), token)
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let organization_id = body["id"].as_str().unwrap().parse().unwrap();

    (organization_id, BucketCleanup { organization_id })
}

/// Creates a form and publishes it, returning its body.
async fn published_form(app: &TestApp, token: &str, organization_id: Uuid) -> Value {
    let (status, form) = app
        .post_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms"),
            json!({ "name": "Expenses", "schema": upload_schema() }),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{form}");

    let (status, published) = app
        .post_auth(
            &format!(
                "/api/v1/organizations/{organization_id}/forms/{}/publish",
                form["id"].as_str().unwrap()
            ),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{published}");

    published
}

/// Sends one upload and reads the response.
async fn upload(
    app: &TestApp,
    public_id: &str,
    field_key: &str,
    filename: &str,
    content_type: &str,
    bytes: &[u8],
) -> (StatusCode, Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!(
            "/f/{public_id}/files/{field_key}?filename={filename}"
        ))
        .header(header::CONTENT_TYPE, content_type)
        .extension(ConnectInfo(TEST_IP))
        .body(Body::from(bytes.to_vec()))
        .expect("request builds");

    read(app.send(request).await).await
}

async fn submit(app: &TestApp, public_id: &str, body: Value) -> (StatusCode, Value) {
    app.post_json(&format!("/f/{public_id}"), body).await
}

/// The bucket, so tests can observe storage directly rather than inferring it from the database.
fn bucket() -> object_store::aws::AmazonS3 {
    AmazonS3Builder::new()
        .with_bucket_name(BUCKET)
        .with_region("auto")
        .with_endpoint(ENDPOINT)
        .with_allow_http(true)
        .with_access_key_id(ACCESS_KEY)
        .with_secret_access_key(SECRET_KEY)
        .with_virtual_hosted_style_request(false)
        .build()
        .expect("the test bucket is configured")
}

/// Every object this form has written, by key.
async fn objects_of(organization_id: Uuid, form_id: Uuid) -> Vec<String> {
    let prefix = ObjectPath::from(format!("{organization_id}/{form_id}"));
    let mut listing = bucket().list(Some(&prefix));

    let mut keys = Vec::new();
    while let Some(item) = listing.next().await {
        keys.push(item.expect("the bucket is listable").location.to_string());
    }

    keys
}

async fn ledger_rows(pool: &PgPool, form_id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM file_uploads WHERE form_id = $1")
        .bind(form_id)
        .fetch_one(pool)
        .await
        .expect("the ledger is readable")
}

#[sqlx::test(migrations = "./migrations")]
async fn an_upload_travels_through_a_submission_and_back_out(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();
    let form_id: Uuid = form["id"].as_str().unwrap().parse().unwrap();

    let (status, uploaded) =
        upload(&app, public_id, "receipt", "receipt.png", "image/png", PNG).await;
    assert_eq!(status, StatusCode::CREATED, "{uploaded}");
    assert_eq!(uploaded["filename"], "receipt.png");
    assert_eq!(uploaded["content_type"], "image/png");
    assert_eq!(uploaded["size"], PNG.len() as i64);

    let key = uploaded["key"].as_str().unwrap();
    assert!(
        key.starts_with(&format!("{organization_id}/{form_id}/")),
        "the key is namespaced to the form: {key}"
    );

    // The key is the answer, and it is recorded with its metadata.
    let (status, accepted) =
        submit(&app, public_id, json!({ "note": "lunch", "receipt": key })).await;
    assert_eq!(status, StatusCode::CREATED, "{accepted}");

    let (status, submission) = app
        .get_auth(
            &format!(
                "/api/v1/organizations/{organization_id}/submissions/{}",
                accepted["id"].as_str().unwrap()
            ),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{submission}");
    assert_eq!(submission["files"]["receipt"]["filename"], "receipt.png");
    assert_eq!(submission["files"]["receipt"]["size"], PNG.len() as i64);

    // And it streams back byte for byte.
    let response = app
        .send(
            Request::builder()
                .method(Method::GET)
                .uri(format!(
                    "/api/v1/organizations/{organization_id}/submissions/{}/files/receipt",
                    accepted["id"].as_str().unwrap()
                ))
                .header(header::AUTHORIZATION, format!("Bearer {owner}"))
                .extension(ConnectInfo(TEST_IP))
                .body(Body::empty())
                .unwrap(),
        )
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "image/png");
    // Never rendered inline, which is what stops an uploaded page from running on this origin.
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .starts_with("attachment;")
    );
    assert_eq!(
        response.headers()[header::X_CONTENT_TYPE_OPTIONS],
        "nosniff"
    );

    let returned = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("the file is readable");
    assert_eq!(returned.as_ref(), PNG);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_file_over_the_field_limit_is_refused_and_leaves_nothing_behind(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();
    let form_id: Uuid = form["id"].as_str().unwrap().parse().unwrap();

    let mut oversized = PNG.to_vec();
    oversized.resize(4096, b'x');

    let (status, body) = upload(
        &app,
        public_id,
        "receipt",
        "big.png",
        "image/png",
        &oversized,
    )
    .await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");

    // What this asserts, precisely: no completed object and no ledger row. Both would appear here
    // if the rejected bytes had been committed instead of discarded — replacing the discard with
    // a completion makes this test fail.
    //
    // It deliberately does NOT assert that the multipart upload was aborted, because an
    // in-progress multipart upload is invisible to a listing; only `AbortIncompleteMultipartUpload`
    // on the bucket reveals it. That half is covered by a lifecycle rule rather than by this test,
    // and for a good reason: a process killed mid-upload never reaches the discard path at all, so
    // the bucket rule is the only mechanism that can catch that case.
    assert!(
        objects_of(organization_id, form_id).await.is_empty(),
        "a refused upload must leave no object behind"
    );
    assert_eq!(ledger_rows(&pool, form_id).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn bytes_that_contradict_the_declared_type_are_refused(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();
    let form_id: Uuid = form["id"].as_str().unwrap().parse().unwrap();

    // A PDF claiming to be a PNG. A declared type is a claim; the signature is evidence.
    let (status, body) = upload(&app, public_id, "receipt", "x.png", "image/png", PDF).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("look like"),
        "{body}"
    );

    assert!(objects_of(organization_id, form_id).await.is_empty());
    assert_eq!(ledger_rows(&pool, form_id).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_type_outside_the_field_allowlist_is_refused(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();

    let (status, body) = upload(&app, public_id, "receipt", "x.pdf", "application/pdf", PDF).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("does not accept"),
        "{body}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_public_id_cannot_be_used_as_a_field(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();

    // `note` is a text field, so it takes no upload.
    let (status, body) = upload(&app, public_id, "note", "x.png", "image/png", PNG).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_submission_cannot_reference_a_file_it_was_never_given(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();

    // A key this server never issued. Storing it would leave a submission pointing at nothing.
    let (status, body) = submit(
        &app,
        public_id,
        json!({ "receipt": format!("{organization_id}/anything/made-up") }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("did not receive"),
        "{body}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_file_uploaded_for_one_field_cannot_answer_another(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;

    let (status, form) = app
        .post_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms"),
            json!({
                "name": "Two files",
                "schema": {
                    "title": "Two files",
                    "fields": [
                        { "key": "first", "type": "file", "label": "First" },
                        { "key": "second", "type": "file", "label": "Second" }
                    ]
                }
            }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{form}");

    let (status, published) = app
        .post_auth(
            &format!(
                "/api/v1/organizations/{organization_id}/forms/{}/publish",
                form["id"].as_str().unwrap()
            ),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{published}");

    let public_id = published["public_id"].as_str().unwrap();

    let (_, uploaded) = upload(&app, public_id, "first", "x.png", "image/png", PNG).await;
    let key = uploaded["key"].as_str().unwrap();

    // Uploaded for `first`, offered as `second`.
    let (status, body) = submit(&app, public_id, json!({ "second": key })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("different field"),
        "{body}"
    );

    // The reference is ignored, not honoured, so the upload is still available for `first`.
    let (status, body) = submit(&app, public_id, json!({ "first": key })).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[sqlx::test(migrations = "./migrations")]
async fn one_upload_cannot_be_claimed_by_two_submissions(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();
    let (_, uploaded) = upload(&app, public_id, "receipt", "x.png", "image/png", PNG).await;
    let key = uploaded["key"].as_str().unwrap();

    let (status, first) = submit(&app, public_id, json!({ "receipt": key })).await;
    assert_eq!(status, StatusCode::CREATED, "{first}");

    let (status, second) = submit(&app, public_id, json!({ "receipt": key })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{second}");
    assert!(
        second["error"]
            .as_str()
            .unwrap_or_default()
            .contains("already used"),
        "{second}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn another_organisation_cannot_download_the_file(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();
    let (_, uploaded) = upload(&app, public_id, "receipt", "x.png", "image/png", PNG).await;

    let (_, accepted) = submit(
        &app,
        public_id,
        json!({ "receipt": uploaded["key"].as_str().unwrap() }),
    )
    .await;

    let (_, outsider) = account(&app, "outsider@example.com").await;

    // The key is unguessable, but that is not what protects it: the submission it belongs to is
    // scoped to an organization the outsider is not a member of.
    let (status, _) = app
        .get_auth(
            &format!(
                "/api/v1/organizations/{organization_id}/submissions/{}/files/receipt",
                accepted["id"].as_str().unwrap()
            ),
            &outsider,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_form_with_a_file_field_cannot_be_published_without_storage(pool: PgPool) {
    // The default test configuration has no bucket, which is the mode a self-hoster without
    // object storage runs in.
    let app = TestApp::new(pool);
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;

    let (status, form) = app
        .post_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms"),
            json!({ "name": "Expenses", "schema": upload_schema() }),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{form}");

    // Storing the definition is fine; the refusal belongs at the moment it would start accepting
    // input, because that is when a file answer would become possible and impossible at once.
    let (status, body) = app
        .post_auth(
            &format!(
                "/api/v1/organizations/{organization_id}/forms/{}/publish",
                form["id"].as_str().unwrap()
            ),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not configured"),
        "{body}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn an_abandoned_upload_is_collected(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();
    let form_id: Uuid = form["id"].as_str().unwrap().parse().unwrap();

    let (status, uploaded) = upload(&app, public_id, "receipt", "x.png", "image/png", PNG).await;
    assert_eq!(status, StatusCode::CREATED, "{uploaded}");
    assert_eq!(objects_of(organization_id, form_id).await.len(), 1);

    // Backdating is what a test can do that a deployment cannot: wait out the grace period.
    sqlx::query("UPDATE file_uploads SET created_at = NOW() - INTERVAL '2 days'")
        .execute(&pool)
        .await
        .expect("the ledger row is aged");

    let forms = common::api_state(&app.config, pool.clone()).forms;
    let collected = forms.reap_abandoned_uploads().await.expect("reaping works");
    assert_eq!(collected, 1, "the unclaimed upload is collected");

    assert!(
        objects_of(organization_id, form_id).await.is_empty(),
        "the object is gone from the bucket"
    );
    assert_eq!(ledger_rows(&pool, form_id).await, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_claimed_upload_is_never_collected(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();
    let form_id: Uuid = form["id"].as_str().unwrap().parse().unwrap();

    let (_, uploaded) = upload(&app, public_id, "receipt", "x.png", "image/png", PNG).await;
    let (status, accepted) = submit(
        &app,
        public_id,
        json!({ "receipt": uploaded["key"].as_str().unwrap() }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{accepted}");

    // Aged well past the grace period, but the submission owns it now.
    sqlx::query("UPDATE file_uploads SET created_at = NOW() - INTERVAL '30 days'")
        .execute(&pool)
        .await
        .expect("the ledger row is aged");

    let forms = common::api_state(&app.config, pool.clone()).forms;
    assert_eq!(
        forms.reap_abandoned_uploads().await.expect("reaping works"),
        0
    );
    assert_eq!(objects_of(organization_id, form_id).await.len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn deleting_a_submission_hands_its_files_back_to_the_reaper(pool: PgPool) {
    let app = storage_app(pool.clone());
    let (_, owner) = account(&app, "owner@example.com").await;
    let (organization_id, _cleanup) = create_organization(&app, &owner, "Acme").await;
    let form = published_form(&app, &owner, organization_id).await;

    let public_id = form["public_id"].as_str().unwrap();
    let form_id: Uuid = form["id"].as_str().unwrap().parse().unwrap();

    let (_, uploaded) = upload(&app, public_id, "receipt", "x.png", "image/png", PNG).await;
    let (_, accepted) = submit(
        &app,
        public_id,
        json!({ "receipt": uploaded["key"].as_str().unwrap() }),
    )
    .await;

    let (status, _) = app
        .delete_auth(
            &format!(
                "/api/v1/organizations/{organization_id}/submissions/{}",
                accepted["id"].as_str().unwrap()
            ),
            &owner,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The files of a deleted submission would otherwise sit in the bucket unreachable, so the
    // foreign key hands them back as unclaimed and the reaper finishes the job.
    sqlx::query("UPDATE file_uploads SET created_at = NOW() - INTERVAL '2 days'")
        .execute(&pool)
        .await
        .expect("the ledger row is aged");

    let forms = common::api_state(&app.config, pool.clone()).forms;
    assert_eq!(
        forms.reap_abandoned_uploads().await.expect("reaping works"),
        1
    );
    assert!(objects_of(organization_id, form_id).await.is_empty());
}
