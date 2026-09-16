//! Webhook endpoints and signed delivery.
//!
//! The delivery tests point at a real HTTP server on loopback rather than a mock, because the
//! things worth proving — that the signature verifies, that a non-2xx is retried, that a
//! receiver which never recovers is eventually abandoned — only exist at the socket.

mod common;

use std::sync::{Arc, Mutex};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use common::{PASSWORD, TestApp, access_token, with_worker_config, worker_graph};
use hmac::{Hmac, Mac, digest::KeyInit};
use serde_json::{Value, json};
use sha2::Sha256;
use sqlx::PgPool;
use submitsnap_core::{dispatcher::Dispatcher, modules::webhook::WebhookDeliverer};
use uuid::Uuid;

const SIGNATURE_HEADER: &str = "x-submitsnap-signature";
const TIMESTAMP_HEADER: &str = "x-submitsnap-timestamp";

// ---------------------------------------------------------------------------------------
// A receiver
// ---------------------------------------------------------------------------------------

#[derive(Default, Clone)]
struct Receiver {
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: Arc<Mutex<u16>>,
}

struct Seen {
    headers: HeaderMap,
    body: Vec<u8>,
}

impl Receiver {
    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().drain(..).collect()
    }

    fn answer_with(&self, status: u16) {
        *self.answer.lock().unwrap() = status;
    }

    /// Verifies a request the way a receiver would, using only the headers and the raw body.
    fn signature_of(&self, secret: &str, request: &Seen) -> String {
        sign(
            secret,
            request.headers[TIMESTAMP_HEADER].to_str().unwrap(),
            &request.body,
        )
    }
}

fn sign(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);

    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

async fn spawn_receiver() -> (String, Receiver) {
    let receiver = Receiver {
        seen: Arc::default(),
        answer: Arc::new(Mutex::new(200)),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a port is free");
    let address = listener.local_addr().expect("the listener has an address");

    let router = Router::new()
        .route(
            "/hooks",
            post(
                |State(receiver): State<Receiver>, headers: HeaderMap, body: Bytes| async move {
                    receiver.seen.lock().unwrap().push(Seen {
                        headers,
                        body: body.to_vec(),
                    });

                    let answer = *receiver.answer.lock().unwrap();
                    StatusCode::from_u16(answer).expect("a valid status")
                },
            ),
        )
        .with_state(receiver.clone());

    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    (format!("http://{address}/hooks"), receiver)
}

// ---------------------------------------------------------------------------------------
// A harness that is both the API and the worker
// ---------------------------------------------------------------------------------------

/// Everything a delivery test needs. The API drives the setup, the dispatcher and deliverer
/// drive the work, and they share one database — which is the point.
struct Harness {
    app: TestApp,
    dispatcher: Arc<Dispatcher>,
    deliverer: WebhookDeliverer,
    pool: PgPool,
    owner: String,
    organization_id: Uuid,
    form_id: Uuid,
    public_id: String,
}

impl Harness {
    /// A harness whose endpoints may point at loopback, which is how the receiver is reached.
    async fn new(pool: PgPool) -> Self {
        let (app, config) = with_worker_config(
            vec![("webhook_allow_private_targets", "true".into())],
            pool.clone(),
        );

        let (status, _) = app.register("owner@example.com", PASSWORD).await;
        assert_eq!(status, StatusCode::CREATED);
        let (_, session) = app.login("owner@example.com", PASSWORD).await;
        let owner = access_token(&session);

        let organization_id = app
            .post_json_auth("/api/v1/organizations", json!({ "name": "Acme" }), &owner)
            .await
            .1["id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();

        let (status, form) = app
            .post_json_auth(
                &format!("/api/v1/organizations/{organization_id}/forms"),
                json!({
                    "name": "Contact us",
                    "schema": {
                        "title": "Contact us",
                        "fields": [
                            { "key": "email", "type": "email", "label": "Email", "required": true }
                        ]
                    }
                }),
                &owner,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{form}");

        let form_id: Uuid = form["id"].as_str().unwrap().parse().unwrap();
        let public_id = form["public_id"].as_str().unwrap().to_owned();
        app.post_auth(
            &format!("/api/v1/organizations/{organization_id}/forms/{form_id}/publish"),
            &owner,
        )
        .await;

        let (dispatcher, deliverer, _queue) = worker_graph(&config, pool.clone());

        Self {
            app,
            dispatcher,
            deliverer,
            pool,
            owner,
            organization_id,
            form_id,
            public_id,
        }
    }

    async fn watch(&self, url: &str) -> Value {
        self.watch_opt(url, None).await
    }

    async fn watch_opt(&self, url: &str, form_id: Option<Uuid>) -> Value {
        let mut body = json!({ "url": url });
        if let Some(form_id) = form_id {
            body["form_id"] = json!(form_id);
        }

        let (status, created) = self
            .app
            .post_json_auth(
                &format!(
                    "/api/v1/organizations/{}/webhook-endpoints",
                    self.organization_id
                ),
                body,
                &self.owner,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");

        created
    }

    async fn submit(&self) {
        let (status, body) = self
            .app
            .post_json_auth(
                &format!("/f/{}", self.public_id),
                json!({ "email": "person@example.com" }),
                "",
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
    }

    /// Runs dispatch, then delivery, the way the worker's two loops would.
    async fn work(&self) {
        self.dispatcher.run_once().await.expect("dispatch");
        self.deliverer.run_once().await.expect("delivery");
    }

    async fn delivery(&self) -> (String, i32, Option<i32>, Option<String>, bool) {
        sqlx::query_as(
            "SELECT status::text, attempts, response_status, last_error, next_attempt_at > NOW() \
             FROM webhook_deliveries",
        )
        .fetch_one(&self.pool)
        .await
        .expect("a delivery row")
    }

    /// Makes every queued attempt due now, standing in for the backoff having elapsed.
    async fn elapse_backoff(&self) {
        sqlx::query("UPDATE webhook_deliveries SET next_attempt_at = NOW()")
            .execute(&self.pool)
            .await
            .expect("the schedule is reset");
    }

    async fn delivery_log(&self, filter: &str) -> Value {
        self.app
            .get_auth(
                &format!(
                    "/api/v1/organizations/{}/webhook-deliveries{filter}",
                    self.organization_id
                ),
                &self.owner,
            )
            .await
            .1
    }
}

// ---------------------------------------------------------------------------------------
// Endpoint management
// ---------------------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn the_secret_is_returned_once_and_then_never_listed(pool: PgPool) {
    let harness = Harness::new(pool).await;

    let created = harness.watch("https://example.com/hooks").await;
    let secret = created["secret"].as_str().expect("a secret").to_owned();
    assert!(secret.len() >= 16);

    let (_, listed) = harness
        .app
        .get_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints",
                harness.organization_id
            ),
            &harness.owner,
        )
        .await;

    let endpoint = &listed["endpoints"][0];
    assert!(
        endpoint.get("secret").is_none(),
        "a signing secret that can be listed leaks with a support ticket: {endpoint}"
    );
    assert_eq!(endpoint["url"], "https://example.com/hooks");
    assert_eq!(endpoint["enabled"], true);
    assert!(endpoint["form_id"].is_null(), "null means every form");
}

#[sqlx::test(migrations = "./migrations")]
async fn a_url_that_is_not_usable_is_refused(pool: PgPool) {
    // The harness allows private targets so its receiver is reachable; this test is about the
    // default, so it uses an ordinary app sharing the same database and the same owner.
    let harness = Harness::new(pool.clone()).await;
    let strict = TestApp::new(pool);

    for url in [
        "ftp://example.com/hooks",
        "example.com/hooks",
        "https://",
        // Refused by default: a webhook is fetched by this server, and link-local is where
        // cloud instance credentials live.
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:9000/hooks",
    ] {
        let (status, body) = strict
            .post_json_auth(
                &format!(
                    "/api/v1/organizations/{}/webhook-endpoints",
                    harness.organization_id
                ),
                json!({ "url": url }),
                &harness.owner,
            )
            .await;

        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{url} was accepted: {body}"
        );
    }

    // With the escape hatch on, a receiver on the same host is allowed. That is what the
    // delivery tests rely on, and what a self-hosted deployment would turn on deliberately.
    let (status, body) = harness
        .app
        .post_json_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints",
                harness.organization_id
            ),
            json!({ "url": "http://127.0.0.1:9000/hooks" }),
            &harness.owner,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

#[sqlx::test(migrations = "./migrations")]
async fn an_endpoint_cannot_watch_a_form_from_another_organization(pool: PgPool) {
    let harness = Harness::new(pool).await;

    let (status, _) = harness.app.register("outsider@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, session) = harness.app.login("outsider@example.com", PASSWORD).await;
    let outsider = access_token(&session);

    let (_, other) = harness
        .app
        .post_json_auth(
            "/api/v1/organizations",
            json!({ "name": "Other" }),
            &outsider,
        )
        .await;
    let (_, their_form) = harness
        .app
        .post_json_auth(
            &format!(
                "/api/v1/organizations/{}/forms",
                other["id"].as_str().unwrap()
            ),
            json!({
                "name": "Theirs",
                "schema": {
                    "title": "Theirs",
                    "fields": [{ "key": "a", "type": "text", "label": "A" }]
                }
            }),
            &outsider,
        )
        .await;

    let (status, body) = harness
        .app
        .post_json_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints",
                harness.organization_id
            ),
            json!({
                "url": "https://example.com/hooks",
                "form_id": their_form["id"].as_str().unwrap(),
            }),
            &harness.owner,
        )
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("form_id"),
        "{body}"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rotating_the_secret_replaces_it(pool: PgPool) {
    let harness = Harness::new(pool).await;
    let created = harness.watch("https://example.com/hooks").await;
    let first = created["secret"].as_str().unwrap().to_owned();

    let (status, rotated) = harness
        .app
        .post_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints/{}/rotate-secret",
                harness.organization_id,
                created["id"].as_str().unwrap()
            ),
            &harness.owner,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "{rotated}");
    let second = rotated["secret"].as_str().unwrap();
    assert_ne!(second, first, "the old secret must stop verifying");

    // And the new one is what a delivery is actually signed with.
    let stored: String = sqlx::query_scalar("SELECT secret FROM webhook_endpoints")
        .fetch_one(&harness.pool)
        .await
        .unwrap();
    assert_eq!(stored, second);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_member_may_read_but_not_manage_endpoints(pool: PgPool) {
    let harness = Harness::new(pool).await;
    let created = harness.watch("https://example.com/hooks").await;
    let endpoint_id = created["id"].as_str().unwrap().to_owned();

    let (status, _) = harness.app.register("member@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, session) = harness.app.login("member@example.com", PASSWORD).await;
    let member = access_token(&session);

    harness
        .app
        .post_json_auth(
            &format!("/api/v1/organizations/{}/members", harness.organization_id),
            json!({ "email": "member@example.com", "role": "member" }),
            &harness.owner,
        )
        .await;

    let (read, _) = harness
        .app
        .get_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints/{endpoint_id}",
                harness.organization_id
            ),
            &member,
        )
        .await;
    assert_eq!(read, StatusCode::OK, "reading is a member's business");

    let (created_by_member, _) = harness
        .app
        .post_json_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints",
                harness.organization_id
            ),
            json!({ "url": "https://example.com/other" }),
            &member,
        )
        .await;
    assert_eq!(created_by_member, StatusCode::FORBIDDEN);

    let (deleted, _) = harness
        .app
        .delete_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints/{endpoint_id}",
                harness.organization_id
            ),
            &member,
        )
        .await;
    assert_eq!(deleted, StatusCode::FORBIDDEN);
}

#[sqlx::test(migrations = "./migrations")]
async fn only_the_organization_that_owns_an_endpoint_can_see_it(pool: PgPool) {
    let harness = Harness::new(pool).await;
    let created = harness.watch("https://example.com/hooks").await;
    let endpoint_id = created["id"].as_str().unwrap();

    let (status, _) = harness.app.register("outsider@example.com", PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, session) = harness.app.login("outsider@example.com", PASSWORD).await;
    let outsider = access_token(&session);

    let (_, theirs) = harness
        .app
        .post_json_auth(
            "/api/v1/organizations",
            json!({ "name": "Other" }),
            &outsider,
        )
        .await;
    let theirs = theirs["id"].as_str().unwrap();

    let (forbidden, _) = harness
        .app
        .get_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints/{endpoint_id}",
                harness.organization_id
            ),
            &outsider,
        )
        .await;
    assert_eq!(forbidden, StatusCode::FORBIDDEN);

    // Pairing the endpoint with an organization the caller does belong to must not work either.
    let (missing, _) = harness
        .app
        .get_auth(
            &format!("/api/v1/organizations/{theirs}/webhook-endpoints/{endpoint_id}"),
            &outsider,
        )
        .await;
    assert_eq!(missing, StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------------------
// Fan-out
// ---------------------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn one_delivery_is_queued_per_watching_endpoint(pool: PgPool) {
    let harness = Harness::new(pool).await;

    harness.watch("https://example.com/all").await;
    harness
        .watch_opt("https://example.com/this-one", Some(harness.form_id))
        .await;

    // Disabled, so it must be skipped.
    let disabled = harness.watch("https://example.com/off").await;
    harness
        .app
        .patch_json_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints/{}",
                harness.organization_id,
                disabled["id"].as_str().unwrap()
            ),
            json!({ "enabled": false }),
            &harness.owner,
        )
        .await;

    harness.submit().await;
    assert_eq!(
        harness.dispatcher.run_once().await.unwrap(),
        1,
        "one outbox event"
    );

    let urls: Vec<String> = sqlx::query_scalar(
        "SELECT e.url FROM webhook_deliveries d \
         JOIN webhook_endpoints e ON e.id = d.endpoint_id ORDER BY e.url",
    )
    .fetch_all(&harness.pool)
    .await
    .unwrap();

    assert_eq!(
        urls,
        vec!["https://example.com/all", "https://example.com/this-one"],
        "a disabled endpoint must not be delivered to"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn dispatching_the_same_event_twice_queues_one_delivery(pool: PgPool) {
    let harness = Harness::new(pool).await;
    harness.watch("https://example.com/hooks").await;
    harness.submit().await;

    harness.dispatcher.run_once().await.unwrap();

    // Dispatch is at-least-once: a later step can fail, and then the whole event is retried.
    // A receiver must not be sent the same submission twice because of that.
    sqlx::query("UPDATE outbox_events SET dispatched_at = NULL, available_at = NOW()")
        .execute(&harness.pool)
        .await
        .unwrap();
    harness.dispatcher.run_once().await.unwrap();

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM webhook_deliveries")
        .fetch_one(&harness.pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "the fan-out must be idempotent");
}

// ---------------------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn a_delivery_is_signed_over_the_exact_bytes_that_were_sent(pool: PgPool) {
    let (url, receiver) = spawn_receiver().await;
    let harness = Harness::new(pool).await;
    harness.watch(&url).await;

    harness.submit().await;
    harness.work().await;

    let requests = receiver.requests();
    assert_eq!(requests.len(), 1, "the receiver was called once");
    let request = &requests[0];

    let secret: String = sqlx::query_scalar("SELECT secret FROM webhook_endpoints")
        .fetch_one(&harness.pool)
        .await
        .unwrap();

    // A receiver recomputes the signature from the headers and the raw body it received.
    assert_eq!(
        request.headers[SIGNATURE_HEADER].to_str().unwrap(),
        receiver.signature_of(&secret, request),
        "the signature must verify over the bytes that arrived"
    );

    // The timestamp is inside what was signed, so a captured request cannot be replayed.
    let replayed = sign(&secret, "1", &request.body);
    assert_ne!(
        request.headers[SIGNATURE_HEADER].to_str().unwrap(),
        replayed,
        "a different timestamp must not verify"
    );

    let payload: Value = serde_json::from_slice(&request.body).expect("a JSON body");
    assert_eq!(payload["event"], "submission.received");
    assert_eq!(payload["submission"]["data"]["email"], "person@example.com");
    assert_eq!(payload["form"]["name"], "Contact us");
    assert_eq!(
        request.headers["x-submitsnap-event"].to_str().unwrap(),
        "submission.received"
    );

    let (status, attempts, _, _, _) = harness.delivery().await;
    assert_eq!(status, "delivered");
    assert_eq!(attempts, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_receiver_that_answers_an_error_is_retried(pool: PgPool) {
    let (url, receiver) = spawn_receiver().await;
    receiver.answer_with(500);

    let harness = Harness::new(pool).await;
    harness.watch(&url).await;
    harness.submit().await;
    harness.work().await;

    let (status, attempts, response_status, last_error, retry_later) = harness.delivery().await;

    assert_eq!(status, "pending");
    assert_eq!(attempts, 1);
    assert_eq!(response_status, Some(500));
    assert!(last_error.unwrap().contains("500"));
    assert!(
        retry_later,
        "the next attempt must be scheduled in the future"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_receiver_that_never_recovers_is_eventually_given_up_on(pool: PgPool) {
    let (url, receiver) = spawn_receiver().await;
    receiver.answer_with(500);

    let harness = Harness::new(pool).await;
    harness.watch(&url).await;
    harness.submit().await;
    harness.dispatcher.run_once().await.unwrap();

    for _ in 0..10 {
        harness.elapse_backoff().await;
        harness.deliverer.run_once().await.unwrap();
    }

    let (status, attempts, _, _, _) = harness.delivery().await;
    assert_eq!(status, "failed", "after {attempts} attempts");
    assert_eq!(
        attempts,
        submitsnap_core::modules::webhook::MAX_ATTEMPTS,
        "it stops at the configured ceiling rather than retrying forever"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_failed_delivery_can_be_redelivered_by_hand(pool: PgPool) {
    let (url, receiver) = spawn_receiver().await;
    receiver.answer_with(503);

    let harness = Harness::new(pool).await;
    harness.watch(&url).await;
    harness.submit().await;
    harness.dispatcher.run_once().await.unwrap();

    for _ in 0..10 {
        harness.elapse_backoff().await;
        harness.deliverer.run_once().await.unwrap();
    }
    assert_eq!(harness.delivery().await.0, "failed");

    // The receiver comes back, and an operator reaches for the redeliver button.
    receiver.answer_with(200);
    let delivery_id: Uuid = sqlx::query_scalar("SELECT id FROM webhook_deliveries")
        .fetch_one(&harness.pool)
        .await
        .unwrap();

    let (status, body) = harness
        .app
        .post_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-deliveries/{delivery_id}/redeliver",
                harness.organization_id
            ),
            &harness.owner,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "pending", "queued again, not forgotten");

    harness.deliverer.run_once().await.unwrap();
    assert_eq!(harness.delivery().await.0, "delivered");
}

#[sqlx::test(migrations = "./migrations")]
async fn the_delivery_log_can_be_narrowed(pool: PgPool) {
    let (url, receiver) = spawn_receiver().await;
    receiver.answer_with(500);

    let harness = Harness::new(pool).await;
    harness.watch(&url).await;
    harness.submit().await;
    harness.work().await;

    let everything = harness.delivery_log("").await;
    assert_eq!(everything["total"], 1);
    assert_eq!(everything["deliveries"][0]["response_status"], 500);
    assert_eq!(everything["deliveries"][0]["attempts"], 1);

    assert_eq!(harness.delivery_log("?status=delivered").await["total"], 0);
    assert_eq!(harness.delivery_log("?status=pending").await["total"], 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_removed_endpoint_takes_its_delivery_log_with_it(pool: PgPool) {
    let harness = Harness::new(pool).await;
    let created = harness.watch("https://example.com/hooks").await;
    harness.submit().await;
    harness.dispatcher.run_once().await.unwrap();

    let (status, _) = harness
        .app
        .delete_auth(
            &format!(
                "/api/v1/organizations/{}/webhook-endpoints/{}",
                harness.organization_id,
                created["id"].as_str().unwrap()
            ),
            &harness.owner,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM webhook_deliveries")
        .fetch_one(&harness.pool)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
}
