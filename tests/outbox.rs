//! The outbox row, which is the whole reason a notification cannot be lost.
//!
//! The claim being tested is not that an email is sent — nothing drains the outbox yet — but
//! that the *decision* to deliver is made by the same statement that accepts the submission,
//! and made correctly: skipped when there is nowhere to deliver to, written when there is.

mod common;

use axum::http::StatusCode;
use std::sync::Arc;

use common::{PASSWORD, TestApp, access_token};
use serde_json::json;
use sqlx::PgPool;
use submitsnap_core::shared::{config::AppConfig, queue::EmailQueue};
use uuid::Uuid;

fn schema() -> serde_json::Value {
    json!({
        "title": "Contact us",
        "fields": [{ "key": "email", "type": "email", "label": "Email", "required": true }]
    })
}

async fn owner(app: &TestApp, email: &str) -> String {
    let (status, _) = app.register(email, PASSWORD).await;
    assert_eq!(status, StatusCode::CREATED);

    let (_, session) = app.login(email, PASSWORD).await;
    access_token(&session)
}

async fn organization(app: &TestApp, token: &str) -> Uuid {
    app.post_json_auth("/api/v1/organizations", json!({ "name": "Acme" }), token)
        .await
        .1["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

async fn form(
    app: &TestApp,
    token: &str,
    organization_id: Uuid,
    notify: serde_json::Value,
) -> (Uuid, String) {
    let (status, body) = app
        .post_json_auth(
            &format!("/api/v1/organizations/{organization_id}/forms"),
            json!({ "name": "Contact us", "schema": schema(), "notify_emails": notify }),
            token,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let form_id = body["id"].as_str().unwrap().to_owned();
    app.post_auth(
        &format!("/api/v1/organizations/{organization_id}/forms/{form_id}/publish"),
        token,
    )
    .await;

    (
        Uuid::parse_str(&form_id).unwrap(),
        body["public_id"].as_str().unwrap().to_owned(),
    )
}

async fn submit(app: &TestApp, public_id: &str) {
    let (status, body) = app
        .post_json_auth(
            &format!("/f/{public_id}"),
            json!({ "email": "person@example.com" }),
            "",
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
}

async fn queued(pool: &PgPool) -> Vec<(String, serde_json::Value)> {
    sqlx::query_as("SELECT kind::text, payload FROM outbox_events ORDER BY id")
        .fetch_all(pool)
        .await
        .expect("the outbox is readable")
}

#[sqlx::test(migrations = "./migrations")]
async fn nothing_is_queued_when_there_is_nowhere_to_deliver(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (_, public_id) = form(&app, &token, organization_id, json!([])).await;

    submit(&app, &public_id).await;

    assert!(
        queued(&pool).await.is_empty(),
        "a form nobody is watching should not pay for a queue row"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_notification_address_queues_the_submission(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (form_id, public_id) =
        form(&app, &token, organization_id, json!(["team@example.com"])).await;

    submit(&app, &public_id).await;

    let events = queued(&pool).await;
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].0, "submission_received");
    assert_eq!(events[0].1["form_id"], json!(form_id));

    // The payload names the submission, which is what the dispatcher will need to render it.
    let submission_id = events[0].1["submission_id"]
        .as_str()
        .expect("a submission id");
    let stored: Option<Uuid> = sqlx::query_scalar("SELECT id FROM submissions WHERE id = $1")
        .bind(Uuid::parse_str(submission_id).unwrap())
        .fetch_optional(&pool)
        .await
        .unwrap();
    assert!(
        stored.is_some(),
        "the queued submission must be the one that was stored"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_webhook_alone_is_enough_to_queue_a_submission(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (_, public_id) = form(&app, &token, organization_id, json!([])).await;

    // No HTTP endpoint creates these yet, so the row is placed directly. What is under test is
    // the containment check inside the submission insert, not the API that will feed it.
    sqlx::query("INSERT INTO webhook_endpoints (organization_id, url, secret) VALUES ($1, $2, $3)")
        .bind(organization_id)
        .bind("https://example.com/hooks")
        .bind("a-secret-long-enough-to-pass")
        .execute(&pool)
        .await
        .unwrap();

    submit(&app, &public_id).await;

    assert_eq!(queued(&pool).await.len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_scoped_webhook_belonging_to_another_form_does_not_queue(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (_, public_id) = form(&app, &token, organization_id, json!([])).await;

    // An endpoint bound to a form that is not this one must not drag every submission in the
    // organization through the queue.
    let other = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO forms (organization_id, name, public_id, schema) \
         VALUES ($1, 'Other', 'otherpublic0000000001', $2) RETURNING id",
    )
    .bind(organization_id)
    .bind(sqlx::types::Json(schema()))
    .fetch_one(&pool)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO webhook_endpoints (organization_id, form_id, url, secret) \
         VALUES ($1, $2, $3, $4)",
    )
    .bind(organization_id)
    .bind(other)
    .bind("https://example.com/hooks")
    .bind("a-secret-long-enough-to-pass")
    .execute(&pool)
    .await
    .unwrap();

    submit(&app, &public_id).await;

    assert!(queued(&pool).await.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_disabled_webhook_does_not_queue(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (_, public_id) = form(&app, &token, organization_id, json!([])).await;

    sqlx::query(
        "INSERT INTO webhook_endpoints (organization_id, url, secret, enabled) \
         VALUES ($1, $2, $3, FALSE)",
    )
    .bind(organization_id)
    .bind("https://example.com/hooks")
    .bind("a-secret-long-enough-to-pass")
    .execute(&pool)
    .await
    .unwrap();

    submit(&app, &public_id).await;

    assert!(queued(&pool).await.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn a_spam_submission_is_queued_like_any_other(pool: PgPool) {
    let app = TestApp::new(pool.clone());
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (_, public_id) = form(&app, &token, organization_id, json!(["team@example.com"])).await;

    // Filling the honeypot is recorded, not rejected — the submitter cannot tell, and the
    // organization still gets told, because a spam row is exactly what it filters on.
    let (status, body) = app
        .post_json_auth(
            &format!("/f/{public_id}"),
            json!({ "email": "bot@example.com", "_gotcha": "filled" }),
            "",
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");

    let status: String = sqlx::query_scalar("SELECT status::text FROM submissions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, "spam");
    assert_eq!(queued(&pool).await.len(), 1);
}

// ---------------------------------------------------------------------------------------
// The dispatcher
// ---------------------------------------------------------------------------------------

/// Every dispatch test needs a queue it can actually read, because an enqueue that fails is a
/// failure by design. `with_worker_config` points at the real server under a prefix of its own.
async fn dispatchable(pool: &PgPool) -> (TestApp, Arc<AppConfig>) {
    common::with_worker_config(Vec::new(), pool.clone())
}

/// Registers an account, which queues a verification email. Everything after this starts from
/// an empty queue, so an assertion is about the notification and nothing else.
async fn fresh_queue(config: &AppConfig) -> EmailQueue {
    let queue = common::email_queue(config);
    queue.clear().await.expect("the queue is reachable");
    queue
}

#[sqlx::test(migrations = "./migrations")]
async fn dispatching_settles_the_event_and_queues_the_notification(pool: PgPool) {
    let (app, config) = dispatchable(&pool).await;
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (_, public_id) = form(&app, &token, organization_id, json!(["team@example.com"])).await;

    let queue = fresh_queue(&config).await;
    submit(&app, &public_id).await;
    assert_eq!(queued(&pool).await.len(), 1, "something is owed");

    let (dispatcher, _deliverer, _queue) = common::worker_graph(&config, pool.clone());
    assert_eq!(dispatcher.run_once().await.unwrap(), 1);

    // The event is settled, with no error left behind.
    let (dispatched, last_error): (bool, Option<String>) =
        sqlx::query_as("SELECT dispatched_at IS NOT NULL, last_error FROM outbox_events")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(dispatched, "the event is settled");
    assert!(last_error.is_none());

    // And the message is on the queue, addressed to the form's watcher.
    let job = queue
        .dequeue()
        .await
        .expect("the queue is reachable")
        .expect("a notification was queued");

    assert_eq!(job.to, "team@example.com");
    assert!(
        job.subject.contains("Contact us"),
        "the subject names the form: {}",
        job.subject
    );
    assert!(
        job.text_body.contains("person@example.com"),
        "the body carries the answer: {}",
        job.text_body
    );
    assert_eq!(queue.pending().await.unwrap(), 0, "exactly one message");

    queue.clear().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn a_form_nobody_watches_creates_no_event_and_no_message(pool: PgPool) {
    let (app, config) = dispatchable(&pool).await;
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    // No notification address and no webhook: the form only collects.
    let (_, public_id) = form(&app, &token, organization_id, json!([])).await;

    let queue = fresh_queue(&config).await;
    submit(&app, &public_id).await;

    // The submission statement decides whether work is owed, so a form nobody watches does not
    // pay for a queue row at all — there is nothing to settle later.
    assert!(
        queued(&pool).await.is_empty(),
        "no destination means no event"
    );

    let (dispatcher, _deliverer, _queue) = common::worker_graph(&config, pool.clone());
    assert_eq!(
        dispatcher.run_once().await.unwrap(),
        0,
        "nothing to dispatch"
    );
    assert_eq!(queue.pending().await.unwrap(), 0, "nothing was queued");

    queue.clear().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn an_event_whose_submission_is_gone_is_settled_rather_than_retried(pool: PgPool) {
    let (app, config) = dispatchable(&pool).await;
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (form_id, public_id) =
        form(&app, &token, organization_id, json!(["team@example.com"])).await;

    let queue = fresh_queue(&config).await;
    submit(&app, &public_id).await;

    // The submission is deleted between acceptance and dispatch. Retrying would never change
    // that, so the event must be settled rather than spun on forever.
    sqlx::query("DELETE FROM submissions WHERE form_id = $1")
        .bind(form_id)
        .execute(&pool)
        .await
        .unwrap();

    let (dispatcher, _deliverer, _queue) = common::worker_graph(&config, pool.clone());
    assert_eq!(dispatcher.run_once().await.unwrap(), 1);

    let (dispatched, attempts): (bool, i32) =
        sqlx::query_as("SELECT dispatched_at IS NOT NULL, attempts FROM outbox_events")
            .fetch_one(&pool)
            .await
            .unwrap();

    assert!(dispatched, "a missing target is not worth retrying");
    assert_eq!(attempts, 1, "it was attempted once and settled");
    assert_eq!(queue.pending().await.unwrap(), 0);

    queue.clear().await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn a_queue_that_cannot_be_reached_leaves_the_event_for_later(pool: PgPool) {
    // The ordinary test config, with an unreachable Redis. An enqueue failure must not lose the
    // notification: the event stays owed and comes back.
    let app = TestApp::new(pool.clone());
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (_, public_id) = form(&app, &token, organization_id, json!(["team@example.com"])).await;

    submit(&app, &public_id).await;

    let (dispatcher, _deliverer, _queue) = common::worker_graph(&app.config, pool.clone());
    dispatcher.run_once().await.unwrap();

    let (dispatched, attempts, last_error, retry_later): (bool, i32, Option<String>, bool) =
        sqlx::query_as(
            "SELECT dispatched_at IS NOT NULL, attempts, last_error, available_at > NOW() \
             FROM outbox_events",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

    assert!(!dispatched, "the work is still owed");
    assert_eq!(attempts, 1);
    assert!(last_error.is_some(), "the reason is left on the row");
    assert!(retry_later, "the next attempt is scheduled in the future");
}

#[sqlx::test(migrations = "./migrations")]
async fn claiming_leases_an_event_so_two_workers_do_not_take_it(pool: PgPool) {
    let (app, _config) = dispatchable(&pool).await;
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (_, public_id) = form(&app, &token, organization_id, json!(["team@example.com"])).await;

    submit(&app, &public_id).await;

    let outbox = submitsnap_core::shared::outbox::OutboxRepository::new(pool.clone());

    let first = outbox.claim_due(10, 120).await.unwrap();
    assert_eq!(first.len(), 1, "the first worker takes it");
    assert_eq!(first[0].attempts, 1);

    // The claim pushed `available_at` past the lease, so a second worker — or this same one
    // running immediately — finds nothing. Locking the row instead would hold a database
    // connection open for the length of an SMTP handshake.
    let second = outbox.claim_due(10, 120).await.unwrap();
    assert!(second.is_empty(), "a leased event is not handed out twice");

    // Once the lease has elapsed the work comes back, with the attempt counted.
    sqlx::query("UPDATE outbox_events SET available_at = NOW()")
        .execute(&pool)
        .await
        .unwrap();

    let third = outbox.claim_due(10, 120).await.unwrap();
    assert_eq!(third.len(), 1);
    assert_eq!(third[0].attempts, 2, "the attempt count is kept");
}

#[sqlx::test(migrations = "./migrations")]
async fn the_webhook_fan_out_happens_before_the_email(pool: PgPool) {
    // The queue is deliberately unreachable, so the email step fails. The fan-out must already
    // have happened: it runs first, and it is idempotent where sending mail is not.
    let app = TestApp::with_config(
        vec![("redis_url", "redis://127.0.0.1:1".into())],
        pool.clone(),
    );
    let token = owner(&app, "owner@example.com").await;
    let organization_id = organization(&app, &token).await;
    let (_, public_id) = form(&app, &token, organization_id, json!(["team@example.com"])).await;

    sqlx::query("INSERT INTO webhook_endpoints (organization_id, url, secret) VALUES ($1, $2, $3)")
        .bind(organization_id)
        .bind("https://example.com/hooks")
        .bind("a-secret-long-enough-to-pass")
        .execute(&pool)
        .await
        .unwrap();

    submit(&app, &public_id).await;

    let (dispatcher, _deliverer, _queue) = common::worker_graph(&app.config, pool.clone());
    dispatcher.run_once().await.unwrap();

    let deliveries: i64 =
        sqlx::query_scalar("SELECT count(*) FROM webhook_deliveries WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(deliveries, 1, "the fan-out ran even though mail could not");

    let dispatched: bool = sqlx::query_scalar(
        "SELECT dispatched_at IS NOT NULL FROM outbox_events WHERE organization_id = $1",
    )
    .bind(organization_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        !dispatched,
        "the event stays owed until the mail is queued too"
    );
}
