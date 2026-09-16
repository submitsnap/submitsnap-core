//! The background worker.
//!
//! Four loops run side by side, and they are deliberately independent: a queue that is down
//! must not stop webhooks from being delivered, and a receiver that is slow must not stop mail.
//!
//! * **email** — drains the Redis queue and talks SMTP.
//! * **outbox** — turns accepted submissions into notifications and webhook deliveries.
//! * **webhooks** — sends those deliveries, signed, with retries.
//! * **uploads** — deletes uploads no submission ever claimed.

use std::sync::Arc;
use std::time::Duration;

use submitsnap_core::{
    dispatcher::Dispatcher,
    modules::{form::FormService, organization::OrganizationService, webhook::WebhookDeliverer},
    shared::{
        config::AppConfig,
        db,
        email::EmailClient,
        logging::{self, LogFormat},
        queue::EmailQueue,
        ratelimit::RateLimiters,
        storage::FileStorage,
    },
};
use tracing::{error, info, warn};

/// How many events or deliveries one pass takes. Small enough that a slow receiver does not
/// hold up everything behind it.
const BATCH_SIZE: i64 = 20;

/// How long a pass sleeps when it found nothing. The alternative would be a poll loop that
/// spins, which is worse for a self-hosted box than a few seconds of latency.
const IDLE_SLEEP: Duration = Duration::from_secs(2);
const ERROR_SLEEP: Duration = Duration::from_secs(5);

/// Abandoned uploads are not urgent, so this loop looks far less often than the others.
const REAP_INTERVAL: Duration = Duration::from_secs(900);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let log_format = logging::configured_format();
    logging::init(log_format);

    let config = Arc::new(AppConfig::from_env()?);
    config.log_deployment_warnings();

    let database = db::connect(&config).await?;
    let queue = EmailQueue::connect(&config.redis_url, &config.redis_key_prefix)?;
    let email = EmailClient::from_config(&config.email_settings())?;

    // The worker builds the same service graph the API does, because it reads the same rows and
    // must apply the same rendering rules. It listens on nothing.
    let identity = Arc::new(submitsnap_core::modules::identity::IdentityService::new(
        database.clone(),
        queue.clone(),
        config.clone(),
    )?);
    let organizations = Arc::new(OrganizationService::new(database.clone(), identity));
    let webhooks = Arc::new(submitsnap_core::modules::webhook::WebhookService::new(
        database.clone(),
        organizations.clone(),
        config.webhook_allow_private_targets,
    ));

    // Built here as well as in the API, because collecting an abandoned upload means talking to
    // the same bucket the API wrote it to.
    let storage = Arc::new(FileStorage::from_config(&config)?);
    let uploads_enabled = storage.is_enabled();
    let forms = Arc::new(FormService::new(
        database.clone(),
        organizations,
        // Never consulted by the reaper, but the service is built the same way on both sides so
        // there is one code path to reason about rather than two.
        RateLimiters::from_config(&config).submissions_per_form,
        storage,
        config.upload_max_bytes,
        config.upload_ttl_hours,
    ));

    let dispatcher = Arc::new(Dispatcher::new(
        database.clone(),
        queue.clone(),
        webhooks.clone(),
        BATCH_SIZE,
    ));
    let deliverer = Arc::new(WebhookDeliverer::new(
        database,
        config.webhook_timeout_seconds,
        BATCH_SIZE,
    )?);

    describe(&config, log_format);

    // A panic in one loop is contained rather than taking the process down with it.
    let mail = tokio::spawn(run_email_loop(queue.clone(), email));
    let outbox = tokio::spawn(run_outbox_loop(dispatcher));
    let webhook = tokio::spawn(run_webhook_loop(deliverer));
    let uploads = tokio::spawn(run_upload_loop(forms, uploads_enabled));

    let _ = tokio::join!(mail, outbox, webhook, uploads);
    Ok(())
}

fn describe(config: &AppConfig, log_format: LogFormat) {
    if config.uses_smtp() {
        info!(
            smtp_host = %config.smtp_host.as_deref().unwrap_or("unset"),
            smtp_port = config.smtp_port,
            tls = %config.smtp_tls_mode.to_ascii_lowercase(),
            "email loop started"
        );
    } else {
        // Every job this loop takes will be acknowledged and dropped, which is fine for
        // development but silently loses mail anywhere else.
        warn!("EMAIL_PROVIDER is disabled; queued mail will be discarded");
    }

    info!(
        timeout_seconds = config.webhook_timeout_seconds,
        "outbox dispatcher and webhook delivery started"
    );

    if log_format == LogFormat::Pretty {
        println!(
            "\n  SubmitSnap Core worker\n\n  \
             loops   email · outbox · webhooks\n  \
             Email   {}\n  \
             Webhooks  {}s timeout\n\n  \
             Press Ctrl+C to stop\n",
            if config.uses_smtp() {
                "SMTP"
            } else {
                "disabled"
            },
            config.webhook_timeout_seconds,
        );
    }
}

async fn run_email_loop(queue: EmailQueue, email: EmailClient) {
    loop {
        match queue.dequeue().await {
            Ok(Some(job)) => {
                if let Err(error) = email.send(&job).await {
                    error!(error = ?error, recipient = %job.to, "email delivery failed");
                    if let Err(error) = queue.dead_letter(&job).await {
                        error!(error = ?error, recipient = %job.to, "failed to dead-letter email");
                    }
                }
            }
            Ok(None) => tokio::time::sleep(IDLE_SLEEP).await,
            Err(error) => {
                error!(error = ?error, "email queue unavailable");
                tokio::time::sleep(ERROR_SLEEP).await;
            }
        }
    }
}

async fn run_outbox_loop(dispatcher: Arc<Dispatcher>) {
    loop {
        match dispatcher.run_once().await {
            Ok(0) => tokio::time::sleep(IDLE_SLEEP).await,
            Ok(_) => {}
            Err(error) => {
                error!(error = ?error, "outbox dispatch failed");
                tokio::time::sleep(ERROR_SLEEP).await;
            }
        }
    }
}

async fn run_webhook_loop(deliverer: Arc<WebhookDeliverer>) {
    loop {
        match deliverer.run_once().await {
            Ok(0) => tokio::time::sleep(IDLE_SLEEP).await,
            Ok(_) => {}
            Err(error) => {
                error!(error = ?error, "webhook delivery failed");
                tokio::time::sleep(ERROR_SLEEP).await;
            }
        }
    }
}

/// Deletes uploads that were written to the bucket but never submitted.
///
/// Someone who attaches a file and then closes the tab leaves an object behind that no submission
/// will ever reference. Nothing else could find it again, so this is what keeps the bucket from
/// growing with files nobody will ever ask for.
async fn run_upload_loop(forms: Arc<FormService>, uploads_enabled: bool) {
    if !uploads_enabled {
        return;
    }

    loop {
        match forms.reap_abandoned_uploads().await {
            Ok(0) => {}
            Ok(collected) => {
                info!(collected, "removed abandoned uploads");
            }
            Err(error) => error!(error = ?error, "collecting abandoned uploads failed"),
        }

        tokio::time::sleep(REAP_INTERVAL).await;
    }
}
