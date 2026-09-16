//! The outbox dispatcher: the one place that answers "a submission arrived, now what?".
//!
//! It lives at the crate root rather than under `modules` because it is where the modules meet:
//! it reads a submission through the form module's tables and hands work to the webhook module.
//! Neither of those modules knows about the other, and neither knows about this.
//!
//! Delivery is **at-least-once**. Every step is ordered so the failure mode is the cheap one:
//! the webhook fan-out runs first and is idempotent, and the email is enqueued last, so nothing
//! re-runs after mail has gone out. A crash in the narrow window between enqueuing and marking
//! the event dispatched can therefore send a notification email twice. That is the deliberate
//! trade: a duplicate notification is a nuisance, a lost one is a bug report.

mod render;
mod repository;

use std::sync::Arc;

use sqlx::PgPool;

use crate::{
    modules::webhook::WebhookService,
    shared::{
        outbox::{CLAIM_LEASE_SECONDS, OutboxEvent, OutboxKind, OutboxRepository, backoff_seconds},
        queue::EmailQueue,
    },
};

use self::repository::{DispatcherRepository, NotificationSource};

pub struct Dispatcher {
    outbox: OutboxRepository,
    sources: DispatcherRepository,
    queue: EmailQueue,
    webhooks: Arc<WebhookService>,
    batch_size: i64,
}

impl Dispatcher {
    pub fn new(
        database: PgPool,
        queue: EmailQueue,
        webhooks: Arc<WebhookService>,
        batch_size: i64,
    ) -> Self {
        Self {
            outbox: OutboxRepository::new(database.clone()),
            sources: DispatcherRepository::new(database),
            queue,
            webhooks,
            batch_size,
        }
    }

    /// Claims and dispatches one batch. Returns how many events were attempted, so a caller can
    /// tell "nothing to do" from "did some work" and sleep accordingly.
    pub async fn run_once(&self) -> anyhow::Result<usize> {
        let events = self
            .outbox
            .claim_due(self.batch_size, CLAIM_LEASE_SECONDS)
            .await?;

        for event in &events {
            match self.dispatch(event).await {
                Ok(()) => {
                    self.outbox.mark_dispatched(event.id).await?;
                }
                Err(error) => {
                    // Put it back with a widening delay rather than dropping it: the work is
                    // still owed, and the error stays on the row for an operator to read.
                    let delay = backoff_seconds(event.attempts);
                    self.outbox
                        .reschedule(event.id, &format!("{error:#}"), delay)
                        .await?;

                    tracing::warn!(
                        event = event.id,
                        kind = ?event.kind,
                        attempts = event.attempts,
                        retry_in_seconds = delay,
                        error = %error,
                        "outbox event could not be dispatched"
                    );
                }
            }
        }

        Ok(events.len())
    }

    async fn dispatch(&self, event: &OutboxEvent) -> anyhow::Result<()> {
        match event.kind {
            OutboxKind::SubmissionReceived => self.dispatch_submission(event).await,
        }
    }

    async fn dispatch_submission(&self, event: &OutboxEvent) -> anyhow::Result<()> {
        let payload = event.submission_received().ok_or_else(|| {
            anyhow::anyhow!("outbox event {} has an unreadable payload", event.id)
        })?;

        let Some(source) = self
            .sources
            .notification_source(payload.submission_id)
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
        else {
            // The submission was deleted before it was dispatched. Retrying would never change
            // that, so the event is settled rather than spun on forever.
            tracing::info!(
                submission = %payload.submission_id,
                "submission no longer exists; nothing to deliver"
            );
            return Ok(());
        };

        self.fan_out_webhooks(&source).await?;
        self.enqueue_emails(&source).await?;

        Ok(())
    }

    async fn fan_out_webhooks(&self, source: &NotificationSource) -> anyhow::Result<()> {
        let payload = render::webhook_payload(source);

        let queued = self
            .webhooks
            .enqueue_deliveries(
                source.organization_id,
                source.form_id,
                source.submission_id,
                &payload,
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;

        if queued > 0 {
            tracing::info!(
                submission = %source.submission_id,
                deliveries = queued,
                "queued webhook deliveries"
            );
        }

        Ok(())
    }

    /// One job per address, enqueued last so a webhook failure cannot cause a second email.
    async fn enqueue_emails(&self, source: &NotificationSource) -> anyhow::Result<()> {
        for recipient in &source.notify_emails {
            let job = render::notification_email(source, recipient);
            self.queue.enqueue(&job).await?;

            tracing::info!(
                submission = %source.submission_id,
                recipient = %recipient,
                "queued a notification email"
            );
        }

        Ok(())
    }
}
