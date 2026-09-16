//! The outbox: work that must happen after a request has already been answered.
//!
//! A submission is accepted and its notification is owed in the *same* statement, so the two
//! cannot disagree. This half is pure infrastructure — it reserves rows and tracks attempts
//! without knowing what an event means. Interpreting them is the dispatcher's job.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::{FromRow, PgPool, types::Json};
use uuid::Uuid;

/// What an outbox row asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "outbox_kind", rename_all = "snake_case")]
pub enum OutboxKind {
    SubmissionReceived,
}

/// The payload of a [`OutboxKind::SubmissionReceived`] event. Ids rather than a copy of the
/// data: the dispatcher reads the submission when it runs, so a long backlog never delivers a
/// stale answer.
#[derive(Debug, Clone, Deserialize)]
pub struct SubmissionReceived {
    pub form_id: Uuid,
    pub submission_id: Uuid,
}

#[derive(Debug, Clone, FromRow)]
pub struct OutboxEvent {
    pub id: i64,
    pub organization_id: Uuid,
    pub kind: OutboxKind,
    pub payload: Json<serde_json::Value>,
    /// Already incremented by the claim that produced this row.
    pub attempts: i32,
    pub created_at: DateTime<Utc>,
}

impl OutboxEvent {
    /// The typed payload, or `None` when it cannot be read — which happens only if a producer
    /// wrote a shape this version does not know.
    pub fn submission_received(&self) -> Option<SubmissionReceived> {
        serde_json::from_value(self.payload.0.clone()).ok()
    }
}

#[derive(Clone)]
pub struct OutboxRepository {
    database: PgPool,
}

impl OutboxRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    /// Reserves up to `limit` due events by moving `available_at` past a lease window.
    ///
    /// One statement, so several workers can run at once: the loser of a race finds the row
    /// already pushed out of range rather than locking it. The work itself is not done inside a
    /// transaction on purpose — an SMTP handshake can take seconds, and rolling the attempt
    /// count back on a crash would turn a poison message into an infinite loop.
    pub async fn claim_due(
        &self,
        limit: i64,
        lease_seconds: i32,
    ) -> Result<Vec<OutboxEvent>, sqlx::Error> {
        sqlx::query_as::<_, OutboxEvent>(
            "UPDATE outbox_events AS e \
             SET attempts = e.attempts + 1, \
                 available_at = NOW() + ($2 * INTERVAL '1 second') \
             WHERE e.id IN ( \
                 SELECT id FROM outbox_events \
                 WHERE dispatched_at IS NULL AND available_at <= NOW() \
                 ORDER BY available_at, id \
                 LIMIT $1 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING e.id, e.organization_id, e.kind, e.payload, e.attempts, e.created_at",
        )
        .bind(limit)
        .bind(lease_seconds)
        .fetch_all(&self.database)
        .await
    }

    pub async fn mark_dispatched(&self, id: i64) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE outbox_events SET dispatched_at = NOW(), last_error = NULL WHERE id = $1",
        )
        .bind(id)
        .execute(&self.database)
        .await?;

        Ok(())
    }

    /// Schedules the next attempt. The row is never dropped: the work is still owed, so it
    /// keeps coming back at a widening interval and the error is left on the row for an
    /// operator to find.
    pub async fn reschedule(
        &self,
        id: i64,
        error: &str,
        delay_seconds: i32,
    ) -> Result<(), sqlx::Error> {
        // Truncated so one runaway message cannot fill the column.
        let error: String = error.chars().take(500).collect();

        sqlx::query(
            "UPDATE outbox_events \
             SET available_at = NOW() + ($2 * INTERVAL '1 second'), last_error = $3 \
             WHERE id = $1",
        )
        .bind(id)
        .bind(delay_seconds)
        .bind(error)
        .execute(&self.database)
        .await?;

        Ok(())
    }

    /// Events still owed. Exposed for the health of a deployment rather than for the API.
    pub async fn pending_count(&self) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar("SELECT count(*) FROM outbox_events WHERE dispatched_at IS NULL")
            .fetch_one(&self.database)
            .await
    }
}

/// The delay before the next attempt, widening with each failure and capped so a permanently
/// broken destination is retried roughly hourly rather than never.
pub fn backoff_seconds(attempts: i32) -> i32 {
    match attempts {
        0 | 1 => 5,
        2 => 30,
        3 => 120,
        4 => 600,
        _ => 3600,
    }
}

/// How long a claimed event is invisible to other workers.
pub const CLAIM_LEASE_SECONDS: i32 = 120;

/// The most a notification body is allowed to grow.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_widens_and_then_stops_growing() {
        assert_eq!(backoff_seconds(1), 5);
        assert_eq!(backoff_seconds(2), 30);
        assert_eq!(backoff_seconds(3), 120);
        assert_eq!(backoff_seconds(4), 600);
        assert_eq!(
            backoff_seconds(50),
            3600,
            "a broken destination still retries"
        );
    }

    #[test]
    fn an_unreadable_payload_is_reported_rather_than_guessed() {
        let event = OutboxEvent {
            id: 1,
            organization_id: Uuid::nil(),
            kind: OutboxKind::SubmissionReceived,
            payload: Json(serde_json::json!({ "unexpected": true })),
            attempts: 1,
            created_at: Utc::now(),
        };

        assert!(event.submission_received().is_none());
    }

    #[test]
    fn a_well_formed_payload_is_read() {
        let form_id = Uuid::new_v4();
        let submission_id = Uuid::new_v4();
        let event = OutboxEvent {
            id: 1,
            organization_id: Uuid::nil(),
            kind: OutboxKind::SubmissionReceived,
            payload: Json(serde_json::json!({
                "form_id": form_id,
                "submission_id": submission_id,
            })),
            attempts: 1,
            created_at: Utc::now(),
        };

        let parsed = event.submission_received().expect("a readable payload");
        assert_eq!(parsed.form_id, form_id);
        assert_eq!(parsed.submission_id, submission_id);
    }
}
