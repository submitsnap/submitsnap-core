use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, types::Json};
use utoipa::ToSchema;
use uuid::Uuid;

/// Columns selected whenever an endpoint is loaded. The secret is deliberately absent: it is
/// handed out once, at creation or rotation, and never again.
pub const ENDPOINT_COLUMNS: &str = "id, organization_id, form_id, url, description, enabled, \
     created_at, updated_at";

pub const DELIVERY_COLUMNS: &str = "id, organization_id, endpoint_id, submission_id, status, \
     attempts, response_status, last_error, next_attempt_at, created_at, delivered_at";

/// How many failed attempts before a delivery is given up on. The log keeps every one, and a
/// human can redeliver by hand, so giving up is safe.
pub const MAX_ATTEMPTS: i32 = 6;

/// How long a claimed delivery is invisible to other workers.
pub const CLAIM_LEASE_SECONDS: i32 = 120;

/// The event name receivers switch on.
pub const SUBMISSION_RECEIVED_EVENT: &str = "submission.received";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "webhook_delivery_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum DeliveryStatus {
    Pending,
    Delivered,
    /// Given up on after [`MAX_ATTEMPTS`]. It stays in the log so it can be redelivered.
    Failed,
}

#[derive(Debug, Clone, FromRow)]
pub struct WebhookEndpointRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub form_id: Option<Uuid>,
    pub url: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct WebhookDeliveryRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub endpoint_id: Uuid,
    pub submission_id: Option<Uuid>,
    pub status: DeliveryStatus,
    pub attempts: i32,
    pub response_status: Option<i32>,
    pub last_error: Option<String>,
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

/// A delivery reserved for sending, joined with everything the request needs so the send is
/// one statement followed by one HTTP call.
#[derive(Debug, Clone, FromRow)]
pub struct ClaimedDelivery {
    pub id: Uuid,
    pub url: String,
    pub secret: String,
    pub payload: Json<serde_json::Value>,
    /// Already incremented by the claim that produced this row.
    pub attempts: i32,
}

/// Narrowing applied when reading the delivery log.
#[derive(Debug, Clone, Default)]
pub struct DeliveryFilters {
    pub endpoint_id: Option<Uuid>,
    pub status: Option<DeliveryStatus>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

/// The delay before the next attempt. Widening rather than fixed, so a receiver that is down
/// for a minute is not hammered, and one that is down for an hour is still reached.
pub fn backoff_seconds(attempts: i32) -> i32 {
    match attempts {
        0 | 1 => 10,
        2 => 60,
        3 => 300,
        4 => 1800,
        _ => 7200,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_backoff_widens() {
        assert_eq!(backoff_seconds(1), 10);
        assert_eq!(backoff_seconds(2), 60);
        assert_eq!(backoff_seconds(3), 300);
        assert_eq!(backoff_seconds(4), 1800);
        assert_eq!(backoff_seconds(5), 7200);
    }
}
