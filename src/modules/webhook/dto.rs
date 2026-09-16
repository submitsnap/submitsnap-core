use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::modules::webhook::model::{DeliveryFilters, DeliveryStatus};

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateWebhookEndpointRequest {
    /// Must be an absolute `http` or `https` address.
    #[schema(example = "https://example.com/hooks/submitsnap")]
    pub url: String,
    /// Omit to receive every form in the organization.
    #[serde(default)]
    pub form_id: Option<Uuid>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Absent leaves a field alone; `null` clears a nullable one.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateWebhookEndpointRequest {
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// `null` widens the endpoint back to every form in the organization.
    #[serde(default, deserialize_with = "double_option")]
    pub form_id: Option<Option<Uuid>>,
    #[serde(default, deserialize_with = "double_option")]
    pub description: Option<Option<String>>,
}

fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct WebhookEndpointQuery {
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<u32>,
    #[param(minimum = 0)]
    pub offset: Option<u32>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DeliveryQuery {
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<u32>,
    #[param(minimum = 0)]
    pub offset: Option<u32>,
    pub endpoint_id: Option<Uuid>,
    pub status: Option<DeliveryStatus>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl From<&DeliveryQuery> for DeliveryFilters {
    fn from(query: &DeliveryQuery) -> Self {
        Self {
            endpoint_id: query.endpoint_id,
            status: query.status,
            since: query.since,
            until: query.until,
        }
    }
}

/// Never carries the secret. That is returned once, on creation or rotation, and is otherwise
/// unreadable — a signing secret that can be listed is one that leaks with a support ticket.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookEndpointResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    /// `null` means every form in the organization.
    pub form_id: Option<Uuid>,
    pub url: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookEndpointListResponse {
    pub endpoints: Vec<WebhookEndpointResponse>,
    pub total: i64,
}

/// The one response that carries the secret, returned at creation and rotation only.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookSecretResponse {
    pub id: Uuid,
    pub url: String,
    /// Signs `<timestamp>.<body>` with HMAC-SHA256. Store it now: it cannot be read again.
    pub secret: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookDeliveryResponse {
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub submission_id: Option<Uuid>,
    pub status: DeliveryStatus,
    pub attempts: i32,
    /// The receiver's HTTP status, when it answered at all.
    pub response_status: Option<i32>,
    pub last_error: Option<String>,
    pub next_attempt_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub delivered_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct WebhookDeliveryListResponse {
    pub deliveries: Vec<WebhookDeliveryResponse>,
    pub total: i64,
}
