pub(crate) mod delivery;
pub(crate) mod dto;
mod error;
pub(crate) mod handler;
pub(crate) mod model;
mod repository;
mod service;

pub use delivery::WebhookDeliverer;
pub use error::WebhookError;
pub use model::{DeliveryStatus, MAX_ATTEMPTS};
pub use service::WebhookService;

use axum::{
    Router,
    routing::{get, post},
};

use crate::modules::ApiState;

/// Routes mounted under `/api/v1/organizations`, merged with the organization and form routes
/// in `lib.rs`.
pub fn router<S>(state: ApiState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/{organization_id}/webhook-endpoints",
            get(handler::list_endpoints).post(handler::create_endpoint),
        )
        .route(
            "/{organization_id}/webhook-endpoints/{endpoint_id}",
            get(handler::get_endpoint)
                .patch(handler::update_endpoint)
                .delete(handler::delete_endpoint),
        )
        .route(
            "/{organization_id}/webhook-endpoints/{endpoint_id}/rotate-secret",
            post(handler::rotate_secret),
        )
        .route(
            "/{organization_id}/webhook-deliveries",
            get(handler::list_deliveries),
        )
        .route(
            "/{organization_id}/webhook-deliveries/{delivery_id}/redeliver",
            post(handler::redeliver),
        )
        .with_state(state)
}
