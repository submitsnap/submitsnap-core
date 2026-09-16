pub(crate) mod dto;
mod error;
pub(crate) mod handler;
pub(crate) mod model;
pub(crate) mod public;
mod repository;
mod service;
pub(crate) mod validation;

pub use error::FormError;
pub use model::{FormStatus, SubmissionStatus};
pub use service::FormService;

use axum::{Router, routing::get};

use crate::modules::ApiState;

/// Routes mounted under `/api/v1/organizations/{organization_id}/forms`.
///
/// The organization's own routes live under the same prefix, and the two are merged in
/// `lib.rs`; keeping them in separate modules is what lets `form` depend on `organization`
/// without the reverse.
pub fn router<S>(state: ApiState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/{organization_id}/forms",
            get(handler::list_forms).post(handler::create_form),
        )
        .route(
            "/{organization_id}/forms/{form_id}",
            get(handler::get_form)
                .patch(handler::update_form)
                .delete(handler::delete_form),
        )
        .route(
            "/{organization_id}/forms/{form_id}/publish",
            axum::routing::post(handler::publish_form),
        )
        .route(
            "/{organization_id}/forms/{form_id}/close",
            axum::routing::post(handler::close_form),
        )
        .route(
            "/{organization_id}/forms/{form_id}/public-id",
            axum::routing::post(handler::rotate_public_id),
        )
        .with_state(state)
}

/// Public routes mounted at `/f`. Outside `/api/v1` on purpose: these responses are cacheable
/// and open to every origin, which is not true of anything under the API prefix.
pub fn public_router<S>(state: ApiState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/{public_id}", get(public::definition).post(public::submit))
        .with_state(state)
}
