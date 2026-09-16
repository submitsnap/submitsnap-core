pub(crate) mod dto;
mod error;
pub(crate) mod export;
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
use tower_http::limit::RequestBodyLimitLayer;

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
        .route(
            "/{organization_id}/submissions",
            get(handler::list_submissions),
        )
        .route(
            "/{organization_id}/forms/{form_id}/submissions",
            get(handler::list_form_submissions),
        )
        .route(
            "/{organization_id}/forms/{form_id}/submissions/export",
            get(handler::export_submissions),
        )
        .route(
            "/{organization_id}/submissions/{submission_id}",
            get(handler::get_submission)
                .patch(handler::update_submission)
                .delete(handler::delete_submission),
        )
        .route(
            "/{organization_id}/submissions/{submission_id}/files/{field_key}",
            get(handler::download_submission_file),
        )
        .with_state(state)
}

/// Public routes mounted at `/f`. Outside `/api/v1` on purpose: these responses are cacheable
/// and open to every origin, which is not true of anything under the API prefix.
///
/// `body_limit` is the deployment's ordinary request limit. Uploads need far more than that, so
/// the limit is applied per route here rather than once around the whole router — a layer around
/// everything can only ever be lowered from the inside.
pub fn public_router<S>(state: ApiState, body_limit: usize) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let upload_limit = state.config.upload_max_bytes as usize;

    Router::new()
        .route(
            "/{public_id}",
            get(public::definition)
                .post(public::submit)
                .layer(RequestBodyLimitLayer::new(body_limit)),
        )
        .route(
            "/{public_id}/files/{field_key}",
            axum::routing::post(public::upload).layer(RequestBodyLimitLayer::new(upload_limit)),
        )
        .with_state(state)
}
