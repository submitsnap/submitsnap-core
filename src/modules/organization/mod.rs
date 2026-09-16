pub(crate) mod dto;
mod error;
pub(crate) mod handler;
mod model;
mod repository;
mod service;

pub use error::OrganizationError;
pub use model::OrganizationRole;
pub use service::{Access, OrganizationService};

use axum::{Router, routing::get};

use crate::modules::ApiState;

/// Routes mounted under `/api/v1/organizations`.
pub fn router<S>(state: ApiState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/",
            get(handler::list_organizations).post(handler::create_organization),
        )
        .route(
            "/{id}",
            get(handler::get_organization)
                .patch(handler::rename_organization)
                .delete(handler::delete_organization),
        )
        .route(
            "/{id}/members",
            get(handler::list_members).post(handler::add_member),
        )
        .route(
            "/{id}/members/{user_id}",
            axum::routing::put(handler::set_member_role).delete(handler::remove_member),
        )
        .with_state(state)
}

/// Read-only routes mounted under `/api/v1/admin/organizations`.
///
/// An instance administrator may look but not touch: the mutating organization routes require
/// membership, which the instance role does not grant.
pub fn admin_router<S>(state: ApiState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/organizations", get(handler::admin_list_organizations))
        .route("/organizations/{id}", get(handler::admin_get_organization))
        .with_state(state)
}
