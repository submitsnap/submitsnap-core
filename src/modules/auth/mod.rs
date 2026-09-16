pub(crate) mod admin;
pub(crate) mod cookies;
pub(crate) mod dto;
mod error;
mod extractor;
pub(crate) mod handler;
mod service;
mod token;

pub use extractor::AuthenticatedUser;
pub use service::AuthService;

use axum::{Router, routing::get};

use crate::{
    modules::ApiState,
    shared::ratelimit::{RateLimiters, limit},
};

/// The request budgets that apply to this module's routes. Taken from the shared state so the
/// router does not have to know how they were built.
fn limiters(state: &ApiState) -> RateLimiters {
    state.limiters.clone()
}

/// Routes mounted under `/api/v1/auth`.
pub fn router<S>(state: ApiState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let budgets = limiters(&state);

    // Account creation is slow and expensive, so it gets the tightest budget.
    let registration = limit(
        Router::new().route("/register", axum::routing::post(handler::register)),
        budgets.register.clone(),
    );

    // Everything that accepts a credential or a refresh token shares the sign-in budget.
    let sign_in = limit(
        Router::new()
            .route("/login", axum::routing::post(handler::login))
            .route(
                "/dashboard/login",
                axum::routing::post(handler::dashboard_login),
            )
            .route("/refresh", axum::routing::post(handler::refresh)),
        budgets.login.clone(),
    );

    let account = Router::new()
        .route("/logout", axum::routing::post(handler::logout))
        .route("/logout-all", axum::routing::post(handler::logout_all))
        .route("/me", get(handler::me))
        .route(
            "/password/change",
            axum::routing::post(handler::change_password),
        );

    Router::new()
        .merge(registration)
        .merge(sign_in)
        .merge(account)
        .with_state(state)
}

/// Routes mounted under `/api/v1/admin`. Authorization is enforced by the handlers through
/// [`AuthenticatedUser::require_role`].
pub fn admin_router<S>(state: ApiState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/users", get(admin::list_users))
        .route(
            "/users/{id}",
            get(admin::get_user).delete(admin::delete_user),
        )
        .route(
            "/users/{id}/status",
            axum::routing::patch(admin::set_user_status),
        )
        .route(
            "/users/{id}/roles",
            axum::routing::put(admin::set_user_roles),
        )
        .route(
            "/users/{id}/unlock",
            axum::routing::post(admin::unlock_user),
        )
        .route(
            "/users/{id}/sessions",
            axum::routing::delete(admin::revoke_user_sessions),
        )
        .route("/audit-events", get(admin::list_audit_events))
        .with_state(state)
}
