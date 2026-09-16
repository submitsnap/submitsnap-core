pub(crate) mod cookies;
pub(crate) mod dto;
mod error;
mod extractor;
pub(crate) mod handler;
mod service;
mod token;

pub use extractor::AuthenticatedUser;

use std::sync::Arc;

use axum::{
    Router,
    routing::{get, patch, post},
};
use sqlx::PgPool;

use crate::{
    modules::identity::IdentityService,
    shared::{
        config::AppConfig,
        ratelimit::{RateLimiters, limit},
    },
};

/// Shared state for the authentication routes and the `AuthenticatedUser` extractor.
#[derive(Clone)]
pub struct AuthState {
    pub service: Arc<service::AuthService>,
    pub identity: Arc<IdentityService>,
    pub config: Arc<AppConfig>,
    pub limiters: RateLimiters,
}

impl AuthState {
    pub fn new(
        identity: Arc<IdentityService>,
        database: PgPool,
        config: Arc<AppConfig>,
        limiters: RateLimiters,
    ) -> Self {
        let service = Arc::new(service::AuthService::new(
            identity.clone(),
            database,
            config.clone(),
        ));

        Self {
            service,
            identity,
            config,
            limiters,
        }
    }
}

/// Routes mounted under `/api/v1/auth`.
pub fn router<S>(state: AuthState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    // Account creation is slow and expensive, so it gets the tightest budget.
    let registration = limit(
        Router::new().route("/register", post(handler::register)),
        state.limiters.register.clone(),
    );

    // Everything that accepts a credential or a refresh token shares the sign-in budget.
    let sign_in = limit(
        Router::new()
            .route("/login", post(handler::login))
            .route("/dashboard/login", post(handler::dashboard_login))
            .route("/refresh", post(handler::refresh)),
        state.limiters.login.clone(),
    );

    let account = Router::new()
        .route("/logout", post(handler::logout))
        .route("/logout-all", post(handler::logout_all))
        .route("/me", get(handler::me))
        .route("/password/change", post(handler::change_password));

    Router::new()
        .merge(registration)
        .merge(sign_in)
        .merge(account)
        .with_state(state)
}

/// Routes mounted under `/api/v1/admin`. Authorization is enforced by the handlers through
/// [`AuthenticatedUser::require_role`].
pub fn admin_router<S>(state: AuthState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/users", get(handler::list_users))
        .route("/users/{id}/status", patch(handler::set_user_status))
        .with_state(state)
}
