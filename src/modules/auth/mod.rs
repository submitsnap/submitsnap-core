mod dto;
mod error;
mod extractor;
mod handler;
mod repository;
mod service;

pub use dto::PublicUser;
pub use extractor::AuthenticatedUser;

use axum::{
    Router,
    routing::{get, post},
};

use crate::shared::state::AppState;

use self::{repository::UserRepository, service::AuthService};

#[derive(Clone)]
pub struct AuthState {
    service: AuthService,
    cookie_secure: bool,
}

impl AuthState {
    pub fn new(shared: &AppState) -> Self {
        Self {
            service: AuthService::new(
                UserRepository::new(shared.database.clone()),
                shared.queue.clone(),
                &shared.config.jwt_secret,
                shared.config.jwt_issuer.clone(),
            ),
            cookie_secure: shared.config.cookie_secure,
        }
    }
}

pub fn router<S>(state: AuthState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/register", post(handler::register))
        .route("/login", post(handler::login))
        .route("/dashboard/login", post(handler::dashboard_login))
        .route("/me", get(handler::me))
        .with_state(state)
}
