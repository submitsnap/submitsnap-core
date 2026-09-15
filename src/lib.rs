pub mod auth;
pub mod config;
pub mod email;
pub mod error;
pub mod queue;
pub mod state;

mod handlers;
mod middleware;
mod models;

use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{get, post},
};
use handlers::{dashboard_login, health_check, login, me, register};
use middleware::rate_limit;
use state::AppState;
use tower_http::trace::TraceLayer;

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .nest(
            "/api/v1",
            Router::new()
                .route("/auth/register", post(register))
                .route("/auth/login", post(login))
                .route("/auth/dashboard/login", post(dashboard_login))
                .route("/auth/me", get(me)),
        )
        .layer(from_fn_with_state(state.clone(), rate_limit))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
