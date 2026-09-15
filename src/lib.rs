pub mod modules;
pub mod shared;

use axum::{Router, middleware::from_fn_with_state, routing::get};
use tower_http::trace::TraceLayer;

use crate::{
    modules::auth,
    shared::{health, middleware::rate_limit, state::AppState},
};

pub fn app(state: AppState) -> Router {
    let auth = auth::AuthState::new(&state);

    Router::new()
        .route("/health", get(health::health_check))
        .nest("/api/v1", Router::new().nest("/auth", auth::router(auth)))
        .layer(from_fn_with_state(state.clone(), rate_limit))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
