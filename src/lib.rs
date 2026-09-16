pub mod modules;
pub mod openapi;
pub mod shared;

use std::sync::Arc;

use axum::{Router, routing::get};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi as _;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    modules::{
        auth::{AuthState, admin_router, router as auth_router},
        identity::{IdentityService, IdentityState, router as identity_router},
    },
    shared::{health, ratelimit, security, state::AppState},
};

/// Builds the HTTP application.
///
/// Fails when the process configuration or the CORS allowlist cannot be turned into a valid
/// service, so a misconfigured deployment stops at startup instead of at the first request.
pub fn app(state: AppState) -> anyhow::Result<Router> {
    let identity = Arc::new(IdentityService::new(
        state.database.clone(),
        state.queue.clone(),
        state.config.clone(),
    )?);

    let auth_state = AuthState::new(
        identity.clone(),
        state.database.clone(),
        state.config.clone(),
        state.rate_limiters.clone(),
    );

    let identity_state = IdentityState {
        service: identity,
        limiters: state.rate_limiters.clone(),
    };

    let api = Router::new()
        .nest("/auth", auth_router(auth_state.clone()))
        .nest("/identity", identity_router(identity_state))
        .nest("/admin", admin_router(auth_state));

    // Everything under the API can return or establish a credential.
    let api = security::no_store(api);

    let mut router = Router::new()
        .route("/health", get(health::health_check))
        .nest("/api/v1", api);

    if state.config.api_docs_enabled {
        // The Swagger UI serves both its own assets and the document at
        // `/api-docs/openapi.json`, so no separate route is registered here.
        router = router.merge(
            SwaggerUi::new("/docs").url("/api-docs/openapi.json", openapi::ApiDoc::openapi()),
        );
    }

    let router = security::harden(router, &state.config)?;
    let router = ratelimit::limit(router, state.rate_limiters.global.clone());

    Ok(router.layer(TraceLayer::new_for_http()).with_state(state))
}
