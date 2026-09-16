pub mod modules;
pub mod openapi;
pub mod shared;

use axum::{Router, routing::get};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi as _;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    modules::{
        ApiState,
        auth::{admin_router as auth_admin_router, router as auth_router},
        identity::router as identity_router,
        organization::{admin_router as organization_admin_router, router as organization_router},
    },
    shared::{health, ratelimit, security, state::AppState},
};

/// Builds the HTTP application.
///
/// Fails when the process configuration or the CORS allowlist cannot be turned into a valid
/// service, so a misconfigured deployment stops at startup instead of at the first request.
pub fn app(state: AppState) -> anyhow::Result<Router> {
    let api_state = ApiState::new(
        state.database.clone(),
        state.queue.clone(),
        state.config.clone(),
        state.rate_limiters.clone(),
    )?;

    // Every administrative route lives behind one prefix, whether it manages accounts or
    // organizations, so the surface is easy to reason about and to lock down.
    let administration =
        auth_admin_router(api_state.clone()).merge(organization_admin_router(api_state.clone()));

    let api = Router::new()
        .nest("/auth", auth_router(api_state.clone()))
        .nest("/identity", identity_router(api_state.clone()))
        .nest("/organizations", organization_router(api_state))
        .nest("/admin", administration);

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
