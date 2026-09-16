pub mod dispatcher;
pub mod modules;
pub mod openapi;
pub mod shared;

use axum::{Router, routing::get};
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};
use utoipa::OpenApi as _;
use utoipa_swagger_ui::SwaggerUi;

use crate::{
    modules::{
        ApiState,
        auth::{admin_router as auth_admin_router, router as auth_router},
        form::{public_router as form_public_router, router as form_router},
        identity::router as identity_router,
        organization::{admin_router as organization_admin_router, router as organization_router},
        webhook::router as webhook_router,
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

    // Organizations, their forms, and their webhooks share a prefix but live in separate
    // modules, which is what keeps the dependency running one way: form and webhook know about
    // organization, not the reverse, and neither knows about the other.
    let organizations = organization_router(api_state.clone())
        .merge(form_router(api_state.clone()))
        .merge(webhook_router(api_state.clone()));

    let api = Router::new()
        .nest("/auth", auth_router(api_state.clone()))
        .nest("/identity", identity_router(api_state.clone()))
        .nest("/organizations", organizations)
        .nest("/admin", administration);

    // Everything under the API can return or establish a credential, and every one of its routes
    // takes a small JSON body.
    let api = api.layer(RequestBodyLimitLayer::new(
        state.config.request_body_limit_bytes,
    ));
    let api = security::no_store(api);
    let api = security::api_cors(api, &state.config)?;

    // The public form endpoints are a different contract: cacheable, open to every origin, and
    // holding their own tighter budget. Their one large-body route raises the limit itself.
    let public = form_public_router(api_state, state.config.request_body_limit_bytes);
    let public = security::public_cors(public);
    let public = ratelimit::limit(public, state.rate_limiters.submissions.clone());

    let mut router = Router::new()
        .route("/health", get(health::health_check))
        .nest("/api/v1", api)
        .nest("/f", public);

    if state.config.api_docs_enabled {
        // The Swagger UI serves both its own assets and the document at
        // `/api-docs/openapi.json`, so no separate route is registered here.
        router = router.merge(
            SwaggerUi::new("/docs").url("/api-docs/openapi.json", openapi::ApiDoc::openapi()),
        );
    }

    let router = security::transport(router, &state.config)?;
    let router = ratelimit::limit(router, state.rate_limiters.global.clone());

    Ok(router.layer(TraceLayer::new_for_http()).with_state(state))
}
