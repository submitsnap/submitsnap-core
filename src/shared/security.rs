use std::time::Duration;

use axum::{
    Router,
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
};

use crate::shared::config::AppConfig;

/// Transport-level protections every deployment should have: security headers, a bounded
/// request body, and a request deadline.
///
/// CORS is deliberately *not* applied here. There are two different policies — the API's
/// allowlist and the wide-open one the public form endpoints need — and a single layer over the
/// whole router would let the outer one overwrite the inner one's headers.
pub fn transport<S>(router: Router<S>, config: &AppConfig) -> anyhow::Result<Router<S>>
where
    S: Clone + Send + Sync + 'static,
{
    let mut router = router
        .layer(header_layer(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(header_layer(header::X_FRAME_OPTIONS, "DENY"))
        .layer(header_layer(header::REFERRER_POLICY, "no-referrer"))
        .layer(RequestBodyLimitLayer::new(config.request_body_limit_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(config.request_timeout_seconds),
        ));

    if config.cookie_secure {
        router = router.layer(header_layer(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000; includeSubDomains",
        ));
    }

    Ok(router)
}

/// Applies the deployment's origin allowlist. Meant for the API subtree only, and disabled
/// entirely when no origins are configured.
pub fn api_cors<S>(router: Router<S>, config: &AppConfig) -> anyhow::Result<Router<S>>
where
    S: Clone + Send + Sync + 'static,
{
    match config.cors_origins() {
        Some(origins) => Ok(router.layer(allowlisted(&origins)?)),
        None => Ok(router),
    }
}

/// Opens the public form endpoints to every origin.
///
/// A form is embedded on somebody else's site by design, so its submission arrives cross-origin
/// and the browser refuses it unless the response welcomes that origin. Credentials are not
/// allowed here: these endpoints read no cookie and establish nothing, and asking for
/// credentials together with a wildcard origin is the combination browsers reject outright.
pub fn public_cors<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(
        CorsLayer::new()
            .allow_origin(AllowOrigin::any())
            .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE]),
    )
}

/// Marks a response as non-cacheable. Required for every response that carries or
/// establishes a credential.
pub fn no_store<S>(router: Router<S>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(header_layer(header::CACHE_CONTROL, "no-store"))
}

fn header_layer(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(name, HeaderValue::from_static(value))
}

fn allowlisted(origins: &[String]) -> anyhow::Result<CorsLayer> {
    let origins = origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin)
                .map_err(|error| anyhow::anyhow!("invalid CORS origin {origin:?}: {error}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(Duration::from_secs(600)))
}
