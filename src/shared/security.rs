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

/// Applies the transport-level protections every deployment should have: a bounded request
/// body, a request deadline, security headers, and an optional CORS allowlist.
pub fn harden<S>(router: Router<S>, config: &AppConfig) -> anyhow::Result<Router<S>>
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

    if let Some(origins) = config.cors_origins() {
        router = router.layer(cors_layer(&origins)?);
    }

    Ok(router)
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

fn cors_layer(origins: &[String]) -> anyhow::Result<CorsLayer> {
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
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(Duration::from_secs(600)))
}
