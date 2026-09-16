use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    extract::{ConnectInfo, Request, State},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};

use crate::shared::{config::AppConfig, error::AppError};

pub type KeyedLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;

/// Per-client-IP request budgets. Authentication endpoints get tighter budgets than the
/// global default because they are the primary target for credential stuffing.
#[derive(Clone)]
pub struct RateLimiters {
    pub global: Arc<KeyedLimiter>,
    pub login: Arc<KeyedLimiter>,
    pub register: Arc<KeyedLimiter>,
    /// Shared budget for sensitive unauthenticated endpoints: password reset and email
    /// verification.
    pub sensitive: Arc<KeyedLimiter>,
}

impl RateLimiters {
    pub fn from_config(config: &AppConfig) -> Self {
        Self {
            global: per_minute(config.rate_limit_per_minute),
            login: per_minute(config.login_rate_limit_per_minute),
            register: per_hour(config.register_rate_limit_per_hour),
            sensitive: per_hour(config.sensitive_rate_limit_per_hour),
        }
    }
}

/// Applies `limiter` to every route in `router`.
pub fn limit<S>(router: Router<S>, limiter: Arc<KeyedLimiter>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router.layer(middleware::from_fn_with_state(limiter, enforce))
}

async fn enforce(
    State(limiter): State<Arc<KeyedLimiter>>,
    request: Request,
    next: Next,
) -> Response {
    if limiter.check_key(&client_ip(&request)).is_err() {
        return AppError::TooManyRequests.into_response();
    }
    next.run(request).await
}

/// Requests without connection information share a single bucket. Serve the API with
/// `into_make_service_with_connect_info` so real client addresses are always available;
/// forwarded-IP headers are deliberately not trusted because they are spoofable.
fn client_ip(request: &Request) -> IpAddr {
    request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|address| address.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

fn per_minute(limit: u32) -> Arc<KeyedLimiter> {
    Arc::new(RateLimiter::keyed(Quota::per_minute(non_zero(limit))))
}

fn per_hour(limit: u32) -> Arc<KeyedLimiter> {
    let quota = Quota::with_period(Duration::from_secs(60 * 60))
        .unwrap_or_else(|| Quota::per_minute(non_zero(limit)))
        .allow_burst(non_zero(limit));
    Arc::new(RateLimiter::keyed(quota))
}

/// Configuration is validated at startup, so a zero budget cannot reach this point.
fn non_zero(limit: u32) -> NonZeroU32 {
    NonZeroU32::new(limit).unwrap_or(NonZeroU32::MIN)
}
