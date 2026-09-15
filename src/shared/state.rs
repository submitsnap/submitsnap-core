use std::{net::IpAddr, num::NonZeroU32, sync::Arc};

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DashMapStateStore};
use sqlx::PgPool;

use crate::shared::{config::AppConfig, queue::EmailQueue};

pub type RequestLimiter = RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub database: PgPool,
    pub queue: EmailQueue,
    pub request_limiter: Arc<RequestLimiter>,
}

impl AppState {
    pub fn new(config: Arc<AppConfig>, database: PgPool, queue: EmailQueue) -> Self {
        let quota = Quota::per_minute(
            NonZeroU32::new(config.rate_limit_per_minute).unwrap_or(NonZeroU32::MIN),
        );
        Self {
            config,
            database,
            queue,
            request_limiter: Arc::new(RateLimiter::keyed(quota)),
        }
    }
}
