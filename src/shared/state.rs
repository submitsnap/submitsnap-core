use std::sync::Arc;

use sqlx::PgPool;

use crate::shared::{config::AppConfig, queue::EmailQueue, ratelimit::RateLimiters};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub database: PgPool,
    pub queue: EmailQueue,
    pub rate_limiters: RateLimiters,
}

impl AppState {
    pub fn new(config: Arc<AppConfig>, database: PgPool, queue: EmailQueue) -> Self {
        let rate_limiters = RateLimiters::from_config(&config);
        Self {
            config,
            database,
            queue,
            rate_limiters,
        }
    }
}
