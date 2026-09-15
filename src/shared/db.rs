use sqlx::{PgPool, postgres::PgPoolOptions};

use crate::shared::config::AppConfig;

pub async fn connect(config: &AppConfig) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .connect(&config.database_url)
        .await?;
    Ok(pool)
}
