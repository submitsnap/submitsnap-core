use std::sync::Arc;

use submitsnap_core::{
    app,
    shared::{config::AppConfig, db, queue::EmailQueue, state::AppState},
};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let config = AppConfig::from_env()?;
    let database = db::connect(&config).await?;
    let queue = EmailQueue::connect(&config.redis_url)?;
    let state = AppState::new(Arc::new(config), database, queue);
    let bind_address = state.config.bind_address()?;
    let listener = tokio::net::TcpListener::bind(bind_address).await?;

    info!(address = %bind_address, "HTTP server listening");
    axum::serve(
        listener,
        app(state)?.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "submitsnap_core=debug,tower_http=info".into());

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}
