use std::sync::Arc;

use submitsnap_core::{
    app,
    shared::{
        banner::{self, Startup},
        config::AppConfig,
        db,
        logging::{self, LogFormat},
        queue::EmailQueue,
        state::AppState,
    },
};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let log_format = logging::configured_format();
    logging::init(log_format);

    let config = AppConfig::from_env()?;
    config.log_deployment_warnings();

    let database = db::connect(&config).await?;
    let queue = EmailQueue::connect(&config.redis_url)?;
    let state = AppState::new(Arc::new(config), database, queue);

    let listener = tokio::net::TcpListener::bind(state.config.bind_address()?).await?;
    let address = listener.local_addr()?;

    // Report a broken mail path now rather than at someone's first sign-up.
    let queue_reachable = state.queue.ping().await.is_ok();
    if !queue_reachable {
        tracing::warn!(
            "the email queue is unreachable; verification and reset messages cannot be delivered"
        );
    }

    match log_format {
        LogFormat::Pretty => banner::print(Startup {
            address,
            config: &state.config,
            queue_reachable,
        }),
        LogFormat::Json => info!(%address, queue_reachable, "HTTP server listening"),
    }

    axum::serve(
        listener,
        app(state)?.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}
