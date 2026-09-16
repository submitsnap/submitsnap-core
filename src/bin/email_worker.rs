use submitsnap_core::shared::{config::AppConfig, email::EmailClient, queue::EmailQueue};
use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let config = AppConfig::from_env()?;
    config.log_deployment_warnings();
    let queue = EmailQueue::connect(&config.redis_url)?;
    let email = EmailClient::from_config(&config.email_settings())?;
    info!("email worker started");

    loop {
        match queue.dequeue().await {
            Ok(Some(job)) => {
                if let Err(error) = email.send(&job).await {
                    error!(error = ?error, recipient = %job.to, "email delivery failed");
                    if let Err(error) = queue.dead_letter(&job).await {
                        error!(error = ?error, recipient = %job.to, "failed to dead-letter email job");
                    }
                }
            }
            Ok(None) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
            Err(error) => {
                error!(error = ?error, "email queue unavailable");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}
