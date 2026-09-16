use submitsnap_core::shared::{
    config::AppConfig,
    email::EmailClient,
    logging::{self, LogFormat},
    queue::EmailQueue,
};
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let log_format = logging::configured_format();
    logging::init(log_format);

    let config = AppConfig::from_env()?;
    config.log_deployment_warnings();

    let queue = EmailQueue::connect(&config.redis_url)?;
    let email = EmailClient::from_config(&config.email_settings())?;

    if config.uses_smtp() {
        info!(
            smtp_host = %config.smtp_host.as_deref().unwrap_or("unset"),
            smtp_port = config.smtp_port,
            tls = %config.smtp_tls_mode.to_ascii_lowercase(),
            "email worker started, waiting for jobs"
        );
    } else {
        // Every job this worker takes will be acknowledged and dropped, which is fine for
        // development but silently loses mail anywhere else.
        tracing::warn!("EMAIL_PROVIDER is disabled; jobs taken from the queue will be discarded");
    }

    if log_format == LogFormat::Pretty {
        println!("\n  SubmitSnap Core email worker\n  Press Ctrl+C to stop\n");
    }

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
