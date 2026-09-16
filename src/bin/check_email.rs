//! Sends a single message through the configured provider.
//!
//! Its purpose is to prove that the SMTP settings in `.env` actually work, without going
//! through registration and waiting on a real user.
//!
//! ```text
//! make check-email TO=you@example.com
//! # or
//! cargo run --bin check_email -- you@example.com
//! ```

use std::env;

use submitsnap_core::shared::{config::AppConfig, email::EmailClient, queue::EmailJob};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let recipient = env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: check_email <recipient@example.com>"))?;

    let config = AppConfig::from_env()?;

    // Refuse rather than report success for a message that was silently dropped.
    if !config.uses_smtp() {
        anyhow::bail!(
            "EMAIL_PROVIDER is {:?}; set it to smtp and configure SMTP_HOST and EMAIL_FROM",
            config.email_provider
        );
    }

    let client = EmailClient::from_config(&config.email_settings())?;
    let job = EmailJob {
        to: recipient.clone(),
        subject: "SubmitSnap SMTP check".into(),
        text_body: "If you are reading this, the configured SMTP settings work.\n".into(),
    };

    client.send(&job).await?;
    println!("Sent a test message to {recipient}");

    Ok(())
}
