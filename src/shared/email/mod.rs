mod http;

use std::str::FromStr;

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};

use crate::shared::{config::EmailConfig, queue::EmailJob};

use self::http::{HttpEmailClient, HttpProvider};

#[derive(Clone)]
pub enum EmailClient {
    Disabled,
    Smtp {
        client: AsyncSmtpTransport<Tokio1Executor>,
        from: Mailbox,
    },
    Resend(HttpEmailClient),
    Postmark(HttpEmailClient),
}

impl EmailClient {
    pub fn from_config(config: &EmailConfig) -> anyhow::Result<Self> {
        match config.email_provider.as_str() {
            "disabled" => Ok(Self::Disabled),
            "smtp" => {
                let host = required(&config.smtp_host, "SMTP_HOST")?;
                let from = Mailbox::from_str(required(&config.email_from, "EMAIL_FROM")?)?;
                let mut builder = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?;
                builder = builder.port(config.smtp_port);
                if let (Some(username), Some(password)) =
                    (&config.smtp_username, &config.smtp_password)
                {
                    builder =
                        builder.credentials(Credentials::new(username.clone(), password.clone()));
                }
                Ok(Self::Smtp {
                    client: builder.build(),
                    from,
                })
            }
            "resend" => Ok(Self::Resend(HttpEmailClient::new(
                config,
                HttpProvider::Resend,
            )?)),
            "postmark" => Ok(Self::Postmark(HttpEmailClient::new(
                config,
                HttpProvider::Postmark,
            )?)),
            provider => anyhow::bail!("unsupported EMAIL_PROVIDER: {provider}"),
        }
    }

    pub async fn send(&self, job: &EmailJob) -> anyhow::Result<()> {
        match self {
            Self::Disabled => {
                tracing::warn!(recipient = %job.to, "email provider disabled; message was not delivered");
                Ok(())
            }
            Self::Smtp { client, from } => {
                let message = Message::builder()
                    .from(from.clone())
                    .to(Mailbox::from_str(&job.to)?)
                    .subject(&job.subject)
                    .body(job.text_body.clone())?;
                client.send(message).await?;
                Ok(())
            }
            Self::Resend(client) | Self::Postmark(client) => client.send(job).await,
        }
    }
}

fn required<'a>(value: &'a Option<String>, setting: &str) -> anyhow::Result<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{setting} is required"))
}
