use std::str::FromStr;

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use reqwest::Client;
use serde_json::json;

use crate::{config::EmailConfig, queue::EmailJob};

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

#[derive(Clone)]
pub struct HttpEmailClient {
    client: Client,
    endpoint: String,
    token: String,
    from: String,
    provider: HttpProvider,
}

#[derive(Clone, Copy)]
pub enum HttpProvider {
    Resend,
    Postmark,
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

impl HttpEmailClient {
    fn new(config: &EmailConfig, provider: HttpProvider) -> anyhow::Result<Self> {
        let base_url = config
            .email_api_base_url
            .as_deref()
            .unwrap_or(match provider {
                HttpProvider::Resend => "https://api.resend.com",
                HttpProvider::Postmark => "https://api.postmarkapp.com",
            });
        let endpoint = match provider {
            HttpProvider::Resend => format!("{}/emails", base_url.trim_end_matches('/')),
            HttpProvider::Postmark => format!("{}/email", base_url.trim_end_matches('/')),
        };
        Ok(Self {
            client: Client::new(),
            endpoint,
            token: required(&config.email_api_token, "EMAIL_API_TOKEN")?.to_owned(),
            from: required(&config.email_from, "EMAIL_FROM")?.to_owned(),
            provider,
        })
    }

    async fn send(&self, job: &EmailJob) -> anyhow::Result<()> {
        let request = match self.provider {
            HttpProvider::Resend => self.client.post(&self.endpoint)
                .bearer_auth(&self.token)
                .json(&json!({ "from": self.from, "to": [job.to], "subject": job.subject, "text": job.text_body })),
            HttpProvider::Postmark => self.client.post(&self.endpoint)
                .header("X-Postmark-Server-Token", &self.token)
                .json(&json!({ "From": self.from, "To": job.to, "Subject": job.subject, "TextBody": job.text_body })),
        };
        request.send().await?.error_for_status()?;
        Ok(())
    }
}

fn required<'a>(value: &'a Option<String>, setting: &str) -> anyhow::Result<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{setting} is required"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[tokio::test]
    async fn resend_client_sends_expected_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/emails"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = HttpEmailClient {
            client: Client::new(),
            endpoint: format!("{}/emails", server.uri()),
            token: "test-token".into(),
            from: "test@example.com".into(),
            provider: HttpProvider::Resend,
        };
        client
            .send(&EmailJob {
                to: "recipient@example.com".into(),
                subject: "Hello".into(),
                text_body: "World".into(),
            })
            .await
            .unwrap();
    }
}
