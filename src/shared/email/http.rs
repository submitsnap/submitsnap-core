use reqwest::Client;
use serde_json::json;

use crate::shared::{config::EmailConfig, queue::EmailJob};

use super::required;

#[derive(Clone)]
pub struct HttpEmailClient {
    client: Client,
    endpoint: String,
    token: String,
    from: String,
    provider: HttpProvider,
}

#[derive(Clone, Copy)]
pub(super) enum HttpProvider {
    Resend,
    Postmark,
}

impl HttpEmailClient {
    pub(super) fn new(config: &EmailConfig, provider: HttpProvider) -> anyhow::Result<Self> {
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

    pub(super) async fn send(&self, job: &EmailJob) -> anyhow::Result<()> {
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
