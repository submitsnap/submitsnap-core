//! Signed delivery, and the retry policy around it.
//!
//! A receiver verifies two headers: `X-SubmitSnap-Timestamp` and `X-SubmitSnap-Signature`. The
//! signature covers `<timestamp>.<raw body>`, so a captured request cannot be replayed later —
//! the timestamp is inside what was signed. Receivers should reject anything older than a few
//! minutes.
//!
//! The body is sent as the exact bytes that were signed. Re-serializing the payload at send
//! time would be a subtly different string and break every signature.

use std::time::Duration;

use hmac::{Hmac, Mac, digest::KeyInit};
use serde_json::Value;
use sha2::Sha256;
use sqlx::PgPool;

use crate::modules::webhook::{
    model::{CLAIM_LEASE_SECONDS, ClaimedDelivery, backoff_seconds},
    repository::WebhookRepository,
};

pub const SIGNATURE_HEADER: &str = "x-submitsnap-signature";
pub const TIMESTAMP_HEADER: &str = "x-submitsnap-timestamp";
pub const DELIVERY_HEADER: &str = "x-submitsnap-delivery";
pub const EVENT_HEADER: &str = "x-submitsnap-event";

const USER_AGENT: &str = concat!("SubmitSnap-Core/", env!("CARGO_PKG_VERSION"));

/// Computes the value of [`SIGNATURE_HEADER`].
pub fn sign(secret: &str, timestamp: i64, body: &[u8]) -> String {
    // HMAC accepts a key of any length, so this cannot fail.
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts keys of any length");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);

    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

#[derive(Clone)]
pub struct WebhookDeliverer {
    repository: WebhookRepository,
    client: reqwest::Client,
    batch_size: i64,
}

impl WebhookDeliverer {
    pub fn new(database: PgPool, timeout_seconds: u64, batch_size: i64) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            // A receiver that answers with a redirect is not something to follow: the signature
            // would be re-sent to a host that did not need to prove anything.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(USER_AGENT)
            .build()?;

        Ok(Self {
            repository: WebhookRepository::new(database),
            client,
            batch_size,
        })
    }

    /// Sends one batch. Returns how many were attempted.
    pub async fn run_once(&self) -> anyhow::Result<usize> {
        let deliveries = self
            .repository
            .claim_due_deliveries(self.batch_size, CLAIM_LEASE_SECONDS)
            .await?;

        for delivery in &deliveries {
            self.deliver(delivery).await;
        }

        Ok(deliveries.len())
    }

    async fn deliver(&self, delivery: &ClaimedDelivery) {
        let body = match serde_json::to_vec(&delivery.payload.0) {
            Ok(body) => body,
            Err(error) => {
                // The payload came out of the database as JSON, so this cannot happen; if it
                // somehow does, the row must not spin forever.
                self.record_failure(delivery, None, &format!("unrenderable payload: {error}"))
                    .await;
                return;
            }
        };

        let timestamp = chrono::Utc::now().timestamp();
        let signature = sign(&delivery.secret, timestamp, &body);
        let event = delivery
            .payload
            .0
            .get("event")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();

        let response = self
            .client
            .post(&delivery.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(SIGNATURE_HEADER, signature)
            .header(TIMESTAMP_HEADER, timestamp.to_string())
            .header(DELIVERY_HEADER, delivery.id.to_string())
            .header(EVENT_HEADER, event)
            .body(body)
            .send()
            .await;

        match response {
            Ok(response) if response.status().is_success() => {
                let status = response.status().as_u16() as i32;
                if let Err(error) = self.repository.mark_delivered(delivery.id, status).await {
                    tracing::error!(error = ?error, delivery = %delivery.id, "failed to record delivery");
                }
            }
            Ok(response) => {
                let status = response.status().as_u16() as i32;
                self.record_failure(
                    delivery,
                    Some(status),
                    &format!("receiver answered {status}"),
                )
                .await;
            }
            Err(error) => {
                self.record_failure(delivery, None, &describe(&error)).await;
            }
        }
    }

    async fn record_failure(
        &self,
        delivery: &ClaimedDelivery,
        response_status: Option<i32>,
        error: &str,
    ) {
        let delay = backoff_seconds(delivery.attempts);

        match self
            .repository
            .record_attempt_failure(
                delivery.id,
                delivery.attempts,
                error,
                delay,
                response_status,
            )
            .await
        {
            Ok(true) => tracing::warn!(
                delivery = %delivery.id,
                attempts = delivery.attempts,
                url = %delivery.url,
                error = %error,
                "giving up on a webhook delivery; it stays in the log for a redelivery"
            ),
            Ok(false) => tracing::info!(
                delivery = %delivery.id,
                attempts = delivery.attempts,
                retry_in_seconds = delay,
                error = %error,
                "webhook delivery failed, will retry"
            ),
            Err(error) => {
                tracing::error!(error = ?error, delivery = %delivery.id, "failed to record delivery attempt")
            }
        }
    }
}

/// One line an operator can act on, rather than a whole error chain per attempt.
fn describe(error: &reqwest::Error) -> String {
    if error.is_timeout() {
        "the receiver did not answer in time".to_owned()
    } else if error.is_connect() {
        "could not connect to the receiver".to_owned()
    } else {
        error.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_covers_the_timestamp_and_the_body() {
        let secret = "a-secret-long-enough-to-pass";
        let body = br#"{"event":"submission.received"}"#;

        let signature = sign(secret, 1_700_000_000, body);
        assert!(signature.starts_with("sha256="));
        assert_eq!(signature.len(), "sha256=".len() + 64, "a hex sha256 digest");

        // Stable for the same inputs, which is what makes it reproducible by a receiver.
        assert_eq!(signature, sign(secret, 1_700_000_000, body));

        // A different secret, timestamp, or body all produce a different signature.
        assert_ne!(
            signature,
            sign("another-secret-long-enough", 1_700_000_000, body)
        );
        assert_ne!(signature, sign(secret, 1_700_000_001, body));
        assert_ne!(
            signature,
            sign(secret, 1_700_000_000, br#"{"event":"other"}"#)
        );
    }

    /// Pins the exact bytes that are signed: `<timestamp>.<body>`, hex, with the `sha256=`
    /// prefix. The expected values come from `openssl dgst -sha256 -hmac`, so this fails if the
    /// format ever drifts rather than if it merely changes.
    #[test]
    fn the_signature_matches_openssl() {
        assert_eq!(
            sign("a-secret-long-enough-to-pass", 1_700_000_000, b"hello"),
            "sha256=d2b9190ff20abeacfb781bc91e308e84e840c453ecb484c6b0e6dbaf758dad45"
        );
    }
}
