use std::str::FromStr;

use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor, message::Mailbox,
    transport::smtp::authentication::Credentials,
};
use secrecy::ExposeSecret;

use crate::shared::{config::EmailConfig, queue::EmailJob};

/// How the SMTP connection is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTls {
    /// Connect in the clear, then upgrade the connection with STARTTLS. The usual choice for
    /// port 587 and what most self-hosted servers expect.
    StartTls,
    /// TLS from the first byte, as used by port 465.
    Implicit,
    /// No encryption. Credentials and message bodies travel in the clear.
    None,
}

impl FromStr for SmtpTls {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "starttls" => Ok(Self::StartTls),
            "implicit" | "tls" => Ok(Self::Implicit),
            "none" => Ok(Self::None),
            other => {
                anyhow::bail!(
                    "unsupported SMTP_TLS_MODE {other:?}; use starttls, implicit, or none"
                )
            }
        }
    }
}

#[derive(Clone)]
pub enum EmailClient {
    /// Accepts messages and drops them. The default, so a development checkout never sends
    /// mail by accident.
    Disabled,
    Smtp(Box<SmtpSender>),
}

/// The SMTP transport plus the envelope sender. Boxed because the transport is an order of
/// magnitude larger than the disabled variant.
#[derive(Clone)]
pub struct SmtpSender {
    client: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl EmailClient {
    pub fn from_config(config: &EmailConfig) -> anyhow::Result<Self> {
        match config.email_provider.trim().to_ascii_lowercase().as_str() {
            "disabled" => Ok(Self::Disabled),
            "smtp" => Ok(Self::Smtp(Box::new(SmtpSender {
                client: smtp_transport(config)?,
                from: Mailbox::from_str(required(&config.email_from, "EMAIL_FROM")?)?,
            }))),
            other => anyhow::bail!(
                "unsupported EMAIL_PROVIDER {other:?}; supported values are disabled and smtp"
            ),
        }
    }

    pub async fn send(&self, job: &EmailJob) -> anyhow::Result<()> {
        match self {
            Self::Disabled => {
                tracing::warn!(recipient = %job.to, "email provider disabled; message was not delivered");
                Ok(())
            }
            Self::Smtp(sender) => {
                let message = Message::builder()
                    .from(sender.from.clone())
                    .to(Mailbox::from_str(&job.to)?)
                    .subject(&job.subject)
                    .body(job.text_body.clone())?;

                sender.client.send(message).await?;
                Ok(())
            }
        }
    }
}

fn smtp_transport(config: &EmailConfig) -> anyhow::Result<AsyncSmtpTransport<Tokio1Executor>> {
    let host = required(&config.smtp_host, "SMTP_HOST")?;
    let tls = SmtpTls::from_str(&config.smtp_tls_mode)?;

    let mut builder = match tls {
        SmtpTls::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)?,
        SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(host)?,
        SmtpTls::None => {
            tracing::warn!(
                "SMTP_TLS_MODE=none: credentials and message bodies will be sent unencrypted"
            );
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
        }
    };

    builder = builder.port(config.smtp_port);

    // An empty value means "not configured", not "configured as empty". `.env.example` ships
    // these blank, so treating them as credentials would make the documented setup path try to
    // authenticate against a relay that has no authentication — and fail with an error about
    // authentication mechanisms rather than about configuration.
    let username = non_empty(config.smtp_username.as_deref());
    let password = config
        .smtp_password
        .as_ref()
        .map(ExposeSecret::expose_secret)
        .map(str::trim)
        .filter(|password| !password.is_empty());

    match (username, password) {
        (Some(username), Some(password)) => {
            builder =
                builder.credentials(Credentials::new(username.to_owned(), password.to_owned()));
        }
        // Nothing to authenticate with, so nothing is attempted. A relay that offers AUTH but
        // is given no credentials is a misconfiguration, and saying so beats a handshake that
        // fails with "no compatible authentication mechanism was found".
        _ => {
            builder = builder.authentication(Vec::new());
        }
    }

    Ok(builder.build())
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn required<'a>(value: &'a Option<String>, setting: &str) -> anyhow::Result<&'a str> {
    value
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{setting} is required when EMAIL_PROVIDER=smtp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    fn smtp_config() -> EmailConfig {
        EmailConfig {
            email_provider: "smtp".into(),
            smtp_host: Some("smtp.example.com".into()),
            smtp_port: 587,
            smtp_username: Some("mailer".into()),
            smtp_password: Some(SecretString::from("hunter2".to_owned())),
            email_from: Some("hello@example.com".into()),
            smtp_tls_mode: "starttls".into(),
        }
    }

    #[test]
    fn disabled_needs_no_further_configuration() {
        let config = EmailConfig {
            email_provider: "disabled".into(),
            smtp_host: None,
            smtp_port: 587,
            smtp_username: None,
            smtp_password: None,
            email_from: None,
            smtp_tls_mode: "starttls".into(),
        };

        assert!(matches!(
            EmailClient::from_config(&config).unwrap(),
            EmailClient::Disabled
        ));
    }

    #[test]
    fn smtp_requires_a_host() {
        let config = EmailConfig {
            smtp_host: None,
            ..smtp_config()
        };

        let error = EmailClient::from_config(&config)
            .err()
            .expect("expected an error")
            .to_string();
        assert!(error.contains("SMTP_HOST"), "{error}");
    }

    #[test]
    fn smtp_requires_a_sender() {
        let config = EmailConfig {
            email_from: None,
            ..smtp_config()
        };

        let error = EmailClient::from_config(&config)
            .err()
            .expect("expected an error")
            .to_string();
        assert!(error.contains("EMAIL_FROM"), "{error}");
    }

    #[test]
    fn unsupported_providers_name_the_valid_values() {
        let config = EmailConfig {
            email_provider: "resend".into(),
            ..smtp_config()
        };

        let error = EmailClient::from_config(&config)
            .err()
            .expect("expected an error")
            .to_string();
        assert!(error.contains("disabled and smtp"), "{error}");
    }

    #[test]
    fn tls_modes_are_parsed_and_unknown_values_rejected() {
        assert_eq!("starttls".parse::<SmtpTls>().unwrap(), SmtpTls::StartTls);
        assert_eq!("IMPLICIT".parse::<SmtpTls>().unwrap(), SmtpTls::Implicit);
        assert_eq!("tls".parse::<SmtpTls>().unwrap(), SmtpTls::Implicit);
        assert_eq!("none".parse::<SmtpTls>().unwrap(), SmtpTls::None);
        assert!("ssl".parse::<SmtpTls>().is_err());
    }

    #[test]
    fn a_blank_username_or_password_means_no_authentication() {
        // `.env.example` ships both blank, and a relay that needs no credentials is ordinary.
        // Treating a blank value as a credential made the documented setup path fail with
        // "no compatible authentication mechanism was found".
        assert_eq!(non_empty(Some("")), None);
        assert_eq!(non_empty(Some("   ")), None);
        assert_eq!(non_empty(Some("mailer\n")), Some("mailer"));
        assert_eq!(non_empty(None), None);

        let config = EmailConfig {
            smtp_username: Some(String::new()),
            smtp_password: Some(SecretString::from(String::new())),
            ..smtp_config()
        };
        assert!(
            EmailClient::from_config(&config).is_ok(),
            "a blank pair is a relay without authentication, not a broken one"
        );
    }

    #[test]
    fn every_tls_mode_builds_a_client() {
        for mode in ["starttls", "implicit", "none"] {
            let config = EmailConfig {
                smtp_tls_mode: mode.into(),
                ..smtp_config()
            };

            assert!(
                matches!(
                    EmailClient::from_config(&config).unwrap(),
                    EmailClient::Smtp(_)
                ),
                "mode {mode} should build an SMTP client"
            );
        }
    }
}
