use std::net::SocketAddr;

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: SecretString,
    #[serde(default = "default_jwt_issuer")]
    pub jwt_issuer: String,
    #[serde(default = "default_jwt_audience")]
    pub jwt_audience: String,
    #[serde(default = "default_server_host")]
    pub server_host: String,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
    #[serde(default = "default_database_max_connections")]
    pub database_max_connections: u32,
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
    #[serde(default = "default_login_rate_limit_per_minute")]
    pub login_rate_limit_per_minute: u32,
    #[serde(default = "default_register_rate_limit_per_hour")]
    pub register_rate_limit_per_hour: u32,
    /// Budget for unauthenticated endpoints that trigger outbound email or consume a
    /// single-use token (password reset, email verification).
    #[serde(default = "default_sensitive_rate_limit_per_hour")]
    pub sensitive_rate_limit_per_hour: u32,
    #[serde(default)]
    pub cookie_secure: bool,
    #[serde(default = "default_access_token_ttl_seconds")]
    pub access_token_ttl_seconds: u64,
    #[serde(default = "default_refresh_token_ttl_seconds")]
    pub refresh_token_ttl_seconds: u64,
    #[serde(default = "default_email_verification_ttl_seconds")]
    pub email_verification_ttl_seconds: u64,
    #[serde(default = "default_password_reset_ttl_seconds")]
    pub password_reset_ttl_seconds: u64,
    #[serde(default)]
    pub require_email_verification: bool,
    #[serde(default = "default_max_failed_login_attempts")]
    pub max_failed_login_attempts: u32,
    #[serde(default = "default_account_lock_duration_seconds")]
    pub account_lock_duration_seconds: u64,
    #[serde(default)]
    pub password_pepper: Option<SecretString>,
    /// Comma-separated list of browser origins allowed to call the API with credentials.
    #[serde(default)]
    pub cors_allowed_origins: Option<String>,
    #[serde(default = "default_request_body_limit_bytes")]
    pub request_body_limit_bytes: usize,
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    #[serde(default = "default_api_docs_enabled")]
    pub api_docs_enabled: bool,
    /// Base URL of the web application. Used to build the links inside outgoing emails.
    #[serde(default = "default_app_base_url")]
    pub app_base_url: String,

    // Email settings live directly on this struct rather than in a flattened nested struct:
    // `envy` feeds serde strings, and a flattened struct buffers those strings in a way that
    // cannot be deserialized into numbers such as `SMTP_PORT`.
    #[serde(default = "default_email_provider")]
    pub email_provider: String,
    #[serde(default)]
    pub smtp_host: Option<String>,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_username: Option<String>,
    #[serde(default)]
    pub smtp_password: Option<SecretString>,
    #[serde(default)]
    pub email_from: Option<String>,
    #[serde(default)]
    pub email_api_token: Option<SecretString>,
    #[serde(default)]
    pub email_api_base_url: Option<String>,
}

/// The subset of configuration the email adapters require. Plain data: it is derived from
/// [`AppConfig`] rather than deserialized, which keeps the environment parsing in one place.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub email_provider: String,
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<SecretString>,
    pub email_from: Option<String>,
    pub email_api_token: Option<SecretString>,
    pub email_api_base_url: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_settings(std::env::vars())
    }

    pub fn from_settings<I, K, V>(iter: I) -> anyhow::Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: Into<String>,
    {
        let settings = iter
            .into_iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.into()));
        let config: Self = envy::from_iter(settings)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        let mut invalid = Vec::new();

        if self.jwt_secret.expose_secret().len() < 32 {
            invalid.push("JWT_SECRET must be at least 32 characters long");
        }
        if self.rate_limit_per_minute == 0 {
            invalid.push("RATE_LIMIT_PER_MINUTE must be greater than zero");
        }
        if self.login_rate_limit_per_minute == 0 {
            invalid.push("LOGIN_RATE_LIMIT_PER_MINUTE must be greater than zero");
        }
        if self.register_rate_limit_per_hour == 0 {
            invalid.push("REGISTER_RATE_LIMIT_PER_HOUR must be greater than zero");
        }
        if self.sensitive_rate_limit_per_hour == 0 {
            invalid.push("SENSITIVE_RATE_LIMIT_PER_HOUR must be greater than zero");
        }
        if self.access_token_ttl_seconds == 0 {
            invalid.push("ACCESS_TOKEN_TTL_SECONDS must be greater than zero");
        }
        if self.refresh_token_ttl_seconds == 0 {
            invalid.push("REFRESH_TOKEN_TTL_SECONDS must be greater than zero");
        }
        if self.email_verification_ttl_seconds == 0 {
            invalid.push("EMAIL_VERIFICATION_TTL_SECONDS must be greater than zero");
        }
        if self.password_reset_ttl_seconds == 0 {
            invalid.push("PASSWORD_RESET_TTL_SECONDS must be greater than zero");
        }
        if self.max_failed_login_attempts == 0 {
            invalid.push("MAX_FAILED_LOGIN_ATTEMPTS must be greater than zero");
        }
        if self.account_lock_duration_seconds == 0 {
            invalid.push("ACCOUNT_LOCK_DURATION_SECONDS must be greater than zero");
        }
        if self.request_body_limit_bytes == 0 {
            invalid.push("REQUEST_BODY_LIMIT_BYTES must be greater than zero");
        }
        if self.request_timeout_seconds == 0 {
            invalid.push("REQUEST_TIMEOUT_SECONDS must be greater than zero");
        }
        if self.access_token_ttl_seconds >= self.refresh_token_ttl_seconds {
            invalid.push("ACCESS_TOKEN_TTL_SECONDS must be shorter than REFRESH_TOKEN_TTL_SECONDS");
        }

        if invalid.is_empty() {
            return Ok(());
        }
        anyhow::bail!("invalid configuration: {}", invalid.join("; "))
    }

    pub fn bind_address(&self) -> anyhow::Result<SocketAddr> {
        format!("{}:{}", self.server_host, self.server_port)
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid SERVER_HOST or SERVER_PORT: {error}"))
    }

    /// The email adapter settings derived from this configuration.
    pub fn email_settings(&self) -> EmailConfig {
        EmailConfig {
            email_provider: self.email_provider.clone(),
            smtp_host: self.smtp_host.clone(),
            smtp_port: self.smtp_port,
            smtp_username: self.smtp_username.clone(),
            smtp_password: self.smtp_password.clone(),
            email_from: self.email_from.clone(),
            email_api_token: self.email_api_token.clone(),
            email_api_base_url: self.email_api_base_url.clone(),
        }
    }

    /// Browser origins permitted to send credentialed requests, or `None` when CORS is disabled.
    pub fn cors_origins(&self) -> Option<Vec<String>> {
        let origins: Vec<String> = self
            .cors_allowed_origins
            .as_deref()?
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(str::to_owned)
            .collect();
        (!origins.is_empty()).then_some(origins)
    }
}

fn default_jwt_issuer() -> String {
    "submitsnap".into()
}
fn default_jwt_audience() -> String {
    "submitsnap-api".into()
}
fn default_server_host() -> String {
    "127.0.0.1".into()
}
fn default_server_port() -> u16 {
    8080
}
fn default_database_max_connections() -> u32 {
    10
}
fn default_rate_limit_per_minute() -> u32 {
    120
}
fn default_login_rate_limit_per_minute() -> u32 {
    10
}
fn default_register_rate_limit_per_hour() -> u32 {
    5
}
fn default_sensitive_rate_limit_per_hour() -> u32 {
    5
}

fn default_access_token_ttl_seconds() -> u64 {
    900
}
fn default_refresh_token_ttl_seconds() -> u64 {
    60 * 60 * 24 * 30
}
fn default_email_verification_ttl_seconds() -> u64 {
    60 * 60 * 24
}
fn default_password_reset_ttl_seconds() -> u64 {
    60 * 60
}
fn default_max_failed_login_attempts() -> u32 {
    5
}
fn default_account_lock_duration_seconds() -> u64 {
    900
}
fn default_request_body_limit_bytes() -> usize {
    64 * 1024
}
fn default_request_timeout_seconds() -> u64 {
    15
}
fn default_api_docs_enabled() -> bool {
    true
}
fn default_app_base_url() -> String {
    "http://localhost:3000".into()
}
fn default_email_provider() -> String {
    "disabled".into()
}
fn default_smtp_port() -> u16 {
    587
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_settings() -> Vec<(&'static str, String)> {
        vec![
            ("database_url", "postgres://localhost/submitsnap".into()),
            ("redis_url", "redis://127.0.0.1:6379".into()),
            (
                "jwt_secret",
                "a-development-secret-that-is-long-enough".into(),
            ),
        ]
    }

    #[test]
    fn config_uses_documented_defaults() {
        let config = AppConfig::from_settings(base_settings()).unwrap();

        assert_eq!(config.jwt_issuer, "submitsnap");
        assert_eq!(config.jwt_audience, "submitsnap-api");
        assert_eq!(config.access_token_ttl_seconds, 900);
        assert_eq!(config.refresh_token_ttl_seconds, 2_592_000);
        assert_eq!(config.max_failed_login_attempts, 5);
        assert!(!config.require_email_verification);
        assert!(!config.cookie_secure);
        assert!(config.api_docs_enabled);
        assert!(config.cors_origins().is_none());
        assert_eq!(config.email_provider, "disabled");
        assert_eq!(config.smtp_port, 587);
    }

    #[test]
    fn numeric_settings_parse_from_environment_strings() {
        // Regression: nested/flattened structs buffer serde strings in a way that cannot be
        // deserialized into numbers, which made `SMTP_PORT=587` fail at startup.
        let mut settings = base_settings();
        settings.push(("smtp_port", "2525".into()));
        settings.push(("server_port", "9090".into()));
        settings.push(("request_body_limit_bytes", "1024".into()));

        let config = AppConfig::from_settings(settings).unwrap();

        assert_eq!(config.smtp_port, 2525);
        assert_eq!(config.server_port, 9090);
        assert_eq!(config.request_body_limit_bytes, 1024);
        assert_eq!(config.email_settings().smtp_port, 2525);
    }

    #[test]
    fn secrets_are_redacted_when_formatted() {
        let mut settings = base_settings();
        settings.push(("email_api_token", "provider-token-value".into()));
        let config = AppConfig::from_settings(settings).unwrap();

        let rendered = format!("{config:?}");
        assert!(!rendered.contains("a-development-secret-that-is-long-enough"));
        assert!(!rendered.contains("provider-token-value"));
        assert_eq!(
            config.jwt_secret.expose_secret(),
            "a-development-secret-that-is-long-enough"
        );
    }

    #[test]
    fn short_jwt_secret_is_rejected() {
        let settings = vec![
            ("database_url", "postgres://localhost/submitsnap".to_owned()),
            ("redis_url", "redis://127.0.0.1:6379".to_owned()),
            ("jwt_secret", "too-short".to_owned()),
        ];

        let error = AppConfig::from_settings(settings).unwrap_err().to_string();
        assert!(error.contains("JWT_SECRET"));
    }

    #[test]
    fn access_token_must_expire_before_refresh_token() {
        let mut settings = base_settings();
        settings.push(("access_token_ttl_seconds", "7200".into()));
        settings.push(("refresh_token_ttl_seconds", "3600".into()));

        let error = AppConfig::from_settings(settings).unwrap_err().to_string();
        assert!(error.contains("ACCESS_TOKEN_TTL_SECONDS"));
    }

    #[test]
    fn cors_origins_are_trimmed_and_filtered() {
        let mut settings = base_settings();
        settings.push((
            "cors_allowed_origins",
            " https://app.example.com , ,https://admin.example.com ".into(),
        ));

        let config = AppConfig::from_settings(settings).unwrap();
        assert_eq!(
            config.cors_origins().unwrap(),
            vec!["https://app.example.com", "https://admin.example.com"]
        );
    }
}
