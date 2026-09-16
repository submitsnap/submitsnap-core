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
    /// Per-IP budget for public form submissions.
    #[serde(default = "default_submission_rate_limit_per_minute")]
    pub submission_rate_limit_per_minute: u32,
    /// Per-form budget, which is what protects one tenant from a flood aimed at a single form
    /// regardless of where it comes from.
    #[serde(default = "default_submission_per_form_rate_limit_per_minute")]
    pub submission_per_form_rate_limit_per_minute: u32,
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
    /// `starttls` (port 587), `implicit` (port 465), or `none`.
    #[serde(default = "default_smtp_tls_mode")]
    pub smtp_tls_mode: String,

    /// Set to enable file uploads. Storage is optional: without it the product works fully,
    /// except that a form containing a file field cannot be published.
    #[serde(default)]
    pub s3_bucket: Option<String>,
    #[serde(default = "default_s3_region")]
    pub s3_region: String,
    /// Unset for AWS. Set it for anything else: Cloudflare R2, MinIO, Backblaze B2, and so on.
    #[serde(default)]
    pub s3_endpoint: Option<String>,
    /// Left unset, the SDK's own credential chain is used, which is how instance roles work.
    #[serde(default)]
    pub s3_access_key_id: Option<String>,
    #[serde(default)]
    pub s3_secret_access_key: Option<SecretString>,
    /// Most non-AWS endpoints address buckets as `host/bucket` rather than `bucket.host`.
    #[serde(default)]
    pub s3_force_path_style: bool,
    /// The ceiling for one uploaded file, no matter what a form asks for. A form cannot raise it.
    #[serde(default = "default_upload_max_bytes")]
    pub upload_max_bytes: u64,
    /// How long an upload may sit unclaimed before the worker deletes it.
    #[serde(default = "default_upload_ttl_hours")]
    pub upload_ttl_hours: u64,

    /// How long a webhook delivery waits for the receiver before it is counted as a failure.
    #[serde(default = "default_webhook_timeout_seconds")]
    pub webhook_timeout_seconds: u64,

    /// Whether a webhook may point at a loopback or link-local address.
    ///
    /// Off by default, because a webhook URL is fetched *by this server*, which makes the
    /// link-local range — where cloud instance credentials live — reachable by anyone who can
    /// administer an organization. Turn it on when the receiver genuinely runs on the same host
    /// or a private network.
    #[serde(default)]
    pub webhook_allow_private_targets: bool,

    /// Prefix for every key this deployment writes to Redis. Two deployments sharing one Redis
    /// need different prefixes; so do tests, which is the other reason it exists.
    #[serde(default = "default_redis_key_prefix")]
    pub redis_key_prefix: String,
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
    pub smtp_tls_mode: String,
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
        if is_placeholder_secret(self.jwt_secret.expose_secret()) {
            invalid.push(
                "JWT_SECRET is still a placeholder value; generate one with \
                 `openssl rand -base64 48` and keep it secret",
            );
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
        if self.submission_rate_limit_per_minute == 0 {
            invalid.push("SUBMISSION_RATE_LIMIT_PER_MINUTE must be greater than zero");
        }
        if self.submission_per_form_rate_limit_per_minute == 0 {
            invalid.push("SUBMISSION_PER_FORM_RATE_LIMIT_PER_MINUTE must be greater than zero");
        }
        if self.webhook_timeout_seconds == 0 {
            invalid.push("WEBHOOK_TIMEOUT_SECONDS must be greater than zero");
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

        // Fail at startup rather than at the first verification email.
        if self.uses_smtp() {
            if self.smtp_host.as_deref().is_none_or(str::is_empty) {
                invalid.push("SMTP_HOST is required when EMAIL_PROVIDER=smtp");
            }
            if self.email_from.as_deref().is_none_or(str::is_empty) {
                invalid.push("EMAIL_FROM is required when EMAIL_PROVIDER=smtp");
            }
            // A blank value means "no authentication", so half a pair is a mistake rather than
            // an unusual setup: a username with no password is not a relay that anyone runs.
            if self.smtp_username.is_some() != self.smtp_password.is_some() {
                invalid.push("SMTP_USERNAME and SMTP_PASSWORD must be set together");
            }
        }
        if !matches!(
            self.smtp_tls_mode.trim().to_ascii_lowercase().as_str(),
            "starttls" | "implicit" | "tls" | "none"
        ) {
            invalid.push("SMTP_TLS_MODE must be starttls, implicit, or none");
        }

        // Half a credential pair is a mistake rather than an unusual setup. Leaving both blank is
        // legitimate: the SDK then uses its own chain, which is how an instance role works.
        if self.s3_access_key_id.is_some() != self.s3_secret_access_key.is_some() {
            invalid.push("S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY must be set together");
        }
        if self.upload_max_bytes == 0 {
            invalid.push("UPLOAD_MAX_BYTES must be greater than zero");
        }
        if self.upload_ttl_hours == 0 {
            invalid.push("UPLOAD_TTL_HOURS must be greater than zero");
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
            smtp_tls_mode: self.smtp_tls_mode.clone(),
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

    pub fn uses_smtp(&self) -> bool {
        self.email_provider.trim().eq_ignore_ascii_case("smtp")
    }

    /// Whether file uploads are available. Storage is deliberately optional.
    pub fn file_uploads_enabled(&self) -> bool {
        self.s3_bucket
            .as_deref()
            .is_some_and(|bucket| !bucket.trim().is_empty())
    }

    /// Emits [`Self::deployment_warnings`] through the tracing subscriber. Never fails: a
    /// warning must not stop a deployment the operator chose on purpose.
    pub fn log_deployment_warnings(&self) {
        for warning in self.deployment_warnings() {
            tracing::warn!(target: "submitsnap_core::config", "{warning}");
        }
    }

    /// Whether the service is bound to an address only reachable from this host. Used to
    /// decide how loudly to warn about development-friendly settings.
    pub fn is_loopback_only(&self) -> bool {
        matches!(
            self.server_host.trim(),
            "127.0.0.1" | "localhost" | "::1" | "[::1]"
        )
    }

    /// Settings that are fine locally but risky in production. Logged at startup so a
    /// misconfigured deployment is obvious from its own logs, without refusing to boot.
    pub fn deployment_warnings(&self) -> Vec<String> {
        if self.is_loopback_only() {
            return Vec::new();
        }

        let mut warnings = Vec::new();

        if !self.cookie_secure {
            warnings.push(
                "COOKIE_SECURE=false while serving a non-loopback address: session cookies \
                 will travel over plain HTTP"
                    .into(),
            );
        }
        if self.api_docs_enabled {
            warnings.push(
                "API_DOCS_ENABLED=true while serving a non-loopback address: the endpoint \
                 list is publicly readable"
                    .into(),
            );
        }
        if !self.require_email_verification {
            warnings.push(
                "REQUIRE_EMAIL_VERIFICATION=false: unverified email addresses can sign in".into(),
            );
        }
        if self.email_provider.trim().eq_ignore_ascii_case("disabled") {
            warnings.push(
                "EMAIL_PROVIDER=disabled: verification and password reset messages are \
                 discarded, so nobody can recover an account"
                    .into(),
            );
        }
        if self.password_pepper.is_none() {
            warnings.push(
                "PASSWORD_PEPPER is unset: a database disclosure alone would be enough to \
                 attack password hashes offline"
                    .into(),
            );
        }
        if self
            .s3_endpoint
            .as_deref()
            .is_some_and(|endpoint| endpoint.trim().starts_with("http://"))
        {
            warnings.push(
                "S3_ENDPOINT is plain http while serving a non-loopback address: storage \
                 credentials and every uploaded file travel unencrypted"
                    .into(),
            );
        }

        warnings
    }
}

/// Well-known values people copy from documentation or compose files and then forget to
/// replace. Rejecting them turns a silent, total authentication bypass into a startup error.
const PLACEHOLDER_SECRET_MARKERS: [&str; 6] = [
    "replace-with",
    "changeme",
    "change-me",
    "placeholder",
    "your-secret",
    "insecure",
];

fn is_placeholder_secret(secret: &str) -> bool {
    let secret = secret.to_ascii_lowercase();
    PLACEHOLDER_SECRET_MARKERS
        .iter()
        .any(|marker| secret.contains(marker))
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

fn default_submission_rate_limit_per_minute() -> u32 {
    30
}
fn default_submission_per_form_rate_limit_per_minute() -> u32 {
    120
}

fn default_s3_region() -> String {
    // R2 and several other providers ignore the region but still require one, and "auto" is
    // what they document.
    "auto".to_owned()
}

fn default_upload_max_bytes() -> u64 {
    25 * 1024 * 1024
}

fn default_upload_ttl_hours() -> u64 {
    24
}

fn default_webhook_timeout_seconds() -> u64 {
    10
}

fn default_redis_key_prefix() -> String {
    "submitsnap".to_owned()
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
fn default_smtp_tls_mode() -> String {
    "starttls".into()
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
    fn half_of_an_smtp_credential_pair_is_refused() {
        let mut settings = base_settings();
        settings.push(("email_provider", "smtp".into()));
        settings.push(("smtp_host", "smtp.example.com".into()));
        settings.push(("email_from", "hello@example.com".into()));
        settings.push(("smtp_username", "mailer".into()));

        let error = AppConfig::from_settings(settings).unwrap_err().to_string();
        assert!(error.contains("SMTP_USERNAME and SMTP_PASSWORD"), "{error}");
    }

    #[test]
    fn an_smtp_relay_without_credentials_is_accepted() {
        let mut settings = base_settings();
        settings.push(("email_provider", "smtp".into()));
        settings.push(("smtp_host", "smtp.example.com".into()));
        settings.push(("email_from", "hello@example.com".into()));

        assert!(AppConfig::from_settings(settings).is_ok());
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
        settings.push(("smtp_password", "provider-token-value".into()));
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
    fn documented_placeholder_secrets_are_rejected() {
        // The value shipped in `.env.example`. Accepting it would let anyone who has read the
        // repository forge access tokens.
        for placeholder in [
            "replace-with-a-random-secret-at-least-32-characters-long",
            "CHANGEME-please-rotate-this-value-now",
            "my-placeholder-secret-for-development",
        ] {
            let settings = vec![
                ("database_url", "postgres://localhost/submitsnap".to_owned()),
                ("redis_url", "redis://127.0.0.1:6379".to_owned()),
                ("jwt_secret", placeholder.to_owned()),
            ];

            let error = AppConfig::from_settings(settings).unwrap_err().to_string();
            assert!(error.contains("placeholder"), "{placeholder}: {error}");
        }
    }

    #[test]
    fn smtp_requires_a_host_and_sender() {
        let mut settings = base_settings();
        settings.push(("email_provider", "smtp".into()));

        let error = AppConfig::from_settings(settings).unwrap_err().to_string();
        assert!(error.contains("SMTP_HOST"), "{error}");
        assert!(error.contains("EMAIL_FROM"), "{error}");
    }

    #[test]
    fn smtp_tls_mode_must_be_known() {
        let mut settings = base_settings();
        settings.push(("smtp_tls_mode", "ssl".into()));

        let error = AppConfig::from_settings(settings).unwrap_err().to_string();
        assert!(error.contains("SMTP_TLS_MODE"), "{error}");
    }

    #[test]
    fn local_development_produces_no_deployment_warnings() {
        let config = AppConfig::from_settings(base_settings()).unwrap();

        assert!(config.is_loopback_only());
        assert!(config.deployment_warnings().is_empty());
    }

    #[test]
    fn public_deployment_flags_development_settings() {
        let mut settings = base_settings();
        settings.push(("server_host", "0.0.0.0".into()));

        let config = AppConfig::from_settings(settings).unwrap();
        let warnings = config.deployment_warnings();

        assert!(!config.is_loopback_only());
        for expected in [
            "COOKIE_SECURE",
            "API_DOCS_ENABLED",
            "REQUIRE_EMAIL_VERIFICATION",
            "EMAIL_PROVIDER",
            "PASSWORD_PEPPER",
        ] {
            assert!(
                warnings.iter().any(|warning| warning.contains(expected)),
                "expected a warning mentioning {expected}, got {warnings:?}"
            );
        }
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
