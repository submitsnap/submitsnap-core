use std::net::SocketAddr;

use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct AppConfig {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    #[serde(default = "default_jwt_issuer")]
    pub jwt_issuer: String,
    #[serde(default = "default_server_host")]
    pub server_host: String,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
    #[serde(default = "default_database_max_connections")]
    pub database_max_connections: u32,
    #[serde(default = "default_rate_limit_per_minute")]
    pub rate_limit_per_minute: u32,
    #[serde(default)]
    pub cookie_secure: bool,
    #[serde(flatten)]
    pub email: EmailConfig,
}

#[derive(Clone, Deserialize)]
pub struct EmailConfig {
    #[serde(default = "default_email_provider")]
    pub email_provider: String,
    #[serde(default)]
    pub smtp_host: Option<String>,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_username: Option<String>,
    #[serde(default)]
    pub smtp_password: Option<String>,
    #[serde(default)]
    pub email_from: Option<String>,
    #[serde(default)]
    pub email_api_token: Option<String>,
    #[serde(default)]
    pub email_api_base_url: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let config: Self = envy::from_env()?;
        if config.jwt_secret.len() < 32 {
            anyhow::bail!("JWT_SECRET must be at least 32 characters long");
        }
        if config.rate_limit_per_minute == 0 {
            anyhow::bail!("RATE_LIMIT_PER_MINUTE must be greater than zero");
        }
        Ok(config)
    }

    pub fn bind_address(&self) -> anyhow::Result<SocketAddr> {
        format!("{}:{}", self.server_host, self.server_port)
            .parse()
            .map_err(|error| anyhow::anyhow!("invalid SERVER_HOST or SERVER_PORT: {error}"))
    }
}

fn default_jwt_issuer() -> String {
    "submitsnap".into()
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
fn default_email_provider() -> String {
    "disabled".into()
}
fn default_smtp_port() -> u16 {
    587
}
