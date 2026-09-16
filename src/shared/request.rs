use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{header, request::Parts},
};

/// Upper bound on the stored user agent. The header is attacker controlled, so it is
/// truncated before it reaches the database.
const MAX_USER_AGENT_LEN: usize = 512;

/// Best-effort request metadata for audit records. Never fails extraction: absent or
/// malformed metadata degrades to `None` rather than rejecting the request.
#[derive(Debug, Clone, Default)]
pub struct ClientInfo {
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
}

impl<S> FromRequestParts<S> for ClientInfo
where
    S: Send + Sync,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ip_address = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|info| info.0.ip());

        let user_agent = parts
            .headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(MAX_USER_AGENT_LEN).collect());

        Ok(Self {
            ip_address,
            user_agent,
        })
    }
}
