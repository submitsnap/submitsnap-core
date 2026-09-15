use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::shared::state::AppState;

pub async fn rate_limit(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|address| address.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if state.request_limiter.check_key(&client_ip).is_err() {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    next.run(request).await
}
