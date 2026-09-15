use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};

use crate::{
    modules::auth::{AuthState, dto::PublicUser},
    shared::error::AppError,
};

#[derive(Debug)]
pub struct AuthenticatedUser(pub PublicUser);

#[async_trait::async_trait]
impl FromRequestParts<AuthState> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts)
            .or_else(|| cookie_token(parts))
            .ok_or(AppError::Unauthorized)?;
        let user = state.service.authenticate(token).await?;
        Ok(Self(user))
    }
}

fn bearer_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn cookie_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(str::trim)
                .find_map(|item| item.strip_prefix("access_token="))
        })
}
