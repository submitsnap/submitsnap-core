use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use axum_extra::extract::cookie::CookieJar;
use uuid::Uuid;

use crate::{
    modules::{
        auth::{AuthState, cookies::ACCESS_TOKEN_COOKIE},
        identity::PublicUser,
        rbac::RoleName,
    },
    shared::error::AppError,
};

/// A caller that presented a valid access token and whose session is still active.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user: PublicUser,
    /// The session this request belongs to, used to target logout and password-change
    /// revocation at the right session.
    pub session_id: Uuid,
}

impl AuthenticatedUser {
    pub fn has_role(&self, role: &RoleName) -> bool {
        self.user.roles.iter().any(|held| held == role)
    }

    /// Guard for endpoints restricted to a role. Pair with [`AuthenticatedUser`] extraction so
    /// the failure is a 403 rather than a redirect.
    pub fn require_role(&self, role: &RoleName) -> Result<(), AppError> {
        if self.has_role(role) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }
}

impl FromRequestParts<AuthState> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AuthState,
    ) -> Result<Self, Self::Rejection> {
        let token = match bearer_token(parts) {
            Some(token) => token.to_owned(),
            None => {
                // Fall back to the dashboard cookie so the browser flow needs no JavaScript
                // access to the token. Parsing is delegated to the `cookie` crate.
                let jar = CookieJar::from_request_parts(parts, state)
                    .await
                    .unwrap_or_default();
                jar.get(ACCESS_TOKEN_COOKIE)
                    .map(|cookie| cookie.value().to_owned())
                    .ok_or(AppError::Unauthorized)?
            }
        };

        Ok(state.service.authenticate(&token).await?)
    }
}

fn bearer_token(parts: &Parts) -> Option<&str> {
    let value = parts.headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;

    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim())
        .filter(|token| !token.is_empty())
}
