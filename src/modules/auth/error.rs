use thiserror::Error;

use crate::{modules::identity::IdentityError, shared::error::AppError};

#[derive(Debug, Error)]
pub enum AuthError {
    /// Credential, lockout, and account-state failures raised by the identity domain.
    #[error(transparent)]
    Identity(#[from] IdentityError),
    /// Access or refresh token could not be trusted. Always surfaced as 401 so the client
    /// knows to authenticate again.
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("internal authentication error")]
    Internal(#[from] anyhow::Error),
}

impl From<AuthError> for AppError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::Identity(error) => error.into(),
            AuthError::InvalidToken => Self::Unauthorized,
            AuthError::Internal(error) => Self::Internal(error),
        }
    }
}
