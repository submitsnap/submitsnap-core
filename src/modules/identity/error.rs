use thiserror::Error;

use crate::shared::error::AppError;

/// Failures raised by the identity domain. Every variant maps to a response that does not
/// reveal whether an account exists unless the caller already proved it belongs to them.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("email is already registered")]
    EmailTaken,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("account is disabled")]
    AccountDisabled,
    #[error("account is temporarily locked")]
    AccountLocked,
    #[error("email address is not verified")]
    EmailNotVerified,
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("account not found")]
    NotFound,
    #[error("internal identity error")]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for IdentityError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl From<IdentityError> for AppError {
    fn from(error: IdentityError) -> Self {
        match error {
            IdentityError::EmailTaken => Self::Conflict,
            IdentityError::InvalidCredentials => Self::Unauthorized,
            IdentityError::AccountDisabled => Self::Forbidden,
            IdentityError::AccountLocked => Self::AccountLocked,
            IdentityError::EmailNotVerified => Self::Forbidden,
            IdentityError::InvalidToken => Self::InvalidToken,
            IdentityError::NotFound => Self::NotFound,
            IdentityError::Internal(error) => Self::Internal(error),
        }
    }
}
