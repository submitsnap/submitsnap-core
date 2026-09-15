use thiserror::Error;

use crate::shared::error::AppError;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("email is already registered")]
    EmailTaken,
    #[error("internal authentication error")]
    Internal(#[from] anyhow::Error),
}

impl From<AuthError> for AppError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::InvalidCredentials => Self::Unauthorized,
            AuthError::EmailTaken => Self::Conflict,
            AuthError::Internal(error) => Self::Internal(error),
        }
    }
}
