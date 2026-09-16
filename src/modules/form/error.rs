use thiserror::Error;

use crate::{modules::organization::OrganizationError, shared::error::AppError};

#[derive(Debug, Error)]
pub enum FormError {
    #[error("form not found")]
    NotFound,
    #[error("forbidden")]
    Forbidden,
    /// The stored definition is not usable. The message lists every problem at once.
    #[error("{0}")]
    InvalidSchema(String),
    /// The submitted payload does not match the form. The message lists every problem at once.
    #[error("{0}")]
    InvalidSubmission(String),
    #[error("this form is no longer accepting submissions")]
    Closed,
    #[error("file uploads are not configured on this instance")]
    FileUploadsUnavailable,
    #[error("too many submissions for this form; try again shortly")]
    TooManySubmissions,
    #[error("internal form error")]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for FormError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(error.into())
    }
}

/// Only the two organization outcomes that matter here are carried over; the rest cannot arise
/// from an access check.
impl From<OrganizationError> for FormError {
    fn from(error: OrganizationError) -> Self {
        match error {
            OrganizationError::NotFound
            | OrganizationError::AccountNotFound
            | OrganizationError::MemberNotFound => Self::NotFound,
            OrganizationError::NotAMember | OrganizationError::InsufficientRole => Self::Forbidden,
            other => Self::Internal(anyhow::anyhow!(other.to_string())),
        }
    }
}

impl From<FormError> for AppError {
    fn from(error: FormError) -> Self {
        match error {
            FormError::NotFound => Self::NotFound,
            FormError::Forbidden => Self::Forbidden,
            FormError::InvalidSchema(message) => Self::Validation(message),
            FormError::InvalidSubmission(message) => Self::Validation(message),
            FormError::Closed => Self::Gone(error.to_string()),
            FormError::FileUploadsUnavailable => Self::Validation(error.to_string()),
            FormError::TooManySubmissions => Self::TooManyRequests,
            FormError::Internal(error) => Self::Internal(error),
        }
    }
}
