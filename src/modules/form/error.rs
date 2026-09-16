use thiserror::Error;

use crate::{
    modules::organization::OrganizationError,
    shared::{error::AppError, storage::StorageError},
};

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
    /// A file answer was not acceptable: an unknown reference, one already used by another
    /// submission, or one that belongs to a different field.
    #[error("{0}")]
    FileRejected(String),
    #[error("the file exceeds the {limit} byte limit")]
    FileTooLarge { limit: u64 },
    #[error("the stored file is no longer available")]
    FileMissing,
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

/// Storage outcomes are translated once, here, so no handler has to know about the adapter.
impl From<StorageError> for FormError {
    fn from(error: StorageError) -> Self {
        match error {
            StorageError::NotConfigured => Self::FileUploadsUnavailable,
            StorageError::TooLarge { limit } => Self::FileTooLarge { limit },
            StorageError::NotFound => Self::FileMissing,
            StorageError::Internal(error) => Self::Internal(error),
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
            FormError::FileRejected(message) => Self::Validation(message),
            FormError::FileTooLarge { limit } => {
                Self::PayloadTooLarge(format!("the file exceeds the {limit} byte limit"))
            }
            FormError::FileMissing => Self::NotFound,
            FormError::TooManySubmissions => Self::TooManyRequests,
            FormError::Internal(error) => Self::Internal(error),
        }
    }
}
