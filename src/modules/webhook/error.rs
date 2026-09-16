use thiserror::Error;

use crate::{modules::organization::OrganizationError, shared::error::AppError};

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("webhook endpoint not found")]
    EndpointNotFound,
    #[error("delivery not found")]
    DeliveryNotFound,
    #[error("forbidden")]
    Forbidden,
    /// The request does not describe something that can be stored.
    #[error("{0}")]
    Invalid(String),
    #[error("internal webhook error")]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for WebhookError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl From<OrganizationError> for WebhookError {
    fn from(error: OrganizationError) -> Self {
        match error {
            OrganizationError::NotFound
            | OrganizationError::AccountNotFound
            | OrganizationError::MemberNotFound => Self::EndpointNotFound,
            OrganizationError::NotAMember | OrganizationError::InsufficientRole => Self::Forbidden,
            other => Self::Internal(anyhow::anyhow!(other.to_string())),
        }
    }
}

impl From<WebhookError> for AppError {
    fn from(error: WebhookError) -> Self {
        match error {
            WebhookError::EndpointNotFound | WebhookError::DeliveryNotFound => Self::NotFound,
            WebhookError::Forbidden => Self::Forbidden,
            WebhookError::Invalid(message) => Self::Validation(message),
            WebhookError::Internal(error) => Self::Internal(error),
        }
    }
}
