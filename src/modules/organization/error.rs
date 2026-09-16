use thiserror::Error;

use crate::shared::error::AppError;

#[derive(Debug, Error)]
pub enum OrganizationError {
    #[error("organization not found")]
    NotFound,
    /// The caller has nothing to do with this organization. Answered with 403 rather than 404
    /// on purpose: identifiers are random UUIDs, so nothing is enumerable, and "you are not a
    /// member" is more useful to a client than pretending the organization is missing.
    #[error("you are not a member of this organization")]
    NotAMember,
    #[error("your role in this organization does not permit that")]
    InsufficientRole,
    #[error("an organization must keep at least one owner")]
    LastOwner,
    #[error("no account exists for that email address")]
    AccountNotFound,
    #[error("that account is not a member of this organization")]
    MemberNotFound,
    #[error("internal organization error")]
    Internal(#[from] anyhow::Error),
}

impl From<sqlx::Error> for OrganizationError {
    fn from(error: sqlx::Error) -> Self {
        Self::Internal(error.into())
    }
}

/// The identity module is consulted to resolve an invited address. Only its internal failures
/// are meaningful here, so everything else is folded into one.
impl From<crate::modules::identity::IdentityError> for OrganizationError {
    fn from(error: crate::modules::identity::IdentityError) -> Self {
        match error {
            crate::modules::identity::IdentityError::Internal(error) => Self::Internal(error),
            other => Self::Internal(anyhow::anyhow!(other.to_string())),
        }
    }
}

impl From<OrganizationError> for AppError {
    fn from(error: OrganizationError) -> Self {
        match error {
            OrganizationError::NotFound => Self::NotFound,
            OrganizationError::NotAMember => Self::Forbidden,
            OrganizationError::InsufficientRole => Self::Forbidden,
            OrganizationError::LastOwner => Self::Validation(error.to_string()),
            OrganizationError::AccountNotFound => Self::NotFound,
            OrganizationError::MemberNotFound => Self::NotFound,
            OrganizationError::Internal(error) => Self::Internal(error),
        }
    }
}
