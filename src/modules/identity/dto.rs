use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::modules::{
    identity::model::{UserRecord, UserStatus, normalize_email},
    rbac::RoleName,
};

pub const DEFAULT_PAGE_SIZE: u32 = 50;
pub const MAX_PAGE_SIZE: u32 = 100;

/// Normalizes an email as it enters the process, before validation runs. Every entry point
/// therefore validates, stores, and looks up the same canonical form.
fn normalize_email_field<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(normalize_email(&String::deserialize(deserializer)?))
}

/// The public projection of an account. Never carries the password hash or lock state.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PublicUser {
    pub id: Uuid,
    pub email: String,
    pub status: UserStatus,
    pub email_verified: bool,
    pub roles: Vec<RoleName>,
    pub created_at: DateTime<Utc>,
}

impl PublicUser {
    pub fn new(user: &UserRecord, roles: Vec<RoleName>) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            status: user.status,
            email_verified: user.is_email_verified(),
            roles,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RegisterRequest {
    #[serde(deserialize_with = "normalize_email_field")]
    #[validate(email, length(max = 320))]
    #[schema(example = "person@example.com")]
    pub email: String,
    #[validate(length(min = 12, max = 128))]
    #[schema(
        example = "correct horse battery staple",
        min_length = 12,
        max_length = 128
    )]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[serde(deserialize_with = "normalize_email_field")]
    #[validate(email, length(max = 320))]
    #[schema(example = "person@example.com")]
    pub email: String,
    #[validate(length(min = 1, max = 128))]
    #[schema(example = "correct horse battery staple")]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ForgotPasswordRequest {
    #[serde(deserialize_with = "normalize_email_field")]
    #[validate(email, length(max = 320))]
    #[schema(example = "person@example.com")]
    pub email: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 1, max = 512))]
    pub token: String,
    #[validate(length(min = 12, max = 128))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct VerifyEmailRequest {
    #[validate(length(min = 1, max = 512))]
    pub token: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ResendVerificationRequest {
    #[serde(deserialize_with = "normalize_email_field")]
    #[validate(email, length(max = 320))]
    #[schema(example = "person@example.com")]
    pub email: String,
}

/// Response body for operations whose details must not be disclosed.
#[derive(Debug, Serialize, ToSchema)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PaginationQuery {
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<u32>,
    #[param(minimum = 0)]
    pub offset: Option<u32>,
}

impl PaginationQuery {
    pub fn bounds(&self) -> (i64, i64) {
        let limit = self
            .limit
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE);
        let offset = self.offset.unwrap_or(0);
        (i64::from(limit), i64::from(offset))
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListResponse {
    pub users: Vec<PublicUser>,
    pub total: i64,
}
