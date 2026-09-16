use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::modules::{
    identity::{
        events::{AuditEventRecord, AuthEventType},
        model::{UserRecord, UserStatus, normalize_email},
    },
    rbac::RoleName,
};

/// Normalizes an email as it enters the process, before validation runs. Every entry point
/// therefore validates, stores, and looks up the same canonical form.
pub(crate) fn normalize_email_field<'de, D>(deserializer: D) -> Result<String, D::Error>
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

/// The status values an administrator may set. `pending` is deliberately excluded: it is
/// assigned by the system when verification is required, not chosen by an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AccountStatusUpdate {
    Active,
    Disabled,
}

impl From<AccountStatusUpdate> for UserStatus {
    fn from(update: AccountStatusUpdate) -> Self {
        match update {
            AccountStatusUpdate::Active => Self::Active,
            AccountStatusUpdate::Disabled => Self::Disabled,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserStatusRequest {
    pub status: AccountStatusUpdate,
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

/// The administrator's view of an account: [`PublicUser`] plus the operational state that a
/// self-service endpoint deliberately withholds.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AdminUser {
    pub id: Uuid,
    pub email: String,
    pub status: UserStatus,
    pub email_verified: bool,
    pub roles: Vec<RoleName>,
    pub failed_login_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl AdminUser {
    pub fn new(user: &UserRecord, roles: Vec<RoleName>) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            status: user.status,
            email_verified: user.is_email_verified(),
            roles,
            failed_login_attempts: user.failed_login_attempts,
            locked_until: user.locked_until,
            last_login_at: user.last_login_at,
            created_at: user.created_at,
        }
    }
}

/// The complete role set an account should end up with.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRolesRequest {
    pub roles: Vec<RoleName>,
}

/// Deleting an account is irreversible, so the caller must echo the address back as a
/// deliberate confirmation rather than a mis-clicked identifier.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteAccountRequest {
    #[schema(example = "person@example.com")]
    pub confirm_email: String,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListUsersQuery {
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<u32>,
    #[param(minimum = 0)]
    pub offset: Option<u32>,
    /// Case-insensitive substring match on the email address.
    pub search: Option<String>,
    pub status: Option<UserStatus>,
    pub role: Option<RoleName>,
}

impl ListUsersQuery {
    pub fn bounds(&self) -> (i64, i64) {
        page_bounds(self.limit, self.offset)
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListResponse {
    pub users: Vec<AdminUser>,
    pub total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventResponse {
    pub id: i64,
    /// The account the event concerns.
    pub user_id: Option<Uuid>,
    /// The account that caused it, when that is not the same account.
    pub actor_user_id: Option<Uuid>,
    /// The organization the event concerns, for membership changes.
    pub organization_id: Option<Uuid>,
    /// The resource the event concerns: a form, a submission, a webhook endpoint.
    pub target_id: Option<Uuid>,
    pub email: Option<String>,
    pub event_type: AuthEventType,
    /// Source address, without the netmask an `INET` would otherwise carry.
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<AuditEventRecord> for AuditEventResponse {
    fn from(record: AuditEventRecord) -> Self {
        Self {
            id: record.id,
            user_id: record.user_id,
            actor_user_id: record.actor_user_id,
            organization_id: record.organization_id,
            target_id: record.target_id,
            email: record.email,
            event_type: record.event_type,
            ip_address: record.ip_address,
            user_agent: record.user_agent,
            created_at: record.created_at,
        }
    }
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListAuditEventsQuery {
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<u32>,
    #[param(minimum = 0)]
    pub offset: Option<u32>,
    pub user_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub email: Option<String>,
    pub event_type: Option<AuthEventType>,
    /// Inclusive lower bound, as an RFC 3339 timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Exclusive upper bound, as an RFC 3339 timestamp.
    pub until: Option<DateTime<Utc>>,
}

impl ListAuditEventsQuery {
    pub fn bounds(&self) -> (i64, i64) {
        page_bounds(self.limit, self.offset)
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventListResponse {
    pub events: Vec<AuditEventResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionsRevokedResponse {
    pub revoked: u64,
}

/// Clamps a requested page to something a single query can serve.
pub(crate) fn page_bounds(limit: Option<u32>, offset: Option<u32>) -> (i64, i64) {
    crate::shared::pagination::page_bounds(limit, offset)
}
