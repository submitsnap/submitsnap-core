use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "auth_event_type", rename_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum AuthEventType {
    AccountCreated,
    LoginSucceeded,
    LoginFailed,
    AccountLocked,
    Logout,
    TokenRefreshed,
    TokenReuseDetected,
    EmailVerificationSent,
    EmailVerified,
    PasswordResetRequested,
    PasswordResetCompleted,
    PasswordChanged,
    AccountStatusChanged,
    RoleGranted,
    RoleRevoked,
    AccountUnlocked,
    SessionsRevoked,
    AccountDeleted,
    OrganizationCreated,
    OrganizationRenamed,
    OrganizationDeleted,
    OrganizationMemberAdded,
    OrganizationMemberRoleChanged,
    OrganizationMemberRemoved,
}

/// An audit record to append. Borrowed fields keep the call sites cheap.
#[derive(Debug)]
pub struct AuthEvent<'a> {
    /// The account the event is about.
    pub user_id: Option<Uuid>,
    /// The authenticated account that caused it. Equal to `user_id` for anything an account
    /// does to itself, and different when an administrator acts on somebody else.
    pub actor_user_id: Option<Uuid>,
    /// Set for events that concern an organization's membership.
    pub organization_id: Option<Uuid>,
    /// Attempted email address. Recorded for failed logins so credential-stuffing campaigns
    /// can be investigated; it is personal data covered by the retention policy.
    pub email: Option<&'a str>,
    pub event_type: AuthEventType,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AuditEventRecord {
    pub id: i64,
    pub user_id: Option<Uuid>,
    pub actor_user_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub email: Option<String>,
    pub event_type: AuthEventType,
    /// Selected through `host()` so the value is a bare address rather than the `INET` text
    /// form, which carries a netmask.
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Narrowing applied when reading the audit trail. `None` means "do not filter on this".
#[derive(Debug, Clone, Default)]
pub struct AuditFilters {
    pub user_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    /// Normalized to lowercase, matching how addresses are stored and looked up.
    pub email: Option<String>,
    pub event_type: Option<AuthEventType>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

impl AuditFilters {
    pub fn from_query(
        user_id: Option<Uuid>,
        organization_id: Option<Uuid>,
        email: Option<&str>,
        event_type: Option<AuthEventType>,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            user_id,
            organization_id,
            email: email
                .map(str::trim)
                .filter(|address| !address.is_empty())
                .map(crate::modules::identity::model::normalize_email),
            event_type,
            since,
            until,
        }
    }
}

/// Shared `WHERE` for the audit queries. Every branch is `NULL`-tolerant so a single
/// parameterized statement serves filtered and unfiltered reads alike.
const AUDIT_FILTERS: &str = "WHERE ($1::uuid IS NULL OR user_id = $1) \
     AND ($2::uuid IS NULL OR organization_id = $2) \
     AND ($3::text IS NULL OR lower(email) = $3) \
     AND ($4::auth_event_type IS NULL OR event_type = $4) \
     AND ($5::timestamptz IS NULL OR created_at >= $5) \
     AND ($6::timestamptz IS NULL OR created_at < $6)";

#[derive(Clone)]
pub struct AuthEventRepository {
    database: PgPool,
}

impl AuthEventRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    /// Appends an audit record. Audit writes must never fail the operation they describe,
    /// so failures are logged instead of propagated. No field of the event is logged.
    pub async fn record(&self, event: AuthEvent<'_>) {
        let result = sqlx::query(
            "INSERT INTO auth_events \
                 (user_id, actor_user_id, organization_id, email, event_type, ip_address, user_agent) \
             VALUES ($1, $2, $3, $4, $5, $6::inet, $7)",
        )
        .bind(event.user_id)
        .bind(event.actor_user_id)
        .bind(event.organization_id)
        .bind(event.email)
        .bind(event.event_type)
        .bind(event.ip_address.map(|address| address.to_string()))
        .bind(event.user_agent)
        .execute(&self.database)
        .await;

        if let Err(error) = result {
            tracing::error!(
                error = ?error,
                event_type = ?event.event_type,
                "failed to record authentication event"
            );
        }
    }

    /// Reads the audit trail, newest first. Backed by the `(…, created_at DESC)` indexes.
    pub async fn list(
        &self,
        filters: &AuditFilters,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditEventRecord>, sqlx::Error> {
        sqlx::query_as::<_, AuditEventRecord>(&format!(
            "SELECT id, user_id, actor_user_id, organization_id, email, event_type, \
                    host(ip_address) AS ip_address, user_agent, created_at \
             FROM auth_events {AUDIT_FILTERS} \
             ORDER BY created_at DESC, id DESC LIMIT $7 OFFSET $8"
        ))
        .bind(filters.user_id)
        .bind(filters.organization_id)
        .bind(filters.email.as_deref())
        .bind(filters.event_type)
        .bind(filters.since)
        .bind(filters.until)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.database)
        .await
    }

    pub async fn count(&self, filters: &AuditFilters) -> Result<i64, sqlx::Error> {
        sqlx::query_scalar(&format!("SELECT count(*) FROM auth_events {AUDIT_FILTERS}"))
            .bind(filters.user_id)
            .bind(filters.organization_id)
            .bind(filters.email.as_deref())
            .bind(filters.event_type)
            .bind(filters.since)
            .bind(filters.until)
            .fetch_one(&self.database)
            .await
    }
}
