use std::net::IpAddr;

use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "auth_event_type", rename_all = "snake_case")]
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
}

/// An audit record to append. Borrowed fields keep the call sites cheap.
#[derive(Debug)]
pub struct AuthEvent<'a> {
    pub user_id: Option<Uuid>,
    /// Attempted email address. Recorded for failed logins so credential-stuffing campaigns
    /// can be investigated; it is personal data covered by the retention policy.
    pub email: Option<&'a str>,
    pub event_type: AuthEventType,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
}

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
            "INSERT INTO auth_events (user_id, email, event_type, ip_address, user_agent) \
             VALUES ($1, $2, $3, $4::inet, $5)",
        )
        .bind(event.user_id)
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
}
