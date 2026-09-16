use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::modules::{
    identity::{
        error::IdentityError,
        model::{USER_COLUMNS, UserRecord, UserStatus},
    },
    rbac::RoleName,
};

/// Narrowing applied when listing accounts. `None` means "do not filter on this".
#[derive(Debug, Clone, Default)]
pub struct UserFilters {
    /// A `LIKE` pattern, already escaped and wrapped in wildcards by [`UserFilters::from_query`].
    pub search: Option<String>,
    pub status: Option<UserStatus>,
    pub role: Option<RoleName>,
}

impl UserFilters {
    /// Builds filters from raw operator input, escaping the search term so a stray `%` is
    /// matched literally instead of widening the query.
    pub fn from_query(
        search: Option<&str>,
        status: Option<UserStatus>,
        role: Option<RoleName>,
    ) -> Self {
        Self {
            search: search
                .map(str::trim)
                .filter(|term| !term.is_empty())
                .map(like_contains),
            status,
            role,
        }
    }
}

/// Escapes the `LIKE` metacharacters in a term so it matches literally, then wraps it in
/// wildcards for a substring search.
fn like_contains(term: &str) -> String {
    let escaped = term
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");

    format!("%{escaped}%")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_terms_are_escaped_and_wrapped() {
        assert_eq!(like_contains("ann"), "%ann%");
        assert_eq!(like_contains("100%"), "%100\\%%");
        assert_eq!(like_contains("a_b"), "%a\\_b%");
        assert_eq!(like_contains("back\\slash"), "%back\\\\slash%");
    }

    #[test]
    fn blank_search_terms_are_dropped() {
        assert!(
            UserFilters::from_query(Some("   "), None, None)
                .search
                .is_none()
        );
        assert!(UserFilters::from_query(None, None, None).search.is_none());
        assert_eq!(
            UserFilters::from_query(Some(" ann "), None, None)
                .search
                .as_deref(),
            Some("%ann%")
        );
    }
}

/// Shared `WHERE` for the account listing queries. Every branch is `NULL`-tolerant, so one
/// parameterized statement serves filtered and unfiltered reads alike.
const USER_FILTERS: &str = "WHERE ($1::text IS NULL OR lower(email) LIKE $1) \
     AND ($2::user_status IS NULL OR status = $2) \
     AND ($3::text IS NULL OR EXISTS ( \
         SELECT 1 FROM user_roles \
         JOIN roles ON roles.id = user_roles.role_id \
         WHERE user_roles.user_id = users.id AND roles.name = $3))";

#[derive(Clone)]
pub struct UserRepository {
    database: PgPool,
}

impl UserRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    /// Starts a transaction so account creation and role assignment commit together.
    pub async fn begin(&self) -> Result<Transaction<'static, Postgres>, IdentityError> {
        self.database.begin().await.map_err(internal)
    }

    pub async fn insert<'e, E>(
        &self,
        executor: E,
        id: Uuid,
        email: &str,
        password_hash: &str,
        status: UserStatus,
    ) -> Result<UserRecord, IdentityError>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, UserRecord>(&format!(
            "INSERT INTO users (id, email, password_hash, status) VALUES ($1, $2, $3, $4) \
             RETURNING {USER_COLUMNS}"
        ))
        .bind(id)
        .bind(email)
        .bind(password_hash)
        .bind(status)
        .fetch_one(executor)
        .await
        .map_err(map_insert_error)
    }

    /// Lookup is case-insensitive on both sides so a record written before normalization was
    /// introduced can still authenticate.
    pub async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>, IdentityError> {
        sqlx::query_as::<_, UserRecord>(&format!(
            "SELECT {USER_COLUMNS} FROM users WHERE lower(email) = $1"
        ))
        .bind(email)
        .fetch_optional(&self.database)
        .await
        .map_err(internal)
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<UserRecord>, IdentityError> {
        sqlx::query_as::<_, UserRecord>(&format!("SELECT {USER_COLUMNS} FROM users WHERE id = $1"))
            .bind(id)
            .fetch_optional(&self.database)
            .await
            .map_err(internal)
    }

    /// Lists accounts newest first, with optional narrowing. Backed by the `created_at DESC`
    /// index; `search` is a substring match, so it scans within the page rather than seeking.
    pub async fn list(
        &self,
        filters: &UserFilters,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<UserRecord>, IdentityError> {
        sqlx::query_as::<_, UserRecord>(&format!(
            "SELECT {USER_COLUMNS} FROM users {USER_FILTERS} \
             ORDER BY created_at DESC, id LIMIT $4 OFFSET $5"
        ))
        .bind(filters.search.as_deref())
        .bind(filters.status)
        .bind(filters.role.as_ref().map(RoleName::as_str))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.database)
        .await
        .map_err(internal)
    }

    pub async fn count(&self, filters: &UserFilters) -> Result<i64, IdentityError> {
        sqlx::query_scalar(&format!("SELECT count(*) FROM users {USER_FILTERS}"))
            .bind(filters.search.as_deref())
            .bind(filters.status)
            .bind(filters.role.as_ref().map(RoleName::as_str))
            .fetch_one(&self.database)
            .await
            .map_err(internal)
    }

    /// Removes an account. Sessions, refresh tokens, and role grants cascade away; audit rows
    /// survive with their account reference cleared, which is what an audit trail should do.
    pub async fn delete(&self, id: Uuid) -> Result<bool, IdentityError> {
        let outcome = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.database)
            .await
            .map_err(internal)?;

        Ok(outcome.rows_affected() > 0)
    }

    /// Clears the failure window after a successful authentication.
    pub async fn record_login_success(&self, id: Uuid) -> Result<(), IdentityError> {
        sqlx::query(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW() \
             WHERE id = $1",
        )
        .bind(id)
        .execute(&self.database)
        .await
        .map_err(internal)?;

        Ok(())
    }

    /// Clears counters left behind by an expired lock so the next failure starts a fresh window.
    pub async fn reset_login_failures(&self, id: Uuid) -> Result<(), IdentityError> {
        sqlx::query(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = $1",
        )
        .bind(id)
        .execute(&self.database)
        .await
        .map_err(internal)?;

        Ok(())
    }

    /// Counts a failed attempt and applies `lock_until` once `max_attempts` is reached.
    /// Returns the lock expiry when the account is now locked.
    pub async fn record_login_failure(
        &self,
        id: Uuid,
        max_attempts: u32,
        lock_until: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>, IdentityError> {
        let max_attempts = i32::try_from(max_attempts).unwrap_or(i32::MAX);

        sqlx::query_scalar(
            "UPDATE users \
             SET failed_login_attempts = failed_login_attempts + 1, \
                 locked_until = CASE \
                     WHEN failed_login_attempts + 1 >= $2 THEN $3 \
                     ELSE locked_until \
                 END \
             WHERE id = $1 \
             RETURNING locked_until",
        )
        .bind(id)
        .bind(max_attempts)
        .bind(lock_until)
        .fetch_one(&self.database)
        .await
        .map_err(internal)
    }

    /// Sets a new password and invalidates any active lock, used by reset and change flows.
    pub async fn update_password(
        &self,
        id: Uuid,
        password_hash: &str,
    ) -> Result<(), IdentityError> {
        sqlx::query(
            "UPDATE users \
             SET password_hash = $2, password_changed_at = NOW(), \
                 failed_login_attempts = 0, locked_until = NULL \
             WHERE id = $1",
        )
        .bind(id)
        .bind(password_hash)
        .execute(&self.database)
        .await
        .map_err(internal)?;

        Ok(())
    }

    /// Replaces the stored hash without touching lock state or the password-changed timestamp.
    /// Used when a password verifies against outdated Argon2 parameters.
    pub async fn replace_password_hash(
        &self,
        id: Uuid,
        password_hash: &str,
    ) -> Result<(), IdentityError> {
        sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(password_hash)
            .execute(&self.database)
            .await
            .map_err(internal)?;

        Ok(())
    }

    pub async fn mark_email_verified(&self, id: Uuid) -> Result<(), IdentityError> {
        sqlx::query(
            "UPDATE users \
             SET email_verified_at = NOW(), \
                 status = CASE WHEN status = 'pending'::user_status \
                     THEN 'active'::user_status ELSE status END \
             WHERE id = $1",
        )
        .bind(id)
        .execute(&self.database)
        .await
        .map_err(internal)?;

        Ok(())
    }

    /// Applies an administrative status change. Returns `false` when no such account exists,
    /// so the caller can answer with a 404 instead of pretending it worked.
    pub async fn set_status(&self, id: Uuid, status: UserStatus) -> Result<bool, IdentityError> {
        let outcome = sqlx::query("UPDATE users SET status = $2 WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(&self.database)
            .await
            .map_err(internal)?;

        Ok(outcome.rows_affected() > 0)
    }
}

fn internal(error: sqlx::Error) -> IdentityError {
    IdentityError::Internal(error.into())
}

/// Translates the case-insensitive email uniqueness violation into a domain error.
fn map_insert_error(error: sqlx::Error) -> IdentityError {
    let is_duplicate_email = error
        .as_database_error()
        .filter(|database_error| database_error.code().as_deref() == Some("23505"))
        .and_then(|database_error| database_error.constraint())
        .is_some_and(|constraint| constraint.contains("email"));

    if is_duplicate_email {
        IdentityError::EmailTaken
    } else {
        internal(error)
    }
}
