use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::modules::session::RefreshOutcome;

#[derive(Debug, FromRow)]
struct TokenLookup {
    token_id: Uuid,
    session_id: Uuid,
    user_id: Uuid,
    used_at: Option<DateTime<Utc>>,
    token_expires_at: DateTime<Utc>,
    session_revoked_at: Option<DateTime<Utc>>,
    session_expires_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct SessionRepository {
    database: PgPool,
}

impl SessionRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    /// Opens a session and records its first refresh token.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        user_id: Uuid,
        token_hash: &[u8],
        user_agent: Option<&str>,
        ip_address: Option<&str>,
        session_expires_at: DateTime<Utc>,
        token_expires_at: DateTime<Utc>,
    ) -> anyhow::Result<Uuid> {
        let mut transaction = self.database.begin().await?;

        let session_id: Uuid = sqlx::query_scalar(
            "INSERT INTO sessions (user_id, user_agent, ip_address, expires_at) \
             VALUES ($1, $2, $3::inet, $4) RETURNING id",
        )
        .bind(user_id)
        .bind(user_agent)
        .bind(ip_address)
        .bind(session_expires_at)
        .fetch_one(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT INTO session_tokens (session_id, token_hash, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(session_id)
        .bind(token_hash)
        .bind(token_expires_at)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(session_id)
    }

    /// Exchanges a refresh token for a new one.
    ///
    /// The lookup takes a row lock so two concurrent redemptions of the same token cannot
    /// both succeed; the loser observes `used_at` and is reported as a reuse.
    pub async fn refresh(
        &self,
        presented_hash: &[u8],
        new_hash: &[u8],
        new_expires_at: DateTime<Utc>,
    ) -> anyhow::Result<RefreshOutcome> {
        let mut transaction = self.database.begin().await?;

        let lookup = sqlx::query_as::<_, TokenLookup>(
            "SELECT session_tokens.id AS token_id, session_tokens.session_id, \
                    sessions.user_id, session_tokens.used_at, \
                    session_tokens.expires_at AS token_expires_at, \
                    sessions.revoked_at AS session_revoked_at, \
                    sessions.expires_at AS session_expires_at \
             FROM session_tokens \
             JOIN sessions ON sessions.id = session_tokens.session_id \
             WHERE session_tokens.token_hash = $1 \
             FOR UPDATE",
        )
        .bind(presented_hash)
        .fetch_optional(&mut *transaction)
        .await?;

        let Some(lookup) = lookup else {
            return Ok(RefreshOutcome::Invalid);
        };

        if lookup.used_at.is_some() {
            // Nothing to undo: a rolled back transaction keeps the state attackers see.
            return Ok(RefreshOutcome::Reused {
                user_id: lookup.user_id,
                session_id: lookup.session_id,
            });
        }

        let now = Utc::now();
        if lookup.session_revoked_at.is_some()
            || lookup.token_expires_at <= now
            || lookup.session_expires_at <= now
        {
            return Ok(RefreshOutcome::Invalid);
        }

        // The replacement token never outlives the session it belongs to, so rotation cannot
        // extend a session indefinitely.
        let replacement_id: Uuid = sqlx::query_scalar(
            "INSERT INTO session_tokens (session_id, token_hash, expires_at) \
             SELECT sessions.id, $2, LEAST($3::timestamptz, sessions.expires_at) \
             FROM sessions WHERE sessions.id = $1 \
             RETURNING id",
        )
        .bind(lookup.session_id)
        .bind(new_hash)
        .bind(new_expires_at)
        .fetch_one(&mut *transaction)
        .await?;

        sqlx::query("UPDATE session_tokens SET used_at = NOW(), replaced_by = $2 WHERE id = $1")
            .bind(lookup.token_id)
            .bind(replacement_id)
            .execute(&mut *transaction)
            .await?;

        sqlx::query("UPDATE sessions SET last_used_at = NOW() WHERE id = $1")
            .bind(lookup.session_id)
            .execute(&mut *transaction)
            .await?;

        transaction.commit().await?;

        Ok(RefreshOutcome::Rotated {
            user_id: lookup.user_id,
            session_id: lookup.session_id,
        })
    }

    /// Whether the session is still usable by that user. Cheap primary-key lookup, called on
    /// every authenticated request so that logout takes effect immediately rather than when
    /// the access token expires.
    pub async fn is_active(&self, session_id: Uuid, user_id: Uuid) -> anyhow::Result<bool> {
        let active: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM sessions \
             WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > NOW())",
        )
        .bind(session_id)
        .bind(user_id)
        .fetch_one(&self.database)
        .await?;

        Ok(active)
    }

    pub async fn revoke(&self, session_id: Uuid) -> anyhow::Result<()> {
        sqlx::query("UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL")
            .bind(session_id)
            .execute(&self.database)
            .await?;

        Ok(())
    }

    pub async fn revoke_all_for_user(&self, user_id: Uuid) -> anyhow::Result<u64> {
        let outcome = sqlx::query(
            "UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .execute(&self.database)
        .await?;

        Ok(outcome.rows_affected())
    }

    /// Revokes every session except the one making the request, used after a password change.
    pub async fn revoke_others(&self, user_id: Uuid, keep: Uuid) -> anyhow::Result<u64> {
        let outcome = sqlx::query(
            "UPDATE sessions SET revoked_at = NOW() \
             WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(keep)
        .execute(&self.database)
        .await?;

        Ok(outcome.rows_affected())
    }
}
