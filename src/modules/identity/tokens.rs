use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "one_time_token_purpose", rename_all = "snake_case")]
pub enum OneTimeTokenPurpose {
    EmailVerification,
    PasswordReset,
}

#[derive(Clone)]
pub struct OneTimeTokenRepository {
    database: PgPool,
}

impl OneTimeTokenRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    /// Invalidates previously issued tokens of the same purpose, so at most one link is
    /// live per account and purpose.
    pub async fn invalidate_outstanding<'e, E>(
        &self,
        executor: E,
        user_id: Uuid,
        purpose: OneTimeTokenPurpose,
    ) -> anyhow::Result<()>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "UPDATE one_time_tokens SET consumed_at = NOW() \
             WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL",
        )
        .bind(user_id)
        .bind(purpose)
        .execute(executor)
        .await?;

        Ok(())
    }

    pub async fn issue<'e, E>(
        &self,
        executor: E,
        user_id: Uuid,
        purpose: OneTimeTokenPurpose,
        token_hash: &[u8],
        expires_at: DateTime<Utc>,
    ) -> anyhow::Result<()>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO one_time_tokens (user_id, purpose, token_hash, expires_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(user_id)
        .bind(purpose)
        .bind(token_hash)
        .bind(expires_at)
        .execute(executor)
        .await?;

        Ok(())
    }

    /// Claims a token for single use. The `consumed_at IS NULL AND expires_at > NOW()` guard
    /// makes concurrent redemptions safe: exactly one caller sees the user id.
    pub async fn consume(
        &self,
        token_hash: &[u8],
        purpose: OneTimeTokenPurpose,
    ) -> anyhow::Result<Option<Uuid>> {
        let user_id: Option<Uuid> = sqlx::query_scalar(
            "UPDATE one_time_tokens SET consumed_at = NOW() \
             WHERE token_hash = $1 AND purpose = $2 \
               AND consumed_at IS NULL AND expires_at > NOW() \
             RETURNING user_id",
        )
        .bind(token_hash)
        .bind(purpose)
        .fetch_optional(&self.database)
        .await?;

        Ok(user_id)
    }
}
