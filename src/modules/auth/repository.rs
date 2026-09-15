use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::modules::auth::error::AuthError;

#[derive(Debug, FromRow)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct UserRepository {
    database: PgPool,
}

impl UserRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    pub async fn insert(
        &self,
        id: Uuid,
        email: &str,
        password_hash: &str,
    ) -> Result<UserRecord, AuthError> {
        sqlx::query_as::<_, UserRecord>(
            "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) \
             RETURNING id, email, password_hash, created_at",
        )
        .bind(id)
        .bind(email)
        .bind(password_hash)
        .fetch_one(&self.database)
        .await
        .map_err(map_insert_error)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<UserRecord>, AuthError> {
        sqlx::query_as::<_, UserRecord>(
            "SELECT id, email, password_hash, created_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.database)
        .await
        .map_err(|error| AuthError::Internal(error.into()))
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Option<UserRecord>, AuthError> {
        sqlx::query_as::<_, UserRecord>(
            "SELECT id, email, password_hash, created_at FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.database)
        .await
        .map_err(|error| AuthError::Internal(error.into()))
    }
}

fn map_insert_error(error: sqlx::Error) -> AuthError {
    if error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        == Some("23505".into())
    {
        AuthError::EmailTaken
    } else {
        AuthError::Internal(error.into())
    }
}
