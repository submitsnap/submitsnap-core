use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    error::AppError,
    models::{PublicUser, UserRecord},
};

const TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Clone)]
pub struct AuthService {
    database: PgPool,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    exp: u64,
}

#[derive(Debug)]
pub struct AuthenticatedUser(pub PublicUser);

impl AuthService {
    pub fn new(database: PgPool, secret: &str, issuer: String) -> Self {
        Self {
            database,
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            issuer,
        }
    }

    pub async fn register(&self, email: String, password: String) -> Result<PublicUser, AppError> {
        let password_hash = hash_password(&password)?;
        let user_id = Uuid::new_v4();
        let user = sqlx::query_as::<_, UserRecord>(
            "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) \
             RETURNING id, email, password_hash, created_at",
        )
        .bind(user_id)
        .bind(email)
        .bind(password_hash)
        .fetch_one(&self.database)
        .await
        .map_err(map_database_error)?;
        Ok(user.into())
    }

    pub async fn login(
        &self,
        email: String,
        password: String,
    ) -> Result<(PublicUser, String), AppError> {
        let user = sqlx::query_as::<_, UserRecord>(
            "SELECT id, email, password_hash, created_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.database)
        .await
        .map_err(|error| AppError::Internal(error.into()))?
        .ok_or(AppError::Unauthorized)?;

        verify_password(&password, &user.password_hash)?;
        let public_user = PublicUser::from(user);
        let token = self.issue_token(public_user.id)?;
        Ok((public_user, token))
    }

    pub async fn authenticate(&self, token: &str) -> Result<AuthenticatedUser, AppError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);
        let claims = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| AppError::Unauthorized)?
            .claims;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AppError::Unauthorized)?;
        let user = sqlx::query_as::<_, UserRecord>(
            "SELECT id, email, password_hash, created_at FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.database)
        .await
        .map_err(|error| AppError::Internal(error.into()))?
        .ok_or(AppError::Unauthorized)?;
        Ok(AuthenticatedUser(user.into()))
    }

    fn issue_token(&self, user_id: Uuid) -> Result<String, AppError> {
        let expiry = SystemTime::now()
            .checked_add(TOKEN_LIFETIME)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("unable to calculate token expiry")))?
            .as_secs();
        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            exp: expiry,
        };
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|error| AppError::Internal(error.into()))
    }
}

#[async_trait]
impl FromRequestParts<crate::state::AppState> for AuthenticatedUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &crate::state::AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = bearer_token(parts)
            .or_else(|| cookie_token(parts))
            .ok_or(AppError::Unauthorized)?;
        state.auth.authenticate(token).await
    }
}

fn bearer_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn cookie_token(parts: &Parts) -> Option<&str> {
    parts
        .headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies
                .split(';')
                .map(str::trim)
                .find_map(|item| item.strip_prefix("access_token="))
        })
}

fn hash_password(password: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| AppError::Internal(anyhow::anyhow!(error.to_string())))
}

fn verify_password(password: &str, password_hash: &str) -> Result<(), AppError> {
    let parsed_hash = PasswordHash::new(password_hash).map_err(|_| AppError::Unauthorized)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::Unauthorized)
}

fn map_database_error(error: sqlx::Error) -> AppError {
    if error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        == Some("23505".into())
    {
        AppError::Conflict
    } else {
        AppError::Internal(error.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hashes_are_not_reversible() {
        let hash = hash_password("a sufficiently long password").unwrap();
        assert_ne!(hash, "a sufficiently long password");
        assert!(verify_password("a sufficiently long password", &hash).is_ok());
        assert!(verify_password("wrong password", &hash).is_err());
    }
}
