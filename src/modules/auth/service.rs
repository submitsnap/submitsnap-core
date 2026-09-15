use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    modules::auth::{dto::PublicUser, error::AuthError, repository::UserRepository},
    shared::queue::{EmailJob, EmailQueue},
};

const TOKEN_LIFETIME: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Clone)]
pub struct AuthService {
    users: UserRepository,
    queue: EmailQueue,
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

impl AuthService {
    pub fn new(users: UserRepository, queue: EmailQueue, secret: &str, issuer: String) -> Self {
        Self {
            users,
            queue,
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            issuer,
        }
    }

    pub async fn register(&self, email: String, password: String) -> Result<PublicUser, AuthError> {
        let password_hash = hash_password(&password)?;
        let user = self
            .users
            .insert(Uuid::new_v4(), &email, &password_hash)
            .await?;
        let public_user = PublicUser::from(user);
        self.send_welcome_email(&email, public_user.id).await;
        Ok(public_user)
    }

    pub async fn login(
        &self,
        email: String,
        password: String,
    ) -> Result<(PublicUser, String), AuthError> {
        let user = self
            .users
            .find_by_email(&email)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        verify_password(&password, &user.password_hash)?;
        let public_user = PublicUser::from(user);
        let token = self.issue_token(public_user.id)?;
        Ok((public_user, token))
    }

    pub async fn authenticate(&self, token: &str) -> Result<PublicUser, AuthError> {
        let mut validation = Validation::default();
        validation.set_issuer(&[&self.issuer]);
        let claims = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| AuthError::InvalidCredentials)?
            .claims;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::InvalidCredentials)?;
        let user = self
            .users
            .find_by_id(user_id)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;
        Ok(user.into())
    }

    async fn send_welcome_email(&self, email: &str, user_id: Uuid) {
        let job = EmailJob {
            to: email.to_owned(),
            subject: "Welcome to SubmitSnap".into(),
            text_body: "Your SubmitSnap account is ready.".into(),
        };
        if let Err(error) = self.queue.enqueue(&job).await {
            // An account must not be rejected merely because a non-critical welcome email is delayed.
            tracing::error!(error = ?error, user_id = %user_id, "failed to enqueue welcome email");
        }
    }

    fn issue_token(&self, user_id: Uuid) -> Result<String, AuthError> {
        let expiry = SystemTime::now()
            .checked_add(TOKEN_LIFETIME)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .ok_or_else(|| {
                AuthError::Internal(anyhow::anyhow!("unable to calculate token expiry"))
            })?
            .as_secs();
        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            exp: expiry,
        };
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|error| AuthError::Internal(error.into()))
    }
}

fn hash_password(password: &str) -> Result<String, AuthError> {
    let salt = SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| AuthError::Internal(anyhow::anyhow!(error.to_string())))
}

fn verify_password(password: &str, password_hash: &str) -> Result<(), AuthError> {
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|_| AuthError::InvalidCredentials)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AuthError::InvalidCredentials)
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
