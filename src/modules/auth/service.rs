use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    modules::{
        auth::{error::AuthError, extractor::AuthenticatedUser, token::AccessTokens},
        identity::{AuthEventType, IdentityService, PublicUser, UserStatus},
        session::{RefreshOutcome, SessionRepository},
    },
    shared::{
        config::AppConfig,
        request::ClientInfo,
        time::expires_in,
        tokens::{generate_secret_token, hash_secret_token},
    },
};

/// Everything a caller needs to establish a client-side session.
pub struct IssuedSession {
    pub user: PublicUser,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

struct SessionTokens {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

#[derive(Clone)]
pub struct AuthService {
    identity: Arc<IdentityService>,
    sessions: SessionRepository,
    tokens: AccessTokens,
    config: Arc<AppConfig>,
}

impl AuthService {
    pub fn new(identity: Arc<IdentityService>, database: PgPool, config: Arc<AppConfig>) -> Self {
        let tokens = AccessTokens::new(
            &config.jwt_secret,
            config.jwt_issuer.clone(),
            config.jwt_audience.clone(),
            config.access_token_ttl_seconds,
        );

        Self {
            identity,
            sessions: SessionRepository::new(database),
            tokens,
            config,
        }
    }

    /// Creates the account and sends the confirmation link. No session is issued: the client
    /// signs in through [`Self::login`], which enforces the verification requirement.
    pub async fn register(
        &self,
        email: &str,
        password: &str,
        client: &ClientInfo,
    ) -> Result<PublicUser, AuthError> {
        let registration = self.identity.register(email, password, client).await?;
        Ok(registration.user)
    }

    pub async fn login(
        &self,
        email: &str,
        password: &str,
        client: &ClientInfo,
    ) -> Result<IssuedSession, AuthError> {
        let user = self
            .identity
            .verify_credentials(email, password, client)
            .await?;
        let tokens = self.start_session(user.id, client).await?;
        let user = self.identity.public_user(&user).await?;

        Ok(IssuedSession {
            user,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_in: tokens.expires_in,
        })
    }

    /// Exchanges a refresh token for a new pair. Rotating on every use means a leaked token
    /// is only useful until the legitimate client refreshes.
    pub async fn refresh(
        &self,
        refresh_token: &str,
        client: &ClientInfo,
    ) -> Result<IssuedSession, AuthError> {
        let replacement = generate_secret_token();

        let outcome = self
            .sessions
            .refresh(
                &hash_secret_token(refresh_token),
                &hash_secret_token(&replacement),
                expires_in(self.config.refresh_token_ttl_seconds),
            )
            .await?;

        match outcome {
            RefreshOutcome::Rotated {
                user_id,
                session_id,
            } => {
                let user = self.session_user(user_id).await?;
                let (access_token, expires_in) = self.tokens.issue(user_id, session_id)?;

                self.identity
                    .record_event(AuthEventType::TokenRefreshed, user_id, client)
                    .await;

                Ok(IssuedSession {
                    user,
                    access_token,
                    refresh_token: replacement,
                    expires_in,
                })
            }
            RefreshOutcome::Reused {
                user_id,
                session_id,
            } => {
                // The whole session family is revoked rather than every session the account
                // holds: a rotated token can be replayed by a stolen copy or by a client
                // retrying a refresh it already completed, and neither should sign the user
                // out everywhere.
                self.sessions.revoke(session_id).await?;
                self.identity
                    .record_event(AuthEventType::TokenReuseDetected, user_id, client)
                    .await;

                Err(AuthError::InvalidToken)
            }
            RefreshOutcome::Invalid => Err(AuthError::InvalidToken),
        }
    }

    pub async fn logout(
        &self,
        session_id: Uuid,
        user_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(), AuthError> {
        self.sessions.revoke(session_id).await?;
        self.identity
            .record_event(AuthEventType::Logout, user_id, client)
            .await;

        Ok(())
    }

    pub async fn logout_all(&self, user_id: Uuid, client: &ClientInfo) -> Result<(), AuthError> {
        self.sessions.revoke_all_for_user(user_id).await?;
        self.identity
            .record_event(AuthEventType::Logout, user_id, client)
            .await;

        Ok(())
    }

    /// Resolves an access token to the acting user. The session is re-checked on every
    /// request so that a revoked session stops working immediately instead of lingering until
    /// the access token expires.
    pub async fn authenticate(&self, access_token: &str) -> Result<AuthenticatedUser, AuthError> {
        let claims = self.tokens.verify(access_token)?;
        let user_id = Uuid::parse_str(&claims.sub).map_err(|_| AuthError::InvalidToken)?;
        let session_id = Uuid::parse_str(&claims.sid).map_err(|_| AuthError::InvalidToken)?;

        if !self.sessions.is_active(session_id, user_id).await? {
            return Err(AuthError::InvalidToken);
        }

        let user = self.session_user(user_id).await?;

        Ok(AuthenticatedUser { user, session_id })
    }

    async fn start_session(
        &self,
        user_id: Uuid,
        client: &ClientInfo,
    ) -> Result<SessionTokens, AuthError> {
        let refresh_token = generate_secret_token();
        let ttl_seconds = self.config.refresh_token_ttl_seconds;
        let ip_address = client.ip_address.map(|address| address.to_string());

        let session_id = self
            .sessions
            .create(
                user_id,
                &hash_secret_token(&refresh_token),
                client.user_agent.as_deref(),
                ip_address.as_deref(),
                expires_in(ttl_seconds),
                expires_in(ttl_seconds),
            )
            .await?;

        let (access_token, expires_in) = self.tokens.issue(user_id, session_id)?;

        Ok(SessionTokens {
            access_token,
            refresh_token,
            expires_in,
        })
    }

    async fn session_user(&self, user_id: Uuid) -> Result<PublicUser, AuthError> {
        let user = self
            .identity
            .user_by_id(user_id)
            .await?
            .ok_or(AuthError::InvalidToken)?;

        if user.status == UserStatus::Disabled {
            return Err(AuthError::InvalidToken);
        }

        self.identity.public_user(&user).await.map_err(Into::into)
    }
}
