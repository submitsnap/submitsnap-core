use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    modules::{
        identity::{
            dto::PublicUser,
            error::IdentityError,
            events::{AuthEvent, AuthEventRepository, AuthEventType},
            model::{UserRecord, UserStatus, normalize_email},
            password::PasswordHasher,
            repository::UserRepository,
            tokens::{OneTimeTokenPurpose, OneTimeTokenRepository},
        },
        rbac::{RoleName, RoleRepository},
        session::SessionRepository,
    },
    shared::{
        config::AppConfig,
        queue::{EmailJob, EmailQueue},
        request::ClientInfo,
        time::expires_in,
        tokens::{generate_secret_token, hash_secret_token},
    },
};

/// Outcome of a registration. `verification_token` lets the caller dispatch the confirmation
/// link (and lets tests complete the flow); it must never reach an HTTP response body.
pub struct Registration {
    pub user: PublicUser,
    pub verification_token: String,
}

/// How many times handing a message to the queue is attempted before giving up.
const EMAIL_ENQUEUE_ATTEMPTS: u32 = 3;
/// First retry delay; each subsequent retry doubles it.
const EMAIL_ENQUEUE_BASE_DELAY_MS: u64 = 50;

/// Shared collaborators for the account lifecycle and for administration, which lives in the
/// sibling `administration` module and therefore needs `pub(super)` access.
#[derive(Clone)]
pub struct IdentityService {
    pub(super) users: UserRepository,
    pub(super) tokens: OneTimeTokenRepository,
    pub(super) roles: RoleRepository,
    pub(super) sessions: SessionRepository,
    pub(super) events: AuthEventRepository,
    passwords: PasswordHasher,
    queue: EmailQueue,
    config: Arc<AppConfig>,
}

impl IdentityService {
    pub fn new(
        database: PgPool,
        queue: EmailQueue,
        config: Arc<AppConfig>,
    ) -> anyhow::Result<Self> {
        let passwords = PasswordHasher::new(config.password_pepper.clone())?;

        Ok(Self {
            users: UserRepository::new(database.clone()),
            tokens: OneTimeTokenRepository::new(database.clone()),
            roles: RoleRepository::new(database.clone()),
            sessions: SessionRepository::new(database.clone()),
            events: AuthEventRepository::new(database),
            passwords,
            queue,
            config,
        })
    }

    pub async fn register(
        &self,
        email: &str,
        password: &str,
        client: &ClientInfo,
    ) -> Result<Registration, IdentityError> {
        let email = normalize_email(email);
        let password_hash = self
            .passwords
            .hash(password)
            .map_err(IdentityError::Internal)?;
        let status = if self.config.require_email_verification {
            UserStatus::Pending
        } else {
            UserStatus::Active
        };

        // The account and its default role must both exist or neither should.
        let mut transaction = self.users.begin().await?;
        let user = self
            .users
            .insert(
                &mut *transaction,
                Uuid::new_v4(),
                &email,
                &password_hash,
                status,
            )
            .await?;
        self.roles
            .assign(&mut *transaction, user.id, &RoleName::user())
            .await
            .map_err(IdentityError::Internal)?;
        transaction.commit().await?;

        self.record(
            AuthEventType::AccountCreated,
            Some(user.id),
            Some(&user.email),
            client,
        )
        .await;

        let verification_token = self.issue_email_verification(&user, client).await?;
        let roles = self.roles_for(user.id).await?;

        Ok(Registration {
            user: PublicUser::new(&user, roles),
            verification_token,
        })
    }

    /// Verifies a password and updates the account's login state, including lockout.
    /// Unknown accounts still pay the cost of a password verification so response timing
    /// does not disclose whether an address is registered.
    pub async fn verify_credentials(
        &self,
        email: &str,
        password: &str,
        client: &ClientInfo,
    ) -> Result<UserRecord, IdentityError> {
        let email = normalize_email(email);
        let Some(user) = self.users.find_by_email(&email).await? else {
            self.passwords.verify_canary(password);
            self.record(AuthEventType::LoginFailed, None, Some(&email), client)
                .await;
            return Err(IdentityError::InvalidCredentials);
        };

        let now = Utc::now();
        if user.is_locked(now) {
            self.record(
                AuthEventType::LoginFailed,
                Some(user.id),
                Some(&user.email),
                client,
            )
            .await;
            return Err(IdentityError::AccountLocked);
        }

        if user.status == UserStatus::Disabled {
            self.record(
                AuthEventType::LoginFailed,
                Some(user.id),
                Some(&user.email),
                client,
            )
            .await;
            return Err(IdentityError::AccountDisabled);
        }

        if !self.passwords.verify(password, &user.password_hash) {
            // A leftover lock that has already expired must not count against this attempt.
            if user.locked_until.is_some() {
                self.users.reset_login_failures(user.id).await?;
            }

            let locked_until = self.lock_expiry();
            let locked = self
                .users
                .record_login_failure(user.id, self.config.max_failed_login_attempts, locked_until)
                .await?;

            self.record(
                AuthEventType::LoginFailed,
                Some(user.id),
                Some(&user.email),
                client,
            )
            .await;

            if locked.is_some_and(|until| until > now) {
                self.record(
                    AuthEventType::AccountLocked,
                    Some(user.id),
                    Some(&user.email),
                    client,
                )
                .await;
                return Err(IdentityError::AccountLocked);
            }

            return Err(IdentityError::InvalidCredentials);
        }

        if self.config.require_email_verification && !user.is_email_verified() {
            return Err(IdentityError::EmailNotVerified);
        }

        if self.passwords.needs_rehash(&user.password_hash) {
            self.upgrade_password_hash(user.id, password).await;
        }

        self.users.record_login_success(user.id).await?;
        self.record(
            AuthEventType::LoginSucceeded,
            Some(user.id),
            Some(&user.email),
            client,
        )
        .await;

        Ok(user)
    }

    /// Replaces the password and signs out every other device, keeping the caller's session.
    pub async fn change_password(
        &self,
        user: &UserRecord,
        current_password: &str,
        new_password: &str,
        current_session: Uuid,
        client: &ClientInfo,
    ) -> Result<(), IdentityError> {
        if !self.passwords.verify(current_password, &user.password_hash) {
            return Err(IdentityError::InvalidCredentials);
        }

        let password_hash = self
            .passwords
            .hash(new_password)
            .map_err(IdentityError::Internal)?;
        self.users.update_password(user.id, &password_hash).await?;
        self.sessions
            .revoke_others(user.id, current_session)
            .await
            .map_err(IdentityError::Internal)?;

        self.record(
            AuthEventType::PasswordChanged,
            Some(user.id),
            Some(&user.email),
            client,
        )
        .await;

        Ok(())
    }

    /// Starts a password reset. Always reports success so the endpoint cannot be used to
    /// discover which addresses have accounts.
    ///
    /// The raw reset token is returned so the caller can dispatch it; it must never reach an
    /// HTTP response body.
    pub async fn request_password_reset(
        &self,
        email: &str,
        client: &ClientInfo,
    ) -> Result<Option<String>, IdentityError> {
        let email = normalize_email(email);
        let Some(user) = self.users.find_by_email(&email).await? else {
            return Ok(None);
        };

        if user.status == UserStatus::Disabled {
            return Ok(None);
        }

        let token = self
            .issue_one_time_token(
                user.id,
                OneTimeTokenPurpose::PasswordReset,
                self.config.password_reset_ttl_seconds,
            )
            .await?;

        self.record(
            AuthEventType::PasswordResetRequested,
            Some(user.id),
            Some(&user.email),
            client,
        )
        .await;

        let link = format!(
            "{}/reset-password?token={token}",
            self.config.app_base_url.trim_end_matches('/')
        );
        self.enqueue_email(
            &user.email,
            "Reset your SubmitSnap password",
            &format!(
                "Use this link to choose a new password:\n{link}\n\n\
                 If you did not request this, you can ignore this message."
            ),
        )
        .await;

        Ok(Some(token))
    }

    /// Completes a password reset. Every session is revoked, because a reset is the recovery
    /// path for a possibly compromised account.
    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
        client: &ClientInfo,
    ) -> Result<(), IdentityError> {
        let token_hash = hash_secret_token(token);
        let user_id = self
            .tokens
            .consume(&token_hash, OneTimeTokenPurpose::PasswordReset)
            .await
            .map_err(IdentityError::Internal)?
            .ok_or(IdentityError::InvalidToken)?;

        let password_hash = self
            .passwords
            .hash(new_password)
            .map_err(IdentityError::Internal)?;
        self.users.update_password(user_id, &password_hash).await?;
        self.sessions
            .revoke_all_for_user(user_id)
            .await
            .map_err(IdentityError::Internal)?;

        let email = self.users.find_by_id(user_id).await?.map(|user| user.email);
        self.record(
            AuthEventType::PasswordResetCompleted,
            Some(user_id),
            email.as_deref(),
            client,
        )
        .await;

        Ok(())
    }

    pub async fn verify_email(
        &self,
        token: &str,
        client: &ClientInfo,
    ) -> Result<(), IdentityError> {
        let token_hash = hash_secret_token(token);
        let user_id = self
            .tokens
            .consume(&token_hash, OneTimeTokenPurpose::EmailVerification)
            .await
            .map_err(IdentityError::Internal)?
            .ok_or(IdentityError::InvalidToken)?;

        self.users.mark_email_verified(user_id).await?;

        let email = self.users.find_by_id(user_id).await?.map(|user| user.email);
        self.record(
            AuthEventType::EmailVerified,
            Some(user_id),
            email.as_deref(),
            client,
        )
        .await;

        Ok(())
    }

    /// Re-sends the verification link. Reports success for unknown, already verified, and
    /// disabled accounts so the endpoint leaks nothing.
    pub async fn resend_verification(
        &self,
        email: &str,
        client: &ClientInfo,
    ) -> Result<(), IdentityError> {
        let email = normalize_email(email);
        let Some(user) = self.users.find_by_email(&email).await? else {
            return Ok(());
        };

        if user.is_email_verified() || user.status == UserStatus::Disabled {
            return Ok(());
        }

        self.issue_email_verification(&user, client).await?;

        Ok(())
    }

    pub async fn user_by_id(&self, id: Uuid) -> Result<Option<UserRecord>, IdentityError> {
        self.users.find_by_id(id).await
    }

    pub async fn roles_for(&self, user_id: Uuid) -> Result<Vec<RoleName>, IdentityError> {
        self.roles
            .roles_for_user(user_id)
            .await
            .map_err(IdentityError::Internal)
    }

    pub async fn public_user(&self, user: &UserRecord) -> Result<PublicUser, IdentityError> {
        let roles = self.roles_for(user.id).await?;
        Ok(PublicUser::new(user, roles))
    }

    /// Issues (and emails) a fresh verification link, invalidating any outstanding one.
    /// The raw token is returned to the caller for dispatch and must not be exposed.
    async fn issue_email_verification(
        &self,
        user: &UserRecord,
        client: &ClientInfo,
    ) -> Result<String, IdentityError> {
        let token = self
            .issue_one_time_token(
                user.id,
                OneTimeTokenPurpose::EmailVerification,
                self.config.email_verification_ttl_seconds,
            )
            .await?;

        self.record(
            AuthEventType::EmailVerificationSent,
            Some(user.id),
            Some(&user.email),
            client,
        )
        .await;

        let link = format!(
            "{}/verify-email?token={token}",
            self.config.app_base_url.trim_end_matches('/')
        );
        self.enqueue_email(
            &user.email,
            "Confirm your SubmitSnap email address",
            &format!("Confirm your email address by visiting:\n{link}\n"),
        )
        .await;

        Ok(token)
    }

    async fn issue_one_time_token(
        &self,
        user_id: Uuid,
        purpose: OneTimeTokenPurpose,
        ttl_seconds: u64,
    ) -> Result<String, IdentityError> {
        let token = generate_secret_token();
        let expires_at = expires_in(ttl_seconds);

        let mut transaction = self.users.begin().await?;
        self.tokens
            .invalidate_outstanding(&mut *transaction, user_id, purpose)
            .await
            .map_err(IdentityError::Internal)?;
        self.tokens
            .issue(
                &mut *transaction,
                user_id,
                purpose,
                &hash_secret_token(&token),
                expires_at,
            )
            .await
            .map_err(IdentityError::Internal)?;
        transaction.commit().await?;

        Ok(token)
    }

    /// Appends an audit record for an account-scoped security event raised outside this
    /// module (session and token lifecycle events).
    pub async fn record_event(
        &self,
        event_type: AuthEventType,
        user_id: Uuid,
        client: &ClientInfo,
    ) {
        self.record(event_type, Some(user_id), None, client).await;
    }

    async fn upgrade_password_hash(&self, user_id: Uuid, password: &str) {
        let Ok(password_hash) = self.passwords.hash(password) else {
            return;
        };
        if let Err(error) = self
            .users
            .replace_password_hash(user_id, &password_hash)
            .await
        {
            tracing::warn!(error = ?error, "failed to upgrade stored password hash");
        }
    }

    /// Hands a message to the queue, retrying a couple of times so a brief broker blip does
    /// not lose a verification link. The operation that triggered the mail must not fail
    /// because of it, so an exhausted retry is logged rather than returned; the recipient can
    /// always ask for another link. Never logs the message body, which carries the token.
    async fn enqueue_email(&self, to: &str, subject: &str, body: &str) {
        let job = EmailJob {
            to: to.to_owned(),
            subject: subject.to_owned(),
            text_body: body.to_owned(),
        };

        for attempt in 1..=EMAIL_ENQUEUE_ATTEMPTS {
            match self.queue.enqueue(&job).await {
                Ok(()) => return,
                Err(error) if attempt == EMAIL_ENQUEUE_ATTEMPTS => {
                    tracing::error!(
                        error = ?error,
                        attempts = attempt,
                        "failed to enqueue email; the recipient must request another link"
                    );
                }
                Err(_) => {
                    let backoff = EMAIL_ENQUEUE_BASE_DELAY_MS * 2u64.pow(attempt - 1);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                }
            }
        }
    }

    /// Appends an audit record for something an account did to itself, where the actor and the
    /// subject are the same account.
    pub(super) async fn record(
        &self,
        event_type: AuthEventType,
        user_id: Option<Uuid>,
        email: Option<&str>,
        client: &ClientInfo,
    ) {
        self.events
            .record(AuthEvent {
                user_id,
                actor_user_id: user_id,
                organization_id: None,
                target_id: None,
                email,
                event_type,
                ip_address: client.ip_address,
                user_agent: client.user_agent.as_deref(),
            })
            .await;
    }

    /// Appends an audit record for an action one account takes against another. The actor is
    /// stored separately, because knowing who did it is the point of the trail.
    pub(super) async fn record_action(
        &self,
        event_type: AuthEventType,
        actor_id: Uuid,
        subject_id: Option<Uuid>,
        email: Option<&str>,
        client: &ClientInfo,
    ) {
        self.events
            .record(AuthEvent {
                user_id: subject_id,
                actor_user_id: Some(actor_id),
                organization_id: None,
                target_id: None,
                email,
                event_type,
                ip_address: client.ip_address,
                user_agent: client.user_agent.as_deref(),
            })
            .await;
    }

    /// Resolves an address to an account, for features that reference accounts by address —
    /// inviting somebody to an organization, for instance.
    pub async fn user_id_by_email(&self, email: &str) -> Result<Option<Uuid>, IdentityError> {
        Ok(self
            .users
            .find_by_email(&normalize_email(email))
            .await?
            .map(|user| user.id))
    }

    fn lock_expiry(&self) -> DateTime<Utc> {
        expires_in(self.config.account_lock_duration_seconds)
    }
}
