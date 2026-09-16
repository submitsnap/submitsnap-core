//! Administrator operations over accounts.
//!
//! The invariant is that an instance always keeps at least one administrator who can sign in.
//! It is upheld by two complementary rules:
//!
//! * Status changes and deletions refuse to target the caller. The caller is provably an
//!   active administrator, so at least one such account always survives them.
//! * Role changes *may* target the caller, so an administrator can step down, but only while
//!   somebody else still holds the role.
//!
//! Every change is written to the audit trail.

use std::collections::HashSet;

use uuid::Uuid;

use crate::{
    modules::{
        identity::{
            dto::{AdminUser, AuditEventResponse},
            error::IdentityError,
            events::{AuditFilters, AuthEventType},
            model::{UserRecord, UserStatus, normalize_email},
            repository::UserFilters,
        },
        rbac::RoleName,
    },
    shared::request::ClientInfo,
};

use super::service::IdentityService;

impl IdentityService {
    /// A page of accounts, newest first.
    pub async fn list_accounts(
        &self,
        filters: &UserFilters,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AdminUser>, i64), IdentityError> {
        let users = self.users.list(filters, limit, offset).await?;
        let total = self.users.count(filters).await?;

        let ids: Vec<Uuid> = users.iter().map(|user| user.id).collect();
        let mut roles = self
            .roles
            .roles_for_users(&ids)
            .await
            .map_err(IdentityError::Internal)?;

        let accounts = users
            .iter()
            .map(|user| AdminUser::new(user, roles.remove(&user.id).unwrap_or_default()))
            .collect();

        Ok((accounts, total))
    }

    pub async fn account(&self, id: Uuid) -> Result<AdminUser, IdentityError> {
        let user = self.load(id).await?;
        Ok(AdminUser::new(&user, self.roles_for(id).await?))
    }

    /// Enables or disables an account. Disabling also signs it out everywhere, because this is
    /// normally a response to abuse rather than a routine edit.
    ///
    /// Refusing to target the caller is what keeps the instance administrable.
    pub async fn set_account_status(
        &self,
        target_id: Uuid,
        status: UserStatus,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<AdminUser, IdentityError> {
        if target_id == actor_id {
            return Err(IdentityError::SelfTargeted);
        }

        if !self.users.set_status(target_id, status).await? {
            return Err(IdentityError::NotFound);
        }

        if status == UserStatus::Disabled {
            self.sessions
                .revoke_all_for_user(target_id)
                .await
                .map_err(IdentityError::Internal)?;
        }

        let user = self.load(target_id).await?;
        self.record_action(
            AuthEventType::AccountStatusChanged,
            actor_id,
            Some(target_id),
            Some(&user.email),
            client,
        )
        .await;

        self.account(target_id).await
    }

    /// Replaces an account's roles with exactly `roles`, auditing every grant and revocation.
    ///
    /// Unlike the status change, this may target the caller: stepping down is a reasonable
    /// thing to do, and it is refused only when nobody else could take over.
    pub async fn set_account_roles(
        &self,
        target_id: Uuid,
        roles: Vec<RoleName>,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<AdminUser, IdentityError> {
        self.reject_unknown_roles(&roles).await?;

        let before: HashSet<RoleName> = self.roles_for(target_id).await?.into_iter().collect();
        let after: HashSet<RoleName> = roles.into_iter().collect();

        if before.contains(&RoleName::admin()) && !after.contains(&RoleName::admin()) {
            self.ensure_an_admin_remains(target_id).await?;
        }

        // Reading the account first means a missing one is a 404 before anything changes.
        let user = self.load(target_id).await?;
        let desired: Vec<RoleName> = after.iter().cloned().collect();

        self.roles
            .replace_for_user(target_id, &desired)
            .await
            .map_err(IdentityError::Internal)?;

        for granted in after.difference(&before) {
            tracing::info!(target: "submitsnap_core::audit", user_id = %target_id, role = %granted, "role granted");
            self.record_action(
                AuthEventType::RoleGranted,
                actor_id,
                Some(target_id),
                Some(&user.email),
                client,
            )
            .await;
        }

        for revoked in before.difference(&after) {
            tracing::info!(target: "submitsnap_core::audit", user_id = %target_id, role = %revoked, "role revoked");
            self.record_action(
                AuthEventType::RoleRevoked,
                actor_id,
                Some(target_id),
                Some(&user.email),
                client,
            )
            .await;
        }

        self.account(target_id).await
    }

    /// Clears an account's failed-attempt counter and lock, so a locked-out user can try again
    /// without waiting out the window or resetting their password.
    pub async fn unlock_account(
        &self,
        target_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<AdminUser, IdentityError> {
        let user = self.load(target_id).await?;

        self.users.reset_login_failures(target_id).await?;
        self.record_action(
            AuthEventType::AccountUnlocked,
            actor_id,
            Some(target_id),
            Some(&user.email),
            client,
        )
        .await;

        self.account(target_id).await
    }

    /// Signs an account out everywhere without changing its status.
    pub async fn revoke_account_sessions(
        &self,
        target_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<u64, IdentityError> {
        let user = self.load(target_id).await?;

        let revoked = self
            .sessions
            .revoke_all_for_user(target_id)
            .await
            .map_err(IdentityError::Internal)?;

        self.record_action(
            AuthEventType::SessionsRevoked,
            actor_id,
            Some(target_id),
            Some(&user.email),
            client,
        )
        .await;

        Ok(revoked)
    }

    /// Permanently removes an account. Sessions, refresh tokens, and role grants cascade; the
    /// audit trail keeps its rows with the account reference cleared.
    ///
    /// Refusing to target the caller is what keeps the instance administrable.
    pub async fn delete_account(
        &self,
        target_id: Uuid,
        confirm_email: &str,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(), IdentityError> {
        if target_id == actor_id {
            return Err(IdentityError::SelfTargeted);
        }

        let user = self.load(target_id).await?;
        if normalize_email(confirm_email) != user.email {
            return Err(IdentityError::ConfirmationMismatch);
        }

        if !self.users.delete(target_id).await? {
            return Err(IdentityError::NotFound);
        }

        // Recorded after the delete so the row never references a missing account; the address
        // is what keeps the entry useful afterwards.
        self.record_action(
            AuthEventType::AccountDeleted,
            actor_id,
            None,
            Some(&user.email),
            client,
        )
        .await;

        Ok(())
    }

    /// A page of the audit trail, newest first.
    pub async fn audit_events(
        &self,
        filters: &AuditFilters,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AuditEventResponse>, i64), IdentityError> {
        let events = self.events.list(filters, limit, offset).await?;
        let total = self.events.count(filters).await?;

        Ok((events.into_iter().map(Into::into).collect(), total))
    }

    /// Adds a role to the account with that address, keeping any it already holds.
    ///
    /// Used by the bootstrap command, which has no session to authenticate with. It only ever
    /// adds, so it cannot be the reason an instance ends up without an administrator.
    pub async fn grant_role_by_email(
        &self,
        email: &str,
        role: &RoleName,
    ) -> Result<Uuid, IdentityError> {
        self.reject_unknown_roles(std::slice::from_ref(role))
            .await?;

        let user = self
            .users
            .find_by_email(&normalize_email(email))
            .await?
            .ok_or(IdentityError::NotFound)?;

        let mut roles = self.roles_for(user.id).await?;
        if !roles.contains(role) {
            roles.push(role.clone());
        }

        self.roles
            .replace_for_user(user.id, &roles)
            .await
            .map_err(IdentityError::Internal)?;

        // Attributed to nobody: this path exists precisely because there is no session behind
        // it. The record still matters, because it is the only trace of a role being handed out
        // outside the API.
        self.events
            .record(crate::modules::identity::events::AuthEvent {
                user_id: Some(user.id),
                actor_user_id: None,
                organization_id: None,
                target_id: None,
                email: Some(&user.email),
                event_type: AuthEventType::RoleGranted,
                ip_address: None,
                user_agent: None,
            })
            .await;

        Ok(user.id)
    }

    async fn load(&self, id: Uuid) -> Result<UserRecord, IdentityError> {
        self.users
            .find_by_id(id)
            .await?
            .ok_or(IdentityError::NotFound)
    }

    async fn reject_unknown_roles(&self, roles: &[RoleName]) -> Result<(), IdentityError> {
        let known = self
            .roles
            .role_names()
            .await
            .map_err(IdentityError::Internal)?;

        if let Some(unknown) = roles.iter().find(|role| !known.contains(role)) {
            return Err(IdentityError::UnknownRole(unknown.to_string()));
        }

        Ok(())
    }

    /// Refuses a change when `target_id` is the only administrator who can still sign in.
    async fn ensure_an_admin_remains(&self, target_id: Uuid) -> Result<(), IdentityError> {
        let admins = self
            .roles
            .active_admin_ids()
            .await
            .map_err(IdentityError::Internal)?;

        if admins.len() == 1 && admins[0] == target_id {
            return Err(IdentityError::LastAdministrator);
        }

        Ok(())
    }
}
