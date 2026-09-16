//! Organizations and their membership.
//!
//! Two invariants run through everything here:
//!
//! * An organization always keeps at least one owner. Removing or demoting the last one is
//!   refused, which is also what makes leaving safe to allow.
//! * An account may only reach as far as its own role. An owner reaches everyone; an admin
//!   reaches peers and members, so only an owner can create another owner or touch one.
//!
//! Every change is written to the audit trail with the actor and the organization.

use std::sync::Arc;

use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::{
    modules::{
        identity::{
            IdentityService,
            events::{AuthEvent, AuthEventRepository, AuthEventType},
        },
        organization::{
            dto::{
                AddOrganizationMemberRequest, AdminOrganizationResponse,
                OrganizationMemberResponse, OrganizationResponse,
            },
            error::OrganizationError,
            model::{OrganizationRecord, OrganizationRole},
            repository::OrganizationRepository,
        },
    },
    shared::request::ClientInfo,
};

/// The caller's standing in an organization, resolved once per request and then asked to
/// authorize. Bundling the role with the organization makes it awkward to act without having
/// resolved access first.
pub struct Access {
    pub organization: OrganizationRecord,
    pub member_count: i64,
    pub role: OrganizationRole,
}

impl Access {
    /// Fails unless the caller may change the organization or its membership.
    pub fn require_manager(&self) -> Result<(), OrganizationError> {
        require_manager(self.role)
    }

    /// Fails unless the caller owns the organization.
    pub fn require_owner(&self) -> Result<(), OrganizationError> {
        if self.role.is_owner() {
            Ok(())
        } else {
            Err(OrganizationError::InsufficientRole)
        }
    }

    pub fn response(&self) -> OrganizationResponse {
        OrganizationResponse::new(&self.organization, self.member_count, self.role)
    }
}

/// Authorization for the membership operations, which read the role inside their transaction
/// rather than resolving an [`Access`] beforehand.
fn require_manager(role: OrganizationRole) -> Result<(), OrganizationError> {
    if role.is_manager() {
        Ok(())
    } else {
        Err(OrganizationError::InsufficientRole)
    }
}

/// Fails unless `role` can reach an account holding `other`.
fn require_reaches(
    role: OrganizationRole,
    other: OrganizationRole,
) -> Result<(), OrganizationError> {
    if role.reaches(other) {
        Ok(())
    } else {
        Err(OrganizationError::InsufficientRole)
    }
}

#[derive(Clone)]
pub struct OrganizationService {
    organizations: OrganizationRepository,
    identity: Arc<IdentityService>,
    events: AuthEventRepository,
}

impl OrganizationService {
    pub fn new(database: PgPool, identity: Arc<IdentityService>) -> Self {
        Self {
            organizations: OrganizationRepository::new(database.clone()),
            identity,
            events: AuthEventRepository::new(database),
        }
    }

    /// Resolves the caller's standing, distinguishing "no such organization" from "not a
    /// member".
    pub async fn access(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Access, OrganizationError> {
        let row = self
            .organizations
            .access(organization_id, user_id)
            .await?
            .ok_or(OrganizationError::NotFound)?;

        let role = row.role.ok_or(OrganizationError::NotAMember)?;

        Ok(Access {
            organization: OrganizationRecord {
                id: row.id,
                name: row.name,
                created_at: row.created_at,
            },
            member_count: row.member_count,
            role,
        })
    }

    /// Creates an organization and makes the caller its owner. Any account may do this, which
    /// is why no bootstrap step is needed the way it is for the instance `admin` role.
    pub async fn create(
        &self,
        name: &str,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<OrganizationResponse, OrganizationError> {
        let organization = self.organizations.create(name.trim(), actor_id).await?;

        self.audit(
            AuthEventType::OrganizationCreated,
            organization.id,
            actor_id,
            Some(actor_id),
            Some(&organization.name),
            client,
        )
        .await;

        Ok(OrganizationResponse::new(
            &organization,
            1,
            OrganizationRole::Owner,
        ))
    }

    pub async fn list_mine(
        &self,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<OrganizationResponse>, i64), OrganizationError> {
        let organizations = self
            .organizations
            .list_for_user(user_id, limit, offset)
            .await?;
        let total = self.organizations.count_for_user(user_id).await?;

        Ok((organizations.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationResponse, OrganizationError> {
        Ok(self.access(organization_id, user_id).await?.response())
    }

    pub async fn rename(
        &self,
        organization_id: Uuid,
        name: &str,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<OrganizationResponse, OrganizationError> {
        let access = self.access(organization_id, actor_id).await?;
        access.require_manager()?;

        self.organizations
            .rename(organization_id, name.trim())
            .await?;

        // The organization is the subject here, so the actor doubles as it.
        self.audit(
            AuthEventType::OrganizationRenamed,
            organization_id,
            actor_id,
            Some(actor_id),
            Some(name.trim()),
            client,
        )
        .await;

        self.get(organization_id, actor_id).await
    }

    /// Removes the organization. Its memberships cascade away with it, and the audit trail
    /// keeps its rows with the organization reference cleared.
    pub async fn delete(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(), OrganizationError> {
        let access = self.access(organization_id, actor_id).await?;
        access.require_owner()?;

        // Recorded first, while the organization still exists for the foreign key to accept.
        // Deleting it then clears the reference, which is the same rule that lets account
        // deletions keep their history.
        self.audit(
            AuthEventType::OrganizationDeleted,
            organization_id,
            actor_id,
            Some(actor_id),
            Some(&access.organization.name),
            client,
        )
        .await;

        if !self.organizations.delete(organization_id).await? {
            return Err(OrganizationError::NotFound);
        }

        Ok(())
    }

    pub async fn members(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<OrganizationMemberResponse>, i64), OrganizationError> {
        self.access(organization_id, user_id).await?;

        let members = self
            .organizations
            .members(organization_id, limit, offset)
            .await?;
        let total = self.organizations.count_members(organization_id).await?;

        Ok((members.into_iter().map(Into::into).collect(), total))
    }

    /// Adds the account with that address, or updates its role when it is already a member.
    /// Returns whether a membership was created, so the caller can answer 201 or 200.
    pub async fn add_member(
        &self,
        organization_id: Uuid,
        request: &AddOrganizationMemberRequest,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(OrganizationMemberResponse, bool), OrganizationError> {
        let Some(user_id) = self.identity.user_id_by_email(&request.email).await? else {
            return Err(OrganizationError::AccountNotFound);
        };

        let mut transaction = self.organizations.begin().await?;
        self.organizations
            .lock(&mut *transaction, organization_id)
            .await?;

        let actor_role = self
            .locked_role(&mut transaction, organization_id, actor_id)
            .await?;
        require_manager(actor_role)?;
        require_reaches(actor_role, request.role)?;

        let existing = self
            .organizations
            .role_of(&mut *transaction, organization_id, user_id)
            .await?;

        if let Some(current) = existing {
            require_reaches(actor_role, current)?;
            if current == request.role {
                // Nothing to change, so nothing to write and nothing to audit.
                transaction.commit().await?;
                return Ok((self.member(organization_id, user_id).await?, false));
            }
            if current.is_owner() {
                self.ensure_another_owner(&mut transaction, organization_id)
                    .await?;
            }
        }

        self.organizations
            .upsert_member(&mut *transaction, organization_id, user_id, request.role)
            .await?;
        transaction.commit().await?;

        let member = self.member(organization_id, user_id).await?;
        self.audit(
            if existing.is_none() {
                AuthEventType::OrganizationMemberAdded
            } else {
                AuthEventType::OrganizationMemberRoleChanged
            },
            organization_id,
            actor_id,
            Some(user_id),
            Some(&member.email),
            client,
        )
        .await;

        Ok((member, existing.is_none()))
    }

    pub async fn set_member_role(
        &self,
        organization_id: Uuid,
        target_id: Uuid,
        role: OrganizationRole,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<OrganizationMemberResponse, OrganizationError> {
        let mut transaction = self.organizations.begin().await?;
        self.organizations
            .lock(&mut *transaction, organization_id)
            .await?;

        let actor_role = self
            .locked_role(&mut transaction, organization_id, actor_id)
            .await?;
        require_manager(actor_role)?;

        let current = self
            .organizations
            .role_of(&mut *transaction, organization_id, target_id)
            .await?
            .ok_or(OrganizationError::MemberNotFound)?;

        require_reaches(actor_role, current)?;
        require_reaches(actor_role, role)?;

        if current == role {
            transaction.commit().await?;
            return self.member(organization_id, target_id).await;
        }

        if current.is_owner() {
            self.ensure_another_owner(&mut transaction, organization_id)
                .await?;
        }

        self.organizations
            .upsert_member(&mut *transaction, organization_id, target_id, role)
            .await?;
        transaction.commit().await?;

        let member = self.member(organization_id, target_id).await?;
        self.audit(
            AuthEventType::OrganizationMemberRoleChanged,
            organization_id,
            actor_id,
            Some(target_id),
            Some(&member.email),
            client,
        )
        .await;

        Ok(member)
    }

    /// Removes a member, or lets the caller leave when the target is themselves.
    pub async fn remove_member(
        &self,
        organization_id: Uuid,
        target_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(), OrganizationError> {
        let mut transaction = self.organizations.begin().await?;
        self.organizations
            .lock(&mut *transaction, organization_id)
            .await?;

        let actor_role = self
            .locked_role(&mut transaction, organization_id, actor_id)
            .await?;

        let current = self
            .organizations
            .role_of(&mut *transaction, organization_id, target_id)
            .await?
            .ok_or(OrganizationError::MemberNotFound)?;

        // Leaving is always allowed; acting on somebody else needs the standing to do it.
        if target_id != actor_id {
            require_manager(actor_role)?;
            require_reaches(actor_role, current)?;
        }

        if current.is_owner() {
            self.ensure_another_owner(&mut transaction, organization_id)
                .await?;
        }

        let member = self.member(organization_id, target_id).await?;
        self.organizations
            .remove_member(&mut *transaction, organization_id, target_id)
            .await?;
        transaction.commit().await?;

        self.audit(
            AuthEventType::OrganizationMemberRemoved,
            organization_id,
            actor_id,
            Some(target_id),
            Some(&member.email),
            client,
        )
        .await;

        Ok(())
    }

    /// Read-only listing for an instance administrator. Deliberately separate from
    /// [`Self::list_mine`]: an administrator who is not a member has no role to report.
    pub async fn list_all(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<AdminOrganizationResponse>, i64), OrganizationError> {
        let organizations = self.organizations.list_all(limit, offset).await?;
        let total = self.organizations.count_all().await?;

        Ok((organizations.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get_as_administrator(
        &self,
        organization_id: Uuid,
    ) -> Result<AdminOrganizationResponse, OrganizationError> {
        self.organizations
            .summary(organization_id)
            .await?
            .map(Into::into)
            .ok_or(OrganizationError::NotFound)
    }

    async fn member(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationMemberResponse, OrganizationError> {
        self.organizations
            .member_of(organization_id, user_id)
            .await?
            .map(Into::into)
            .ok_or(OrganizationError::MemberNotFound)
    }

    /// The caller's role, read *inside* the transaction that is about to act on it, so a role
    /// revoked a moment ago cannot still be used.
    async fn locked_role(
        &self,
        transaction: &mut Transaction<'static, Postgres>,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<OrganizationRole, OrganizationError> {
        self.organizations
            .role_of(&mut **transaction, organization_id, user_id)
            .await?
            .ok_or(OrganizationError::NotAMember)
    }

    /// Refuses a change that would leave the organization with no owner.
    ///
    /// Called with the organization already locked, which is what makes the count meaningful:
    /// nothing else can change the membership between this read and the write it guards.
    async fn ensure_another_owner(
        &self,
        transaction: &mut Transaction<'static, Postgres>,
        organization_id: Uuid,
    ) -> Result<(), OrganizationError> {
        if self
            .organizations
            .owner_count(&mut **transaction, organization_id)
            .await?
            <= 1
        {
            return Err(OrganizationError::LastOwner);
        }

        Ok(())
    }

    /// Appends an audit record. The organization is always known here, and the actor is always
    /// an authenticated account, which is what makes this trail worth keeping.
    async fn audit(
        &self,
        event_type: AuthEventType,
        organization_id: Uuid,
        actor_id: Uuid,
        subject_id: Option<Uuid>,
        email: Option<&str>,
        client: &ClientInfo,
    ) {
        self.events
            .record(AuthEvent {
                user_id: subject_id,
                actor_user_id: Some(actor_id),
                organization_id: Some(organization_id),
                target_id: None,
                email,
                event_type,
                ip_address: client.ip_address,
                user_agent: client.user_agent.as_deref(),
            })
            .await;
    }
}
