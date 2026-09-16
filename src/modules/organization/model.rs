use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

/// A member's standing inside one organization.
///
/// This is deliberately separate from the instance roles in [`crate::modules::rbac`]: those
/// decide who administers the deployment, these decide who manages a tenant's resources.
/// Because the hierarchy is fixed, it is an enum on both sides — a `match` over it is
/// exhaustive and an unknown value cannot reach the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "organization_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum OrganizationRole {
    Owner,
    Admin,
    Member,
}

impl OrganizationRole {
    /// Whether an account holding this role may reach an account holding `other` — grant it a
    /// role, change its role, or remove it.
    ///
    /// An owner reaches everyone. An admin reaches peers and members, which means only an owner
    /// can create another owner, and nobody but an owner can touch one.
    pub fn reaches(self, other: Self) -> bool {
        match self {
            Self::Owner => true,
            Self::Admin => matches!(other, Self::Admin | Self::Member),
            Self::Member => false,
        }
    }

    /// Whether this role may change the organization itself or its membership.
    pub fn is_manager(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn is_owner(self) -> bool {
        matches!(self, Self::Owner)
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct OrganizationRecord {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
}

/// An organization together with the caller's own standing in it, so a client can render the
/// right actions without a second request.
#[derive(Debug, Clone, FromRow)]
pub struct OrganizationWithRole {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub role: OrganizationRole,
    pub member_count: i64,
}

/// An organization as seen by an instance administrator, who may not be a member and therefore
/// has no role to report.
#[derive(Debug, Clone, FromRow)]
pub struct OrganizationSummary {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub member_count: i64,
}

#[derive(Debug, Clone, FromRow)]
pub struct MemberRecord {
    pub user_id: Uuid,
    pub email: String,
    pub role: OrganizationRole,
    pub joined_at: DateTime<Utc>,
}

/// A row of the access lookup, which resolves existence, the caller's role, and the member
/// count in one query.
#[derive(Debug, Clone, FromRow)]
pub struct AccessRow {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub member_count: i64,
    pub role: Option<OrganizationRole>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_owner_reaches_everyone_and_nobody_else_reaches_an_owner() {
        assert!(OrganizationRole::Owner.reaches(OrganizationRole::Owner));
        assert!(OrganizationRole::Owner.reaches(OrganizationRole::Member));
        assert!(OrganizationRole::Admin.reaches(OrganizationRole::Member));
        assert!(OrganizationRole::Admin.reaches(OrganizationRole::Admin));

        assert!(!OrganizationRole::Admin.reaches(OrganizationRole::Owner));
        assert!(!OrganizationRole::Member.reaches(OrganizationRole::Member));
        assert!(!OrganizationRole::Member.reaches(OrganizationRole::Owner));
    }

    #[test]
    fn only_owners_and_admins_manage() {
        assert!(OrganizationRole::Owner.is_manager());
        assert!(OrganizationRole::Admin.is_manager());
        assert!(!OrganizationRole::Member.is_manager());
        assert!(OrganizationRole::Owner.is_owner());
        assert!(!OrganizationRole::Admin.is_owner());
    }
}
