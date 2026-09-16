use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::{
    modules::organization::model::{
        MemberRecord, OrganizationRecord, OrganizationRole, OrganizationSummary,
        OrganizationWithRole,
    },
    shared::pagination::page_bounds,
};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateOrganizationRequest {
    #[validate(length(
        min = 1,
        max = 120,
        message = "name must be between 1 and 120 characters"
    ))]
    #[schema(example = "Acme Receiving")]
    pub name: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RenameOrganizationRequest {
    #[validate(length(
        min = 1,
        max = 120,
        message = "name must be between 1 and 120 characters"
    ))]
    #[schema(example = "Acme Receiving")]
    pub name: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct AddOrganizationMemberRequest {
    /// The account to add. Invitations are addressed by email, because that is what an operator
    /// knows about a person.
    #[serde(deserialize_with = "crate::modules::identity::dto::normalize_email_field")]
    #[validate(email, length(max = 320))]
    #[schema(example = "person@example.com")]
    pub email: String,
    pub role: OrganizationRole,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateOrganizationMemberRequest {
    pub role: OrganizationRole,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PaginationQuery {
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<u32>,
    #[param(minimum = 0)]
    pub offset: Option<u32>,
}

impl PaginationQuery {
    pub fn bounds(&self) -> (i64, i64) {
        page_bounds(self.limit, self.offset)
    }
}

/// An organization as one of its members sees it. Carries the caller's own role so a client can
/// render the right actions without a second request.
#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationResponse {
    pub id: Uuid,
    pub name: String,
    pub role: OrganizationRole,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
}

impl OrganizationResponse {
    pub fn new(
        organization: &OrganizationRecord,
        member_count: i64,
        role: OrganizationRole,
    ) -> Self {
        Self {
            id: organization.id,
            name: organization.name.clone(),
            role,
            member_count,
            created_at: organization.created_at,
        }
    }
}

impl From<OrganizationWithRole> for OrganizationResponse {
    fn from(organization: OrganizationWithRole) -> Self {
        Self {
            id: organization.id,
            name: organization.name,
            role: organization.role,
            member_count: organization.member_count,
            created_at: organization.created_at,
        }
    }
}

/// An organization as an instance administrator sees it. There is no role to report, because
/// reading it does not require membership.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminOrganizationResponse {
    pub id: Uuid,
    pub name: String,
    pub member_count: i64,
    pub created_at: DateTime<Utc>,
}

impl From<OrganizationSummary> for AdminOrganizationResponse {
    fn from(organization: OrganizationSummary) -> Self {
        Self {
            id: organization.id,
            name: organization.name,
            member_count: organization.member_count,
            created_at: organization.created_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationMemberResponse {
    pub user_id: Uuid,
    pub email: String,
    pub role: OrganizationRole,
    pub joined_at: DateTime<Utc>,
}

impl From<MemberRecord> for OrganizationMemberResponse {
    fn from(member: MemberRecord) -> Self {
        Self {
            user_id: member.user_id,
            email: member.email,
            role: member.role,
            joined_at: member.joined_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationListResponse {
    pub organizations: Vec<OrganizationResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminOrganizationListResponse {
    pub organizations: Vec<AdminOrganizationResponse>,
    pub total: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OrganizationMemberListResponse {
    pub members: Vec<OrganizationMemberResponse>,
    pub total: i64,
}
