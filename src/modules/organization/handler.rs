//! The organization surface: `/api/v1/organizations` and the read-only
//! `/api/v1/admin/organizations`.
//!
//! Access is resolved in the service, so a handler reads as "resolve, then authorize, then
//! act". Nothing here trusts a caller-supplied role.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use uuid::Uuid;

use crate::{
    modules::{
        ApiState,
        auth::AuthenticatedUser,
        organization::dto::{
            AddOrganizationMemberRequest, AdminOrganizationListResponse, AdminOrganizationResponse,
            CreateOrganizationRequest, OrganizationListResponse, OrganizationMemberListResponse,
            OrganizationMemberResponse, OrganizationResponse, PaginationQuery,
            RenameOrganizationRequest, UpdateOrganizationMemberRequest,
        },
        rbac::RoleName,
    },
    shared::{
        error::{AppError, ErrorResponse, validate},
        request::ClientInfo,
    },
};

#[utoipa::path(
    post,
    path = "/api/v1/organizations",
    tag = "organizations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    request_body = CreateOrganizationRequest,
    responses(
        (status = 201, description = "Organization created; the caller owns it", body = OrganizationResponse),
        (status = 400, description = "Request was not valid", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
    )
)]
pub async fn create_organization(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Json(request): Json<CreateOrganizationRequest>,
) -> Result<(StatusCode, Json<OrganizationResponse>), AppError> {
    validate(&request)?;

    let organization = state
        .organizations
        .create(&request.name, user.user.id, &client)
        .await?;

    Ok((StatusCode::CREATED, Json(organization)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations",
    tag = "organizations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(PaginationQuery),
    responses(
        (status = 200, description = "Organizations the caller belongs to", body = OrganizationListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
    )
)]
pub async fn list_organizations(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<OrganizationListResponse>, AppError> {
    let (limit, offset) = query.bounds();
    let (organizations, total) = state
        .organizations
        .list_mine(user.user.id, limit, offset)
        .await?;

    Ok(Json(OrganizationListResponse {
        organizations,
        total,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{id}",
    tag = "organizations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Organization identifier")),
    responses(
        (status = 200, description = "The organization, with the caller's role", body = OrganizationResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn get_organization(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<OrganizationResponse>, AppError> {
    Ok(Json(
        state
            .organizations
            .get(organization_id, user.user.id)
            .await?,
    ))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{id}",
    tag = "organizations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Organization identifier")),
    request_body = RenameOrganizationRequest,
    responses(
        (status = 200, description = "Renamed", body = OrganizationResponse),
        (status = 400, description = "Request was not valid", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn rename_organization(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<RenameOrganizationRequest>,
) -> Result<Json<OrganizationResponse>, AppError> {
    validate(&request)?;

    let organization = state
        .organizations
        .rename(organization_id, &request.name, user.user.id, &client)
        .await?;

    Ok(Json(organization))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{id}",
    tag = "organizations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Organization identifier")),
    responses(
        (status = 204, description = "Removed, along with its memberships"),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner role", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn delete_organization(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    state
        .organizations
        .delete(organization_id, user.user.id, &client)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{id}/members",
    tag = "organizations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Organization identifier"), PaginationQuery),
    responses(
        (status = 200, description = "Page of members", body = OrganizationMemberListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn list_members(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<OrganizationMemberListResponse>, AppError> {
    let (limit, offset) = query.bounds();
    let (members, total) = state
        .organizations
        .members(organization_id, user.user.id, limit, offset)
        .await?;

    Ok(Json(OrganizationMemberListResponse { members, total }))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{id}/members",
    tag = "organizations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Organization identifier")),
    request_body = AddOrganizationMemberRequest,
    responses(
        (status = 201, description = "Account added", body = OrganizationMemberResponse),
        (status = 200, description = "Existing member's role updated", body = OrganizationMemberResponse),
        (status = 400, description = "Invalid request, or a role the caller cannot grant", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such organization, or no account for that address", body = ErrorResponse),
    )
)]
pub async fn add_member(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<AddOrganizationMemberRequest>,
) -> Result<(StatusCode, Json<OrganizationMemberResponse>), AppError> {
    validate(&request)?;

    let (member, created) = state
        .organizations
        .add_member(organization_id, &request, user.user.id, &client)
        .await?;

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    Ok((status, Json(member)))
}

#[utoipa::path(
    put,
    path = "/api/v1/organizations/{id}/members/{user_id}",
    tag = "organizations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Organization identifier"),
        ("user_id" = Uuid, Path, description = "Account identifier"),
    ),
    request_body = UpdateOrganizationMemberRequest,
    responses(
        (status = 200, description = "Role updated", body = OrganizationMemberResponse),
        (status = 400, description = "A role the caller cannot grant, or the last owner", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such organization or member", body = ErrorResponse),
    )
)]
pub async fn set_member_role(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, target_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<UpdateOrganizationMemberRequest>,
) -> Result<Json<OrganizationMemberResponse>, AppError> {
    let member = state
        .organizations
        .set_member_role(
            organization_id,
            target_id,
            request.role,
            user.user.id,
            &client,
        )
        .await?;

    Ok(Json(member))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{id}/members/{user_id}",
    tag = "organizations",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("id" = Uuid, Path, description = "Organization identifier"),
        ("user_id" = Uuid, Path, description = "Account identifier; the caller's own id leaves"),
    ),
    responses(
        (status = 204, description = "Member removed"),
        (status = 400, description = "The last owner cannot be removed", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role to remove somebody else", body = ErrorResponse),
        (status = 404, description = "No such organization or member", body = ErrorResponse),
    )
)]
pub async fn remove_member(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, target_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, AppError> {
    state
        .organizations
        .remove_member(organization_id, target_id, user.user.id, &client)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/organizations",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(PaginationQuery),
    responses(
        (status = 200, description = "Every organization on the instance", body = AdminOrganizationListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
    )
)]
pub async fn admin_list_organizations(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<AdminOrganizationListResponse>, AppError> {
    user.require_role(&RoleName::admin())?;

    let (limit, offset) = query.bounds();
    let (organizations, total) = state.organizations.list_all(limit, offset).await?;

    Ok(Json(AdminOrganizationListResponse {
        organizations,
        total,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/organizations/{id}",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Organization identifier")),
    responses(
        (status = 200, description = "The organization", body = AdminOrganizationResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn admin_get_organization(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
) -> Result<Json<AdminOrganizationResponse>, AppError> {
    user.require_role(&RoleName::admin())?;

    Ok(Json(
        state
            .organizations
            .get_as_administrator(organization_id)
            .await?,
    ))
}
