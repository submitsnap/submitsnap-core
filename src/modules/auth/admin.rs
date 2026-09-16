//! The administrator surface: `/api/v1/admin`.
//!
//! Every route here requires the `admin` role, which is checked in the handler rather than by
//! middleware so the failure is a plain 403 and the requirement is visible where it is used.

use axum::{
    Json,
    extract::{Path, Query, State},
};
use uuid::Uuid;

use crate::{
    modules::{
        ApiState,
        auth::extractor::AuthenticatedUser,
        identity::dto::{
            AdminUser, AuditEventListResponse, DeleteAccountRequest, ListAuditEventsQuery,
            ListUsersQuery, MessageResponse, SessionsRevokedResponse, UpdateUserRolesRequest,
            UpdateUserStatusRequest, UserListResponse,
        },
    },
    shared::{
        error::{AppError, ErrorResponse},
        request::ClientInfo,
    },
};

use crate::modules::{
    identity::{events::AuditFilters, repository::UserFilters},
    rbac::RoleName,
};

#[utoipa::path(
    get,
    path = "/api/v1/admin/users",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(ListUsersQuery),
    responses(
        (status = 200, description = "Page of accounts", body = UserListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
    )
)]
pub async fn list_users(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<UserListResponse>, AppError> {
    user.require_role(&RoleName::admin())?;

    let filters =
        UserFilters::from_query(query.search.as_deref(), query.status, query.role.clone());
    let (limit, offset) = query.bounds();
    let (users, total) = state
        .identity
        .list_accounts(&filters, limit, offset)
        .await?;

    Ok(Json(UserListResponse { users, total }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/users/{id}",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Account identifier")),
    responses(
        (status = 200, description = "The account", body = AdminUser),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
        (status = 404, description = "No such account", body = ErrorResponse),
    )
)]
pub async fn get_user(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path(target_id): Path<Uuid>,
) -> Result<Json<AdminUser>, AppError> {
    user.require_role(&RoleName::admin())?;

    Ok(Json(state.identity.account(target_id).await?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/users/{id}/status",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Account identifier")),
    request_body = UpdateUserStatusRequest,
    responses(
        (status = 200, description = "Status updated; disabling also revokes every session", body = AdminUser),
        (status = 400, description = "Invalid request, an unknown status, targeting yourself, or removing the last administrator", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
        (status = 404, description = "No such account", body = ErrorResponse),
    )
)]
pub async fn set_user_status(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path(target_id): Path<Uuid>,
    Json(request): Json<UpdateUserStatusRequest>,
) -> Result<Json<AdminUser>, AppError> {
    user.require_role(&RoleName::admin())?;

    let updated = state
        .identity
        .set_account_status(target_id, request.status.into(), user.user.id, &client)
        .await?;

    Ok(Json(updated))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/users/{id}/roles",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Account identifier")),
    request_body = UpdateUserRolesRequest,
    responses(
        (status = 200, description = "Roles replaced with exactly the supplied set", body = AdminUser),
        (status = 400, description = "Unknown role, or removing the last administrator", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
        (status = 404, description = "No such account", body = ErrorResponse),
    )
)]
pub async fn set_user_roles(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path(target_id): Path<Uuid>,
    Json(request): Json<UpdateUserRolesRequest>,
) -> Result<Json<AdminUser>, AppError> {
    user.require_role(&RoleName::admin())?;

    let updated = state
        .identity
        .set_account_roles(target_id, request.roles, user.user.id, &client)
        .await?;

    Ok(Json(updated))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/users/{id}/unlock",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Account identifier")),
    responses(
        (status = 200, description = "Failed attempts cleared and any lock lifted", body = AdminUser),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
        (status = 404, description = "No such account", body = ErrorResponse),
    )
)]
pub async fn unlock_user(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path(target_id): Path<Uuid>,
) -> Result<Json<AdminUser>, AppError> {
    user.require_role(&RoleName::admin())?;

    Ok(Json(
        state
            .identity
            .unlock_account(target_id, user.user.id, &client)
            .await?,
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/users/{id}/sessions",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Account identifier")),
    responses(
        (status = 200, description = "Every session for the account revoked", body = SessionsRevokedResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
        (status = 404, description = "No such account", body = ErrorResponse),
    )
)]
pub async fn revoke_user_sessions(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path(target_id): Path<Uuid>,
) -> Result<Json<SessionsRevokedResponse>, AppError> {
    user.require_role(&RoleName::admin())?;

    let revoked = state
        .identity
        .revoke_account_sessions(target_id, user.user.id, &client)
        .await?;

    Ok(Json(SessionsRevokedResponse { revoked }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/users/{id}",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("id" = Uuid, Path, description = "Account identifier")),
    request_body = DeleteAccountRequest,
    responses(
        (status = 200, description = "Account removed", body = MessageResponse),
        (status = 400, description = "Confirmation address mismatch, targeting yourself, or removing the last administrator", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
        (status = 404, description = "No such account", body = ErrorResponse),
    )
)]
pub async fn delete_user(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path(target_id): Path<Uuid>,
    Json(request): Json<DeleteAccountRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    user.require_role(&RoleName::admin())?;

    state
        .identity
        .delete_account(target_id, &request.confirm_email, user.user.id, &client)
        .await?;

    Ok(Json(MessageResponse::new(
        "Account removed. Audit entries are retained without the account reference.",
    )))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/audit-events",
    tag = "admin",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(ListAuditEventsQuery),
    responses(
        (status = 200, description = "Page of audit events, newest first", body = AuditEventListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Administrator role required", body = ErrorResponse),
    )
)]
pub async fn list_audit_events(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Query(query): Query<ListAuditEventsQuery>,
) -> Result<Json<AuditEventListResponse>, AppError> {
    user.require_role(&RoleName::admin())?;

    let filters = AuditFilters::from_query(
        query.user_id,
        query.organization_id,
        query.email.as_deref(),
        query.event_type,
        query.since,
        query.until,
    );
    let (limit, offset) = query.bounds();
    let (events, total) = state.identity.audit_events(&filters, limit, offset).await?;

    Ok(Json(AuditEventListResponse { events, total }))
}
