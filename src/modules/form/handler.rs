//! The management surface for forms, under `/api/v1/organizations/{organization_id}/forms`.
//!
//! Authorization is resolved inside the service, so a handler reads as "resolve, authorize,
//! act" without the check being something a maintainer has to remember.

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
        form::dto::{
            CreateFormRequest, FormListResponse, FormResponse, PaginationQuery, UpdateFormRequest,
        },
    },
    shared::{
        error::{AppError, ErrorResponse, validate},
        request::ClientInfo,
    },
};

type FormPath = (Uuid, Uuid);

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/forms",
    tag = "forms",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("organization_id" = Uuid, Path, description = "Organization identifier")),
    request_body = CreateFormRequest,
    responses(
        (status = 201, description = "Form created as a draft", body = FormResponse),
        (status = 400, description = "The definition is not valid; every problem is listed", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn create_form(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
    Json(request): Json<CreateFormRequest>,
) -> Result<(StatusCode, Json<FormResponse>), AppError> {
    validate(&request)?;

    let form = state
        .forms
        .create(organization_id, &request, user.user.id, &client)
        .await?;

    Ok((StatusCode::CREATED, Json(form)))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/forms",
    tag = "forms",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("organization_id" = Uuid, Path, description = "Organization identifier"), PaginationQuery),
    responses(
        (status = 200, description = "Page of forms", body = FormListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn list_forms(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<FormListResponse>, AppError> {
    let (limit, offset) = query.bounds();
    let (forms, total) = state
        .forms
        .list(organization_id, user.user.id, limit, offset)
        .await?;

    Ok(Json(FormListResponse { forms, total }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/forms/{form_id}",
    tag = "forms",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("form_id" = Uuid, Path, description = "Form identifier"),
    ),
    responses(
        (status = 200, description = "The form", body = FormResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such form", body = ErrorResponse),
    )
)]
pub async fn get_form(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path((organization_id, form_id)): Path<FormPath>,
) -> Result<Json<FormResponse>, AppError> {
    Ok(Json(
        state
            .forms
            .get(organization_id, form_id, user.user.id)
            .await?,
    ))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{organization_id}/forms/{form_id}",
    tag = "forms",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("form_id" = Uuid, Path, description = "Form identifier"),
    ),
    request_body = UpdateFormRequest,
    responses(
        (status = 200, description = "Updated. Absent fields are left alone; null clears a nullable one.", body = FormResponse),
        (status = 400, description = "The definition is not valid; every problem is listed", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such form", body = ErrorResponse),
    )
)]
pub async fn update_form(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, form_id)): Path<FormPath>,
    Json(request): Json<UpdateFormRequest>,
) -> Result<Json<FormResponse>, AppError> {
    validate(&request)?;

    let form = state
        .forms
        .update(organization_id, form_id, &request, user.user.id, &client)
        .await?;

    Ok(Json(form))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{organization_id}/forms/{form_id}",
    tag = "forms",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("form_id" = Uuid, Path, description = "Form identifier"),
    ),
    responses(
        (status = 204, description = "Removed, along with its submissions"),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such form", body = ErrorResponse),
    )
)]
pub async fn delete_form(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, form_id)): Path<FormPath>,
) -> Result<StatusCode, AppError> {
    state
        .forms
        .delete(organization_id, form_id, user.user.id, &client)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/forms/{form_id}/publish",
    tag = "forms",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("form_id" = Uuid, Path, description = "Form identifier"),
    ),
    responses(
        (status = 200, description = "Published and accepting submissions", body = FormResponse),
        (status = 400, description = "Not publishable, or it has a file field with no storage configured", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such form", body = ErrorResponse),
    )
)]
pub async fn publish_form(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, form_id)): Path<FormPath>,
) -> Result<Json<FormResponse>, AppError> {
    Ok(Json(
        state
            .forms
            .publish(organization_id, form_id, user.user.id, &client)
            .await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/forms/{form_id}/close",
    tag = "forms",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("form_id" = Uuid, Path, description = "Form identifier"),
    ),
    responses(
        (status = 200, description = "Closed; the public endpoint now answers 410", body = FormResponse),
        (status = 400, description = "Only a published form can be closed", body = ErrorResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such form", body = ErrorResponse),
    )
)]
pub async fn close_form(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, form_id)): Path<FormPath>,
) -> Result<Json<FormResponse>, AppError> {
    Ok(Json(
        state
            .forms
            .close(organization_id, form_id, user.user.id, &client)
            .await?,
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/organizations/{organization_id}/forms/{form_id}/public-id",
    tag = "forms",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("form_id" = Uuid, Path, description = "Form identifier"),
    ),
    responses(
        (status = 200, description = "New public handle issued; the previous link no longer works", body = FormResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such form", body = ErrorResponse),
    )
)]
pub async fn rotate_public_id(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, form_id)): Path<FormPath>,
) -> Result<Json<FormResponse>, AppError> {
    Ok(Json(
        state
            .forms
            .rotate_public_id(organization_id, form_id, user.user.id, &client)
            .await?,
    ))
}
