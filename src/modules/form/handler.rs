//! The management surface for forms, under `/api/v1/organizations/{organization_id}/forms`.
//!
//! Authorization is resolved inside the service, so a handler reads as "resolve, authorize,
//! act" without the check being something a maintainer has to remember.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::{
    modules::{
        ApiState,
        auth::AuthenticatedUser,
        form::dto::{
            CreateFormRequest, ExportFormat, ExportQuery, FormListResponse, FormResponse,
            PaginationQuery, SubmissionListResponse, SubmissionQuery, SubmissionResponse,
            UpdateFormRequest, UpdateSubmissionRequest,
        },
    },
    shared::{
        error::{AppError, ErrorResponse, validate},
        request::ClientInfo,
    },
};

type FormPath = (Uuid, Uuid);
type SubmissionPath = (Uuid, Uuid);
type SubmissionFilePath = (Uuid, Uuid, String);

/// Builds the `Content-Disposition` for an attachment download.
///
/// Both the quoted and the extended form are emitted, which is what RFC 6266 asks for: the first
/// covers ASCII, the second carries anything else. Quotes and backslashes are replaced and every
/// non-ASCII byte is percent-encoded, so a filename can never break out of the header it is
/// placed in.
fn content_disposition(filename: &str) -> String {
    let quoted: String = filename
        .chars()
        .map(|character| match character {
            '"' | '\\' => '_',
            character if character.is_ascii_graphic() || character == ' ' => character,
            _ => '_',
        })
        .collect();

    let encoded: String = filename
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();

    format!("attachment; filename=\"{quoted}\"; filename*=UTF-8''{encoded}")
}

/// Builds the streaming response an export is written into.
fn export_response(stream: crate::modules::form::service::ExportStream) -> Response {
    let disposition = format!(
        "attachment; filename=\"{}\"",
        stream.filename.replace('"', "")
    );

    (
        [
            (header::CONTENT_TYPE, stream.content_type),
            (header::CONTENT_DISPOSITION, disposition.as_str()),
        ],
        axum::body::Body::from_stream(stream.body),
    )
        .into_response()
}

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

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/submissions",
    tag = "submissions",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(("organization_id" = Uuid, Path, description = "Organization identifier"), SubmissionQuery),
    responses(
        (status = 200, description = "Page of submissions across every form in the organization", body = SubmissionListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such organization", body = ErrorResponse),
    )
)]
pub async fn list_submissions(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path(organization_id): Path<Uuid>,
    Query(query): Query<SubmissionQuery>,
) -> Result<Json<SubmissionListResponse>, AppError> {
    let (limit, offset) = query.bounds();
    let (submissions, total) = state
        .forms
        .list_submissions(
            organization_id,
            user.user.id,
            &query.filters(None),
            limit,
            offset,
        )
        .await?;

    Ok(Json(SubmissionListResponse { submissions, total }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/forms/{form_id}/submissions",
    tag = "submissions",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("form_id" = Uuid, Path, description = "Form identifier"),
        SubmissionQuery,
    ),
    responses(
        (status = 200, description = "Page of submissions for one form", body = SubmissionListResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such form", body = ErrorResponse),
    )
)]
pub async fn list_form_submissions(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path((organization_id, form_id)): Path<FormPath>,
    Query(query): Query<SubmissionQuery>,
) -> Result<Json<SubmissionListResponse>, AppError> {
    let (limit, offset) = query.bounds();
    let (submissions, total) = state
        .forms
        .list_submissions(
            organization_id,
            user.user.id,
            &query.filters(Some(form_id)),
            limit,
            offset,
        )
        .await?;

    Ok(Json(SubmissionListResponse { submissions, total }))
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/submissions/{submission_id}",
    tag = "submissions",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("submission_id" = Uuid, Path, description = "Submission identifier"),
    ),
    responses(
        (status = 200, description = "The submission", body = SubmissionResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such submission", body = ErrorResponse),
    )
)]
pub async fn get_submission(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path((organization_id, submission_id)): Path<SubmissionPath>,
) -> Result<Json<SubmissionResponse>, AppError> {
    Ok(Json(
        state
            .forms
            .get_submission(organization_id, submission_id, user.user.id)
            .await?,
    ))
}

#[utoipa::path(
    patch,
    path = "/api/v1/organizations/{organization_id}/submissions/{submission_id}",
    tag = "submissions",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("submission_id" = Uuid, Path, description = "Submission identifier"),
    ),
    request_body = UpdateSubmissionRequest,
    responses(
        (status = 200, description = "Status updated", body = SubmissionResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such submission", body = ErrorResponse),
    )
)]
pub async fn update_submission(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, submission_id)): Path<SubmissionPath>,
    Json(request): Json<UpdateSubmissionRequest>,
) -> Result<Json<SubmissionResponse>, AppError> {
    Ok(Json(
        state
            .forms
            .set_submission_status(
                organization_id,
                submission_id,
                request.status,
                user.user.id,
                &client,
            )
            .await?,
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/organizations/{organization_id}/submissions/{submission_id}",
    tag = "submissions",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("submission_id" = Uuid, Path, description = "Submission identifier"),
    ),
    responses(
        (status = 204, description = "Removed"),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Requires the owner or admin role", body = ErrorResponse),
        (status = 404, description = "No such submission", body = ErrorResponse),
    )
)]
pub async fn delete_submission(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Path((organization_id, submission_id)): Path<SubmissionPath>,
) -> Result<StatusCode, AppError> {
    state
        .forms
        .delete_submission(organization_id, submission_id, user.user.id, &client)
        .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/forms/{form_id}/submissions/export",
    tag = "submissions",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("form_id" = Uuid, Path, description = "Form identifier"),
        ExportQuery,
    ),
    responses(
        (status = 200, description = "Every submission, streamed as CSV or one JSON object per line"),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member", body = ErrorResponse),
        (status = 404, description = "No such form", body = ErrorResponse),
    )
)]
pub async fn export_submissions(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path((organization_id, form_id)): Path<FormPath>,
    Query(query): Query<ExportQuery>,
) -> Result<Response, AppError> {
    let stream = state
        .forms
        .export(
            organization_id,
            form_id,
            user.user.id,
            query.format.unwrap_or(ExportFormat::Csv),
        )
        .await?;

    Ok(export_response(stream))
}

/// Streams one attachment back to a member of the organization.
///
/// The object key is never taken from the request: it is read from the submission, which is
/// scoped by organization. That is what makes an unguessable key valuable on its own terms rather
/// than a bearer token, and it means the bucket can stay entirely private.
#[utoipa::path(
    get,
    path = "/api/v1/organizations/{organization_id}/submissions/{submission_id}/files/{field_key}",
    tag = "forms",
    params(
        ("organization_id" = Uuid, Path, description = "Organization identifier"),
        ("submission_id" = Uuid, Path, description = "Submission identifier"),
        ("field_key" = String, Path, description = "The file field that was answered"),
    ),
    responses(
        (status = 200, description = "The file, streamed back as an attachment"),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
        (status = 403, description = "Not a member of this organization", body = ErrorResponse),
        (status = 404, description = "No such submission, or it has no attachment for that field", body = ErrorResponse),
    )
)]
pub async fn download_submission_file(
    State(state): State<ApiState>,
    user: AuthenticatedUser,
    Path((organization_id, submission_id, field_key)): Path<SubmissionFilePath>,
) -> Result<Response, AppError> {
    let download = state
        .forms
        .submission_file(organization_id, submission_id, &field_key, user.user.id)
        .await?;

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, download.content_type)
        .header(header::CONTENT_LENGTH, download.object.size)
        .header(
            header::CONTENT_DISPOSITION,
            content_disposition(&download.filename),
        )
        // Uploaded bytes are never something this origin should render. Served as an attachment
        // with `nosniff`, an uploaded HTML or SVG file cannot run script against this API.
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(axum::body::Body::from_stream(download.object.stream))
        .map_err(|error| AppError::Internal(error.into()))?;

    Ok(response)
}
