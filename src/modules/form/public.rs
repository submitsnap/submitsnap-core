//! The public surface: `/f/{public_id}`.
//!
//! These routes sit outside `/api/v1` on purpose. A form is embedded on somebody else's site,
//! so the responses must be cacheable and the origin must be open, neither of which is true of
//! the API subtree.

use axum::{
    Json,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
};
use futures_util::StreamExt as _;
use serde_json::{Map, Value};

use crate::{
    modules::{
        ApiState,
        form::dto::{
            PublicFormResponse, SubmissionAcceptedResponse, UploadQuery, UploadedFileResponse,
        },
    },
    shared::{
        error::{AppError, ErrorResponse},
        request::ClientInfo,
    },
};

#[utoipa::path(
    get,
    path = "/f/{public_id}",
    tag = "public",
    params(("public_id" = String, Path, description = "Public form handle")),
    responses(
        (status = 200, description = "The form to render", body = PublicFormResponse),
        (status = 404, description = "No such form, or it is not published yet", body = ErrorResponse),
        (status = 410, description = "The form is closed", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    )
)]
pub async fn definition(
    State(state): State<ApiState>,
    Path(public_id): Path<String>,
) -> Result<Json<PublicFormResponse>, AppError> {
    Ok(Json(state.forms.public_definition(&public_id).await?))
}

#[utoipa::path(
    post,
    path = "/f/{public_id}",
    tag = "public",
    params(("public_id" = String, Path, description = "Public form handle")),
    responses(
        (status = 201, description = "Accepted. A honeypot submission is accepted too, and filed as spam.", body = SubmissionAcceptedResponse),
        (status = 400, description = "The payload does not match the form; every problem is listed", body = ErrorResponse),
        (status = 404, description = "No such form, or it is not published yet", body = ErrorResponse),
        (status = 410, description = "The form is closed", body = ErrorResponse),
        (status = 429, description = "Too many submissions", body = ErrorResponse),
    )
)]
pub async fn submit(
    State(state): State<ApiState>,
    client: ClientInfo,
    headers: HeaderMap,
    Path(public_id): Path<String>,
    Json(payload): Json<Map<String, Value>>,
) -> Result<(axum::http::StatusCode, Json<SubmissionAcceptedResponse>), AppError> {
    let referer = headers
        .get(axum::http::header::REFERER)
        .and_then(|value| value.to_str().ok());

    let accepted = state
        .forms
        .submit(&public_id, &payload, &client, referer)
        .await?;

    Ok((axum::http::StatusCode::CREATED, Json(accepted)))
}

/// Uploads one file answer.
///
/// The bytes travel through this service rather than straight to the bucket, which is the only
/// arrangement in which `max_bytes` and `accept` describe the file instead of describing what the
/// client claimed about it. It costs bandwidth and buys enforcement.
#[utoipa::path(
    post,
    path = "/f/{public_id}/files/{field_key}",
    tag = "public",
    params(
        ("public_id" = String, Path, description = "Public form handle"),
        ("field_key" = String, Path, description = "The file field this upload answers"),
        ("filename" = Option<String>, Query, description = "Shown back to a human and in the download header; never used as a path"),
    ),
    responses(
        (status = 201, description = "Stored. `key` is what the submission sends back as the answer.", body = UploadedFileResponse),
        (status = 400, description = "Not a file field on this form, or the media type is not accepted", body = ErrorResponse),
        (status = 404, description = "No such form, or it is not published yet", body = ErrorResponse),
        (status = 410, description = "The form is closed", body = ErrorResponse),
        (status = 413, description = "The file exceeds the field's limit", body = ErrorResponse),
        (status = 429, description = "Too many uploads", body = ErrorResponse),
    )
)]
pub async fn upload(
    State(state): State<ApiState>,
    Path((public_id, field_key)): Path<(String, String)>,
    Query(query): Query<UploadQuery>,
    headers: HeaderMap,
    body: Body,
) -> Result<(StatusCode, Json<UploadedFileResponse>), AppError> {
    let declared_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());

    // Streamed rather than buffered, so the size of an upload is bounded by the route's limit and
    // not by how much memory the process can spare.
    let streamed = body
        .into_data_stream()
        .map(|chunk| chunk.map_err(|error| anyhow::anyhow!("reading the upload body: {error}")))
        .boxed();

    let stored = state
        .forms
        .upload(
            &public_id,
            &field_key,
            query.filename.as_deref(),
            declared_type,
            streamed,
        )
        .await?;

    Ok((StatusCode::CREATED, Json(stored)))
}
