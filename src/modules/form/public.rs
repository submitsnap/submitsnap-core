//! The public surface: `/f/{public_id}`.
//!
//! These routes sit outside `/api/v1` on purpose. A form is embedded on somebody else's site,
//! so the responses must be cacheable and the origin must be open, neither of which is true of
//! the API subtree.

use axum::{
    Json,
    extract::{Path, State},
    http::HeaderMap,
};
use serde_json::{Map, Value};

use crate::{
    modules::{
        ApiState,
        form::dto::{PublicFormResponse, SubmissionAcceptedResponse},
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
