use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;
use validator::Validate;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid request: {0}")]
    Validation(String),
    #[error("authentication failed")]
    Unauthorized,
    #[error("resource already exists")]
    Conflict,
    #[error("internal server error")]
    Internal(#[from] anyhow::Error),
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Validation(message) => (StatusCode::BAD_REQUEST, message),
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "authentication failed".into()),
            Self::Conflict => (StatusCode::CONFLICT, "resource already exists".into()),
            Self::Internal(error) => {
                tracing::error!(error = ?error, "unhandled application error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".into(),
                )
            }
        };
        (status, Json(ErrorBody { error: &message })).into_response()
    }
}

pub fn validate<T: Validate>(value: &T) -> Result<(), AppError> {
    value
        .validate()
        .map_err(|errors| AppError::Validation(errors.to_string()))
}
