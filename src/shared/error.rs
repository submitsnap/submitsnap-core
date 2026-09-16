use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid request: {0}")]
    Validation(String),
    #[error("invalid or expired token")]
    InvalidToken,
    #[error("authentication failed")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("resource not found")]
    NotFound,
    /// The resource exists but is deliberately not serving: a closed form, for instance.
    #[error("{0}")]
    Gone(String),
    #[error("resource already exists")]
    Conflict,
    #[error("account is locked")]
    AccountLocked,
    #[error("too many requests")]
    TooManyRequests,
    #[error("internal server error")]
    Internal(#[from] anyhow::Error),
}

/// Stable, machine-readable error body. `code` is a fixed identifier clients can branch on;
/// `error` is a human-readable message that never contains internal detail.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

impl AppError {
    fn status(&self) -> StatusCode {
        match self {
            Self::Validation(_) => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Gone(_) => StatusCode::GONE,
            Self::Conflict => StatusCode::CONFLICT,
            Self::AccountLocked => StatusCode::LOCKED,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            Self::Validation(_) => "validation_error",
            Self::InvalidToken => "invalid_token",
            Self::Unauthorized => "authentication_failed",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Gone(_) => "gone",
            Self::Conflict => "conflict",
            Self::AccountLocked => "account_locked",
            Self::TooManyRequests => "too_many_requests",
            Self::Internal(_) => "internal_error",
        }
    }

    fn message(&self) -> String {
        match self {
            Self::Validation(message) => message.clone(),
            Self::Internal(error) => {
                // Log the cause but never return it to the caller.
                tracing::error!(error = ?error, "unhandled application error");
                self.to_string()
            }
            other => other.to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status();
        let code = self.code().to_owned();
        let error = self.message();
        (status, Json(ErrorResponse { error, code })).into_response()
    }
}

pub fn validate<T: Validate>(value: &T) -> Result<(), AppError> {
    value
        .validate()
        .map_err(|errors| AppError::Validation(errors.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn internal_errors_do_not_leak_their_cause() {
        let error = AppError::Internal(anyhow::anyhow!("connection string leaked here"));
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn status_codes_match_their_semantics() {
        assert_eq!(AppError::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(AppError::Forbidden.status(), StatusCode::FORBIDDEN);
        assert_eq!(AppError::Conflict.status(), StatusCode::CONFLICT);
        assert_eq!(AppError::AccountLocked.status(), StatusCode::LOCKED);
        assert_eq!(
            AppError::TooManyRequests.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(AppError::InvalidToken.status(), StatusCode::BAD_REQUEST);
    }
}
