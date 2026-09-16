use axum::{Json, extract::State, http::StatusCode};

use crate::{
    modules::identity::{
        IdentityState,
        dto::{
            ForgotPasswordRequest, MessageResponse, ResendVerificationRequest,
            ResetPasswordRequest, VerifyEmailRequest,
        },
    },
    shared::{
        error::{AppError, ErrorResponse, validate},
        request::ClientInfo,
    },
};

#[utoipa::path(
    post,
    path = "/api/v1/identity/email/verify",
    tag = "identity",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Email address confirmed", body = MessageResponse),
        (status = 400, description = "Token is invalid or has expired", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    )
)]
pub async fn verify_email(
    State(state): State<IdentityState>,
    client: ClientInfo,
    Json(request): Json<VerifyEmailRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    validate(&request)?;
    state.service.verify_email(&request.token, &client).await?;
    Ok(Json(MessageResponse::new("Email address confirmed.")))
}

#[utoipa::path(
    post,
    path = "/api/v1/identity/email/verification",
    tag = "identity",
    request_body = ResendVerificationRequest,
    responses(
        (status = 202, description = "Request accepted", body = MessageResponse),
        (status = 400, description = "Request was not valid", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    )
)]
pub async fn resend_verification(
    State(state): State<IdentityState>,
    client: ClientInfo,
    Json(request): Json<ResendVerificationRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), AppError> {
    validate(&request)?;
    state
        .service
        .resend_verification(&request.email, &client)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(MessageResponse::new(
            "If that address needs confirmation, a new link has been sent.",
        )),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/identity/password/forgot",
    tag = "identity",
    request_body = ForgotPasswordRequest,
    responses(
        (status = 202, description = "Request accepted", body = MessageResponse),
        (status = 400, description = "Request was not valid", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    )
)]
pub async fn forgot_password(
    State(state): State<IdentityState>,
    client: ClientInfo,
    Json(request): Json<ForgotPasswordRequest>,
) -> Result<(StatusCode, Json<MessageResponse>), AppError> {
    validate(&request)?;
    // The reset link is delivered by email, so the raw token is deliberately dropped here.
    let _ = state
        .service
        .request_password_reset(&request.email, &client)
        .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(MessageResponse::new(
            "If an account exists for that address, a reset link has been sent.",
        )),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/identity/password/reset",
    tag = "identity",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password replaced and sessions revoked", body = MessageResponse),
        (status = 400, description = "Token is invalid or has expired", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    )
)]
pub async fn reset_password(
    State(state): State<IdentityState>,
    client: ClientInfo,
    Json(request): Json<ResetPasswordRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    validate(&request)?;
    state
        .service
        .reset_password(&request.token, &request.password, &client)
        .await?;

    Ok(Json(MessageResponse::new(
        "Password replaced. All sessions have been signed out.",
    )))
}
