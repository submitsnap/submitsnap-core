use axum::{
    Json,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};
use serde::Serialize;
use validator::Validate;

use crate::{
    auth::AuthenticatedUser,
    error::AppError,
    models::{AuthResponse, DashboardAuthResponse, LoginRequest, PublicUser, RegisterRequest},
    queue::EmailJob,
    state::AppState,
};

pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<PublicUser>), AppError> {
    validate(&request)?;
    let email = normalize_email(request.email);
    let user = state.auth.register(email.clone(), request.password).await?;

    let job = EmailJob {
        to: email,
        subject: "Welcome to SubmitSnap".into(),
        text_body: "Your SubmitSnap account is ready.".into(),
    };
    if let Err(error) = state.queue.enqueue(&job).await {
        // An account must not be rejected merely because a non-critical welcome email is delayed.
        tracing::error!(error = ?error, user_id = %user.id, "failed to enqueue welcome email");
    }
    Ok((StatusCode::CREATED, Json(user)))
}

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let (user, access_token) = authenticate_login(&state, request).await?;
    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer",
        user,
    }))
}

pub async fn dashboard_login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let (user, access_token) = authenticate_login(&state, request).await?;
    let secure = state
        .config
        .cookie_secure
        .then_some("; Secure")
        .unwrap_or_default();
    let cookie = format!(
        "access_token={access_token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=86400{secure}"
    );
    let mut response = Json(DashboardAuthResponse { user }).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|error| AppError::Internal(error.into()))?,
    );
    Ok(response)
}

async fn authenticate_login(
    state: &AppState,
    request: LoginRequest,
) -> Result<(PublicUser, String), AppError> {
    validate(&request)?;
    state
        .auth
        .login(normalize_email(request.email), request.password)
        .await
}

pub async fn me(AuthenticatedUser(user): AuthenticatedUser) -> Json<PublicUser> {
    Json(user)
}

pub async fn health_check(State(state): State<AppState>) -> Result<Json<HealthResponse>, AppError> {
    sqlx::query("SELECT 1")
        .fetch_one(&state.database)
        .await
        .map_err(|error| AppError::Internal(error.into()))?;
    state.queue.ping().await.map_err(AppError::Internal)?;
    Ok(Json(HealthResponse { status: "ok" }))
}

fn validate<T: Validate>(value: &T) -> Result<(), AppError> {
    value
        .validate()
        .map_err(|errors| AppError::Validation(errors.to_string()))
}

fn normalize_email(email: String) -> String {
    email.trim().to_lowercase()
}

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
}
