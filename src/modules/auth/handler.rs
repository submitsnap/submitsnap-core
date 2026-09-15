use axum::{
    Json,
    extract::State,
    http::{HeaderValue, StatusCode, header},
    response::IntoResponse,
};

use crate::{
    modules::auth::{
        AuthState,
        dto::{AuthResponse, DashboardAuthResponse, LoginRequest, PublicUser, RegisterRequest},
        extractor::AuthenticatedUser,
        service::AuthService,
    },
    shared::error::{AppError, validate},
};

pub async fn register(
    State(state): State<AuthState>,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<PublicUser>), AppError> {
    validate(&request)?;
    let user = state
        .service
        .register(normalize_email(request.email), request.password)
        .await?;
    Ok((StatusCode::CREATED, Json(user)))
}

pub async fn login(
    State(state): State<AuthState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let (user, access_token) = authenticate_login(&state.service, request).await?;
    Ok(Json(AuthResponse {
        access_token,
        token_type: "Bearer",
        user,
    }))
}

pub async fn dashboard_login(
    State(state): State<AuthState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AppError> {
    let (user, access_token) = authenticate_login(&state.service, request).await?;
    let secure = if state.cookie_secure { "; Secure" } else { "" };
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

pub async fn me(AuthenticatedUser(user): AuthenticatedUser) -> Json<PublicUser> {
    Json(user)
}

async fn authenticate_login(
    auth: &AuthService,
    request: LoginRequest,
) -> Result<(PublicUser, String), AppError> {
    validate(&request)?;
    Ok(auth
        .login(normalize_email(request.email), request.password)
        .await?)
}

fn normalize_email(email: String) -> String {
    email.trim().to_lowercase()
}
