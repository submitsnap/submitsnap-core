use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar};

use crate::{
    modules::{
        ApiState,
        auth::{
            cookies::{REFRESH_TOKEN_COOKIE, access_cookie, refresh_cookie, removal_cookies},
            dto::{AuthResponse, ChangePasswordRequest, DashboardAuthResponse, RefreshRequest},
            extractor::AuthenticatedUser,
        },
        identity::{
            PublicUser,
            dto::{LoginRequest, MessageResponse, RegisterRequest},
        },
    },
    shared::{
        error::{AppError, ErrorResponse, validate},
        request::ClientInfo,
    },
};

const TOKEN_TYPE: &str = "Bearer";

#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Account created", body = PublicUser),
        (status = 400, description = "Request was not valid", body = ErrorResponse),
        (status = 409, description = "Email address is already registered", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    )
)]
pub async fn register(
    State(state): State<ApiState>,
    client: ClientInfo,
    Json(request): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<PublicUser>), AppError> {
    validate(&request)?;
    let user = state
        .auth
        .register(&request.email, &request.password, &client)
        .await?;

    Ok((StatusCode::CREATED, Json(user)))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Signed in", body = AuthResponse),
        (status = 400, description = "Request was not valid", body = ErrorResponse),
        (status = 401, description = "Credentials were rejected", body = ErrorResponse),
        (status = 403, description = "Account disabled or email address not verified", body = ErrorResponse),
        (status = 423, description = "Account temporarily locked", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    )
)]
pub async fn login(
    State(state): State<ApiState>,
    client: ClientInfo,
    Json(request): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    validate(&request)?;
    let session = state
        .auth
        .login(&request.email, &request.password, &client)
        .await?;

    Ok(Json(AuthResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        token_type: TOKEN_TYPE.to_owned(),
        expires_in: session.expires_in,
        user: session.user,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/dashboard/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Signed in; tokens are set as HttpOnly cookies", body = DashboardAuthResponse),
        (status = 400, description = "Request was not valid", body = ErrorResponse),
        (status = 401, description = "Credentials were rejected", body = ErrorResponse),
        (status = 403, description = "Account disabled or email address not verified", body = ErrorResponse),
        (status = 423, description = "Account temporarily locked", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    )
)]
pub async fn dashboard_login(
    State(state): State<ApiState>,
    client: ClientInfo,
    jar: CookieJar,
    Json(request): Json<LoginRequest>,
) -> Result<(CookieJar, Json<DashboardAuthResponse>), AppError> {
    validate(&request)?;
    let session = state
        .auth
        .login(&request.email, &request.password, &client)
        .await?;

    let jar = jar
        .add(access_cookie(
            session.access_token,
            state.config.access_token_ttl_seconds,
            state.config.cookie_secure,
        ))
        .add(refresh_cookie(
            session.refresh_token,
            state.config.refresh_token_ttl_seconds,
            state.config.cookie_secure,
        ));

    Ok((
        jar,
        Json(DashboardAuthResponse {
            user: session.user,
            expires_in: session.expires_in,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "New token pair; API clients receive them in the body, browser clients as cookies", body = AuthResponse),
        (status = 401, description = "Refresh token was rejected", body = ErrorResponse),
        (status = 429, description = "Too many requests", body = ErrorResponse),
    )
)]
pub async fn refresh(
    State(state): State<ApiState>,
    client: ClientInfo,
    jar: CookieJar,
    Json(request): Json<RefreshRequest>,
) -> Result<Response, AppError> {
    validate(&request)?;

    // The response shape follows the source of the token: a browser that sent a cookie gets
    // cookies back and never sees the token in JavaScript; an API client gets the body.
    let (token, from_cookie) = match request.refresh_token {
        Some(token) => (token, false),
        None => {
            let token = jar
                .get(REFRESH_TOKEN_COOKIE)
                .map(|cookie| cookie.value().to_owned())
                .ok_or(AppError::Unauthorized)?;
            (token, true)
        }
    };

    let session = state.auth.refresh(&token, &client).await?;

    if from_cookie {
        let jar = jar
            .add(access_cookie(
                session.access_token,
                state.config.access_token_ttl_seconds,
                state.config.cookie_secure,
            ))
            .add(refresh_cookie(
                session.refresh_token,
                state.config.refresh_token_ttl_seconds,
                state.config.cookie_secure,
            ));

        return Ok((
            jar,
            Json(DashboardAuthResponse {
                user: session.user,
                expires_in: session.expires_in,
            }),
        )
            .into_response());
    }

    Ok(Json(AuthResponse {
        access_token: session.access_token,
        refresh_token: session.refresh_token,
        token_type: TOKEN_TYPE.to_owned(),
        expires_in: session.expires_in,
        user: session.user,
    })
    .into_response())
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    responses(
        (status = 200, description = "Session revoked and cookies cleared", body = MessageResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
    )
)]
pub async fn logout(
    State(state): State<ApiState>,
    client: ClientInfo,
    jar: CookieJar,
    user: AuthenticatedUser,
) -> Result<(CookieJar, Json<MessageResponse>), AppError> {
    state
        .auth
        .logout(user.session_id, user.user.id, &client)
        .await?;

    let jar = clear_credentials(jar, state.config.cookie_secure);

    Ok((jar, Json(MessageResponse::new("Signed out."))))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout-all",
    tag = "auth",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    responses(
        (status = 200, description = "Every session revoked", body = MessageResponse),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
    )
)]
pub async fn logout_all(
    State(state): State<ApiState>,
    client: ClientInfo,
    jar: CookieJar,
    user: AuthenticatedUser,
) -> Result<(CookieJar, Json<MessageResponse>), AppError> {
    state.auth.logout_all(user.user.id, &client).await?;

    let jar = clear_credentials(jar, state.config.cookie_secure);

    Ok((
        jar,
        Json(MessageResponse::new("Every session has been signed out.")),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "auth",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    responses(
        (status = 200, description = "Current account", body = PublicUser),
        (status = 401, description = "Not authenticated", body = ErrorResponse),
    )
)]
pub async fn me(user: AuthenticatedUser) -> Json<PublicUser> {
    Json(user.user)
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/password/change",
    tag = "auth",
    security(("bearer_auth" = []), ("cookie_auth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password replaced; other sessions revoked", body = MessageResponse),
        (status = 400, description = "Request was not valid", body = ErrorResponse),
        (status = 401, description = "Current password was rejected", body = ErrorResponse),
    )
)]
pub async fn change_password(
    State(state): State<ApiState>,
    client: ClientInfo,
    user: AuthenticatedUser,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    validate(&request)?;

    let record = state
        .identity
        .user_by_id(user.user.id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    state
        .identity
        .change_password(
            &record,
            &request.current_password,
            &request.new_password,
            user.session_id,
            &client,
        )
        .await?;

    Ok(Json(MessageResponse::new(
        "Password updated. Other sessions were signed out.",
    )))
}

fn clear_credentials(jar: CookieJar, cookie_secure: bool) -> CookieJar {
    removal_cookies(cookie_secure)
        .into_iter()
        .fold(jar, |jar, cookie: Cookie<'static>| jar.add(cookie))
}
