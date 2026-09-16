use utoipa::{
    Modify, OpenApi,
    openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme},
};

use crate::{
    modules::{auth::handler as auth_handlers, identity::handler as identity_handlers},
    shared::{error::ErrorResponse, health::HealthResponse},
};

/// Registers the two ways this API accepts credentials: a bearer access token for API
/// clients and the HttpOnly cookie used by the dashboard.
pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let Some(components) = openapi.components.as_mut() else {
            return;
        };

        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
        components.add_security_scheme(
            "cookie_auth",
            SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new(
                crate::modules::auth::cookies::ACCESS_TOKEN_COOKIE,
            ))),
        );
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        auth_handlers::register,
        auth_handlers::login,
        auth_handlers::dashboard_login,
        auth_handlers::refresh,
        auth_handlers::logout,
        auth_handlers::logout_all,
        auth_handlers::me,
        auth_handlers::change_password,
        auth_handlers::list_users,
        auth_handlers::set_user_status,
        identity_handlers::verify_email,
        identity_handlers::resend_verification,
        identity_handlers::forgot_password,
        identity_handlers::reset_password,
    ),
    components(schemas(
        crate::modules::identity::PublicUser,
        crate::modules::identity::UserStatus,
        crate::modules::rbac::RoleName,
        crate::modules::identity::dto::RegisterRequest,
        crate::modules::identity::dto::LoginRequest,
        crate::modules::auth::dto::RefreshRequest,
        crate::modules::auth::dto::ChangePasswordRequest,
        crate::modules::identity::dto::ForgotPasswordRequest,
        crate::modules::identity::dto::ResetPasswordRequest,
        crate::modules::identity::dto::VerifyEmailRequest,
        crate::modules::identity::dto::ResendVerificationRequest,
        crate::modules::identity::dto::MessageResponse,
        crate::modules::identity::dto::UserListResponse,
        crate::modules::identity::dto::AccountStatusUpdate,
        crate::modules::identity::dto::UpdateUserStatusRequest,
        crate::modules::auth::dto::AuthResponse,
        crate::modules::auth::dto::DashboardAuthResponse,
        ErrorResponse,
        HealthResponse,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth", description = "Sign-in, sessions, and account credentials"),
        (name = "identity", description = "Email verification and password recovery"),
        (name = "admin", description = "Administrative operations"),
    )
)]
pub struct ApiDoc;
