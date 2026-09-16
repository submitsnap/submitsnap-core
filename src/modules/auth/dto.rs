use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::modules::identity::PublicUser;

/// Issued to programmatic clients. The refresh token is returned in the body; browser clients
/// receive it as an HttpOnly cookie instead.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: PublicUser,
}

/// Issued to browser clients. Tokens travel only in cookies, never in the response body.
#[derive(Debug, Serialize, ToSchema)]
pub struct DashboardAuthResponse {
    pub user: PublicUser,
    pub expires_in: i64,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RefreshRequest {
    /// Required for API clients. Browser clients send the refresh cookie instead.
    #[serde(default)]
    #[validate(length(min = 1, max = 512))]
    pub refresh_token: Option<String>,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 1, max = 128))]
    pub current_password: String,
    #[validate(length(min = 12, max = 128))]
    pub new_password: String,
}
