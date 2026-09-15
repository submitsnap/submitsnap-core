use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::modules::auth::repository::UserRecord;

#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email, length(max = 320))]
    pub email: String,
    #[validate(length(min = 12, max = 128))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email, length(max = 320))]
    pub email: String,
    #[validate(length(min = 1, max = 128))]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct PublicUser {
    pub id: Uuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl From<UserRecord> for PublicUser {
    fn from(user: UserRecord) -> Self {
        Self {
            id: user.id,
            email: user.email,
            created_at: user.created_at,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub user: PublicUser,
}

#[derive(Debug, Serialize)]
pub struct DashboardAuthResponse {
    pub user: PublicUser,
}
