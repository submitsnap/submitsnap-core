mod administration;
pub(crate) mod dto;
mod error;
pub(crate) mod events;
pub(crate) mod handler;
mod model;
mod password;
pub(crate) mod repository;
mod service;
mod tokens;

pub use dto::PublicUser;
pub use error::IdentityError;
pub use events::AuthEventType;
pub use model::UserStatus;
pub use service::IdentityService;

use axum::{Router, routing::post};

use crate::{modules::ApiState, shared::ratelimit::limit};

/// Routes mounted under `/api/v1/identity`. Every route here is unauthenticated by design:
/// they are exercised before a caller has a session, and each one either consumes a
/// single-use token or deliberately reveals nothing.
pub fn router<S>(state: ApiState) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let routes = Router::new()
        .route("/email/verify", post(handler::verify_email))
        .route("/email/verification", post(handler::resend_verification))
        .route("/password/forgot", post(handler::forgot_password))
        .route("/password/reset", post(handler::reset_password));

    limit(routes, state.limiters.sensitive.clone()).with_state(state)
}
