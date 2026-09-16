pub mod auth;
pub mod identity;
pub mod organization;
pub mod rbac;
pub mod session;

use std::sync::Arc;

use sqlx::PgPool;

use crate::{
    modules::{auth::AuthService, identity::IdentityService, organization::OrganizationService},
    shared::{config::AppConfig, queue::EmailQueue, ratelimit::RateLimiters},
};

/// Everything the HTTP layer needs, assembled once at startup.
///
/// It lives at the module composition root rather than inside `auth`, so that a route module
/// does not have to borrow another module's state — and so `AuthenticatedUser` can be
/// implemented for one type that every router shares.
#[derive(Clone)]
pub struct ApiState {
    pub auth: Arc<AuthService>,
    pub identity: Arc<IdentityService>,
    pub organizations: Arc<OrganizationService>,
    pub config: Arc<AppConfig>,
    pub limiters: RateLimiters,
}

impl ApiState {
    pub fn new(
        database: PgPool,
        queue: EmailQueue,
        config: Arc<AppConfig>,
        limiters: RateLimiters,
    ) -> anyhow::Result<Self> {
        // The identity service is shared: authentication reads accounts from it, and
        // organizations resolve invited addresses through it.
        let identity = Arc::new(IdentityService::new(
            database.clone(),
            queue,
            config.clone(),
        )?);
        let auth = Arc::new(AuthService::new(
            identity.clone(),
            database.clone(),
            config.clone(),
        ));
        let organizations = Arc::new(OrganizationService::new(database, identity.clone()));

        Ok(Self {
            auth,
            identity,
            organizations,
            config,
            limiters,
        })
    }
}
