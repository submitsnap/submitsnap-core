pub mod auth;
pub mod form;
pub mod identity;
pub mod organization;
pub mod rbac;
pub mod session;
pub mod webhook;

use std::sync::Arc;

use sqlx::PgPool;

use crate::{
    modules::{
        auth::AuthService, form::FormService, identity::IdentityService,
        organization::OrganizationService, webhook::WebhookService,
    },
    shared::{config::AppConfig, queue::EmailQueue, ratelimit::RateLimiters, storage::FileStorage},
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
    pub forms: Arc<FormService>,
    pub webhooks: Arc<WebhookService>,
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
        let organizations = Arc::new(OrganizationService::new(database.clone(), identity.clone()));
        let webhooks = Arc::new(WebhookService::new(
            database.clone(),
            organizations.clone(),
            config.webhook_allow_private_targets,
        ));
        // Built once so the whole process agrees on whether storage exists, and so a broken S3
        // setting stops the service at startup rather than at the first upload.
        let storage = Arc::new(FileStorage::from_config(&config)?);
        let forms = Arc::new(FormService::new(
            database,
            organizations.clone(),
            limiters.submissions_per_form.clone(),
            storage,
            config.upload_max_bytes,
            config.upload_ttl_hours,
        ));

        Ok(Self {
            auth,
            identity,
            organizations,
            forms,
            webhooks,
            config,
            limiters,
        })
    }
}
