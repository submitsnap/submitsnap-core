//! Grants the administrator role to an existing account.
//!
//! A fresh instance has no administrator and no way to create one through the API, because
//! every administrative route requires the very role it would be granting. This command is
//! the bootstrap path, and it is also the way back in if the last administrator is ever lost.
//! It only ever adds the role, so it cannot itself leave an instance unadministrable.
//!
//! ```text
//! make grant-admin EMAIL=you@example.com
//! # or
//! cargo run --bin grant_admin -- you@example.com
//! ```

use std::{env, sync::Arc};

use submitsnap_core::{
    modules::{identity::IdentityService, rbac::RoleName},
    shared::{config::AppConfig, db, logging, queue::EmailQueue},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    logging::init(logging::configured_format());

    let email = env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: grant_admin <email>"))?;

    let config = AppConfig::from_env()?;
    let database = db::connect(&config).await?;
    let queue = EmailQueue::connect(&config.redis_url, &config.redis_key_prefix)?;
    let identity = IdentityService::new(database, queue, Arc::new(config))?;

    let user_id = identity
        .grant_role_by_email(&email, &RoleName::admin())
        .await?;

    println!("Granted the administrator role to {email} ({user_id}).");
    println!("Any session that account already has picks the role up on its next request.");

    Ok(())
}
