use std::collections::HashMap;

use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use crate::modules::rbac::RoleName;

#[derive(Clone)]
pub struct RoleRepository {
    database: PgPool,
}

impl RoleRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    /// Resolves a role name to its identifier. Roles are static seed data, so this read is
    /// intentionally performed outside any caller transaction.
    pub async fn role_id(&self, role: &RoleName) -> anyhow::Result<Uuid> {
        let role_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM roles WHERE name = $1")
            .bind(role.as_str())
            .fetch_optional(&self.database)
            .await?;

        role_id.ok_or_else(|| anyhow::anyhow!("role {role} is not configured; run migrations"))
    }

    /// Grants `role` to `user_id`. Accepts any executor so it can join an existing
    /// transaction during account creation.
    pub async fn assign<'e, E>(
        &self,
        executor: E,
        user_id: Uuid,
        role: &RoleName,
    ) -> anyhow::Result<()>
    where
        E: PgExecutor<'e>,
    {
        let role_id = self.role_id(role).await?;

        sqlx::query(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(role_id)
        .execute(executor)
        .await?;

        Ok(())
    }

    pub async fn roles_for_user(&self, user_id: Uuid) -> anyhow::Result<Vec<RoleName>> {
        let names: Vec<String> = sqlx::query_scalar(
            "SELECT roles.name FROM user_roles \
             JOIN roles ON roles.id = user_roles.role_id \
             WHERE user_roles.user_id = $1 \
             ORDER BY roles.name",
        )
        .bind(user_id)
        .fetch_all(&self.database)
        .await?;

        Ok(names.into_iter().map(RoleName::new).collect())
    }

    /// Roles for many accounts in a single query, for list endpoints. Accounts without roles
    /// are absent from the map rather than mapped to an empty vector.
    pub async fn roles_for_users(
        &self,
        user_ids: &[Uuid],
    ) -> anyhow::Result<HashMap<Uuid, Vec<RoleName>>> {
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT user_roles.user_id, roles.name FROM user_roles \
             JOIN roles ON roles.id = user_roles.role_id \
             WHERE user_roles.user_id = ANY($1) \
             ORDER BY roles.name",
        )
        .bind(user_ids)
        .fetch_all(&self.database)
        .await?;

        let mut roles: HashMap<Uuid, Vec<RoleName>> = HashMap::new();
        for (user_id, name) in rows {
            roles.entry(user_id).or_default().push(RoleName::new(name));
        }

        Ok(roles)
    }
}
