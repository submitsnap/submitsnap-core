use std::collections::HashMap;

use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use crate::modules::rbac::{RoleName, model::ADMIN_ROLE};

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

    /// Every role this deployment defines, for validating operator input before it is applied.
    pub async fn role_names(&self) -> anyhow::Result<Vec<RoleName>> {
        let names: Vec<String> = sqlx::query_scalar("SELECT name FROM roles ORDER BY name")
            .fetch_all(&self.database)
            .await?;

        Ok(names.into_iter().map(RoleName::new).collect())
    }

    /// Replaces an account's role set with exactly `roles`.
    ///
    /// A single statement, so it is atomic without a caller-managed transaction. The delete
    /// and the insert touch disjoint rows, which is why they can share one statement safely.
    pub async fn replace_for_user(&self, user_id: Uuid, roles: &[RoleName]) -> anyhow::Result<()> {
        let names: Vec<&str> = roles.iter().map(RoleName::as_str).collect();

        sqlx::query(
            "WITH desired AS (SELECT id FROM roles WHERE name = ANY($2)), \
                  removed AS ( \
                      DELETE FROM user_roles \
                      WHERE user_id = $1 AND role_id NOT IN (SELECT id FROM desired) \
                  ) \
             INSERT INTO user_roles (user_id, role_id) \
             SELECT $1, id FROM desired \
             ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(&names)
        .execute(&self.database)
        .await?;

        Ok(())
    }

    /// Accounts that both hold the administrator role and can still sign in. Any change that
    /// would empty this list is refused, so an instance cannot be left unadministrable.
    pub async fn active_admin_ids(&self) -> anyhow::Result<Vec<Uuid>> {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT users.id FROM users \
             JOIN user_roles ON user_roles.user_id = users.id \
             JOIN roles ON roles.id = user_roles.role_id \
             WHERE roles.name = $1 AND users.status = 'active'::user_status \
             ORDER BY users.id",
        )
        .bind(ADMIN_ROLE)
        .fetch_all(&self.database)
        .await?;

        Ok(ids)
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
