use sqlx::{PgExecutor, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::modules::organization::{
    error::OrganizationError,
    model::{
        AccessRow, MemberRecord, OrganizationRecord, OrganizationRole, OrganizationSummary,
        OrganizationWithRole,
    },
};

/// Columns for a listing that carries the caller's role and the member count, both resolved in
/// the same query so a page of organizations costs one round trip.
const WITH_ROLE_COLUMNS: &str = "organizations.id, organizations.name, organizations.created_at, \
     organization_members.role, \
     (SELECT count(*) FROM organization_members AS everyone \
      WHERE everyone.organization_id = organizations.id) AS member_count";

const SUMMARY_COLUMNS: &str = "organizations.id, organizations.name, organizations.created_at, \
     (SELECT count(*) FROM organization_members AS everyone \
      WHERE everyone.organization_id = organizations.id) AS member_count";

#[derive(Clone)]
pub struct OrganizationRepository {
    database: PgPool,
}

impl OrganizationRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    /// Creates the organization and its first owner together, so one can never exist without
    /// an owner.
    pub async fn create(
        &self,
        name: &str,
        owner_id: Uuid,
    ) -> Result<OrganizationRecord, OrganizationError> {
        let mut transaction = self.database.begin().await?;

        let organization = sqlx::query_as::<_, OrganizationRecord>(
            "INSERT INTO organizations (name) VALUES ($1) \
             RETURNING id, name, created_at",
        )
        .bind(name)
        .fetch_one(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT INTO organization_members (organization_id, user_id, role) \
             VALUES ($1, $2, 'owner')",
        )
        .bind(organization.id)
        .bind(owner_id)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(organization)
    }

    /// Resolves existence, the caller's role, and the member count in one query. `None` means
    /// the organization does not exist; `Some(row)` with no role means the caller is not a
    /// member.
    pub async fn access(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<AccessRow>, OrganizationError> {
        sqlx::query_as::<_, AccessRow>(
            "SELECT organizations.id, organizations.name, organizations.created_at, \
                    (SELECT count(*) FROM organization_members AS everyone \
                     WHERE everyone.organization_id = organizations.id) AS member_count, \
                    organization_members.role \
             FROM organizations \
             LEFT JOIN organization_members \
                    ON organization_members.organization_id = organizations.id \
                   AND organization_members.user_id = $2 \
             WHERE organizations.id = $1",
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }

    /// Opens a transaction for a membership change, so the last-owner check and the write it
    /// guards cannot be interleaved with another request.
    pub async fn begin(&self) -> Result<Transaction<'static, Postgres>, OrganizationError> {
        Ok(self.database.begin().await?)
    }

    /// Locks the organization for the rest of the transaction.
    ///
    /// This is what makes the last-owner rule hold under concurrency: without it, two requests
    /// each removing a different owner both read "there are two owners", both pass the check,
    /// and the organization is left with none.
    pub async fn lock<'e, E>(&self, executor: E, id: Uuid) -> Result<(), OrganizationError>
    where
        E: PgExecutor<'e>,
    {
        let locked: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(executor)
                .await?;

        locked.map(|_| ()).ok_or(OrganizationError::NotFound)
    }

    pub async fn role_of<'e, E>(
        &self,
        executor: E,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationRole>, OrganizationError>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            "SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2",
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_optional(executor)
        .await
        .map_err(Into::into)
    }

    pub async fn member_of(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<MemberRecord>, OrganizationError> {
        sqlx::query_as::<_, MemberRecord>(
            "SELECT organization_members.user_id, users.email, organization_members.role, \
                    organization_members.created_at AS joined_at \
             FROM organization_members \
             JOIN users ON users.id = organization_members.user_id \
             WHERE organization_members.organization_id = $1 \
               AND organization_members.user_id = $2",
        )
        .bind(organization_id)
        .bind(user_id)
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn list_for_user(
        &self,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OrganizationWithRole>, OrganizationError> {
        sqlx::query_as::<_, OrganizationWithRole>(&format!(
            "SELECT {WITH_ROLE_COLUMNS} \
             FROM organizations \
             JOIN organization_members \
               ON organization_members.organization_id = organizations.id \
              AND organization_members.user_id = $1 \
             ORDER BY organizations.created_at DESC, organizations.id \
             LIMIT $2 OFFSET $3"
        ))
        .bind(user_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn count_for_user(&self, user_id: Uuid) -> Result<i64, OrganizationError> {
        sqlx::query_scalar("SELECT count(*) FROM organization_members WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&self.database)
            .await
            .map_err(Into::into)
    }

    pub async fn rename(&self, id: Uuid, name: &str) -> Result<(), OrganizationError> {
        sqlx::query("UPDATE organizations SET name = $2 WHERE id = $1")
            .bind(id)
            .bind(name)
            .execute(&self.database)
            .await?;

        Ok(())
    }

    /// Removes the organization. Memberships cascade away with it.
    pub async fn delete(&self, id: Uuid) -> Result<bool, OrganizationError> {
        let outcome = sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(id)
            .execute(&self.database)
            .await?;

        Ok(outcome.rows_affected() > 0)
    }

    pub async fn members(
        &self,
        organization_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MemberRecord>, OrganizationError> {
        sqlx::query_as::<_, MemberRecord>(
            "SELECT organization_members.user_id, users.email, organization_members.role, \
                    organization_members.created_at AS joined_at \
             FROM organization_members \
             JOIN users ON users.id = organization_members.user_id \
             WHERE organization_members.organization_id = $1 \
             ORDER BY organization_members.created_at, organization_members.user_id \
             LIMIT $2 OFFSET $3",
        )
        .bind(organization_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn count_members(&self, organization_id: Uuid) -> Result<i64, OrganizationError> {
        sqlx::query_scalar("SELECT count(*) FROM organization_members WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&self.database)
            .await
            .map_err(Into::into)
    }

    /// Adds an account to the organization, or updates its role when it is already a member.
    pub async fn upsert_member<'e, E>(
        &self,
        executor: E,
        organization_id: Uuid,
        user_id: Uuid,
        role: OrganizationRole,
    ) -> Result<(), OrganizationError>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query(
            "INSERT INTO organization_members (organization_id, user_id, role) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role",
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(role)
        .execute(executor)
        .await?;

        Ok(())
    }

    pub async fn remove_member<'e, E>(
        &self,
        executor: E,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, OrganizationError>
    where
        E: PgExecutor<'e>,
    {
        let outcome = sqlx::query(
            "DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(executor)
        .await?;

        Ok(outcome.rows_affected() > 0)
    }

    pub async fn owner_count<'e, E>(
        &self,
        executor: E,
        organization_id: Uuid,
    ) -> Result<i64, OrganizationError>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_scalar(
            "SELECT count(*) FROM organization_members \
             WHERE organization_id = $1 AND role = 'owner'::organization_role",
        )
        .bind(organization_id)
        .fetch_one(executor)
        .await
        .map_err(Into::into)
    }

    pub async fn list_all(
        &self,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OrganizationSummary>, OrganizationError> {
        sqlx::query_as::<_, OrganizationSummary>(&format!(
            "SELECT {SUMMARY_COLUMNS} FROM organizations \
             ORDER BY organizations.created_at DESC, organizations.id \
             LIMIT $1 OFFSET $2"
        ))
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn count_all(&self) -> Result<i64, OrganizationError> {
        sqlx::query_scalar("SELECT count(*) FROM organizations")
            .fetch_one(&self.database)
            .await
            .map_err(Into::into)
    }

    pub async fn summary(
        &self,
        id: Uuid,
    ) -> Result<Option<OrganizationSummary>, OrganizationError> {
        sqlx::query_as::<_, OrganizationSummary>(&format!(
            "SELECT {SUMMARY_COLUMNS} FROM organizations WHERE organizations.id = $1"
        ))
        .bind(id)
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }
}
