use sqlx::PgPool;
use uuid::Uuid;

use crate::modules::form::{
    error::FormError,
    model::{FORM_COLUMNS, FormRecord, FormStatus, NewSubmission},
    validation::FormSchema,
};

#[derive(Clone)]
pub struct FormRepository {
    database: PgPool,
}

impl FormRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    pub async fn create(
        &self,
        organization_id: Uuid,
        name: &str,
        public_id: &str,
        schema: &FormSchema,
    ) -> Result<FormRecord, FormError> {
        sqlx::query_as::<_, FormRecord>(&format!(
            "INSERT INTO forms (organization_id, name, public_id, schema) \
             VALUES ($1, $2, $3, $4) RETURNING {FORM_COLUMNS}"
        ))
        .bind(organization_id)
        .bind(name)
        .bind(public_id)
        .bind(sqlx::types::Json(schema))
        .fetch_one(&self.database)
        .await
        .map_err(Into::into)
    }

    /// Every lookup is scoped by organization, so a form id from one tenant can never reach
    /// another tenant's row.
    pub async fn find(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> Result<Option<FormRecord>, FormError> {
        sqlx::query_as::<_, FormRecord>(&format!(
            "SELECT {FORM_COLUMNS} FROM forms WHERE organization_id = $1 AND id = $2"
        ))
        .bind(organization_id)
        .bind(id)
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }

    /// The public ingestion path, resolved by the only identifier a stranger has.
    pub async fn find_by_public_id(
        &self,
        public_id: &str,
    ) -> Result<Option<FormRecord>, FormError> {
        sqlx::query_as::<_, FormRecord>(&format!(
            "SELECT {FORM_COLUMNS} FROM forms WHERE public_id = $1"
        ))
        .bind(public_id)
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn list(
        &self,
        organization_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<FormRecord>, FormError> {
        sqlx::query_as::<_, FormRecord>(&format!(
            "SELECT {FORM_COLUMNS} FROM forms WHERE organization_id = $1 \
             ORDER BY created_at DESC, id LIMIT $2 OFFSET $3"
        ))
        .bind(organization_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn count(&self, organization_id: Uuid) -> Result<i64, FormError> {
        sqlx::query_scalar("SELECT count(*) FROM forms WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&self.database)
            .await
            .map_err(Into::into)
    }

    /// Replaces the whole editable definition in one statement.
    #[allow(clippy::too_many_arguments)]
    pub async fn replace_definition(
        &self,
        organization_id: Uuid,
        id: Uuid,
        name: &str,
        schema: &FormSchema,
        schema_changed: bool,
        notify_emails: &[String],
        success_message: Option<&str>,
        redirect_url: Option<&str>,
        honeypot_enabled: bool,
    ) -> Result<bool, FormError> {
        let outcome = sqlx::query(
            "UPDATE forms SET \
                 name = $3, \
                 schema = $4, \
                 schema_version = CASE WHEN $5 THEN schema_version + 1 ELSE schema_version END, \
                 notify_emails = $6, \
                 success_message = $7, \
                 redirect_url = $8, \
                 honeypot_enabled = $9 \
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(id)
        .bind(name)
        .bind(sqlx::types::Json(schema))
        .bind(schema_changed)
        .bind(notify_emails)
        .bind(success_message)
        .bind(redirect_url)
        .bind(honeypot_enabled)
        .execute(&self.database)
        .await?;

        Ok(outcome.rows_affected() > 0)
    }

    pub async fn set_status(
        &self,
        organization_id: Uuid,
        id: Uuid,
        status: FormStatus,
    ) -> Result<bool, FormError> {
        let outcome = sqlx::query(
            "UPDATE forms SET \
                 status = $3, \
                 published_at = CASE WHEN $3 = 'published'::form_status THEN NOW() \
                                     ELSE published_at END, \
                 closed_at = CASE WHEN $3 = 'closed'::form_status THEN NOW() ELSE closed_at END \
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(id)
        .bind(status)
        .execute(&self.database)
        .await?;

        Ok(outcome.rows_affected() > 0)
    }

    pub async fn set_public_id(
        &self,
        organization_id: Uuid,
        id: Uuid,
        public_id: &str,
    ) -> Result<bool, FormError> {
        let outcome =
            sqlx::query("UPDATE forms SET public_id = $3 WHERE organization_id = $1 AND id = $2")
                .bind(organization_id)
                .bind(id)
                .bind(public_id)
                .execute(&self.database)
                .await?;

        Ok(outcome.rows_affected() > 0)
    }

    pub async fn delete(&self, organization_id: Uuid, id: Uuid) -> Result<bool, FormError> {
        let outcome = sqlx::query("DELETE FROM forms WHERE organization_id = $1 AND id = $2")
            .bind(organization_id)
            .bind(id)
            .execute(&self.database)
            .await?;

        Ok(outcome.rows_affected() > 0)
    }
}

#[derive(Clone)]
pub struct SubmissionRepository {
    database: PgPool,
}

impl SubmissionRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    /// The public hot path: one statement, no generated columns, no extra round trips.
    pub async fn insert(&self, submission: NewSubmission<'_>) -> Result<Uuid, FormError> {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO submissions \
                 (organization_id, form_id, schema_version, data, status, ip_address, user_agent, referer) \
             VALUES ($1, $2, $3, $4, $5, $6::inet, $7, $8) \
             RETURNING id",
        )
        .bind(submission.organization_id)
        .bind(submission.form_id)
        .bind(submission.schema_version)
        .bind(sqlx::types::Json(submission.data))
        .bind(submission.status)
        .bind(submission.ip_address)
        .bind(submission.user_agent)
        .bind(submission.referer)
        .fetch_one(&self.database)
        .await?;

        Ok(id)
    }
}
