use chrono::{DateTime, Utc};
use sqlx::{PgExecutor, PgPool};
use uuid::Uuid;

use crate::modules::form::{
    error::FormError,
    model::{
        FILE_UPLOAD_COLUMNS, FORM_COLUMNS, FileUploadRecord, FormRecord, FormStatus, NewFileUpload,
        NewSubmission, SUBMISSION_COLUMNS, SubmissionFilters, SubmissionRecord, SubmissionStatus,
    },
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
        notify_emails: &[String],
    ) -> Result<FormRecord, FormError> {
        sqlx::query_as::<_, FormRecord>(&format!(
            "INSERT INTO forms (organization_id, name, public_id, schema, notify_emails) \
             VALUES ($1, $2, $3, $4, $5) RETURNING {FORM_COLUMNS}"
        ))
        .bind(organization_id)
        .bind(name)
        .bind(public_id)
        .bind(sqlx::types::Json(schema))
        .bind(notify_emails)
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

    /// The public hot path, and the only write that matters for latency: one statement, which
    /// also decides whether anything needs to happen next.
    ///
    /// The outbox row is written by the *same* statement as the submission, so the two cannot
    /// disagree and no extra round trip is spent. It is skipped entirely when the form has no
    /// notification address and the organization has no webhook that would match — a condition
    /// the database can evaluate without a second query.
    ///
    /// Accepts any executor so a submission carrying files can be written inside the same
    /// transaction that claims those files. The common case passes the pool.
    pub async fn insert<'e, E>(
        &self,
        executor: E,
        submission: NewSubmission<'_>,
    ) -> Result<Uuid, FormError>
    where
        E: PgExecutor<'e>,
    {
        let id: Uuid = sqlx::query_scalar(
            "WITH stored AS ( \
                 INSERT INTO submissions \
                     (organization_id, form_id, schema_version, data, files, status, \
                      ip_address, user_agent, referer) \
                 VALUES ($1, $2, $3, $4, COALESCE($10::jsonb, '{}'::jsonb), $5, $6::inet, $7, $8) \
                 RETURNING id, organization_id, form_id \
             ), queued AS ( \
                 INSERT INTO outbox_events (organization_id, kind, payload) \
                 SELECT stored.organization_id, 'submission_received', \
                        jsonb_build_object('submission_id', stored.id, 'form_id', stored.form_id) \
                 FROM stored \
                 WHERE $9::boolean \
                    OR EXISTS ( \
                        SELECT 1 FROM webhook_endpoints \
                        WHERE organization_id = stored.organization_id \
                          AND enabled \
                          AND (form_id IS NULL OR form_id = stored.form_id) \
                    ) \
             ) \
             SELECT id FROM stored",
        )
        .bind(submission.organization_id)
        .bind(submission.form_id)
        .bind(submission.schema_version)
        .bind(sqlx::types::Json(submission.data))
        .bind(submission.status)
        .bind(submission.ip_address)
        .bind(submission.user_agent)
        .bind(submission.referer)
        .bind(submission.notify)
        .bind(submission.files.map(sqlx::types::Json))
        .fetch_one(executor)
        .await?;

        Ok(id)
    }

    pub async fn find(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> Result<Option<SubmissionRecord>, FormError> {
        sqlx::query_as::<_, SubmissionRecord>(&format!(
            "SELECT {SUBMISSION_COLUMNS} FROM submissions \
             WHERE organization_id = $1 AND id = $2"
        ))
        .bind(organization_id)
        .bind(id)
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn list(
        &self,
        organization_id: Uuid,
        filters: &SubmissionFilters,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SubmissionRecord>, FormError> {
        sqlx::query_as::<_, SubmissionRecord>(&format!(
            "SELECT {SUBMISSION_COLUMNS} FROM submissions \
             WHERE organization_id = $1 {SUBMISSION_FILTERS} \
             ORDER BY created_at DESC, id DESC LIMIT $8 OFFSET $9"
        ))
        .bind(organization_id)
        .bind(filters.form_id)
        .bind(filters.status)
        .bind(filters.since)
        .bind(filters.until)
        .bind(filters.contains.as_ref().map(|(key, _)| key.clone()))
        .bind(
            filters
                .contains
                .as_ref()
                .map(|(_, value)| sqlx::types::Json(value)),
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn count(
        &self,
        organization_id: Uuid,
        filters: &SubmissionFilters,
    ) -> Result<i64, FormError> {
        sqlx::query_scalar(&format!(
            "SELECT count(*) FROM submissions \
             WHERE organization_id = $1 {SUBMISSION_FILTERS}"
        ))
        .bind(organization_id)
        .bind(filters.form_id)
        .bind(filters.status)
        .bind(filters.since)
        .bind(filters.until)
        .bind(filters.contains.as_ref().map(|(key, _)| key.clone()))
        .bind(
            filters
                .contains
                .as_ref()
                .map(|(_, value)| sqlx::types::Json(value)),
        )
        .fetch_one(&self.database)
        .await
        .map_err(Into::into)
    }

    /// Keyset pagination for the export.
    ///
    /// `OFFSET` would rescan everything already sent, so each page instead continues after the
    /// last row it saw. One index scan, whatever the size of the export.
    pub async fn page_after(
        &self,
        form_id: Uuid,
        after: Option<(chrono::DateTime<chrono::Utc>, Uuid)>,
        limit: i64,
    ) -> Result<Vec<SubmissionRecord>, FormError> {
        sqlx::query_as::<_, SubmissionRecord>(&format!(
            "SELECT {SUBMISSION_COLUMNS} FROM submissions \
             WHERE form_id = $1 \
               AND ($2::timestamptz IS NULL OR (created_at, id) > ($2, $3)) \
             ORDER BY created_at, id LIMIT $4"
        ))
        .bind(form_id)
        .bind(after.map(|(created_at, _)| created_at))
        .bind(after.map(|(_, id)| id))
        .bind(limit)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    /// Every answer key ever stored for this form, so an export written after the definition
    /// changed keeps the columns it used to have.
    pub async fn distinct_answer_keys(&self, form_id: Uuid) -> Result<Vec<String>, FormError> {
        sqlx::query_scalar(
            "SELECT DISTINCT jsonb_object_keys(data) AS key FROM submissions WHERE form_id = $1",
        )
        .bind(form_id)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn set_status(
        &self,
        organization_id: Uuid,
        id: Uuid,
        status: SubmissionStatus,
    ) -> Result<bool, FormError> {
        let outcome = sqlx::query(
            "UPDATE submissions SET status = $3 WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(id)
        .bind(status)
        .execute(&self.database)
        .await?;

        Ok(outcome.rows_affected() > 0)
    }

    pub async fn delete(&self, organization_id: Uuid, id: Uuid) -> Result<bool, FormError> {
        let outcome = sqlx::query("DELETE FROM submissions WHERE organization_id = $1 AND id = $2")
            .bind(organization_id)
            .bind(id)
            .execute(&self.database)
            .await?;

        Ok(outcome.rows_affected() > 0)
    }
}

/// Shared `WHERE` for the inbox queries. Every branch is `NULL`-tolerant, so one statement
/// serves filtered and unfiltered reads alike, and `data @>` is the question the GIN index
/// answers.
const SUBMISSION_FILTERS: &str = "AND ($2::uuid IS NULL OR form_id = $2) \
     AND ($3::submission_status IS NULL OR status = $3) \
     AND ($4::timestamptz IS NULL OR created_at >= $4) \
     AND ($5::timestamptz IS NULL OR created_at < $5) \
     AND ($6::text IS NULL OR data @> jsonb_build_object($6, $7::jsonb))";

/// The upload ledger: what has been written to the bucket and not yet accounted for.
///
/// It exists for two reasons that a bucket listing cannot serve. Ingestion needs to tell a key
/// this server really issued from a string somebody typed, and abandoned uploads have to be
/// findable again so they can be deleted rather than accumulating forever.
#[derive(Clone)]
pub struct FileUploadRepository {
    database: PgPool,
}

impl FileUploadRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    pub async fn insert(&self, upload: NewFileUpload) -> Result<FileUploadRecord, FormError> {
        sqlx::query_as::<_, FileUploadRecord>(&format!(
            "INSERT INTO file_uploads \
                 (organization_id, form_id, field_key, object_key, filename, content_type, \
                  size_bytes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {FILE_UPLOAD_COLUMNS}"
        ))
        .bind(upload.organization_id)
        .bind(upload.form_id)
        .bind(upload.field_key)
        .bind(upload.object_key)
        .bind(upload.filename)
        .bind(upload.content_type)
        .bind(upload.size_bytes)
        .fetch_one(&self.database)
        .await
        .map_err(Into::into)
    }

    /// The ledger rows these object keys name, locked for the rest of the transaction.
    ///
    /// The lock is what stops two submissions claiming one upload: the second waits here, and
    /// then finds the row already claimed. Filtering by `form_id` is what makes a key from another
    /// form — or another tenant — simply not found.
    pub async fn lock_for_claim<'e, E>(
        &self,
        executor: E,
        form_id: Uuid,
        object_keys: &[String],
    ) -> Result<Vec<FileUploadRecord>, FormError>
    where
        E: PgExecutor<'e>,
    {
        sqlx::query_as::<_, FileUploadRecord>(&format!(
            "SELECT {FILE_UPLOAD_COLUMNS} FROM file_uploads \
             WHERE form_id = $1 AND object_key = ANY($2) \
             ORDER BY object_key FOR UPDATE"
        ))
        .bind(form_id)
        .bind(object_keys)
        .fetch_all(executor)
        .await
        .map_err(Into::into)
    }

    pub async fn claim<'e, E>(
        &self,
        executor: E,
        submission_id: Uuid,
        object_keys: &[String],
    ) -> Result<u64, FormError>
    where
        E: PgExecutor<'e>,
    {
        let outcome = sqlx::query(
            "UPDATE file_uploads SET submission_id = $1 \
             WHERE object_key = ANY($2) AND submission_id IS NULL",
        )
        .bind(submission_id)
        .bind(object_keys)
        .execute(executor)
        .await?;

        Ok(outcome.rows_affected())
    }

    /// Uploads no submission ever claimed, oldest first. The reaper's work list.
    ///
    /// `submission_id IS NULL` is the whole predicate: a row loses its submission when that
    /// submission is deleted, so an attachment of a deleted submission is collected here too.
    pub async fn abandoned(
        &self,
        older_than: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<FileUploadRecord>, FormError> {
        sqlx::query_as::<_, FileUploadRecord>(&format!(
            "SELECT {FILE_UPLOAD_COLUMNS} FROM file_uploads \
             WHERE submission_id IS NULL AND created_at < $1 \
             ORDER BY created_at LIMIT $2"
        ))
        .bind(older_than)
        .bind(limit)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn forget(&self, id: Uuid) -> Result<(), FormError> {
        sqlx::query("DELETE FROM file_uploads WHERE id = $1")
            .bind(id)
            .execute(&self.database)
            .await?;

        Ok(())
    }
}
