//! Form lifecycle and public ingestion.
//!
//! Two things are worth knowing about the shape of this module:
//!
//! * Access is resolved through [`OrganizationService::access`], so a form can never be reached
//!   across tenants and the authorization check is one call rather than a convention.
//! * Public ingestion deliberately does the cheapest checks first and touches the queue not at
//!   all. It is the one path whose latency a stranger feels.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use chrono::Utc;
use futures_util::{StreamExt, stream::BoxStream};
use serde_json::{Map, Value};
use sqlx::PgPool;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;
use validator::ValidateEmail;

use crate::{
    modules::{
        form::{
            dto::{
                CreateFormRequest, ExportFormat, FormResponse, PublicFormResponse,
                SubmissionAcceptedResponse, SubmissionResponse, UpdateFormRequest,
                UploadedFileResponse,
            },
            error::FormError,
            export,
            model::{
                FileUploadRecord, FormRecord, NewFileUpload, NewSubmission, SubmissionFilters,
                SubmissionRecord, SubmissionStatus,
            },
            repository::{FileUploadRepository, FormRepository, SubmissionRepository},
            validation::{
                FieldType, FormSchema, HONEYPOT_FIELD, validate_schema, validate_submission,
            },
        },
        identity::events::{AuthEvent, AuthEventRepository, AuthEventType},
        organization::OrganizationService,
    },
    shared::{
        ratelimit::FormLimiter,
        request::ClientInfo,
        sniff::{SUGGESTED_HEAD_BYTES, sniff},
        storage::{DEFAULT_CONTENT_TYPE, FileStorage, StoredObject},
        tokens::generate_secret_token,
    },
};

/// Bytes on their way into storage, with the error type of whatever transport produced them.
pub type IncomingBytes = BoxStream<'static, Result<Bytes, anyhow::Error>>;

/// Everything needed to serve a download: the object to stream, and the headers that go with it.
pub struct Download {
    pub object: StoredObject,
    pub filename: String,
    pub content_type: String,
}

/// How many abandoned uploads one reaper pass will collect. Bounded so a large backlog is worked
/// through steadily rather than in one long transaction.
const REAP_BATCH: i64 = 200;

/// An export in progress: the rows arrive as they are read, so the caller can start writing
/// immediately.
pub struct ExportStream {
    pub content_type: &'static str,
    pub filename: String,
    pub body: ReceiverStream<Result<Bytes, io::Error>>,
}

#[derive(Clone)]
pub struct FormService {
    database: PgPool,
    forms: FormRepository,
    submissions: SubmissionRepository,
    uploads: FileUploadRepository,
    organizations: Arc<OrganizationService>,
    events: AuthEventRepository,
    per_form_limiter: Arc<FormLimiter>,
    storage: Arc<FileStorage>,
    upload_max_bytes: u64,
    upload_ttl: Duration,
}

impl FormService {
    pub fn new(
        database: PgPool,
        organizations: Arc<OrganizationService>,
        per_form_limiter: Arc<FormLimiter>,
        storage: Arc<FileStorage>,
        upload_max_bytes: u64,
        upload_ttl_hours: u64,
    ) -> Self {
        Self {
            forms: FormRepository::new(database.clone()),
            submissions: SubmissionRepository::new(database.clone()),
            uploads: FileUploadRepository::new(database.clone()),
            organizations,
            events: AuthEventRepository::new(database.clone()),
            per_form_limiter,
            storage,
            upload_max_bytes,
            upload_ttl: Duration::from_secs(upload_ttl_hours * 60 * 60),
            database,
        }
    }

    /// Whether this deployment can accept file answers at all.
    pub fn file_uploads_enabled(&self) -> bool {
        self.storage.is_enabled()
    }

    /// The storage description, for the startup banner and the health output.
    pub fn storage_description(&self) -> String {
        self.storage.describe()
    }

    pub async fn create(
        &self,
        organization_id: Uuid,
        request: &CreateFormRequest,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        // A draft may hold a file field; publishing is what demands storage.
        self.check_schema(&request.schema, false)?;

        let form = self
            .forms
            .create(
                organization_id,
                request.name.trim(),
                &generate_secret_token(),
                &request.schema,
                &request.notify_emails,
            )
            .await?;

        self.audit(
            AuthEventType::FormCreated,
            organization_id,
            actor_id,
            form.id,
            Some(&form.name),
            client,
        )
        .await;

        Ok(form.into())
    }

    pub async fn list(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<FormResponse>, i64), FormError> {
        // Reading only needs membership, which is why the role is not required to be a manager.
        self.organizations.access(organization_id, actor_id).await?;

        let forms = self.forms.list(organization_id, limit, offset).await?;
        let total = self.forms.count(organization_id).await?;

        Ok((forms.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
    ) -> Result<FormResponse, FormError> {
        self.organizations.access(organization_id, actor_id).await?;
        Ok(self.load(organization_id, form_id).await?.into())
    }

    pub async fn update(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        request: &UpdateFormRequest,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let current = self.load(organization_id, form_id).await?;

        let name = match request.name.as_deref() {
            Some(name) => name.trim().to_owned(),
            None => current.name.clone(),
        };
        let schema = request
            .schema
            .clone()
            .unwrap_or_else(|| current.schema.0.clone());
        let notify_emails = request
            .notify_emails
            .clone()
            .unwrap_or_else(|| current.notify_emails.clone());
        let success_message = match &request.success_message {
            Some(value) => value.clone(),
            None => current.success_message.clone(),
        };
        let redirect_url = match &request.redirect_url {
            Some(value) => value.clone(),
            None => current.redirect_url.clone(),
        };
        let honeypot_enabled = request.honeypot_enabled.unwrap_or(current.honeypot_enabled);

        if name.is_empty() || name.chars().count() > 120 {
            return Err(FormError::InvalidSchema(
                "name must be between 1 and 120 characters".to_owned(),
            ));
        }

        // A published form must stay submittable, so the definition is checked on every write
        // and not only at creation.
        self.check_schema(&schema, current.status.accepts_submissions())?;
        check_redirect_url(redirect_url.as_deref())?;
        check_notify_emails(&notify_emails)?;

        let schema_changed = schema.fields != current.schema.0.fields;

        let updated = self
            .forms
            .replace_definition(
                organization_id,
                form_id,
                &name,
                &schema,
                schema_changed,
                &notify_emails,
                success_message.as_deref(),
                redirect_url.as_deref(),
                honeypot_enabled,
            )
            .await?;

        if !updated {
            return Err(FormError::NotFound);
        }

        self.audit(
            AuthEventType::FormUpdated,
            organization_id,
            actor_id,
            form_id,
            Some(&name),
            client,
        )
        .await;

        self.get(organization_id, form_id, actor_id).await
    }

    pub async fn delete(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(), FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let form = self.load(organization_id, form_id).await?;
        if !self.forms.delete(organization_id, form_id).await? {
            return Err(FormError::NotFound);
        }

        self.audit(
            AuthEventType::FormDeleted,
            organization_id,
            actor_id,
            form_id,
            Some(&form.name),
            client,
        )
        .await;

        Ok(())
    }

    pub async fn publish(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let form = self.load(organization_id, form_id).await?;
        // Re-checked here because publishing is the moment a definition starts accepting input.
        self.check_schema(&form.schema.0, true)?;

        self.forms
            .set_status(
                organization_id,
                form_id,
                crate::modules::form::model::FormStatus::Published,
            )
            .await?;

        self.audit(
            AuthEventType::FormPublished,
            organization_id,
            actor_id,
            form_id,
            Some(&form.name),
            client,
        )
        .await;

        self.get(organization_id, form_id, actor_id).await
    }

    pub async fn close(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let form = self.load(organization_id, form_id).await?;
        if !form.status.accepts_submissions() {
            return Err(FormError::InvalidSchema(
                "only a published form can be closed".to_owned(),
            ));
        }

        self.forms
            .set_status(
                organization_id,
                form_id,
                crate::modules::form::model::FormStatus::Closed,
            )
            .await?;

        self.audit(
            AuthEventType::FormClosed,
            organization_id,
            actor_id,
            form_id,
            Some(&form.name),
            client,
        )
        .await;

        self.get(organization_id, form_id, actor_id).await
    }

    /// Issues a new public handle, which instantly invalidates the old link. The answer to a
    /// form being spammed.
    pub async fn rotate_public_id(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<FormResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let form = self.load(organization_id, form_id).await?;
        self.forms
            .set_public_id(organization_id, form_id, &generate_secret_token())
            .await?;

        self.audit(
            AuthEventType::FormPublicIdRotated,
            organization_id,
            actor_id,
            form_id,
            Some(&form.name),
            client,
        )
        .await;

        self.get(organization_id, form_id, actor_id).await
    }

    /// The public definition. A draft answers 404 rather than 403 so an unfinished form is not
    /// discoverable by anybody who happened to guess the link.
    pub async fn public_definition(
        &self,
        public_id: &str,
    ) -> Result<PublicFormResponse, FormError> {
        let form = self.load_published(public_id).await?;
        Ok(PublicFormResponse::new(&form))
    }

    /// The public hot path: resolve, validate, insert. No queue, no audit row, and no second
    /// lookup — the form row needed for validation is the one already fetched.
    pub async fn submit(
        &self,
        public_id: &str,
        payload: &Map<String, Value>,
        client: &ClientInfo,
        referer: Option<&str>,
    ) -> Result<SubmissionAcceptedResponse, FormError> {
        let form = self.load_published(public_id).await?;

        // Keyed by form rather than by caller: a flood aimed at one tenant should not consume
        // anybody else's budget, and a busy form is a legitimate thing.
        if self.per_form_limiter.check_key(&form.id).is_err() {
            return Err(FormError::TooManySubmissions);
        }

        let answers = validate_submission(&form.schema.0, payload)
            .map_err(|problems| FormError::InvalidSubmission(problems.join("; ")))?;

        // A bot that fills every input fills the honeypot too. The submission is accepted as
        // normal so it learns nothing, and filed as spam for the organization to ignore.
        let status = if form.honeypot_enabled && honeypot_was_filled(payload) {
            SubmissionStatus::Spam
        } else {
            SubmissionStatus::Unread
        };

        let data = Value::Object(answers);
        let notify = !form.notify_emails.is_empty();
        let file_answers = file_answers(&form.schema.0, &data);

        // Bound before the struct so the borrow outlives it.
        let ip_address = client.ip_address.map(|address| address.to_string());

        let submission = NewSubmission {
            organization_id: form.organization_id,
            form_id: form.id,
            schema_version: form.schema_version,
            data: &data,
            files: None,
            status,
            ip_address: ip_address.as_deref(),
            user_agent: client.user_agent.as_deref(),
            referer,
            notify,
        };

        // A form with no file answers keeps the single-statement path. Most forms have no files,
        // and they should not pay for the ones that do.
        let id = if file_answers.is_empty() {
            self.submissions.insert(&self.database, submission).await?
        } else {
            self.insert_claiming_files(submission, &file_answers)
                .await?
        };

        Ok(SubmissionAcceptedResponse {
            id,
            success_message: form.success_message,
            redirect_url: form.redirect_url,
        })
    }

    /// Writes a submission and hands it the uploads it refers to, in one transaction.
    ///
    /// The uploads are locked before anything is written, so two submissions racing for the same
    /// file cannot both succeed, and a reference that does not check out rolls the submission
    /// back with it.
    async fn insert_claiming_files(
        &self,
        mut submission: NewSubmission<'_>,
        answers: &[(String, String)],
    ) -> Result<Uuid, FormError> {
        let object_keys: Vec<String> = answers
            .iter()
            .map(|(_, object_key)| object_key.clone())
            .collect();

        let mut transaction = self.database.begin().await?;

        let recorded = self
            .uploads
            .lock_for_claim(&mut *transaction, submission.form_id, &object_keys)
            .await?;
        let metadata = check_file_references(answers, &recorded)?;

        let files = Value::Object(metadata);
        submission.files = Some(&files);

        let id = self
            .submissions
            .insert(&mut *transaction, submission)
            .await?;

        let claimed = self
            .uploads
            .claim(&mut *transaction, id, &object_keys)
            .await?;
        if claimed != object_keys.len() as u64 {
            // The lock makes this unreachable; leaving it as an error rather than a panic means a
            // future change to the query cannot silently attach a file that was already used.
            return Err(FormError::FileRejected(
                "a file was claimed by another submission".to_owned(),
            ));
        }

        transaction.commit().await?;

        Ok(id)
    }

    /// Streams an upload into storage, enforcing the field's rules on the bytes that actually
    /// arrive rather than on what the client says about them.
    ///
    /// This is why uploads travel through the service instead of going straight to the bucket:
    /// a presigned URL would never show us the bytes, so `max_bytes` and `accept` would only ever
    /// validate a claim.
    pub async fn upload(
        &self,
        public_id: &str,
        field_key: &str,
        filename: Option<&str>,
        declared_type: Option<&str>,
        mut body: IncomingBytes,
    ) -> Result<UploadedFileResponse, FormError> {
        if !self.file_uploads_enabled() {
            return Err(FormError::FileUploadsUnavailable);
        }

        let form = self.load_published(public_id).await?;

        // Uploads are at least as abusable as submissions, so they draw on the same budget.
        if self.per_form_limiter.check_key(&form.id).is_err() {
            return Err(FormError::TooManySubmissions);
        }

        let field = form
            .schema
            .0
            .field(field_key)
            .filter(|field| field.field_type == FieldType::File)
            .ok_or_else(|| {
                FormError::FileRejected(format!("{field_key} is not a file field on this form"))
            })?;

        let declared = normalise_content_type(declared_type);
        check_declared_type(field, declared.as_deref())?;

        // A form cannot raise the instance ceiling, only lower it.
        let limit = field
            .max_bytes
            .unwrap_or(self.upload_max_bytes)
            .min(self.upload_max_bytes);
        let object_key = new_object_key(form.organization_id, form.id);
        let filename = clean_filename(filename);

        let mut writer = self.storage.begin_upload(&object_key, limit).await?;
        let mut head = Vec::with_capacity(SUGGESTED_HEAD_BYTES);

        let streamed = stream_upload(
            &mut body,
            &mut writer,
            &mut head,
            declared.as_deref(),
            limit,
        )
        .await;
        let size = match streamed {
            Ok(()) => match writer.finish().await {
                Ok(size) => size,
                Err(error) => return Err(error.into()),
            },
            Err(error) => {
                // A request that failed must leave nothing behind in the bucket.
                writer.abort().await.ok();
                return Err(error);
            }
        };

        let recorded = self
            .uploads
            .insert(NewFileUpload {
                organization_id: form.organization_id,
                form_id: form.id,
                field_key: field_key.to_owned(),
                object_key: object_key.clone(),
                filename: filename.clone(),
                content_type: declared.unwrap_or_else(|| DEFAULT_CONTENT_TYPE.to_owned()),
                size_bytes: size as i64,
            })
            .await;

        let recorded = match recorded {
            Ok(recorded) => recorded,
            Err(error) => {
                // Without a ledger row nothing could ever claim this object, so it would be both
                // unreachable and uncollectable. Remove it instead of leaving it to rot.
                self.storage.delete(&object_key).await.ok();
                return Err(error);
            }
        };

        Ok(UploadedFileResponse {
            key: recorded.object_key,
            filename: recorded.filename,
            content_type: recorded.content_type,
            size: recorded.size_bytes,
        })
    }

    /// Opens the attachment one submission answer refers to, for streaming back to a member.
    ///
    /// The lookup goes through the submission, which is scoped by organization, so the object key
    /// is never taken from the request and a stranger's key is not a capability.
    pub async fn submission_file(
        &self,
        organization_id: Uuid,
        submission_id: Uuid,
        field_key: &str,
        actor_id: Uuid,
    ) -> Result<Download, FormError> {
        if !self.file_uploads_enabled() {
            return Err(FormError::FileUploadsUnavailable);
        }

        self.organizations.access(organization_id, actor_id).await?;
        let submission = self.load_submission(organization_id, submission_id).await?;

        let attachment = submission
            .files
            .0
            .get(field_key)
            .ok_or(FormError::FileMissing)?;

        let object_key = attachment
            .get("key")
            .and_then(Value::as_str)
            .ok_or(FormError::FileMissing)?;
        let filename = attachment
            .get("filename")
            .and_then(Value::as_str)
            .unwrap_or("file");
        let content_type = attachment
            .get("content_type")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_CONTENT_TYPE);

        Ok(Download {
            object: self.storage.open(object_key).await?,
            filename: filename.to_owned(),
            content_type: content_type.to_owned(),
        })
    }

    /// Deletes uploads no submission ever claimed, and the objects behind them.
    ///
    /// Without this an abandoned upload — someone who attached a file and then closed the tab —
    /// would stay in the bucket forever with nothing that could ever find it again.
    ///
    /// Returns how many were collected, so a caller can log a useful line.
    pub async fn reap_abandoned_uploads(&self) -> Result<usize, FormError> {
        if !self.file_uploads_enabled() {
            return Ok(0);
        }

        let cutoff = Utc::now() - chrono::Duration::from_std(self.upload_ttl).unwrap_or_default();
        let abandoned = self.uploads.abandoned(cutoff, REAP_BATCH).await?;

        let mut collected = 0;
        for upload in abandoned {
            // The object first: if that fails the ledger row survives, so the next pass tries
            // again rather than forgetting an object that is still there.
            if let Err(error) = self.storage.delete(&upload.object_key).await {
                tracing::warn!(
                    object_key = %upload.object_key,
                    error = %error,
                    "an abandoned upload could not be removed from storage; it will be retried"
                );
                continue;
            }

            self.uploads.forget(upload.id).await?;
            collected += 1;
        }

        Ok(collected)
    }

    /// How many rows are fetched at a time while an export streams.
    const EXPORT_BATCH: i64 = 500;

    pub async fn list_submissions(
        &self,
        organization_id: Uuid,
        actor_id: Uuid,
        filters: &SubmissionFilters,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<SubmissionResponse>, i64), FormError> {
        // Reading needs membership only.
        self.organizations.access(organization_id, actor_id).await?;

        let submissions = self
            .submissions
            .list(organization_id, filters, limit, offset)
            .await?;
        let total = self.submissions.count(organization_id, filters).await?;

        Ok((submissions.into_iter().map(Into::into).collect(), total))
    }

    pub async fn get_submission(
        &self,
        organization_id: Uuid,
        submission_id: Uuid,
        actor_id: Uuid,
    ) -> Result<SubmissionResponse, FormError> {
        self.organizations.access(organization_id, actor_id).await?;

        Ok(self
            .load_submission(organization_id, submission_id)
            .await?
            .into())
    }

    pub async fn set_submission_status(
        &self,
        organization_id: Uuid,
        submission_id: Uuid,
        status: SubmissionStatus,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<SubmissionResponse, FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        let submission = self.load_submission(organization_id, submission_id).await?;
        if !self
            .submissions
            .set_status(organization_id, submission_id, status)
            .await?
        {
            return Err(FormError::NotFound);
        }

        self.audit(
            AuthEventType::SubmissionStatusChanged,
            organization_id,
            actor_id,
            submission_id,
            Some(&submission.form_id.to_string()),
            client,
        )
        .await;

        self.get_submission(organization_id, submission_id, actor_id)
            .await
    }

    /// Removes a submission. Submissions are personal data, so an organization can always
    /// answer a deletion request without touching the form itself.
    pub async fn delete_submission(
        &self,
        organization_id: Uuid,
        submission_id: Uuid,
        actor_id: Uuid,
        client: &ClientInfo,
    ) -> Result<(), FormError> {
        let access = self.organizations.access(organization_id, actor_id).await?;
        access.require_manager()?;

        if !self
            .submissions
            .delete(organization_id, submission_id)
            .await?
        {
            return Err(FormError::NotFound);
        }

        self.audit(
            AuthEventType::SubmissionDeleted,
            organization_id,
            actor_id,
            submission_id,
            None,
            client,
        )
        .await;

        Ok(())
    }

    /// Opens an export.
    ///
    /// Rows are read in batches and handed to the response as they are formatted, so a large
    /// form does not have to fit in memory. The columns are the form's current fields plus any
    /// key ever stored, so an export written after the definition changed still carries the
    /// answers that no longer have a field.
    pub async fn export(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        actor_id: Uuid,
        format: ExportFormat,
    ) -> Result<ExportStream, FormError> {
        self.organizations.access(organization_id, actor_id).await?;
        let form = self.load(organization_id, form_id).await?;

        let mut columns: Vec<String> = form
            .schema
            .0
            .fields
            .iter()
            .map(|field| field.key.clone())
            .collect();
        for key in self.submissions.distinct_answer_keys(form_id).await? {
            if !columns.contains(&key) {
                columns.push(key);
            }
        }

        let (sender, receiver) = tokio::sync::mpsc::channel(4);
        let submissions = self.submissions.clone();
        tokio::spawn(async move {
            // The opening is sent before any rows are read and the closing after the last one,
            // so an export of an empty form is still well formed: a header with no rows, or
            // `[]` rather than an unterminated fragment.
            let opening = match format {
                ExportFormat::Csv => export::csv_header(&columns),
                ExportFormat::Json => "[".to_owned(),
            };
            if sender.send(Ok(export::bytes(opening))).await.is_err() {
                return;
            }

            let mut after = None;
            let mut first_row = true;

            loop {
                let batch = match submissions
                    .page_after(form_id, after, FormService::EXPORT_BATCH)
                    .await
                {
                    Ok(batch) => batch,
                    Err(error) => {
                        let _ = sender.send(Err(io::Error::other(error.to_string()))).await;
                        return;
                    }
                };

                if batch.is_empty() {
                    break;
                }

                after = batch.last().map(|row| (row.created_at, row.id));

                let mut text = String::new();
                for submission in &batch {
                    match format {
                        ExportFormat::Csv => text.push_str(&export::csv_row(&columns, submission)),
                        ExportFormat::Json => {
                            let separator = if first_row { "" } else { "," };
                            text.push_str(&export::json_row(submission, separator));
                        }
                    }
                    first_row = false;
                }

                if sender.send(Ok(export::bytes(text))).await.is_err() {
                    // The client went away; stop reading.
                    return;
                }
            }

            if format == ExportFormat::Json {
                let _ = sender.send(Ok(export::bytes("]".to_owned()))).await;
            }
        });

        Ok(ExportStream {
            content_type: match format {
                ExportFormat::Csv => "text/csv; charset=utf-8",
                ExportFormat::Json => "application/json; charset=utf-8",
            },
            filename: format!(
                "{}-submissions.{}",
                form.name,
                match format {
                    ExportFormat::Csv => "csv",
                    ExportFormat::Json => "json",
                }
            ),
            body: ReceiverStream::new(receiver),
        })
    }

    async fn load_submission(
        &self,
        organization_id: Uuid,
        submission_id: Uuid,
    ) -> Result<SubmissionRecord, FormError> {
        self.submissions
            .find(organization_id, submission_id)
            .await?
            .ok_or(FormError::NotFound)
    }

    async fn load(&self, organization_id: Uuid, form_id: Uuid) -> Result<FormRecord, FormError> {
        self.forms
            .find(organization_id, form_id)
            .await?
            .ok_or(FormError::NotFound)
    }

    /// Resolves a public handle, refusing the states that must not accept submissions. Draft is
    /// reported as missing on purpose; only a closed form explains itself.
    async fn load_published(&self, public_id: &str) -> Result<FormRecord, FormError> {
        let form = self
            .forms
            .find_by_public_id(public_id)
            .await?
            .ok_or(FormError::NotFound)?;

        match form.status {
            crate::modules::form::model::FormStatus::Published => Ok(form),
            crate::modules::form::model::FormStatus::Draft => Err(FormError::NotFound),
            crate::modules::form::model::FormStatus::Closed => Err(FormError::Closed),
        }
    }

    /// A definition is checked on every write, so a stored form is always renderable and always
    /// submittable.
    fn check_schema(
        &self,
        schema: &FormSchema,
        require_submittable: bool,
    ) -> Result<(), FormError> {
        validate_schema(schema)
            .map_err(|problems| FormError::InvalidSchema(problems.join("; ")))?;

        if require_submittable && schema.has_file_field() && !self.file_uploads_enabled() {
            return Err(FormError::FileUploadsUnavailable);
        }

        Ok(())
    }

    async fn audit(
        &self,
        event_type: AuthEventType,
        organization_id: Uuid,
        actor_id: Uuid,
        target_id: Uuid,
        label: Option<&str>,
        client: &ClientInfo,
    ) {
        self.events
            .record(AuthEvent {
                user_id: None,
                actor_user_id: Some(actor_id),
                organization_id: Some(organization_id),
                target_id: Some(target_id),
                email: label,
                event_type,
                ip_address: client.ip_address,
                user_agent: client.user_agent.as_deref(),
            })
            .await;
    }
}

fn honeypot_was_filled(payload: &Map<String, Value>) -> bool {
    payload
        .get(HONEYPOT_FIELD)
        .map(|value| match value {
            Value::Null => false,
            Value::String(text) => !text.trim().is_empty(),
            _ => true,
        })
        .unwrap_or(false)
}

/// The file answers in a validated payload, as (field key, object key) pairs.
fn file_answers(schema: &FormSchema, data: &Value) -> Vec<(String, String)> {
    let Some(answers) = data.as_object() else {
        return Vec::new();
    };

    schema
        .fields
        .iter()
        .filter(|field| field.field_type == FieldType::File)
        .filter_map(|field| {
            answers
                .get(&field.key)
                .and_then(Value::as_str)
                .map(|object_key| (field.key.clone(), object_key.to_owned()))
        })
        .collect()
}

/// Matches each file answer against the upload ledger.
///
/// A key this server never issued for this form and this field is either a mistake or an attempt
/// to attach somebody else's file, so it is refused rather than stored.
fn check_file_references(
    answers: &[(String, String)],
    recorded: &[FileUploadRecord],
) -> Result<Map<String, Value>, FormError> {
    let mut metadata = Map::with_capacity(answers.len());

    for (field_key, object_key) in answers {
        let Some(upload) = recorded
            .iter()
            .find(|upload| &upload.object_key == object_key)
        else {
            return Err(FormError::FileRejected(format!(
                "{field_key} refers to a file this form did not receive"
            )));
        };

        if upload.submission_id.is_some() {
            return Err(FormError::FileRejected(format!(
                "{field_key} refers to a file another submission already used"
            )));
        }

        if &upload.field_key != field_key {
            return Err(FormError::FileRejected(format!(
                "{field_key} refers to a file uploaded for a different field"
            )));
        }

        metadata.insert(field_key.clone(), upload.metadata());
    }

    Ok(metadata)
}

/// Pumps the request body into storage, checking the size and the leading bytes as they arrive.
async fn stream_upload(
    body: &mut IncomingBytes,
    writer: &mut crate::shared::storage::UploadWriter,
    head: &mut Vec<u8>,
    declared: Option<&str>,
    limit: u64,
) -> Result<(), FormError> {
    let mut inspected = false;

    while let Some(chunk) = body.next().await {
        let chunk = chunk.map_err(|error| {
            // The route's transport limit is an outer backstop. Reaching it means the counter in
            // `write` should have refused first, so report it for what it is rather than as an
            // internal failure.
            if writer.written() >= limit {
                FormError::FileTooLarge { limit }
            } else {
                FormError::Internal(error.context("reading the upload"))
            }
        })?;

        if head.len() < SUGGESTED_HEAD_BYTES {
            let take = (SUGGESTED_HEAD_BYTES - head.len()).min(chunk.len());
            head.extend_from_slice(&chunk[..take]);
        }

        writer.write(&chunk).await?;

        // Inspected as soon as there is enough to decide, so a rejected file is not written out
        // to the bucket in full first.
        if !inspected && head.len() >= SUGGESTED_HEAD_BYTES {
            check_bytes(head, declared)?;
            inspected = true;
        }
    }

    // A file shorter than the head buffer can only be inspected now that the stream has ended.
    if !inspected {
        check_bytes(head, declared)?;
    }

    Ok(())
}

/// Refuses bytes that contradict the media type the client declared.
fn check_bytes(head: &[u8], declared: Option<&str>) -> Result<(), FormError> {
    let Some(declared) = declared else {
        return Ok(());
    };

    if sniff(head).is_consistent_with(declared) {
        return Ok(());
    }

    Err(FormError::FileRejected(format!(
        "the contents do not look like {declared}"
    )))
}

/// The declared type has to be one the field accepts. This is what makes `accept` mean something;
/// the signature check only confirms the bytes agree with what was declared.
fn check_declared_type(
    field: &crate::modules::form::validation::FieldDefinition,
    declared: Option<&str>,
) -> Result<(), FormError> {
    let Some(declared) = declared else {
        return Err(FormError::FileRejected(
            "a Content-Type header is required so the file can be checked against the field"
                .to_owned(),
        ));
    };

    if field.accepts(declared) {
        return Ok(());
    }

    Err(FormError::FileRejected(format!(
        "{} does not accept {declared}",
        field.key
    )))
}

/// Lower-cases a declared media type and drops any parameters.
fn normalise_content_type(raw: Option<&str>) -> Option<String> {
    let raw = raw?.split(';').next().unwrap_or_default().trim();

    (!raw.is_empty()).then(|| raw.to_ascii_lowercase())
}

/// Object keys are generated here and never taken from the client, which is what makes a path
/// traversal impossible rather than merely filtered out.
fn new_object_key(organization_id: Uuid, form_id: Uuid) -> String {
    format!(
        "{organization_id}/{form_id}/{}",
        crate::shared::tokens::generate_secret_token()
    )
}

/// A filename is shown to a human and echoed in a `Content-Disposition` header. It never builds a
/// path, so the only goals are keeping it single-line, free of path structure, and short.
fn clean_filename(raw: Option<&str>) -> String {
    let base = raw
        .unwrap_or_default()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default()
        .trim();

    let cleaned: String = base
        .chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect();

    if cleaned.is_empty() {
        "file".to_owned()
    } else {
        cleaned
    }
}

fn check_notify_emails(emails: &[String]) -> Result<(), FormError> {
    if emails.len() > 20 {
        return Err(FormError::InvalidSchema(
            "at most 20 notification addresses".to_owned(),
        ));
    }
    if let Some(bad) = emails.iter().find(|email| !email.validate_email()) {
        return Err(FormError::InvalidSchema(format!(
            "{bad} is not a valid email address"
        )));
    }

    Ok(())
}

fn check_redirect_url(url: Option<&str>) -> Result<(), FormError> {
    let Some(url) = url else {
        return Ok(());
    };
    if !url.starts_with("https://") && !url.starts_with("http://") {
        return Err(FormError::InvalidSchema(
            "redirect_url must be an http or https address".to_owned(),
        ));
    }

    Ok(())
}
