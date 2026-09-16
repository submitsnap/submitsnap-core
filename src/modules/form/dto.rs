use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::{
    modules::form::{
        model::{FormRecord, FormStatus, SubmissionFilters, SubmissionRecord, SubmissionStatus},
        validation::{FieldDefinition, FormSchema, HONEYPOT_FIELD},
    },
    shared::pagination::page_bounds,
};

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateFormRequest {
    #[validate(length(
        min = 1,
        max = 120,
        message = "name must be between 1 and 120 characters"
    ))]
    #[schema(example = "Contact us")]
    pub name: String,
    pub schema: FormSchema,
    /// Where to notify on each submission. Optional: a form that only collects is legitimate.
    #[serde(default)]
    #[validate(length(max = 20, message = "at most 20 notification addresses"))]
    pub notify_emails: Vec<String>,
}

/// Every field is optional: an absent one is left alone, and sending `null` for one of the
/// nullable strings clears it.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateFormRequest {
    #[serde(default)]
    #[validate(length(
        min = 1,
        max = 120,
        message = "name must be between 1 and 120 characters"
    ))]
    pub name: Option<String>,
    #[serde(default)]
    pub schema: Option<FormSchema>,
    #[serde(default)]
    #[validate(length(max = 20, message = "at most 20 notification addresses"))]
    pub notify_emails: Option<Vec<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub success_message: Option<Option<String>>,
    #[serde(default, deserialize_with = "double_option")]
    pub redirect_url: Option<Option<String>>,
    #[serde(default)]
    pub honeypot_enabled: Option<bool>,
}

/// Distinguishes "not sent" from "sent as null", which serde alone cannot express.
fn double_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Deserialize::deserialize(deserializer).map(Some)
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PaginationQuery {
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<u32>,
    #[param(minimum = 0)]
    pub offset: Option<u32>,
}

impl PaginationQuery {
    pub fn bounds(&self) -> (i64, i64) {
        page_bounds(self.limit, self.offset)
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FormResponse {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub status: FormStatus,
    /// The handle the public endpoint uses. Rotating it invalidates the old link.
    pub public_id: String,
    /// Path of the public form, for a client that needs to build a shareable link.
    pub public_path: String,
    pub schema: FormSchema,
    pub schema_version: i32,
    pub notify_emails: Vec<String>,
    pub success_message: Option<String>,
    pub redirect_url: Option<String>,
    pub honeypot_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub published_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
}

impl From<FormRecord> for FormResponse {
    fn from(form: FormRecord) -> Self {
        Self {
            id: form.id,
            organization_id: form.organization_id,
            name: form.name,
            status: form.status,
            public_path: format!("/f/{}", form.public_id),
            public_id: form.public_id,
            schema: form.schema.0,
            schema_version: form.schema_version,
            notify_emails: form.notify_emails,
            success_message: form.success_message,
            redirect_url: form.redirect_url,
            honeypot_enabled: form.honeypot_enabled,
            created_at: form.created_at,
            updated_at: form.updated_at,
            published_at: form.published_at,
            closed_at: form.closed_at,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FormListResponse {
    pub forms: Vec<FormResponse>,
    pub total: i64,
}

/// What a stranger is allowed to see. Never the organization, never the internal identifiers.
#[derive(Debug, Serialize, ToSchema)]
pub struct PublicFormResponse {
    pub title: String,
    pub description: Option<String>,
    pub submit_label: Option<String>,
    pub fields: Vec<FieldDefinition>,
    /// The field the client should render hidden and leave empty, when honeypot protection is
    /// on. A bot that fills every input fills this one too.
    pub honeypot_field: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SubmissionAcceptedResponse {
    pub id: Uuid,
    pub success_message: Option<String>,
    pub redirect_url: Option<String>,
}

/// What an organization sees of a submission. The provenance columns are deliberately absent:
/// an inbox needs the answers, not the visitor's address.
#[derive(Debug, Serialize, ToSchema)]
pub struct SubmissionResponse {
    pub id: Uuid,
    pub form_id: Uuid,
    /// The field set this submission was written against.
    pub schema_version: i32,
    pub data: serde_json::Value,
    /// Attachment metadata per field key, empty for most submissions. Present so an inbox can
    /// offer a download without a second request per row.
    pub files: serde_json::Value,
    pub status: SubmissionStatus,
    pub created_at: DateTime<Utc>,
}

impl From<SubmissionRecord> for SubmissionResponse {
    fn from(submission: SubmissionRecord) -> Self {
        Self {
            id: submission.id,
            form_id: submission.form_id,
            schema_version: submission.schema_version,
            data: submission.data.0,
            files: submission.files.0,
            status: submission.status,
            created_at: submission.created_at,
        }
    }
}

/// The answer to a completed upload. `key` is what the client sends back as the field's value.
#[derive(Debug, Serialize, ToSchema)]
pub struct UploadedFileResponse {
    pub key: String,
    pub filename: String,
    pub content_type: String,
    pub size: i64,
}

/// Query accepted by the upload route.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UploadQuery {
    /// Shown back to a human, and used in the download header. Never used to build a path, so it
    /// is only sanitised for display, not treated as a location.
    #[serde(default)]
    pub filename: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SubmissionListResponse {
    pub submissions: Vec<SubmissionResponse>,
    pub total: i64,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSubmissionRequest {
    pub status: SubmissionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ExportQuery {
    /// Defaults to CSV.
    pub format: Option<ExportFormat>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SubmissionQuery {
    #[param(minimum = 1, maximum = 100)]
    pub limit: Option<u32>,
    #[param(minimum = 0)]
    pub offset: Option<u32>,
    /// Only meaningful for the organization-wide inbox; the per-form listing takes it from the
    /// path.
    pub form_id: Option<Uuid>,
    pub status: Option<SubmissionStatus>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    /// An answer key to match, together with `value`.
    pub field: Option<String>,
    /// Parsed as JSON when it parses, so a number or a boolean matches its stored type rather
    /// than being compared as a string.
    pub value: Option<String>,
}

impl SubmissionQuery {
    pub fn bounds(&self) -> (i64, i64) {
        page_bounds(self.limit, self.offset)
    }

    /// `form_id` overrides whatever the query string carried, for the routes nested under a
    /// form.
    pub fn filters(&self, form_id: Option<Uuid>) -> SubmissionFilters {
        SubmissionFilters {
            form_id: form_id.or(self.form_id),
            status: self.status,
            since: self.since,
            until: self.until,
            contains: match (self.field.as_deref(), self.value.as_deref()) {
                (Some(field), Some(value)) => Some((
                    field.to_owned(),
                    serde_json::from_str(value)
                        .unwrap_or_else(|_| serde_json::Value::String(value.to_owned())),
                )),
                _ => None,
            },
        }
    }
}

impl PublicFormResponse {
    pub fn new(form: &FormRecord) -> Self {
        Self {
            title: form.schema.0.title.clone(),
            description: form.schema.0.description.clone(),
            submit_label: form.schema.0.submit_label.clone(),
            fields: form.schema.0.fields.clone(),
            honeypot_field: form.honeypot_enabled.then(|| HONEYPOT_FIELD.to_owned()),
        }
    }
}
