use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, types::Json};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::modules::form::validation::FormSchema;

/// Columns selected whenever a full form row is loaded.
pub const FORM_COLUMNS: &str = "id, organization_id, name, status, public_id, schema, \
     schema_version, notify_emails, success_message, redirect_url, honeypot_enabled, \
     created_at, updated_at, published_at, closed_at";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "form_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum FormStatus {
    /// Being written. Its public handle exists but answers 404, so an unfinished form is not
    /// discoverable even by somebody who guessed the link.
    Draft,
    Published,
    Closed,
}

impl FormStatus {
    pub fn accepts_submissions(self) -> bool {
        matches!(self, Self::Published)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(type_name = "submission_status", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SubmissionStatus {
    Unread,
    Read,
    Spam,
    Archived,
}

#[derive(Debug, Clone, FromRow)]
pub struct FormRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub status: FormStatus,
    pub public_id: String,
    pub schema: Json<FormSchema>,
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

/// Columns selected whenever a submission is loaded.
pub const SUBMISSION_COLUMNS: &str =
    "id, organization_id, form_id, schema_version, data, files, status, created_at";

#[derive(Debug, Clone, FromRow)]
pub struct SubmissionRecord {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub form_id: Uuid,
    pub schema_version: i32,
    pub data: Json<serde_json::Value>,
    /// Attachment metadata per field key. Empty for the many submissions that carry no files.
    pub files: Json<serde_json::Value>,
    pub status: SubmissionStatus,
    pub created_at: DateTime<Utc>,
}

/// Columns selected whenever a pending upload is loaded.
pub const FILE_UPLOAD_COLUMNS: &str =
    "id, field_key, object_key, filename, content_type, size_bytes, submission_id";

/// An upload that has been written to the bucket but not yet claimed by a submission.
#[derive(Debug, Clone, FromRow)]
pub struct FileUploadRecord {
    pub id: Uuid,
    pub field_key: String,
    pub object_key: String,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    pub submission_id: Option<Uuid>,
}

pub struct NewFileUpload {
    pub organization_id: Uuid,
    pub form_id: Uuid,
    pub field_key: String,
    pub object_key: String,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
}

impl FileUploadRecord {
    /// The shape stored in `submissions.files`. Enough to render a download link and to explain
    /// what was attached, without another lookup.
    pub fn metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "key": self.object_key,
            "filename": self.filename,
            "content_type": self.content_type,
            "size": self.size_bytes,
        })
    }
}

/// Narrowing applied when reading the inbox. `None` means "do not filter on this".
#[derive(Debug, Clone, Default)]
pub struct SubmissionFilters {
    pub form_id: Option<Uuid>,
    pub status: Option<SubmissionStatus>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    /// One `jsonb_build_object(key, value)` term. Containment is the question the GIN index on
    /// `data` answers, which is what makes filtering by an arbitrary field key cheap.
    pub contains: Option<(String, serde_json::Value)>,
}

/// Everything needed to store a submission, gathered before the write so the hot path stays
/// one statement.
pub struct NewSubmission<'a> {
    pub organization_id: Uuid,
    pub form_id: Uuid,
    pub schema_version: i32,
    pub data: &'a serde_json::Value,
    /// Attachment metadata, or `None` for a submission with no file answers. `None` and an empty
    /// object mean the same thing in the database; `None` is what keeps the common insert cheap.
    pub files: Option<&'a serde_json::Value>,
    pub status: SubmissionStatus,
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub referer: Option<&'a str>,
    /// Whether an address should be told about this submission.
    pub notify: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_published_form_accepts_submissions() {
        assert!(FormStatus::Published.accepts_submissions());
        assert!(!FormStatus::Draft.accepts_submissions());
        assert!(!FormStatus::Closed.accepts_submissions());
    }
}
