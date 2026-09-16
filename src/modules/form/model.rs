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

/// Everything needed to store a submission, gathered before the write so the hot path stays
/// one statement.
pub struct NewSubmission<'a> {
    pub organization_id: Uuid,
    pub form_id: Uuid,
    pub schema_version: i32,
    pub data: &'a serde_json::Value,
    pub status: SubmissionStatus,
    pub ip_address: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub referer: Option<&'a str>,
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
