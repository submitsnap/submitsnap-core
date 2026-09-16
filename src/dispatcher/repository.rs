use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool, types::Json};
use uuid::Uuid;

use crate::modules::{
    form::{SubmissionStatus, validation::FormSchema},
    webhook::WebhookError,
};

/// Everything a notification needs, read in one statement when the event is dispatched.
///
/// The submission is read here rather than copied into the outbox payload, so a long backlog
/// never delivers a stale answer, and the form's current notification settings are the ones
/// that apply.
#[derive(Debug, Clone, FromRow)]
pub struct NotificationSource {
    pub organization_id: Uuid,
    pub form_id: Uuid,
    pub form_name: String,
    pub schema: Json<FormSchema>,
    pub notify_emails: Vec<String>,
    pub submission_id: Uuid,
    pub data: Json<serde_json::Value>,
    pub status: SubmissionStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone)]
pub struct DispatcherRepository {
    database: PgPool,
}

impl DispatcherRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    /// `None` when the submission has since been deleted, which is not an error: there is
    /// simply nothing left to deliver.
    pub async fn notification_source(
        &self,
        submission_id: Uuid,
    ) -> Result<Option<NotificationSource>, WebhookError> {
        sqlx::query_as::<_, NotificationSource>(
            "SELECT f.organization_id, f.id AS form_id, f.name AS form_name, f.schema, \
                    f.notify_emails, s.id AS submission_id, s.data, s.status, s.created_at \
             FROM submissions s JOIN forms f ON f.id = s.form_id \
             WHERE s.id = $1",
        )
        .bind(submission_id)
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }
}
