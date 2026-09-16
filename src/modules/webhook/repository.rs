use sqlx::PgPool;
use uuid::Uuid;

use crate::modules::webhook::{
    error::WebhookError,
    model::{
        ClaimedDelivery, DELIVERY_COLUMNS, DeliveryFilters, ENDPOINT_COLUMNS,
        WebhookDeliveryRecord, WebhookEndpointRecord,
    },
};

#[derive(Clone)]
pub struct WebhookRepository {
    database: PgPool,
}

/// The mutable fields of an endpoint. `None` leaves the current value alone; the repository
/// merges against the stored row so a partial update cannot silently clear something.
#[derive(Debug, Default)]
pub struct EndpointChanges<'a> {
    pub url: Option<&'a str>,
    pub description: Option<Option<&'a str>>,
    pub enabled: Option<bool>,
    pub form_id: Option<Option<Uuid>>,
}

impl WebhookRepository {
    pub fn new(database: PgPool) -> Self {
        Self { database }
    }

    pub async fn create_endpoint(
        &self,
        organization_id: Uuid,
        form_id: Option<Uuid>,
        url: &str,
        secret: &str,
        description: Option<&str>,
    ) -> Result<WebhookEndpointRecord, WebhookError> {
        sqlx::query_as::<_, WebhookEndpointRecord>(&format!(
            "INSERT INTO webhook_endpoints (organization_id, form_id, url, secret, description) \
             VALUES ($1, $2, $3, $4, $5) RETURNING {ENDPOINT_COLUMNS}"
        ))
        .bind(organization_id)
        .bind(form_id)
        .bind(url)
        .bind(secret)
        .bind(description)
        .fetch_one(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn find_endpoint(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> Result<Option<WebhookEndpointRecord>, WebhookError> {
        sqlx::query_as::<_, WebhookEndpointRecord>(&format!(
            "SELECT {ENDPOINT_COLUMNS} FROM webhook_endpoints \
             WHERE organization_id = $1 AND id = $2"
        ))
        .bind(organization_id)
        .bind(id)
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn list_endpoints(
        &self,
        organization_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WebhookEndpointRecord>, WebhookError> {
        sqlx::query_as::<_, WebhookEndpointRecord>(&format!(
            "SELECT {ENDPOINT_COLUMNS} FROM webhook_endpoints WHERE organization_id = $1 \
             ORDER BY created_at DESC, id LIMIT $2 OFFSET $3"
        ))
        .bind(organization_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn count_endpoints(&self, organization_id: Uuid) -> Result<i64, WebhookError> {
        sqlx::query_scalar("SELECT count(*) FROM webhook_endpoints WHERE organization_id = $1")
            .bind(organization_id)
            .fetch_one(&self.database)
            .await
            .map_err(Into::into)
    }

    /// COALESCE against the stored row, so a field that was not sent keeps its value while a
    /// field sent as null clears it.
    pub async fn update_endpoint(
        &self,
        organization_id: Uuid,
        id: Uuid,
        changes: &EndpointChanges<'_>,
    ) -> Result<Option<WebhookEndpointRecord>, WebhookError> {
        sqlx::query_as::<_, WebhookEndpointRecord>(&format!(
            "UPDATE webhook_endpoints SET \
                 url = COALESCE($3, url), \
                 description = CASE WHEN $4 THEN $5 ELSE description END, \
                 enabled = COALESCE($6, enabled), \
                 form_id = CASE WHEN $7 THEN $8 ELSE form_id END \
             WHERE organization_id = $1 AND id = $2 \
             RETURNING {ENDPOINT_COLUMNS}"
        ))
        .bind(organization_id)
        .bind(id)
        .bind(changes.url)
        .bind(changes.description.is_some())
        .bind(changes.description.flatten())
        .bind(changes.enabled)
        .bind(changes.form_id.is_some())
        .bind(changes.form_id.flatten())
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn set_endpoint_secret(
        &self,
        organization_id: Uuid,
        id: Uuid,
        secret: &str,
    ) -> Result<bool, WebhookError> {
        let outcome = sqlx::query(
            "UPDATE webhook_endpoints SET secret = $3 WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(id)
        .bind(secret)
        .execute(&self.database)
        .await?;

        Ok(outcome.rows_affected() > 0)
    }

    pub async fn delete_endpoint(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> Result<bool, WebhookError> {
        let outcome =
            sqlx::query("DELETE FROM webhook_endpoints WHERE organization_id = $1 AND id = $2")
                .bind(organization_id)
                .bind(id)
                .execute(&self.database)
                .await?;

        Ok(outcome.rows_affected() > 0)
    }

    /// Whether a form exists in this organization. Checked before an endpoint can be bound to
    /// it, because the foreign key would otherwise let an id from another tenant through.
    pub async fn form_belongs_to(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
    ) -> Result<bool, WebhookError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM forms WHERE organization_id = $1 AND id = $2)",
        )
        .bind(organization_id)
        .bind(form_id)
        .fetch_one(&self.database)
        .await?;

        Ok(exists)
    }

    /// Creates one delivery per enabled endpoint that matches the form.
    ///
    /// A single `INSERT ... SELECT`: the payload is rendered once and fanned out by the
    /// database, so an organization with twenty endpoints still costs one round trip.
    ///
    /// `ON CONFLICT DO NOTHING` is what makes it safe to run twice. Dispatch is at-least-once,
    /// so this will be called again for the same submission after a later step fails, and a
    /// receiver must not see the same submission delivered twice.
    pub async fn create_deliveries(
        &self,
        organization_id: Uuid,
        form_id: Uuid,
        submission_id: Uuid,
        payload: &serde_json::Value,
    ) -> Result<u64, WebhookError> {
        let outcome = sqlx::query(
            "INSERT INTO webhook_deliveries \
                 (organization_id, endpoint_id, submission_id, payload) \
             SELECT $1, e.id, $3, $4 FROM webhook_endpoints e \
             WHERE e.organization_id = $1 AND e.enabled \
               AND (e.form_id IS NULL OR e.form_id = $2) \
             ON CONFLICT (endpoint_id, submission_id) DO NOTHING",
        )
        .bind(organization_id)
        .bind(form_id)
        .bind(submission_id)
        .bind(sqlx::types::Json(payload))
        .execute(&self.database)
        .await?;

        Ok(outcome.rows_affected())
    }

    /// Reserves due deliveries by pushing `next_attempt_at` past a lease window, and returns
    /// each with the endpoint it belongs to.
    pub async fn claim_due_deliveries(
        &self,
        limit: i64,
        lease_seconds: i32,
    ) -> Result<Vec<ClaimedDelivery>, WebhookError> {
        sqlx::query_as::<_, ClaimedDelivery>(
            "UPDATE webhook_deliveries AS d \
             SET attempts = d.attempts + 1, \
                 next_attempt_at = NOW() + ($2 * INTERVAL '1 second') \
             WHERE d.id IN ( \
                 SELECT id FROM webhook_deliveries \
                 WHERE status = 'pending' AND next_attempt_at <= NOW() \
                 ORDER BY next_attempt_at, id \
                 LIMIT $1 \
                 FOR UPDATE SKIP LOCKED \
             ) \
             RETURNING d.id, d.payload, d.attempts, \
                 (SELECT e.url FROM webhook_endpoints e WHERE e.id = d.endpoint_id) AS url, \
                 (SELECT e.secret FROM webhook_endpoints e WHERE e.id = d.endpoint_id) AS secret",
        )
        .bind(limit)
        .bind(lease_seconds)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn mark_delivered(&self, id: Uuid, response_status: i32) -> Result<(), WebhookError> {
        sqlx::query(
            "UPDATE webhook_deliveries \
             SET status = 'delivered', response_status = $2, delivered_at = NOW(), last_error = NULL \
             WHERE id = $1",
        )
        .bind(id)
        .bind(response_status)
        .execute(&self.database)
        .await?;

        Ok(())
    }

    /// Records a failed attempt. Retries until [`crate::modules::webhook::model::MAX_ATTEMPTS`],
    /// then stops: the row stays in the log so it can be redelivered by hand.
    pub async fn record_attempt_failure(
        &self,
        id: Uuid,
        attempts: i32,
        error: &str,
        delay_seconds: i32,
        response_status: Option<i32>,
    ) -> Result<bool, WebhookError> {
        let error: String = error.chars().take(500).collect();
        let give_up = attempts >= crate::modules::webhook::model::MAX_ATTEMPTS;

        let outcome = sqlx::query(
            "UPDATE webhook_deliveries \
             SET status = CASE WHEN $3 THEN 'failed'::webhook_delivery_status \
                               ELSE 'pending'::webhook_delivery_status END, \
                 response_status = $5, \
                 last_error = $4, \
                 next_attempt_at = NOW() + ($6 * INTERVAL '1 second') \
             WHERE id = $1",
        )
        .bind(id)
        .bind(attempts)
        .bind(give_up)
        .bind(error)
        .bind(response_status)
        .bind(delay_seconds)
        .execute(&self.database)
        .await?;

        Ok(outcome.rows_affected() > 0 && give_up)
    }

    pub async fn find_delivery(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> Result<Option<WebhookDeliveryRecord>, WebhookError> {
        sqlx::query_as::<_, WebhookDeliveryRecord>(&format!(
            "SELECT {DELIVERY_COLUMNS} FROM webhook_deliveries \
             WHERE organization_id = $1 AND id = $2"
        ))
        .bind(organization_id)
        .bind(id)
        .fetch_optional(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn list_deliveries(
        &self,
        organization_id: Uuid,
        filters: &DeliveryFilters,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WebhookDeliveryRecord>, WebhookError> {
        sqlx::query_as::<_, WebhookDeliveryRecord>(&format!(
            "SELECT {DELIVERY_COLUMNS} FROM webhook_deliveries WHERE organization_id = $1 {} \
             ORDER BY created_at DESC, id DESC LIMIT $6 OFFSET $7",
            DELIVERY_FILTERS
        ))
        .bind(organization_id)
        .bind(filters.endpoint_id)
        .bind(filters.status)
        .bind(filters.since)
        .bind(filters.until)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn count_deliveries(
        &self,
        organization_id: Uuid,
        filters: &DeliveryFilters,
    ) -> Result<i64, WebhookError> {
        sqlx::query_scalar(&format!(
            "SELECT count(*) FROM webhook_deliveries WHERE organization_id = $1 {DELIVERY_FILTERS}"
        ))
        .bind(organization_id)
        .bind(filters.endpoint_id)
        .bind(filters.status)
        .bind(filters.since)
        .bind(filters.until)
        .fetch_one(&self.database)
        .await
        .map_err(Into::into)
    }

    /// Puts a delivery back in the queue, keeping its attempt history. Used by the redeliver
    /// action, which is what an operator reaches for when a receiver was down.
    pub async fn requeue_delivery(
        &self,
        organization_id: Uuid,
        id: Uuid,
    ) -> Result<bool, WebhookError> {
        let outcome = sqlx::query(
            "UPDATE webhook_deliveries \
             SET status = 'pending', next_attempt_at = NOW(), last_error = NULL \
             WHERE organization_id = $1 AND id = $2",
        )
        .bind(organization_id)
        .bind(id)
        .execute(&self.database)
        .await?;

        Ok(outcome.rows_affected() > 0)
    }
}

/// The narrowing shared by both delivery reads: `$2` endpoint, `$3` status, `$4`/`$5` window.
/// Both queries bind them in that order so the fragment can be one string.
const DELIVERY_FILTERS: &str = "AND ($2::uuid IS NULL OR endpoint_id = $2) \
     AND ($3::webhook_delivery_status IS NULL OR status = $3) \
     AND ($4::timestamptz IS NULL OR created_at >= $4) \
     AND ($5::timestamptz IS NULL OR created_at <= $5)";
