use axum::{Json, extract::State};
use serde::Serialize;

use crate::shared::{error::AppError, state::AppState};

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
}

pub async fn health_check(State(state): State<AppState>) -> Result<Json<HealthResponse>, AppError> {
    sqlx::query("SELECT 1")
        .fetch_one(&state.database)
        .await
        .map_err(|error| AppError::Internal(error.into()))?;
    state.queue.ping().await.map_err(AppError::Internal)?;
    Ok(Json(HealthResponse { status: "ok" }))
}
