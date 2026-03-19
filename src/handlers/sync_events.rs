use crate::app_state::AppState;
use crate::auth::authorize_registered_device;
use crate::error::AppError;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct SyncEventsPullRequest {
    pub device_id: String,
    pub auth_token: String,
    pub since: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct SyncEventItem {
    pub event_id: i64,
    pub source_device_id: String,
    pub event_type: String,
    pub timestamp: i64,
    pub payload: Value,
}

#[derive(Debug, Serialize)]
pub struct SyncEventsPullResponse {
    pub events: Vec<SyncEventItem>,
    pub latest_timestamp: i64,
}

pub async fn sync_events_pull(
    State(state): State<AppState>,
    Json(payload): Json<SyncEventsPullRequest>,
) -> Result<Json<SyncEventsPullResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;

    let since = payload.since.unwrap_or(0);
    let limit = payload.limit.unwrap_or(100).clamp(1, 500);

    let rows = sqlx::query_as::<_, (i64, String, String, i64, Value)>(
        "SELECT event_id, source_device_id, event_type, created_at_ms, payload
         FROM instance_sync_events
         WHERE instance_id = $1
           AND created_at_ms > $2
         ORDER BY created_at_ms ASC, event_id ASC
         LIMIT $3",
    )
    .bind(&auth.instance_id)
    .bind(since)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::internal)?;

    let mut latest_timestamp = since;
    let events = rows
        .into_iter()
        .map(
            |(event_id, source_device_id, event_type, timestamp, payload)| {
                if timestamp > latest_timestamp {
                    latest_timestamp = timestamp;
                }
                SyncEventItem {
                    event_id,
                    source_device_id,
                    event_type,
                    timestamp,
                    payload,
                }
            },
        )
        .collect();

    Ok(Json(SyncEventsPullResponse {
        events,
        latest_timestamp,
    }))
}
