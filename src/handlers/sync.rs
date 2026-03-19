use crate::app_state::{AppState, SyncEventNotification};
use crate::auth::authorize_registered_device;
use crate::error::AppError;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::{Map, Value as JsonValue};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

const SYNC_EVENTS_CHANNEL: &str = "faktoro_sync_events";

const ONLINE_SYNC_TABLES: [&str; 14] = [
    "app_settings",
    "config_storage",
    "client",
    "client_address",
    "price_list_item",
    "client_price_override",
    "time_entry",
    "sync_operation",
    "sync_conflict",
    "vat_code",
    "vat_rate",
    "timesheet",
    "invoice",
    "invoice_item",
];

#[derive(Debug, Deserialize)]
pub struct OnlinePullRequest {
    pub device_id: String,
    pub auth_token: String,
    pub last_pulled_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct OnlinePushRequest {
    pub device_id: String,
    pub auth_token: String,
    pub last_pulled_at: Option<i64>,
    pub changes: HashMap<String, OnlineTableChangeSet>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct OnlineTableChangeSet {
    pub created: Vec<Value>,
    pub updated: Vec<Value>,
    pub deleted: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct OnlinePullResponse {
    pub changes: HashMap<String, OnlineTableChangeSet>,
    pub timestamp: i64,
}

#[derive(Debug, Serialize)]
pub struct OnlinePushResponse {
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct PushSyncRequest {
    pub device_id: String,
    pub auth_token: String,
    pub snapshot: Value,
}

#[derive(Debug, Serialize)]
pub struct PushSyncResponse {
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct PullSyncRequest {
    pub device_id: String,
    pub auth_token: String,
}

#[derive(Debug, Serialize)]
pub struct PullSyncResponse {
    pub snapshot: Option<Value>,
}

pub async fn sync_online_push(
    State(state): State<AppState>,
    Json(payload): Json<OnlinePushRequest>,
) -> Result<Json<OnlinePushResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;

    let mut changed_tables: Vec<String> = Vec::new();
    let _ = payload.last_pulled_at;
    let timestamp = now_ms();
    let mut tx = state.db.begin().await.map_err(AppError::internal)?;

    for (table, table_changes) in payload.changes {
        validate_sync_table(&table)?;
        let has_changes = !table_changes.created.is_empty()
            || !table_changes.updated.is_empty()
            || !table_changes.deleted.is_empty();
        if has_changes {
            changed_tables.push(table.clone());
        }

        for raw in table_changes.created.into_iter().chain(table_changes.updated.into_iter()) {
            let sanitized_raw = sanitize_record_for_storage(raw)?;
            validate_encrypted_record(&sanitized_raw)?;
            let record_id = record_id_from_raw(&sanitized_raw)?;

            sqlx::query(
                "INSERT INTO online_records_shared (
                    instance_id,
                    table_name,
                    record_id,
                    raw,
                    source_device_id,
                    first_seen_at,
                    last_modified_at,
                    is_deleted
                 )
                 VALUES ($1, $2, $3, $4, $5, $6, $6, FALSE)
                 ON CONFLICT (instance_id, table_name, record_id)
                 DO UPDATE SET
                   raw = EXCLUDED.raw,
                   source_device_id = EXCLUDED.source_device_id,
                   is_deleted = FALSE,
                   last_modified_at = EXCLUDED.last_modified_at",
            )
            .bind(&auth.instance_id)
            .bind(&table)
            .bind(&record_id)
            .bind(&sanitized_raw)
            .bind(&auth.device_id)
            .bind(timestamp)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }

        for deleted_id in table_changes.deleted {
            let record_id = sanitize_record_id(&deleted_id)?;
            sqlx::query(
                "INSERT INTO online_records_shared (
                    instance_id,
                    table_name,
                    record_id,
                    raw,
                    source_device_id,
                    first_seen_at,
                    last_modified_at,
                    is_deleted
                 )
                 VALUES ($1, $2, $3, '{}'::jsonb, $4, $5, $5, TRUE)
                 ON CONFLICT (instance_id, table_name, record_id)
                 DO UPDATE SET
                   raw = '{}'::jsonb,
                   source_device_id = EXCLUDED.source_device_id,
                   is_deleted = TRUE,
                   last_modified_at = EXCLUDED.last_modified_at",
            )
            .bind(&auth.instance_id)
            .bind(&table)
            .bind(&record_id)
            .bind(&auth.device_id)
            .bind(timestamp)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }
    }

    tx.commit().await.map_err(AppError::internal)?;

    let payload_json = serde_json::json!({
        "tables": changed_tables
    });
    sqlx::query(
        "INSERT INTO instance_sync_events (
            instance_id,
            source_device_id,
            event_type,
            created_at_ms,
            payload
         )
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&auth.instance_id)
    .bind(&auth.device_id)
    .bind("online_push")
    .bind(timestamp)
    .bind(&payload_json)
    .execute(&state.db)
    .await
    .map_err(AppError::internal)?;

    let notification = SyncEventNotification {
        instance_id: auth.instance_id,
        source_device_id: auth.device_id,
        event_type: "online_push".to_string(),
        timestamp,
        payload: payload_json,
    };
    let notification_payload = serde_json::to_string(&notification)
        .map_err(|e| AppError::internal_message(e.to_string()))?;

    sqlx::query("SELECT pg_notify($1, $2)")
        .bind(SYNC_EVENTS_CHANNEL)
        .bind(notification_payload)
        .execute(&state.db)
        .await
        .map_err(AppError::internal)?;

    Ok(Json(OnlinePushResponse { ok: true }))
}

pub async fn sync_online_pull(
    State(state): State<AppState>,
    Json(payload): Json<OnlinePullRequest>,
) -> Result<Json<OnlinePullResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;

    let last_pulled_at = payload.last_pulled_at.unwrap_or(0);
    let mut changes: HashMap<String, OnlineTableChangeSet> = ONLINE_SYNC_TABLES
        .iter()
        .map(|table| ((*table).to_string(), OnlineTableChangeSet::default()))
        .collect();

    let rows = sqlx::query_as::<_, (String, String, Value, i64, i64, bool)>(
        "SELECT table_name, record_id, raw, first_seen_at, last_modified_at, is_deleted
         FROM online_records_shared
         WHERE instance_id = $1
           AND last_modified_at > $2
           AND (source_device_id IS NULL OR source_device_id <> $3)
         ORDER BY last_modified_at ASC",
    )
    .bind(&auth.instance_id)
    .bind(last_pulled_at)
    .bind(&auth.device_id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::internal)?;

    for (table_name, record_id, raw, first_seen_at, _, is_deleted) in rows {
        validate_sync_table(&table_name)?;
        let Some(table_changes) = changes.get_mut(&table_name) else {
            continue;
        };

        if is_deleted {
            table_changes.deleted.push(record_id);
            continue;
        }

        if first_seen_at > last_pulled_at {
            table_changes.created.push(raw);
        } else {
            table_changes.updated.push(raw);
        }
    }

    Ok(Json(OnlinePullResponse {
        changes,
        timestamp: now_ms(),
    }))
}

pub async fn sync_push(
    State(state): State<AppState>,
    Json(payload): Json<PushSyncRequest>,
) -> Result<Json<PushSyncResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;
    let sanitized_snapshot = sanitize_snapshot_for_storage(payload.snapshot)?;
    validate_encrypted_snapshot(&sanitized_snapshot)?;

    sqlx::query(
        "INSERT INTO sync_snapshots_shared (instance_id, snapshot, version, updated_at)
         VALUES ($1, $2, 1, NOW())
         ON CONFLICT (instance_id)
         DO UPDATE SET
             snapshot = EXCLUDED.snapshot,
             version = sync_snapshots_shared.version + 1,
             updated_at = NOW()",
    )
    .bind(&auth.instance_id)
    .bind(&sanitized_snapshot)
    .execute(&state.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(PushSyncResponse { ok: true }))
}

pub async fn sync_pull(
    State(state): State<AppState>,
    Json(payload): Json<PullSyncRequest>,
) -> Result<Json<PullSyncResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;

    let snapshot = sqlx::query_as::<_, (Value,)>(
        "SELECT snapshot FROM sync_snapshots_shared WHERE instance_id = $1",
    )
    .bind(&auth.instance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?
    .map(|(snapshot,)| snapshot);

    Ok(Json(PullSyncResponse { snapshot }))
}

fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis() as i64,
        Err(_) => 0,
    }
}

fn validate_sync_table(table: &str) -> Result<(), AppError> {
    if table.is_empty() || table.len() > 64 {
        return Err(AppError::bad_request("Invalid sync table name length"));
    }
    if !table
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(AppError::bad_request(format!(
            "Invalid sync table name: {table}"
        )));
    }

    if ONLINE_SYNC_TABLES.contains(&table) {
        Ok(())
    } else {
        Err(AppError::bad_request(format!(
            "Unsupported sync table: {table}"
        )))
    }
}

fn record_id_from_raw(raw: &Value) -> Result<String, AppError> {
    let id = raw
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or_else(|| AppError::bad_request("Record is missing string field 'id'"))?;

    sanitize_record_id(id)
}

fn sanitize_record_id(input: &str) -> Result<String, AppError> {
    if input.is_empty() {
        return Err(AppError::bad_request("Record id cannot be empty"));
    }

    if !input
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.')
    {
        return Err(AppError::bad_request(format!("Invalid record id: {input}")));
    }

    Ok(input.to_string())
}

fn validate_encrypted_record(raw: &Value) -> Result<(), AppError> {
    let obj = raw
        .as_object()
        .ok_or_else(|| AppError::bad_request("Encrypted record must be a JSON object"))?;

    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("Encrypted record is missing string field 'id'"))?;
    sanitize_record_id(id)?;

    let enc_v = obj
        .get("_enc_v")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if enc_v == 0 {
        // Plaintext fallback mode (insecure): accepted for clients without Secure Crypto API.
        return Ok(());
    }
    if enc_v != 1 {
        return Err(AppError::bad_request("Unsupported encrypted payload version"));
    }

    let enc_alg = obj
        .get("_enc_alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("Encrypted record is missing '_enc_alg'"))?;
    if enc_alg != "aes-256-gcm" {
        return Err(AppError::bad_request("Unsupported encrypted payload algorithm"));
    }

    let enc_iv = obj
        .get("_enc_iv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("Encrypted record is missing '_enc_iv'"))?;
    if enc_iv.trim().is_empty() {
        return Err(AppError::bad_request("Encrypted record '_enc_iv' cannot be empty"));
    }

    let enc_ct = obj
        .get("_enc_ct")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("Encrypted record is missing '_enc_ct'"))?;
    if enc_ct.trim().is_empty() {
        return Err(AppError::bad_request("Encrypted record '_enc_ct' cannot be empty"));
    }

    Ok(())
}

fn validate_encrypted_snapshot(snapshot: &Value) -> Result<(), AppError> {
    let obj = snapshot
        .as_object()
        .ok_or_else(|| AppError::bad_request("Encrypted snapshot must be a JSON object"))?;

    let enc_v = obj
        .get("_enc_snapshot_v")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if enc_v == 0 {
        // Plaintext snapshot fallback mode (insecure).
        return Ok(());
    }
    if enc_v != 1 {
        return Err(AppError::bad_request("Unsupported encrypted snapshot version"));
    }

    let enc_alg = obj
        .get("_enc_snapshot_alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("Encrypted snapshot is missing '_enc_snapshot_alg'"))?;
    if enc_alg != "aes-256-gcm" {
        return Err(AppError::bad_request("Unsupported encrypted snapshot algorithm"));
    }

    let enc_iv = obj
        .get("_enc_snapshot_iv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("Encrypted snapshot is missing '_enc_snapshot_iv'"))?;
    if enc_iv.trim().is_empty() {
        return Err(AppError::bad_request("Encrypted snapshot '_enc_snapshot_iv' cannot be empty"));
    }

    let enc_ct = obj
        .get("_enc_snapshot_ct")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("Encrypted snapshot is missing '_enc_snapshot_ct'"))?;
    if enc_ct.trim().is_empty() {
        return Err(AppError::bad_request("Encrypted snapshot '_enc_snapshot_ct' cannot be empty"));
    }

    Ok(())
}

fn sanitize_record_for_storage(raw: Value) -> Result<Value, AppError> {
    let mut obj = raw
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::bad_request("Record must be a JSON object"))?;

    let enc_v = obj.get("_enc_v").and_then(|v| v.as_i64()).unwrap_or(0);
    if enc_v == 0 {
        // Strip Watermelon internal sync metadata for plaintext fallback.
        obj.remove("_status");
        obj.remove("_changed");
    }

    let id = obj
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::bad_request("Record is missing string field 'id'"))?;
    sanitize_record_id(id)?;

    Ok(Value::Object(obj))
}

fn sanitize_snapshot_for_storage(snapshot: Value) -> Result<Value, AppError> {
    let obj = snapshot
        .as_object()
        .cloned()
        .ok_or_else(|| AppError::bad_request("Snapshot must be a JSON object"))?;

    let enc_v = obj
        .get("_enc_snapshot_v")
        .and_then(|v| v.as_i64())
        .unwrap_or(0);
    if enc_v != 0 {
        return Ok(Value::Object(obj));
    }

    let mut sanitized_snapshot = Map::new();
    for (table, table_value) in obj {
        let records = table_value
            .as_array()
            .ok_or_else(|| AppError::bad_request(format!("Snapshot table '{table}' must be an array")))?;

        let mut sanitized_records = Vec::with_capacity(records.len());
        for raw in records {
            let sanitized = sanitize_record_for_storage(raw.clone())?;
            sanitized_records.push(sanitized);
        }
        sanitized_snapshot.insert(table, JsonValue::Array(sanitized_records));
    }

    Ok(Value::Object(sanitized_snapshot))
}
