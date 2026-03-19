use crate::app_state::AppState;
use crate::auth::authorize_registered_device;
use crate::error::AppError;
use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct UpsertDevicePublicKeyRequest {
    pub device_id: String,
    pub auth_token: String,
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct UpsertDevicePublicKeyResponse {
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct DevicePublicKeyQuery {
    pub device_id: String,
    pub auth_token: String,
    pub target_device_id: String,
}

#[derive(Debug, Serialize)]
pub struct DevicePublicKeyResponse {
    pub device_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct UpsertInstanceKeyEnvelopeRequest {
    pub device_id: String,
    pub auth_token: String,
    pub target_device_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub envelope: String,
}

#[derive(Debug, Serialize)]
pub struct UpsertInstanceKeyEnvelopeResponse {
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct InstanceKeyEnvelopeQuery {
    pub device_id: String,
    pub auth_token: String,
    pub key_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InstanceKeyEnvelopeResponse {
    pub target_device_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub envelope: String,
}

pub async fn upsert_device_public_key(
    State(state): State<AppState>,
    Json(payload): Json<UpsertDevicePublicKeyRequest>,
) -> Result<Json<UpsertDevicePublicKeyResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;

    validate_non_empty("key_id", &payload.key_id)?;
    validate_non_empty("algorithm", &payload.algorithm)?;
    validate_non_empty("public_key", &payload.public_key)?;

    sqlx::query(
        "INSERT INTO device_public_keys (
            device_id,
            instance_id,
            key_id,
            algorithm,
            public_key,
            created_at,
            updated_at
         )
         VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
         ON CONFLICT (device_id)
         DO UPDATE SET
           key_id = EXCLUDED.key_id,
           algorithm = EXCLUDED.algorithm,
           public_key = EXCLUDED.public_key,
           updated_at = NOW()",
    )
    .bind(&payload.device_id)
    .bind(&auth.instance_id)
    .bind(payload.key_id.trim())
    .bind(payload.algorithm.trim())
    .bind(payload.public_key.trim())
    .execute(&state.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(UpsertDevicePublicKeyResponse { ok: true }))
}

pub async fn get_device_public_key(
    State(state): State<AppState>,
    Query(query): Query<DevicePublicKeyQuery>,
) -> Result<Json<DevicePublicKeyResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &query.device_id, &query.auth_token).await?;

    let found = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT k.device_id, k.key_id, k.algorithm, k.public_key
         FROM device_public_keys k
         INNER JOIN devices d ON d.id = k.device_id
         WHERE k.device_id = $1
           AND d.instance_id = $2
           AND d.is_registered = TRUE",
    )
    .bind(query.target_device_id.trim())
    .bind(&auth.instance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?;

    let (device_id, key_id, algorithm, public_key) =
        found.ok_or_else(|| AppError::not_found("Target device public key not found"))?;

    Ok(Json(DevicePublicKeyResponse {
        device_id,
        key_id,
        algorithm,
        public_key,
    }))
}

pub async fn upsert_instance_key_envelope(
    State(state): State<AppState>,
    Json(payload): Json<UpsertInstanceKeyEnvelopeRequest>,
) -> Result<Json<UpsertInstanceKeyEnvelopeResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;

    validate_non_empty("target_device_id", &payload.target_device_id)?;
    validate_non_empty("key_id", &payload.key_id)?;
    validate_non_empty("algorithm", &payload.algorithm)?;
    validate_non_empty("envelope", &payload.envelope)?;

    let (target_exists,) = sqlx::query_as::<_, (bool,)>(
        "SELECT EXISTS(
           SELECT 1 FROM devices
           WHERE id = $1
             AND instance_id = $2
             AND is_registered = TRUE
         )",
    )
    .bind(payload.target_device_id.trim())
    .bind(&auth.instance_id)
    .fetch_one(&state.db)
    .await
    .map_err(AppError::internal)?;

    if !target_exists {
        return Err(AppError::not_found("Target device is not part of this instance"));
    }

    sqlx::query(
        "INSERT INTO instance_key_envelopes (
            instance_id,
            target_device_id,
            key_id,
            algorithm,
            envelope,
            wrapped_by_device_id,
            created_at,
            updated_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
         ON CONFLICT (instance_id, target_device_id, key_id)
         DO UPDATE SET
           algorithm = EXCLUDED.algorithm,
           envelope = EXCLUDED.envelope,
           wrapped_by_device_id = EXCLUDED.wrapped_by_device_id,
           updated_at = NOW()",
    )
    .bind(&auth.instance_id)
    .bind(payload.target_device_id.trim())
    .bind(payload.key_id.trim())
    .bind(payload.algorithm.trim())
    .bind(payload.envelope.trim())
    .bind(&auth.device_id)
    .execute(&state.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(UpsertInstanceKeyEnvelopeResponse { ok: true }))
}

pub async fn get_instance_key_envelope(
    State(state): State<AppState>,
    Query(query): Query<InstanceKeyEnvelopeQuery>,
) -> Result<Json<InstanceKeyEnvelopeResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &query.device_id, &query.auth_token).await?;

    let found = if let Some(key_id) = query.key_id.as_ref().map(|v| v.trim()).filter(|v| !v.is_empty()) {
        sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT target_device_id, key_id, algorithm, envelope
             FROM instance_key_envelopes
             WHERE instance_id = $1
               AND target_device_id = $2
               AND key_id = $3",
        )
        .bind(&auth.instance_id)
        .bind(&auth.device_id)
        .bind(key_id)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::internal)?
    } else {
        sqlx::query_as::<_, (String, String, String, String)>(
            "SELECT target_device_id, key_id, algorithm, envelope
             FROM instance_key_envelopes
             WHERE instance_id = $1
               AND target_device_id = $2
             ORDER BY updated_at DESC
             LIMIT 1",
        )
        .bind(&auth.instance_id)
        .bind(&auth.device_id)
        .fetch_optional(&state.db)
        .await
        .map_err(AppError::internal)?
    };

    let (target_device_id, key_id, algorithm, envelope) =
        found.ok_or_else(|| AppError::not_found("Key envelope not found for this device"))?;

    Ok(Json(InstanceKeyEnvelopeResponse {
        target_device_id,
        key_id,
        algorithm,
        envelope,
    }))
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), AppError> {
    if value.trim().is_empty() {
        return Err(AppError::bad_request(format!("{field} is required")));
    }
    Ok(())
}
