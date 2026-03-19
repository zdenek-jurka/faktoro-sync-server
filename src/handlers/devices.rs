use crate::app_state::AppState;
use crate::auth::authorize_registered_device;
use crate::crypto::hash_token;
use crate::error::AppError;
use crate::mailer::send_recovery_email;
use crate::payloads::{parse_pairing_payload, parse_recovery_payload};
use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use sqlx::types::chrono;
use tracing::{error, info};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct RegisterFromScanRequest {
    pub raw_code: String,
    pub device_public_key: Option<DevicePublicKeyPayload>,
}

#[derive(Debug, Deserialize)]
pub struct DevicePublicKeyPayload {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct RegisterFromScanResponse {
    pub instance_id: String,
    pub device_id: String,
    pub device_name: String,
    pub recovery_email: String,
    pub already_registered: bool,
    pub auth_token: Option<String>,
    pub public_key_registered: bool,
}

#[derive(Debug, Deserialize)]
pub struct PairingInitRequest {
    pub recovery_email: String,
    pub device_name: String,
    pub instance_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PairingInitResponse {
    pub instance_id: String,
    pub device_id: String,
    pub token: String,
    pub payload: String,
}

#[derive(Debug, Deserialize)]
pub struct RecoverFromCodeRequest {
    pub raw_code: String,
}

#[derive(Debug, Serialize)]
pub struct RecoverFromCodeResponse {
    pub device_id: String,
    pub device_name: String,
    pub auth_token: String,
}

#[derive(Debug, Deserialize)]
pub struct ForgetRegistrationRequest {
    pub device_id: String,
    pub auth_token: String,
}

#[derive(Debug, Serialize)]
pub struct ForgetRegistrationResponse {
    pub ok: bool,
    pub deleted_instance_id: String,
}

#[derive(Debug, Deserialize)]
pub struct ListDevicesRequest {
    pub device_id: String,
    pub auth_token: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceListItem {
    pub device_id: String,
    pub device_name: String,
    pub recovery_email: String,
    pub is_registered: bool,
    pub is_current: bool,
    pub last_seen_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ListDevicesResponse {
    pub devices: Vec<DeviceListItem>,
}

#[derive(Debug, Deserialize)]
pub struct RemoveDeviceRequest {
    pub device_id: String,
    pub auth_token: String,
    pub target_device_id: String,
}

#[derive(Debug, Serialize)]
pub struct RemoveDeviceResponse {
    pub ok: bool,
    pub removed_device_id: String,
}

pub async fn pairing_init(
    State(state): State<AppState>,
    Json(payload): Json<PairingInitRequest>,
) -> Result<Json<PairingInitResponse>, AppError> {
    info!(
        has_instance_id = payload.instance_id.as_ref().map(|v| !v.trim().is_empty()).unwrap_or(false),
        device_name = %payload.device_name,
        "pairing_init request received"
    );
    let recovery_email = payload.recovery_email.trim().to_lowercase();
    if !recovery_email.contains('@') || recovery_email.len() < 5 {
        return Err(AppError::bad_request("Valid recovery email is required"));
    }

    let device_name = payload.device_name.trim();
    if device_name.is_empty() {
        return Err(AppError::bad_request("Device name is required"));
    }

    let mut tx = state.db.begin().await.map_err(AppError::internal)?;

    let instance_id = if let Some(instance_id) = payload.instance_id {
        let (exists,) = sqlx::query_as::<_, (bool,)>(
            "SELECT EXISTS(SELECT 1 FROM client_instances WHERE id = $1)",
        )
        .bind(&instance_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::internal)?;

        if exists {
            sqlx::query(
                "UPDATE client_instances
                 SET recovery_email = $2,
                     updated_at = NOW(),
                     last_seen_at = NOW()
                 WHERE id = $1",
            )
            .bind(&instance_id)
            .bind(&recovery_email)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        } else {
            sqlx::query(
                "INSERT INTO client_instances (id, recovery_email, created_at, updated_at, last_seen_at)
                 VALUES ($1, $2, NOW(), NOW(), NOW())",
            )
            .bind(&instance_id)
            .bind(&recovery_email)
            .execute(&mut *tx)
            .await
            .map_err(AppError::internal)?;
        }

        instance_id
    } else {
        let new_instance_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO client_instances (id, recovery_email, created_at, updated_at, last_seen_at)
             VALUES ($1, $2, NOW(), NOW(), NOW())",
        )
        .bind(&new_instance_id)
        .bind(&recovery_email)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        new_instance_id
    };

    let device_id = Uuid::new_v4().to_string();
    let token = Uuid::new_v4().to_string();
    let token_hash = hash_token(&token);

    sqlx::query(
        "INSERT INTO devices (
            id, instance_id, name, pairing_token_hash, recovery_email, is_registered, auth_token, created_at
         )
         VALUES ($1, $2, $3, $4, $5, FALSE, NULL, NOW())",
    )
    .bind(&device_id)
    .bind(&instance_id)
    .bind(device_name)
    .bind(&token_hash)
    .bind(&recovery_email)
    .execute(&mut *tx)
    .await
    .map_err(AppError::internal)?;

    tx.commit().await.map_err(AppError::internal)?;

    let payload_json = serde_json::json!({
      "kind": "faktoro_device_pairing_v1",
      "instanceId": instance_id,
      "deviceId": device_id,
      "token": token,
      "deviceName": device_name,
      "recoveryEmail": recovery_email
    })
    .to_string();

    let parsed: serde_json::Value =
        serde_json::from_str(&payload_json).map_err(|e| AppError::internal_message(e.to_string()))?;

    info!(
        instance_id = %parsed.get("instanceId").and_then(|v| v.as_str()).unwrap_or_default(),
        device_id = %parsed.get("deviceId").and_then(|v| v.as_str()).unwrap_or_default(),
        "pairing_init completed"
    );

    Ok(Json(PairingInitResponse {
        instance_id: parsed
            .get("instanceId")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        device_id: parsed
            .get("deviceId")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        token: parsed
            .get("token")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        payload: payload_json,
    }))
}

pub async fn register_from_scan(
    State(state): State<AppState>,
    Json(payload): Json<RegisterFromScanRequest>,
) -> Result<Json<RegisterFromScanResponse>, AppError> {
    info!(
        raw_code_len = payload.raw_code.len(),
        has_device_public_key = payload.device_public_key.is_some(),
        "register_from_scan request received"
    );
    let pairing = parse_pairing_payload(&payload.raw_code)
        .ok_or_else(|| AppError::bad_request("Could not parse pairing payload"))?;
    let recovery_token = Uuid::new_v4().to_string();
    let recovery_token_hash = hash_token(&recovery_token);
    let token_hash = hash_token(&pairing.token);

    let existing = sqlx::query_as::<_, (String, String, String, bool, Option<String>)>(
        "SELECT id, instance_id, name, is_registered, auth_token
         FROM devices
         WHERE id = $1 AND pairing_token_hash = $2 AND instance_id = $3",
    )
    .bind(&pairing.device_id)
    .bind(&token_hash)
    .bind(&pairing.instance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| AppError::unauthorized("Invalid pairing token or instance"))?;

    let (device_id, instance_id, _old_name, already_registered, existing_auth_token) = existing;

    let auth_token = if already_registered {
        sqlx::query(
            "UPDATE devices
             SET recovery_email = $2,
                 recovery_token_hash = $3,
                 last_seen_at = NOW()
             WHERE id = $1",
        )
        .bind(&device_id)
        .bind(&pairing.recovery_email)
        .bind(&recovery_token_hash)
        .execute(&state.db)
        .await
        .map_err(AppError::internal)?;

        existing_auth_token
    } else {
        let new_auth_token = Uuid::new_v4().to_string();
        sqlx::query(
            "UPDATE devices
             SET name = $2,
                 recovery_email = $3,
                 recovery_token_hash = $4,
                 is_registered = TRUE,
                 auth_token = $5,
                 registered_at = NOW(),
                 last_seen_at = NOW()
             WHERE id = $1",
        )
        .bind(&device_id)
        .bind(&pairing.device_name)
        .bind(&pairing.recovery_email)
        .bind(&recovery_token_hash)
        .bind(&new_auth_token)
        .execute(&state.db)
        .await
        .map_err(AppError::internal)?;

        Some(new_auth_token)
    };

    let public_key_registered = if let Some(device_public_key) = payload.device_public_key.as_ref() {
        let key_id = device_public_key.key_id.trim();
        let algorithm = device_public_key.algorithm.trim();
        let public_key = device_public_key.public_key.trim();

        if key_id.is_empty() {
            return Err(AppError::bad_request("device_public_key.key_id is required"));
        }
        if algorithm.is_empty() {
            return Err(AppError::bad_request("device_public_key.algorithm is required"));
        }
        if public_key.is_empty() {
            return Err(AppError::bad_request("device_public_key.public_key is required"));
        }

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
        .bind(&device_id)
        .bind(&instance_id)
        .bind(key_id)
        .bind(algorithm)
        .bind(public_key)
        .execute(&state.db)
        .await
        .map_err(AppError::internal)?;

        true
    } else {
        false
    };

    if let Err(send_error) = send_recovery_email(
        &state.mailer,
        &device_id,
        &pairing.device_name,
        &pairing.recovery_email,
        &recovery_token,
    )
    .await
    {
        error!(
            device_id = %device_id,
            recovery_email = %pairing.recovery_email,
            error = ?send_error,
            "Recovery email sending failed, pairing will continue"
        );
    }

    info!(
        instance_id = %instance_id,
        device_id = %device_id,
        already_registered = already_registered,
        "register_from_scan completed"
    );

    Ok(Json(RegisterFromScanResponse {
        instance_id,
        device_id,
        device_name: pairing.device_name,
        recovery_email: pairing.recovery_email,
        already_registered,
        auth_token,
        public_key_registered,
    }))
}

pub async fn recover_from_code(
    State(state): State<AppState>,
    Json(payload): Json<RecoverFromCodeRequest>,
) -> Result<Json<RecoverFromCodeResponse>, AppError> {
    info!(
        raw_code_len = payload.raw_code.len(),
        "recover_from_code request received"
    );
    let recovery = parse_recovery_payload(&payload.raw_code)
        .ok_or_else(|| AppError::bad_request("Could not parse recovery payload"))?;
    let recovery_hash = hash_token(&recovery.recovery_token);

    let row = sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT id, name, recovery_token_hash
         FROM devices
         WHERE id = $1 AND is_registered = TRUE",
    )
    .bind(&recovery.device_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?;

    let (device_id, device_name, stored_hash) =
        row.ok_or_else(|| AppError::not_found("Recovery device not found"))?;

    if stored_hash.as_deref() != Some(recovery_hash.as_str()) {
        return Err(AppError::unauthorized("Invalid recovery token"));
    }

    let new_auth_token = Uuid::new_v4().to_string();
    sqlx::query(
        "UPDATE devices
         SET auth_token = $2, last_seen_at = NOW()
         WHERE id = $1",
    )
    .bind(&device_id)
    .bind(&new_auth_token)
    .execute(&state.db)
    .await
    .map_err(AppError::internal)?;

    info!(
        device_id = %device_id,
        "recover_from_code completed"
    );

    Ok(Json(RecoverFromCodeResponse {
        device_id,
        device_name,
        auth_token: new_auth_token,
    }))
}

pub async fn forget_registration(
    State(state): State<AppState>,
    Json(payload): Json<ForgetRegistrationRequest>,
) -> Result<Json<ForgetRegistrationResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;

    sqlx::query("DELETE FROM client_instances WHERE id = $1")
        .bind(&auth.instance_id)
        .execute(&state.db)
        .await
        .map_err(AppError::internal)?;

    Ok(Json(ForgetRegistrationResponse {
        ok: true,
        deleted_instance_id: auth.instance_id,
    }))
}

pub async fn list_devices(
    State(state): State<AppState>,
    Query(payload): Query<ListDevicesRequest>,
) -> Result<Json<ListDevicesResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;

    let rows = sqlx::query_as::<_, (String, String, String, bool, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT id, name, recovery_email, is_registered, last_seen_at
         FROM devices
         WHERE instance_id = $1
         ORDER BY created_at ASC",
    )
    .bind(&auth.instance_id)
    .fetch_all(&state.db)
    .await
    .map_err(AppError::internal)?;

    let devices = rows
        .into_iter()
        .map(
            |(device_id, device_name, recovery_email, is_registered, last_seen_at)| DeviceListItem {
                is_current: device_id == auth.device_id,
                device_id,
                device_name,
                recovery_email,
                is_registered,
                last_seen_at: last_seen_at.map(|value| value.to_rfc3339()),
            },
        )
        .collect();

    Ok(Json(ListDevicesResponse { devices }))
}

pub async fn remove_device(
    State(state): State<AppState>,
    Json(payload): Json<RemoveDeviceRequest>,
) -> Result<Json<RemoveDeviceResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;
    let target_device_id = payload.target_device_id.trim();
    if target_device_id.is_empty() {
        return Err(AppError::bad_request("target_device_id is required"));
    }
    if target_device_id == auth.device_id {
        return Err(AppError::bad_request(
            "Current device cannot remove itself from this endpoint",
        ));
    }

    let target_row = sqlx::query_as::<_, (String, bool)>(
        "SELECT id, is_registered
         FROM devices
         WHERE id = $1 AND instance_id = $2",
    )
    .bind(target_device_id)
    .bind(&auth.instance_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?
    .ok_or_else(|| AppError::not_found("Target device not found"))?;

    let (_, target_is_registered) = target_row;
    if target_is_registered {
        let (registered_count,) = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*)::BIGINT
             FROM devices
             WHERE instance_id = $1 AND is_registered = TRUE",
        )
        .bind(&auth.instance_id)
        .fetch_one(&state.db)
        .await
        .map_err(AppError::internal)?;

        if registered_count <= 1 {
            return Err(AppError::bad_request(
                "Cannot remove the last registered device from the instance",
            ));
        }
    }

    sqlx::query("DELETE FROM devices WHERE id = $1 AND instance_id = $2")
        .bind(target_device_id)
        .bind(&auth.instance_id)
        .execute(&state.db)
        .await
        .map_err(AppError::internal)?;

    Ok(Json(RemoveDeviceResponse {
        ok: true,
        removed_device_id: target_device_id.to_string(),
    }))
}
