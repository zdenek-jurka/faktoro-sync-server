use crate::app_state::AppState;
use crate::auth::{authorize_registered_device, extract_credentials_from_headers};
use crate::crypto::hash_token;
use crate::error::AppError;
use crate::mailer::send_recovery_email;
use crate::payloads::{parse_pairing_payload, parse_recovery_payload};
use axum::extract::{Query, State};
use axum::http::HeaderMap;
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
    pub instance_id: String,
    pub allow_plaintext: bool,
    pub instance_key: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpsertRecoveryBootstrapRequest {
    pub device_id: String,
    pub auth_token: String,
    pub allow_plaintext: bool,
    pub instance_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UpsertRecoveryBootstrapResponse {
    pub ok: bool,
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

#[derive(Debug, Deserialize, Default)]
pub struct ListDevicesRequest {
    #[serde(default)]
    pub device_id: String,
    #[serde(default)]
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

struct ResolvedRecoveryBootstrap {
    allow_plaintext: bool,
    instance_key: Option<String>,
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
                 SET updated_at = NOW(),
                     last_seen_at = NOW()
                 WHERE id = $1",
            )
            .bind(&instance_id)
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
      "recoveryEmail": recovery_email,
      "serverBaseUrl": state.public_base_url
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
        let new_auth_token_hash = hash_token(&new_auth_token);
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
        .bind(&new_auth_token_hash)
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
        &instance_id,
        &device_id,
        &pairing.device_name,
        &pairing.recovery_email,
        &recovery_token,
        &state.public_base_url,
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

    let row = sqlx::query_as::<_, (String, String, String, String, Option<String>)>(
        "SELECT id, instance_id, name, recovery_email, recovery_token_hash
         FROM devices
         WHERE id = $1 AND is_registered = TRUE",
    )
    .bind(&recovery.device_id)
    .fetch_optional(&state.db)
    .await
    .map_err(AppError::internal)?;

    let (device_id, instance_id, device_name, recovery_email, stored_hash) =
        row.ok_or_else(|| AppError::not_found("Recovery device not found"))?;

    if !recovery.instance_id.trim().is_empty() && recovery.instance_id != instance_id {
        return Err(AppError::unauthorized("Recovery payload instance mismatch"));
    }

    if stored_hash.as_deref() != Some(recovery_hash.as_str()) {
        return Err(AppError::unauthorized("Invalid recovery token"));
    }

    let bootstrap = resolve_recovery_bootstrap(&state.db, &instance_id).await?;
    let new_auth_token = Uuid::new_v4().to_string();
    let new_auth_token_hash = hash_token(&new_auth_token);
    let new_recovery_token = Uuid::new_v4().to_string();
    let new_recovery_token_hash = hash_token(&new_recovery_token);
    sqlx::query(
        "UPDATE devices
         SET auth_token = $2,
             recovery_token_hash = $3,
             last_seen_at = NOW()
         WHERE id = $1",
    )
    .bind(&device_id)
    .bind(&new_auth_token_hash)
    .bind(&new_recovery_token_hash)
    .execute(&state.db)
    .await
    .map_err(AppError::internal)?;

    sqlx::query(
        "UPDATE client_instances
         SET last_seen_at = NOW(),
             updated_at = NOW()
         WHERE id = $1",
    )
    .bind(&instance_id)
    .execute(&state.db)
    .await
    .map_err(AppError::internal)?;

    if let Err(send_error) = send_recovery_email(
        &state.mailer,
        &instance_id,
        &device_id,
        &device_name,
        &recovery_email,
        &new_recovery_token,
        &state.public_base_url,
    )
    .await
    {
        error!(
            device_id = %device_id,
            recovery_email = %recovery_email,
            error = ?send_error,
            "Recovery email rotation failed after successful recovery"
        );
    }

    info!(
        device_id = %device_id,
        "recover_from_code completed"
    );

    Ok(Json(RecoverFromCodeResponse {
        device_id,
        device_name,
        auth_token: new_auth_token,
        instance_id,
        allow_plaintext: bootstrap.allow_plaintext,
        instance_key: bootstrap.instance_key,
    }))
}

pub async fn upsert_recovery_bootstrap(
    State(state): State<AppState>,
    Json(payload): Json<UpsertRecoveryBootstrapRequest>,
) -> Result<Json<UpsertRecoveryBootstrapResponse>, AppError> {
    let auth = authorize_registered_device(&state.db, &payload.device_id, &payload.auth_token).await?;
    let normalized_instance_key = payload
        .instance_key
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    if payload.allow_plaintext {
        if normalized_instance_key.is_some() {
            return Err(AppError::bad_request(
                "instance_key must be empty when allow_plaintext is true",
            ));
        }
    } else if normalized_instance_key.is_none() {
        return Err(AppError::bad_request(
            "instance_key is required when allow_plaintext is false",
        ));
    }

    sqlx::query(
        "INSERT INTO instance_recovery_bootstraps (
            instance_id,
            allow_plaintext,
            instance_key,
            configured_by_device_id,
            created_at,
            updated_at
         )
         VALUES ($1, $2, $3, $4, NOW(), NOW())
         ON CONFLICT (instance_id)
         DO UPDATE SET
           allow_plaintext = EXCLUDED.allow_plaintext,
           instance_key = EXCLUDED.instance_key,
           configured_by_device_id = EXCLUDED.configured_by_device_id,
           updated_at = NOW()",
    )
    .bind(&auth.instance_id)
    .bind(payload.allow_plaintext)
    .bind(&normalized_instance_key)
    .bind(&auth.device_id)
    .execute(&state.db)
    .await
    .map_err(AppError::internal)?;

    Ok(Json(UpsertRecoveryBootstrapResponse { ok: true }))
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
    headers: HeaderMap,
    Query(payload): Query<ListDevicesRequest>,
) -> Result<Json<ListDevicesResponse>, AppError> {
    let (device_id, auth_token) = if let Some(creds) = extract_credentials_from_headers(&headers) {
        (creds.device_id, creds.auth_token)
    } else {
        (payload.device_id.clone(), payload.auth_token.clone())
    };
    let auth = authorize_registered_device(&state.db, &device_id, &auth_token).await?;

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

async fn resolve_recovery_bootstrap(
    db: &sqlx::PgPool,
    instance_id: &str,
) -> Result<ResolvedRecoveryBootstrap, AppError> {
    let bootstrap = sqlx::query_as::<_, (bool, Option<String>)>(
        "SELECT allow_plaintext, instance_key
         FROM instance_recovery_bootstraps
         WHERE instance_id = $1",
    )
    .bind(instance_id)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    if let Some((allow_plaintext, instance_key)) = bootstrap {
        if !allow_plaintext && instance_key.as_deref().unwrap_or("").trim().is_empty() {
            return Err(AppError::conflict(
                "Encrypted instance recovery bootstrap is missing instance_key",
            ));
        }

        return Ok(ResolvedRecoveryBootstrap {
            allow_plaintext,
            instance_key: instance_key.filter(|value| !value.trim().is_empty()),
        });
    }

    if instance_uses_encrypted_payloads(db, instance_id).await? {
        return Err(AppError::conflict(
            "Instance key unavailable for encrypted recovery",
        ));
    }

    Ok(ResolvedRecoveryBootstrap {
        allow_plaintext: true,
        instance_key: None,
    })
}

async fn instance_uses_encrypted_payloads(
    db: &sqlx::PgPool,
    instance_id: &str,
) -> Result<bool, AppError> {
    let (encrypted,) = sqlx::query_as::<_, (bool,)>(
        "SELECT
            EXISTS(
                SELECT 1
                FROM sync_snapshots_shared
                WHERE instance_id = $1
                  AND jsonb_typeof(snapshot -> '_enc_snapshot_v') = 'number'
                  AND (snapshot ->> '_enc_snapshot_v')::integer > 0
            )
            OR EXISTS(
                SELECT 1
                FROM online_records_shared
                WHERE instance_id = $1
                  AND jsonb_typeof(raw -> '_enc_v') = 'number'
                  AND (raw ->> '_enc_v')::integer > 0
            )",
    )
    .bind(instance_id)
    .fetch_one(db)
    .await
    .map_err(AppError::internal)?;

    Ok(encrypted)
}

#[cfg(test)]
mod tests {
    use super::{
        recover_from_code, upsert_recovery_bootstrap, RecoverFromCodeRequest,
        UpsertRecoveryBootstrapRequest,
    };
    use crate::app_state::{AppState, SyncEventNotification};
    use crate::crypto::hash_token;
    use crate::error::AppError;
    use crate::mailer::MailerConfig;
    use crate::payloads::{encode_recovery_payload_pem, RecoveryPayload};
    use axum::extract::State;
    use axum::response::IntoResponse;
    use axum::Json;
    use lettre::message::Mailbox;
    use lettre::{AsyncSmtpTransport, Tokio1Executor};
    use sqlx::PgPool;
    use tokio::sync::broadcast;
    use uuid::Uuid;

    #[sqlx::test]
    async fn plaintext_recovery_returns_full_bootstrap(pool: PgPool) {
        let state = test_state(pool.clone());
        let instance_id = Uuid::new_v4().to_string();
        let device_id = Uuid::new_v4().to_string();
        let old_auth_token = "old-auth-token";
        let recovery_token = "plain-recovery-token";

        insert_registered_device(
            &pool,
            &instance_id,
            &device_id,
            "Primary iPhone",
            "owner@example.com",
            old_auth_token,
            recovery_token,
        )
        .await;

        let raw_code = encode_recovery_payload_pem(&RecoveryPayload {
            instance_id: instance_id.clone(),
            device_id: device_id.clone(),
            recovery_token: recovery_token.to_string(),
            server_base_url: "https://sync.example.com".to_string(),
        })
        .expect("encode recovery pem");

        let response = recover_from_code(
            State(state),
            Json(RecoverFromCodeRequest { raw_code: raw_code.clone() }),
        )
        .await
        .expect("plaintext recovery succeeds")
        .0;

        assert_eq!(response.device_id, device_id);
        assert_eq!(response.device_name, "Primary iPhone");
        assert_eq!(response.instance_id, instance_id);
        assert!(response.allow_plaintext);
        assert_eq!(response.instance_key, None);
        assert!(!response.auth_token.trim().is_empty());
        assert_ne!(response.auth_token, old_auth_token);

        let (stored_auth_hash, stored_recovery_hash) =
            sqlx::query_as::<_, (Option<String>, Option<String>)>(
                "SELECT auth_token, recovery_token_hash FROM devices WHERE id = $1",
            )
            .bind(&response.device_id)
            .fetch_one(&pool)
            .await
            .expect("load rotated device tokens");

        let rotated_auth_hash = hash_token(&response.auth_token);
        let original_recovery_hash = hash_token(recovery_token);

        assert_eq!(stored_auth_hash.as_deref(), Some(rotated_auth_hash.as_str()));
        assert_ne!(
            stored_recovery_hash.as_deref(),
            Some(original_recovery_hash.as_str())
        );
    }

    #[sqlx::test]
    async fn encrypted_recovery_returns_instance_key(pool: PgPool) {
        let state = test_state(pool.clone());
        let instance_id = Uuid::new_v4().to_string();
        let device_id = Uuid::new_v4().to_string();
        let auth_token = "existing-auth-token";
        let recovery_token = "encrypted-recovery-token";
        let instance_key = "U29tZUJhc2U2NEluc3RhbmNlS2V5MzJCeXRlcw==";

        insert_registered_device(
            &pool,
            &instance_id,
            &device_id,
            "Encrypted iPad",
            "owner@example.com",
            auth_token,
            recovery_token,
        )
        .await;

        let _ = upsert_recovery_bootstrap(
            State(state.clone()),
            Json(UpsertRecoveryBootstrapRequest {
                device_id: device_id.clone(),
                auth_token: auth_token.to_string(),
                allow_plaintext: false,
                instance_key: Some(instance_key.to_string()),
            }),
        )
        .await
        .expect("store encrypted recovery bootstrap");

        let raw_code = serde_json::json!({
            "deviceId": device_id,
            "recoveryToken": recovery_token,
            "serverBaseUrl": "https://sync.example.com"
        })
        .to_string();

        let response = recover_from_code(State(state), Json(RecoverFromCodeRequest { raw_code }))
            .await
            .expect("encrypted recovery succeeds")
            .0;

        assert!(!response.allow_plaintext);
        assert_eq!(response.instance_key.as_deref(), Some(instance_key));
        assert_eq!(response.instance_id, instance_id);
    }

    #[sqlx::test]
    async fn invalid_recovery_token_returns_401(pool: PgPool) {
        let state = test_state(pool.clone());
        let instance_id = Uuid::new_v4().to_string();
        let device_id = Uuid::new_v4().to_string();

        insert_registered_device(
            &pool,
            &instance_id,
            &device_id,
            "Broken Recovery",
            "owner@example.com",
            "auth-token",
            "valid-recovery-token",
        )
        .await;

        let error = recover_from_code(
            State(state),
            Json(RecoverFromCodeRequest {
                raw_code: serde_json::json!({
                    "deviceId": device_id,
                    "recoveryToken": "wrong-token"
                })
                .to_string(),
            }),
        )
        .await
        .expect_err("invalid token should fail");

        assert_eq!(error.into_response().status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test]
    async fn reused_recovery_token_returns_401_after_rotation(pool: PgPool) {
        let state = test_state(pool.clone());
        let instance_id = Uuid::new_v4().to_string();
        let device_id = Uuid::new_v4().to_string();
        let recovery_token = "single-use-recovery-token";

        insert_registered_device(
            &pool,
            &instance_id,
            &device_id,
            "Single Use Device",
            "owner@example.com",
            "auth-token",
            recovery_token,
        )
        .await;

        let raw_code = serde_json::json!({
            "deviceId": device_id,
            "recoveryToken": recovery_token
        })
        .to_string();

        let _ = recover_from_code(
            State(state.clone()),
            Json(RecoverFromCodeRequest {
                raw_code: raw_code.clone(),
            }),
        )
        .await
        .expect("first recovery succeeds");

        let error = recover_from_code(State(state), Json(RecoverFromCodeRequest { raw_code }))
            .await
            .expect_err("reused recovery token should fail");

        assert_eq!(error.into_response().status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    fn test_state(pool: PgPool) -> AppState {
        let (sync_event_tx, _) = broadcast::channel::<SyncEventNotification>(8);
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous("127.0.0.1")
            .port(2525)
            .build();
        let from: Mailbox = "Faktoro Sync <noreply@example.com>"
            .parse()
            .expect("valid mailbox");

        AppState {
            db: pool,
            mailer: MailerConfig { transport, from },
            sync_event_tx,
            public_base_url: "https://sync.example.com".to_string(),
        }
    }

    async fn insert_registered_device(
        pool: &PgPool,
        instance_id: &str,
        device_id: &str,
        device_name: &str,
        recovery_email: &str,
        auth_token: &str,
        recovery_token: &str,
    ) {
        sqlx::query(
            "INSERT INTO client_instances (id, recovery_email, created_at, updated_at, last_seen_at)
             VALUES ($1, $2, NOW(), NOW(), NOW())",
        )
        .bind(instance_id)
        .bind(recovery_email)
        .execute(pool)
        .await
        .expect("insert client instance");

        sqlx::query(
            "INSERT INTO devices (
                id,
                instance_id,
                name,
                pairing_token_hash,
                recovery_email,
                recovery_token_hash,
                is_registered,
                auth_token,
                created_at,
                registered_at,
                last_seen_at
             )
             VALUES ($1, $2, $3, $4, $5, $6, TRUE, $7, NOW(), NOW(), NOW())",
        )
        .bind(device_id)
        .bind(instance_id)
        .bind(device_name)
        .bind(hash_token("pairing-token"))
        .bind(recovery_email)
        .bind(hash_token(recovery_token))
        .bind(hash_token(auth_token))
        .execute(pool)
        .await
        .expect("insert registered device");
    }

    #[test]
    fn conflict_error_maps_to_409() {
        let response = AppError::conflict("missing bootstrap").into_response();
        assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    }
}
