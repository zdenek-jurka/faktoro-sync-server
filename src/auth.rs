use crate::crypto::hash_token;
use crate::error::AppError;
use axum::http::HeaderMap;
use sqlx::PgPool;

#[derive(Debug, Clone)]
pub struct DeviceAuthContext {
    pub device_id: String,
    pub instance_id: String,
}

pub async fn authorize_registered_device(
    db: &PgPool,
    device_id: &str,
    auth_token: &str,
) -> Result<DeviceAuthContext, AppError> {
    let token_hash = hash_token(auth_token);
    let found = sqlx::query_as::<_, (String, bool)>(
        "SELECT instance_id, is_registered
         FROM devices
         WHERE id = $1 AND auth_token = $2",
    )
    .bind(device_id)
    .bind(&token_hash)
    .fetch_optional(db)
    .await
    .map_err(AppError::internal)?;

    match found {
        Some((instance_id, true)) => {
            sqlx::query("UPDATE devices SET last_seen_at = NOW() WHERE id = $1")
                .bind(device_id)
                .execute(db)
                .await
                .map_err(AppError::internal)?;

            sqlx::query(
                "UPDATE client_instances
                 SET last_seen_at = NOW(), updated_at = NOW()
                 WHERE id = $1",
            )
            .bind(&instance_id)
            .execute(db)
            .await
            .map_err(AppError::internal)?;

            Ok(DeviceAuthContext {
                device_id: device_id.to_string(),
                instance_id,
            })
        }
        _ => Err(AppError::unauthorized("Invalid device auth token")),
    }
}

pub struct HeaderCredentials {
    pub device_id: String,
    pub auth_token: String,
}

pub fn extract_credentials_from_headers(headers: &HeaderMap) -> Option<HeaderCredentials> {
    let auth_header = headers.get("authorization")?.to_str().ok()?;
    let auth_token = auth_header.strip_prefix("Bearer ")?.trim().to_string();
    if auth_token.is_empty() {
        return None;
    }

    let device_id = headers
        .get("x-device-id")?
        .to_str()
        .ok()?
        .trim()
        .to_string();
    if device_id.is_empty() {
        return None;
    }

    Some(HeaderCredentials {
        device_id,
        auth_token,
    })
}
