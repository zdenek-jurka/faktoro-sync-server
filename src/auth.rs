use crate::error::AppError;
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
    let found = sqlx::query_as::<_, (String, bool)>(
        "SELECT instance_id, is_registered
         FROM devices
         WHERE id = $1 AND auth_token = $2",
    )
    .bind(device_id)
    .bind(auth_token)
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
