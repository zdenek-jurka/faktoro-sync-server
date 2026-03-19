use crate::mailer::MailerConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEventNotification {
    pub instance_id: String,
    pub source_device_id: String,
    pub event_type: String,
    pub timestamp: i64,
    pub payload: Value,
}

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub mailer: MailerConfig,
    pub sync_event_tx: broadcast::Sender<SyncEventNotification>,
}
