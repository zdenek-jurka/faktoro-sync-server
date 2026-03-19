use crate::app_state::{AppState, SyncEventNotification};
use crate::auth::authorize_registered_device;
use crate::error::AppError;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::warn;

#[derive(Debug, Deserialize)]
pub struct SyncEventsWsQuery {
    pub device_id: String,
    pub auth_token: String,
}

#[derive(Debug, Serialize)]
pub struct SyncEventsWsItem {
    pub source_device_id: String,
    pub event_type: String,
    pub timestamp: i64,
    pub payload: serde_json::Value,
}

pub async fn sync_events_ws(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Query(query): Query<SyncEventsWsQuery>,
) -> Result<Response, AppError> {
    let auth = authorize_registered_device(&state.db, &query.device_id, &query.auth_token).await?;
    let instance_id = auth.instance_id;
    let own_device_id = auth.device_id;
    let receiver = state.sync_event_tx.subscribe();

    Ok(ws.on_upgrade(move |socket| async move {
        handle_ws(socket, receiver, instance_id, own_device_id).await;
    }))
}

async fn handle_ws(
    socket: WebSocket,
    mut receiver: broadcast::Receiver<SyncEventNotification>,
    instance_id: String,
    own_device_id: String,
) {
    let (mut sender, mut inbound) = socket.split();

    loop {
        tokio::select! {
            maybe_msg = inbound.next() => {
                match maybe_msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(error)) => {
                        warn!("WebSocket receive error: {error}");
                        break;
                    }
                }
            }
            event = receiver.recv() => {
                match event {
                    Ok(event) => {
                        if event.instance_id != instance_id || event.source_device_id == own_device_id {
                            continue;
                        }

                        let outgoing = SyncEventsWsItem {
                            source_device_id: event.source_device_id,
                            event_type: event.event_type,
                            timestamp: event.timestamp,
                            payload: event.payload,
                        };

                        let Ok(serialized) = serde_json::to_string(&outgoing) else {
                            continue;
                        };

                        if sender.send(Message::Text(serialized.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!("WebSocket sync-events receiver lagged, skipped {skipped} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}
