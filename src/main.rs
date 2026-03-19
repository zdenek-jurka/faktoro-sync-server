mod app_state;
mod auth;
mod crypto;
mod error;
mod handlers;
mod mailer;
mod payloads;

use app_state::AppState;
use axum::routing::{get, post};
use axum::Router;
use mailer::build_mailer_from_env;
use sqlx::postgres::PgListener;
use sqlx::migrate::Migrator;
use sqlx::PgPool;
use std::env;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::broadcast;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");
const SYNC_EVENTS_CHANNEL: &str = "faktoro_sync_events";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "faktoro_sync_server=info,tower_http=info".into()),
        )
        .init();

    let database_url =
        env::var("DATABASE_URL").expect("DATABASE_URL must be set (postgres connection string)");

    let db = PgPool::connect(&database_url).await?;
    let before_version = read_db_migration_version(&db).await?;
    info!("DB migration version before startup: {before_version}");

    MIGRATOR.run(&db).await?;
    let after_version = read_db_migration_version(&db).await?;
    info!("DB migration version after startup: {after_version}");

    let mailer = build_mailer_from_env()?;
    let (sync_event_tx, _) = broadcast::channel(1024);
    spawn_pg_notify_bridge(database_url.clone(), sync_event_tx.clone());

    let state = AppState {
        db,
        mailer,
        sync_event_tx,
    };

    let app = Router::new()
        .route("/", get(handlers::meta::root))
        .route("/health", get(handlers::meta::health))
        .route("/docs", get(handlers::meta::docs_index))
        .route("/openapi.yaml", get(handlers::meta::openapi_yaml))
        .route("/api/pair/bootstrap", get(handlers::pairing::pair_bootstrap))
        .route("/api/pair/qr", get(handlers::pairing::pair_qr))
        .route("/api/pairing/init", post(handlers::devices::pairing_init))
        .route(
            "/api/devices/register-from-scan",
            post(handlers::devices::register_from_scan),
        )
        .route(
            "/api/devices/recover-from-code",
            post(handlers::devices::recover_from_code),
        )
        .route(
            "/api/devices/forget-registration",
            post(handlers::devices::forget_registration),
        )
        .route("/api/devices", get(handlers::devices::list_devices))
        .route("/api/devices/remove", post(handlers::devices::remove_device))
        .route("/api/sync/events/pull", post(handlers::sync_events::sync_events_pull))
        .route("/api/sync/events/ws", get(handlers::sync_events_ws::sync_events_ws))
        .route(
            "/api/crypto/device-public-key",
            post(handlers::crypto_keys::upsert_device_public_key)
                .get(handlers::crypto_keys::get_device_public_key),
        )
        .route(
            "/api/crypto/instance-key-envelope",
            post(handlers::crypto_keys::upsert_instance_key_envelope)
                .get(handlers::crypto_keys::get_instance_key_envelope),
        )
        .route("/api/sync/online/pull", post(handlers::sync::sync_online_pull))
        .route("/api/sync/online/push", post(handlers::sync::sync_online_push))
        .route("/api/sync/push", post(handlers::sync::sync_push))
        .route("/api/sync/pull", post(handlers::sync::sync_pull))
        .layer(CorsLayer::new().allow_origin(Any).allow_headers(Any).allow_methods(Any))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse()
        .expect("PORT must be a valid number");
    let addr: SocketAddr = format!("{host}:{port}").parse()?;

    info!("Listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn read_db_migration_version(db: &PgPool) -> anyhow::Result<i64> {
    let (migrations_table_exists,) =
        sqlx::query_as::<_, (bool,)>("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(db)
            .await?;

    if !migrations_table_exists {
        return Ok(0);
    }

    let (version,) =
        sqlx::query_as::<_, (i64,)>("SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success = TRUE")
    .fetch_one(db)
    .await?;

    Ok(version)
}

fn spawn_pg_notify_bridge(database_url: String, sync_event_tx: broadcast::Sender<app_state::SyncEventNotification>) {
    tokio::spawn(async move {
        loop {
            match PgListener::connect(&database_url).await {
                Ok(mut listener) => {
                    info!("Connected PG LISTEN/NOTIFY bridge");
                    if let Err(error) = listener.listen(SYNC_EVENTS_CHANNEL).await {
                        warn!("Failed to LISTEN on channel '{SYNC_EVENTS_CHANNEL}': {error}");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }

                    loop {
                        match listener.recv().await {
                            Ok(notification) => {
                                let payload = notification.payload();
                                match serde_json::from_str::<app_state::SyncEventNotification>(payload) {
                                    Ok(event) => {
                                        let _ = sync_event_tx.send(event);
                                    }
                                    Err(error) => {
                                        warn!("Invalid sync event payload from PG NOTIFY: {error}");
                                    }
                                }
                            }
                            Err(error) => {
                                warn!("PG NOTIFY receive failed: {error}");
                                break;
                            }
                        }
                    }
                }
                Err(error) => {
                    warn!("PG LISTEN/NOTIFY bridge connect failed: {error}");
                }
            }

            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}
