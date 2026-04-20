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
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::cors::CorsLayer;
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
    spawn_sync_events_cleanup(db.clone());

    let public_base_url = env::var("PUBLIC_BASE_URL")
        .unwrap_or_default()
        .trim_end_matches('/')
        .to_string();

    let state = AppState {
        db,
        mailer,
        sync_event_tx,
        public_base_url: public_base_url.clone(),
    };

    let body_limit: usize = env::var("REQUEST_BODY_LIMIT_BYTES")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(50 * 1024 * 1024);
    info!(body_limit_bytes = body_limit, "Request body limit configured");

    let common_burst: u32 = env::var("RATE_LIMIT_COMMON_BURST")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(60);
    let common_per_second: u64 = env::var("RATE_LIMIT_COMMON_PER_SECOND")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let sensitive_burst: u32 = env::var("RATE_LIMIT_SENSITIVE_BURST")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(5);
    let sensitive_per_second: u64 = env::var("RATE_LIMIT_SENSITIVE_PER_SECOND")
        .ok().and_then(|v| v.parse().ok()).unwrap_or(12);

    info!(
        common_burst, common_per_second,
        sensitive_burst, sensitive_per_second,
        "Rate limiting configured"
    );

    let sensitive_governor = GovernorLayer::new(
        GovernorConfigBuilder::default()
            .per_second(sensitive_per_second)
            .burst_size(sensitive_burst)
            .finish()
            .expect("sensitive rate limiter config"),
    );

    let common_governor = GovernorLayer::new(
        GovernorConfigBuilder::default()
            .per_second(common_per_second)
            .burst_size(common_burst)
            .finish()
            .expect("common rate limiter config"),
    );

    let sensitive_routes = Router::new()
        .route("/api/pairing/init", post(handlers::devices::pairing_init))
        .route(
            "/api/devices/register-from-scan",
            post(handlers::devices::register_from_scan),
        )
        .route(
            "/api/sync/recovery-bootstrap",
            post(handlers::devices::upsert_recovery_bootstrap),
        )
        .route(
            "/api/devices/recover-from-code",
            post(handlers::devices::recover_from_code),
        )
        .layer(sensitive_governor);

    let app = Router::new()
        .route("/", get(handlers::meta::root))
        .route("/health", get(handlers::meta::health))
        .route("/docs", get(handlers::meta::docs_index))
        .route("/openapi.yaml", get(handlers::meta::openapi_yaml))
        .route("/api/pair/qr", get(handlers::pairing::pair_qr))
        .route(
            "/api/devices/forget-registration",
            post(handlers::devices::forget_registration),
        )
        .route("/api/devices", get(handlers::devices::list_devices))
        .route("/api/devices/remove", post(handlers::devices::remove_device))
        .route("/api/sync/events/pull", post(handlers::sync_events::sync_events_pull))
        .route("/api/sync/events/ws", get(handlers::sync_events_ws::sync_events_ws))
        .route("/api/sync/online/pull", post(handlers::sync::sync_online_pull))
        .route("/api/sync/online/push", post(handlers::sync::sync_online_push))
        .route("/api/sync/push", post(handlers::sync::sync_push))
        .route("/api/sync/pull", post(handlers::sync::sync_pull))
        .merge(sensitive_routes)
        .layer(common_governor)
        .layer(tower_http::limit::RequestBodyLimitLayer::new(body_limit))
        .layer(build_cors_layer(&public_base_url))
        .layer(axum::middleware::from_fn(security_headers))
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
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

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

async fn security_headers(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(axum::http::header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    headers.insert(axum::http::header::STRICT_TRANSPORT_SECURITY, "max-age=63072000; includeSubDomains".parse().unwrap());
    headers.insert(axum::http::header::CONTENT_SECURITY_POLICY, "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:".parse().unwrap());
    response
}

fn spawn_sync_events_cleanup(db: PgPool) {
    const RETENTION_DAYS: i64 = 30;
    const CLEANUP_INTERVAL_HOURS: u64 = 6;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_HOURS * 3600));
        interval.tick().await;

        loop {
            interval.tick().await;

            let cutoff_ms = (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64)
                - (RETENTION_DAYS * 24 * 3600 * 1000);

            match sqlx::query("DELETE FROM instance_sync_events WHERE created_at_ms < $1")
                .bind(cutoff_ms)
                .execute(&db)
                .await
            {
                Ok(result) => {
                    let count = result.rows_affected();
                    if count > 0 {
                        info!(deleted = count, retention_days = RETENTION_DAYS, "Sync events cleanup completed");
                    }
                }
                Err(error) => {
                    warn!("Sync events cleanup failed: {error}");
                }
            }
        }
    });
}

fn build_cors_layer(public_base_url: &str) -> CorsLayer {
    use axum::http::{header, Method};
    use tower_http::cors::AllowOrigin;

    let origin = public_base_url.to_string();

    if origin.is_empty() {
        warn!("PUBLIC_BASE_URL is not set, CORS will reject all cross-origin requests");
        return CorsLayer::new();
    }

    info!(cors_origin = %origin, "CORS allowed origin");

    CorsLayer::new()
        .allow_origin(AllowOrigin::exact(origin.parse().expect("PUBLIC_BASE_URL must be a valid header value")))
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_methods([Method::GET, Method::POST])
}
