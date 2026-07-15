mod auth;
mod config;
mod crypto;
mod db;
mod error;
mod handlers;
mod models;

use std::sync::Arc;

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use sqlx::postgres::PgPoolOptions;
use tokio::signal;

#[derive(Clone)]
pub struct AppState {
    pool: sqlx::PgPool,
    config: Arc<config::Config>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = config::Config::from_env()?;

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&cfg.database_url)
        .await?;

    // Сервис владеет своей схемой самостоятельно — идемпотентно, без
    // внешнего migration-раннера. См. migrations/0001_init.sql.
    sqlx::migrate!("./migrations").run(&pool).await?;

    let state = AppState {
        pool,
        config: Arc::new(cfg),
    };

    let bind_addr = state.config.bind_addr.clone();

    let app = Router::new()
        .route("/healthz", get(handlers::health))
        .route(
            "/internal/v1/keys/identity",
            put(handlers::put_identity_keys),
        )
        .route(
            "/internal/v1/keys/signed-prekey",
            put(handlers::put_signed_prekey),
        )
        .route(
            "/internal/v1/keys/one-time-prekeys",
            post(handlers::post_one_time_prekeys),
        )
        .route(
            "/internal/v1/keys/one-time-prekeys/count",
            get(handlers::get_one_time_prekey_count),
        )
        .route(
            "/internal/v1/keys/bundle/:target_user_id",
            get(handlers::get_bundle),
        )
        .route("/internal/v1/keys", delete(handlers::delete_keys))
        .with_state(state);

    tracing::info!(%bind_addr, "e2ee-key-server listening");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
