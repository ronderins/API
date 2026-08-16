pub mod circuits;
pub mod cli;
pub mod compliance;
pub mod crypto;
pub mod crypto_core;
pub mod error;
pub mod handlers;
pub mod hsm;
pub mod identity;
pub mod merkle;
pub mod models;
pub mod mpc;
pub mod plonk;
pub mod privacy_engine;
pub mod sdk;
pub mod security;
pub mod smart_contracts;
pub mod store;
pub mod wasm;
pub mod zkp;
pub mod zkvm;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::store::Repository;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "zk_identity_api_rust=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let repo = Repository::new().await;
    let state = Arc::new(repo);

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/healthz", get(handlers::healthz))
        .route("/api/v1/session", get(handlers::create_session))
        .route("/api/v1/verify", post(handlers::create_verify_proof))
        .route("/api/v1/verify-token", post(handlers::verify_token))
        .route("/api/v1/verify-merkle", post(handlers::verify_merkle_inclusion))
        .route("/api/v1/proofs/:id", get(handlers::get_proof))
        .route("/api/v1/proofs", get(handlers::list_proofs))
        .route("/api/v1/ledger", get(handlers::get_ledger))
        .route("/api/v1/metrics", get(handlers::get_metrics))
        .route("/api/v1/stats", get(handlers::get_stats))
        .layer(cors)
        .with_state(state);

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("[Rust ZK-Identity API v0.2.0] listening on http://{}", addr);
    println!("Active: Zeroize Memory Lockdown | Blake3 Receipt Ledger | Blind QR Sessions | Sysinfo Telemetry | Canary Dead-Man Switch");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
