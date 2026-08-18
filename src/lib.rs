// rockbase — PocketBase-shaped backend.
// Dynamic collections, JSON records in SQLite, JWT auth, SSE realtime.

pub mod auth;
pub mod backup;
pub mod collections;
pub mod db;
pub mod filter;
pub mod records;
pub mod realtime;
pub mod rules;

use std::sync::{Arc, Mutex};

use axum::{
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use rusqlite::Connection;
use serde_json::{json, Value};
use tokio::sync::broadcast;

pub struct App {
    // ponytail: single Mutex<Connection>, swap for r2d2 pool if concurrency matters
    pub db: Mutex<Connection>,
    pub events: broadcast::Sender<String>,
    pub jwt_secret: String,
    pub admin_token: String,
}

pub type S = Arc<App>;
pub type Reply = Result<Json<Value>, (StatusCode, Json<Value>)>;

pub fn err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (code, Json(json!({ "code": code.as_u16(), "message": msg.into() })))
}

pub fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub fn build_app(conn: Connection, admin_token: String) -> Router {
    db::harden(&conn);
    db::init_db(&conn);
    let jwt_secret = match std::env::var("RB_JWT_SECRET") {
        Ok(s) => s,
        Err(_) => db::param_get_or_create(
            &conn,
            "jwt_secret",
            &uuid::Uuid::new_v4().simple().to_string(),
        ),
    };
    let (tx, _) = broadcast::channel(64);
    let app = Arc::new(App {
        db: Mutex::new(conn),
        events: tx,
        jwt_secret,
        admin_token,
    });
    Router::new()
        .route("/api/health", get(health))
        .route(
            "/api/collections",
            get(collections::collections_list).post(collections::collections_create),
        )
        .route(
            "/api/collections/{name}",
            delete(collections::collections_delete).patch(collections::collections_update),
        )
        .route(
            "/api/collections/{name}/records",
            get(records::records_list).post(records::record_create),
        )
        .route(
            "/api/collections/{name}/records/{id}",
            get(records::record_view)
                .patch(records::record_update)
                .delete(records::record_delete),
        )
        .route(
            "/api/collections/{name}/auth-with-password",
            post(auth::auth_with_password),
        )
        .route("/api/collections/{name}/auth-refresh", post(auth::auth_refresh))
        .route("/api/backups", get(backup::backup_download))
        .route("/api/realtime", get(realtime::realtime))
        .with_state(app)
}
