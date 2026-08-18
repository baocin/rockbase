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
    routing::{get, post},
    Json, Router,
};
use rusqlite::Connection;
use serde_json::{json, Value};
use tokio::sync::broadcast;

pub struct App {
    // ponytail: single Mutex<Connection>, swap for r2d2 pool if concurrency matters
    pub db: Mutex<Connection>,
    pub events: broadcast::Sender<Value>,
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

// ponytail: permissive CORS (allow *, no credentials), split per-origin if anyone needs cookies.
// Also the request log — same wrap, so one layer instead of two.
async fn cors_and_log(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start = std::time::Instant::now();
    // preflight short-circuits before routing, so unregistered OPTIONS is 204, not 404/405
    let mut resp = if method == axum::http::Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let hv = axum::http::HeaderValue::from_static;
    let h = resp.headers_mut();
    h.insert("access-control-allow-origin", hv("*"));
    h.insert(
        "access-control-allow-methods",
        hv("GET, POST, PATCH, DELETE, OPTIONS"),
    );
    h.insert(
        "access-control-allow-headers",
        hv("Authorization, Content-Type"),
    );
    println!(
        "{method} {path} {} {}ms",
        resp.status().as_u16(),
        start.elapsed().as_millis()
    );
    resp
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
            get(collections::collections_get)
                .patch(collections::collections_update)
                .delete(collections::collections_delete),
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
        .layer(axum::middleware::from_fn(cors_and_log))
        .with_state(app)
}
