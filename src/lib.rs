// rockbase — PocketBase-shaped backend.
// Dynamic collections, JSON records in SQLite, JWT auth, SSE realtime.

pub mod auth;
pub mod backup;
pub mod batch;
pub mod collections;
pub mod db;
pub mod files;
pub mod filter;
pub mod realtime;
pub mod records;
pub mod rules;

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use tokio::sync::broadcast;

pub struct App {
    /// Hand-rolled connection pool (`db::Pool`) — handlers check a connection out
    /// for the duration of one synchronous stretch and the guard returns it on drop.
    /// Never hold one across an `.await`.
    pub db: db::Pool,
    pub events: broadcast::Sender<Value>,
    pub jwt_secret: String,
    pub admin_token: String,
    /// Bumped by every _collections create/update/delete. Long-lived readers (SSE)
    /// cache per-collection rules and drop the cache when this changes, so an admin
    /// editing a rule still applies to already-open subscriptions.
    pub cols_version: AtomicU64,
    /// Consecutive failed logins per (collection, identity), with the time of the last
    /// one. `auth::auth_with_password` refuses an identity that crossed the limit until
    /// its cooldown expires; a good login clears the entry.
    ///
    /// ponytail: in-process map, no dependency and no eviction thread — stale entries
    /// are dropped when the identity is seen again. Move it into SQLite (or Redis) if
    /// rockbase ever runs as more than one process.
    pub login_fails: Mutex<HashMap<(String, String), (u32, Instant)>>,
    /// `RB_CORS_ORIGINS`, split on commas and trimmed. Empty = the wide-open `*`
    /// default that local dev and the test suite rely on.
    pub cors_origins: Vec<String>,
}

pub type S = Arc<App>;
pub type Reply = Result<Json<Value>, (StatusCode, Json<Value>)>;

pub fn err(code: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<Value>) {
    (
        code,
        Json(json!({ "code": code.as_u16(), "message": msg.into() })),
    )
}

pub fn ident_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// One round trip that proves the database FILE is reachable, not merely that the
/// library links: `sqlite_version()` is answered from memory, but the `_params`
/// subquery has to read a real page. O(1) — `_params` holds a handful of rows and
/// never grows with user data, and its count is deliberately not in the body.
pub fn db_status(conn: &rusqlite::Connection) -> Result<Value, rusqlite::Error> {
    let (sqlite, _params): (String, i64) = conn.query_row(
        "SELECT sqlite_version(), (SELECT count(*) FROM _params)",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(json!({ "status": "ok", "db": "ok", "sqlite": sqlite }))
}

/// Fail closed: an unreadable database is 503, never a panic and never a false 200.
fn health_reply(status: Result<Value, rusqlite::Error>) -> (StatusCode, Json<Value>) {
    match status {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "error", "db": "error", "error": e.to_string() })),
        ),
    }
}

async fn health(axum::extract::State(s): axum::extract::State<S>) -> (StatusCode, Json<Value>) {
    // The guard is dropped on this line: a load-balancer poll holds a connection for
    // one cheap query and never blocks a real request behind it.
    let status = db_status(&s.db.get());
    health_reply(status)
}

// Compile-time constant on purpose: nothing runtime (admin token, jwt secret) is ever
// templated into it, so every server serves byte-identical HTML. The token is typed
// by the user in the browser and kept in localStorage.
const ADMIN_HTML: &str = include_str!("../assets/admin.html");

async fn admin_ui() -> axum::response::Html<&'static str> {
    axum::response::Html(ADMIN_HTML)
}

// CORS plus the request log — same wrap, so one layer instead of two. No credentials
// either way, so `*` stays a safe default; `RB_CORS_ORIGINS` narrows it to an allowlist.
async fn cors_and_log(
    axum::extract::State(s): axum::extract::State<S>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let start = std::time::Instant::now();
    // preflight short-circuits before routing, so unregistered OPTIONS is 204, not 404/405
    let mut resp = if method == axum::http::Method::OPTIONS {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let hv = axum::http::HeaderValue::from_static;
    let h = resp.headers_mut();
    if s.cors_origins.is_empty() {
        h.insert("access-control-allow-origin", hv("*"));
    } else {
        // The response now depends on the request's Origin, so a shared cache must not
        // reuse one origin's allow header for another. A rejected origin gets no
        // allow-origin header at all — the status is untouched, the browser blocks it.
        h.insert("vary", hv("Origin"));
        if let Some(v) = origin
            .filter(|o| s.cors_origins.iter().any(|a| a == o))
            .and_then(|o| axum::http::HeaderValue::from_str(&o).ok())
        {
            h.insert("access-control-allow-origin", v);
        }
    }
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

/// `db` is a filesystem path or `":memory:"`; the pool opens its own connections
/// (each already hardened — WAL + busy_timeout).
pub fn build_app(db: &str, admin_token: String) -> Router {
    let pool = db::Pool::open(db, db::pool_size());
    db::init_db(&pool.get());
    let jwt_secret = match std::env::var("RB_JWT_SECRET") {
        Ok(s) => s,
        Err(_) => db::param_get_or_create(
            &pool.get(),
            "jwt_secret",
            &uuid::Uuid::new_v4().simple().to_string(),
        ),
    };
    let (tx, _) = broadcast::channel(64);
    let app = Arc::new(App {
        db: pool,
        events: tx,
        jwt_secret,
        admin_token,
        cols_version: AtomicU64::new(0),
        login_fails: Mutex::default(),
        // Read here, not in `main`: `build_app` is what 16 test files call, and its
        // signature is fixed — same reasoning as RB_JWT_SECRET above.
        cors_origins: std::env::var("RB_CORS_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|o| !o.is_empty())
            .map(str::to_string)
            .collect(),
    });
    Router::new()
        .route("/api/health", get(health))
        .route("/api/batch", post(batch::batch))
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
        .route(
            "/api/collections/{name}/auth-refresh",
            post(auth::auth_refresh),
        )
        .route(
            "/api/collections/{name}/request-password-reset",
            post(auth::request_password_reset),
        )
        .route(
            "/api/collections/{name}/confirm-password-reset",
            post(auth::confirm_password_reset),
        )
        .route(
            "/api/collections/{name}/request-verification",
            post(auth::request_verification),
        )
        .route(
            "/api/collections/{name}/confirm-verification",
            post(auth::confirm_verification),
        )
        // The only place a reset/verification token can be read back: the mailer hook.
        .route("/api/tokens", get(auth::tokens_list))
        .route(
            "/api/files/{collection}/{id}/{filename}",
            get(files::file_serve),
        )
        .route("/api/backups", get(backup::backup_download))
        .route("/api/realtime", get(realtime::realtime))
        // ponytail: three literal routes, no wildcard — one HTML file is the whole UI.
        // axum 0.8 does not redirect trailing slashes, so `/_` and `/_/` are both real.
        .route("/_", get(admin_ui))
        .route("/_/", get(admin_ui))
        .route("/_/index.html", get(admin_ui))
        // axum's default is 2MB; this raises it and caps multipart uploads, which
        // turn into 413 mid-stream — before the row or the bytes are written
        .layer(axum::extract::DefaultBodyLimit::max(files::MAX_BODY))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            cors_and_log,
        ))
        .with_state(app)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 503 path cannot be reached from outside the process — once the server owns
    /// the connection, deleting the file leaves the open fd working and WAL keeps a
    /// shared lock for the connection's lifetime (see the note at the bottom of
    /// tests/ops.rs). So break the connection from in here instead: drop the table the
    /// check reads, which is exactly what a corrupt or truncated database looks like to
    /// the query. It must degrade to 503, not panic.
    #[test]
    fn unreadable_database_is_503_not_a_panic() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::init_db(&conn);
        let (ok, body) = health_reply(db_status(&conn));
        assert_eq!(ok, StatusCode::OK, "{:?}", body.0);
        assert_eq!(body.0["db"], "ok");
        assert!(body.0["sqlite"].is_string(), "{:?}", body.0);

        conn.execute_batch("DROP TABLE _params").unwrap();
        let status = db_status(&conn);
        assert!(status.is_err(), "a missing table must not read as healthy");
        let (code, body) = health_reply(status);
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body.0["status"], "error");
        assert_eq!(body.0["db"], "error");
    }
}
