use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::db::get_collection;
use crate::records::{fetch_record, record_json};
use crate::{err, App, Reply, S};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub col: String,
    pub exp: u64,
}

pub enum Who {
    Admin,
    User { col: String, id: String },
    Guest,
}

/// Decode a bare JWT into a user identity. `None` for anything invalid — bad
/// signature, expired, malformed — and also for a token whose user has since been
/// deleted, which behaves exactly like no token at all.
///
/// ponytail: this locks app.db itself — never call it while already holding the
/// lock. Every call site resolves identity before the handler takes the lock.
fn from_jwt(app: &App, t: &str) -> Option<Who> {
    let t = decode::<Claims>(
        t,
        &DecodingKey::from_secret(app.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .ok()?;
    let c = t.claims;
    let db = app.db.lock().unwrap();
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE collection = ?1 AND id = ?2)",
            params![c.col, c.sub],
            |r| r.get(0),
        )
        .unwrap_or(false);
    exists.then_some(Who::User {
        col: c.col,
        id: c.sub,
    })
}

/// Resolve a bare credential carrying no scheme prefix — either the admin token or
/// a JWT. This exists solely for the SSE `?token=` fallback, because browser
/// `EventSource` cannot set an Authorization header.
///
/// SSE ONLY. Do NOT wire this into `who()`. A credential in a URL leaks into access
/// logs, browser history, and `Referer` headers, so it must not become a general
/// purpose auth mechanism — `tests/sse_token.rs` asserts the REST API still refuses it.
pub fn who_from_query_token(app: &App, t: &str) -> Who {
    if t == app.admin_token {
        return Who::Admin;
    }
    from_jwt(app, t).unwrap_or(Who::Guest)
}

pub fn who(app: &App, headers: &HeaderMap) -> Who {
    let Some(h) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Who::Guest;
    };
    if let Some(t) = h.strip_prefix("Admin ") {
        if t == app.admin_token {
            return Who::Admin;
        }
    }
    if let Some(t) = h.strip_prefix("Bearer ") {
        if let Some(w) = from_jwt(app, t) {
            return w;
        }
    }
    Who::Guest
}

pub fn require_admin(app: &App, headers: &HeaderMap) -> Result<(), (StatusCode, Json<Value>)> {
    match who(app, headers) {
        Who::Admin => Ok(()),
        _ => Err(err(StatusCode::UNAUTHORIZED, "admin token required")),
    }
}

fn make_token(app: &App, col: &str, id: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 7 * 24 * 3600;
    let claims = Claims {
        sub: id.into(),
        col: col.into(),
        exp,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(app.jwt_secret.as_bytes()),
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

// PocketBase-shaped: valid Bearer of this same collection gets a fresh 7-day
// token plus its record. Admin tokens are rejected (an admin is not an auth record).
pub async fn auth_refresh(
    State(app): State<S>,
    Path(name): Path<String>,
    headers: HeaderMap,
) -> Reply {
    let Who::User { col, id } = who(&app, &headers) else {
        return Err(err(StatusCode::UNAUTHORIZED, "auth token required"));
    };
    if col != name {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "token is for another collection",
        ));
    }
    // ponytail: no auth-collection type check — a User token only ever names an
    // auth collection, and who() already proved the record exists there.
    let token = make_token(&app, &col, &id)?;
    let db = app.db.lock().unwrap();
    let Some((data, created, updated)) = fetch_record(&db, &name, &id) else {
        return Err(err(StatusCode::NOT_FOUND, "record not found")); // race: deleted since who()
    };
    Ok(Json(json!({
        "token": token,
        "record": record_json(&name, &id, &data, &created, &updated),
    })))
}

pub async fn auth_with_password(
    State(app): State<S>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let db = app.db.lock().unwrap();
    // ponytail: auth-with-password is deliberately not rule-gated — the login
    // endpoint has to work before the caller has any identity to test.
    let Some(col) = get_collection(&db, &name) else {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    };
    if col.ty != "auth" {
        return Err(err(StatusCode::BAD_REQUEST, "not an auth collection"));
    }
    let identity = body.get("identity").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let row = db
        .query_row(
            "SELECT id, data, created, updated FROM records \
             WHERE collection = ?1 AND json_extract(data, '$.email') = ?2",
            params![name, identity],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            },
        )
        .ok();
    let Some((id, data, created, updated)) = row else {
        return Err(err(StatusCode::BAD_REQUEST, "invalid credentials"));
    };
    let parsed: Map<String, Value> = serde_json::from_str(&data).unwrap_or_default();
    let hash = parsed
        .get("password_hash")
        .and_then(|h| h.as_str())
        .unwrap_or("");
    if !bcrypt::verify(password, hash).unwrap_or(false) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid credentials"));
    }
    let token = make_token(&app, &name, &id)?;
    Ok(Json(json!({
        "token": token,
        "record": record_json(&name, &id, &data, &created, &updated),
    })))
}
