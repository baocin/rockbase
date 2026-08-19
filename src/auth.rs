use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
use crate::records::{fetch_record, record_json, token_epoch};
use crate::{err, App, Reply, S};

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub col: String,
    pub exp: u64,
    /// Revocation epoch the token was minted against; `from_jwt` refuses it once the
    /// record has moved past it. Defaulted so tokens issued before revocation existed
    /// decode as 0 — the same value a record without a stored epoch reads as — instead
    /// of failing to deserialize and 500ing.
    #[serde(default)]
    pub epoch: i64,
}

/// Consecutive failed logins allowed per identity before the cooldown starts.
const MAX_FAILS: u32 = 5;
/// How long a locked-out identity stays locked out, counted from its last failure.
const COOLDOWN: Duration = Duration::from_secs(15 * 60);

pub enum Who {
    Admin,
    User { col: String, id: String },
    Guest,
}

/// Decode a bare JWT into a user identity. `None` for anything invalid — bad
/// signature, expired, malformed — and also for a token whose user has since been
/// deleted or whose epoch the record has moved past. All of them behave exactly like
/// no token at all: Guest, never a half-authenticated user and never a 500.
///
/// ponytail: this checks a pooled connection out itself — never call it while
/// already holding one. Every call site resolves identity before the handler
/// checks out, so no request ever needs two connections (which could deadlock a
/// fully checked-out pool).
fn from_jwt(app: &App, t: &str) -> Option<Who> {
    let t = decode::<Claims>(
        t,
        &DecodingKey::from_secret(app.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .ok()?;
    let c = t.claims;
    let db = app.db.get();
    // Fail closed twice over: no row and an unreadable row both resolve to no identity.
    let data: String = db
        .query_row(
            "SELECT data FROM records WHERE collection = ?1 AND id = ?2",
            params![c.col, c.sub],
            |r| r.get(0),
        )
        .ok()?; // deleted since the token was issued
    (token_epoch(&data) == Some(c.epoch)).then_some(Who::User {
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
    if ct_eq(t, &app.admin_token) {
        return Who::Admin;
    }
    from_jwt(app, t).unwrap_or(Who::Guest)
}

/// Constant-time comparison for the admin token.
///
/// `==` on `str` short-circuits at the first differing byte, so response time leaks
/// how long a correct prefix was — a remote attacker can recover the token byte by
/// byte given enough samples. This token is a bearer credential to the entire
/// database, so the few lines are worth it.
///
/// ponytail: the length check still leaks the length. That is a poor oracle against a
/// random token, and hiding it would mean hashing both sides; revisit if tokens ever
/// become user-chosen.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn who(app: &App, headers: &HeaderMap) -> Who {
    let Some(h) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Who::Guest;
    };
    if let Some(t) = h.strip_prefix("Admin ") {
        if ct_eq(t, &app.admin_token) {
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

fn make_token(
    app: &App,
    col: &str,
    id: &str,
    epoch: i64,
) -> Result<String, (StatusCode, Json<Value>)> {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 7 * 24 * 3600;
    let claims = Claims {
        sub: id.into(),
        col: col.into(),
        exp,
        epoch,
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
    // The record is read first because the fresh token has to carry the CURRENT epoch;
    // still one checkout, and make_token never touches the pool.
    let db = app.db.get();
    let Some((data, created, updated)) = fetch_record(&db, &name, &id) else {
        return Err(err(StatusCode::NOT_FOUND, "record not found")); // race: deleted since who()
    };
    let Some(epoch) = token_epoch(&data) else {
        return Err(err(StatusCode::UNAUTHORIZED, "auth token required"));
    };
    let token = make_token(&app, &col, &id, epoch)?;
    Ok(Json(json!({
        "token": token,
        "record": record_json(&name, &id, &data, &created, &updated),
    })))
}

/// Failed-login bookkeeping, keyed by (collection, identity). Never global: one
/// account is locked by six fumbled logins, and a global counter would let that lock
/// out everyone else too — the cheapest denial of service in the codebase.
///
/// Only ever taken for a few statements and never while acquiring a pooled connection,
/// so it cannot participate in a deadlock with the pool.
fn login_fails(app: &App) -> std::sync::MutexGuard<'_, HashMap<(String, String), (u32, Instant)>> {
    app.login_fails.lock().unwrap_or_else(|e| e.into_inner())
}

pub async fn auth_with_password(
    State(app): State<S>,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    let identity = body.get("identity").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let key = (name.clone(), identity.to_string());
    // Before the checkout, so a throttled caller never even takes a connection.
    {
        let mut fails = login_fails(&app);
        if let Some(&(n, at)) = fails.get(&key) {
            if n >= MAX_FAILS {
                if at.elapsed() < COOLDOWN {
                    // A correct password does not help either — otherwise the throttle
                    // is a hint about how close the last guess was.
                    return Err(err(
                        StatusCode::TOO_MANY_REQUESTS,
                        "too many failed login attempts, try again later",
                    ));
                }
                fails.remove(&key); // cooldown served
            }
        }
    }
    let reject = || {
        let mut fails = login_fails(&app);
        let slot = fails.entry(key.clone()).or_insert((0, Instant::now()));
        slot.0 += 1;
        slot.1 = Instant::now();
        err(StatusCode::BAD_REQUEST, "invalid credentials")
    };
    let db = app.db.get();
    // ponytail: auth-with-password is deliberately not rule-gated — the login
    // endpoint has to work before the caller has any identity to test.
    let Some(col) = get_collection(&db, &name) else {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    };
    if col.ty != "auth" {
        return Err(err(StatusCode::BAD_REQUEST, "not an auth collection"));
    }
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
        return Err(reject());
    };
    let parsed: Map<String, Value> = serde_json::from_str(&data).unwrap_or_default();
    let hash = parsed
        .get("password_hash")
        .and_then(|h| h.as_str())
        .unwrap_or("");
    if !bcrypt::verify(password, hash).unwrap_or(false) {
        return Err(reject());
    }
    let Some(epoch) = token_epoch(&data) else {
        return Err(reject()); // unreadable row: fail closed
    };
    login_fails(&app).remove(&key);
    let token = make_token(&app, &name, &id, epoch)?;
    Ok(Json(json!({
        "token": token,
        "record": record_json(&name, &id, &data, &created, &updated),
    })))
}
