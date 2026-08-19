// Transactional batch endpoint (specs/batch.md).
//
// Every sub-request runs the SAME core as its standalone endpoint — including the
// per-collection rule gate — so POST /api/batch can never do what the standalone
// route would refuse. The cores take a `&Connection`; a rusqlite `Transaction`
// derefs to one, which is the whole trick: one tx, all-or-nothing.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::auth::{who, Who};
use crate::records::{broadcast_change, create_core, delete_core, update_core, Effect};
use crate::{err, Reply, S};

const MAX: usize = 50;

/// `/api/collections/{c}/records` or `/api/collections/{c}/records/{id}` — nothing else.
/// No query string, no trailing segments, no empty segments.
///
/// ponytail: fixed-shape match, no router reuse; grow it if batch ever accepts more endpoints.
fn parse_url(url: &str) -> Option<(&str, Option<&str>)> {
    if url.contains('?') || url.contains('#') {
        return None;
    }
    let mut it = url.strip_prefix("/api/collections/")?.split('/');
    let col = it.next().filter(|c| !c.is_empty())?;
    if it.next()? != "records" {
        return None;
    }
    let id = it.next();
    if it.next().is_some() {
        return None; // trailing segment
    }
    match id {
        Some("") => None, // .../records/ is not a record url
        _ => Some((col, id)),
    }
}

/// Run one sub-request against the batch transaction.
fn one(db: &Connection, w: &Who, req: &Value) -> Effect {
    let bad = || err(StatusCode::BAD_REQUEST, "bad method or url");
    let method = req.get("method").and_then(|m| m.as_str()).ok_or_else(bad)?;
    let url = req.get("url").and_then(|u| u.as_str()).ok_or_else(bad)?;
    let (name, id) = parse_url(url).ok_or_else(bad)?;
    // absent body is Value::Null; the cores already reject non-objects
    let body = req.get("body").cloned().unwrap_or(Value::Null);
    match (method, id) {
        ("POST", None) => create_core(db, w, name, &body),
        ("PATCH", Some(id)) => update_core(db, w, name, id, &body),
        ("DELETE", Some(id)) => delete_core(db, w, name, id),
        _ => Err(bad()),
    }
}

pub async fn batch(State(app): State<S>, headers: HeaderMap, Json(body): Json<Value>) -> Reply {
    // who() locks the db itself, so identity is resolved before we take the lock
    let w = who(&app, &headers);
    if matches!(w, Who::Guest) {
        return Err(err(StatusCode::UNAUTHORIZED, "auth required"));
    }
    let Some(reqs) = body.get("requests").and_then(|r| r.as_array()) else {
        return Err(err(StatusCode::BAD_REQUEST, "requests must be an array"));
    };
    if reqs.len() > MAX {
        return Err(err(
            StatusCode::BAD_REQUEST,
            format!("max {MAX} requests per batch"),
        ));
    }

    let mut db = app.db.lock().unwrap();
    let tx = db
        .transaction()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut results = Vec::with_capacity(reqs.len());
    // Events are buffered, never sent inside the tx: on rollback subscribers must not
    // be told about records that no longer exist.
    let mut events = Vec::with_capacity(reqs.len());
    for (i, req) in reqs.iter().enumerate() {
        match one(&tx, &w, req) {
            Ok((res, event)) => {
                results.push(res);
                events.push(event);
            }
            // Dropping `tx` here rolls back — rusqlite's default drop behavior.
            // The outer status is always 400; the inner message and index say what and where.
            Err((_, Json(e))) => {
                let message = e.get("message").cloned().unwrap_or(json!("error"));
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "code": 400, "message": message, "index": i })),
                ));
            }
        }
    }
    tx.commit()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    drop(db);
    for event in events {
        broadcast_change(&app, event);
    }
    Ok(Json(Value::Array(results)))
}
