use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::params;
use serde_json::{json, Value};

use crate::auth::require_admin;
use crate::{err, ident_ok, Reply, S};

pub async fn collections_list(State(app): State<S>, headers: HeaderMap) -> Reply {
    require_admin(&app, &headers)?;
    let db = app.db.lock().unwrap();
    let mut stmt = db
        .prepare("SELECT name, type, schema FROM _collections ORDER BY name")
        .unwrap();
    let items: Vec<Value> = stmt
        .query_map([], |r| {
            let (name, ty, schema): (String, String, String) =
                (r.get(0)?, r.get(1)?, r.get(2)?);
            Ok(json!({
                "name": name,
                "type": ty,
                "schema": serde_json::from_str::<Value>(&schema).unwrap_or(json!([])),
            }))
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect();
    Ok(Json(json!({ "items": items })))
}

pub async fn collections_create(
    State(app): State<S>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Reply {
    require_admin(&app, &headers)?;
    let name = body.get("name").and_then(|n| n.as_str()).unwrap_or("");
    if !ident_ok(name) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid collection name"));
    }
    let ty = body.get("type").and_then(|t| t.as_str()).unwrap_or("base");
    if ty != "base" && ty != "auth" {
        return Err(err(StatusCode::BAD_REQUEST, "type must be 'base' or 'auth'"));
    }
    let schema = body.get("schema").cloned().unwrap_or(json!([]));
    let Some(fields) = schema.as_array() else {
        return Err(err(StatusCode::BAD_REQUEST, "schema must be an array"));
    };
    for f in fields {
        let fname = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let fty = f.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if !ident_ok(fname) || !["text", "number", "bool", "json"].contains(&fty) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "schema fields need valid name and type in text|number|bool|json",
            ));
        }
    }
    let db = app.db.lock().unwrap();
    let n = db
        .execute(
            "INSERT OR IGNORE INTO _collections(name, type, schema) VALUES(?1, ?2, ?3)",
            params![name, ty, schema.to_string()],
        )
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if n == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "collection already exists"));
    }
    Ok(Json(json!({ "name": name, "type": ty, "schema": schema })))
}

pub async fn collections_delete(
    State(app): State<S>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Reply {
    require_admin(&app, &headers)?;
    let db = app.db.lock().unwrap();
    let n = db
        .execute("DELETE FROM _collections WHERE name = ?1", [&name])
        .unwrap();
    if n == 0 {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    }
    db.execute("DELETE FROM records WHERE collection = ?1", [&name])
        .unwrap();
    Ok(Json(json!({})))
}
