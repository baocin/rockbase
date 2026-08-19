use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::params;
use serde_json::{json, Value};

use crate::auth::require_admin;
use crate::db::{get_collection, Col};
use crate::rules::{compile_rule, defaults};
use crate::{err, ident_ok, Reply, S};

/// Invalidate every cached copy of the collection rules (see `App::cols_version`).
/// Called by each handler that writes `_collections`, before it returns.
fn bump(app: &S) {
    app.cols_version
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// The five rules, as (JSON key, SQL column), in LIST/VIEW/CREATE/UPDATE/DELETE order.
const RULE_KEYS: [(&str, &str); 5] = [
    ("listRule", "list_rule"),
    ("viewRule", "view_rule"),
    ("createRule", "create_rule"),
    ("updateRule", "update_rule"),
    ("deleteRule", "delete_rule"),
];

fn col_json(name: &str, c: &Col) -> Value {
    let mut out = json!({ "name": name, "type": c.ty, "schema": c.schema });
    for (i, (key, _)) in RULE_KEYS.iter().enumerate() {
        out[*key] = json!(c.rules[i]);
    }
    out
}

/// The field array of a schema value, or 400. Shared by create and update so the
/// two can never drift.
fn schema_ok(schema: &Value) -> Result<&Vec<Value>, (StatusCode, Json<Value>)> {
    let Some(fields) = schema.as_array() else {
        return Err(err(StatusCode::BAD_REQUEST, "schema must be an array"));
    };
    for f in fields {
        let fname = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let fty = f.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if !ident_ok(fname)
            || !["text", "number", "bool", "json", "relation", "file"].contains(&fty)
        {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "schema fields need valid name and type in text|number|bool|json|relation|file",
            ));
        }
        // A relation needs a usable target name. Target existence is NOT checked here:
        // per-write validation already fails closed, and skipping it allows self-relations
        // and forward references to a collection created later.
        if fty == "relation" {
            let target = f
                .pointer("/options/collection")
                .and_then(|c| c.as_str())
                .unwrap_or("");
            if !ident_ok(target) {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    "relation fields need options.collection naming a target collection",
                ));
            }
        }
        // Reserved: record_json always overwrites these with system values, so a field
        // with one of these names would be stored but never returned (silent data loss),
        // and rules would resolve it to the data value in memory but to the real column
        // in SQL — create and update gating would disagree on the same rule.
        if crate::records::RESERVED_FIELDS.contains(&fname) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                format!("'{fname}' is a reserved field name"),
            ));
        }
    }
    Ok(fields)
}

/// A rule field from a request body. `Ok(None)` = the key was absent (leave alone).
/// Must be JSON null or a string, and a non-empty string must compile.
fn read_rule(body: &Value, key: &str) -> Result<Option<Option<String>>, (StatusCode, Json<Value>)> {
    let Some(v) = body.get(key) else {
        return Ok(None);
    };
    if v.is_null() {
        return Ok(Some(None));
    }
    let bad = || err(StatusCode::BAD_REQUEST, format!("invalid {key}"));
    let s = v.as_str().ok_or_else(bad)?;
    // dummy auth id: compilation only proves the shape, never the caller
    if !s.is_empty() && compile_rule(s, "").is_none() {
        return Err(bad());
    }
    Ok(Some(Some(s.to_string())))
}

pub async fn collections_list(State(app): State<S>, headers: HeaderMap) -> Reply {
    require_admin(&app, &headers)?;
    let db = app.db.get();
    let mut stmt = db
        .prepare(
            "SELECT name, type, schema, list_rule, view_rule, create_rule, update_rule, \
             delete_rule FROM _collections ORDER BY name",
        )
        .unwrap();
    let items: Vec<Value> = stmt
        .query_map([], |r| {
            let name: String = r.get(0)?;
            let c = Col {
                ty: r.get(1)?,
                schema: serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or_default(),
                rules: [r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?],
            };
            Ok(col_json(&name, &c))
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
        return Err(err(
            StatusCode::BAD_REQUEST,
            "type must be 'base' or 'auth'",
        ));
    }
    let schema = body.get("schema").cloned().unwrap_or(json!([]));
    schema_ok(&schema)?;
    // named rules override, absent ones fall back to the type defaults
    let mut rules = defaults(ty);
    for (i, (key, _)) in RULE_KEYS.iter().enumerate() {
        if let Some(r) = read_rule(&body, key)? {
            rules[i] = r;
        }
    }
    let db = app.db.get();
    let n = db
        .execute(
            "INSERT OR IGNORE INTO _collections\
             (name, type, schema, list_rule, view_rule, create_rule, update_rule, delete_rule) \
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                name,
                ty,
                schema.to_string(),
                rules[0],
                rules[1],
                rules[2],
                rules[3],
                rules[4]
            ],
        )
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if n == 0 {
        return Err(err(StatusCode::BAD_REQUEST, "collection already exists"));
    }
    bump(&app);
    Ok(Json(col_json(
        name,
        &Col {
            ty: ty.into(),
            schema: schema.as_array().cloned().unwrap_or_default(),
            rules,
        },
    )))
}

pub async fn collections_get(
    State(app): State<S>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Reply {
    require_admin(&app, &headers)?;
    let db = app.db.get();
    let Some(c) = get_collection(&db, &name) else {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    };
    Ok(Json(col_json(&name, &c)))
}

/// Admin-only edits: the five rule keys plus a wholesale `schema` replacement.
/// A rule key present with null sets NULL, an absent key is left untouched.
/// `name`/`type` are rejected outright; any other key is ignored.
///
/// ponytail: removed fields linger in stored JSON; a cleanup sweep over records is the upgrade
pub async fn collections_update(
    State(app): State<S>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<Value>,
) -> Reply {
    require_admin(&app, &headers)?;
    // validate every named key first, so a rejected write changes nothing
    if body.get("name").is_some() || body.get("type").is_some() {
        return Err(err(StatusCode::BAD_REQUEST, "name/type cannot be changed"));
    }
    let mut updates: Vec<(&str, Option<String>)> = Vec::new();
    for (key, column) in RULE_KEYS {
        if let Some(r) = read_rule(&body, key)? {
            updates.push((column, r));
        }
    }
    let schema = match body.get("schema") {
        Some(s) => {
            schema_ok(s)?;
            Some(s.to_string())
        }
        None => None,
    };
    let db = app.db.get();
    if get_collection(&db, &name).is_none() {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    }
    for (column, rule) in updates {
        // `column` comes from RULE_KEYS, never from the request
        db.execute(
            &format!("UPDATE _collections SET {column} = ?1 WHERE name = ?2"),
            params![rule, name],
        )
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    if let Some(s) = schema {
        db.execute(
            "UPDATE _collections SET schema = ?1 WHERE name = ?2",
            params![s, name],
        )
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    let c = get_collection(&db, &name).unwrap();
    bump(&app);
    Ok(Json(col_json(&name, &c)))
}

pub async fn collections_delete(
    State(app): State<S>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Reply {
    require_admin(&app, &headers)?;
    let db = app.db.get();
    let n = db
        .execute("DELETE FROM _collections WHERE name = ?1", [&name])
        .unwrap();
    if n == 0 {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    }
    db.execute("DELETE FROM records WHERE collection = ?1", [&name])
        .unwrap();
    bump(&app);
    drop(db); // never do file IO while holding a connection
    crate::files::remove_collection_files(&name);
    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_rejects_reserved_field_names() {
        for name in crate::records::RESERVED_FIELDS {
            let schema = json!([{ "name": name, "type": "text" }]);
            assert!(
                schema_ok(&schema).is_err(),
                "'{name}' must be rejected: record_json overwrites it, so it would be \
                 stored but never returned, and rules would resolve it inconsistently"
            );
        }
        // a normal field still passes
        assert!(schema_ok(&json!([{ "name": "title", "type": "text" }])).is_ok());
    }
}
