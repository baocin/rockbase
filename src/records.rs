use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rusqlite::{params, params_from_iter, Connection};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::auth::{who, Who};
use crate::db::{get_collection, now};
use crate::files::{check_file_fields, read_body, remove_record_files, write_files};
use crate::rules::{
    auth_id, check_rule, compile_rule, deny, eval_rule_mem, CREATE, DELETE, LIST, UPDATE, VIEW,
};
use crate::{err, ident_ok, App, Reply, S};

fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..15].to_string()
}

/// Names record_json injects from system columns; a schema field may not use them.
pub const RESERVED_FIELDS: [&str; 5] = [
    "id",
    "created",
    "updated",
    "collectionName",
    "password_hash",
];

pub fn record_json(collection: &str, id: &str, data: &str, created: &str, updated: &str) -> Value {
    let mut obj: Map<String, Value> = serde_json::from_str(data).unwrap_or_default();
    obj.remove("password_hash");
    obj.insert("id".into(), json!(id));
    obj.insert("collectionName".into(), json!(collection));
    obj.insert("created".into(), json!(created));
    obj.insert("updated".into(), json!(updated));
    Value::Object(obj)
}

pub fn validate(
    schema: &[Value],
    data: &Map<String, Value>,
    is_auth: bool,
    partial: bool,
) -> Result<(), String> {
    let field_def = |k: &str| {
        schema
            .iter()
            .find(|f| f.get("name").and_then(|n| n.as_str()) == Some(k))
    };
    for (k, v) in data {
        let known = field_def(k).is_some() || (is_auth && (k == "email" || k == "password"));
        if !known {
            return Err(format!("unknown field '{k}'"));
        }
        if let Some(def) = field_def(k) {
            let ty = def.get("type").and_then(|t| t.as_str()).unwrap_or("json");
            let ok = v.is_null()
                || match ty {
                    "text" => v.is_string(),
                    "number" => v.is_number(),
                    "bool" => v.is_boolean(),
                    // an id string; existence is a DB question, checked by check_relations
                    "relation" => v.is_string(),
                    // the stored value of a file field is the bare filename
                    "file" => v.is_string(),
                    _ => true, // json = anything
                };
            if !ok {
                return Err(format!("field '{k}' must be {ty}"));
            }
        }
    }
    for f in schema {
        if f.get("required").and_then(|r| r.as_bool()).unwrap_or(false) {
            let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
            match data.get(name) {
                // explicit null is never allowed for a required field, even on PATCH
                Some(v) if v.is_null() => return Err(format!("field '{name}' is required")),
                None if !partial => return Err(format!("field '{name}' is required")),
                _ => {}
            }
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct ListParams {
    page: Option<u32>,
    #[serde(rename = "perPage")]
    per_page: Option<u32>,
    sort: Option<String>,
    filter: Option<String>,
    fields: Option<String>,
    #[serde(rename = "skipTotal")]
    skip_total: Option<String>,
    expand: Option<String>,
}

pub fn sort_clause(s: &str) -> Option<String> {
    let (field, dir) = match s.strip_prefix('-') {
        Some(f) => (f, "DESC"),
        None => (s, "ASC"),
    };
    if !ident_ok(field) {
        return None;
    }
    // ident_ok guards the interpolation
    let col = match field {
        "id" | "created" | "updated" => field.to_string(),
        _ => format!("json_extract(data, '$.{field}')"),
    };
    Some(format!("{col} {dir}"))
}

pub async fn records_list(
    State(app): State<S>,
    Path(name): Path<String>,
    headers: HeaderMap,
    Query(q): Query<ListParams>,
) -> Reply {
    // who() takes the db lock itself, so it must run before we do
    let w = who(&app, &headers);
    let db = app.db.lock().unwrap();
    let Some(col) = get_collection(&db, &name) else {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    };
    let rule = check_rule(&w, &col.rules[LIST])?;
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(30).clamp(1, 500);

    let mut where_sql = String::from("collection = ?");
    let mut binds: Vec<rusqlite::types::Value> = vec![name.clone().into()];
    if let Some(f) = q.filter.as_deref() {
        let (frag, mut fbinds) = crate::filter::compile(f)
            .map_err(|m| err(StatusCode::BAD_REQUEST, format!("invalid filter: {m}")))?;
        where_sql.push_str(&format!(" AND ({frag})"));
        binds.append(&mut fbinds);
    }
    // the list rule ANDs into both the COUNT and the page query, so a user
    // `filter=` can only ever narrow what the rule already allows
    if let Some(r) = rule {
        let Some((frag, mut rbinds)) = compile_rule(&r, auth_id(&w)) else {
            return Err(deny(&w)); // stored rule no longer compiles: fail closed
        };
        where_sql.push_str(&format!(" AND ({frag})"));
        binds.append(&mut rbinds);
    }
    let order = match q.sort.as_deref() {
        // each segment passes ident_ok inside sort_clause before hitting the SQL string
        Some(s) => s
            .split(',')
            .map(|seg| sort_clause(seg.trim()))
            .collect::<Option<Vec<_>>>()
            .map(|v| v.join(", "))
            .ok_or_else(|| err(StatusCode::BAD_REQUEST, "bad sort field"))?,
        None => "created ASC".to_string(),
    };
    // Stable tiebreak. Inserts routinely land inside the same millisecond, and ids are
    // random uuids, so neither `created` nor `id` orders them by insertion. SQLite's
    // rowid increments per insert, so it is both unique and chronological — without it
    // tied rows come back in arbitrary order and pagination repeats or skips records.
    let order = format!("{order}, rowid ASC");

    let keep_set: Option<std::collections::HashSet<&str>> = match q.fields.as_deref() {
        Some(f) => {
            let set: std::collections::HashSet<&str> = f.split(',').map(str::trim).collect();
            if set.iter().any(|k| !ident_ok(k)) {
                return Err(err(StatusCode::BAD_REQUEST, "bad fields"));
            }
            Some(set)
        }
        None => None,
    };

    // skipTotal=1 (PocketBase parity): skip the COUNT, return -1 sentinels
    let (total_items, total_pages): (i64, i64) = if q.skip_total.as_deref() == Some("1") {
        (-1, -1)
    } else {
        let total: i64 = db
            .query_row(
                &format!("SELECT COUNT(*) FROM records WHERE {where_sql}"),
                params_from_iter(binds.iter()),
                |r| r.get(0),
            )
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        (total, (total as u32).div_ceil(per_page) as i64)
    };

    let sql = format!(
        "SELECT id, data, created, updated FROM records WHERE {where_sql} \
         ORDER BY {order} LIMIT {per_page} OFFSET {}",
        (page - 1) * per_page
    );
    let mut stmt = db
        .prepare(&sql)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let mut items: Vec<Value> = stmt
        .query_map(params_from_iter(binds.iter()), |r| {
            let (id, data, created, updated): (String, String, String, String) =
                (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?);
            Ok(record_json(&name, &id, &data, &created, &updated))
        })
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?
        .filter_map(|r| r.ok())
        .collect();

    // before the ?fields= projection: expanding needs the raw relation ids, which a
    // narrow `fields=` would have stripped
    if let Some(e) = q.expand.as_deref() {
        expand_records(&db, &w, &col.schema, e, &mut items);
    }
    if let Some(keep) = &keep_set {
        for item in items.iter_mut() {
            if let Value::Object(m) = item {
                // `expand` survives the projection: ?fields=id,title&expand=author
                // asks for both, and dropping one silently would be a lie
                m.retain(|k, _| k == "id" || k == "expand" || keep.contains(k.as_str()));
            }
        }
    }

    Ok(Json(json!({
        "page": page,
        "perPage": per_page,
        "totalItems": total_items,
        "totalPages": total_pages,
        "items": items,
    })))
}

/// Enforce a row-level rule against one existing record.
pub(crate) fn gate_record(
    db: &Connection,
    w: &Who,
    rule: &Option<String>,
    name: &str,
    id: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let Some(expr) = check_rule(w, rule)? else {
        return Ok(());
    };
    let Some((frag, rbinds)) = compile_rule(&expr, auth_id(w)) else {
        return Err(deny(w)); // stored rule no longer compiles: fail closed
    };
    let mut binds: Vec<rusqlite::types::Value> =
        vec![name.to_string().into(), id.to_string().into()];
    binds.extend(rbinds);
    let allowed: bool = db
        .query_row(
            &format!(
                "SELECT EXISTS(SELECT 1 FROM records \
                 WHERE collection = ? AND id = ? AND {frag})"
            ),
            params_from_iter(binds.iter()),
            |r| r.get(0),
        )
        .unwrap_or(false);
    if allowed {
        Ok(())
    } else {
        Err(deny(w))
    }
}

pub(crate) fn fetch_record(
    db: &Connection,
    name: &str,
    id: &str,
) -> Option<(String, String, String)> {
    db.query_row(
        "SELECT data, created, updated FROM records WHERE collection = ?1 AND id = ?2",
        params![name, id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .ok()
}

/// Relation values must name an existing record in the TARGET collection. Absent
/// and null values are fine (`required` is enforced by `validate`); a non-string
/// already 400'd in `validate`.
fn check_relations(
    db: &Connection,
    schema: &[Value],
    data: &Map<String, Value>,
) -> Result<(), String> {
    for f in schema {
        if f.get("type").and_then(|t| t.as_str()) != Some("relation") {
            continue;
        }
        let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let Some(id) = data.get(name).and_then(|v| v.as_str()) else {
            continue;
        };
        let target = f
            .pointer("/options/collection")
            .and_then(|c| c.as_str())
            .unwrap_or("");
        if fetch_record(db, target, id).is_none() {
            return Err(format!("field '{name}': no record '{id}' in '{target}'"));
        }
    }
    Ok(())
}

/// Inline related records under `expand`, one level deep.
///
/// Expand is a read amplifier, so every target row is gated by the TARGET
/// collection's view rule against the SAME caller: it can never surface a record
/// `GET /api/collections/<target>/records/<id>` would have refused. A hidden,
/// dangling, null, unknown or non-relation target is silently omitted and the
/// parent record still returns 200; if nothing resolves there is no `expand` key.
///
/// Cost is one `_collections` read plus ONE `id IN (...)` query per requested
/// field, independent of row count. Batching does not weaken the gate: the exact
/// fragment `gate_record` would have run per row is ANDed into the bulk SELECT, so
/// a row that per-row EXISTS would have rejected simply never comes back. Same
/// rule text, same compiler, same binds, and SQLite still evaluates it per row —
/// which is what keeps `owner = @request.auth.id` row-by-row correct.
fn expand_records(db: &Connection, w: &Who, schema: &[Value], expand: &str, items: &mut [Value]) {
    for field in expand.split(',').map(str::trim) {
        let Some(def) = schema.iter().find(|f| {
            f.get("name").and_then(|n| n.as_str()) == Some(field)
                && f.get("type").and_then(|t| t.as_str()) == Some("relation")
        }) else {
            continue; // unknown or non-relation name
        };
        let target = def
            .pointer("/options/collection")
            .and_then(|c| c.as_str())
            .unwrap_or("");
        // one _collections read per requested field; a missing target fails closed
        let Some(tcol) = get_collection(db, target) else {
            continue;
        };
        // distinct ids this field points at; null/absent relations contribute none
        let mut ids: Vec<String> = items
            .iter()
            .filter_map(|r| r.get(field).and_then(|v| v.as_str()).map(str::to_string))
            .collect();
        ids.sort();
        ids.dedup();
        if ids.is_empty() {
            continue;
        }
        // The gate, hoisted out of the row loop but NOT out of the row: the rule is
        // per-caller so it compiles once, then SQLite applies it to each row.
        let gate = match check_rule(w, &tcol.rules[VIEW]) {
            Ok(None) => None, // admin bypass or public rule
            Ok(Some(expr)) => match compile_rule(&expr, auth_id(w)) {
                Some(g) => Some(g),
                None => continue, // stored rule no longer compiles: fail closed
            },
            Err(_) => continue, // NULL rule = admin only
        };
        // one '?' per id, every id bound — never spliced into the SQL text
        let mut sql = format!(
            "SELECT id, data, created, updated FROM records \
             WHERE collection = ? AND id IN ({})",
            ["?"].repeat(ids.len()).join(",")
        );
        let mut binds: Vec<rusqlite::types::Value> = vec![target.to_string().into()];
        binds.extend(ids.into_iter().map(rusqlite::types::Value::from));
        if let Some((frag, rbinds)) = gate {
            sql.push_str(&format!(" AND {frag}"));
            binds.extend(rbinds);
        }
        let Ok(mut stmt) = db.prepare(&sql) else {
            continue;
        };
        // record_json strips password_hash, so auth targets stay scrubbed
        let rows: std::collections::HashMap<String, Value> =
            match stmt.query_map(params_from_iter(binds.iter()), |r| {
                let (id, data, created, updated): (String, String, String, String) =
                    (r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?);
                Ok((
                    id.clone(),
                    record_json(target, &id, &data, &created, &updated),
                ))
            }) {
                Ok(it) => it.filter_map(|r| r.ok()).collect(),
                Err(_) => continue,
            };
        for rec in items.iter_mut() {
            let Some(row) = rec
                .get(field)
                .and_then(|v| v.as_str())
                .and_then(|id| rows.get(id))
                .cloned()
            else {
                continue; // null, dangling, or gated out
            };
            if let Some(Value::Object(e)) = rec
                .as_object_mut()
                .map(|o| o.entry("expand").or_insert_with(|| json!({})))
            {
                e.insert(field.to_string(), row);
            }
        }
    }
}

fn email_taken(db: &Connection, col: &str, email: &str, exclude_id: &str) -> bool {
    db.query_row(
        "SELECT COUNT(*) FROM records WHERE collection = ?1 \
         AND json_extract(data, '$.email') = ?2 AND id != ?3",
        params![col, email, exclude_id],
        |r| r.get::<_, i64>(0),
    )
    .unwrap_or(0)
        > 0
}

fn hash_password(data: &mut Map<String, Value>) -> Result<(), (StatusCode, Json<Value>)> {
    if let Some(pw) = data.remove("password") {
        let pw = pw.as_str().unwrap_or("");
        if pw.len() < 8 {
            return Err(err(
                StatusCode::BAD_REQUEST,
                "password must be at least 8 chars",
            ));
        }
        let hash = bcrypt::hash(pw, 10)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        data.insert("password_hash".into(), json!(hash));
    }
    Ok(())
}

/// What one record write produced: the HTTP response body, plus the realtime event
/// to publish. Cores never lock and never broadcast — the caller does both, which is
/// what lets a batch buffer the events and publish them only after its tx commits.
pub type Effect = Result<(Value, Value), (StatusCode, Json<Value>)>;

fn change(action: &str, topic: &str, record: Value) -> Value {
    json!({ "action": action, "topic": topic, "record": record })
}

pub fn broadcast_change(app: &App, event: Value) {
    let _ = app.events.send(event);
}

/// Core of POST /api/collections/{name}/records. Runs against any `&Connection`,
/// including a `Transaction` (which derefs to one).
pub fn create_core(db: &Connection, w: &Who, name: &str, body: &Value) -> Effect {
    let Some(col) = get_collection(db, name) else {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    };
    let (ty, schema) = (col.ty, col.schema);
    let Some(mut data) = body.as_object().cloned() else {
        return Err(err(StatusCode::BAD_REQUEST, "body must be a JSON object"));
    };
    let is_auth = ty == "auth";
    // Gate BEFORE validating. If validation ran first, an unauthorized caller could tell
    // a valid body from an invalid one by 400-vs-403 and map out a schema that is
    // otherwise admin-only. Evaluating the rule against an unvalidated body is safe:
    // an unresolvable or wrongly-typed operand makes the comparison false, i.e. denies.
    // It also spares the database the relation lookups for callers who cannot write.
    if let Some(expr) = check_rule(w, &col.rules[CREATE])? {
        if !eval_rule_mem(&expr, auth_id(w), &data) {
            return Err(deny(w));
        }
    }
    validate(&schema, &data, is_auth, false).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    check_relations(db, &schema, &data).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    if is_auth {
        let email = data.get("email").and_then(|e| e.as_str()).unwrap_or("");
        if !email.contains('@') {
            return Err(err(StatusCode::BAD_REQUEST, "valid email required"));
        }
        if !data.contains_key("password") {
            return Err(err(StatusCode::BAD_REQUEST, "password required"));
        }
        if email_taken(db, name, email, "") {
            return Err(err(StatusCode::BAD_REQUEST, "email already in use"));
        }
        hash_password(&mut data)?;
    }
    let id = new_id();
    let ts = now(db);
    db.execute(
        "INSERT INTO records(collection, id, data, created, updated) VALUES(?1, ?2, ?3, ?4, ?4)",
        params![name, id, Value::Object(data.clone()).to_string(), ts],
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rec = record_json(name, &id, &Value::Object(data).to_string(), &ts, &ts);
    Ok((rec.clone(), change("create", name, rec)))
}

/// Core of PATCH /api/collections/{name}/records/{id}.
pub fn update_core(db: &Connection, w: &Who, name: &str, id: &str, body: &Value) -> Effect {
    let Some(col) = get_collection(db, name) else {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    };
    let (ty, schema) = (col.ty, col.schema);
    let Some((data, created, _)) = fetch_record(db, name, id) else {
        return Err(err(StatusCode::NOT_FOUND, "record not found"));
    };
    gate_record(db, w, &col.rules[UPDATE], name, id)?;
    let Some(patch) = body.as_object().cloned() else {
        return Err(err(StatusCode::BAD_REQUEST, "body must be a JSON object"));
    };
    let is_auth = ty == "auth";
    validate(&schema, &patch, is_auth, true).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    check_relations(db, &schema, &patch).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
    if is_auth {
        if let Some(email) = patch.get("email").and_then(|e| e.as_str()) {
            if !email.contains('@') {
                return Err(err(StatusCode::BAD_REQUEST, "valid email required"));
            }
            if email_taken(db, name, email, id) {
                return Err(err(StatusCode::BAD_REQUEST, "email already in use"));
            }
        }
    }
    let mut merged: Map<String, Value> = serde_json::from_str(&data).unwrap_or_default();
    for (k, v) in patch {
        merged.insert(k, v); // ponytail: shallow merge, deep merge when nested patches show up
    }
    // ponytail: password change via plain PATCH, old-password confirmation skipped;
    // add an oldPassword check (bcrypt::verify against stored hash) when untrusted
    // clients can hold long-lived tokens.
    hash_password(&mut merged)?;
    let ts = now(db);
    db.execute(
        "UPDATE records SET data = ?1, updated = ?2 WHERE collection = ?3 AND id = ?4",
        params![Value::Object(merged.clone()).to_string(), ts, name, id],
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rec = record_json(name, id, &Value::Object(merged).to_string(), &created, &ts);
    Ok((rec.clone(), change("update", name, rec)))
}

/// Core of DELETE /api/collections/{name}/records/{id}. Response body is `{}`;
/// the event still carries the whole record so subscribers can be gated against it.
pub fn delete_core(db: &Connection, w: &Who, name: &str, id: &str) -> Effect {
    let Some(col) = get_collection(db, name) else {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    };
    // keep the row: a delete event carries the full record so subscribers can be
    // rule-gated against it after the row is gone
    let Some((data, created, updated)) = fetch_record(db, name, id) else {
        return Err(err(StatusCode::NOT_FOUND, "record not found"));
    };
    gate_record(db, w, &col.rules[DELETE], name, id)?;
    db.execute(
        "DELETE FROM records WHERE collection = ?1 AND id = ?2",
        params![name, id],
    )
    .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let rec = record_json(name, id, &data, &created, &updated);
    Ok((json!({}), change("delete", name, rec)))
}

pub async fn record_create(
    State(app): State<S>,
    Path(name): Path<String>,
    headers: HeaderMap,
    req: Request,
) -> Reply {
    // who() takes the db lock itself, so it must run before we do
    let w = who(&app, &headers);
    // every await happens here, before the lock: JSON body or multipart, same shape
    let up = read_body(req, &app).await?;
    let db = app.db.lock().unwrap();
    if !up.files.is_empty() {
        let Some(col) = get_collection(&db, &name) else {
            return Err(err(StatusCode::NOT_FOUND, "no such collection"));
        };
        check_file_fields(&col.schema, &up.files)?;
    }
    let (rec, event) = create_core(&db, &w, &name, &up.data)?;
    drop(db);
    // only after the row exists: a rule-denied create must leave nothing on disk
    write_files(&name, rec["id"].as_str().unwrap_or_default(), &up.files)?;
    broadcast_change(&app, event);
    Ok(Json(rec))
}

pub async fn record_view(
    State(app): State<S>,
    Path((name, id)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<ListParams>,
) -> Reply {
    let w = who(&app, &headers);
    let db = app.db.lock().unwrap();
    let Some(col) = get_collection(&db, &name) else {
        return Err(err(StatusCode::NOT_FOUND, "no such collection"));
    };
    let Some((data, created, updated)) = fetch_record(&db, &name, &id) else {
        return Err(err(StatusCode::NOT_FOUND, "record not found"));
    };
    gate_record(&db, &w, &col.rules[VIEW], &name, &id)?;
    let mut rec = record_json(&name, &id, &data, &created, &updated);
    if let Some(e) = q.expand.as_deref() {
        expand_records(&db, &w, &col.schema, e, std::slice::from_mut(&mut rec));
    }
    Ok(Json(rec))
}

pub async fn record_update(
    State(app): State<S>,
    Path((name, id)): Path<(String, String)>,
    headers: HeaderMap,
    req: Request,
) -> Reply {
    let w = who(&app, &headers);
    let up = read_body(req, &app).await?;
    let db = app.db.lock().unwrap();
    if !up.files.is_empty() {
        let Some(col) = get_collection(&db, &name) else {
            return Err(err(StatusCode::NOT_FOUND, "no such collection"));
        };
        check_file_fields(&col.schema, &up.files)?;
    }
    let (rec, event) = update_core(&db, &w, &name, &id, &up.data)?;
    drop(db);
    // a denied PATCH returns above, so it can never overwrite the stored bytes
    write_files(&name, &id, &up.files)?;
    broadcast_change(&app, event);
    Ok(Json(rec))
}

pub async fn record_delete(
    State(app): State<S>,
    Path((name, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Reply {
    let w = who(&app, &headers);
    let db = app.db.lock().unwrap();
    let (out, event) = delete_core(&db, &w, &name, &id)?;
    drop(db);
    remove_record_files(&name, &id);
    broadcast_change(&app, event);
    Ok(Json(out))
}
