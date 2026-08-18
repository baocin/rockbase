> **HISTORICAL — superseded, and INCOMPLETE ON SECURITY.**
> This document predates per-collection API rules and says nothing about gating batch
> sub-requests. An ungated batch endpoint is privilege escalation: it would let a caller
> do via `POST /api/batch` what the standalone routes refuse. Sub-requests now run the
> same `*_core` functions the standalone handlers use. Its prescribed error type
> (`(StatusCode, String)`) and delete payload are also stale.
> The authoritative specification is `tests/batch.rs` plus the source.
> Do not implement from this document.

# Spec: Transactional batch endpoint — POST /api/batch

Status: agreed lazy scope. Everything happens in `src/main.rs` (the whole crate is one file).
No new dependencies. No new files besides this spec.

## Endpoint

`POST /api/batch` — allowed for any authenticated user or admin (`require_writer`).
Guests get `401 {"code":401,"message":"auth required"}` before any work.

Request body:

```json
{
  "requests": [
    {"method": "POST",   "url": "/api/collections/posts/records",       "body": {"title": "a"}},
    {"method": "PATCH",  "url": "/api/collections/posts/records/abc123", "body": {"views": 2}},
    {"method": "DELETE", "url": "/api/collections/posts/records/abc123"}
  ]
}
```

Rules:
- `requests` must be a JSON array; missing/non-array → `400 "requests must be an array"`.
- Max **50** entries; more → `400 "max 50 requests per batch"`. Empty array is fine → `200 []`.
- `method` must be exactly `POST`, `PATCH`, or `DELETE` (case-sensitive). Anything else (incl. GET) fails that index.
- `url` must be `/api/collections/{c}/records` (POST) or `/api/collections/{c}/records/{id}` (PATCH/DELETE).
  No query strings. Anything else fails that index.
- `body` is optional JSON; passed to the core as-is (`Value::Null` when absent — the create/update cores already reject non-objects with "body must be a JSON object"). Ignored for DELETE.

All requests execute inside **one SQLite transaction**. First failure rolls back everything:

```json
// 400 on first failure, e.g. request 1 missing a required field:
{"code": 400, "message": "field 'title' is required", "index": 1}
```

The overall status is always 400 on failure, even when the inner failure was a 404
(e.g. PATCH of a missing record) — the inner message is preserved, the index says which request.

Success returns `200` with the array of individual result bodies, in request order —
the same JSON each standalone endpoint returns (record object for POST/PATCH, `{}` for DELETE):

```json
[ {"id":"...","collectionName":"posts","title":"a","created":"...","updated":"..."}, {...}, {} ]
```

SSE events (`create`/`update`/`delete`) for all requests are broadcast only **after commit**, in order. Nothing is broadcast on rollback.

## Refactor: extract record cores

Split each of `record_create` / `record_update` / `record_delete` into a thin axum handler
plus a `pub(crate)` core taking `&Connection` (a rusqlite `Transaction` derefs to `Connection`,
so the same cores run inside the batch tx). Cores do **no locking and no broadcasting**.

```rust
pub(crate) fn create_record_core(db: &Connection, name: &str, body: &Value)
    -> Result<Value, (StatusCode, String)>;   // returns the record JSON
pub(crate) fn update_record_core(db: &Connection, name: &str, id: &str, body: &Value)
    -> Result<Value, (StatusCode, String)>;   // returns the updated record JSON
pub(crate) fn delete_record_core(db: &Connection, name: &str, id: &str)
    -> Result<Value, (StatusCode, String)>;   // returns json!({"id": id, "collectionName": name})
```

Mechanical moves, behavior unchanged:
- Body of each handler after `require_writer` + `db.lock()` moves into its core verbatim
  (get_collection, validate, email checks, hash_password, INSERT/UPDATE/DELETE with the
  existing parameterized SQL — no SQL changes).
- Error type becomes `(StatusCode, String)`; change `hash_password` to return
  `Result<(), (StatusCode, String)>` to match. Handlers re-wrap with `.map_err(|(c, m)| err(c, m))`.
- Handlers keep their own `broadcast_change` call after a successful core call, using the
  returned record (`delete` handler broadcasts the core's return value — same payload as today).

## Batch handler

```rust
async fn batch(State(app): State<S>, headers: HeaderMap, Json(body): Json<Value>) -> Reply {
    require_writer(&app, &headers)?;
    // validate `requests`: array, len <= 50
    let mut db = app.db.lock().unwrap();          // MutexGuard derefs to &mut Connection
    let tx = db.transaction().map_err(/* 500 */)?;
    let mut results = Vec::new();
    let mut events: Vec<(&'static str, Value)> = Vec::new(); // buffered until commit
    for (i, req) in requests.iter().enumerate() {
        // parse method + url; run the matching core against &tx;
        // on Err((_, msg)) or parse failure: drop tx (implicit rollback) and
        // return err-with-index: (400, json!({"code":400,"message":msg,"index":i}))
    }
    tx.commit().map_err(/* 500 */)?;
    for (action, rec) in events { broadcast_change(&app, action, &rec); }
    Ok(Json(Value::Array(results)))
}
```

URL parsing — no regex, just segments:

```rust
// ponytail: fixed-shape match, no router reuse; grow if batch ever accepts more endpoints
fn parse_batch_url(url: &str) -> Option<(&str, Option<&str>)> {
    let mut it = url.strip_prefix("/api/collections/")?.split('/');
    let col = it.next().filter(|c| !c.is_empty())?;
    if it.next()? != "records" { return None; }
    let id = it.next().filter(|i| !i.is_empty());
    if it.next().is_some() { return None; }        // no trailing segments
    Some((col, id))
}
```

Dispatch: `("POST", (c, None))` → create; `("PATCH", (c, Some(id)))` → update;
`("DELETE", (c, Some(id)))` → delete; every other combination fails that index with
`"bad method or url"`. Collection names need no extra whitelist here — cores hit
`get_collection` (parameterized) and 404 unknown ones; no SQL identifier interpolation is added.

Routing: add `.route("/api/batch", post(batch))` in `build_app`.

## Edge cases (decided)

- Create-then-patch the same record in one batch works: the create's returned `id` is unknown
  to the client mid-batch, so cross-referencing results is NOT supported — callers patch ids
  they already know. (PocketBase parity here is out of scope.)
- Duplicate-email check for auth records runs inside the tx, so two creates with the same
  email in one batch: the second fails, whole batch rolls back.
- A failure after N successful requests must leave zero rows changed (rollback test below).
- `Transaction` default drop behavior is rollback — early `return Err(...)` needs no explicit call.
- Buffered SSE events reference records that exist post-commit; on rollback subscribers see nothing.

## Acceptance tests (add to `mod tests` in src/main.rs; use existing `app()` + `call()` helpers)

1. **Happy path**: seed `posts` collection + a bearer token; batch of [create, create] → 200,
   array of 2 record objects with ids; `GET /api/collections/posts/records` shows `totalItems: 2`.
2. **Rollback**: batch of [valid create, create missing required `title`] → 400 with
   `index == 1` and message containing `required`; list shows `totalItems: 0`.
3. **Mixed methods**: create a record via the normal endpoint; batch of
   [PATCH it `{"views": 5}`, DELETE it] → 200 `[record, {}]`; subsequent GET of the id → 404.
4. **Inner 404 flattens to 400**: batch of [PATCH `/api/collections/posts/records/nope`] →
   400, `index == 0`, message `"record not found"`.
5. **Cap**: 51 no-op requests → 400 with message `"max 50 requests per batch"` (nothing executed).
6. **Auth**: any batch with no Authorization header → 401.
7. **Bad url/method**: `{"method":"GET","url":"/api/collections/posts/records"}` and
   `{"method":"POST","url":"/api/health"}` each → 400 at their index.
8. **Empty**: `{"requests": []}` → 200 `[]`.

Done when: `cargo test` green, existing `full_flow` untouched, no new deps in Cargo.toml.
