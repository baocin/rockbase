# Spec: File uploads and serving

Scope: new `file` schema field type; multipart create/update on records; disk storage under the
data dir; one download endpoint; cleanup on record delete. Everything lands in `src/main.rs`.

## Cargo.toml

- `axum = { version = "0.8", features = ["multipart"] }` (only change; no new crates).

## Storage layout

- Files live at `<data_dir>/storage/{collection}/{record_id}/{filename}`.
- `data_dir` is the same directory the DB lives in. Today `main()` hardcodes `rb_data`; thread it
  through: add `data_dir: std::path::PathBuf` field to `App`, add a `data_dir: PathBuf` param to
  `build_app(conn, admin_token, data_dir)`. `main()` passes `PathBuf::from("rb_data")`. Tests pass
  a fresh temp dir, e.g. `std::env::temp_dir().join(format!("rb_test_{}", uuid::Uuid::new_v4().simple()))`.
- Helper: `fn record_dir(app: &App, col: &str, id: &str) -> PathBuf { app.data_dir.join("storage").join(col).join(id) }`.
  Only call it with `ident_ok`-checked `col`/`id` and sanitized filenames (path traversal guard).

## Schema: the `file` field type

- `collections_create` (line ~252): add `"file"` to the allowed types array:
  `["text", "number", "bool", "json", "file"]`.
- `validate()` (line ~130): add match arm `"file" => v.is_string(),` — the stored JSON value for a
  file field is the bare filename string (or null).

## Filename sanitization

```rust
// Keep only [A-Za-z0-9._-]; reject empty or dot-only results. Caps length at 100.
fn sanitize_filename(raw: &str) -> Option<String> {
    let s: String = raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(100).collect();
    if s.is_empty() || s.chars().all(|c| c == '.') { None } else { Some(s) }
}
```
No `/`, `\`, or bare `..` can survive this, so joining it under `record_dir` is safe.

## Multipart on POST /api/collections/{name}/records and PATCH .../records/{id}

Change `record_create` and `record_update` to take `axum::extract::Request` as the last extractor
(instead of `Json<Value>`); keep `State`, `Path`, `HeaderMap` before it. Inside:

1. Branch on `content-type` header:
   - starts with `multipart/form-data` → `Multipart::from_request(req, &state)`, parse per step 2.
   - otherwise → collect body bytes (`axum::body::to_bytes`), `serde_json::from_slice` to `Value`,
     proceed exactly as today (400 `"body must be a JSON object"` on non-object).
2. Multipart parsing (do ALL awaiting before locking `app.db` — never hold the Mutex across await):
   - Text part (no `file_name()`): value = `serde_json::from_str(&text).unwrap_or(Value::String(text))`
     inserted into the data map under the part name. So part `views` = `42` becomes a number,
     part `title` = `hello` becomes a string.
   - File part (`file_name()` is Some): part name must equal a schema field with `"type": "file"`,
     else 400 `"field '{name}' is not a file field"`. Sanitize the client filename; None → 400
     `"invalid filename"`. Read `field.bytes().await` and buffer.
     // ponytail: files buffered in RAM, fine under the 10MB cap; stream to disk if the cap grows
   - For each file part, insert `json!(filename)` into the data map under the field name, and keep
     `(field_name, filename, bytes)` in a Vec for step 4.
3. Lock db, run the existing flow unchanged: collection lookup, `validate` (file values are now
   strings so it passes), auth-collection checks, id generation (create) / merge (update).
4. After the successful INSERT/UPDATE, write each buffered file:
   `fs::create_dir_all(record_dir)` then `fs::write(dir.join(filename), bytes)`; on error return
   500. // ponytail: DB row can outlive a failed file write; two-phase cleanup if it ever matters
   PATCH overwrite: same field, new filename → old file stays on disk, JSON points at the new one.
   // ponytail: replaced files are orphaned until record delete; GC pass if disk fills
5. Response JSON is the normal record shape, e.g.
   `{"id":"a1b2...","collectionName":"posts","title":"hello","avatar":"cat.png","created":...,"updated":...}`.

Body cap: add `.layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024))` to the Router in
`build_app` (axum's default is 2MB; this raises it and caps multipart at 10MB → 413 above it).

## GET /api/files/{collection}/{id}/{filename}

New route in `build_app`; new handler `file_serve(State, Path<(String, String, String)>)`:

1. 400 unless `ident_ok(collection)`, `ident_ok(id)`, and `sanitize_filename(&filename)` returns
   exactly the input filename (reject anything the upload path could not have produced).
2. `std::fs::read(record_dir(...).join(&filename))` → 404 `"file not found"` on any error.
3. Respond `([(header::CONTENT_TYPE, ctype)], bytes)` where ctype comes from:

```rust
// ponytail: tiny map, not a mime crate; extend the list when someone hits octet-stream
fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg", "png" => "image/png", "gif" => "image/gif",
        "webp" => "image/webp", "svg" => "image/svg+xml", "pdf" => "application/pdf",
        "txt" => "text/plain", "json" => "application/json", "html" => "text/html",
        _ => "application/octet-stream",
    }
}
```

No auth on downloads (matches the guests-read rule used by record GETs).

## Record delete

In `record_delete`, after the row delete succeeds:
`let _ = std::fs::remove_dir_all(record_dir(&app, &name, &id));` — ignore errors (dir may not exist).

## Non-goals (do not build)

Multi-file fields, thumbnails, protected/token downloads, S3 backends, streaming uploads,
orphan-file GC, storage cleanup on collection delete.

## Edge cases

- Multipart file part whose part name matches a non-file schema field → 400.
- Multipart with only text parts → behaves exactly like the JSON body path.
- File part on a field not in the schema at all → 400 (fails the file-field check).
- Filename sanitizes to empty (`"???"`) or dot-only (`"..."`, `".."`) → 400.
- Download with traversal-shaped segment (`..%2fdata.db` etc.) → 400 from step 1 checks.
- Unknown extension → served as `application/octet-stream`.
- JSON body may also set a file field to any string (it is just a string field to `validate`);
  harmless — downloads 404 unless the file exists.

## Acceptance tests (extend `mod tests`; build multipart bodies by hand with a fixed boundary)

Test helper: `call_multipart(app, method, uri, auth, boundary, body_bytes)` setting
`content-type: multipart/form-data; boundary=X`. App helper gains the temp `data_dir` (see above).

1. Create collection `posts` with schema `[{"name":"title","type":"text"},{"name":"doc","type":"file"}]`;
   multipart POST with text part `title=hello` and file part `doc` (filename `a.txt`, bytes `hi`)
   → 200, response has `title == "hello"` and `doc == "a.txt"`; file exists at
   `<tmp>/storage/posts/<id>/a.txt` with content `hi`.
2. GET `/api/files/posts/<id>/a.txt` → 200, body `hi`, `content-type: text/plain`.
3. Upload filename `we ird$$.PNG` → stored/served as `weird.PNG`; upload filename `...` → 400.
4. File part named `title` (a text field) → 400.
5. Plain JSON POST/PATCH on the same collection still works (regression; existing `full_flow` stays green).
6. Multipart PATCH replacing `doc` with filename `b.txt` → record shows `b.txt`; GET serves `b.txt`.
7. DELETE the record → 200; GET `/api/files/posts/<id>/a.txt` → 404; storage dir gone.
8. GET `/api/files/posts/<id>/nope.txt` → 404.
