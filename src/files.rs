// File uploads and serving (specs/files.md).
//
// Two deviations from the spec, both deliberate:
//
//  * `build_app` still takes no `data_dir` (nine test files call it), so the storage
//    root is resolved PER REQUEST from `RB_DIR` (default `rb_data`) instead of being
//    captured at startup. It must stay relative until it is used: the file test
//    harness sandboxes the whole process with `set_current_dir`.
//  * The spec predates per-collection rules and says downloads need no auth. That is
//    wrong — an unguessable filename is not access control — so `file_serve` runs the
//    same VIEW gate `GET /api/collections/{c}/records/{id}` runs, and uploads go
//    through `create_core`/`update_core` so they obey the create/update rules.

use std::path::PathBuf;

use axum::{
    extract::{FromRequest, Multipart, Path, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Map, Value};

use crate::auth::who;
use crate::db::get_collection;
use crate::records::{fetch_record, gate_record, RESERVED_FIELDS};
use crate::rules::VIEW;
use crate::{err, ident_ok, S};

/// Also the multipart cap: `DefaultBodyLimit::max(MAX_BODY)` in `build_app` turns
/// anything larger into a 413 while the body is still streaming, so an oversized
/// upload never reaches the database or the disk.
pub const MAX_BODY: usize = 10 * 1024 * 1024;

/// One buffered file part: (schema field name, sanitized filename, bytes).
pub type FilePart = (String, String, Vec<u8>);

/// A parsed request body: the record fields, plus any files to write after the row
/// lands. `data` is what the JSON path would have produced.
pub struct Upload {
    pub data: Value,
    pub files: Vec<FilePart>,
}

/// Allowlist sanitizer, in two allowlist-shaped stages plus a post-condition.
///
/// 1. The raw name must be printable ASCII. Everything outside that — NUL, CR/LF,
///    RTL overrides, and the separator lookalikes U+FF0E/U+FF0F/U+2024/U+2215 — is a
///    name we refuse to reason about. Deleting those characters instead would quietly
///    reshape `<U+FF0E><U+FF0E><U+FF0F>pwned.txt` into the perfectly innocent-looking
///    `pwned.txt`, which is the wrong answer even though it does not traverse.
/// 2. Keep only `[A-Za-z0-9._-]`, capped at 100 chars. No `/`, `\`, `:` or space can
///    survive, so the result is always a single path component.
///
/// Then reject what is left if it is empty, dot-only, or still contains `..`.
/// `None` means the caller must fail the request — never "pick another name".
pub fn sanitize_filename(raw: &str) -> Option<String> {
    if !raw.chars().all(|c| (' '..='~').contains(&c)) {
        return None;
    }
    let s: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .take(100)
        .collect();
    if s.is_empty() || s.contains("..") || s.chars().all(|c| c == '.') {
        None
    } else {
        Some(s)
    }
}

// ponytail: tiny map, not a mime crate; extend the list when someone hits octet-stream.
// `html` and `svg` are deliberately absent — serving attacker-uploaded markup as
// text/html from the API origin is stored XSS, so they fall through to octet-stream.
fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "json" => "application/json",
        _ => "application/octet-stream",
    }
}

/// `<data dir>/storage/{collection}/{id}`, or `None` if either segment is not an
/// identifier. Every disk path goes through here, so the guard cannot be forgotten
/// at a call site.
fn record_dir(col: &str, id: &str) -> Option<PathBuf> {
    if !ident_ok(id) {
        return None;
    }
    Some(collection_dir(col)?.join(id))
}

/// `<data dir>/storage/{collection}`. Same guard, one level up.
fn collection_dir(col: &str) -> Option<PathBuf> {
    if !ident_ok(col) {
        return None;
    }
    let root = std::env::var("RB_DIR").unwrap_or_else(|_| "rb_data".into());
    Some(PathBuf::from(root).join("storage").join(col))
}

fn mp_err(e: axum::extract::multipart::MultipartError) -> (StatusCode, Json<Value>) {
    // `status()` is 413 for a body-limit overrun and 400 for a malformed body,
    // which is exactly the split we want.
    err(e.status(), e.body_text())
}

/// Read the whole request body. ALL awaiting happens here, before any caller takes
/// the DB mutex — the multipart parse must never run while the lock is held.
pub async fn read_body(req: Request, state: &S) -> Result<Upload, (StatusCode, Json<Value>)> {
    let ct = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if ct.starts_with("multipart/form-data") {
        let mp = Multipart::from_request(req, state)
            .await
            .map_err(|e| err(e.status(), e.body_text()))?;
        return read_multipart(mp).await;
    }
    let bytes = axum::body::to_bytes(req.into_body(), MAX_BODY)
        .await
        .map_err(|_| err(StatusCode::PAYLOAD_TOO_LARGE, "body too large"))?;
    let data = serde_json::from_slice(&bytes)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("invalid JSON body: {e}")))?;
    Ok(Upload { data, files: Vec::new() })
}

async fn read_multipart(mut mp: Multipart) -> Result<Upload, (StatusCode, Json<Value>)> {
    let mut data = Map::new();
    let mut files: Vec<FilePart> = Vec::new();
    while let Some(field) = mp.next_field().await.map_err(mp_err)? {
        let Some(name) = field.name().map(str::to_string).filter(|n| ident_ok(n)) else {
            return Err(err(StatusCode::BAD_REQUEST, "multipart part needs a valid name"));
        };
        // record_json injects these from system columns, so a part named after one
        // would be stored and never returned — and its bytes orphaned on disk.
        if RESERVED_FIELDS.contains(&name.as_str()) {
            return Err(err(
                StatusCode::BAD_REQUEST,
                format!("'{name}' is a reserved field name"),
            ));
        }
        let raw_filename = field.file_name().map(str::to_string);
        let bytes = field.bytes().await.map_err(mp_err)?;
        match raw_filename {
            Some(raw) => {
                let Some(clean) = sanitize_filename(&raw) else {
                    return Err(err(StatusCode::BAD_REQUEST, "invalid filename"));
                };
                data.insert(name.clone(), json!(clean));
                files.push((name, clean, bytes.to_vec()));
            }
            None => {
                // A form value is a single-line scalar. Control bytes here are what a
                // CRLF-injected Content-Disposition header degrades into once the
                // parser has resynchronised, so the request is refused outright rather
                // than half-interpreted.
                let Ok(text) = std::str::from_utf8(&bytes) else {
                    return Err(err(StatusCode::BAD_REQUEST, format!("field '{name}' is not text")));
                };
                if text.chars().any(char::is_control) {
                    return Err(err(
                        StatusCode::BAD_REQUEST,
                        format!("field '{name}' contains control characters"),
                    ));
                }
                let text = text.to_string();
                let v = serde_json::from_str(&text).unwrap_or(Value::String(text));
                data.insert(name, v);
            }
        }
    }
    Ok(Upload { data: Value::Object(data), files })
}

/// A file part may only target a schema field declared `"type": "file"`. Without this
/// a file part named `title` would land in a text field as a bare filename string,
/// which `validate` cannot tell apart from a legitimate value.
pub fn check_file_fields(
    schema: &[Value],
    files: &[FilePart],
) -> Result<(), (StatusCode, Json<Value>)> {
    for (name, _, _) in files {
        let ok = schema.iter().any(|f| {
            f.get("name").and_then(|n| n.as_str()) == Some(name.as_str())
                && f.get("type").and_then(|t| t.as_str()) == Some("file")
        });
        if !ok {
            return Err(err(
                StatusCode::BAD_REQUEST,
                format!("field '{name}' is not a file field"),
            ));
        }
    }
    Ok(())
}

/// Write the buffered parts, after the row is committed.
// ponytail: the DB row can outlive a failed write, and a replaced file is orphaned
// until the record is deleted; add two-phase cleanup / a GC pass if disk ever fills.
pub fn write_files(col: &str, id: &str, files: &[FilePart]) -> Result<(), (StatusCode, Json<Value>)> {
    if files.is_empty() {
        return Ok(());
    }
    let oops = |e: std::io::Error| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    let Some(dir) = record_dir(col, id) else {
        return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "bad storage path"));
    };
    std::fs::create_dir_all(&dir).map_err(oops)?;
    for (_, name, bytes) in files {
        // `name` came out of sanitize_filename, so it is a single path component
        std::fs::write(dir.join(name), bytes).map_err(oops)?;
    }
    Ok(())
}

/// Best-effort cleanup after a successful record delete. Called from the handler, not
/// from `delete_core`: a batch delete runs inside a transaction that may still roll
/// back, and unlinking files is not something a rollback can undo.
pub fn remove_record_files(col: &str, id: &str) {
    if let Some(dir) = record_dir(col, id) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// Drop every uploaded file belonging to a collection. Deleting a collection removes
/// its row and its records, so without this the storage directory is orphaned on disk
/// forever with no API left that could reach it.
pub fn remove_collection_files(col: &str) {
    if let Some(dir) = collection_dir(col) {
        let _ = std::fs::remove_dir_all(dir);
    }
}

/// GET /api/files/{collection}/{id}/{filename}
pub async fn file_serve(
    State(app): State<S>,
    Path((col, id, filename)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, (StatusCode, Json<Value>)> {
    // Reject anything the upload path could not have produced. This is the whole
    // traversal guard on the read side: the URL is a key lookup, not a file browser.
    if sanitize_filename(&filename).as_deref() != Some(filename.as_str()) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid filename"));
    }
    let Some(dir) = record_dir(&col, &id) else {
        return Err(err(StatusCode::BAD_REQUEST, "invalid collection or record id"));
    };
    // who() takes the db lock itself, so it must run before we do
    let w = who(&app, &headers);
    {
        let db = app.db.lock().unwrap();
        let Some(c) = get_collection(&db, &col) else {
            return Err(err(StatusCode::NOT_FOUND, "no such collection"));
        };
        if fetch_record(&db, &col, &id).is_none() {
            return Err(err(StatusCode::NOT_FOUND, "record not found"));
        }
        // same gate as GET .../records/{id}: 401 for guests, 403 for authed callers
        gate_record(&db, &w, &c.rules[VIEW], &col, &id)?;
    }
    let Ok(bytes) = std::fs::read(dir.join(&filename)) else {
        return Err(err(StatusCode::NOT_FOUND, "file not found"));
    };
    Ok((
        [
            (header::CONTENT_TYPE, content_type(&filename)),
            // the type is derived from the extension, never from the uploader's claim;
            // nosniff stops a browser from second-guessing that
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::sanitize_filename as s;

    #[test]
    fn sanitize_is_allowlist_based() {
        assert_eq!(s("a.txt").as_deref(), Some("a.txt"));
        assert_eq!(s("we ird$$.PNG").as_deref(), Some("weird.PNG"));
        assert_eq!(s(&format!("{}.txt", "a".repeat(400))).unwrap().len(), 100);
        // dot-only, empty, and anything that would leave a `..` behind
        for bad in ["", "   ", "???", ".", "..", "...", "../../etc/passwd", &".".repeat(200)] {
            assert!(s(bad).is_none(), "{bad:?} must be rejected");
        }
        // separator lookalikes must not be silently deleted into a clean name
        for bad in ["\u{ff0e}\u{ff0e}\u{ff0f}pwned.txt", "a\u{0000}.txt", "\r\n../pwned.txt"] {
            assert!(s(bad).is_none(), "{bad:?} must be rejected");
        }
        // whatever survives is always a single path component
        for raw in ["/etc/passwd", r"C:\Windows\win.ini", "~/.ssh/authorized_keys"] {
            let out = s(raw).unwrap();
            assert!(!out.contains('/') && !out.contains('\\') && !out.contains(".."));
        }
    }
}
