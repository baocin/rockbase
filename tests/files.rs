// File uploads and serving (specs/files.md) — TDD red phase.
// Same harness style as tests/basic.rs and tests/rules.rs: tower oneshot against
// `rockbase::build_app`, `Admin testtoken`.
//
// NOTE ON STORAGE LOCATION: `build_app(conn, admin_token)` takes no `data_dir`
// today, and `RB_DIR` is only read by `main.rs`, so a test cannot point uploads at
// a directory of its own choosing. Until `build_app` grows a `data_dir` parameter
// (or `build_app` itself reads `RB_DIR`), these tests move the whole process into a
// temp sandbox with `set_current_dir` so that any relative data dir the
// implementation picks (`rb_data` today) lands there and never in the repo tree.
// Every filesystem assertion below is therefore written to be path-independent:
// it checks canaries at absolute paths and the bytes served over HTTP, never a
// hardcoded storage path.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::OnceLock;
use tower::ServiceExt;

use rockbase::build_app;
use rockbase::records::RESERVED_FIELDS;

const ADMIN: &str = "Admin testtoken";
const PW: &str = "clubrock1";
const BOUNDARY: &str = "rockbaseTESTboundary1234";

/// Process-wide sandbox: uploads must never touch the repo working tree.
/// Returns the canonical sandbox root, which is also the process CWD.
fn sandbox() -> &'static PathBuf {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        // bounded litter: sandboxes from previous runs are dropped here, so at most
        // one stale directory ever survives in the system temp dir
        if let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) {
            for e in rd.flatten() {
                if e.file_name()
                    .to_string_lossy()
                    .starts_with("rockbase_files_test_")
                {
                    let _ = std::fs::remove_dir_all(e.path());
                }
            }
        }
        let root = std::env::temp_dir().join(format!(
            "rockbase_files_test_{}",
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&root).expect("create sandbox");
        std::env::set_current_dir(&root).expect("enter sandbox");
        std::fs::canonicalize(&root).expect("canonicalize sandbox")
    })
}

fn app() -> Router {
    sandbox();
    std::env::set_var("RB_JWT_SECRET", "testsecret");
    build_app(Connection::open_in_memory().unwrap(), "testtoken".into())
}

// ---------------------------------------------------------------- HTTP helpers

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(json!(null)))
}

/// Raw GET: (status, content-type, body bytes).
async fn get_raw(app: &Router, uri: &str, auth: Option<&str>) -> (StatusCode, String, Vec<u8>) {
    let mut req = Request::builder().method("GET").uri(uri);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, ct, bytes.to_vec())
}

// ------------------------------------------------------------ multipart bodies

struct Part {
    name: String,
    filename: Option<String>,
    ctype: Option<String>,
    body: Vec<u8>,
}

fn text(name: &str, value: &str) -> Part {
    Part {
        name: name.into(),
        filename: None,
        ctype: None,
        body: value.as_bytes().to_vec(),
    }
}

fn file(name: &str, filename: &str, body: &[u8]) -> Part {
    file_ct(name, filename, "text/plain", body)
}

fn file_ct(name: &str, filename: &str, ctype: &str, body: &[u8]) -> Part {
    Part {
        name: name.into(),
        filename: Some(filename.into()),
        ctype: Some(ctype.into()),
        body: body.to_vec(),
    }
}

fn encode(parts: &[Part]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        let mut cd = format!("Content-Disposition: form-data; name=\"{}\"", p.name);
        if let Some(f) = &p.filename {
            cd.push_str(&format!("; filename=\"{f}\""));
        }
        out.extend_from_slice(cd.as_bytes());
        out.extend_from_slice(b"\r\n");
        if let Some(ct) = &p.ctype {
            out.extend_from_slice(format!("Content-Type: {ct}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&p.body);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
    out
}

async fn upload(
    app: &Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    parts: &[Part],
) -> (StatusCode, Value) {
    upload_bytes(app, method, uri, auth, encode(parts)).await
}

async fn upload_bytes(
    app: &Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={BOUNDARY}"),
        );
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(json!(null)))
}

// ------------------------------------------------------------- fixture helpers

/// Create a collection, asserting 200. `body` is the full collections POST body.
async fn mkcol(app: &Router, body: Value) {
    let (s, v) = call(app, "POST", "/api/collections", Some(ADMIN), Some(body.clone())).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "create collection {body}: {v} — the \"file\" schema type must be accepted"
    );
}

/// The standard `posts` fixture: one text field, one file field.
async fn mkposts(app: &Router) {
    mkcol(
        app,
        json!({
            "name": "posts",
            "schema": [{"name": "title", "type": "text"}, {"name": "doc", "type": "file"}],
            "listRule": "", "viewRule": "", "createRule": "",
            "updateRule": "", "deleteRule": ""
        }),
    )
    .await;
}

/// Seed a user via the admin bypass and log in. Returns (id, "Bearer <token>").
async fn user(app: &Router, email: &str) -> (String, String) {
    let (s, u) = call(
        app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": email, "password": PW})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "seed user {email}: {u}");
    let id = u["id"].as_str().unwrap().to_string();
    let (s, v) = call(
        app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": email, "password": PW})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "login {email}: {v}");
    (id, format!("Bearer {}", v["token"].as_str().unwrap()))
}

/// Every stored filename must be something `sanitize_filename` could have produced.
fn assert_clean(raw: &str, stored: &Value) {
    let name = stored
        .as_str()
        .unwrap_or_else(|| panic!("upload of {raw:?}: stored value must be a filename string, got {stored}"));
    assert!(
        !name.is_empty(),
        "upload of {raw:?}: stored an empty filename"
    );
    assert!(
        name.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')),
        "upload of {raw:?} stored as {name:?}: only [A-Za-z0-9._-] may survive sanitization"
    );
    assert!(
        !name.contains(".."),
        "upload of {raw:?} stored as {name:?}: '..' must not survive"
    );
    assert!(
        !name.chars().all(|c| c == '.'),
        "upload of {raw:?} stored as {name:?}: dot-only names must be rejected"
    );
    assert!(
        name.len() <= 100,
        "upload of {raw:?} stored as {name:?}: filenames cap at 100 chars"
    );
}

// =============================================================== schema plumbing

// 1. `file` is a legal schema field type (specs/files.md "Schema: the file field type").
#[tokio::test]
async fn file_is_a_schema_field_type() {
    let app = app();
    mkposts(&app).await;
    let (s, v) = call(&app, "GET", "/api/collections/posts", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["schema"][1]["type"], "file", "file field type round-trips: {v}");
}

// 2. A file field may not be named after a reserved field, exactly like text fields.
//    RESERVED_FIELDS names are injected by record_json, so a `file` typed one would be
//    silently dropped — and its bytes orphaned on disk.
#[tokio::test]
async fn reserved_names_cannot_be_file_fields() {
    let app = app();
    for name in RESERVED_FIELDS {
        let (s, v) = call(
            &app,
            "POST",
            "/api/collections",
            Some(ADMIN),
            Some(json!({"name": format!("c_{}", name.to_lowercase()),
                        "schema": [{"name": name, "type": "file"}]})),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "'{name}' is reserved and must be rejected as a file field too: {v}"
        );
    }
}

// 3. `validate()` treats a file value as a string: a JSON body may not stuff a number in.
#[tokio::test]
async fn file_field_value_must_be_a_string() {
    let app = app();
    mkposts(&app).await;
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(json!({"title": "t", "doc": 42})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "a file field holds a filename string, not a number: {v}"
    );
    // null is still allowed (no file attached)
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(json!({"title": "t", "doc": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "null file field is allowed: {v}");
}

// =============================================================== happy path

// 4. Multipart create writes the file and the record; the download endpoint serves it.
//    (specs/files.md acceptance tests 1 and 2.)
#[tokio::test]
async fn upload_then_download_roundtrip() {
    let app = app();
    mkposts(&app).await;
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[text("title", "hello"), file("doc", "a.txt", b"hi")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "multipart create: {v}");
    assert_eq!(v["title"], "hello", "text part becomes a field: {v}");
    assert_eq!(v["doc"], "a.txt", "file part stores the sanitized filename: {v}");
    assert_eq!(v["collectionName"], "posts", "{v}");
    let id = v["id"].as_str().expect("id").to_string();

    let (s, ct, body) = get_raw(&app, &format!("/api/files/posts/{id}/a.txt"), None).await;
    assert_eq!(s, StatusCode::OK, "download a.txt");
    assert_eq!(body, b"hi", "served bytes are the uploaded bytes");
    assert!(ct.starts_with("text/plain"), "content-type from extension, got {ct:?}");

    // the record itself still reports the filename
    let (s, v) = call(&app, "GET", &format!("/api/collections/posts/records/{id}"), None, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["doc"], "a.txt", "{v}");
}

// 5. Text-only multipart is the JSON path: values are JSON-parsed when they parse.
//    (specs/files.md "Multipart with only text parts".)
#[tokio::test]
async fn text_only_multipart_matches_json_body() {
    let app = app();
    mkcol(
        &app,
        json!({"name": "notes",
               "schema": [{"name": "title", "type": "text"}, {"name": "views", "type": "number"}],
               "listRule": "", "viewRule": "", "createRule": "",
               "updateRule": "", "deleteRule": ""}),
    )
    .await;
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/notes/records",
        Some(ADMIN),
        &[text("title", "hello"), text("views", "42")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "text-only multipart create: {v}");
    assert_eq!(v["title"], "hello", "{v}");
    assert_eq!(v["views"], 42, "numeric text part is parsed as JSON: {v}");
}

// 6. Plain JSON create/update still works on a collection that has a file field
//    (regression guard for the Request-extractor rewrite), and a JSON-set filename
//    that has no bytes on disk downloads as 404, not 500.
#[tokio::test]
async fn json_body_still_works_on_a_file_collection() {
    let app = app();
    mkposts(&app).await;
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(json!({"title": "plain", "doc": "ghost.txt"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "JSON create: {v}");
    let id = v["id"].as_str().expect("id").to_string();

    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{id}"),
        Some(ADMIN),
        Some(json!({"title": "patched"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "JSON patch: {v}");
    assert_eq!(v["title"], "patched", "{v}");
    assert_eq!(v["doc"], "ghost.txt", "{v}");

    let (s, _, _) = get_raw(&app, &format!("/api/files/posts/{id}/ghost.txt"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "no bytes on disk for a JSON-set name");
}

// 7. Multipart PATCH replaces the file. (specs/files.md acceptance test 6.)
#[tokio::test]
async fn multipart_patch_replaces_the_file() {
    let app = app();
    mkposts(&app).await;
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[text("title", "hello"), file("doc", "a.txt", b"hi")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().expect("id").to_string();

    let (s, v) = upload(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{id}"),
        Some(ADMIN),
        &[file("doc", "b.txt", b"bye")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "multipart patch: {v}");
    assert_eq!(v["doc"], "b.txt", "{v}");
    assert_eq!(v["title"], "hello", "patch is a merge, title survives: {v}");

    let (s, _, body) = get_raw(&app, &format!("/api/files/posts/{id}/b.txt"), None).await;
    assert_eq!(s, StatusCode::OK, "new file serves");
    assert_eq!(body, b"bye");
}

// 8. Extension drives the served content-type; unknown extensions fall back.
#[tokio::test]
async fn unknown_extension_is_octet_stream() {
    let app = app();
    mkposts(&app).await;
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", "data.bin", b"\x00\x01\x02")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().expect("id").to_string();
    let (s, ct, body) = get_raw(&app, &format!("/api/files/posts/{id}/data.bin"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(ct.starts_with("application/octet-stream"), "got {ct:?}");
    assert_eq!(body, b"\x00\x01\x02");
}

// 9. Missing file → 404. (specs/files.md acceptance test 8.)
#[tokio::test]
async fn missing_file_is_404() {
    let app = app();
    mkposts(&app).await;
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", "a.txt", b"hi")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().expect("id").to_string();
    let (s, _, _) = get_raw(&app, &format!("/api/files/posts/{id}/nope.txt"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    // unknown record id, unknown collection
    let (s, _, _) = get_raw(&app, "/api/files/posts/nosuchrecord/a.txt", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = get_raw(&app, &format!("/api/files/nosuchcol/{id}/a.txt"), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// =============================================================== security: names

// 10. Sanitization: junk characters are stripped, dot-only names are rejected.
//     (specs/files.md acceptance test 3 + edge cases.)
#[tokio::test]
async fn filenames_are_sanitized() {
    let app = app();
    mkposts(&app).await;

    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", "we ird$$.PNG", b"px")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "sanitizable name is accepted: {v}");
    assert_eq!(v["doc"], "weird.PNG", "junk chars are stripped: {v}");
    let id = v["id"].as_str().expect("id").to_string();
    let (s, ct, body) = get_raw(&app, &format!("/api/files/posts/{id}/weird.PNG"), None).await;
    assert_eq!(s, StatusCode::OK, "sanitized name is what serves");
    assert_eq!(body, b"px");
    assert!(ct.starts_with("image/png"), "extension match is case-insensitive, got {ct:?}");
    // the pre-sanitization name must not be reachable
    let (s, _, _) = get_raw(&app, "/api/files/posts/x/we%20ird%24%24.PNG", None).await;
    assert_ne!(s, StatusCode::OK, "raw client filename must not be a valid key");

    // names that sanitize to nothing usable
    for bad in ["...", "..", ".", "???", "", "   "] {
        let (s, v) = upload(
            &app,
            "POST",
            "/api/collections/posts/records",
            Some(ADMIN),
            &[file("doc", bad, b"x")],
        )
        .await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "filename {bad:?} sanitizes to nothing and must be rejected: {v}"
        );
    }

    // over-long names are capped, never rejected into a 500 or written whole
    let long = format!("{}.txt", "a".repeat(400));
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", &long, b"x")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "long name is truncated, not fatal: {v}");
    assert_clean(&long, &v["doc"]);
}

// 11. THE traversal test: no attacker-supplied filename may write outside the
//     storage directory. Canaries live at absolute paths inside the sandbox, so this
//     holds no matter where the implementation puts its data dir.
#[tokio::test]
async fn upload_filenames_cannot_escape_storage() {
    let root = sandbox().clone();
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let canary_name = format!("canary_{tag}.txt");
    let canary = root.join(&canary_name);
    std::fs::write(&canary, b"CANARY").unwrap();
    let absolute = root.join(format!("abs_{tag}.txt"));

    let app = app();
    mkposts(&app).await;

    let mut attacks: Vec<String> = vec![
        "../../etc/passwd".into(),
        "../../../../../../../../etc/passwd".into(),
        "/etc/passwd".into(),
        "..\\..\\windows\\win.ini".into(),
        "..\\/..\\/etc/hosts".into(),
        r"C:\Windows\System32\drivers\etc\hosts".into(),
        absolute.to_string_lossy().into_owned(),
        "....//....//pwned.txt".into(),
        "..;/..;/pwned.txt".into(),
        "%2e%2e%2fpwned.txt".into(),
        "..%2f..%2fpwned.txt".into(),
        "\u{ff0e}\u{ff0e}\u{ff0f}pwned.txt".into(), // fullwidth . . /
        "\u{2024}\u{2024}\u{2215}pwned.txt".into(), // one-dot-leader + division slash
        "\u{ff0e}\u{ff0e}/pwned.txt".into(),
        "a\u{0000}.txt".into(),
        "\u{0000}../../pwned.txt".into(),
        "a.txt\u{0000}.png".into(),
        "\r\n../pwned.txt".into(),
        "a\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\ninjected.txt".into(),
        ".".repeat(200),
        "~/.ssh/authorized_keys".into(),
        "\u{202e}gnp.exe".into(), // right-to-left override
    ];
    // relative escapes at every plausible storage depth, all aimed at the canary
    for n in 1..=8 {
        attacks.push(format!("{}{canary_name}", "../".repeat(n)));
        attacks.push(format!("{}{canary_name}", "..\\".repeat(n)));
    }

    for raw in &attacks {
        let (s, v) = upload(
            &app,
            "POST",
            "/api/collections/posts/records",
            Some(ADMIN),
            &[file("doc", raw, b"PWNED")],
        )
        .await;
        assert!(
            s == StatusCode::OK || s == StatusCode::BAD_REQUEST,
            "upload of {raw:?}: expected 200 (sanitized) or 400 (rejected), got {s} {v}"
        );
        if s == StatusCode::OK {
            assert_clean(raw, &v["doc"]);
            // and the sanitized name must actually be what serves
            let id = v["id"].as_str().expect("id");
            let name = v["doc"].as_str().unwrap();
            let (gs, _, body) = get_raw(&app, &format!("/api/files/posts/{id}/{name}"), None).await;
            assert_eq!(gs, StatusCode::OK, "sanitized {raw:?} -> {name:?} must serve");
            assert_eq!(body, b"PWNED");
        }
    }

    assert_eq!(
        std::fs::read(&canary).unwrap(),
        b"CANARY",
        "a traversal filename overwrote the canary at {}",
        canary.display()
    );
    assert!(
        !absolute.exists(),
        "an absolute upload filename wrote outside storage: {}",
        absolute.display()
    );
    // nothing called pwned.txt / passwd anywhere in the sandbox
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let n = e.file_name().to_string_lossy().into_owned();
            assert!(
                !matches!(n.as_str(), "passwd" | "pwned.txt" | "hosts" | "win.ini" | "authorized_keys"),
                "traversal escaped: attacker bytes landed at {}",
                p.display()
            );
        }
    }
}

// 12. A file part must name a schema field of type `file`.
//     (specs/files.md acceptance test 4 + edge cases.)
#[tokio::test]
async fn file_part_must_target_a_file_field() {
    let app = app();
    mkposts(&app).await;

    // `title` is text
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("title", "a.txt", b"hi")],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "file part on a text field: {v}");

    // not in the schema at all
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("nosuch", "a.txt", b"hi")],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "file part on an unknown field: {v}");

    // reserved/system names must not be a back door either
    for name in RESERVED_FIELDS {
        let (s, v) = upload(
            &app,
            "POST",
            "/api/collections/posts/records",
            Some(ADMIN),
            &[file(name, "a.txt", b"hi")],
        )
        .await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "file part named '{name}' must be rejected: {v}"
        );
    }

    // and the same on PATCH
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", "a.txt", b"hi")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().expect("id").to_string();
    let (s, v) = upload(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{id}"),
        Some(ADMIN),
        &[file("title", "b.txt", b"hi")],
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "file part on a text field via PATCH: {v}");
}

// =============================================================== security: serving

// 13. The download URL is not a file browser: no path segment may read arbitrary disk.
#[tokio::test]
async fn download_url_cannot_read_arbitrary_paths() {
    let root = sandbox().clone();
    let tag = uuid::Uuid::new_v4().simple().to_string();
    let secret_name = format!("secret_{tag}.txt");
    std::fs::write(root.join(&secret_name), b"TOPSECRET").unwrap();

    let app = app();
    mkposts(&app).await;
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", "a.txt", b"hi")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().expect("id").to_string();

    let mut uris: Vec<String> = vec![
        format!("/api/files/posts/{id}/..%2F..%2F..%2F..%2Fdata.db"),
        format!("/api/files/posts/{id}/%2Fetc%2Fpasswd"),
        format!("/api/files/posts/{id}/..%5C..%5Cdata.db"),
        format!("/api/files/posts/{id}/a.txt%00.png"),
        format!("/api/files/posts/{id}/%2e%2e%2f%2e%2e%2fdata.db"),
        format!("/api/files/posts/{id}/....%2f%2f....%2f%2fdata.db"),
        format!("/api/files/posts/{id}/%252e%252e%252fdata.db"),
        format!("/api/files/posts/..%2F..%2Fetc/{id}/a.txt"),
        format!("/api/files/..%2F..%2Fetc/{id}/a.txt"),
        format!("/api/files/posts/{id}%2F..%2F..%2Fx/a.txt"),
        // the sanitized-name check must reject anything the upload path could not produce
        format!("/api/files/posts/{id}/we ird$$.PNG").replace(' ', "%20"),
        format!("/api/files/posts/{id}/."),
        format!("/api/files/posts/{id}/.."),
    ];
    for n in 1..=8 {
        uris.push(format!(
            "/api/files/posts/{id}/{}{secret_name}",
            "..%2F".repeat(n)
        ));
    }

    for uri in &uris {
        let (s, _, body) = get_raw(&app, uri, Some(ADMIN)).await;
        assert_ne!(s, StatusCode::OK, "{uri} must not serve anything");
        assert!(
            s == StatusCode::BAD_REQUEST || s == StatusCode::NOT_FOUND,
            "{uri}: expected 400/404, got {s}"
        );
        assert!(
            !String::from_utf8_lossy(&body).contains("TOPSECRET"),
            "{uri} leaked a file outside storage"
        );
        assert!(
            !body.starts_with(b"SQLite format 3\0"),
            "{uri} served the database"
        );
    }
}

// 14. The client's declared Content-Type is never echoed back; the extension decides.
//     Otherwise an attacker uploads `x.txt` labelled `text/html` and gets stored XSS.
#[tokio::test]
async fn client_content_type_is_not_trusted() {
    let app = app();
    mkposts(&app).await;

    // lying about a .txt to make it render as HTML
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file_ct("doc", "note.txt", "text/html", b"<script>alert(1)</script>")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().expect("id").to_string();
    let (s, ct, _) = get_raw(&app, &format!("/api/files/posts/{id}/note.txt"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        ct.starts_with("text/plain"),
        "content-type comes from the .txt extension, not the client's claim; got {ct:?}"
    );

    // and lying the other way does not downgrade a real image either
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file_ct("doc", "pic.png", "application/x-evil; charset=utf-7", b"\x89PNG")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().expect("id").to_string();
    let (s, ct, _) = get_raw(&app, &format!("/api/files/posts/{id}/pic.png"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(ct.starts_with("image/png"), "got {ct:?}");
    assert!(
        !ct.contains("x-evil") && !ct.contains("utf-7"),
        "client content-type must never be reflected: {ct:?}"
    );
}

// 15. Body limit: the multipart cap is 10MB. Under it works (proving the default 2MB
//     limit was raised), over it is 413 and nothing is written.
#[tokio::test]
async fn oversized_upload_is_413() {
    let app = app();
    mkposts(&app).await;

    // 3MB — above axum's 2MB default, below the 10MB cap
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", "big.bin", &vec![b'x'; 3 * 1024 * 1024])],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "3MB upload must fit under the 10MB cap: {v}");
    let id = v["id"].as_str().expect("id").to_string();
    let (s, _, body) = get_raw(&app, &format!("/api/files/posts/{id}/big.bin"), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body.len(), 3 * 1024 * 1024, "all bytes round-trip");

    // 11MB — over the cap
    let (s, _) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", "huge.bin", &vec![b'x'; 11 * 1024 * 1024])],
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "11MB must be rejected");

    // rejected upload left no record behind
    let (s, v) = call(&app, "GET", "/api/collections/posts/records", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["totalItems"], 1, "only the 3MB record exists: {v}");

    // an oversized body with a huge *filename* is also refused, not written
    let (s, _) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", &"a".repeat(9000), &vec![b'x'; 11 * 1024 * 1024])],
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
}

// =============================================================== security: rules
//
// specs/files.md predates per-collection API rules and says "No auth on downloads".
// That is wrong: an unguessable filename is not access control. Uploading is a record
// create/update and must pass the create/update rule; downloading a file attached to a
// record the caller may not view must be denied.

// 16. Uploading is a record write and obeys the create and update rules.
#[tokio::test]
async fn upload_obeys_create_and_update_rules() {
    let app = app();
    let (_a_id, a) = user(&app, "a@cave.dev").await;
    let (_b_id, b) = user(&app, "b@cave.dev").await;
    // defaults for a base collection: public read, authed write
    mkcol(
        &app,
        json!({"name": "docs",
               "schema": [{"name": "owner", "type": "text"}, {"name": "doc", "type": "file"}]}),
    )
    .await;

    // guest multipart create → 401, and nothing is stored
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/docs/records",
        None,
        &[file("doc", "guest.txt", b"nope")],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "guest upload must be denied: {v}");
    let (s, v) = call(&app, "GET", "/api/collections/docs/records", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["totalItems"], 0, "a denied upload creates no record: {v}");

    // A uploads
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/docs/records",
        Some(&a),
        &[text("owner", "a"), file("doc", "mine.txt", b"AAA")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "authed upload: {v}");
    let id = v["id"].as_str().expect("id").to_string();

    // lock updates to nobody, then B (and A) must not be able to replace the bytes
    let (s, v) = call(
        &app,
        "PATCH",
        "/api/collections/docs",
        Some(ADMIN),
        Some(json!({"updateRule": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = upload(
        &app,
        "PATCH",
        &format!("/api/collections/docs/records/{id}"),
        Some(&b),
        &[file("doc", "hijack.txt", b"BBB")],
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "admin-only updateRule blocks B: {v}");

    // the original bytes are untouched and no hijack file was written
    let (s, _, body) = get_raw(&app, &format!("/api/files/docs/{id}/mine.txt"), Some(ADMIN)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, b"AAA", "denied PATCH must not overwrite");
    let (s, _, _) = get_raw(&app, &format!("/api/files/docs/{id}/hijack.txt"), Some(ADMIN)).await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "a denied PATCH must not write its file to disk"
    );
}

// 17. Downloading obeys the view rule. An unguessable filename is not access control.
#[tokio::test]
async fn download_obeys_the_view_rule() {
    let app = app();
    let (a_id, a) = user(&app, "owner@cave.dev").await;
    let (_b_id, b) = user(&app, "other@cave.dev").await;
    mkcol(
        &app,
        json!({"name": "private",
               "schema": [{"name": "owner", "type": "text"}, {"name": "doc", "type": "file"}],
               "listRule": "owner = @request.auth.id",
               "viewRule": "owner = @request.auth.id",
               "createRule": "@request.auth.id != ''",
               "updateRule": "owner = @request.auth.id",
               "deleteRule": "owner = @request.auth.id"}),
    )
    .await;

    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/private/records",
        Some(&a),
        &[text("owner", &a_id), file("doc", "salary.pdf", b"CONFIDENTIAL")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner uploads: {v}");
    let id = v["id"].as_str().expect("id").to_string();
    let uri = format!("/api/files/private/{id}/salary.pdf");

    // sanity: B cannot view the record
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/collections/private/records/{id}"),
        Some(&b),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "record view is gated");

    // therefore B cannot fetch the attached file either
    let (s, _, body) = get_raw(&app, &uri, Some(&b)).await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "a file attached to a record the caller cannot view must not download"
    );
    assert!(!String::from_utf8_lossy(&body).contains("CONFIDENTIAL"));

    // nor can a guest
    let (s, _, body) = get_raw(&app, &uri, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "guest download must be denied");
    assert!(!String::from_utf8_lossy(&body).contains("CONFIDENTIAL"));

    // the owner and an admin can
    let (s, _, body) = get_raw(&app, &uri, Some(&a)).await;
    assert_eq!(s, StatusCode::OK, "owner downloads their own file");
    assert_eq!(body, b"CONFIDENTIAL");
    let (s, _, body) = get_raw(&app, &uri, Some(ADMIN)).await;
    assert_eq!(s, StatusCode::OK, "admin bypasses rules");
    assert_eq!(body, b"CONFIDENTIAL");
}

// =============================================================== lifecycle

// 18. Deleting the record deletes its files. (specs/files.md acceptance test 7.)
#[tokio::test]
async fn delete_record_removes_its_files() {
    let app = app();
    mkposts(&app).await;
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", "a.txt", b"hi")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().expect("id").to_string();
    let uri = format!("/api/files/posts/{id}/a.txt");
    let (s, _, _) = get_raw(&app, &uri, Some(ADMIN)).await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = call(
        &app,
        "DELETE",
        &format!("/api/collections/posts/records/{id}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let (s, _, body) = get_raw(&app, &uri, Some(ADMIN)).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "bytes are gone after record delete");
    assert!(!String::from_utf8_lossy(&body).contains("hi"));

    // and a new record reusing the same route sees nothing stale
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        &[file("doc", "b.txt", b"new")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id2 = v["id"].as_str().expect("id").to_string();
    let (s, _, _) = get_raw(&app, &format!("/api/files/posts/{id2}/a.txt"), Some(ADMIN)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// 19. A denied delete must not delete the files either.
#[tokio::test]
async fn denied_delete_keeps_the_file() {
    let app = app();
    let (a_id, a) = user(&app, "keep@cave.dev").await;
    let (_b_id, b) = user(&app, "nope@cave.dev").await;
    mkcol(
        &app,
        json!({"name": "vault",
               "schema": [{"name": "owner", "type": "text"}, {"name": "doc", "type": "file"}],
               "listRule": "", "viewRule": "", "createRule": "@request.auth.id != ''",
               "updateRule": "owner = @request.auth.id",
               "deleteRule": "owner = @request.auth.id"}),
    )
    .await;
    let (s, v) = upload(
        &app,
        "POST",
        "/api/collections/vault/records",
        Some(&a),
        &[text("owner", &a_id), file("doc", "keep.txt", b"KEEP")],
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().expect("id").to_string();

    let (s, v) = call(
        &app,
        "DELETE",
        &format!("/api/collections/vault/records/{id}"),
        Some(&b),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "B may not delete A's record: {v}");

    let (s, _, body) = get_raw(&app, &format!("/api/files/vault/{id}/keep.txt"), None).await;
    assert_eq!(s, StatusCode::OK, "a denied delete must not remove the file");
    assert_eq!(body, b"KEEP");
}
