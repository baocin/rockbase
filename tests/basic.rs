use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

use rockbase::build_app;

const ADMIN: &str = "Admin testtoken";

fn app() -> Router {
    std::env::set_var("RB_JWT_SECRET", "testsecret");
    build_app(Connection::open_in_memory().unwrap(), "testtoken".into())
}

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
    let val = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, val)
}

async fn call_raw(
    app: &Router,
    method: &str,
    uri: &str,
    auth: Option<&str>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes.to_vec())
}

fn scratch(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "rockbase_test_{}_{name}",
        uuid::Uuid::new_v4().simple()
    ))
}

#[tokio::test]
async fn backups() {
    // clear stale backup temp files so the cleanup assertion below is exact
    for e in std::fs::read_dir(std::env::temp_dir()).unwrap().flatten() {
        if e.file_name()
            .to_string_lossy()
            .starts_with("rockbase_backup_")
        {
            let _ = std::fs::remove_file(e.path());
        }
    }

    let app = app();

    // no auth -> 401 JSON
    let (s, v) = call(&app, "GET", "/api/backups", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["code"], 401);

    // user bearer -> still 401 (admin only)
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": "bk@cave.dev", "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": "bk@cave.dev", "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let bearer = format!("Bearer {}", v["token"].as_str().unwrap());
    let (s, _) = call(&app, "GET", "/api/backups", Some(&bearer), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // seed data for the round-trip
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "notes", "schema": [{"name": "body", "type": "text"}]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/notes/records",
        Some(ADMIN),
        Some(json!({"body": "hi"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // admin -> 200, right headers, SQLite magic
    let (s, h, body) = call_raw(&app, "GET", "/api/backups", Some(ADMIN)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h["content-type"], "application/octet-stream");
    let cd = h["content-disposition"].to_str().unwrap();
    assert!(cd.starts_with("attachment; filename=\"rockbase_"), "{cd}");
    assert!(cd.ends_with(".db\""), "{cd}");
    assert!(body.starts_with(b"SQLite format 3\0"));

    // round-trip: restored file is a working DB with our data
    let restored = scratch("restore.db");
    std::fs::write(&restored, &body).unwrap();
    let conn = Connection::open(&restored).unwrap();
    let n: i64 = conn
        .query_row("SELECT COUNT(*) FROM records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2); // 1 user + 1 note
    let has: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM _collections WHERE name = 'notes'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(has, 1);
    drop(conn);
    let _ = std::fs::remove_file(&restored);

    // temp cleanup: no backup temp files left behind
    let leftovers: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with("rockbase_backup_")
        })
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[tokio::test]
async fn wal_persists_on_file_db() {
    let path = scratch("wal.db");
    let _app = build_app(Connection::open(&path).unwrap(), "testtoken".into());
    // fresh second connection: WAL mode is persistent in the file
    let conn = Connection::open(&path).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    drop(conn);
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", path.display()));
    }
}

#[tokio::test]
async fn full_flow() {
    let app = app();

    // collections need admin
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections",
        None,
        Some(json!({"name": "posts"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // create collection with schema
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "posts", "schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "views", "type": "number"}
        ]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // unauth write blocked
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        None,
        Some(json!({"title": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // sign up user, log in
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": "og@cave.dev", "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": "og@cave.dev", "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let bearer = format!("Bearer {}", v["token"].as_str().unwrap());
    assert!(v["record"].get("password_hash").is_none());

    // bad password rejected
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": "og@cave.dev", "password": "wrongwrong"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // validation: required + type + unknown field
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"views": 1})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": 5})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "a", "nope": 1})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // create two, filter, sort
    let (s, first) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "first", "views": 10})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "second", "views": 99})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?filter=views%3E50",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["totalItems"], 1);
    assert_eq!(v["items"][0]["title"], "second");

    // expression filter: && works, dangling || is a 400
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?filter=views%3E50%20%26%26%20title%3D'second'",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["totalItems"], 1);
    assert_eq!(v["items"][0]["title"], "second");
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?filter=views%3E50%20%7C%7C",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["code"], 400);

    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?sort=-views",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["items"][0]["title"], "second");

    // view, patch, delete
    let id = first["id"].as_str().unwrap();
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{id}"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["title"], "first");

    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{id}"),
        Some(&bearer),
        Some(json!({"views": 11})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["views"], 11);
    assert_eq!(v["title"], "first");

    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/collections/posts/records/{id}"),
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{id}"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // duplicate email blocked
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": "og@cave.dev", "password": "clubrock2"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn query_extras_and_patch_null() {
    let app = app();

    // seed: posts collection, a user, three posts
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "posts", "schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "views", "type": "number"}
        ]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": "q@cave.dev", "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": "q@cave.dev", "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let bearer = format!("Bearer {}", v["token"].as_str().unwrap());
    let mut id_b = String::new();
    for (title, views) in [("b", 5), ("a", 5), ("c", 9)] {
        let (s, v) = call(
            &app,
            "POST",
            "/api/collections/posts/records",
            Some(&bearer),
            Some(json!({"title": title, "views": views})),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        if title == "b" {
            id_b = v["id"].as_str().unwrap().to_string();
        }
    }

    // 1. multi-field sort: views DESC, title ASC tiebreak
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?sort=-views,title",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let titles: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["c", "a", "b"]);

    // 2. bad sort segments -> 400
    for uri in [
        "/api/collections/posts/records?sort=views,bad-seg!",
        "/api/collections/posts/records?sort=views,",
    ] {
        let (s, v) = call(&app, "GET", uri, None, None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert_eq!(v["message"], "bad sort field");
    }

    // 3. fields projection: exactly id + title
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?fields=title",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    for item in v["items"].as_array().unwrap() {
        let keys: Vec<&String> = item.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 2, "{item}");
        assert!(
            item.get("id").is_some() && item.get("title").is_some(),
            "{item}"
        );
    }

    // 4. bad fields segment -> 400
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?fields=title;views",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["message"], "bad fields");

    // 5. skipTotal=1: -1 sentinels, pagination still works
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?skipTotal=1&perPage=2",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["totalItems"], -1);
    assert_eq!(v["totalPages"], -1);
    assert_eq!(v["items"].as_array().unwrap().len(), 2);

    // 6. params compose: filter + skipTotal + sort + fields
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?filter=views%3E4&skipTotal=1&sort=-views&fields=title",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["totalItems"], -1);
    assert_eq!(v["items"][0]["title"], "c");
    for item in v["items"].as_array().unwrap() {
        assert_eq!(item.as_object().unwrap().len(), 2, "{item}");
    }

    // 7. PATCH null on a required field -> 400, record unchanged
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{id_b}"),
        Some(&bearer),
        Some(json!({"title": null})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["message"], "field 'title' is required");
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{id_b}"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["title"], "b");

    // 8. PATCH null on a non-required field -> 200
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{id_b}"),
        Some(&bearer),
        Some(json!({"views": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["views"], json!(null));
}

#[tokio::test]
async fn auth_refresh_identity_and_existence() {
    let app = app();

    // seed: posts collection, a user, log in
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "posts", "schema": [{"name": "title", "type": "text"}]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, u) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": "og@cave.dev", "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let uid = u["id"].as_str().unwrap().to_string();
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": "og@cave.dev", "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let bearer = format!("Bearer {}", v["token"].as_str().unwrap());

    // 1. refresh ok: fresh token + record, password_hash stripped
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/auth-refresh",
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let fresh = v["token"].as_str().unwrap().to_string();
    assert!(!fresh.is_empty());
    assert_eq!(v["record"]["email"], "og@cave.dev");
    assert_eq!(v["record"]["id"], uid.as_str());
    assert!(v["record"].get("password_hash").is_none());

    // 2. refreshed token works as a writer
    let fresh_bearer = format!("Bearer {fresh}");
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&fresh_bearer),
        Some(json!({"title": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // 3. no / garbage token -> 401
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/auth-refresh",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["code"], 401);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/auth-refresh",
        Some("Bearer notatoken"),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // 4. admin token rejected (not an auth record)
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/auth-refresh",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // 5. wrong collection: users token against staff refresh -> 401
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "staff", "type": "auth"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/staff/auth-refresh",
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["message"], "token is for another collection");

    // 7. password change via PATCH: old login dies, new works
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/collections/users/records/{uid}"),
        Some(&bearer),
        Some(json!({"password": "newpass99"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": "og@cave.dev", "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": "og@cave.dev", "password": "newpass99"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // 6. deleted user is Guest: old bearer stops writing and refreshing
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/collections/users/records/{uid}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "y"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/auth-refresh",
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
