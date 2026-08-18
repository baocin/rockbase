// Collection read + schema update: GET/PATCH /api/collections/{name}.
// TDD red phase — the route currently only carries DELETE, so GET/PATCH 405 today.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

use rockbase::build_app;

const ADMIN: &str = "Admin testtoken";
const RULES: [&str; 5] = [
    "listRule",
    "viewRule",
    "createRule",
    "updateRule",
    "deleteRule",
];

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

/// posts: required `title` text + `views` number.
async fn seed_posts(app: &Router) {
    let (s, _) = call(
        app,
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
}

/// A logged-in non-admin bearer token.
async fn seed_user(app: &Router, email: &str) -> String {
    let (s, _) = call(
        app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": email, "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": email, "password": "clubrock1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    format!("Bearer {}", v["token"].as_str().unwrap())
}

fn field_names(v: &Value) -> Vec<&str> {
    v["schema"]
        .as_array()
        .unwrap_or_else(|| panic!("schema must be an array, got {v}"))
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect()
}

#[tokio::test]
async fn get_collection_returns_full_shape() {
    let app = app();
    seed_posts(&app).await;

    let (s, v) = call(&app, "GET", "/api/collections/posts", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["name"], "posts");
    assert_eq!(v["type"], "base");
    assert_eq!(field_names(&v), ["title", "views"]);
    assert_eq!(v["schema"][0]["required"], json!(true));
    assert_eq!(v["schema"][1]["type"], "number");
    // rules are present keys, all null on a fresh collection
    for k in RULES {
        assert!(v.get(k).is_some(), "missing rule key {k} in {v}");
        assert!(v[k].is_null(), "rule {k} should be null, got {}", v[k]);
    }

    // the seeded auth collection reports its type too
    let (s, v) = call(&app, "GET", "/api/collections/users", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["type"], "auth");
    assert_eq!(v["schema"], json!([]));
}

#[tokio::test]
async fn get_missing_collection_404s() {
    let app = app();
    let (s, v) = call(&app, "GET", "/api/collections/nope", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["code"], 404);
}

#[tokio::test]
async fn get_and_patch_require_admin() {
    let app = app();
    seed_posts(&app).await;
    let bearer = seed_user(&app, "nonadmin@cave.dev").await;

    for auth in [None, Some(bearer.as_str()), Some("Admin wrongtoken")] {
        let (s, v) = call(&app, "GET", "/api/collections/posts", auth, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "GET auth={auth:?}");
        assert_eq!(v["code"], 401);

        let (s, v) = call(
            &app,
            "PATCH",
            "/api/collections/posts",
            auth,
            Some(json!({"schema": [{"name": "title", "type": "text"}]})),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "PATCH auth={auth:?}");
        assert_eq!(v["code"], 401);
    }

    // and the non-admin PATCH changed nothing
    let (s, v) = call(&app, "GET", "/api/collections/posts", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(field_names(&v), ["title", "views"]);
}

#[tokio::test]
async fn patch_missing_collection_404s() {
    let app = app();
    let (s, v) = call(
        &app,
        "PATCH",
        "/api/collections/nope",
        Some(ADMIN),
        Some(json!({"schema": []})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(v["code"], 404);
}

#[tokio::test]
async fn patch_replaces_schema_and_merges_rules() {
    let app = app();
    seed_posts(&app).await;

    // full replacement: drop `views`, add `tags`, drop `required` off `title`
    let (s, v) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({
            "schema": [{"name": "title", "type": "text"}, {"name": "tags", "type": "json"}],
            "listRule": ""
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(field_names(&v), ["title", "tags"]);

    // GET reflects it, and only the sent rule key changed
    let (s, v) = call(&app, "GET", "/api/collections/posts", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["name"], "posts");
    assert_eq!(v["type"], "base");
    assert_eq!(field_names(&v), ["title", "tags"]);
    assert_eq!(v["schema"][1]["type"], "json");
    assert!(
        v["schema"][0].get("required").map_or(true, |r| !r.as_bool().unwrap_or(true)),
        "title should no longer be required: {v}"
    );
    assert_eq!(v["listRule"], json!(""));
    for k in ["viewRule", "createRule", "updateRule", "deleteRule"] {
        assert!(v[k].is_null(), "rule {k} should still be null, got {}", v[k]);
    }

    // a second PATCH touching one rule leaves listRule alone
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"deleteRule": "@request.auth.id != ''"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&app, "GET", "/api/collections/posts", Some(ADMIN), None).await;
    assert_eq!(v["listRule"], json!(""));
    assert_eq!(v["deleteRule"], "@request.auth.id != ''");
    assert_eq!(field_names(&v), ["title", "tags"], "rule PATCH must not touch schema");

    // rules are null-able again
    let (s, v) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"deleteRule": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["deleteRule"].is_null(), "{v}");
}

#[tokio::test]
async fn patch_empty_body_is_a_noop() {
    let app = app();
    seed_posts(&app).await;

    let (s, before) = call(&app, "GET", "/api/collections/posts", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(&app, "PATCH", "/api/collections/posts", Some(ADMIN), Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v, before, "empty PATCH must return the unchanged collection");
}

#[tokio::test]
async fn patch_rejects_bad_input() {
    let app = app();
    seed_posts(&app).await;

    let bad_bodies = [
        // same validity rules as create: ident_ok(name), type in text|number|bool|json
        json!({"schema": [{"name": "x", "type": "blob"}]}),
        json!({"schema": [{"name": "bad-name", "type": "text"}]}),
        json!({"schema": [{"name": "", "type": "text"}]}),
        json!({"schema": [{"name": "x"}]}),
        json!({"schema": [{"type": "text"}]}),
        // schema must be an array
        json!({"schema": {"title": "text"}}),
        json!({"schema": "title"}),
        // name/type cannot be changed
        json!({"name": "renamed"}),
        json!({"name": "bad-name!"}),
        json!({"type": "auth"}),
        json!({"type": "base"}),
        // rules must be string or null
        json!({"listRule": 5}),
        json!({"viewRule": ["a"]}),
        json!({"createRule": {"a": 1}}),
        json!({"updateRule": true}),
    ];
    for body in bad_bodies {
        let (s, v) = call(
            &app,
            "PATCH",
            "/api/collections/posts",
            Some(ADMIN),
            Some(body.clone()),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "body={body}");
        assert_eq!(v["code"], 400, "body={body}");
    }

    // unknown keys are ignored, not rejected
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"whatever": 1, "id": "abc"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // nothing above mutated the collection
    let (s, v) = call(&app, "GET", "/api/collections/posts", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["name"], "posts");
    assert_eq!(v["type"], "base");
    assert_eq!(field_names(&v), ["title", "views"]);
}

#[tokio::test]
async fn dropped_field_lingers_in_stored_records_but_is_unwritable() {
    let app = app();
    seed_posts(&app).await;
    let bearer = seed_user(&app, "dropper@cave.dev").await;

    let (s, rec) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "old", "views": 10})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let id = rec["id"].as_str().unwrap().to_string();

    // drop `views` from the schema
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"schema": [{"name": "title", "type": "text", "required": true}]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // existing data is untouched: still round-trips on view and list
    let (s, v) = call(&app, "GET", &format!("/api/collections/posts/records/{id}"), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["views"], 10);
    let (s, v) = call(&app, "GET", "/api/collections/posts/records", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["items"][0]["views"], 10);

    // but writing the removed field is now an unknown field
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "new", "views": 1})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["message"], "unknown field 'views'");
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{id}"),
        Some(&bearer),
        Some(json!({"views": 2})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // a write without the removed field still works
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "new"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn adding_required_field_does_not_backfill_existing_records() {
    let app = app();
    seed_posts(&app).await;
    let bearer = seed_user(&app, "req@cave.dev").await;

    let (s, rec) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "before"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let id = rec["id"].as_str().unwrap().to_string();

    // add a required `slug`
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "views", "type": "number"},
            {"name": "slug", "type": "text", "required": true}
        ]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // the old record is still readable and simply has no slug
    let (s, v) = call(&app, "GET", &format!("/api/collections/posts/records/{id}"), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v.get("slug").is_none(), "no backfill expected: {v}");

    // partial PATCH of the old record still succeeds (no required check on PATCH)
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{id}"),
        Some(&bearer),
        Some(json!({"views": 3})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // but new records must carry it
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "after"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(v["message"], "field 'slug' is required");
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "after", "slug": "after"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn changed_field_type_only_affects_future_writes() {
    let app = app();
    seed_posts(&app).await;
    let bearer = seed_user(&app, "typer@cave.dev").await;

    let (s, rec) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "t", "views": 7})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let id = rec["id"].as_str().unwrap().to_string();

    // views: number -> text
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "views", "type": "text"}
        ]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // stored value is not re-validated
    let (s, v) = call(&app, "GET", &format!("/api/collections/posts/records/{id}"), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["views"], 7);

    // new writes follow the new type
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "t2", "views": 8})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&bearer),
        Some(json!({"title": "t2", "views": "eight"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn auth_collection_schema_edits_leave_email_and_password_alone() {
    let app = app();

    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/users",
        Some(ADMIN),
        Some(json!({"schema": [{"name": "nickname", "type": "text"}]})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = call(&app, "GET", "/api/collections/users", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["type"], "auth");
    assert_eq!(field_names(&v), ["nickname"]);

    // email/password still work, nickname is now a real field, password_hash never leaks
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": "nick@cave.dev", "password": "clubrock1", "nickname": "nick"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["nickname"], "nick");
    assert!(v.get("password_hash").is_none());

    // DELETE on the route is unchanged and still allowed for users
    let (s, _) = call(&app, "DELETE", "/api/collections/users", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, "GET", "/api/collections/users", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}
