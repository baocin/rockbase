// Transactional batch endpoint (specs/batch.md) — TDD red phase.
//
// Everything talks HTTP against `build_app`, same harness style as tests/rules.rs.
//
// Two things these tests pin that the spec does not:
//  1. RULES. specs/batch.md predates per-collection API rules. A batch sub-request
//     MUST be gated by the same create/update/delete rule as the standalone
//     endpoint, otherwise POST /api/batch is a privilege-escalation hole.
//  2. ROLLBACK PROOF. Every rollback test asserts the failure response FIRST
//     (status + index + message), so a missing/404 route fails the test instead of
//     vacuously "passing" the no-writes assertion; then compares a full DB snapshot
//     taken before the batch; then re-runs the batch's first sub-request standalone
//     to prove it was valid on its own (so its absence is rollback, not invalidity).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

use rockbase::build_app;

const ADMIN: &str = "Admin testtoken";
const PW: &str = "clubrock1";

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

/// One batch sub-request.
fn r(method: &str, url: &str, body: Option<Value>) -> Value {
    match body {
        Some(b) => json!({"method": method, "url": url, "body": b}),
        None => json!({"method": method, "url": url}),
    }
}

/// POST /api/batch with a `requests` array.
async fn batch(app: &Router, auth: Option<&str>, requests: Value) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        "/api/batch",
        auth,
        Some(json!({"requests": requests})),
    )
    .await
}

/// Seed a user through the admin bypass and log in. Returns (id, "Bearer <token>").
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

/// `posts` with a required `title`, a numeric `views` and an `author` owner field.
/// `extra` merges extra top-level keys into the create body (rules, mostly).
async fn mkposts(app: &Router, extra: Value) {
    let mut body = json!({
        "name": "posts",
        "schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "views", "type": "number"},
            {"name": "author", "type": "text"}
        ]
    });
    if let Some(m) = extra.as_object() {
        for (k, v) in m {
            body[k] = v.clone();
        }
    }
    let (s, v) = call(app, "POST", "/api/collections", Some(ADMIN), Some(body)).await;
    assert_eq!(s, StatusCode::OK, "create posts: {v}");
}

async fn mkpost(app: &Router, auth: &str, body: Value) -> String {
    let (s, v) = call(
        app,
        "POST",
        "/api/collections/posts/records",
        Some(auth),
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "seed post: {v}");
    v["id"].as_str().unwrap().to_string()
}

async fn records(app: &Router, name: &str) -> Value {
    let (s, v) = call(
        app,
        "GET",
        &format!("/api/collections/{name}/records?perPage=500&sort=id"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "list {name}: {v}");
    v
}

async fn total(app: &Router, name: &str) -> i64 {
    records(app, name).await["totalItems"].as_i64().unwrap()
}

/// Everything an HTTP client can observe of the database: every collection with its
/// rules and schema, plus every record of every collection with its id, data,
/// `created` and `updated`. Any partial write — an inserted row, a deleted row, a
/// changed field, a bumped `updated` timestamp — changes this value.
async fn snapshot(app: &Router) -> Value {
    let (s, cols) = call(app, "GET", "/api/collections", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK, "snapshot collections: {cols}");
    let mut out = serde_json::Map::new();
    for c in cols["items"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        out.insert(name.to_string(), records(app, name).await["items"].clone());
    }
    out.insert("_collections".into(), cols["items"].clone());
    Value::Object(out)
}

/// A batch failure: 400 envelope carrying the inner message and the failing index.
fn assert_failed_at(s: StatusCode, v: &Value, index: usize, msg_part: &str) {
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "batch should fail with 400: {v}"
    );
    assert_eq!(v["code"], 400, "error envelope code: {v}");
    assert_eq!(v["index"], json!(index), "failing index: {v}");
    let m = v["message"].as_str().unwrap_or_default();
    assert!(
        m.contains(msg_part),
        "message {m:?} should contain {msg_part:?}: {v}"
    );
}

// ---------------------------------------------------------------- happy paths

// spec test 1
#[tokio::test]
async fn happy_path_two_creates_commit() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;

    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"title": "a"}))
            ),
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"title": "b", "views": 3}))
            ),
        ]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "batch: {v}");
    let items = v
        .as_array()
        .unwrap_or_else(|| panic!("body should be an array: {v}"));
    assert_eq!(items.len(), 2, "one result per request: {v}");
    assert_eq!(items[0]["title"], "a");
    assert_eq!(items[0]["collectionName"], "posts");
    assert!(
        items[0]["id"].as_str().is_some_and(|i| !i.is_empty()),
        "result 0 has an id: {v}"
    );
    assert_eq!(items[1]["title"], "b");
    assert_eq!(items[1]["views"], 3);
    assert_ne!(items[0]["id"], items[1]["id"], "distinct ids: {v}");

    assert_eq!(total(&app, "posts").await, 2);
}

// spec test 3
#[tokio::test]
async fn mixed_methods_patch_then_delete() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;
    let id = mkpost(&app, &tok, json!({"title": "t"})).await;

    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([
            r(
                "PATCH",
                &format!("/api/collections/posts/records/{id}"),
                Some(json!({"views": 5}))
            ),
            r(
                "DELETE",
                &format!("/api/collections/posts/records/{id}"),
                None
            ),
        ]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "batch: {v}");
    let items = v
        .as_array()
        .unwrap_or_else(|| panic!("body should be an array: {v}"));
    assert_eq!(items.len(), 2, "{v}");
    assert_eq!(items[0]["id"], json!(id), "PATCH returns the record: {v}");
    assert_eq!(items[0]["views"], 5);
    assert_eq!(items[0]["title"], "t");
    assert_eq!(items[1], json!({}), "DELETE returns {{}}: {v}");

    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{id}"),
        Some(&tok),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "record is gone after the batch");
    assert_eq!(total(&app, "posts").await, 0);
}

// spec test 8
#[tokio::test]
async fn empty_batch_is_ok() {
    let app = app();
    let (_, tok) = user(&app, "a@x.com").await;
    let (s, v) = batch(&app, Some(&tok), json!([])).await;
    assert_eq!(s, StatusCode::OK, "empty batch: {v}");
    assert_eq!(v, json!([]));
}

#[tokio::test]
async fn fifty_requests_is_the_boundary_not_the_cap() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;
    let reqs: Vec<Value> = (0..50)
        .map(|i| {
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"title": format!("t{i}")})),
            )
        })
        .collect();

    let (s, v) = batch(&app, Some(&tok), json!(reqs)).await;
    assert_eq!(s, StatusCode::OK, "50 requests must be accepted: {v}");
    assert_eq!(v.as_array().map(|a| a.len()), Some(50), "{v}");
    assert_eq!(total(&app, "posts").await, 50);
}

// ------------------------------------------------------------ shape / framing

// spec test 6
#[tokio::test]
async fn guest_is_rejected_before_any_work() {
    let app = app();
    mkposts(&app, json!({})).await;

    let (s, v) = batch(
        &app,
        None,
        json!([r(
            "POST",
            "/api/collections/posts/records",
            Some(json!({"title": "a"}))
        )]),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "guest batch: {v}");
    assert_eq!(v["code"], 401, "{v}");
    assert_eq!(total(&app, "posts").await, 0, "guest batch wrote nothing");
}

#[tokio::test]
async fn requests_must_be_an_array() {
    let app = app();
    let (_, tok) = user(&app, "a@x.com").await;

    for body in [
        json!({}),
        json!({"requests": "nope"}),
        json!({"requests": {"a": 1}}),
        json!({"requests": 3}),
    ] {
        let (s, v) = call(&app, "POST", "/api/batch", Some(&tok), Some(body.clone())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "body {body}: {v}");
        assert_eq!(
            v["message"], "requests must be an array",
            "body {body}: {v}"
        );
    }
}

// spec test 5
#[tokio::test]
async fn cap_of_fifty_rejects_before_executing_anything() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;
    let before = snapshot(&app).await;

    // 51 individually valid creates: the cap is the only possible reason to fail
    let reqs: Vec<Value> = (0..51)
        .map(|i| {
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"title": format!("t{i}")})),
            )
        })
        .collect();
    let (s, v) = batch(&app, Some(&tok), json!(reqs)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "51 requests: {v}");
    assert_eq!(v["message"], "max 50 requests per batch", "{v}");
    assert_eq!(total(&app, "posts").await, 0, "nothing executed: {v}");
    assert_eq!(
        snapshot(&app).await,
        before,
        "cap rejection must not touch the db"
    );
}

// spec test 7
#[tokio::test]
async fn bad_method_or_url_fails_at_its_index() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;
    let id = mkpost(&app, &tok, json!({"title": "t"})).await;
    let one = format!("/api/collections/posts/records/{id}");

    let bad = [
        r("GET", "/api/collections/posts/records", None),
        r(
            "post",
            "/api/collections/posts/records",
            Some(json!({"title": "a"})),
        ), // case-sensitive
        r("PUT", &one, Some(json!({"title": "a"}))),
        r("POST", "/api/health", Some(json!({}))),
        r("POST", &one, Some(json!({"title": "a"}))), // POST must have no id
        r(
            "PATCH",
            "/api/collections/posts/records",
            Some(json!({"title": "a"})),
        ), // PATCH needs an id
        r("DELETE", "/api/collections/posts/records", None), // DELETE needs an id
        r(
            "POST",
            "/api/collections/posts/records?a=1",
            Some(json!({"title": "a"})),
        ), // no query strings
        r(
            "POST",
            "/api/collections//records",
            Some(json!({"title": "a"})),
        ), // empty collection
        r(
            "PATCH",
            &format!("{one}/extra"),
            Some(json!({"title": "a"})),
        ), // trailing segment
        r(
            "POST",
            "/api/collections/posts",
            Some(json!({"title": "a"})),
        ),
        json!({"url": "/api/collections/posts/records", "body": {"title": "a"}}), // no method
        json!({"method": "POST", "body": {"title": "a"}}),                        // no url
    ];

    for b in bad {
        // put a valid create first, so a pass also proves the good one rolled back
        let (s, v) = batch(
            &app,
            Some(&tok),
            json!([
                r(
                    "POST",
                    "/api/collections/posts/records",
                    Some(json!({"title": "ok"}))
                ),
                b.clone()
            ]),
        )
        .await;
        assert_failed_at(s, &v, 1, "bad method or url");
        assert_eq!(
            total(&app, "posts").await,
            1,
            "sub-request {b} left a write behind: {v}"
        );
    }
}

// spec test 4
#[tokio::test]
async fn inner_404_flattens_to_400_with_index() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;

    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([r(
            "PATCH",
            "/api/collections/posts/records/nope",
            Some(json!({"views": 1}))
        )]),
    )
    .await;
    assert_failed_at(s, &v, 0, "record not found");

    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([r("DELETE", "/api/collections/posts/records/nope", None)]),
    )
    .await;
    assert_failed_at(s, &v, 0, "record not found");
}

#[tokio::test]
async fn bodies_are_passed_to_the_cores_as_is() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;

    // POST with no body at all -> Value::Null -> "body must be a JSON object"
    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([r("POST", "/api/collections/posts/records", None)]),
    )
    .await;
    assert_failed_at(s, &v, 0, "body must be a JSON object");

    // non-object body -> same
    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([r(
            "POST",
            "/api/collections/posts/records",
            Some(json!("nope"))
        )]),
    )
    .await;
    assert_failed_at(s, &v, 0, "body must be a JSON object");

    // unknown field still rejected inside a batch
    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([r(
            "POST",
            "/api/collections/posts/records",
            Some(json!({"title": "a", "nope": 1}))
        )]),
    )
    .await;
    assert_failed_at(s, &v, 0, "unknown field 'nope'");

    // wrong type still rejected inside a batch
    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([r(
            "POST",
            "/api/collections/posts/records",
            Some(json!({"title": 7}))
        )]),
    )
    .await;
    assert_failed_at(s, &v, 0, "field 'title' must be text");

    assert_eq!(total(&app, "posts").await, 0);
}

// ------------------------------------------------------------------ rollback
//
// Each of these: assert the failure envelope first (so a 404 route fails the test
// rather than trivially satisfying "nothing was written"), then compare the full
// pre-batch snapshot, then prove request 0 was valid on its own.

// spec test 2
#[tokio::test]
async fn rollback_on_validation_failure() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;
    let keep = mkpost(&app, &tok, json!({"title": "keep", "views": 1})).await;
    let before = snapshot(&app).await;

    let good = r(
        "POST",
        "/api/collections/posts/records",
        Some(json!({"title": "new"})),
    );
    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([
            good.clone(),
            r(
                "PATCH",
                &format!("/api/collections/posts/records/{keep}"),
                Some(json!({"views": 99}))
            ),
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"views": 2}))
            ), // missing required title
        ]),
    )
    .await;
    assert_failed_at(s, &v, 2, "required");

    assert_eq!(total(&app, "posts").await, 1, "the create rolled back: {v}");
    assert_eq!(
        snapshot(&app).await,
        before,
        "db must be identical after a rolled-back batch"
    );

    // positive control: request 0 really would have succeeded, so its absence is rollback
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&tok),
        Some(json!({"title": "new"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "request 0 was valid standalone: {v}");
}

#[tokio::test]
async fn rollback_on_missing_record() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;
    let doomed = mkpost(&app, &tok, json!({"title": "doomed"})).await;
    let before = snapshot(&app).await;

    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"title": "new"}))
            ),
            r(
                "DELETE",
                &format!("/api/collections/posts/records/{doomed}"),
                None
            ),
            r(
                "PATCH",
                "/api/collections/posts/records/ghost",
                Some(json!({"views": 1}))
            ),
        ]),
    )
    .await;
    assert_failed_at(s, &v, 2, "record not found");

    // the delete in slot 1 must be undone too
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{doomed}"),
        Some(&tok),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "the deleted record came back");
    assert_eq!(
        snapshot(&app).await,
        before,
        "db must be identical after a rolled-back batch"
    );
}

#[tokio::test]
async fn rollback_on_missing_collection() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;
    let before = snapshot(&app).await;

    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"title": "new"}))
            ),
            r(
                "POST",
                "/api/collections/ghosts/records",
                Some(json!({"title": "x"}))
            ),
        ]),
    )
    .await;
    assert_failed_at(s, &v, 1, "no such collection");

    assert_eq!(total(&app, "posts").await, 0, "the create rolled back: {v}");
    assert_eq!(
        snapshot(&app).await,
        before,
        "db must be identical after a rolled-back batch"
    );

    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&tok),
        Some(json!({"title": "new"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "request 0 was valid standalone: {v}");
}

// spec "Edge cases": duplicate email inside one tx
#[tokio::test]
async fn rollback_on_duplicate_email_in_one_batch() {
    let app = app();
    let before_users = total(&app, "users").await;
    let before = snapshot(&app).await;

    let (s, v) = batch(
        &app,
        Some(ADMIN),
        json!([
            r(
                "POST",
                "/api/collections/users/records",
                Some(json!({"email": "dup@x.com", "password": PW}))
            ),
            r(
                "POST",
                "/api/collections/users/records",
                Some(json!({"email": "dup@x.com", "password": PW}))
            ),
        ]),
    )
    .await;
    assert_failed_at(s, &v, 1, "email already in use");

    assert_eq!(
        total(&app, "users").await,
        before_users,
        "neither user survived: {v}"
    );
    assert_eq!(
        snapshot(&app).await,
        before,
        "db must be identical after a rolled-back batch"
    );
}

#[tokio::test]
async fn rollback_undoes_a_long_prefix_of_successes() {
    let app = app();
    mkposts(&app, json!({})).await;
    let (_, tok) = user(&app, "a@x.com").await;
    let victim = mkpost(&app, &tok, json!({"title": "victim", "views": 0})).await;
    let before = snapshot(&app).await;

    let mut reqs: Vec<Value> = (0..10)
        .map(|i| {
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"title": format!("t{i}")})),
            )
        })
        .collect();
    // interleave writes against the pre-existing row so `updated` would move too
    reqs.push(r(
        "PATCH",
        &format!("/api/collections/posts/records/{victim}"),
        Some(json!({"views": 7})),
    ));
    reqs.push(r(
        "DELETE",
        &format!("/api/collections/posts/records/{victim}"),
        None,
    ));
    reqs.push(r(
        "PATCH",
        "/api/collections/posts/records/ghost",
        Some(json!({"views": 1})),
    ));

    let (s, v) = batch(&app, Some(&tok), json!(reqs)).await;
    assert_failed_at(s, &v, 12, "record not found");

    assert_eq!(
        total(&app, "posts").await,
        1,
        "only the pre-existing row remains: {v}"
    );
    assert_eq!(
        snapshot(&app).await,
        before,
        "db must be identical after a rolled-back batch"
    );
}

// ------------------------------------------------------------------- rules
//
// specs/batch.md predates rules. Batch must not be a way around them.

#[tokio::test]
async fn create_rule_gates_batch_creates() {
    let app = app();
    // NULL createRule = admin only
    mkposts(&app, json!({"createRule": null})).await;
    let (_, tok) = user(&app, "a@x.com").await;
    let before = snapshot(&app).await;

    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([r(
            "POST",
            "/api/collections/posts/records",
            Some(json!({"title": "sneaky"}))
        )]),
    )
    .await;
    assert_failed_at(s, &v, 0, "not allowed");
    assert_eq!(
        total(&app, "posts").await,
        0,
        "batch must not bypass createRule: {v}"
    );
    assert_eq!(snapshot(&app).await, before);

    // sanity: the standalone endpoint denies it too (403 for an authed caller)
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&tok),
        Some(json!({"title": "sneaky"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "standalone create is denied");

    // admin bypasses
    let (s, v) = batch(
        &app,
        Some(ADMIN),
        json!([r(
            "POST",
            "/api/collections/posts/records",
            Some(json!({"title": "fine"}))
        )]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "admin bypasses createRule: {v}");
    assert_eq!(total(&app, "posts").await, 1);
}

#[tokio::test]
async fn create_rule_expression_is_evaluated_per_request() {
    let app = app();
    mkposts(&app, json!({"createRule": "author = @request.auth.id"})).await;
    let (aid, tok) = user(&app, "a@x.com").await;

    // own-authored create passes
    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([r(
            "POST",
            "/api/collections/posts/records",
            Some(json!({"title": "mine", "author": aid}))
        )]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "own create allowed: {v}");
    assert_eq!(total(&app, "posts").await, 1);

    // forging someone else's author fails, and rolls the valid sibling back
    let before = snapshot(&app).await;
    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"title": "mine2", "author": aid}))
            ),
            r(
                "POST",
                "/api/collections/posts/records",
                Some(json!({"title": "forged", "author": "someone-else"}))
            ),
        ]),
    )
    .await;
    assert_failed_at(s, &v, 1, "not allowed");
    assert_eq!(
        snapshot(&app).await,
        before,
        "rule denial rolls back the whole batch"
    );
}

#[tokio::test]
async fn update_rule_gates_batch_patches_and_rolls_back() {
    let app = app();
    mkposts(&app, json!({"updateRule": "author = @request.auth.id"})).await;
    let (aid, atok) = user(&app, "a@x.com").await;
    let (bid, _btok) = user(&app, "b@x.com").await;
    let mine = mkpost(&app, &atok, json!({"title": "mine", "author": aid})).await;
    let theirs = mkpost(&app, ADMIN, json!({"title": "theirs", "author": bid})).await;
    let before = snapshot(&app).await;

    let good = r(
        "PATCH",
        &format!("/api/collections/posts/records/{mine}"),
        Some(json!({"views": 1})),
    );
    let (s, v) = batch(
        &app,
        Some(&atok),
        json!([
            good.clone(),
            r(
                "PATCH",
                &format!("/api/collections/posts/records/{theirs}"),
                Some(json!({"views": 42}))
            ),
        ]),
    )
    .await;
    assert_failed_at(s, &v, 1, "not allowed");
    assert_eq!(
        snapshot(&app).await,
        before,
        "denied patch must roll back the allowed one"
    );

    // positive control: the allowed patch really was allowed
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{mine}"),
        Some(&atok),
        Some(json!({"views": 1})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "request 0 was allowed standalone: {v}");
}

#[tokio::test]
async fn delete_rule_gates_batch_deletes() {
    let app = app();
    mkposts(&app, json!({"deleteRule": null})).await; // admin only
    let (_, tok) = user(&app, "a@x.com").await;
    let id = mkpost(&app, ADMIN, json!({"title": "t"})).await;
    let before = snapshot(&app).await;

    let (s, v) = batch(
        &app,
        Some(&tok),
        json!([r(
            "DELETE",
            &format!("/api/collections/posts/records/{id}"),
            None
        )]),
    )
    .await;
    assert_failed_at(s, &v, 0, "not allowed");
    assert_eq!(
        snapshot(&app).await,
        before,
        "denied delete must not remove the row"
    );

    let (s, v) = batch(
        &app,
        Some(ADMIN),
        json!([r(
            "DELETE",
            &format!("/api/collections/posts/records/{id}"),
            None
        )]),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "admin bypasses deleteRule: {v}");
    assert_eq!(total(&app, "posts").await, 0);
}

#[tokio::test]
async fn users_own_record_rule_holds_inside_a_batch() {
    let app = app();
    let (_aid, atok) = user(&app, "a@x.com").await;
    let (bid, _btok) = user(&app, "b@x.com").await;
    let before = snapshot(&app).await;

    // users.updateRule defaults to `id = @request.auth.id`: a cannot patch b
    let (s, v) = batch(
        &app,
        Some(&atok),
        json!([r(
            "PATCH",
            &format!("/api/collections/users/records/{bid}"),
            Some(json!({"email": "hijack@x.com"}))
        )]),
    )
    .await;
    assert_failed_at(s, &v, 0, "not allowed");
    assert_eq!(
        snapshot(&app).await,
        before,
        "denied user patch changed nothing"
    );

    // users.deleteRule likewise
    let (s, v) = batch(
        &app,
        Some(&atok),
        json!([r(
            "DELETE",
            &format!("/api/collections/users/records/{bid}"),
            None
        )]),
    )
    .await;
    assert_failed_at(s, &v, 0, "not allowed");
    assert_eq!(
        snapshot(&app).await,
        before,
        "denied user delete changed nothing"
    );
}
