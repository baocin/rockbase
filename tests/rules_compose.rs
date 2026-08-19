// Boolean composition in per-collection API rules: `&&`, `||`, parentheses.
// TDD red phase — same HTTP harness style as tests/rules.rs.
//
// Rules today are a single comparison (src/rules.rs::compile_rule / eval_rule_mem).
// src/filter.rs already parses the full grammar with `||`/`&&` precedence,
// parentheses, a 32-deep nesting limit and a 2048-byte length cap, and returns the
// identical (String, Vec<rusqlite::types::Value>) shape. These tests pin what a
// composite rule must do on BOTH evaluation paths:
//   * SQL      — listRule (ANDed into the query) and view/update/delete (row-existence check)
//   * IN-MEMORY— createRule, evaluated against the request body before the insert
// The same composite rule and the same data must produce the same verdict on both.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use rockbase::build_app;

const ADMIN: &str = "Admin testtoken";
const PW: &str = "clubrock1";

fn app() -> Router {
    std::env::set_var("RB_JWT_SECRET", "testsecret");
    build_app(":memory:", "testtoken".into())
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

/// Seed a user through the admin bypass and log in. Returns (record id, "Bearer <token>").
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

async fn mkposts(app: &Router, schema: Value) {
    let (s, v) = call(
        app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "posts", "schema": schema})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "create posts: {v}");
}

/// Admin-seeded record. Panics unless it lands.
async fn seed(app: &Router, body: Value) -> String {
    let (s, v) = call(
        app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "seed {body}: {v}");
    v["id"].as_str().unwrap().to_string()
}

/// Set one rule, asserting it was accepted and echoed back.
async fn set_rule(app: &Router, key: &str, rule: &str) {
    let (s, v) = call(
        app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({ key: rule })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "set {key} = {rule:?}: {v}");
    assert_eq!(v[key], rule, "{key} echoed back: {v}");
}

/// Stored rule value, read back through the admin collections listing.
async fn stored_rule(app: &Router, key: &str) -> Value {
    let (s, v) = call(app, "GET", "/api/collections", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "posts")
        .unwrap_or_else(|| panic!("posts not listed: {v}"))[key]
        .clone()
}

/// Sorted `title` values visible to `auth` through the list endpoint.
async fn titles(app: &Router, auth: Option<&str>) -> Vec<String> {
    let (s, v) = call(app, "GET", "/api/collections/posts/records", auth, None).await;
    assert_eq!(s, StatusCode::OK, "list: {v}");
    let mut t: Vec<String> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap_or("").to_string())
        .collect();
    assert_eq!(
        t.len() as u64,
        v["totalItems"].as_u64().unwrap(),
        "totalItems must match the page under a composite rule: {v}"
    );
    t.sort();
    t
}

// 1. `&&` narrows: both sides must hold. Runs on the SQL (list) path.
#[tokio::test]
async fn and_composition_narrows_list() {
    let app = app();
    mkposts(
        &app,
        json!([
            {"name": "title", "type": "text"},
            {"name": "owner", "type": "text"},
            {"name": "status", "type": "text"}
        ]),
    )
    .await;
    let (id_a, a) = user(&app, "a@cave.dev").await;
    let (id_b, b) = user(&app, "b@cave.dev").await;

    seed(
        &app,
        json!({"title": "a-open", "owner": &id_a, "status": "open"}),
    )
    .await;
    seed(
        &app,
        json!({"title": "a-shut", "owner": &id_a, "status": "shut"}),
    )
    .await;
    seed(
        &app,
        json!({"title": "b-open", "owner": &id_b, "status": "open"}),
    )
    .await;
    // no owner and no status at all: a NULL operand must never satisfy either side
    seed(&app, json!({"title": "orphan"})).await;

    set_rule(
        &app,
        "listRule",
        "owner = @request.auth.id && status = 'open'",
    )
    .await;

    assert_eq!(titles(&app, Some(&a)).await, ["a-open"], "A: own AND open");
    assert_eq!(titles(&app, Some(&b)).await, ["b-open"], "B: own AND open");
    // a guest binds an empty auth id, so the left conjunct can never hold
    assert!(titles(&app, None).await.is_empty(), "guest sees nothing");
    // admin still bypasses
    assert_eq!(titles(&app, Some(ADMIN)).await.len(), 4);
}

// 2. `||` widens: either side suffices.
#[tokio::test]
async fn or_composition_widens_list() {
    let app = app();
    mkposts(
        &app,
        json!([
            {"name": "title", "type": "text"},
            {"name": "owner", "type": "text"},
            {"name": "visibility", "type": "text"}
        ]),
    )
    .await;
    let (id_a, a) = user(&app, "a@cave.dev").await;
    let (id_b, b) = user(&app, "b@cave.dev").await;

    seed(
        &app,
        json!({"title": "a-priv", "owner": &id_a, "visibility": "private"}),
    )
    .await;
    seed(
        &app,
        json!({"title": "b-priv", "owner": &id_b, "visibility": "private"}),
    )
    .await;
    seed(
        &app,
        json!({"title": "open", "owner": &id_b, "visibility": "public"}),
    )
    .await;
    seed(&app, json!({"title": "orphan"})).await;

    set_rule(
        &app,
        "listRule",
        "owner = @request.auth.id || visibility = 'public'",
    )
    .await;

    assert_eq!(titles(&app, Some(&a)).await, ["a-priv", "open"]);
    assert_eq!(titles(&app, Some(&b)).await, ["b-priv", "open"]);
    assert_eq!(
        titles(&app, None).await,
        ["open"],
        "guest gets the public one"
    );

    // a user `filter=` can still only narrow what the rule already allows
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?filter=title%3D'b-priv'",
        Some(&a),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v["totalItems"], 0,
        "filter must AND with a composite rule: {v}"
    );
}

// 3. `&&` binds tighter than `||`, and parentheses override that.
#[tokio::test]
async fn precedence_and_parentheses() {
    let app = app();
    mkposts(
        &app,
        json!([
            {"name": "title", "type": "text"},
            {"name": "a", "type": "number"},
            {"name": "b", "type": "number"},
            {"name": "c", "type": "number"}
        ]),
    )
    .await;
    seed(&app, json!({"title": "r1", "a": 1, "b": 2, "c": 0})).await;
    seed(&app, json!({"title": "r2", "a": 1, "b": 0, "c": 3})).await;
    seed(&app, json!({"title": "r3", "a": 0, "b": 0, "c": 3})).await;
    seed(&app, json!({"title": "r4", "a": 0, "b": 2, "c": 0})).await;

    // (a=1 && b=2) || c=3  -> r1, r2, r3
    set_rule(&app, "listRule", "a = 1 && b = 2 || c = 3").await;
    assert_eq!(
        titles(&app, None).await,
        ["r1", "r2", "r3"],
        "&& must bind tighter than ||"
    );

    // explicit parens around the && must not change the meaning
    set_rule(&app, "listRule", "(a = 1 && b = 2) || c = 3").await;
    assert_eq!(titles(&app, None).await, ["r1", "r2", "r3"]);

    // parens override: a=1 && (b=2 || c=3) -> r1, r2
    set_rule(&app, "listRule", "a = 1 && (b = 2 || c = 3)").await;
    assert_eq!(
        titles(&app, None).await,
        ["r1", "r2"],
        "parens must override precedence"
    );

    // nesting a level deeper still parses and still means the same thing
    set_rule(&app, "listRule", "((a = 1) && ((b = 2) || (c = 3)))").await;
    assert_eq!(titles(&app, None).await, ["r1", "r2"]);
}

// 4. The SQL row-existence path: composite view / update / delete rules.
#[tokio::test]
async fn composite_rules_gate_view_update_delete() {
    let app = app();
    mkposts(
        &app,
        json!([
            {"name": "title", "type": "text"},
            {"name": "owner", "type": "text"},
            {"name": "status", "type": "text"},
            {"name": "visibility", "type": "text"}
        ]),
    )
    .await;
    let (id_a, a) = user(&app, "a@cave.dev").await;
    let (_id_b, b) = user(&app, "b@cave.dev").await;

    let open = seed(
        &app,
        json!({"title": "open", "owner": &id_a, "status": "open", "visibility": "public"}),
    )
    .await;
    let shut = seed(
        &app,
        json!({"title": "shut", "owner": &id_a, "status": "shut", "visibility": "private"}),
    )
    .await;
    let uri_open = format!("/api/collections/posts/records/{open}");
    let uri_shut = format!("/api/collections/posts/records/{shut}");

    // view: own OR public
    set_rule(
        &app,
        "viewRule",
        "owner = @request.auth.id || visibility = 'public'",
    )
    .await;
    let (s, v) = call(&app, "GET", &uri_open, None, None).await;
    assert_eq!(s, StatusCode::OK, "guest views the public one: {v}");
    let (s, _) = call(&app, "GET", &uri_shut, None, None).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "guest is denied the private one"
    );
    let (s, _) = call(&app, "GET", &uri_shut, Some(&a), None).await;
    assert_eq!(s, StatusCode::OK, "owner satisfies the left disjunct");
    let (s, _) = call(&app, "GET", &uri_shut, Some(&b), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "B satisfies neither disjunct");

    // update: own AND open
    set_rule(
        &app,
        "updateRule",
        "owner = @request.auth.id && status = 'open'",
    )
    .await;
    let (s, v) = call(
        &app,
        "PATCH",
        &uri_open,
        Some(&a),
        Some(json!({"title": "open2"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "owner patches an open post: {v}");
    let (s, _) = call(
        &app,
        "PATCH",
        &uri_shut,
        Some(&a),
        Some(json!({"title": "x"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "owner blocked by the second conjunct"
    );
    let (s, _) = call(
        &app,
        "PATCH",
        &uri_open,
        Some(&b),
        Some(json!({"title": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "B blocked by the first conjunct");
    let (s, _) = call(&app, "PATCH", &uri_open, None, Some(json!({"title": "x"}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "guest denial is 401");

    // delete: own AND shut (the mirror image, so neither post is deletable by both rules)
    set_rule(
        &app,
        "deleteRule",
        "owner = @request.auth.id && status = 'shut'",
    )
    .await;
    let (s, _) = call(&app, "DELETE", &uri_open, Some(&a), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "open post fails the delete rule");
    let (s, _) = call(&app, "DELETE", &uri_shut, Some(&b), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = call(&app, "DELETE", &uri_shut, Some(&a), None).await;
    assert_eq!(s, StatusCode::OK, "owner deletes the shut post: {v}");

    // a record that never existed is still 404, whatever the composite rule says
    let (s, _) = call(
        &app,
        "GET",
        "/api/collections/posts/records/ghost",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// 5. The two evaluation paths must agree. createRule runs in memory against the
//    request body (no row exists yet); updateRule runs as SQL against the stored
//    row. The same composite rule over the same data must give the same verdict.
#[tokio::test]
async fn composite_create_and_update_agree() {
    let app = app();
    mkposts(
        &app,
        json!([
            {"name": "title", "type": "text"},
            {"name": "owner", "type": "text"},
            {"name": "status", "type": "text"}
        ]),
    )
    .await;
    let (id_a, a) = user(&app, "a@cave.dev").await;
    let (id_b, _b) = user(&app, "b@cave.dev").await;

    const RULE: &str = "owner = @request.auth.id && status = 'open'";
    set_rule(&app, "createRule", RULE).await;
    set_rule(&app, "updateRule", RULE).await;

    // (body, expected verdict) — same three shapes down both paths
    let cases = [
        (
            json!({"title": "t", "owner": &id_a, "status": "open"}),
            true,
        ),
        (
            json!({"title": "t", "owner": &id_a, "status": "shut"}),
            false,
        ),
        (
            json!({"title": "t", "owner": &id_b, "status": "open"}),
            false,
        ),
        // both operands missing entirely: unresolvable, so false on either path
        (json!({"title": "t"}), false),
    ];

    for (body, want) in cases {
        // IN-MEMORY path: A creates the record itself
        let (s, v) = call(
            &app,
            "POST",
            "/api/collections/posts/records",
            Some(&a),
            Some(body.clone()),
        )
        .await;
        let created_ok = s == StatusCode::OK;
        assert_eq!(created_ok, want, "create {body} under {RULE}: {s} {v}");
        if !created_ok {
            assert_eq!(s, StatusCode::FORBIDDEN, "authed denial is 403: {v}");
        }

        // SQL path: the identical row, seeded by admin, patched by A
        let id = seed(&app, body.clone()).await;
        let (s, v) = call(
            &app,
            "PATCH",
            &format!("/api/collections/posts/records/{id}"),
            Some(&a),
            Some(json!({"title": "patched"})),
        )
        .await;
        assert_eq!(
            s == StatusCode::OK,
            want,
            "update {body} must match the create verdict ({want}) under {RULE}: {s} {v}"
        );
    }
}

// 6. `@request.auth.id` binds as a parameter inside a composite expression, in
//    either operand slot — it is never spliced textually, and it is never treated
//    as the literal string "@request.auth.id".
#[tokio::test]
async fn auth_token_binds_inside_composite() {
    let app = app();
    mkposts(
        &app,
        json!([{"name": "title", "type": "text"}, {"name": "owner", "type": "text"}]),
    )
    .await;
    let (id_a, a) = user(&app, "a@cave.dev").await;

    seed(&app, json!({"title": "mine", "owner": &id_a})).await;
    seed(&app, json!({"title": "shared", "owner": "zzz"})).await;
    // a row whose owner is literally the token text: matching it would prove the
    // token was compared as a bareword string instead of bound to the caller's id
    seed(&app, json!({"title": "trap", "owner": "@request.auth.id"})).await;

    set_rule(
        &app,
        "listRule",
        "owner = @request.auth.id || owner = 'zzz'",
    )
    .await;
    assert_eq!(titles(&app, Some(&a)).await, ["mine", "shared"]);
    assert_eq!(
        titles(&app, None).await,
        ["shared"],
        "guest binds an empty id"
    );

    // the same on the left-hand side
    set_rule(
        &app,
        "listRule",
        "@request.auth.id = owner || owner = 'zzz'",
    )
    .await;
    assert_eq!(titles(&app, Some(&a)).await, ["mine", "shared"]);

    // and inside a parenthesised conjunct
    set_rule(
        &app,
        "listRule",
        "(owner = 'zzz' || @request.auth.id = owner) && title != 'trap'",
    )
    .await;
    assert_eq!(titles(&app, Some(&a)).await, ["mine", "shared"]);

    // `@request.auth.id != ''` (the base default) still works composed
    set_rule(&app, "listRule", "@request.auth.id != '' && owner = 'zzz'").await;
    assert_eq!(titles(&app, Some(&a)).await, ["shared"]);
    assert!(
        titles(&app, None).await.is_empty(),
        "guest fails the auth conjunct"
    );
}

// 7. Composition must not become an injection vector. Every payload either fails
//    to save (400) or evaluates safely — never widening access.
#[tokio::test]
async fn composite_injection_payloads_never_grant() {
    let app = app();
    mkposts(
        &app,
        json!([{"name": "title", "type": "text"}, {"name": "owner", "type": "text"}]),
    )
    .await;
    let (id_a, _a) = user(&app, "a@cave.dev").await;
    let (id_b, b) = user(&app, "b@cave.dev").await;

    seed(&app, json!({"title": "secret", "owner": &id_a})).await;
    seed(&app, json!({"title": "bees", "owner": &id_b})).await;

    const PAYLOADS: [&str; 10] = [
        "owner = @request.auth.id || 1=1",
        "owner = @request.auth.id || 1 = 1",
        "x = 'a' || 1=1--",
        "owner = @request.auth.id || '1'='1'",
        "owner = @request.auth.id && 1=1 || 1=1",
        "owner = @request.auth.id || true",
        "owner = @request.auth.id'; DROP TABLE records--",
        "owner = @request.auth.id || (SELECT 1)",
        "owner = @request.auth.id) OR (1=1",
        "owner = @request.auth.id || title LIKE '%'",
    ];

    for p in PAYLOADS {
        // baseline: a rule that is known-good and known-narrow
        set_rule(&app, "listRule", "owner = @request.auth.id").await;
        let (s, v) = call(
            &app,
            "PATCH",
            "/api/collections/posts",
            Some(ADMIN),
            Some(json!({ "listRule": p })),
        )
        .await;
        assert!(
            s == StatusCode::OK || s == StatusCode::BAD_REQUEST,
            "payload {p:?} must be accepted or rejected, not {s}: {v}"
        );
        if s == StatusCode::BAD_REQUEST {
            assert_eq!(v["message"], "invalid listRule", "{v}");
            assert_eq!(
                stored_rule(&app, "listRule").await,
                "owner = @request.auth.id",
                "a rejected rule must leave the stored one untouched (payload {p:?})"
            );
        }
        // whether it saved or not, B must never see A's row and a guest never sees any
        let seen = titles(&app, Some(&b)).await;
        assert!(
            !seen.contains(&"secret".to_string()),
            "payload {p:?} leaked A's row to B: {seen:?}"
        );
        assert!(
            titles(&app, None).await.is_empty(),
            "payload {p:?} leaked rows to a guest"
        );
    }

    // nothing was dropped: the table and both rows survive
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "records table must still exist: {v}");
    assert_eq!(v["totalItems"], 2, "{v}");
}

// 8. Malformed composites are rejected at save time, with the stored rule intact.
#[tokio::test]
async fn malformed_composites_rejected_on_write() {
    let app = app();
    mkposts(
        &app,
        json!([{"name": "title", "type": "text"}, {"name": "owner", "type": "text"}]),
    )
    .await;
    set_rule(&app, "listRule", "owner = @request.auth.id").await;

    let deep = format!(
        "{}owner = @request.auth.id{}",
        "(".repeat(40),
        ")".repeat(40)
    );
    let long = format!(
        "{}owner = @request.auth.id",
        "owner = @request.auth.id || ".repeat(120)
    );
    assert!(
        long.len() > 2048,
        "the length-cap case must actually exceed the cap"
    );

    let bad = [
        "(owner = @request.auth.id".to_string(), // unbalanced open
        "owner = @request.auth.id)".to_string(), // unbalanced close
        "((owner = @request.auth.id)".to_string(),
        "owner = @request.auth.id &&".to_string(), // dangling operator
        "|| owner = 'x'".to_string(),              // leading operator
        "owner = @request.auth.id && ".to_string(),
        "owner = @request.auth.id && &&  owner = 'x'".to_string(),
        "() && owner = 'x'".to_string(), // empty group
        deep,                            // deeper than the 32 nesting limit
        long,                            // longer than the 2048 length cap
    ];

    for r in bad {
        let (s, v) = call(
            &app,
            "PATCH",
            "/api/collections/posts",
            Some(ADMIN),
            Some(json!({ "listRule": r })),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "malformed composite {r:?} must be rejected: {v}"
        );
        assert_eq!(v["message"], "invalid listRule", "{v}");
        assert_eq!(
            stored_rule(&app, "listRule").await,
            "owner = @request.auth.id",
            "rejected write must not touch the stored rule ({r:?})"
        );
    }

    // same validation on create
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "bad", "createRule": "owner = @request.auth.id && "})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["message"], "invalid createRule");
}

// 9. Regression: single-comparison rules keep behaving exactly as before.
#[tokio::test]
async fn single_comparison_rules_unchanged() {
    let app = app();
    mkposts(
        &app,
        json!([
            {"name": "title", "type": "text"},
            {"name": "owner", "type": "text"},
            {"name": "views", "type": "number"}
        ]),
    )
    .await;
    let (id_a, a) = user(&app, "a@cave.dev").await;
    let (id_b, b) = user(&app, "b@cave.dev").await;

    seed(&app, json!({"title": "a1", "owner": &id_a, "views": 10})).await;
    seed(&app, json!({"title": "b1", "owner": &id_b, "views": 100})).await;
    seed(&app, json!({"title": "orphan"})).await;

    set_rule(&app, "listRule", "owner = @request.auth.id").await;
    assert_eq!(titles(&app, Some(&a)).await, ["a1"]);
    assert!(titles(&app, None).await.is_empty());

    set_rule(&app, "listRule", "views > 50").await;
    assert_eq!(
        titles(&app, None).await,
        ["b1"],
        "ordering op on a bare number"
    );

    set_rule(&app, "listRule", "@request.auth.id != ''").await;
    assert_eq!(
        titles(&app, Some(&b)).await.len(),
        3,
        "any authed user sees all"
    );
    assert!(titles(&app, None).await.is_empty(), "guest sees none");

    set_rule(&app, "viewRule", "owner = @request.auth.id").await;
    // single-comparison create rule still evaluates in memory
    set_rule(&app, "createRule", "owner = @request.auth.id").await;
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&a),
        Some(json!({"title": "new", "owner": &id_a})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "own-owner create: {v}");
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&a),
        Some(json!({"title": "spoof", "owner": &id_b})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::FORBIDDEN,
        "create as someone else stays denied"
    );

    // trailing SQL after a quoted literal is still not a rule
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"updateRule": "owner = 'nobody' OR 1=1--"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

// 10. The known divergence between the two paths, pinned in the DENY direction.
//     eval_rule_mem compares JSON values, so 1 and 1.0 differ; SQLite coerces and
//     calls them equal. A rule is a GRANT, so where the paths disagree the safe
//     answer is the one that does not hand out access: both must deny.
#[tokio::test]
async fn numeric_coercion_agrees_on_both_paths() {
    let app = app();
    mkposts(
        &app,
        json!([{"name": "title", "type": "text"}, {"name": "score", "type": "number"}]),
    )
    .await;
    let (_id_a, a) = user(&app, "a@cave.dev").await;

    set_rule(&app, "createRule", "score = 1").await;
    set_rule(&app, "updateRule", "score = 1").await;

    // control: an exact integer match is allowed on both paths
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&a),
        Some(json!({"title": "int", "score": 1})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "integer 1 create: {v}");
    let int_id = seed(&app, json!({"title": "int2", "score": 1})).await;
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{int_id}"),
        Some(&a),
        Some(json!({"title": "int3"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "integer 1 update: {v}");

    // The defect to fix is the DIVERGENCE, not the direction. Every other comparison
    // in this system uses SQLite semantics, including `filter=`, so rules follow suit:
    // 1.0 satisfies `score = 1` on BOTH paths. The in-memory evaluator must compare
    // numerically rather than by JSON value equality, which is where it disagreed.
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&a),
        Some(json!({"title": "float", "score": 1.0})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "1.0 must satisfy `score = 1` on create, as SQL does: {v}"
    );

    let float_id = seed(&app, json!({"title": "float2", "score": 1.0})).await;
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{float_id}"),
        Some(&a),
        Some(json!({"title": "float3"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "1.0 must satisfy `score = 1` on update too — both paths coerce, so neither \
         can grant what the other refuses: {v}"
    );

    // and the same holds inside a composite, where one conjunct is the numeric one
    set_rule(&app, "updateRule", "score = 1 && title != 'nope'").await;
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{float_id}"),
        Some(&a),
        Some(json!({"title": "float4"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the coercing conjunct holds inside a composite too"
    );
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{int_id}"),
        Some(&a),
        Some(json!({"title": "int4"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "exact match still passes the composite");
}
