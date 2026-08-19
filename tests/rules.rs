// Per-collection API rules (specs/rules.md) — TDD red phase.
// Everything here talks HTTP against `build_app`, same harness style as tests/basic.rs.

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

/// Seed a user through the admin bypass (works before and after rules land) and log in.
/// Returns (record id, "Bearer <token>").
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

/// One collection out of `GET /api/collections`.
async fn collection(app: &Router, name: &str) -> Value {
    let (s, v) = call(app, "GET", "/api/collections", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("collection {name} not listed: {v}"))
        .clone()
}

fn assert_rules(c: &Value, list: Value, view: Value, create: Value, update: Value, delete: Value) {
    assert_eq!(c["listRule"], list, "listRule of {c}");
    assert_eq!(c["viewRule"], view, "viewRule of {c}");
    assert_eq!(c["createRule"], create, "createRule of {c}");
    assert_eq!(c["updateRule"], update, "updateRule of {c}");
    assert_eq!(c["deleteRule"], delete, "deleteRule of {c}");
}

// 1. Rules are stored per collection, with per-type defaults. NULL = admin only, '' = public.
#[tokio::test]
async fn rule_defaults_per_type() {
    let app = app();
    mkposts(&app, json!([{"name": "title", "type": "text"}])).await;

    // base: public read, any authed user writes
    let posts = collection(&app, "posts").await;
    assert_rules(
        &posts,
        json!(""),
        json!(""),
        json!("@request.auth.id != ''"),
        json!("@request.auth.id != ''"),
        json!("@request.auth.id != ''"),
    );

    // auth: public signup, admin-only list/view (NULL), own-record update/delete
    let users = collection(&app, "users").await;
    assert_rules(
        &users,
        json!(null),
        json!(null),
        json!(""),
        json!("id = @request.auth.id"),
        json!("id = @request.auth.id"),
    );

    // a second auth collection gets the same auth defaults
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "staff", "type": "auth"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // create echoes the rules back
    assert_rules(
        &v,
        json!(null),
        json!(null),
        json!(""),
        json!("id = @request.auth.id"),
        json!("id = @request.auth.id"),
    );
    assert_rules(
        &collection(&app, "staff").await,
        json!(null),
        json!(null),
        json!(""),
        json!("id = @request.auth.id"),
        json!("id = @request.auth.id"),
    );
}

// 2. Empty-string createRule on users = public signup, no auth header at all.
#[tokio::test]
async fn empty_rule_is_public_signup() {
    let app = app();
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        None,
        Some(json!({"email": "walkin@cave.dev", "password": PW})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "public signup: {v}");
    assert!(v["id"].is_string(), "{v}");
    assert!(v.get("password_hash").is_none(), "{v}");
}

// 3. NULL list/view rule on users = admin only. Guest -> 401, authed user -> 403, admin -> 200.
#[tokio::test]
async fn null_rule_is_admin_only() {
    let app = app();
    let (id_a, a) = user(&app, "a@cave.dev").await;

    let (s, v) = call(&app, "GET", "/api/collections/users/records", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "guest list users: {v}");
    assert_eq!(v["code"], 401);

    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/users/records",
        Some(&a),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "user list users: {v}");
    assert_eq!(v["code"], 403);

    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/users/records",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "admin list users: {v}");
    assert_eq!(v["totalItems"], 1);

    // viewRule is NULL too: same ladder on a single record, even your own
    let uri = format!("/api/collections/users/records/{id_a}");
    let (s, _) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&app, "GET", &uri, Some(&a), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&app, "GET", &uri, Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK);
}

// 4. `id = @request.auth.id` on users: own record only, admin bypasses.
#[tokio::test]
async fn own_record_update_and_delete() {
    let app = app();
    let (id_a, a) = user(&app, "a@cave.dev").await;
    let (id_b, b) = user(&app, "b@cave.dev").await;

    // A patches B -> 403
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/users/records/{id_b}"),
        Some(&a),
        Some(json!({"email": "hijack@cave.dev"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "A patches B: {v}");
    assert_eq!(v["code"], 403);

    // A patches A -> 200
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/users/records/{id_a}"),
        Some(&a),
        Some(json!({"email": "a2@cave.dev"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "A patches A: {v}");
    assert_eq!(v["email"], "a2@cave.dev");

    // guest patches A -> 401 (rule expression cannot match an empty auth id, guest denial is 401)
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/users/records/{id_a}"),
        None,
        Some(json!({"email": "guest@cave.dev"})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "guest patches A: {v}");

    // admin bypasses
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/collections/users/records/{id_b}"),
        Some(ADMIN),
        Some(json!({"email": "b2@cave.dev"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // A deletes B -> 403; B deletes B -> 200
    let (s, v) = call(
        &app,
        "DELETE",
        &format!("/api/collections/users/records/{id_b}"),
        Some(&a),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "A deletes B: {v}");
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/collections/users/records/{id_b}"),
        Some(&b),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // still 404 for a record that never existed, whatever the rule says
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/users/records/nope",
        Some(ADMIN),
        Some(json!({})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// 5. A custom rule expression is evaluated against the requesting user, in either operand slot.
#[tokio::test]
async fn custom_rule_evaluated_against_requester() {
    let app = app();
    mkposts(
        &app,
        json!([{"name": "title", "type": "text"}, {"name": "author", "type": "text"}]),
    )
    .await;
    let (id_a, a) = user(&app, "a@cave.dev").await;
    let (_id_b, b) = user(&app, "b@cave.dev").await;

    let (s, v) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"updateRule": "author = @request.auth.id"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "patch updateRule: {v}");
    assert_eq!(v["updateRule"], "author = @request.auth.id");

    let (s, post) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&a),
        Some(json!({"title": "mine", "author": id_a})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "A creates post: {post}");
    let pid = post["id"].as_str().unwrap().to_string();
    let uri = format!("/api/collections/posts/records/{pid}");

    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(&a),
        Some(json!({"title": "mine2"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "author patches own post: {v}");
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(&b),
        Some(json!({"title": "yours"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "B patches A's post: {v}");
    let (s, _) = call(&app, "PATCH", &uri, None, Some(json!({"title": "guest"}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // the auth token binds as a parameter, so it works on the left-hand side too
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"updateRule": "@request.auth.id = author"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "PATCH",
        &uri,
        Some(&a),
        Some(json!({"title": "mine3"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "PATCH",
        &uri,
        Some(&b),
        Some(json!({"title": "yours"})),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // a quoted literal is a bind, not a splice: a rule that is simply false denies everyone
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"updateRule": "author = 'nobody' OR 1=1--"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "rule with trailing SQL must not compile"
    );
}

// 6. NULL rule set after the fact locks the door for everyone but admin.
#[tokio::test]
async fn null_rule_locks_out_writers() {
    let app = app();
    mkposts(&app, json!([{"name": "title", "type": "text"}])).await;
    let (_id_a, a) = user(&app, "a@cave.dev").await;
    let (s, post) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(&a),
        Some(json!({"title": "x"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{post}");
    let uri = format!(
        "/api/collections/posts/records/{}",
        post["id"].as_str().unwrap()
    );

    let (s, v) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"deleteRule": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "set deleteRule null: {v}");
    assert_eq!(v["deleteRule"], json!(null));

    let (s, v) = call(&app, "DELETE", &uri, Some(&a), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "user delete under NULL rule: {v}");
    assert_eq!(v["code"], 403);
    let (s, v) = call(&app, "DELETE", &uri, None, None).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "guest delete under NULL rule: {v}"
    );
    assert_eq!(v["code"], 401);
    let (s, _) = call(&app, "DELETE", &uri, Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK, "admin bypasses NULL rule");
}

// 7. A list rule ANDs into the query: rows you may not see simply are not there.
#[tokio::test]
async fn list_rule_filters_rows() {
    let app = app();
    mkposts(
        &app,
        json!([{"name": "title", "type": "text"}, {"name": "owner", "type": "text"}]),
    )
    .await;
    let (id_a, a) = user(&app, "a@cave.dev").await;
    let (id_b, b) = user(&app, "b@cave.dev").await;

    for (owner, title) in [(&id_a, "a1"), (&id_a, "a2"), (&id_b, "b1")] {
        let (s, v) = call(
            &app,
            "POST",
            "/api/collections/posts/records",
            Some(ADMIN),
            Some(json!({"title": title, "owner": owner})),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
    }
    // one row with no owner field at all: NULL comparison must never match
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(json!({"title": "orphan"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"listRule": "owner = @request.auth.id"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "set listRule: {v}");

    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records",
        Some(&a),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["totalItems"], 2, "A sees only its own rows: {v}");
    let titles: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["a1", "a2"]);

    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records",
        Some(&b),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["totalItems"], 1, "{v}");
    assert_eq!(v["items"][0]["title"], "b1");

    // guest binds an empty auth id: 200 with nothing in it, count included
    let (s, v) = call(&app, "GET", "/api/collections/posts/records", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["totalItems"], 0, "{v}");
    assert_eq!(v["items"].as_array().unwrap().len(), 0);

    // a user filter cannot widen the rule
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?filter=title%3D'b1'",
        Some(&a),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v["totalItems"], 0,
        "user filter must AND with the rule: {v}"
    );

    // admin bypasses the list rule entirely
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["totalItems"], 4, "{v}");
}

// 8. Rules are validated on write.
#[tokio::test]
async fn invalid_rule_rejected() {
    let app = app();
    mkposts(&app, json!([{"name": "title", "type": "text"}])).await;

    for bad in [
        json!("no operator here"),
        json!(5),
        json!(true),
        json!(["a"]),
        json!({"a": 1}),
    ] {
        let (s, v) = call(
            &app,
            "PATCH",
            "/api/collections/posts",
            Some(ADMIN),
            Some(json!({"listRule": bad})),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "listRule {bad} must be rejected: {v}"
        );
        assert_eq!(v["message"], "invalid listRule", "{v}");
    }
    // rejected writes leave the stored rule alone
    assert_eq!(collection(&app, "posts").await["listRule"], "");

    // same validation on create
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "bad", "createRule": "nonsense"})),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["message"], "invalid createRule");

    // unknown collection
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/ghost",
        Some(ADMIN),
        Some(json!({"listRule": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// 9. Only admins set rules, and a PATCH touches only the keys it names.
#[tokio::test]
async fn rules_are_admin_only_and_partial() {
    let app = app();
    mkposts(
        &app,
        json!([{"name": "title", "type": "text"}, {"name": "author", "type": "text"}]),
    )
    .await;
    let (_id_a, a) = user(&app, "a@cave.dev").await;

    // non-admin cannot set rules
    let (s, v) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(&a),
        Some(json!({"listRule": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "user sets rules: {v}");
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        None,
        Some(json!({"listRule": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections",
        Some(&a),
        Some(json!({"name": "sneaky", "listRule": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // nothing changed
    assert_rules(
        &collection(&app, "posts").await,
        json!(""),
        json!(""),
        json!("@request.auth.id != ''"),
        json!("@request.auth.id != ''"),
        json!("@request.auth.id != ''"),
    );

    // explicit values on create are honored
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({
            "name": "notes",
            "schema": [{"name": "title", "type": "text"}],
            "listRule": null,
            "createRule": ""
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    // named keys applied, unnamed keys get the base defaults
    assert_rules(
        &collection(&app, "notes").await,
        json!(null),
        json!(""),
        json!(""),
        json!("@request.auth.id != ''"),
        json!("@request.auth.id != ''"),
    );

    // PATCH: named key set, explicit null clears, absent keys survive untouched
    let (s, v) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"updateRule": "author = @request.auth.id", "deleteRule": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["name"], "posts");
    assert_eq!(v["type"], "base");
    assert_eq!(v["schema"][0]["name"], "title");
    let posts = collection(&app, "posts").await;
    assert_rules(
        &posts,
        json!(""),
        json!(""),
        json!("@request.auth.id != ''"),
        json!("author = @request.auth.id"),
        json!(null),
    );

    // a second, unrelated PATCH leaves the earlier ones in place
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"viewRule": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_rules(
        &collection(&app, "posts").await,
        json!(""),
        json!(""),
        json!("@request.auth.id != ''"),
        json!("author = @request.auth.id"),
        json!(null),
    );

    // rules are per collection: notes kept its own
    assert_eq!(
        collection(&app, "notes").await["updateRule"],
        "@request.auth.id != ''"
    );
}

// 10. Empty string really is public, and a literal-valued rule gates single reads.
#[tokio::test]
async fn empty_rule_is_public_and_literals_gate_view() {
    let app = app();
    mkposts(
        &app,
        json!([{"name": "title", "type": "text"}, {"name": "visibility", "type": "text"}]),
    )
    .await;

    // createRule '' -> a guest can create
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"createRule": ""})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, pub_post) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        None,
        Some(json!({"title": "open", "visibility": "public"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "guest create under empty rule: {pub_post}"
    );

    let (s, priv_post) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        None,
        Some(json!({"title": "closed", "visibility": "private"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{priv_post}");

    // viewRule against a quoted literal
    let (s, _) = call(
        &app,
        "PATCH",
        "/api/collections/posts",
        Some(ADMIN),
        Some(json!({"viewRule": "visibility = 'public'"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let open = format!(
        "/api/collections/posts/records/{}",
        pub_post["id"].as_str().unwrap()
    );
    let closed = format!(
        "/api/collections/posts/records/{}",
        priv_post["id"].as_str().unwrap()
    );
    let (s, v) = call(&app, "GET", &open, None, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["title"], "open");
    let (s, v) = call(&app, "GET", &closed, None, None).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "guest reads a private record: {v}"
    );
    let (_id_a, a) = user(&app, "a@cave.dev").await;
    let (s, v) = call(&app, "GET", &closed, Some(&a), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "user reads a private record: {v}");
    let (s, _) = call(&app, "GET", &closed, Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK, "admin bypasses viewRule");

    // a missing record is 404 before any rule talk
    let (s, _) = call(
        &app,
        "GET",
        "/api/collections/posts/records/ghost",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // create is gated in memory, before the insert: an empty createRule never rejects
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["totalItems"], 2, "{v}");
}
