// Relation fields + `?expand=` (specs/relations.md) — TDD red phase.
// Same harness as tests/basic.rs / tests/rules.rs: tower oneshot against build_app.
//
// The spec predates the rules feature. `expand` is a read amplifier, so the
// rule-leak tests below (expand_respects_target_view_rule,
// expand_into_auth_collection_*) are deliberately stricter than the spec text.

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

/// Admin-create a collection. Returns (status, body) so negative cases can assert too.
async fn mkcol(app: &Router, body: Value) -> (StatusCode, Value) {
    call(app, "POST", "/api/collections", Some(ADMIN), Some(body)).await
}

/// Admin-create a collection that must succeed.
async fn mkcol_ok(app: &Router, body: Value) {
    let (s, v) = mkcol(app, body.clone()).await;
    assert_eq!(s, StatusCode::OK, "create collection {body}: {v}");
}

/// Admin-create a record that must succeed; returns its id.
async fn mkrec(app: &Router, col: &str, body: Value) -> String {
    let (s, v) = call(
        app,
        "POST",
        &format!("/api/collections/{col}/records"),
        Some(ADMIN),
        Some(body.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "create {col} record {body}: {v}");
    v["id"].as_str().expect("record id").to_string()
}

/// Seed an auth user via the admin bypass and log in. Returns (id, "Bearer …").
async fn user(app: &Router, email: &str) -> (String, String) {
    let id = mkrec(app, "users", json!({"email": email, "password": PW})).await;
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

/// The standard fixture: `authors` (name + secret) and `posts` (title + author relation).
async fn seed_authors_posts(app: &Router) {
    mkcol_ok(
        app,
        json!({"name": "authors", "schema": [
            {"name": "name", "type": "text"},
            {"name": "secret", "type": "text"}
        ]}),
    )
    .await;
    mkcol_ok(
        app,
        json!({"name": "posts", "schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "author", "type": "relation", "options": {"collection": "authors"}}
        ]}),
    )
    .await;
}

/// Assert the response carries no expanded record under `field` — either no
/// `expand` key at all, or an `expand` object without that key.
fn assert_not_expanded(v: &Value, field: &str, why: &str) {
    let leaked = v.get("expand").and_then(|e| e.get(field));
    assert!(
        leaked.is_none() || leaked == Some(&Value::Null),
        "{why}: expand.{field} leaked {leaked:?} in {v}"
    );
}

/// Find one item of a list response by its `title`.
fn item<'a>(list: &'a Value, title: &str) -> &'a Value {
    list["items"]
        .as_array()
        .unwrap_or_else(|| panic!("no items array in {list}"))
        .iter()
        .find(|i| i["title"] == json!(title))
        .unwrap_or_else(|| panic!("no item titled {title} in {list}"))
}

// ---------------------------------------------------------------------------
// 1. Schema
// ---------------------------------------------------------------------------

// A `relation` field type is accepted, needs options.collection, and the target
// is NOT required to exist at schema time (so self-relations work).
#[tokio::test]
async fn schema_accepts_relation_field() {
    let app = app();
    mkcol_ok(
        &app,
        json!({"name": "authors", "schema": [{"name": "name", "type": "text"}]}),
    )
    .await;

    let (s, v) = mkcol(
        &app,
        json!({"name": "posts", "schema": [
            {"name": "title", "type": "text"},
            {"name": "author", "type": "relation", "options": {"collection": "authors"}}
        ]}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "relation field must be a valid schema type: {v}"
    );
    assert_eq!(
        v["schema"][1]["type"],
        json!("relation"),
        "echoed schema: {v}"
    );
    assert_eq!(
        v["schema"][1]["options"]["collection"],
        json!("authors"),
        "echoed schema: {v}"
    );

    // read back through GET, not just the create echo
    let (s, v) = call(&app, "GET", "/api/collections/posts", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["schema"][1]["type"],
        json!("relation"),
        "stored schema: {v}"
    );

    // self-relation: target need not exist yet / may be the collection itself
    let (s, v) = mkcol(
        &app,
        json!({"name": "nodes", "schema": [
            {"name": "parent", "type": "relation", "options": {"collection": "nodes"}}
        ]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "self-relation must be accepted: {v}");

    // target collection that does not exist is also fine at schema time
    let (s, v) = mkcol(
        &app,
        json!({"name": "later", "schema": [
            {"name": "rel", "type": "relation", "options": {"collection": "notyet"}}
        ]}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "unknown target checked per-write, not at schema time: {v}"
    );
}

// A relation field without a usable options.collection is a 400.
#[tokio::test]
async fn schema_rejects_relation_without_target() {
    let app = app();
    for bad in [
        json!({"name": "author", "type": "relation"}),
        json!({"name": "author", "type": "relation", "options": {}}),
        json!({"name": "author", "type": "relation", "options": {"collection": ""}}),
        json!({"name": "author", "type": "relation", "options": {"collection": 7}}),
        // ident_ok: no dots, dashes, spaces or SQL
        json!({"name": "author", "type": "relation", "options": {"collection": "a-b"}}),
        json!({"name": "author", "type": "relation", "options": {"collection": "au thors"}}),
        json!({"name": "author", "type": "relation", "options": {"collection": "x'; DROP"}}),
    ] {
        let (s, v) = mkcol(&app, json!({"name": "posts", "schema": [bad.clone()]})).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "must reject {bad}: got {v}");
    }
}

// Relation fields obey RESERVED_FIELDS like every other field type.
#[tokio::test]
async fn relation_field_cannot_use_reserved_name() {
    let app = app();
    mkcol_ok(
        &app,
        json!({"name": "authors", "schema": [{"name": "name", "type": "text"}]}),
    )
    .await;
    for name in [
        "id",
        "created",
        "updated",
        "collectionName",
        "password_hash",
    ] {
        let (s, v) = mkcol(
            &app,
            json!({"name": "posts", "schema": [
                {"name": name, "type": "relation", "options": {"collection": "authors"}}
            ]}),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "reserved relation name '{name}' must 400: {v}"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Value validation
// ---------------------------------------------------------------------------

// A relation value must be a string naming an existing record in the target.
#[tokio::test]
async fn relation_value_must_be_an_existing_id() {
    let app = app();
    seed_authors_posts(&app).await;
    let og = mkrec(&app, "authors", json!({"name": "Og"})).await;

    // real id -> 200, echoed back as the raw id string (not inlined)
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(json!({"title": "hello", "author": og})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "post with real author: {v}");
    assert_eq!(v["author"], json!(og), "author echoed as id string: {v}");
    assert!(
        v.get("expand").is_none(),
        "create must not auto-expand: {v}"
    );

    // unknown id -> 400 (DB existence check)
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(json!({"title": "dangling", "author": "nope"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "unknown relation id must 400: {v}"
    );

    // a real id, but in the WRONG collection -> still 400
    let (uid, _) = user(&app, "wrong@example.com").await;
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(json!({"title": "crosscol", "author": uid})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "id from another collection must 400: {v}"
    );

    // non-string -> 400 on the type check, before any DB hit
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(json!({"title": "typed", "author": 42})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "non-string relation must 400: {v}"
    );

    // null is fine on an optional relation
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(json!({"title": "orphan", "author": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "null relation on optional field: {v}");
}

// PATCH runs the same check, and only over the fields being written.
#[tokio::test]
async fn relation_patch_is_validated() {
    let app = app();
    seed_authors_posts(&app).await;
    let og = mkrec(&app, "authors", json!({"name": "Og"})).await;
    let ug = mkrec(&app, "authors", json!({"name": "Ug"})).await;
    let post = mkrec(&app, "posts", json!({"title": "hello", "author": &og})).await;
    let uri = format!("/api/collections/posts/records/{post}");

    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(ADMIN),
        Some(json!({"author": "nope"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "PATCH to unknown id must 400: {v}"
    );

    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(ADMIN),
        Some(json!({"author": &ug})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "PATCH to a real id: {v}");
    assert_eq!(v["author"], json!(ug), "{v}");

    // patching an unrelated field must not re-validate (or clobber) the relation
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(ADMIN),
        Some(json!({"title": "bye"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "unrelated PATCH: {v}");
    assert_eq!(v["author"], json!(ug), "relation preserved: {v}");

    // explicit null clears an optional relation
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(ADMIN),
        Some(json!({"author": null})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "clearing an optional relation: {v}");
    assert_eq!(v["author"], json!(null), "{v}");
}

// ---------------------------------------------------------------------------
// 3. Expand
// ---------------------------------------------------------------------------

// ?expand=field on a single record view inlines the related record.
#[tokio::test]
async fn expand_on_view() {
    let app = app();
    seed_authors_posts(&app).await;
    let og = mkrec(&app, "authors", json!({"name": "Og", "secret": "no"})).await;
    let post = mkrec(&app, "posts", json!({"title": "hello", "author": &og})).await;

    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{post}?expand=author"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "expand on view: {v}");
    assert_eq!(v["author"], json!(og), "raw id stays alongside expand: {v}");
    assert_eq!(v["expand"]["author"]["name"], json!("Og"), "{v}");
    assert_eq!(v["expand"]["author"]["id"], json!(og), "{v}");
    assert_eq!(
        v["expand"]["author"]["collectionName"],
        json!("authors"),
        "{v}"
    );
    assert!(
        v["expand"]["author"]["created"].is_string(),
        "expanded record is a full record: {v}"
    );
    // one level only: the expanded record is never itself expanded
    assert!(
        v["expand"]["author"].get("expand").is_none(),
        "expand must be one level: {v}"
    );

    // no expand param at all -> no expand key
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{post}"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v.get("expand").is_none(),
        "no ?expand= means no expand key: {v}"
    );
}

// Unknown names and non-relation fields in ?expand= are silently skipped (PocketBase parity).
#[tokio::test]
async fn expand_skips_unknown_and_non_relation_fields() {
    let app = app();
    seed_authors_posts(&app).await;
    let og = mkrec(&app, "authors", json!({"name": "Og"})).await;
    let post = mkrec(&app, "posts", json!({"title": "hello", "author": &og})).await;

    // `title` is a text field, `bogus` is not a field at all -> 200, nothing resolved
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{post}?expand=title,bogus"),
        None,
        None,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "unknown expand names are skipped, not rejected: {v}"
    );
    assert!(
        v.get("expand").is_none(),
        "nothing resolved -> no expand key at all: {v}"
    );

    // a good name mixed with junk still resolves the good one
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{post}?expand=bogus,author"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["expand"]["author"]["name"], json!("Og"), "{v}");
    assert!(v["expand"].get("bogus").is_none(), "{v}");
}

// Null and dangling relation ids expand to nothing; the raw id is preserved.
#[tokio::test]
async fn expand_null_and_dangling_relations() {
    let app = app();
    seed_authors_posts(&app).await;
    let og = mkrec(&app, "authors", json!({"name": "Og"})).await;
    let orphan = mkrec(&app, "posts", json!({"title": "orphan", "author": null})).await;
    let post = mkrec(&app, "posts", json!({"title": "hello", "author": &og})).await;

    // null relation
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{orphan}?expand=author"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        v.get("expand").is_none(),
        "null relation resolves nothing: {v}"
    );

    // now delete the author: the id dangles
    let (s, v) = call(
        &app,
        "DELETE",
        &format!("/api/collections/authors/records/{og}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "delete author: {v}");

    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{post}?expand=author"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "dangling relation must not 404/500: {v}");
    assert_eq!(
        v["author"],
        json!(og),
        "dangling id is kept on the record: {v}"
    );
    assert!(
        v.get("expand").is_none(),
        "dangling id resolves nothing: {v}"
    );
}

// ?expand= works on the list endpoint, per item.
#[tokio::test]
async fn expand_on_list() {
    let app = app();
    seed_authors_posts(&app).await;
    let og = mkrec(&app, "authors", json!({"name": "Og"})).await;
    let ug = mkrec(&app, "authors", json!({"name": "Ug"})).await;
    mkrec(&app, "posts", json!({"title": "a", "author": &og})).await;
    mkrec(&app, "posts", json!({"title": "b", "author": &ug})).await;
    mkrec(&app, "posts", json!({"title": "c", "author": null})).await;

    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?expand=author",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "expand on list: {v}");
    assert_eq!(v["totalItems"], json!(3), "{v}");
    assert_eq!(
        item(&v, "a")["expand"]["author"]["name"],
        json!("Og"),
        "{v}"
    );
    assert_eq!(
        item(&v, "b")["expand"]["author"]["name"],
        json!("Ug"),
        "{v}"
    );
    assert!(
        item(&v, "c").get("expand").is_none(),
        "null relation item has no expand: {v}"
    );

    // expand survives alongside the other list params
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?expand=author&filter=title='b'&sort=-created",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["totalItems"], json!(1), "{v}");
    assert_eq!(
        item(&v, "b")["expand"]["author"]["name"],
        json!("Ug"),
        "{v}"
    );
}

// Several relation fields expand independently in one request.
#[tokio::test]
async fn expand_multiple_relations() {
    let app = app();
    mkcol_ok(
        &app,
        json!({"name": "authors", "schema": [{"name": "name", "type": "text"}]}),
    )
    .await;
    mkcol_ok(
        &app,
        json!({"name": "tags", "schema": [{"name": "label", "type": "text"}]}),
    )
    .await;
    mkcol_ok(
        &app,
        json!({"name": "posts", "schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "author", "type": "relation", "options": {"collection": "authors"}},
            {"name": "editor", "type": "relation", "options": {"collection": "authors"}},
            {"name": "tag", "type": "relation", "options": {"collection": "tags"}}
        ]}),
    )
    .await;
    let og = mkrec(&app, "authors", json!({"name": "Og"})).await;
    let ug = mkrec(&app, "authors", json!({"name": "Ug"})).await;
    let rock = mkrec(&app, "tags", json!({"label": "rock"})).await;
    let post = mkrec(
        &app,
        "posts",
        json!({"title": "hello", "author": &og, "editor": &ug, "tag": &rock}),
    )
    .await;

    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{post}?expand=author,editor"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["expand"]["author"]["name"], json!("Og"), "{v}");
    assert_eq!(v["expand"]["editor"]["name"], json!("Ug"), "{v}");
    assert!(
        v["expand"].get("tag").is_none(),
        "only requested fields expand: {v}"
    );

    // whitespace around names is tolerated, and all three expand at once
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{post}?expand=author,%20editor,tag"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["expand"]["editor"]["name"],
        json!("Ug"),
        "trimmed names: {v}"
    );
    assert_eq!(v["expand"]["tag"]["label"], json!("rock"), "{v}");
}

// ---------------------------------------------------------------------------
// 4. Expand is a read amplifier: it must not bypass the TARGET collection's rules
//    (specs/relations.md predates specs/rules.md — this is the leak class).
// ---------------------------------------------------------------------------

// A target record the caller could not GET directly must not arrive via expand.
#[tokio::test]
async fn expand_respects_target_view_rule() {
    let app = app();
    mkcol_ok(
        &app,
        json!({"name": "authors",
               "schema": [{"name": "name", "type": "text"}, {"name": "secret", "type": "text"}],
               "viewRule": "secret = 'no'",
               "listRule": "secret = 'no'"}),
    )
    .await;
    mkcol_ok(
        &app,
        json!({"name": "posts", "schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "author", "type": "relation", "options": {"collection": "authors"}}
        ]}),
    )
    .await;
    let open = mkrec(&app, "authors", json!({"name": "Og", "secret": "no"})).await;
    let hidden = mkrec(&app, "authors", json!({"name": "Ghost", "secret": "yes"})).await;
    let open_post = mkrec(&app, "posts", json!({"title": "open", "author": &open})).await;
    let hidden_post = mkrec(&app, "posts", json!({"title": "hidden", "author": &hidden})).await;
    let (_, tok) = user(&app, "reader@example.com").await;

    // baseline: the hidden author is NOT directly fetchable by this caller
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/collections/authors/records/{hidden}"),
        Some(&tok),
        None,
    )
    .await;
    assert_ne!(
        s,
        StatusCode::OK,
        "fixture is wrong: hidden author is directly viewable"
    );

    // ...so expand must not hand it over either
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{hidden_post}?expand=author"),
        Some(&tok),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "the post itself is public: {v}");
    assert_not_expanded(&v, "author", "expand must not bypass the target viewRule");
    assert!(
        !v.to_string().contains("Ghost"),
        "hidden author data leaked through expand: {v}"
    );

    // the visible one still expands normally
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{open_post}?expand=author"),
        Some(&tok),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["expand"]["author"]["name"], json!("Og"), "{v}");

    // and the same holds on the list endpoint, which amplifies the leak N times
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?expand=author",
        Some(&tok),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        !v.to_string().contains("Ghost"),
        "hidden author leaked through list expand: {v}"
    );
    assert_not_expanded(
        item(&v, "hidden"),
        "author",
        "list expand must not bypass viewRule",
    );
    assert_eq!(
        item(&v, "open")["expand"]["author"]["name"],
        json!("Og"),
        "{v}"
    );

    // admin still sees everything (rules do not apply to admins)
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{hidden_post}?expand=author"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["expand"]["author"]["name"],
        json!("Ghost"),
        "admin expand: {v}"
    );
}

// `users` is admin-only by default (viewRule NULL) — expanding into it must
// respect that, for the owner of the record as much as for a stranger.
#[tokio::test]
async fn expand_into_auth_collection_respects_admin_only_rule() {
    let app = app();
    mkcol_ok(
        &app,
        json!({"name": "posts", "schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "owner", "type": "relation", "options": {"collection": "users"}}
        ]}),
    )
    .await;
    let (owner_id, owner_tok) = user(&app, "owner@example.com").await;
    let (_, other_tok) = user(&app, "other@example.com").await;
    let post = mkrec(&app, "posts", json!({"title": "mine", "owner": &owner_id})).await;
    let uri = format!("/api/collections/posts/records/{post}?expand=owner");

    // baseline: users viewRule defaults to NULL = admin only, for everyone
    for (tok, who) in [(&owner_tok, "owner"), (&other_tok, "stranger")] {
        let (s, _) = call(
            &app,
            "GET",
            &format!("/api/collections/users/records/{owner_id}"),
            Some(tok),
            None,
        )
        .await;
        assert_ne!(
            s,
            StatusCode::OK,
            "fixture is wrong: {who} can directly view a users record"
        );
    }

    for (tok, who) in [(&owner_tok, "owner"), (&other_tok, "stranger")] {
        let (s, v) = call(&app, "GET", &uri, Some(tok), None).await;
        assert_eq!(s, StatusCode::OK, "the post is public: {v}");
        assert_not_expanded(
            &v,
            "owner",
            &format!("{who} must not read a users record via expand"),
        );
        assert!(
            !v.to_string().contains("owner@example.com"),
            "auth record leaked through expand to {who}: {v}"
        );
    }

    // guests too
    let (s, v) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_not_expanded(&v, "owner", "guest must not read a users record via expand");
}

// An expanded auth record never carries password_hash — not even for an admin.
#[tokio::test]
async fn expand_never_exposes_password_hash() {
    let app = app();
    mkcol_ok(
        &app,
        json!({"name": "posts", "schema": [
            {"name": "title", "type": "text", "required": true},
            {"name": "owner", "type": "relation", "options": {"collection": "users"}}
        ]}),
    )
    .await;
    let (owner_id, _) = user(&app, "owner@example.com").await;
    let post = mkrec(&app, "posts", json!({"title": "mine", "owner": &owner_id})).await;

    // admin can expand (rules do not gate admins) but still gets a scrubbed record
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records/{post}?expand=owner"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["expand"]["owner"]["id"],
        json!(owner_id),
        "admin expand resolves: {v}"
    );
    assert!(
        v["expand"]["owner"].get("password_hash").is_none(),
        "expanded auth record must not carry password_hash: {v}"
    );
    assert!(
        !v.to_string().contains("password_hash") && !v.to_string().contains("$2b$"),
        "no bcrypt hash anywhere in an expanded response: {v}"
    );

    // and on the list endpoint
    let (s, v) = call(
        &app,
        "GET",
        "/api/collections/posts/records?expand=owner",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        !v.to_string().contains("password_hash") && !v.to_string().contains("$2b$"),
        "no bcrypt hash anywhere in an expanded list: {v}"
    );
}
