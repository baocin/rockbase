// Realtime topics (specs/realtime2.md) + rule-aware event filtering — TDD red phase.
//
// Same harness style as tests/basic.rs / tests/rules.rs: tower::ServiceExt::oneshot
// against `rockbase::build_app`. SSE bodies never end, so every read is bounded by
// a `tokio::time::timeout` and no test ever reads a body to completion.
//
// NOTE on the spec: specs/realtime2.md predates the rules feature and explicitly puts
// rule-aware filtering "out of scope". That is the security hole these tests close —
// where the spec and least-privilege disagree, the tests here follow least-privilege.

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tokio::time::timeout;
use tower::ServiceExt;

use rockbase::build_app;

const ADMIN: &str = "Admin testtoken";
const PW: &str = "clubrock1";

/// Silence window that ends a drain. The broadcast `send` happens synchronously inside
/// the write handler, so by the time a write's `oneshot` future resolves the message is
/// already queued on every existing receiver — draining only waits for the task to be
/// polled, not for I/O. 300ms is therefore ~3 orders of magnitude of slack.
const QUIET_MS: u64 = 300;

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

/// Open an SSE subscription. Returns the (never-ending) body; the handler has already
/// subscribed to the broadcast channel by the time this resolves, so writes issued
/// afterwards are guaranteed to be seen.
async fn sse(app: &Router, uri: &str, auth: Option<&str>) -> Body {
    let mut req = Request::builder().method("GET").uri(uri);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "subscribe {uri}");
    let ct = resp.headers()["content-type"].to_str().unwrap().to_string();
    assert!(
        ct.starts_with("text/event-stream"),
        "content-type of {uri}: {ct}"
    );
    resp.into_body()
}

/// Every `data:` payload that arrives before QUIET_MS of silence. Bounded: it can never
/// block longer than QUIET_MS past the last frame, so it terminates on an idle stream.
async fn drain(body: &mut Body) -> Vec<Value> {
    let mut out = Vec::new();
    while let Ok(Some(Ok(frame))) = timeout(Duration::from_millis(QUIET_MS), body.frame()).await {
        let Ok(bytes) = frame.into_data() else {
            continue;
        };
        for line in String::from_utf8_lossy(&bytes).lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                let rest = rest.trim();
                out.push(serde_json::from_str(rest).unwrap_or_else(|_| json!(rest)));
            }
        }
    }
    out
}

/// The change events out of a drain, i.e. everything that is not the clientId hello.
fn changes(vals: Vec<Value>) -> Vec<Value> {
    vals.into_iter()
        .filter(|v| v.get("clientId").is_none())
        .collect()
}

/// One frame, or None if nothing arrives inside the window.
async fn next(body: &mut Body) -> Option<Value> {
    let frame = timeout(Duration::from_millis(QUIET_MS), body.frame())
        .await
        .ok()??
        .ok()?;
    let bytes = frame.into_data().ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let line = text.lines().find(|l| l.starts_with("data:"))?;
    let rest = line.strip_prefix("data:")?.trim();
    Some(serde_json::from_str(rest).unwrap_or_else(|_| json!(rest)))
}

/// Compact `[(action, topic, title-or-id)]` view, for readable assertion failures.
fn summary(evs: &[Value]) -> Vec<String> {
    evs.iter()
        .map(|e| {
            format!(
                "{}/{}/{}",
                e["action"].as_str().unwrap_or("?"),
                e["topic"].as_str().unwrap_or("?"),
                e["record"]["title"]
                    .as_str()
                    .or_else(|| e["record"]["id"].as_str())
                    .unwrap_or("?")
            )
        })
        .collect()
}

async fn mkcol(app: &Router, body: Value) {
    let (s, v) = call(app, "POST", "/api/collections", Some(ADMIN), Some(body)).await;
    assert_eq!(s, StatusCode::OK, "create collection: {v}");
}

async fn create(app: &Router, col: &str, auth: Option<&str>, body: Value) -> Value {
    let (s, v) = call(
        app,
        "POST",
        &format!("/api/collections/{col}/records"),
        auth,
        Some(body),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "create in {col}: {v}");
    v
}

/// Seed a user through the admin bypass and log in. Returns (record id, "Bearer <tok>").
async fn user(app: &Router, email: &str) -> (String, String) {
    let u = create(
        app,
        "users",
        Some(ADMIN),
        json!({"email": email, "password": PW}),
    )
    .await;
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

/// posts + comments, both with the default public base rules.
async fn seed_public(app: &Router) {
    mkcol(
        app,
        json!({"name": "posts", "schema": [{"name": "title", "type": "text"}]}),
    )
    .await;
    mkcol(
        app,
        json!({"name": "comments", "schema": [{"name": "title", "type": "text"}]}),
    )
    .await;
}

// ---------------------------------------------------------------------------
// 1. Connect handshake: exactly one clientId frame, before any change event.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn hello_frame_carries_client_id() {
    let app = app();
    let mut body = sse(&app, "/api/realtime", None).await;

    let hello = next(&mut body).await.expect("no frame at all on connect");
    let id = hello["clientId"]
        .as_str()
        .unwrap_or_else(|| panic!("first frame must be the clientId hello, got {hello}"));
    assert_eq!(
        id.len(),
        32,
        "clientId must be a 32-char uuid simple form: {id}"
    );
    assert!(
        id.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "clientId must be lowercase hex: {id}"
    );

    // and only one hello — nothing else is pending on an idle stream
    assert!(
        changes(drain(&mut body).await).is_empty(),
        "idle stream must be quiet"
    );
}

// ---------------------------------------------------------------------------
// 2. Payload shape: action + full record + topic.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn create_event_payload_shape() {
    let app = app();
    seed_public(&app).await;
    let mut body = sse(&app, "/api/realtime", None).await;

    let rec = create(&app, "posts", Some(ADMIN), json!({"title": "hi"})).await;

    let evs = changes(drain(&mut body).await);
    assert_eq!(
        evs.len(),
        1,
        "expected exactly one event, got {:?}",
        summary(&evs)
    );
    let e = &evs[0];
    assert_eq!(e["action"], "create", "{e}");
    assert_eq!(e["topic"], "posts", "every payload carries its topic: {e}");
    assert_eq!(e["record"]["id"], rec["id"], "{e}");
    assert_eq!(e["record"]["collectionName"], "posts", "{e}");
    assert_eq!(e["record"]["title"], "hi", "{e}");
}

// ---------------------------------------------------------------------------
// 3. update + delete events, and the delete payload shape.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn update_and_delete_events() {
    let app = app();
    seed_public(&app).await;
    let rec = create(&app, "posts", Some(ADMIN), json!({"title": "before"})).await;
    let id = rec["id"].as_str().unwrap().to_string();

    let mut body = sse(&app, "/api/realtime", None).await;

    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/collections/posts/records/{id}"),
        Some(ADMIN),
        Some(json!({"title": "after"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/collections/posts/records/{id}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let evs = changes(drain(&mut body).await);
    assert_eq!(
        evs.len(),
        2,
        "expected update then delete, got {:?}",
        summary(&evs)
    );
    assert_eq!(evs[0]["action"], "update", "{}", evs[0]);
    assert_eq!(evs[0]["topic"], "posts", "{}", evs[0]);
    assert_eq!(evs[0]["record"]["title"], "after", "{}", evs[0]);
    assert_eq!(evs[1]["action"], "delete", "{}", evs[1]);
    assert_eq!(evs[1]["topic"], "posts", "{}", evs[1]);
    assert_eq!(evs[1]["record"]["id"], json!(id), "{}", evs[1]);
    assert_eq!(evs[1]["record"]["collectionName"], "posts", "{}", evs[1]);
}

// ---------------------------------------------------------------------------
// 4. ?topics=posts forwards only posts events.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn single_topic_filters_other_collections() {
    let app = app();
    seed_public(&app).await;
    let mut body = sse(&app, "/api/realtime?topics=posts", None).await;

    create(&app, "comments", Some(ADMIN), json!({"title": "nope"})).await;
    create(&app, "posts", Some(ADMIN), json!({"title": "yes"})).await;

    let evs = changes(drain(&mut body).await);
    assert_eq!(
        evs.len(),
        1,
        "only the posts event may arrive, got {:?}",
        summary(&evs)
    );
    assert_eq!(evs[0]["topic"], "posts", "{}", evs[0]);
    assert_eq!(evs[0]["record"]["title"], "yes", "{}", evs[0]);
}

// ---------------------------------------------------------------------------
// 5. Two topics; whitespace and duplicates are harmless.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn two_topics_receive_both() {
    let app = app();
    seed_public(&app).await;
    mkcol(
        &app,
        json!({"name": "other", "schema": [{"name": "title", "type": "text"}]}),
    )
    .await;
    let mut body = sse(
        &app,
        "/api/realtime?topics=posts,%20comments%20,posts",
        None,
    )
    .await;

    create(&app, "posts", Some(ADMIN), json!({"title": "p"})).await;
    create(&app, "other", Some(ADMIN), json!({"title": "o"})).await;
    create(&app, "comments", Some(ADMIN), json!({"title": "c"})).await;

    let evs = changes(drain(&mut body).await);
    assert_eq!(
        summary(&evs),
        vec![
            "create/posts/p".to_string(),
            "create/comments/c".to_string()
        ],
        "`other` must be filtered out"
    );
}

// ---------------------------------------------------------------------------
// 6. Wildcard: no param, empty param, and comma-only all mean "everything".
// ---------------------------------------------------------------------------
#[tokio::test]
async fn empty_topics_means_all_events() {
    for uri in [
        "/api/realtime",
        "/api/realtime?topics=",
        "/api/realtime?topics=%20,%20,",
    ] {
        let app = app();
        seed_public(&app).await;
        let mut body = sse(&app, uri, None).await;

        create(&app, "posts", Some(ADMIN), json!({"title": "p"})).await;
        create(&app, "comments", Some(ADMIN), json!({"title": "c"})).await;

        let evs = changes(drain(&mut body).await);
        assert_eq!(
            summary(&evs),
            vec![
                "create/posts/p".to_string(),
                "create/comments/c".to_string()
            ],
            "{uri} must not filter"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. An unknown topic connects fine and simply never matches. Proven against a
//    second, unfiltered subscriber so this can't false-pass on a broken broadcast.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn unknown_topic_receives_nothing() {
    let app = app();
    seed_public(&app).await;
    let mut filtered = sse(&app, "/api/realtime?topics=nope", None).await;
    let mut witness = sse(&app, "/api/realtime", None).await;

    create(&app, "posts", Some(ADMIN), json!({"title": "p"})).await;

    // the witness proves the event really was broadcast...
    let seen = changes(drain(&mut witness).await);
    assert_eq!(summary(&seen), vec!["create/posts/p".to_string()]);
    // ...so the filtered subscriber's silence is filtering, not a missing event
    assert!(
        changes(drain(&mut filtered).await).is_empty(),
        "topics=nope must never match"
    );
}

// ---------------------------------------------------------------------------
// 8. SECURITY: a guest must not receive events from an admin-only collection
//    (listRule/viewRule NULL). The public `posts` event issued *after* it is the
//    positive control — broadcast preserves order, so if `posts` arrived and
//    `secrets` did not, `secrets` was filtered, not merely slow.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn guest_gets_no_events_from_admin_only_collection() {
    let app = app();
    seed_public(&app).await;
    mkcol(
        &app,
        json!({
            "name": "secrets",
            "schema": [{"name": "title", "type": "text"}],
            "listRule": null,
            "viewRule": null
        }),
    )
    .await;

    let mut guest = sse(&app, "/api/realtime", None).await;

    create(&app, "secrets", Some(ADMIN), json!({"title": "nuclear"})).await;
    create(&app, "posts", Some(ADMIN), json!({"title": "public"})).await;

    let evs = changes(drain(&mut guest).await);
    assert!(
        !evs.iter().any(|e| e["topic"] == "secrets"
            || e["record"]["collectionName"] == "secrets"
            || e["record"]["title"] == "nuclear"),
        "guest leaked an admin-only collection event: {:?}",
        summary(&evs)
    );
    assert_eq!(
        summary(&evs),
        vec!["create/posts/public".to_string()],
        "guest must still get the public collection's event"
    );
}

// ---------------------------------------------------------------------------
// 9. SECURITY: an authenticated user must not receive events for records the
//    list/view rule hides from them. Same ordering trick for the absence.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn user_gets_no_events_for_records_a_rule_hides() {
    let app = app();
    mkcol(
        &app,
        json!({
            "name": "posts",
            "schema": [{"name": "title", "type": "text"}, {"name": "owner", "type": "text"}],
            "listRule": "owner = @request.auth.id",
            "viewRule": "owner = @request.auth.id"
        }),
    )
    .await;
    let (alice_id, alice) = user(&app, "alice@cave.dev").await;
    let (bob_id, _bob) = user(&app, "bob@cave.dev").await;

    let mut sub = sse(&app, "/api/realtime", Some(&alice)).await;

    create(
        &app,
        "posts",
        Some(ADMIN),
        json!({"title": "bobs", "owner": bob_id}),
    )
    .await;
    create(
        &app,
        "posts",
        Some(ADMIN),
        json!({"title": "alices", "owner": alice_id}),
    )
    .await;

    let evs = changes(drain(&mut sub).await);
    assert!(
        !evs.iter().any(|e| e["record"]["title"] == "bobs"),
        "alice leaked a record her view rule hides: {:?}",
        summary(&evs)
    );
    assert_eq!(
        summary(&evs),
        vec!["create/posts/alices".to_string()],
        "alice must still receive her own record's event"
    );
}

// ---------------------------------------------------------------------------
// 10. Admin bypasses rule filtering and receives everything.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn admin_receives_everything() {
    let app = app();
    seed_public(&app).await;
    mkcol(
        &app,
        json!({
            "name": "secrets",
            "schema": [{"name": "title", "type": "text"}],
            "listRule": null,
            "viewRule": null
        }),
    )
    .await;

    let mut sub = sse(&app, "/api/realtime", Some(ADMIN)).await;

    create(&app, "secrets", Some(ADMIN), json!({"title": "s"})).await;
    create(&app, "posts", Some(ADMIN), json!({"title": "p"})).await;

    let evs = changes(drain(&mut sub).await);
    assert_eq!(
        summary(&evs),
        vec!["create/secrets/s".to_string(), "create/posts/p".to_string()],
        "admin must see every collection"
    );
}

// ---------------------------------------------------------------------------
// 11. SECURITY: delete events are gated too — a delete frame still names the
//     record id and collection, so an ungated one leaks the existence of rows
//     the subscriber could never read.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn delete_events_are_rule_gated() {
    let app = app();
    seed_public(&app).await;
    mkcol(
        &app,
        json!({
            "name": "secrets",
            "schema": [{"name": "title", "type": "text"}],
            "listRule": null,
            "viewRule": null
        }),
    )
    .await;
    let secret = create(&app, "secrets", Some(ADMIN), json!({"title": "s"})).await;
    let sid = secret["id"].as_str().unwrap().to_string();

    let mut guest = sse(&app, "/api/realtime", None).await;

    let (s, v) = call(
        &app,
        "DELETE",
        &format!("/api/collections/secrets/records/{sid}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "admin delete: {v}");
    create(&app, "posts", Some(ADMIN), json!({"title": "control"})).await;

    let evs = changes(drain(&mut guest).await);
    assert!(
        !evs.iter()
            .any(|e| e["record"]["id"] == json!(sid) || e["topic"] == "secrets"),
        "guest leaked the delete of an admin-only record: {:?}",
        summary(&evs)
    );
    assert_eq!(
        summary(&evs),
        vec!["create/posts/control".to_string()],
        "the control event must still arrive"
    );
}
