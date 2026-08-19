// SSE lag notification — TDD red phase.
//
// THE BUG: `build_app` creates `broadcast::channel(64)`; `realtime.rs` reads it with
// `let ev = m.ok()?;`. When a subscriber falls more than 64 events behind, the
// `BroadcastStream` yields `Err(RecvError::Lagged(n))` and `.ok()?` throws it away.
// The subscriber silently misses n events and is never told, so it believes it is in
// sync. For a realtime client that is worse than being disconnected: a dropped
// connection is observable and triggers a refetch, a silent hole is not.
//
// THE CONTRACT PINNED HERE: on lag the stream emits one frame
//
//     data: {"lagged": <n>}
//
// where `n` is the number of events the subscriber missed, and then CONTINUES with
// the events still in the buffer. Shape chosen to be self-describing and impossible
// to confuse with a change event: a change event is `{"action","topic","record"}`, so
// existing clients (and the `changes()` helper below) already key off those. A single
// unambiguous `lagged` key is the smallest thing a client can branch on to know it
// must refetch, and it is the only thing that may be revealed — the count, never the
// records. `changes()` here therefore filters out BOTH the clientId hello and the lag
// frame, so a lag frame can never be mistaken for an event by these tests.
//
// Harness is a copy of tests/realtime.rs / tests/sse_token.rs: tower::ServiceExt::oneshot
// against `rockbase::build_app`. SSE bodies never end, so every read is bounded by a
// `tokio::time::timeout` and no test ever reads a body to completion.
//
// HOW THE OVERRUN IS TRIGGERED (the crux, and why it is deterministic rather than
// timing-dependent): `realtime()` calls `app.events.subscribe()` eagerly, before it
// returns the `Sse` response, so the receiver exists and holds position 0 the moment
// `sse()` resolves. Nothing polls a `Body` we merely hold — `oneshot` does not spawn a
// task for it — so the receiver stays at position 0 for as long as we do not read.
// We then publish PUBLISHED (=100) events via `/api/batch`, whose `broadcast_change`
// calls all happen inside the handler, before its response resolves. 100 sends into a
// 64-slot ring with a receiver parked at 0 overruns it by construction: tokio drops
// the oldest 36 and the next `recv` reports `Lagged(36)`. No sleep, no scheduling race,
// no dependence on relative task speed — only on "we did not read yet", which is
// enforced by doing every write before the first `frame()` call.

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

/// Silence window that ends a drain — same reasoning as tests/realtime.rs: the
/// broadcast `send` is synchronous inside the write handler, so every message is
/// already queued on every live receiver by the time the write's oneshot resolves.
const QUIET_MS: u64 = 300;

/// Broadcast channel capacity in `build_app`. Only used for the failure message —
/// no assertion depends on this number.
const CAP: usize = 64;
/// Events published without reading. Comfortably over CAP, and a whole number of
/// `/api/batch` calls (batch caps at 50 sub-requests).
const PUBLISHED: usize = 100;
const BATCH: usize = 50;

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

/// Open an SSE subscription. The handler has already subscribed to the broadcast
/// channel by the time this resolves, so every later write is either delivered or
/// missed-and-counted — never simply absent.
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

/// Every `data:` payload that arrives before QUIET_MS of silence. Bounded: it can
/// never block longer than QUIET_MS past the last frame, so it terminates on an idle
/// stream and never reads the (endless) body to completion.
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

/// The lag count of a frame, if it is a lag frame.
fn lag_of(v: &Value) -> Option<u64> {
    v.get("lagged")?.as_u64()
}

/// The change events out of a drain: neither the clientId hello nor a lag frame.
fn changes(vals: &[Value]) -> Vec<Value> {
    vals.iter()
        .filter(|v| v.get("clientId").is_none() && lag_of(v).is_none())
        .cloned()
        .collect()
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

/// A one-line census of a drain, so a failure says what actually arrived.
fn census(vals: &[Value]) -> String {
    let hellos = vals.iter().filter(|v| v.get("clientId").is_some()).count();
    let lags: Vec<u64> = vals.iter().filter_map(lag_of).collect();
    format!(
        "{hellos} hello, {} change event(s), lag frames {lags:?}",
        changes(vals).len()
    )
}

async fn mkcol(app: &Router, body: Value) {
    let (s, v) = call(app, "POST", "/api/collections", Some(ADMIN), Some(body)).await;
    assert_eq!(s, StatusCode::OK, "create collection: {v}");
}

async fn create(app: &Router, col: &str, title: &str) -> Value {
    let (s, v) = call(
        app,
        "POST",
        &format!("/api/collections/{col}/records"),
        Some(ADMIN),
        Some(json!({ "title": title })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "create in {col}: {v}");
    v
}

/// Publish `n` cheap records into `col` as admin, in `/api/batch` chunks — one HTTP
/// round-trip per 50 records instead of per record, and `batch` broadcasts all of a
/// chunk's events after its commit, still inside the handler.
async fn publish(app: &Router, col: &str, n: usize) {
    let mut done = 0;
    while done < n {
        let take = BATCH.min(n - done);
        let reqs: Vec<Value> = (done..done + take)
            .map(|i| {
                json!({
                    "method": "POST",
                    "url": format!("/api/collections/{col}/records"),
                    "body": { "title": format!("e{i}") }
                })
            })
            .collect();
        let (s, v) = call(
            app,
            "POST",
            "/api/batch",
            Some(ADMIN),
            Some(json!({ "requests": reqs })),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "batch publish into {col}: {v}");
        done += take;
    }
}

async fn seed(app: &Router, name: &str) {
    mkcol(
        app,
        json!({"name": name, "schema": [{"name": "title", "type": "text"}]}),
    )
    .await;
}

// ---------------------------------------------------------------------------
// 1. A subscriber that is overrun MUST be told, and told how much it missed.
//    The accounting is exact: every published event is either delivered or
//    counted in a lag frame. Nothing may vanish silently — that is the bug.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn overrun_subscriber_is_told_how_many_events_it_missed() {
    let app = app();
    seed(&app, "posts").await;

    let mut body = sse(&app, "/api/realtime", Some(ADMIN)).await;

    // every write happens before the first read, so the receiver is parked at 0
    publish(&app, "posts", PUBLISHED).await;

    let vals = drain(&mut body).await;
    let lags: Vec<u64> = vals.iter().filter_map(lag_of).collect();
    let evs = changes(&vals);

    assert_eq!(
        lags.len(),
        1,
        "{PUBLISHED} events into a {CAP}-slot channel must produce exactly one \
         `{{\"lagged\": n}}` frame; got {}",
        census(&vals)
    );
    let missed = lags[0];
    assert!(
        missed >= 1,
        "a lag frame must report a positive count, got {missed}"
    );
    assert_eq!(
        missed as usize + evs.len(),
        PUBLISHED,
        "every published event must be either delivered or counted as missed: \
         {missed} reported missed + {} delivered != {PUBLISHED} published ({})",
        evs.len(),
        census(&vals)
    );

    // the notification precedes the events that followed the hole, so a client can
    // refetch before it starts applying the post-gap deltas
    let lag_at = vals.iter().position(|v| lag_of(v).is_some()).unwrap();
    let first_change = vals
        .iter()
        .position(|v| v.get("clientId").is_none() && lag_of(v).is_none());
    if let Some(first_change) = first_change {
        assert!(
            lag_at < first_change,
            "the lag frame must arrive before the events that follow the gap ({})",
            census(&vals)
        );
    }

    // and it must be a notification, not a payload: a count, never the missed rows
    let frame = &vals[lag_at];
    assert!(
        frame.get("record").is_none() && frame.get("topic").is_none(),
        "a lag frame carries the count only, never record data: {frame}"
    );
}

// ---------------------------------------------------------------------------
// 2. A lag must not kill the subscription: after the notification the stream keeps
//    delivering, and a caught-up subscriber gets no second lag frame.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn stream_continues_after_a_lag() {
    let app = app();
    seed(&app, "posts").await;

    let mut body = sse(&app, "/api/realtime", Some(ADMIN)).await;
    publish(&app, "posts", PUBLISHED).await;

    let first = drain(&mut body).await;
    assert_eq!(
        first.iter().filter_map(lag_of).count(),
        1,
        "expected one lag frame in the overrun drain, got {}",
        census(&first)
    );

    // ...the subscriber is caught up now; a fresh event must still arrive
    create(&app, "posts", "after-the-gap").await;

    let second = drain(&mut body).await;
    assert_eq!(
        summary(&changes(&second)),
        vec!["create/posts/after-the-gap".to_string()],
        "a lag must not end the subscription ({})",
        census(&second)
    );
    assert!(
        second.iter().filter_map(lag_of).next().is_none(),
        "a caught-up subscriber must not be told it lagged again ({})",
        census(&second)
    );
}

// ---------------------------------------------------------------------------
// 3. SECURITY: the lag notification must not become a leak. A guest overrun by
//    events from an admin-only collection may learn the COUNT and nothing else —
//    no ids, no titles, no topic names. Rule gating still applies after the lag,
//    proven by a permitted control event issued afterwards.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn lagged_subscriber_is_still_rule_gated() {
    let app = app();
    seed(&app, "posts").await;
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

    // overrun the guest purely with events it was never entitled to
    publish(&app, "secrets", PUBLISHED).await;

    let vals = drain(&mut guest).await;
    let raw = format!("{:?}", vals);
    assert!(
        !raw.contains("secrets") && !raw.contains("\"e0\"") && !raw.contains("e99"),
        "a lagged guest was shown data from an admin-only collection: {raw}"
    );
    assert!(
        changes(&vals).is_empty(),
        "a lagged guest must receive no gated events at all, got {:?}",
        summary(&changes(&vals))
    );
    assert_eq!(
        vals.iter().filter_map(lag_of).count(),
        1,
        "the guest was overrun and must still be told so — the count is not secret ({})",
        census(&vals)
    );

    // ...and the subscription is intact and still gated afterwards
    create(&app, "posts", "control").await;
    let after = drain(&mut guest).await;
    assert_eq!(
        summary(&changes(&after)),
        vec!["create/posts/control".to_string()],
        "the guest must still receive permitted events after a lag ({})",
        census(&after)
    );
}

// ---------------------------------------------------------------------------
// 4. REGRESSION GUARD: a subscriber that keeps up never sees a lag frame. Passes
//    today and must keep passing — the fix must not cry wolf.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn subscriber_that_keeps_up_never_sees_a_lag_frame() {
    let app = app();
    seed(&app, "posts").await;

    let mut body = sse(&app, "/api/realtime", Some(ADMIN)).await;

    // well under CAP per round, and drained every round
    for round in 0..4 {
        publish(&app, "posts", 5).await;
        let vals = drain(&mut body).await;
        assert!(
            vals.iter().filter_map(lag_of).next().is_none(),
            "round {round}: a subscriber that keeps up must never be told it lagged ({})",
            census(&vals)
        );
        assert_eq!(
            changes(&vals).len(),
            5,
            "round {round}: every event must arrive ({})",
            census(&vals)
        );
    }
}
