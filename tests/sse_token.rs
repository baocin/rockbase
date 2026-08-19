// SSE subscription auth via `?token=` — TDD red phase.
//
// Why this exists: browser `EventSource` cannot set request headers, so every
// real browser subscription to /api/realtime today connects as a GUEST and only
// ever sees guest-visible events (the admin UI's live feed is literally labelled
// "guest view" because of it). The fix is to accept the same credential as a
// query parameter — without turning a credential-in-a-URL into a general-purpose
// auth mechanism, because URLs leak into logs, history and Referer headers.
//
// Harness is a copy of tests/realtime.rs: tower::ServiceExt::oneshot against
// `rockbase::build_app`. SSE bodies never end, so every read is bounded by a
// `tokio::time::timeout` and no test ever reads a body to completion. Absence
// assertions are always followed by a PERMITTED control event — broadcast
// preserves order, so a slow machine fails the test instead of false-passing.
//
// PRECEDENCE PINNED HERE: if an `Authorization` header is present at all, it
// alone decides the identity and `?token=` is ignored — even when the header is
// garbage (see `bad_header_ignores_valid_query_token`). The header is the
// stronger channel: it is not logged, not stored in history, and never travels
// in a Referer. Query-param auth is a browser-only fallback for the one client
// that cannot send a header, so it must never be able to override, or silently
// upgrade, a deliberate header credential.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tokio::time::timeout;
use tower::ServiceExt;

use rockbase::build_app;

const ADMIN_TOKEN: &str = "testtoken";
const ADMIN: &str = "Admin testtoken";
const PW: &str = "clubrock1";

/// Silence window that ends a drain — same reasoning as tests/realtime.rs: the
/// broadcast `send` is synchronous inside the write handler, so the message is
/// already queued on every live receiver by the time the write's oneshot
/// resolves. 300ms is ~3 orders of magnitude of slack.
const QUIET_MS: u64 = 300;

fn app() -> Router {
    std::env::set_var("RB_JWT_SECRET", "testsecret");
    build_app(":memory:", ADMIN_TOKEN.into())
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
/// channel by the time this resolves, so later writes are guaranteed to be seen.
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
/// never block longer than QUIET_MS past the last frame.
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

/// Seed a user through the admin bypass and log in. Returns (record id, raw JWT).
/// The raw JWT is what goes in `?token=`; `Bearer {jwt}` is what goes in a header.
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
    (id, v["token"].as_str().unwrap().to_string())
}

/// `posts` owned per-user, plus a public `feed` used as the ordering control.
async fn seed_owned(app: &Router) {
    mkcol(
        app,
        json!({
            "name": "posts",
            "schema": [{"name": "title", "type": "text"}, {"name": "owner", "type": "text"}],
            "listRule": "owner = @request.auth.id",
            "viewRule": "owner = @request.auth.id"
        }),
    )
    .await;
    mkcol(
        app,
        json!({"name": "feed", "schema": [{"name": "title", "type": "text"}]}),
    )
    .await;
}

/// public `posts` + admin-only `secrets` (NULL list/view rules).
async fn seed_public_and_secret(app: &Router) {
    mkcol(
        app,
        json!({"name": "posts", "schema": [{"name": "title", "type": "text"}]}),
    )
    .await;
    mkcol(
        app,
        json!({
            "name": "secrets",
            "schema": [{"name": "title", "type": "text"}],
            "listRule": null,
            "viewRule": null
        }),
    )
    .await;
}

// ---------------------------------------------------------------------------
// 1. `?token=<jwt>` must authenticate a subscription exactly like
//    `Authorization: Bearer <jwt>`. Two subscribers on one app, one of each
//    flavour, must observe byte-identical event streams.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn query_token_matches_bearer_header() {
    let app = app();
    seed_owned(&app).await;
    let (alice_id, alice) = user(&app, "alice@cave.dev").await;
    let (bob_id, _bob) = user(&app, "bob@cave.dev").await;

    let mut by_header = sse(&app, "/api/realtime", Some(&format!("Bearer {alice}"))).await;
    let mut by_query = sse(&app, &format!("/api/realtime?token={alice}"), None).await;

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
    create(&app, "feed", Some(ADMIN), json!({"title": "public"})).await;

    let want = summary(&changes(drain(&mut by_header).await));
    let got = summary(&changes(drain(&mut by_query).await));

    assert_eq!(
        want,
        vec![
            "create/posts/alices".to_string(),
            "create/feed/public".to_string()
        ],
        "sanity: the header subscriber's own baseline"
    );
    assert_eq!(
        got, want,
        "?token= must deliver exactly what Bearer delivers (header saw {want:?}, query saw {got:?})"
    );
}

// ---------------------------------------------------------------------------
// 2. `?token=<admin token>` must authenticate exactly like `Authorization:
//    Admin <token>` — including the rule bypass on an admin-only collection.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn query_admin_token_matches_admin_header() {
    let app = app();
    seed_public_and_secret(&app).await;

    let mut by_header = sse(&app, "/api/realtime", Some(ADMIN)).await;
    let mut by_query = sse(&app, &format!("/api/realtime?token={ADMIN_TOKEN}"), None).await;

    create(&app, "secrets", Some(ADMIN), json!({"title": "nuclear"})).await;
    create(&app, "posts", Some(ADMIN), json!({"title": "public"})).await;

    let want = summary(&changes(drain(&mut by_header).await));
    let got = summary(&changes(drain(&mut by_query).await));

    assert_eq!(
        want,
        vec![
            "create/secrets/nuclear".to_string(),
            "create/posts/public".to_string()
        ],
        "sanity: the Admin-header subscriber's own baseline"
    );
    assert_eq!(
        got, want,
        "?token=<admin token> must equal `Admin <token>` (header saw {want:?}, query saw {got:?})"
    );
}

// ---------------------------------------------------------------------------
// 3. `?token=` composes with `?topics=` — adding the credential must not break
//    the existing query parsing, and the topic filter still applies on top.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn query_token_composes_with_topics_filter() {
    let app = app();
    seed_owned(&app).await;
    let (alice_id, alice) = user(&app, "alice@cave.dev").await;

    let mut sub = sse(
        &app,
        &format!("/api/realtime?topics=posts&token={alice}"),
        None,
    )
    .await;

    create(&app, "feed", Some(ADMIN), json!({"title": "filtered-out"})).await;
    create(
        &app,
        "posts",
        Some(ADMIN),
        json!({"title": "alices", "owner": alice_id}),
    )
    .await;

    let evs = changes(drain(&mut sub).await);
    assert_eq!(
        summary(&evs),
        vec!["create/posts/alices".to_string()],
        "topics filter and ?token= must both apply"
    );
}

// ---------------------------------------------------------------------------
// 4. SECURITY: rule gating is unchanged for a ?token= subscriber. Alice must not
//    receive events for records her view rule hides, nor for an admin-only
//    collection. Both absences are proven by a permitted event issued *after*
//    them — broadcast preserves order.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn query_token_subscriber_is_still_rule_gated() {
    let app = app();
    seed_owned(&app).await;
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
    let (alice_id, alice) = user(&app, "alice@cave.dev").await;
    let (bob_id, _bob) = user(&app, "bob@cave.dev").await;

    let mut sub = sse(&app, &format!("/api/realtime?token={alice}"), None).await;

    create(
        &app,
        "posts",
        Some(ADMIN),
        json!({"title": "bobs", "owner": bob_id}),
    )
    .await;
    create(&app, "secrets", Some(ADMIN), json!({"title": "nuclear"})).await;
    create(
        &app,
        "posts",
        Some(ADMIN),
        json!({"title": "alices", "owner": alice_id}),
    )
    .await;

    let evs = changes(drain(&mut sub).await);
    assert!(
        !evs.iter().any(|e| e["record"]["title"] == "bobs"
            || e["topic"] == "secrets"
            || e["record"]["title"] == "nuclear"),
        "?token= subscriber leaked a record her rules hide: {:?}",
        summary(&evs)
    );
    assert_eq!(
        summary(&evs),
        vec!["create/posts/alices".to_string()],
        "...and the permitted event must still arrive, so the absences above are real"
    );
}

// ---------------------------------------------------------------------------
// 5. SECURITY: a bad `?token=` fails CLOSED — guest access, not a 500 and not
//    elevated access. Covers garbage, empty, a wrong-shaped JWT, a tampered
//    signature, and a token whose user record was deleted.
//
//    (An expired-but-correctly-signed JWT cannot be minted here: `jsonwebtoken`
//    is a normal dependency, not a dev-dependency, so integration tests cannot
//    sign one and Cargo.toml is frozen. The tampered-signature and deleted-user
//    cases exercise the same fail-closed branch of `who`.)
// ---------------------------------------------------------------------------
#[tokio::test]
async fn invalid_query_token_is_guest_not_error() {
    let app = app();
    seed_public_and_secret(&app).await;
    let (_alice_id, alice) = user(&app, "alice@cave.dev").await;

    // a real, valid token whose user record no longer exists
    let (ghost_id, ghost) = user(&app, "ghost@cave.dev").await;
    let (s, v) = call(
        &app,
        "DELETE",
        &format!("/api/collections/users/records/{ghost_id}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "delete ghost: {v}");

    let tampered = format!("{alice}x");
    let bad: Vec<String> = vec![
        "garbage".into(),
        String::new(),
        "a.b.c".into(),
        format!("Bearer%20{alice}"), // the scheme belongs in the header, not the value
        tampered,
        ghost,
        format!("{ADMIN_TOKEN}x"), // near-miss on the admin token
    ];

    for t in &bad {
        let mut sub = sse(&app, &format!("/api/realtime?token={t}"), None).await;

        create(&app, "secrets", Some(ADMIN), json!({"title": "nuclear"})).await;
        create(&app, "posts", Some(ADMIN), json!({"title": "public"})).await;

        let evs = changes(drain(&mut sub).await);
        assert!(
            !evs.iter()
                .any(|e| e["topic"] == "secrets" || e["record"]["title"] == "nuclear"),
            "token={t:?} must not grant elevated access, got {:?}",
            summary(&evs)
        );
        assert_eq!(
            summary(&evs),
            vec!["create/posts/public".to_string()],
            "token={t:?} must degrade to guest — still subscribed, still gets public events"
        );
    }
}

// ---------------------------------------------------------------------------
// 6. The `Authorization` header still works and WINS when both are present.
//    Alice's header + Bob's query token => Alice's view, never Bob's.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn header_takes_precedence_over_query_token() {
    let app = app();
    seed_owned(&app).await;
    let (alice_id, alice) = user(&app, "alice@cave.dev").await;
    let (bob_id, bob) = user(&app, "bob@cave.dev").await;

    let mut sub = sse(
        &app,
        &format!("/api/realtime?token={bob}"),
        Some(&format!("Bearer {alice}")),
    )
    .await;

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
        "the query token must not override the header identity: {:?}",
        summary(&evs)
    );
    assert_eq!(
        summary(&evs),
        vec!["create/posts/alices".to_string()],
        "the header identity decides, and its own event still arrives"
    );
}

// ---------------------------------------------------------------------------
// 7. Precedence, the sharp edge: an `Authorization` header that is PRESENT but
//    invalid is still the deciding credential — the request is a guest, and the
//    valid `?token=` alongside it does NOT silently upgrade it. A caller that
//    sent a header meant to authenticate with a header; a query param appended
//    to that URL (by a redirect, a copy-paste, an injected link) must never be
//    able to change who the request is.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn bad_header_ignores_valid_query_token() {
    let app = app();
    seed_owned(&app).await;
    let (alice_id, alice) = user(&app, "alice@cave.dev").await;

    let mut sub = sse(
        &app,
        &format!("/api/realtime?token={alice}"),
        Some("Bearer not-a-real-token"),
    )
    .await;

    create(
        &app,
        "posts",
        Some(ADMIN),
        json!({"title": "alices", "owner": alice_id}),
    )
    .await;
    create(&app, "feed", Some(ADMIN), json!({"title": "public"})).await;

    let evs = changes(drain(&mut sub).await);
    assert!(
        !evs.iter().any(|e| e["record"]["title"] == "alices"),
        "a present Authorization header must decide alone; ?token= must not upgrade it: {:?}",
        summary(&evs)
    );
    assert_eq!(
        summary(&evs),
        vec!["create/feed/public".to_string()],
        "...and the guest-visible control event proves the absence above is filtering"
    );
}

// ---------------------------------------------------------------------------
// 8. SECURITY: `?token=` is an SSE-only affordance. It must NOT become a
//    general-purpose auth mechanism — URLs end up in access logs, browser
//    history, bookmarks and Referer headers, so a credential in one must buy as
//    little as possible.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn query_token_does_not_authenticate_the_rest_api() {
    let app = app();
    seed_owned(&app).await;
    let (alice_id, alice) = user(&app, "alice@cave.dev").await;
    create(
        &app,
        "posts",
        Some(ADMIN),
        json!({"title": "alices", "owner": alice_id}),
    )
    .await;

    // admin token in the URL buys nothing on an admin endpoint
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections?token={ADMIN_TOKEN}"),
        None,
        None,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "admin token in a URL must not authenticate: {v}"
    );

    // ...nor on a collection write
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/collections?token={ADMIN_TOKEN}"),
        None,
        Some(json!({"name": "sneaky", "schema": []})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "admin token in a URL must not create collections: {v}"
    );

    // ...and a user token in the URL is still a guest on the records API
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/collections/posts/records?token={alice}"),
        None,
        None,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "guest list of a rule-gated collection: {v}"
    );
    assert_eq!(
        v["items"],
        json!([]),
        "?token= must not authenticate the records API — alice's rows leaked: {v}"
    );
}

// ---------------------------------------------------------------------------
// 9. CREDENTIAL-IN-URL LEAK: `cors_and_log` prints one line per request. If the
//    token ever reaches that line it is written to stdout, log files and log
//    aggregators verbatim. The logged line must redact it.
//
//    Process-level, because the log goes to the real process stdout: same
//    child-process technique as tests/cli.rs (`Command` + piped stdout + a
//    reader thread), which is also the only way to keep `cargo test`'s parallel
//    threads out of each other's environment.
// ---------------------------------------------------------------------------

const BIN: &str = env!("CARGO_BIN_EXE_rockbase");
const BOOT: Duration = Duration::from_secs(20);

struct Server {
    proc: std::process::Child,
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.proc.kill();
        let _ = self.proc.wait();
    }
}

impl Server {
    fn wait_for(&mut self, what: &str, pred: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + BOOT;
        if let Some(l) = self.seen.iter().find(|l| pred(l)) {
            return l.clone();
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                panic!(
                    "timed out waiting for {what}; stdout so far: {:?}",
                    self.seen
                );
            }
            match self.lines.recv_timeout(left) {
                Ok(l) => {
                    self.seen.push(l.clone());
                    if pred(&l) {
                        return l;
                    }
                }
                Err(_) => panic!("server stdout ended before {what}; got {:?}", self.seen),
            }
        }
    }
}

fn spawn(dir: &Path, env: &[(&str, &str)]) -> Server {
    std::fs::create_dir_all(dir).unwrap();
    let mut cmd = Command::new(BIN);
    cmd.current_dir(dir)
        .env_remove("RB_PORT")
        .env_remove("RB_DIR")
        .env("RB_ADMIN_TOKEN", ADMIN_TOKEN)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    let mut proc = cmd.spawn().expect("spawn rockbase binary");
    let out = proc.stdout.take().unwrap();
    let (tx, lines) = mpsc::channel();
    std::thread::spawn(move || {
        for l in BufReader::new(out).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                break;
            }
        }
    });
    Server {
        proc,
        lines,
        seen: Vec::new(),
    }
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rockbase_ssetoken_{}_{name}",
        uuid::Uuid::new_v4().simple()
    ))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn connect(port: u16) -> std::net::TcpStream {
    let deadline = Instant::now() + BOOT;
    loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => return s,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("could not connect to the server on {port}: {e}"),
        }
    }
}

#[test]
fn request_log_redacts_the_query_token() {
    // distinctive enough that a substring hit is unambiguous
    const SECRET: &str = "eyJleUJsZUEK.leaked-credential-must-not-be-logged.sIgNaTuRe";

    let dir = scratch("log");
    let port = free_port();
    let data = dir.join("rb_data");
    let mut srv = spawn(
        &dir,
        &[
            ("RB_PORT", &port.to_string()),
            ("RB_DIR", data.to_str().unwrap()),
        ],
    );
    srv.wait_for("startup banner", |l| l.contains("rockbase on"));

    // 1) an ordinary endpoint carrying the credential: terminates, so it can be
    //    read to completion. Hand-rolled HTTP/1.1 — no http client in dev-deps.
    let mut stream = connect(port);
    stream
        .write_all(
            format!(
                "GET /api/health?token={SECRET} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
    srv.wait_for("health request log line", |l| {
        l.starts_with("GET /api/health")
    });

    // 2) the real case: the SSE subscription. Its body NEVER ends, so this
    //    request is written and never read — the log line is emitted as soon as
    //    the handler returns the streaming response.
    let mut sse_stream = connect(port);
    sse_stream
        .write_all(
            format!("GET /api/realtime?token={SECRET} HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    srv.wait_for("realtime request log line", |l| {
        l.starts_with("GET /api/realtime")
    });
    let _ = sse_stream.shutdown(std::net::Shutdown::Both);

    for line in &srv.seen {
        assert!(
            !line.contains(SECRET),
            "the request log leaked the credential verbatim: {line}"
        );
        if let Some(i) = line.find("token=") {
            assert!(
                line[i..].starts_with("token=***"),
                "a logged token must be redacted as `token=***`: {line}"
            );
        }
    }

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}
