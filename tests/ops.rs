// Operational hardening (specs: ops). Three things a deployed rockbase needs and
// does not have today:
//
//   1. /api/health that actually asks the database whether it is alive.
//   2. A CORS allowlist, so a public deployment is not `Access-Control-Allow-Origin: *`.
//   3. Graceful shutdown on SIGTERM/SIGINT, because that is what Docker and systemd send.
//
// Style follows the existing suite: in-process `build_app` + `tower::ServiceExt::oneshot`
// for anything that is pure request/response (tests/basic.rs), and the real binary as a
// child process with per-child env vars (tests/cli.rs) for anything process-shaped —
// env-driven config and signal handling. `Command::env` is per-child, so these stay safe
// under `cargo test`'s parallel threads; no test here mutates this process's environment.
//
// Every child-process wait is bounded and kills the child on overrun, so a missing
// feature fails the suite instead of hanging it.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

use rockbase::build_app;

const BIN: &str = env!("CARGO_BIN_EXE_rockbase");
const ADMIN: &str = "Admin testtoken";
/// Generous: the first spawn in a run may page the binary in cold.
const BOOT: Duration = Duration::from_secs(20);
/// A graceful shutdown of an idle server is a few milliseconds; 10s is a bug, not slowness.
const EXIT_WAIT: Duration = Duration::from_secs(10);

// ------------------------------------------------------------- in-process

fn app() -> Router {
    build_app(":memory:", "testtoken".into())
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    hdrs: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in hdrs {
        req = req.header(*k, *v);
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
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes.to_vec())
}

async fn health_json(app: &Router) -> (StatusCode, Value) {
    let (s, _, body) = call(app, "GET", "/api/health", &[], None).await;
    let v = serde_json::from_slice(&body).unwrap_or_else(|e| {
        panic!(
            "health body is not JSON ({e}): {:?}",
            String::from_utf8_lossy(&body)
        )
    });
    (s, v)
}

/// The SQLite version the bundled library reports. Identical for every connection in
/// this process, so a throwaway one tells us what the server's connection must answer.
fn sqlite_version() -> String {
    Connection::open_in_memory()
        .unwrap()
        .query_row("SELECT sqlite_version()", [], |r| r.get(0))
        .unwrap()
}

// --------------------------------------------------------------- health

#[tokio::test]
async fn health_reports_database_state() {
    let (s, v) = health_json(&app()).await;
    assert_eq!(s, StatusCode::OK, "healthy instance must answer 200: {v}");
    assert_eq!(v["status"], "ok", "{v}");
    // A load balancer needs to know the DB is usable, not merely that the process
    // is listening. Today this field does not exist: the handler is a static literal.
    assert_eq!(
        v["db"], "ok",
        "health must report the database it just queried: {v}"
    );
}

#[tokio::test]
async fn health_answer_comes_from_the_database() {
    // The only honest in-process proof that the handler touched the connection: make it
    // report a value that can only be obtained by executing a query on it. A trivial
    // one — `SELECT sqlite_version()` — not a scan. See the report for what this
    // cannot prove (it does not force the query to hit the file).
    let (_, v) = health_json(&app()).await;
    assert_eq!(
        v["sqlite"],
        Value::String(sqlite_version()),
        "health must run a real query and report its result, not a compile-time literal: {v}"
    );
}

#[tokio::test]
async fn health_does_not_scan_tables() {
    let app = app();
    let before = health_json(&app).await.1;

    let (s, _, _) = call(
        &app,
        "POST",
        "/api/collections",
        &[("authorization", ADMIN)],
        Some(json!({ "name": "ops_probe", "schema": [{ "name": "n", "type": "number" }] })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "setup: create collection");
    for n in 0..200 {
        let (s, _, _) = call(
            &app,
            "POST",
            "/api/collections/ops_probe/records",
            &[("authorization", ADMIN)],
            Some(json!({ "n": n })),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "setup: insert record {n}");
    }

    let after = health_json(&app).await.1;
    // Row counts in the payload mean the check walks user data, and a health probe
    // that scales with table size is a health probe that times out under load.
    assert_eq!(
        before, after,
        "health must be O(1): its body changed after 200 inserts"
    );
}

// ----------------------------------------------------------------- CORS

#[tokio::test]
async fn cors_default_stays_wide_open() {
    // No RB_CORS_ORIGINS set => unchanged behaviour, `*` for everyone. Local dev and
    // tests/cli.rs both depend on this; the allowlist must be opt-in.
    let app = app();
    let (s, h, _) = call(
        &app,
        "GET",
        "/api/health",
        &[("origin", "https://anything.example.com")],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        h.get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap()),
        Some("*"),
        "default CORS must remain `*`: {h:?}"
    );

    let (s, h, _) = call(&app, "OPTIONS", "/api/collections/posts/records", &[], None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(
        h.get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap()),
        Some("*"),
        "default preflight must remain `*`: {h:?}"
    );
}

#[test]
fn cors_allowlist_from_env() {
    // Driven through the real binary rather than std::env::set_var, so the env var is
    // per-child and cannot race the in-process tests above.
    //
    // Format pinned here: RB_CORS_ORIGINS = comma-separated exact origins, surrounding
    // whitespace ignored. Unset (or empty) = `*`.
    let dir = scratch("cors");
    let port = free_port();
    let mut srv = spawn(
        &dir,
        port,
        &[(
            "RB_CORS_ORIGINS",
            "https://app.example.com, https://admin.example.com",
        )],
    );
    srv.wait_for_banner();

    for allowed in ["https://app.example.com", "https://admin.example.com"] {
        let (st, h, _) = http(port, "GET", "/api/health", &[("Origin", allowed)]);
        assert_eq!(st, 200, "{allowed}");
        assert_eq!(
            h.get("access-control-allow-origin").map(String::as_str),
            Some(allowed),
            "an allowlisted origin must be echoed back, never `*`: {h:?}"
        );
        // Without this, a shared cache can serve one origin's allow header to another.
        assert!(
            h.get("vary").map(|v| v.to_lowercase().contains("origin")) == Some(true),
            "an origin-dependent response needs `Vary: Origin`: {h:?}"
        );
    }

    let (st, h, _) = http(
        port,
        "GET",
        "/api/health",
        &[("Origin", "https://evil.example.com")],
    );
    assert_eq!(st, 200, "the server still serves it; the browser blocks it");
    assert_eq!(
        h.get("access-control-allow-origin"),
        None,
        "a disallowed origin must get no allow-origin header at all: {h:?}"
    );

    // Preflight keeps its 204 short-circuit either way, only the origin header differs.
    let (st, h, _) = http(
        port,
        "OPTIONS",
        "/api/collections/posts/records",
        &[("Origin", "https://app.example.com")],
    );
    assert_eq!(st, 204, "preflight is still 204: {h:?}");
    assert_eq!(
        h.get("access-control-allow-origin").map(String::as_str),
        Some("https://app.example.com"),
        "{h:?}"
    );

    let (st, h, _) = http(
        port,
        "OPTIONS",
        "/api/collections/posts/records",
        &[("Origin", "https://evil.example.com")],
    );
    assert_eq!(
        st, 204,
        "preflight is still 204 for a rejected origin: {h:?}"
    );
    assert_eq!(
        h.get("access-control-allow-origin"),
        None,
        "rejected preflight must not carry an allow-origin header: {h:?}"
    );

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn cors_default_in_the_real_binary() {
    // Same guarantee as cors_default_stays_wide_open, but through the binary: an absent
    // RB_CORS_ORIGINS must not turn into an empty allowlist that rejects everything.
    let dir = scratch("corsdefault");
    let port = free_port();
    let mut srv = spawn(&dir, port, &[]);
    srv.wait_for_banner();

    let (st, h, _) = http(
        port,
        "GET",
        "/api/health",
        &[("Origin", "https://anything.example.com")],
    );
    assert_eq!(st, 200);
    assert_eq!(
        h.get("access-control-allow-origin").map(String::as_str),
        Some("*"),
        "unset RB_CORS_ORIGINS must keep the wide-open default: {h:?}"
    );

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------- shutdown

#[test]
fn sigterm_shuts_down_cleanly() {
    let dir = scratch("sigterm");
    let port = free_port();
    let mut srv = spawn(&dir, port, &[]);
    srv.wait_for_banner();

    signal(&srv.proc, "TERM");
    let st = srv.wait_exit(EXIT_WAIT);
    // Unhandled SIGTERM => killed by signal => code() is None. Docker sends SIGTERM on
    // every `stop`/rolling deploy, so today every deploy looks like a crash.
    assert_eq!(
        st.code(),
        Some(0),
        "SIGTERM must be handled and exit 0, got {st}"
    );
    let out = srv.drain();
    assert!(
        out.iter().any(|l| l.to_lowercase().contains("shut")),
        "shutdown must be logged so an operator can tell a clean stop from a kill: {out:?}"
    );

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sigint_shuts_down_cleanly() {
    // Ctrl-C in a terminal. Same path as SIGTERM, and cheap to pin so one is not wired
    // up without the other.
    let dir = scratch("sigint");
    let port = free_port();
    let mut srv = spawn(&dir, port, &[]);
    srv.wait_for_banner();

    signal(&srv.proc, "INT");
    let st = srv.wait_exit(EXIT_WAIT);
    assert_eq!(
        st.code(),
        Some(0),
        "SIGINT must be handled and exit 0, got {st}"
    );

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sigterm_lets_an_inflight_request_finish() {
    // Genuinely in-flight, not a race: `collections_create` takes `Json<Value>` last, so
    // axum parks the handler until the whole body arrives. We send the headers plus half
    // the body, signal, and only then send the rest. There is no window in which the
    // request could already have completed.
    let dir = scratch("inflight");
    let port = free_port();
    let mut srv = spawn(&dir, port, &[]);
    srv.wait_for_banner();

    let body = br#"{"name":"ops_inflight","schema":[]}"#;
    let (head, tail) = body.split_at(12);

    let mut sock = connect(port);
    sock.set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        sock,
        "POST /api/collections HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {ADMIN}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    sock.write_all(head).unwrap();
    sock.flush().unwrap();
    std::thread::sleep(Duration::from_millis(300)); // server is now parked on the body

    signal(&srv.proc, "TERM");
    std::thread::sleep(Duration::from_millis(300));

    // A severed connection makes these fail; that failure is the bug, so do not unwrap.
    let _ = sock.write_all(tail);
    let _ = sock.flush();

    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf); // read timeout bounds this, never hangs
    let resp = String::from_utf8_lossy(&buf).into_owned();
    assert!(
        resp.starts_with("HTTP/1.1 200"),
        "an in-flight request must be allowed to finish across SIGTERM, got {resp:?}"
    );

    let st = srv.wait_exit(EXIT_WAIT);
    assert_eq!(
        st.code(),
        Some(0),
        "the server must exit 0 once the last request drains, got {st}"
    );

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------- child-process harness

/// A running `rockbase` binary plus a channel of its stdout lines. (Same shape as
/// tests/cli.rs — integration test binaries cannot share a module.)
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
    fn wait_for_banner(&mut self) {
        let deadline = Instant::now() + BOOT;
        loop {
            if self.seen.iter().any(|l| l.contains("rockbase on")) {
                return;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                panic!("server never printed its banner; stdout: {:?}", self.seen);
            }
            match self.lines.recv_timeout(left) {
                Ok(l) => self.seen.push(l),
                Err(_) => panic!("server stdout ended before startup; got {:?}", self.seen),
            }
        }
    }

    /// Bounded: SIGKILL and fail rather than let the suite hang.
    fn wait_exit(&mut self, within: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(st) = self.proc.try_wait().unwrap() {
                return st;
            }
            if Instant::now() >= deadline {
                let _ = self.proc.kill();
                let _ = self.proc.wait();
                panic!(
                    "server ignored the signal and was still running after {within:?}; stdout: {:?}",
                    self.seen
                );
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    /// Every stdout line seen so far. Call after the process is gone: the reader thread
    /// is at EOF, so the last recv returns immediately.
    fn drain(&mut self) -> Vec<String> {
        while let Ok(l) = self.lines.recv_timeout(Duration::from_millis(500)) {
            self.seen.push(l);
        }
        self.seen.clone()
    }
}

fn spawn(dir: &Path, port: u16, env: &[(&str, &str)]) -> Server {
    std::fs::create_dir_all(dir).unwrap();
    let mut cmd = Command::new(BIN);
    cmd.current_dir(dir)
        .env_remove("RB_PORT")
        .env_remove("RB_DIR")
        .env_remove("RB_CORS_ORIGINS")
        .env("RB_ADMIN_TOKEN", "testtoken")
        .env("RB_PORT", port.to_string())
        .env("RB_DIR", dir.join("data"))
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

/// `kill(2)` via the system binary: tokio's `signal` feature is off and there is no libc
/// dependency, so this is the only way to deliver a real SIGTERM from here.
fn signal(proc: &std::process::Child, sig: &str) {
    let st = Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(proc.id().to_string())
        .status()
        .expect("run `kill`");
    assert!(st.success(), "kill -{sig} {} failed: {st}", proc.id());
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "rockbase_ops_{}_{name}",
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

fn connect(port: u16) -> TcpStream {
    let deadline = Instant::now() + BOOT;
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => return s,
            Err(e) if Instant::now() >= deadline => panic!("cannot connect on {port}: {e}"),
            Err(_) => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

/// One hand-rolled HTTP/1.1 request — there is no HTTP client in dev-dependencies and
/// Cargo.toml is frozen. Returns (status, lowercased headers, body).
fn http(
    port: u16,
    method: &str,
    path: &str,
    hdrs: &[(&str, &str)],
) -> (u16, HashMap<String, String>, String) {
    let mut sock = connect(port);
    sock.set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let mut req =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    for (k, v) in hdrs {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    sock.write_all(req.as_bytes()).unwrap();
    sock.flush().unwrap();

    let mut buf = Vec::new();
    let _ = sock.read_to_end(&mut buf); // bounded by the read timeout
    let raw = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("{method} {path}: no complete response head, got {raw:?}"));
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|c| c.parse().ok())
        .unwrap_or_else(|| panic!("{method} {path}: bad status line in {head:?}"));
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_lowercase(), v.to_string()))
        .collect();
    (status, headers, body.to_string())
}

// No test drives /api/health to 503. Once the server owns the connection there is no
// honest way from out here to make SQLite fail: deleting or chmod-ing data.db leaves the
// open fd working, and a second connection cannot steal the file because WAL mode keeps a
// shared lock for the connection's lifetime. Pinning the 503 needs a unit test inside the
// crate against a deliberately broken Connection — see the report.
