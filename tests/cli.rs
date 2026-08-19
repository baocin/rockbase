// Integration tests for specs/cli.md: env config, permissive CORS, request log.
//
// CORS is tested through `build_app` with tower::ServiceExt::oneshot (same style
// as tests/basic.rs), asserting on response headers.
//
// Config is tested by running the real binary as a child process instead of
// mutating this process's environment: `Command::env` is per-child, so these
// tests are safe under `cargo test`'s parallel threads. There is no public
// config-parsing fn to call today (see report), and a `mod tests` in src/main.rs
// is not reachable from an integration test.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use tower::ServiceExt;

use rockbase::build_app;

const BIN: &str = env!("CARGO_BIN_EXE_rockbase");
const BOOT: Duration = Duration::from_secs(20);

fn app() -> Router {
    build_app(":memory:", "testtoken".into())
}

/// Send one request through the router and hand back status + headers + body.
async fn raw(
    app: &Router,
    method: &str,
    uri: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes.to_vec())
}

fn header<'a>(h: &'a axum::http::HeaderMap, name: &str) -> &'a str {
    h.get(name)
        .unwrap_or_else(|| panic!("missing header {name}; got {h:?}"))
        .to_str()
        .unwrap()
}

// ---------------------------------------------------------------- CORS

#[tokio::test]
async fn cors_preflight_is_204_with_headers() {
    let app = app();
    let (s, h, body) = raw(&app, "OPTIONS", "/api/collections/posts/records").await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(body.is_empty(), "preflight body should be empty: {body:?}");
    assert_eq!(header(&h, "access-control-allow-origin"), "*");
    assert!(
        header(&h, "access-control-allow-methods").contains("PATCH"),
        "{h:?}"
    );
    assert!(
        header(&h, "access-control-allow-headers").contains("Authorization"),
        "{h:?}"
    );
}

#[tokio::test]
async fn cors_preflight_beats_the_404_fallback() {
    let app = app();
    let (s, h, _) = raw(&app, "OPTIONS", "/no/such/route").await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(header(&h, "access-control-allow-origin"), "*");
}

#[tokio::test]
async fn cors_headers_on_success_and_error_responses() {
    let app = app();

    let (s, h, _) = raw(&app, "GET", "/api/health").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(header(&h, "access-control-allow-origin"), "*");

    // browsers hide error bodies from JS without CORS headers, so 4xx needs them too
    let (s, h, _) = raw(&app, "GET", "/api/collections").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(header(&h, "access-control-allow-origin"), "*");

    // ...and so does the router's own 404 fallback
    let (s, h, _) = raw(&app, "GET", "/no/such/route").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert_eq!(header(&h, "access-control-allow-origin"), "*");
}

// ------------------------------------------------- child-process harness

/// A running `rockbase` binary plus a channel of its stdout lines.
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
    /// Block until a stdout line matches `pred`, or panic after `BOOT`.
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
        .env("RB_ADMIN_TOKEN", "testtoken")
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
        "rockbase_cli_{}_{name}",
        uuid::Uuid::new_v4().simple()
    ))
}

/// A port nothing is listening on right now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// -------------------------------------------------------------- config

#[test]
fn config_defaults_to_8090_and_rb_data() {
    let dir = scratch("defaults");
    let mut srv = spawn(&dir, &[]);
    // the binary prints the URL after creating the data dir, so one wait covers both
    let line = srv.wait_for("startup banner", |l| l.contains("rockbase on"));
    assert!(
        line.contains("http://127.0.0.1:8090"),
        "default port should be 8090: {line}"
    );
    assert!(
        dir.join("rb_data").join("data.db").exists(),
        "default data dir should be ./rb_data"
    );
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_honors_rb_port_and_rb_dir() {
    let dir = scratch("env");
    let port = free_port();
    let data = dir.join("custom").join("nested");
    let mut srv = spawn(
        &dir,
        &[
            ("RB_PORT", &port.to_string()),
            ("RB_DIR", data.to_str().unwrap()),
        ],
    );
    let line = srv.wait_for("startup banner", |l| l.contains("rockbase on"));
    assert!(
        line.contains(&format!("http://127.0.0.1:{port}")),
        "RB_PORT should be honored (wanted {port}): {line}"
    );
    assert!(
        data.join("data.db").exists(),
        "RB_DIR should be created and hold data.db: {}",
        data.display()
    );
    assert!(
        !dir.join("rb_data").exists(),
        "RB_DIR set means no ./rb_data fallback"
    );
    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn config_rejects_invalid_rb_port() {
    // a typo'd port must fail loudly, not silently serve on 8090
    for bad in ["abc", "99999", "-1", ""] {
        let dir = scratch("badport");
        let mut srv = spawn(&dir, &[("RB_PORT", bad)]);
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            match srv.proc.try_wait().unwrap() {
                Some(st) => break Some(st),
                None if Instant::now() >= deadline => break None,
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        };
        let Some(st) = status else {
            panic!("RB_PORT={bad:?} should abort startup, but the server kept running");
        };
        assert!(
            !st.success(),
            "RB_PORT={bad:?} should exit non-zero, got {st}"
        );
        // exited, so stderr is at EOF and this cannot block
        let mut errs = String::new();
        if let Some(mut e) = srv.proc.stderr.take() {
            let _ = e.read_to_string(&mut errs);
        }
        // must die on the port parse, not incidentally on a busy default port
        assert!(
            errs.contains("RB_PORT"),
            "RB_PORT={bad:?} should fail with an RB_PORT message, got: {errs}"
        );
        drop(srv);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// --------------------------------------------------------- request log

#[test]
fn logs_one_line_per_request() {
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

    // hand-rolled HTTP/1.1 GET: no http client in dev-dependencies, and one
    // request is all this needs
    let deadline = Instant::now() + BOOT;
    let mut stream = loop {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => break s,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("could not connect to the server on {port}: {e}"),
        }
    };
    stream
        .write_all(b"GET /api/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut resp = String::new();
    stream.read_to_string(&mut resp).unwrap();
    assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");

    // exact shape: `METHOD /path STATUS Nms`
    let line = srv.wait_for("request log line", |l| l.starts_with("GET /api/health "));
    let parts: Vec<&str> = line.split(' ').collect();
    assert_eq!(
        parts.len(),
        4,
        "log line should be `METHOD /path STATUS Nms`: {line}"
    );
    assert_eq!(parts[2], "200", "{line}");
    let ms = parts[3]
        .strip_suffix("ms")
        .unwrap_or_else(|| panic!("{line}"));
    assert!(ms.parse::<u64>().is_ok(), "{line}");

    drop(srv);
    let _ = std::fs::remove_dir_all(&dir);
}
