# Spec: Config, CORS, request log, graceful shutdown

Scope: env config (`RB_PORT`, `RB_DIR`), permissive CORS, one-line request log
to stdout, ctrl-c graceful shutdown. Nothing else — no TLS, no bind-address
knob, no log levels, no log files. All changes live in `src/main.rs` plus one
feature flag in `Cargo.toml`. No new endpoints.

## 1. Cargo.toml

`tokio::signal::ctrl_c` needs the `signal` feature. One-line change, no new crates:

```toml
tokio = { version = "1", features = ["rt-multi-thread", "macros", "signal"] }
```

CORS is hand-rolled (~20 lines, below) — do NOT add tower-http; a new
dependency loses to a small middleware fn.

## 2. Env config (main() only)

| Var            | Default     | Meaning                                        |
|----------------|-------------|------------------------------------------------|
| `RB_PORT`      | `8090`      | TCP port, bound on `127.0.0.1`                 |
| `RB_DIR`       | `./rb_data` | Data dir: holds `data.db` (and file storage when specs/files.md lands) |
| `RB_ADMIN_TOKEN` | random uuid (printed) | already exists — unchanged        |
| `RB_JWT_SECRET`  | persisted in `_params`  | already exists — unchanged        |

Add a helper next to `main()` so it is unit-testable (env parsing is a trust
boundary — a typo'd port must fail loudly, not silently become 8090):

```rust
fn env_config() -> (u16, std::path::PathBuf) {
    let port = match std::env::var("RB_PORT") {
        Ok(v) => v.parse().expect("RB_PORT must be a valid port number"),
        Err(_) => 8090,
    };
    let dir = std::env::var("RB_DIR").unwrap_or_else(|_| "rb_data".into());
    (port, dir.into())
}
```

`main()` changes to:

```rust
let (port, dir) = env_config();
std::fs::create_dir_all(&dir).expect("create data dir");
let conn = Connection::open(dir.join("data.db")).expect("open db");
// ... admin_token as today ...
println!("rockbase on http://127.0.0.1:{port}");
let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await.expect("bind");
```

When specs/files.md is implemented (it adds a `data_dir` param to
`build_app`), pass this same `dir` there. Until then, `dir` is used only in
`main()` — `build_app` signature does not change in this spec.

## 3. CORS + request log: one middleware

One `async fn` handles both (they wrap every request identically; two layers
would be more lines for no gain). Place it near `health()`:

```rust
// ponytail: permissive CORS (allow *), split into per-origin config if anyone needs credentials.
async fn cors_and_log(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    use axum::response::IntoResponse;
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start = std::time::Instant::now();
    let mut resp = if method == axum::http::Method::OPTIONS {
        // preflight: short-circuit so unregistered OPTIONS doesn't 405
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(req).await
    };
    let h = resp.headers_mut();
    let hv = axum::http::HeaderValue::from_static;
    h.insert("access-control-allow-origin", hv("*"));
    h.insert("access-control-allow-methods", hv("GET, POST, PATCH, DELETE, OPTIONS"));
    h.insert("access-control-allow-headers", hv("Authorization, Content-Type"));
    println!("{method} {path} {} {}ms", resp.status().as_u16(), start.elapsed().as_millis());
    resp
}
```

Wire it in `build_app`, after the routes, before `.with_state(app)`:

```rust
.route("/api/realtime", get(realtime))
.layer(axum::middleware::from_fn(cors_and_log))
.with_state(app)
```

Rules baked in — do not lose them:
- Headers go on EVERY response: success, 4xx error bodies, and the router's
  default 404 fallback (the layer wraps all of them). Browsers hide error
  bodies from JS without them.
- OPTIONS short-circuits before routing → 204 empty body for any path,
  including paths with no registered OPTIONS handler.
- Log line is exactly `METHOD /path STATUS Nms`, e.g.
  `GET /api/health 200 0ms`. `println!` to stdout; no timestamps (process
  supervisors add their own), no query string, no new deps.
- Method and path are cloned before `next.run` consumes the request.

## 4. Graceful shutdown

In `main()`, replace the serve line:

```rust
axum::serve(listener, router)
    .with_graceful_shutdown(async {
        tokio::signal::ctrl_c().await.expect("install ctrl-c handler");
        println!("shutting down");
    })
    .await
    .expect("serve");
```

That is the whole feature: on SIGINT axum stops accepting, lets in-flight
requests finish, then `main` returns 0. Open SSE connections to
`/api/realtime` are long-lived and would stall a fully "graceful" drain —
axum closes idle/streaming connections when the shutdown future resolves and
connections have no grace timeout configured; accept that, no
`serve::Serve::with_graceful_shutdown` timeout knob. No SIGTERM handling
(unix-only code path); add `tokio::signal::unix` if containers need it.

## 5. Edge cases

- `RB_PORT=abc` or `RB_PORT=99999` → panic at startup with the expect message
  (fail loud beats silently serving on the wrong port).
- `RB_DIR=/nonexistent/deep/path` → `create_dir_all` creates it or panics.
- `OPTIONS /anything/at/all` → 204 with CORS headers (never 404/405).
- Env vars are process-global: tests that set them must not run in parallel
  with each other — cover default + override in ONE test (see below).
- Tests print log lines; `cargo test` captures stdout, harmless.

## 6. Acceptance tests

Add to `mod tests` in `src/main.rs`. The `call` helper drops headers, so CORS
tests build a `Request` and use `app.clone().oneshot(req)` directly, asserting
on `resp.headers()` (same pattern as specs/db.md).

1. `OPTIONS /api/collections/posts/records` (no auth) → 204, empty body,
   `access-control-allow-origin: *`,
   `access-control-allow-methods` contains `PATCH`,
   `access-control-allow-headers` contains `Authorization`.
2. `GET /api/health` → 200 AND response carries `access-control-allow-origin: *`.
3. `GET /api/collections` with no auth → 401 AND still carries
   `access-control-allow-origin: *` (errors get CORS too).
4. `env_config()` in one test: with `RB_PORT`/`RB_DIR` unset (call
   `std::env::remove_var` first) returns `(8090, "rb_data")`; then
   `set_var("RB_PORT", "9999")`, `set_var("RB_DIR", "/tmp/rbx")` returns
   `(9999, "/tmp/rbx")`; `remove_var` both at the end.
5. `OPTIONS /no/such/route` → 204 (preflight beats the 404 fallback).
6. Existing `full_flow` test stays green, untouched.

Manual check (not automated — it would test axum, not us): `RB_PORT=9091
cargo run`, confirm the printed URL and one log line per curl request, hit
ctrl-c, confirm "shutting down" prints and exit code 0.

Done when: all of the above pass under `cargo test` in the crate root.
