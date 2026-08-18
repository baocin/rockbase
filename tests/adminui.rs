// Embedded admin dashboard at `/_/` (specs/adminui.md) — TDD red phase.
// Same harness style as tests/basic.rs: tower oneshot against `build_app`.
//
// Deliberately loose on markup, strict on HTTP behavior: the asset
// (assets/admin.html) does not exist yet, so only the strings the spec itself
// names are asserted, plus the security invariant that no secret is baked in.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::Connection;
use tower::ServiceExt;

use rockbase::build_app;

fn app() -> Router {
    std::env::set_var("RB_JWT_SECRET", "testsecret");
    build_app(Connection::open_in_memory().unwrap(), "testtoken".into())
}

fn app_with(admin_token: &str) -> Router {
    std::env::set_var("RB_JWT_SECRET", "testsecret");
    build_app(Connection::open_in_memory().unwrap(), admin_token.into())
}

/// Raw GET: status, headers, body as a String (the page is UTF-8 HTML).
async fn get(app: &Router, uri: &str, auth: Option<&str>) -> (StatusCode, axum::http::HeaderMap, String) {
    let mut req = Request::builder().method("GET").uri(uri);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let resp = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8_lossy(&bytes).into_owned())
}

fn ctype(h: &axum::http::HeaderMap) -> String {
    h.get("content-type")
        .map(|v| v.to_str().unwrap_or("").to_string())
        .unwrap_or_default()
}

// 1. The page is served with no auth header at all: 200 + text/html.
#[tokio::test]
async fn admin_ui_served() {
    let app = app();
    let (s, h, body) = get(&app, "/_/", None).await;
    assert_eq!(s, StatusCode::OK, "GET /_/ with no auth");
    assert!(
        ctype(&h).starts_with("text/html"),
        "content-type must start with text/html, got {:?}",
        ctype(&h)
    );
    assert!(!body.is_empty(), "admin page body is empty");
    let lower = body.to_lowercase();
    assert!(
        lower.contains("<html") || lower.contains("<!doctype html"),
        "body does not look like an HTML document: {:.200}",
        body
    );
    assert!(lower.contains("<title"), "admin page has no <title>");
}

// 2. `/_`, `/_/`, `/_/index.html` are the same page (axum 0.8 treats them as
//    distinct paths — the spec registers all three rather than redirecting).
#[tokio::test]
async fn admin_ui_three_paths_same_page() {
    let app = app();
    let (s0, h0, b0) = get(&app, "/_/", None).await;
    assert_eq!(s0, StatusCode::OK);

    for uri in ["/_", "/_/index.html"] {
        let (s, h, b) = get(&app, uri, None).await;
        assert_eq!(s, StatusCode::OK, "GET {uri}");
        assert!(
            ctype(&h).starts_with("text/html"),
            "GET {uri} content-type: {:?}",
            ctype(&h)
        );
        assert_eq!(ctype(&h), ctype(&h0), "GET {uri} content-type differs from /_/");
        assert_eq!(b, b0, "GET {uri} body differs from /_/");
    }
}

// 3. The page itself is public — only the API calls it makes need the token.
//    A missing, malformed, or plain wrong Authorization header changes nothing.
#[tokio::test]
async fn admin_ui_needs_no_auth() {
    let app = app();
    let (_, _, expected) = get(&app, "/_/", None).await;

    for auth in [
        None,
        Some("Admin testtoken"),
        Some("Admin totally-wrong-token"),
        Some("Bearer garbage"),
        Some("not-even-a-scheme"),
        Some(""),
    ] {
        let (s, h, b) = get(&app, "/_/", auth).await;
        assert_eq!(s, StatusCode::OK, "GET /_/ with auth {auth:?} must be 200");
        assert!(ctype(&h).starts_with("text/html"), "auth {auth:?}: {:?}", ctype(&h));
        assert_eq!(b, expected, "auth {auth:?} changed the served page");
    }

    // a public static asset must not try to open a session
    let (_, h, _) = get(&app, "/_/", None).await;
    assert!(h.get("set-cookie").is_none(), "admin page must not set cookies");
    assert!(
        h.get("www-authenticate").is_none(),
        "admin page must not challenge for credentials"
    );
}

// 4. SECURITY: nothing secret is baked into the embedded page. The admin token
//    is generated at startup and printed to stdout — it must never reach the HTML.
#[tokio::test]
async fn admin_ui_leaks_no_secrets() {
    let secret_token = "s3cr3t-admin-token-9f2a1c";
    let app = app_with(secret_token);
    let (s, _, body) = get(&app, "/_/", None).await;
    assert_eq!(s, StatusCode::OK);

    for needle in [
        secret_token,
        "testsecret", // RB_JWT_SECRET
        "jwt_secret",
        "password_hash",
        "$2b$", // bcrypt hash prefix
        "BEGIN PRIVATE KEY",
    ] {
        assert!(
            !body.contains(needle),
            "admin page leaks {needle:?} into the served HTML"
        );
    }

    // Strongest form of the same check: the page is a compile-time constant, so
    // two servers with different admin tokens must serve byte-identical HTML.
    let other = app_with("a-completely-different-token-4b7e");
    let (s2, _, body2) = get(&other, "/_/", None).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        body, body2,
        "served HTML varies with the admin token — a secret is being injected"
    );
}

// 5. The cors_and_log middleware wraps the whole router, so it covers `/_/` too.
#[tokio::test]
async fn admin_ui_has_cors_headers() {
    let app = app();
    let (s, h, _) = get(&app, "/_/", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        h.get("access-control-allow-origin").map(|v| v.to_str().unwrap()),
        Some("*"),
        "missing CORS origin header on /_/"
    );
    assert!(
        h.get("access-control-allow-methods").is_some(),
        "missing CORS methods header on /_/"
    );
    assert!(
        h.get("access-control-allow-headers").is_some(),
        "missing CORS headers header on /_/"
    );

    // preflight short-circuits before routing
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/_/")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "OPTIONS /_/ preflight");
    assert_eq!(
        resp.headers().get("access-control-allow-origin").map(|v| v.to_str().unwrap()),
        Some("*")
    );
}

// 6. No wildcard under `/_/`. Spec "Out of scope": serving any other static
//    asset, favicon, or `/_/{path}` wildcard — one HTML file only. So an
//    unknown path falls through to the router's 404, it does not re-serve the page.
#[tokio::test]
async fn admin_ui_no_wildcard_under_underscore() {
    let app = app();
    for uri in [
        "/_/favicon.ico",
        "/_/app.js",
        "/_/nope",
        "/_/nested/deep/path",
        "/_/index.htm",
        "/_index.html",
    ] {
        let (s, _, b) = get(&app, uri, None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "GET {uri} must 404, got body {:.120}", b);
    }

    // and the API is untouched by the new routes
    let (s, _, _) = get(&app, "/api/health", None).await;
    assert_eq!(s, StatusCode::OK, "/api/health still works");
}

// 7. The embedded asset's own contract, exactly as the spec's acceptance tests
//    state it: login wiring, live feed wiring, and the escaping rule.
#[tokio::test]
async fn admin_ui_asset_contract() {
    let app = app();
    let (s, _, body) = get(&app, "/_/", None).await;
    assert_eq!(s, StatusCode::OK);

    // login wiring present
    for needle in ["Authorization", "Admin ", "rb_admin_token"] {
        assert!(body.contains(needle), "admin page missing {needle:?}");
    }
    // live feed wired
    for needle in ["EventSource", "/api/realtime"] {
        assert!(body.contains(needle), "admin page missing {needle:?}");
    }
    // escaping rule, mechanically enforced
    assert!(
        !body.contains("innerHTML"),
        "innerHTML must not appear anywhere in the admin page"
    );
    assert!(body.contains("textContent"), "admin page must use textContent");

    // single file, kept small
    assert!(
        body.lines().count() < 400,
        "admin page is {} lines, spec caps it under 400",
        body.lines().count()
    );
}
