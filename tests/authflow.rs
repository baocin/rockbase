// Password reset + email verification for auth collections — TDD red phase.
// Harness style copied from tests/rules.rs (HTTP against `build_app`).
//
// DESIGN PINNED HERE (there is NO mailer and none is being added):
//
//   POST /api/collections/{c}/request-password-reset  {"email"}            -> 200 {} ALWAYS
//   POST /api/collections/{c}/confirm-password-reset  {"token","password"} -> 200 {}
//   POST /api/collections/{c}/request-verification    {"email"}            -> 200 {} ALWAYS
//   POST /api/collections/{c}/confirm-verification    {"token"}            -> 200 {}
//   GET  /api/tokens                                  ADMIN ONLY           -> {"items":[...]}
//
// The request endpoints NEVER return the token and never reveal whether the address
// exists — same status, same byte-identical body either way. The token is an opaque
// random string stored server-side in `_tokens`, and the ONLY way to read it back is
// `GET /api/tokens` with the admin token. That is the whole mailer integration point:
// an operator polls it (or reads the row) and sends the mail themselves. Admin already
// has `GET /api/backups`, i.e. the entire database, so this leaks no new privilege —
// while an unauthenticated caller has no endpoint at all that returns a token.
//
// `_tokens(token PK, collection, record, type, created, expires)`, type is
// "password_reset" | "verification", lifetime 3600s, row DELETEd on use (single use).
// Server-side rows, not JWTs: a stateless JWT cannot be burned after one use.
//
// Two tests reach into `_tokens` with a second connection on a file-backed DB to
// backdate `expires` — real expiry cannot be tested without controlling the clock,
// and this file does not sleep.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use tower::ServiceExt;

use rockbase::build_app;

const ADMIN: &str = "Admin testtoken";
const PW: &str = "clubrock1";
// Comfortably over any minimum a sibling agent pins in tests/authsec.rs.
const NEWPW: &str = "granitecountertop9";
// Short enough to violate any sane minimum, so this file pins no competing number.
const SHORTPW: &str = "abc";

fn app() -> Router {
    std::env::set_var("RB_JWT_SECRET", "testsecret");
    build_app(":memory:", "testtoken".into())
}

/// A file-backed app plus a second connection to the same DB, so a test can age a
/// token row instead of sleeping. Returns (app, side connection, path to clean up).
fn app_on_disk(tag: &str) -> (Router, Connection, std::path::PathBuf) {
    std::env::set_var("RB_JWT_SECRET", "testsecret");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("rockbase-authflow-{tag}-{nanos}.db"));
    let _ = std::fs::remove_file(&path);
    let app = build_app(path.to_str().unwrap(), "testtoken".into());
    let side = Connection::open(&path).unwrap();
    side.busy_timeout(std::time::Duration::from_millis(5000))
        .unwrap();
    (app, side, path)
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

/// Seed an auth record through the admin bypass. Returns its id.
async fn seed(app: &Router, col: &str, email: &str) -> String {
    let (s, v) = call(
        app,
        "POST",
        &format!("/api/collections/{col}/records"),
        Some(ADMIN),
        Some(json!({"email": email, "password": PW})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "seed {email}: {v}");
    v["id"].as_str().unwrap().to_string()
}

/// Log in, returning the "Bearer …" header value.
async fn login(app: &Router, col: &str, email: &str, pw: &str) -> Option<String> {
    let (s, v) = call(
        app,
        "POST",
        &format!("/api/collections/{col}/auth-with-password"),
        None,
        Some(json!({"identity": email, "password": pw})),
    )
    .await;
    (s == StatusCode::OK).then(|| format!("Bearer {}", v["token"].as_str().unwrap()))
}

async fn assert_login(app: &Router, col: &str, email: &str, pw: &str, want: bool, what: &str) {
    assert_eq!(
        login(app, col, email, pw).await.is_some(),
        want,
        "login({email}, {pw}) — {what}"
    );
}

/// Every outstanding token, admin-only. This is the mailer hook.
async fn tokens(app: &Router) -> Vec<Value> {
    let (s, v) = call(app, "GET", "/api/tokens", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK, "GET /api/tokens: {v}");
    v["items"]
        .as_array()
        .unwrap_or_else(|| panic!("GET /api/tokens must return items[]: {v}"))
        .clone()
}

/// The newest outstanding `ty` token for record `id`.
async fn token_for(app: &Router, id: &str, ty: &str) -> String {
    let all = tokens(app).await;
    let hit: Vec<&Value> = all
        .iter()
        .filter(|t| t["record"] == json!(id) && t["type"] == json!(ty))
        .collect();
    assert_eq!(
        hit.len(),
        1,
        "want exactly one {ty} token for {id}: {all:?}"
    );
    hit[0]["token"]
        .as_str()
        .unwrap_or_else(|| panic!("token row must carry a token string: {}", hit[0]))
        .to_string()
}

async fn request_reset(app: &Router, col: &str, email: &str) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        &format!("/api/collections/{col}/request-password-reset"),
        None,
        Some(json!({ "email": email })),
    )
    .await
}

async fn confirm_reset(app: &Router, col: &str, token: &str, pw: &str) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        &format!("/api/collections/{col}/confirm-password-reset"),
        None,
        Some(json!({ "token": token, "password": pw })),
    )
    .await
}

async fn request_verification(app: &Router, col: &str, email: &str) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        &format!("/api/collections/{col}/request-verification"),
        None,
        Some(json!({ "email": email })),
    )
    .await
}

async fn confirm_verification(app: &Router, col: &str, token: &str) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        &format!("/api/collections/{col}/confirm-verification"),
        None,
        Some(json!({ "token": token })),
    )
    .await
}

async fn record(app: &Router, col: &str, id: &str) -> Value {
    let (s, v) = call(
        app,
        "GET",
        &format!("/api/collections/{col}/records/{id}"),
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "view {col}/{id}: {v}");
    v
}

// ---------------------------------------------------------------- password reset

// 1. A reset request is a black hole: same 200, same body, whether or not the
//    address exists — and it never hands the token back to the caller.
#[tokio::test]
async fn reset_request_never_enumerates_users() {
    let app = app();
    let id = seed(&app, "users", "real@ex.com").await;

    let (s1, hit) = request_reset(&app, "users", "real@ex.com").await;
    let (s2, miss) = request_reset(&app, "users", "nobody@ex.com").await;

    assert_eq!(s1, StatusCode::OK, "known address: {hit}");
    assert_eq!(s2, StatusCode::OK, "unknown address: {miss}");
    assert_eq!(hit, miss, "known and unknown must be byte-identical");
    for body in [&hit, &miss] {
        assert!(
            !body.to_string().contains("token"),
            "the response must never carry the reset token: {body}"
        );
    }

    // ... and only the real address produced one.
    let all = tokens(&app).await;
    assert_eq!(all.len(), 1, "one token issued, for the real user: {all:?}");
    assert_eq!(all[0]["record"], json!(id));
    assert_eq!(all[0]["type"], json!("password_reset"));
}

// 2. The only way to read a token is the admin token. Guests and ordinary users
//    are locked out — this is the property the whole no-mailer design rests on.
#[tokio::test]
async fn tokens_endpoint_is_admin_only() {
    let app = app();
    seed(&app, "users", "a@ex.com").await;
    let bearer = login(&app, "users", "a@ex.com", PW).await.unwrap();
    request_reset(&app, "users", "a@ex.com").await;

    for auth in [None, Some(bearer.as_str()), Some("Admin wrongtoken")] {
        let (s, v) = call(&app, "GET", "/api/tokens", auth, None).await;
        assert_eq!(
            s,
            StatusCode::UNAUTHORIZED,
            "GET /api/tokens as {auth:?}: {v}"
        );
        assert!(
            !v.to_string().contains("password_reset"),
            "no token material in the refusal: {v}"
        );
    }
    let (s, _) = call(&app, "GET", "/api/tokens", Some(ADMIN), None).await;
    assert_eq!(s, StatusCode::OK, "admin may read tokens");
}

// 3. A valid token swaps the password: old stops working, new works.
#[tokio::test]
async fn reset_token_sets_new_password() {
    let app = app();
    let id = seed(&app, "users", "a@ex.com").await;
    request_reset(&app, "users", "a@ex.com").await;
    let t = token_for(&app, &id, "password_reset").await;

    let (s, v) = confirm_reset(&app, "users", &t, NEWPW).await;
    assert_eq!(s, StatusCode::OK, "confirm reset: {v}");

    assert_login(&app, "users", "a@ex.com", PW, false, "old password is dead").await;
    assert_login(&app, "users", "a@ex.com", NEWPW, true, "new password works").await;
}

// 4. Single use. The replay fails and the password it carried never takes effect.
#[tokio::test]
async fn reset_token_is_single_use() {
    let app = app();
    let id = seed(&app, "users", "a@ex.com").await;
    request_reset(&app, "users", "a@ex.com").await;
    let t = token_for(&app, &id, "password_reset").await;

    assert_eq!(
        confirm_reset(&app, "users", &t, NEWPW).await.0,
        StatusCode::OK
    );

    let (s, v) = confirm_reset(&app, "users", &t, "replayedpassword1").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "replay must fail: {v}");
    assert_login(
        &app,
        "users",
        "a@ex.com",
        "replayedpassword1",
        false,
        "replay changed nothing",
    )
    .await;
    assert_login(
        &app,
        "users",
        "a@ex.com",
        NEWPW,
        true,
        "first reset still stands",
    )
    .await;

    // A spent token is gone from the admin listing too.
    assert!(
        tokens(&app).await.is_empty(),
        "spent tokens must not linger"
    );
}

// 5. Lifetime is 3600s and an aged token is refused. Backdated through a second
//    connection — no sleeping, no clock control needed.
#[tokio::test]
async fn reset_token_expires_after_one_hour() {
    let (app, side, path) = app_on_disk("reset-exp");
    let id = seed(&app, "users", "a@ex.com").await;
    request_reset(&app, "users", "a@ex.com").await;
    let t = token_for(&app, &id, "password_reset").await;

    let secs: i64 = side
        .query_row(
            "SELECT CAST((julianday(expires) - julianday(created)) * 86400 + 0.5 AS INTEGER) \
             FROM _tokens WHERE token = ?1",
            params![t],
            |r| r.get(0),
        )
        .expect("_tokens(token, collection, record, type, created, expires) must exist");
    assert!(
        (3599..=3601).contains(&secs),
        "reset token lifetime is 1 hour, got {secs}s"
    );

    side.execute(
        "UPDATE _tokens SET expires = '2000-01-01 00:00:00.000' WHERE token = ?1",
        params![t],
    )
    .unwrap();

    let (s, v) = confirm_reset(&app, "users", &t, NEWPW).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "expired token must fail: {v}");
    assert_login(
        &app,
        "users",
        "a@ex.com",
        NEWPW,
        false,
        "expired token changed nothing",
    )
    .await;
    assert_login(
        &app,
        "users",
        "a@ex.com",
        PW,
        true,
        "original password survives",
    )
    .await;

    drop(side);
    let _ = std::fs::remove_file(&path);
}

// 6. A token is bound to one record in one collection. It cannot be pointed at a
//    neighbour, and it cannot be replayed against another auth collection.
#[tokio::test]
async fn reset_token_cannot_touch_another_user() {
    let app = app();
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "staff", "type": "auth", "schema": []})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "create staff collection: {v}");

    let a = seed(&app, "users", "a@ex.com").await;
    seed(&app, "users", "b@ex.com").await;
    seed(&app, "staff", "b@ex.com").await;

    request_reset(&app, "users", "a@ex.com").await;
    let t = token_for(&app, &a, "password_reset").await;

    // Same token, different collection: refused, and staff/b is untouched.
    let (s, v) = confirm_reset(&app, "staff", &t, NEWPW).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "cross-collection replay: {v}");
    assert_login(&app, "staff", "b@ex.com", NEWPW, false, "staff untouched").await;
    assert_login(&app, "staff", "b@ex.com", PW, true, "staff password intact").await;

    // Spending it on the right collection only ever moves user A.
    assert_eq!(
        confirm_reset(&app, "users", &t, NEWPW).await.0,
        StatusCode::OK
    );
    assert_login(
        &app,
        "users",
        "b@ex.com",
        NEWPW,
        false,
        "sibling user untouched",
    )
    .await;
    assert_login(
        &app,
        "users",
        "b@ex.com",
        PW,
        true,
        "sibling password intact",
    )
    .await;
}

// 7. Forged, empty, missing and borrowed-JWT tokens all fail closed.
#[tokio::test]
async fn forged_reset_tokens_fail_closed() {
    let app = app();
    seed(&app, "users", "a@ex.com").await;
    let bearer = login(&app, "users", "a@ex.com", PW).await.unwrap();
    let jwt = bearer.strip_prefix("Bearer ").unwrap().to_string();
    let long = "f".repeat(64);

    for bad in [
        "",
        "garbage",
        "../../etc/passwd",
        long.as_str(),
        jwt.as_str(),
    ] {
        let (s, v) = confirm_reset(&app, "users", bad, NEWPW).await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "token {bad:?} must be refused: {v}"
        );
    }
    // No token field at all.
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/confirm-password-reset",
        None,
        Some(json!({ "password": NEWPW })),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "missing token: {v}");

    assert_login(&app, "users", "a@ex.com", NEWPW, false, "nothing was reset").await;
    assert_login(
        &app,
        "users",
        "a@ex.com",
        PW,
        true,
        "original password intact",
    )
    .await;
}

// 8. A reset kills sessions issued before it. Whoever knew the old password —
//    or stole a token with it — is logged out. (Sibling tests/authsec.rs specifies
//    the revocation epoch; asserted here purely as observable behaviour, so it holds
//    whatever mechanism lands.)
#[tokio::test]
async fn reset_invalidates_outstanding_sessions() {
    let app = app();
    let id = seed(&app, "users", "a@ex.com").await;
    let stale = login(&app, "users", "a@ex.com", PW).await.unwrap();

    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/users/auth-refresh",
        Some(&stale),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "session is live before the reset");

    request_reset(&app, "users", "a@ex.com").await;
    let t = token_for(&app, &id, "password_reset").await;
    assert_eq!(
        confirm_reset(&app, "users", &t, NEWPW).await.0,
        StatusCode::OK
    );

    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/auth-refresh",
        Some(&stale),
        None,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "pre-reset session must be dead: {v}"
    );
}

// 9. The reset path is not a way around the password policy, and a rejected
//    password must not burn the token — otherwise a typo locks the user out for good.
#[tokio::test]
async fn reset_enforces_password_policy_without_burning_the_token() {
    let app = app();
    let id = seed(&app, "users", "a@ex.com").await;
    request_reset(&app, "users", "a@ex.com").await;
    let t = token_for(&app, &id, "password_reset").await;

    let (s, v) = confirm_reset(&app, "users", &t, SHORTPW).await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "short password must be refused: {v}"
    );
    assert_login(
        &app,
        "users",
        "a@ex.com",
        SHORTPW,
        false,
        "short password not set",
    )
    .await;

    // The token survives the rejection and still works.
    let (s, v) = confirm_reset(&app, "users", &t, NEWPW).await;
    assert_eq!(s, StatusCode::OK, "token survives a policy rejection: {v}");
    assert_login(&app, "users", "a@ex.com", NEWPW, true, "retry succeeded").await;
}

// ----------------------------------------------------------- email verification

// 10. Signing up proves nothing about the address, so the record starts unverified —
//     visible everywhere the record is.
#[tokio::test]
async fn signup_starts_unverified() {
    let app = app();
    let (s, created) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": "a@ex.com", "password": PW})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "signup: {created}");
    assert_eq!(
        created["verified"],
        json!(false),
        "create response: {created}"
    );

    let id = created["id"].as_str().unwrap();
    assert_eq!(record(&app, "users", id).await["verified"], json!(false));

    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": "a@ex.com", "password": PW})),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["record"]["verified"], json!(false), "login record: {v}");
}

// 11. A verification token flips the flag; the request endpoint enumerates nobody
//     and hands back nothing, exactly like the reset request.
#[tokio::test]
async fn verification_token_marks_record_verified() {
    let app = app();
    let id = seed(&app, "users", "a@ex.com").await;

    let (s1, hit) = request_verification(&app, "users", "a@ex.com").await;
    let (s2, miss) = request_verification(&app, "users", "nobody@ex.com").await;
    assert_eq!(s1, StatusCode::OK, "known address: {hit}");
    assert_eq!(s2, StatusCode::OK, "unknown address: {miss}");
    assert_eq!(hit, miss, "known and unknown must be byte-identical");
    assert!(
        !hit.to_string().contains("token"),
        "no token in body: {hit}"
    );

    let t = token_for(&app, &id, "verification").await;
    let (s, v) = confirm_verification(&app, "users", &t).await;
    assert_eq!(s, StatusCode::OK, "confirm verification: {v}");

    assert_eq!(record(&app, "users", &id).await["verified"], json!(true));
    let bearer = login(&app, "users", "a@ex.com", PW).await.unwrap();
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/auth-refresh",
        Some(&bearer),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["record"]["verified"], json!(true), "refresh record: {v}");
}

// 12. Single use, and bound to the record it was issued for — B cannot ride A's token.
#[tokio::test]
async fn verification_token_is_single_use_and_bound_to_one_user() {
    let app = app();
    let a = seed(&app, "users", "a@ex.com").await;
    let b = seed(&app, "users", "b@ex.com").await;

    request_verification(&app, "users", "a@ex.com").await;
    let t = token_for(&app, &a, "verification").await;
    assert_eq!(
        confirm_verification(&app, "users", &t).await.0,
        StatusCode::OK
    );

    let (s, v) = confirm_verification(&app, "users", &t).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "replay must fail: {v}");
    assert_eq!(
        record(&app, "users", &b).await["verified"],
        json!(false),
        "A's token must never verify B"
    );
    assert!(tokens(&app).await.is_empty(), "spent token must be gone");

    let (s, v) = confirm_verification(&app, "users", "garbage").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "forged verification token: {v}");
    assert_eq!(record(&app, "users", &b).await["verified"], json!(false));
}

// 13. `verified` is server-owned. Nobody writes it through the record API — not a
//     guest, not the owner, not the signup body.
#[tokio::test]
async fn verified_cannot_be_set_through_the_record_api() {
    let app = app();
    let id = seed(&app, "users", "a@ex.com").await;
    let bearer = login(&app, "users", "a@ex.com", PW).await.unwrap();
    let uri = format!("/api/collections/users/records/{id}");

    for auth in [None, Some(bearer.as_str())] {
        let (s, v) = call(&app, "PATCH", &uri, auth, Some(json!({"verified": true}))).await;
        assert!(
            !s.is_success(),
            "PATCH verified as {auth:?} must be refused, got {s}: {v}"
        );
        assert_eq!(
            record(&app, "users", &id).await["verified"],
            json!(false),
            "record must still be unverified after PATCH as {auth:?}"
        );
    }

    // Nor smuggled in at signup.
    let (_, v) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": "b@ex.com", "password": PW, "verified": true})),
    )
    .await;
    assert_ne!(v["verified"], json!(true), "signup cannot self-verify: {v}");
}

// 14. `verified` is a system field, so a schema may not shadow it.
#[tokio::test]
async fn verified_is_a_reserved_field_name() {
    let app = app();
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({"name": "shadow", "schema": [{"name": "verified", "type": "bool"}]})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "'verified' must be reserved: {v}"
    );
}

// 15. Verification tokens age out on the same 1-hour clock as reset tokens.
#[tokio::test]
async fn verification_token_expires_after_one_hour() {
    let (app, side, path) = app_on_disk("verify-exp");
    let id = seed(&app, "users", "a@ex.com").await;
    request_verification(&app, "users", "a@ex.com").await;
    let t = token_for(&app, &id, "verification").await;

    let secs: i64 = side
        .query_row(
            "SELECT CAST((julianday(expires) - julianday(created)) * 86400 + 0.5 AS INTEGER) \
             FROM _tokens WHERE token = ?1",
            params![t],
            |r| r.get(0),
        )
        .expect("_tokens(token, collection, record, type, created, expires) must exist");
    assert!(
        (3599..=3601).contains(&secs),
        "verification token lifetime is 1 hour, got {secs}s"
    );

    side.execute(
        "UPDATE _tokens SET expires = '2000-01-01 00:00:00.000' WHERE token = ?1",
        params![t],
    )
    .unwrap();

    let (s, v) = confirm_verification(&app, "users", &t).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "expired token must fail: {v}");
    assert_eq!(record(&app, "users", &id).await["verified"], json!(false));

    drop(side);
    let _ = std::fs::remove_file(&path);
}
