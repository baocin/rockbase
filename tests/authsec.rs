// Authentication hardening — TDD red phase.
//
// Four weaknesses, pinned here as behavior the server does not have yet. Same
// harness style as tests/basic.rs and tests/rules.rs: everything goes over HTTP
// against `build_app`, because bcrypt is a normal dependency and tests cannot
// hash directly.
//
// THE SPEC THESE TESTS ENCODE (every choice is deliberate, all of it conservative
// and bolted onto endpoints that already exist — no new routes):
//
// 1. Password policy: minimum 8 characters, enforced everywhere a password is
//    accepted (signup AND password change). 400 on violation. The policy check
//    must run BEFORE the email-uniqueness check, so a too-short password returns
//    the same message whether or not the email is already registered — otherwise
//    the signup form is an email-enumeration oracle for anyone who types "x".
//
// 2. Brute force: POST /auth-with-password allows MAX_FAILS = 5 consecutive
//    failed attempts per identity; the 6th is refused with 429 for a cooldown
//    (15 minutes) even when the password is correct. Keyed by (collection,
//    identity), never global — a global lock is a one-line denial of service
//    against every account. A successful login clears the counter.
//    NOT TESTED: cooldown expiry (needs clock control; no test here sleeps).
//
// 3. Password change requires proof of the current password: PATCH on an auth
//    record carrying "password" must also carry "oldPassword" (write-only field,
//    verified against the stored hash, never persisted). Admins are exempt —
//    a support reset has no old password to offer.
//
// 4. Token revocation: an integer token epoch lives on the auth record and rides
//    in the JWT as an `epoch` claim; who() compares them and treats a stale token
//    exactly like no token at all (Guest — 401, not 403, and never 500).
//    Bumping the epoch invalidates every outstanding token for that record.
//    Bumped by: PATCH {"revokeTokens": true} on the record (write-only field,
//    self or admin — this is "log out everywhere"), and by ANY password change,
//    user- or admin-initiated. Killing stolen sessions is the entire point of
//    changing a password.

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
/// Consecutive failures allowed per identity before the cooldown kicks in.
const MAX_FAILS: usize = 5;

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

/// Seed a user through the admin bypass. Returns the record id.
async fn seed(app: &Router, email: &str) -> String {
    let (s, v) = call(
        app,
        "POST",
        "/api/collections/users/records",
        Some(ADMIN),
        Some(json!({"email": email, "password": PW})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "seed {email}: {v}");
    v["id"].as_str().unwrap().to_string()
}

async fn login(app: &Router, email: &str, pw: &str) -> (StatusCode, Value) {
    call(
        app,
        "POST",
        "/api/collections/users/auth-with-password",
        None,
        Some(json!({"identity": email, "password": pw})),
    )
    .await
}

/// Log in and hand back the Authorization header value.
async fn bearer(app: &Router, email: &str, pw: &str) -> String {
    let (s, v) = login(app, email, pw).await;
    assert_eq!(s, StatusCode::OK, "login {email}: {v}");
    format!("Bearer {}", v["token"].as_str().unwrap())
}

/// Cheapest liveness probe for a token: auth-refresh is 200 for a live token and
/// 401 for anything the server refuses.
async fn refresh(app: &Router, auth: &str) -> StatusCode {
    call(
        app,
        "POST",
        "/api/collections/users/auth-refresh",
        Some(auth),
        None,
    )
    .await
    .0
}

fn msg(v: &Value) -> String {
    v["message"].as_str().unwrap_or("").to_string()
}

// ---------------------------------------------------------------- 1. policy

#[tokio::test]
async fn signup_enforces_minimum_password_length() {
    let app = app();

    for (i, pw) in ["", "x", "short7c"].into_iter().enumerate() {
        let (s, v) = call(
            &app,
            "POST",
            "/api/collections/users/records",
            None,
            Some(json!({"email": format!("short{i}@cave.dev"), "password": pw})),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "password {pw:?} accepted: {v}");
        assert!(
            msg(&v).contains('8'),
            "password {pw:?} rejected without naming the 8-char minimum: {v}"
        );
    }

    // exactly at the floor
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        None,
        Some(json!({"email": "eight@cave.dev", "password": "12345678"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "8-char password rejected: {v}");
    assert_eq!(
        login(&app, "eight@cave.dev", "12345678").await.0,
        StatusCode::OK
    );

    // a long passphrase is not an error — no upper bound sneaks in with the lower one
    let long = "correct horse battery staple ".repeat(2);
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        None,
        Some(json!({"email": "long@cave.dev", "password": long})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "long password rejected: {v}");
    assert_eq!(login(&app, "long@cave.dev", &long).await.0, StatusCode::OK);
}

#[tokio::test]
async fn password_policy_does_not_leak_whether_the_email_exists() {
    let app = app();
    seed(&app, "known@cave.dev").await;

    // guest signup, too-short password, on an address that IS registered ...
    let (taken_s, taken_v) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        None,
        Some(json!({"email": "known@cave.dev", "password": "nope"})),
    )
    .await;
    // ... and on one that is not.
    let (fresh_s, fresh_v) = call(
        &app,
        "POST",
        "/api/collections/users/records",
        None,
        Some(json!({"email": "unknown@cave.dev", "password": "nope"})),
    )
    .await;

    assert_eq!(taken_s, StatusCode::BAD_REQUEST);
    assert_eq!(fresh_s, StatusCode::BAD_REQUEST);
    // The password check has to run first, or the two replies differ and the signup
    // form becomes an account-enumeration oracle for anyone who types a short password.
    assert_eq!(
        msg(&taken_v),
        msg(&fresh_v),
        "reply differs by whether the email exists: {taken_v} vs {fresh_v}"
    );
}

#[tokio::test]
async fn password_change_enforces_minimum_length() {
    let app = app();
    let id = seed(&app, "chg@cave.dev").await;
    let auth = bearer(&app, "chg@cave.dev", PW).await;
    let uri = format!("/api/collections/users/records/{id}");

    // owner path: correct old password, but the new one is too short
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(&auth),
        Some(json!({"password": "tiny", "oldPassword": PW})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "short new password accepted: {v}"
    );
    assert!(msg(&v).contains('8'), "wrong rejection reason: {v}");

    // admin path: the policy is not something admins get to skip
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(ADMIN),
        Some(json!({"password": "tiny"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "admin set a short password: {v}"
    );
    assert!(msg(&v).contains('8'), "wrong rejection reason: {v}");

    // nothing was written either way
    assert_eq!(login(&app, "chg@cave.dev", PW).await.0, StatusCode::OK);
    assert_eq!(
        login(&app, "chg@cave.dev", "tiny").await.0,
        StatusCode::BAD_REQUEST
    );
}

// ----------------------------------------------------------- 2. brute force

#[tokio::test]
async fn repeated_failures_lock_the_identity_out() {
    let app = app();
    seed(&app, "bf@cave.dev").await;

    for i in 0..MAX_FAILS {
        let (s, v) = login(&app, "bf@cave.dev", "wrongwrong").await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "attempt {i} was not a plain reject: {v}"
        );
    }

    // the correct password no longer helps — that is what makes this a throttle
    // rather than a hint about whether the guess was close.
    let (s, v) = login(&app, "bf@cave.dev", PW).await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "attempt {} after {MAX_FAILS} failures was not throttled: {v}",
        MAX_FAILS + 1
    );
}

#[tokio::test]
async fn throttle_is_per_identity_not_global() {
    let app = app();
    seed(&app, "victim@cave.dev").await;
    seed(&app, "bystander@cave.dev").await;

    for _ in 0..MAX_FAILS {
        assert_eq!(
            login(&app, "victim@cave.dev", "wrongwrong").await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        login(&app, "victim@cave.dev", PW).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "the throttled identity is not locked"
    );

    // A global limiter would make this the cheapest denial of service in the
    // codebase: lock out every user by fat-fingering one login six times.
    let (s, v) = login(&app, "bystander@cave.dev", PW).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "an unrelated identity got locked out too: {v}"
    );
}

#[tokio::test]
async fn successful_login_resets_the_failure_counter() {
    let app = app();
    seed(&app, "reset@cave.dev").await;

    for _ in 0..MAX_FAILS - 1 {
        assert_eq!(
            login(&app, "reset@cave.dev", "wrongwrong").await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(login(&app, "reset@cave.dev", PW).await.0, StatusCode::OK);

    // second batch: if the counter had not been cleared these would cross the
    // threshold mid-batch and start returning 429.
    for i in 0..MAX_FAILS - 1 {
        let (s, v) = login(&app, "reset@cave.dev", "wrongwrong").await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "failure {i} after a good login was throttled — counter never reset: {v}"
        );
    }
    let (s, v) = login(&app, "reset@cave.dev", PW).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "good login refused below the threshold: {v}"
    );

    // and the limiter still bites after the reset — it is cleared, not disabled
    for _ in 0..MAX_FAILS {
        assert_eq!(
            login(&app, "reset@cave.dev", "wrongwrong").await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        login(&app, "reset@cave.dev", PW).await.0,
        StatusCode::TOO_MANY_REQUESTS,
        "limiter stopped working after a reset"
    );
}

// -------------------------------------------------------- 3. old password

#[tokio::test]
async fn password_change_without_old_password_is_refused() {
    let app = app();
    let id = seed(&app, "steal@cave.dev").await;
    let auth = bearer(&app, "steal@cave.dev", PW).await;

    // A stolen bearer is enough to lock the owner out of their own account
    // permanently unless the current password has to be presented.
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/users/records/{id}"),
        Some(&auth),
        Some(json!({"password": "hijacked1"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "token alone changed the password: {v}"
    );

    assert_eq!(
        login(&app, "steal@cave.dev", "hijacked1").await.0,
        StatusCode::BAD_REQUEST,
        "the refused password was written anyway"
    );
    assert_eq!(
        login(&app, "steal@cave.dev", PW).await.0,
        StatusCode::OK,
        "the owner lost their password to a refused request"
    );
}

#[tokio::test]
async fn old_password_is_verified_before_the_change() {
    let app = app();
    let id = seed(&app, "own@cave.dev").await;
    let auth = bearer(&app, "own@cave.dev", PW).await;
    let uri = format!("/api/collections/users/records/{id}");

    // wrong current password: refused
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(&auth),
        Some(json!({"password": "newrock99", "oldPassword": "notitrock"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "wrong oldPassword accepted: {v}"
    );
    assert_eq!(
        login(&app, "own@cave.dev", "newrock99").await.0,
        StatusCode::BAD_REQUEST,
        "the refused password was written anyway"
    );

    // correct current password: the change goes through
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(&auth),
        Some(json!({"password": "newrock99", "oldPassword": PW})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "correct oldPassword rejected: {v}");
    // oldPassword is a credential, not a column — it must not be echoed or stored
    assert!(
        v["oldPassword"].is_null(),
        "oldPassword leaked into the record: {v}"
    );
    assert!(
        v["password"].is_null(),
        "password leaked into the record: {v}"
    );
    assert!(
        v["password_hash"].is_null(),
        "hash leaked into the record: {v}"
    );

    assert_eq!(
        login(&app, "own@cave.dev", "newrock99").await.0,
        StatusCode::OK
    );
    assert_eq!(
        login(&app, "own@cave.dev", PW).await.0,
        StatusCode::BAD_REQUEST,
        "the old password still works after the change"
    );
}

#[tokio::test]
async fn admin_resets_a_password_without_the_old_one() {
    let app = app();
    let id = seed(&app, "forgot@cave.dev").await;
    let victim = bearer(&app, "forgot@cave.dev", PW).await;

    // The whole point of an admin reset is that nobody has the old password.
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/users/records/{id}"),
        Some(ADMIN),
        Some(json!({"password": "adminset1"})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "admin reset refused: {v}");

    assert_eq!(
        login(&app, "forgot@cave.dev", "adminset1").await.0,
        StatusCode::OK
    );
    assert_eq!(
        login(&app, "forgot@cave.dev", PW).await.0,
        StatusCode::BAD_REQUEST
    );
    // an admin reset is also a session kill — it is the lever used when an account
    // is known to be compromised
    assert_eq!(
        refresh(&app, &victim).await,
        StatusCode::UNAUTHORIZED,
        "tokens survived an admin password reset"
    );
}

// ---------------------------------------------------------- 4. revocation

#[tokio::test]
async fn revoking_tokens_kills_outstanding_ones() {
    let app = app();
    let id = seed(&app, "revoke@cave.dev").await;
    let auth = bearer(&app, "revoke@cave.dev", PW).await;
    let uri = format!("/api/collections/users/records/{id}");

    assert_eq!(
        refresh(&app, &auth).await,
        StatusCode::OK,
        "fresh token refused"
    );

    // "log out everywhere"
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(&auth),
        Some(json!({"revokeTokens": true})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "revokeTokens refused: {v}");

    assert_eq!(
        refresh(&app, &auth).await,
        StatusCode::UNAUTHORIZED,
        "the revoked token still refreshes — logout cannot work"
    );
    // A revoked token must degrade to Guest, not to a half-authenticated user and
    // not to a 500: rules::deny answers 401 for guests and 403 for users, so the
    // status code is the assertion.
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(&auth),
        Some(json!({"email": "x@cave.dev"})),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "revoked token did not behave like no token at all: {s} {v}"
    );

    // logging in again works and yields a token minted against the new epoch
    let fresh = bearer(&app, "revoke@cave.dev", PW).await;
    assert_ne!(fresh, auth, "re-login handed back the revoked token");
    assert_eq!(
        refresh(&app, &fresh).await,
        StatusCode::OK,
        "revocation outlived the tokens it was meant to kill"
    );
}

#[tokio::test]
async fn admin_can_revoke_a_users_tokens() {
    let app = app();
    let id = seed(&app, "pwned@cave.dev").await;
    let auth = bearer(&app, "pwned@cave.dev", PW).await;
    assert_eq!(refresh(&app, &auth).await, StatusCode::OK);

    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/users/records/{id}"),
        Some(ADMIN),
        Some(json!({"revokeTokens": true})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "admin revoke refused: {v}");
    assert_eq!(
        refresh(&app, &auth).await,
        StatusCode::UNAUTHORIZED,
        "admin could not evict a compromised session"
    );

    // the account itself is untouched — revocation is not a ban
    assert_eq!(login(&app, "pwned@cave.dev", PW).await.0, StatusCode::OK);
}

#[tokio::test]
async fn changing_a_password_revokes_existing_tokens() {
    let app = app();
    let id = seed(&app, "rotate@cave.dev").await;
    let stolen = bearer(&app, "rotate@cave.dev", PW).await;
    let owner = bearer(&app, "rotate@cave.dev", PW).await;

    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/collections/users/records/{id}"),
        Some(&owner),
        Some(json!({"password": "rotated99", "oldPassword": PW})),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "password change refused: {v}");

    // Changing your password because someone else has your session is pointless
    // if their session survives it.
    assert_eq!(
        refresh(&app, &stolen).await,
        StatusCode::UNAUTHORIZED,
        "a stolen token survived the password change"
    );
    assert_eq!(
        refresh(&app, &owner).await,
        StatusCode::UNAUTHORIZED,
        "the changing token survived its own password change"
    );

    let fresh = bearer(&app, "rotate@cave.dev", "rotated99").await;
    assert_eq!(refresh(&app, &fresh).await, StatusCode::OK);
}
