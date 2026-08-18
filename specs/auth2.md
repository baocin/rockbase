> **HISTORICAL — superseded by the code and tests.**
> This was a design input, written when the whole crate was a single `src/main.rs`.
> The crate is now modular (`src/lib.rs` + modules), so every file-layout claim below
> is wrong. The authoritative specification is `tests/basic.rs` plus the source.
> Do not implement from this document.

# auth2 — Auth identity, refresh, user existence check

All changes in `src/main.rs`. No new dependencies. No schema changes.

## 1. Identity in `Who`

Change the `User` variant to carry the JWT identity:

```rust
enum Who {
    Admin,
    User { col: String, id: String },
    Guest,
}
```

This is the exposure point for later per-collection rules: any handler that
needs "who is calling" matches on `Who::User { col, id }`.

## 2. `who()` verifies the record still exists

Keep the signature `fn who(app: &App, headers: &HeaderMap) -> Who`. After a
successful JWT decode, take the claims and check the record is still in the DB.
A deleted user's token must behave exactly like no token.

```rust
if let Ok(t) = decode::<Claims>(t, ...) {
    let c = t.claims;
    // ponytail: who() locks app.db itself — never call it while holding the lock.
    // All current call sites run before the handler locks; keep it that way.
    let db = app.db.lock().unwrap();
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM records WHERE collection = ?1 AND id = ?2)",
            params![c.col, c.sub],
            |r| r.get(0),
        )
        .unwrap_or(false);
    if exists {
        return Who::User { col: c.col, id: c.sub };
    }
    // fall through to Guest
}
```

Values via binds only; no identifier interpolation. The existence check is one
PK lookup per authed request — fine at this scale.

Expired/garbage tokens already fall through to `Guest` via
`Validation::default()`; unchanged.

## 3. `require_writer` returns the identity

```rust
fn require_writer(app: &App, headers: &HeaderMap) -> Result<Who, (StatusCode, Json<Value>)> {
    match who(app, headers) {
        Who::Guest => Err(err(StatusCode::UNAUTHORIZED, "auth required")),
        w => Ok(w),
    }
}
```

Existing call sites (`record_create`, `record_update`, `record_delete`) stay as
`require_writer(&app, &headers)?;` — the returned `Who` is simply discarded
today, used by rules later. `require_admin` is unchanged.

## 4. Token minting helper

Extract the encode block from `auth_with_password` (lines ~609-620) so
refresh reuses it:

```rust
fn make_token(app: &App, col: &str, id: &str) -> Result<String, (StatusCode, Json<Value>)> {
    let exp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 7 * 24 * 3600;
    let claims = Claims { sub: id.into(), col: col.into(), exp };
    encode(&Header::default(), &claims, &EncodingKey::from_secret(app.jwt_secret.as_bytes()))
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}
```

`auth_with_password` calls it; response shape there is unchanged.

## 5. New endpoint: `POST /api/collections/{name}/auth-refresh`

PocketBase-shaped: valid Bearer of that same collection gets a fresh 7-day
token plus its record. No request body. Admin tokens are rejected (an admin is
not an auth record).

```rust
async fn auth_refresh(State(app): State<S>, Path(name): Path<String>, headers: HeaderMap) -> Reply {
    let Who::User { col, id } = who(&app, &headers) else {
        return Err(err(StatusCode::UNAUTHORIZED, "auth token required"));
    };
    if col != name {
        return Err(err(StatusCode::UNAUTHORIZED, "token is for another collection"));
    }
    // ponytail: no auth-collection type check — a User token only ever names an
    // auth collection, and who() already proved the record exists there.
    let token = make_token(&app, &col, &id)?;
    let db = app.db.lock().unwrap();
    let Some((data, created, updated)) = fetch_record(&db, &name, &id) else {
        return Err(err(StatusCode::NOT_FOUND, "record not found")); // race: deleted since who()
    };
    Ok(Json(json!({ "token": token, "record": record_json(&name, &id, &data, &created, &updated) })))
}
```

Route, added next to the existing auth route in `build_app`:

```rust
.route("/api/collections/{name}/auth-refresh", post(auth_refresh))
```

### Request / response

```
POST /api/collections/users/auth-refresh
Authorization: Bearer <jwt issued for "users">
```

200:

```json
{
  "token": "eyJ...",
  "record": { "id": "abc123", "collectionName": "users", "email": "og@cave.dev",
              "created": "2026-08-18 10:00:00", "updated": "2026-08-18 10:00:00" }
}
```

Errors: 401 `{"code":401,"message":"auth token required"}` for missing/garbage/
expired/deleted-user/admin tokens; 401 for a token of a different collection.
`record_json` already strips `password_hash`.

## 6. Password change stays via PATCH

No code change — `record_update` already routes `password` through
`hash_password`. Add one comment in `record_update` just above the
`hash_password(&mut merged)?;` line:

```rust
// ponytail: password change via plain PATCH, old-password confirmation skipped;
// add an oldPassword check (bcrypt::verify against stored hash) when untrusted
// clients can hold long-lived tokens.
```

## Acceptance tests

Extend the inline `tests` module in `src/main.rs` (reuse `app()`/`call()`).
Setup per test: admin-create a user, log in, keep the bearer.

1. **refresh ok** — `POST /api/collections/users/auth-refresh` with valid
   bearer → 200; body has non-empty `token` and `record.email == "og@cave.dev"`;
   `record` has no `password_hash`.
2. **refreshed token works** — use the returned token as Bearer to
   `POST /api/collections/posts/records` → 200.
3. **no/garbage token** — refresh with no header → 401; with
   `Bearer notatoken` → 401.
4. **admin token rejected** — refresh with `Admin testtoken` → 401.
5. **wrong collection** — admin-create auth collection `staff`; refresh
   `users` token against `/api/collections/staff/auth-refresh` → 401.
6. **deleted user is Guest** — admin `DELETE /api/collections/users/records/{id}`,
   then old bearer on `POST /api/collections/posts/records` → 401 and on
   `auth-refresh` → 401.
7. **password change via PATCH** — PATCH user record `{"password":"newpass99"}`
   with bearer → 200; old password login → 400; new password login → 200.
8. **existing suite stays green** — `cargo test` passes; `full_flow` unchanged.
