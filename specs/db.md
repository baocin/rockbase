# Spec: DB hardening + backup endpoint

Scope: WAL journal mode + busy_timeout on every connection, and an admin-only
`GET /api/backups` that streams a `VACUUM INTO` snapshot. Nothing else. The
single `Mutex<Connection>` design stays.

All changes live in `src/main.rs` (the whole app is one file; keep it that way).

## 1. Connection hardening

Where: a tiny helper next to `init_db`, called at the top of
`build_app(conn, admin_token)` before `init_db(&conn)`. `build_app` is the
single choke point — `main()` and the test `app()` helper both route through
it, so file-backed and in-memory connections all get the pragmas. It is a
helper (not inlined) only so a test can call it on a connection it still owns
(`build_app` consumes the connection, and busy_timeout is per-connection).

```rust
// ponytail: single Mutex<Connection> stays; swap for a pool (r2d2/deadpool) if
// concurrent throughput ever matters. WAL + busy_timeout is the cheap 90%.
fn harden(conn: &Connection) {
    conn.busy_timeout(std::time::Duration::from_millis(5000)).expect("busy_timeout");
    let _mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .expect("set journal_mode");
}
```

Details:
- `journal_mode=WAL` returns one row (the resulting mode), so use `query_row`,
  not `execute` / `pragma_update` (rusqlite 0.32 errors on statements that
  return rows via `execute`).
- Do NOT assert the returned mode is `"wal"`. In-memory databases report
  `"memory"` — that is the graceful in-memory handling; no branching needed.
- `Connection::busy_timeout` is a rusqlite built-in; no raw SQL needed.
- No new dependencies, no config knobs.

## 2. `GET /api/backups` (admin only)

PocketBase has a multi-endpoint backups API (list/create/download). We ship one
endpoint that creates-and-downloads in a single GET. Note the deviation in the
handler comment: `// ponytail: one-shot download, not PocketBase's
list/create/download trio; split when someone needs stored backups.`

### Route

Add to the `Router` in `build_app`:

```rust
.route("/api/backups", get(backup_download))
```

### Handler

The existing `Reply` alias is JSON-only; the handler returns bytes, so give it
its own signature. New imports needed: `axum::http::header`,
`axum::response::IntoResponse`.

```rust
async fn backup_download(
    State(app): State<S>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, Json<Value>)> {
    require_admin(&app, &headers)?;
    let tmp = std::env::temp_dir().join(format!("rockbase_backup_{}.db", new_id()));
    let tmp_str = tmp.to_str()
        .ok_or_else(|| err(StatusCode::INTERNAL_SERVER_ERROR, "bad temp path"))?
        .to_string();
    {
        let db = app.db.lock().unwrap();
        // VACUUM INTO writes a compacted, consistent copy; works from
        // in-memory DBs too (SQLite >= 3.27; bundled is 3.46).
        db.execute("VACUUM INTO ?1", [&tmp_str])
            .map_err(|e| { let _ = std::fs::remove_file(&tmp);
                err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()) })?;
    } // lock released before file IO
    let bytes = std::fs::read(&tmp)
        .map_err(|e| { let _ = std::fs::remove_file(&tmp);
            err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()) })?;
    let _ = std::fs::remove_file(&tmp);
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION,
             format!("attachment; filename=\"rockbase_{ts}.db\"")),
        ],
        bytes,
    ))
}
```

Rules baked into the above — do not lose them:
- Temp path binds as a parameter (`?1`), never string-interpolated into SQL.
- Temp filename embeds `new_id()` — `VACUUM INTO` fails if the target exists,
  so uniqueness is the collision guard.
- Temp file is removed on every path: VACUUM error, read error, and success.
- The Mutex is held only for the `VACUUM INTO` call, not while reading/serving
  the file. Other requests block during the vacuum; that is accepted
  (same ceiling as every other handler, covered by the ponytail comment in §1).
- Whole file is buffered in memory. `// ponytail: full read into RAM; stream
  the file if backups outgrow memory.`

### Responses

- `200` — body: raw SQLite file bytes. Headers:
  `Content-Type: application/octet-stream`,
  `Content-Disposition: attachment; filename="rockbase_1755500000.db"`.
- `401` — no/wrong admin token: `{"code":401,"message":"admin token required"}`
  (same shape as `require_admin` everywhere else; a user `Bearer` JWT is 401
  too — this is admin-only).
- `500` — VACUUM or file IO failure: `{"code":500,"message":"<error>"}`.

## 3. Edge cases

- In-memory DB: `VACUUM INTO` produces a valid file from `:memory:`; the WAL
  pragma reports `"memory"` and is ignored. No special-casing anywhere.
- Empty DB backup is valid: still a real SQLite file with the schema.
- Concurrent requests during backup: block on the Mutex, then proceed;
  busy_timeout is irrelevant here (one connection) but protects any future
  second connection (e.g. a CLI poking the same file).

## 4. Acceptance tests

Add to the existing `mod tests` in `src/main.rs`. The `call` helper parses JSON
bodies, so the backup tests build requests with `oneshot` directly (or add a
`call_raw` returning `(StatusCode, HeaderMap, Vec<u8>)` — implementer's choice).

1. `GET /api/backups` with no auth header → 401, JSON error body.
2. `GET /api/backups` with a user `Bearer` token (sign up + login first) → 401.
3. `GET /api/backups` with `Admin testtoken` → 200; `content-type` is
   `application/octet-stream`; `content-disposition` starts with
   `attachment; filename="rockbase_` and ends `.db"`; body starts with the
   16-byte magic `b"SQLite format 3\0"`.
4. Round-trip: create a collection + one record, download backup, write bytes
   to a scratch file, `Connection::open` it, assert
   `SELECT COUNT(*) FROM records` matches and `_collections` contains the
   collection.
5. Temp cleanup: after a successful backup, `std::env::temp_dir()` contains no
   entry matching `rockbase_backup_*` (scan the dir; fresh ids make leftovers
   attributable).
6. Pragmas on file DB: `build_app(Connection::open(<scratch file>)...)`, then on
   a second `Connection::open` of the same path assert
   `PRAGMA journal_mode` returns `wal` (WAL persists in the file).
7. busy_timeout: open an in-memory connection, call `harden(&conn)`, assert
   `PRAGMA busy_timeout` returns 5000 (per-connection setting, so test the
   helper directly — `build_app` consumes its connection).
8. Existing `full_flow` test stays green, untouched.

Done when: all of the above pass under `cargo test` in the crate root.
