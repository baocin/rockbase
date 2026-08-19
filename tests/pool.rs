// Connection pooling (replacing `App { db: Mutex<Connection> }`) — TDD guard rails.
//
// WHAT THIS FILE CAN AND CANNOT PROVE
//
// A pool and a single mutexed connection are behaviourally IDENTICAL over HTTP
// except for throughput. There is no deterministic HTTP-level assertion that
// distinguishes "ran in parallel" from "ran one at a time" — only wall-clock
// comparisons can, and those flake on CI. So this file deliberately does NOT
// assert speed or overlap.
//
// What it does assert is the risk the change actually introduces: a pool means
// N connections, so writes can now collide (SQLITE_BUSY), a batch's transaction
// now competes with other connections rather than owning the only one, and
// reads can now observe the DB mid-write. All of that must stay correct.
//
// Consequence: most tests here PASS against today's single mutex (which is
// correct, just serialized). They are the regression suite the pool must not
// break. Real parallelism must be proven by a `#[test]` inside `src/` that
// checks out two connections at once and uses both — impossible to express
// against a `Mutex<Connection>`, and out of scope for this file.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use rusqlite::Connection;
use serde_json::{json, Value};
use tower::ServiceExt;

use rockbase::build_app;

const ADMIN: &str = "Admin testtoken";

/// Every concurrent body runs inside this, so a serialization bug in the pool
/// shows up as a failed test rather than a hung `cargo test`.
const DEADLINE: Duration = Duration::from_secs(60);

fn app_mem() -> Router {
    std::env::set_var("RB_JWT_SECRET", "testsecret");
    build_app(Connection::open_in_memory().unwrap(), "testtoken".into())
}

/// A file-backed DB — the only place WAL and real multi-connection locking exist.
/// In-memory SQLite reports `journal_mode=memory` and (today) is a single handle,
/// so the file cases below are where a pool can genuinely misbehave.
struct TempDb(std::path::PathBuf);

impl TempDb {
    fn new() -> Self {
        TempDb(std::env::temp_dir().join(format!(
            "rockbase_pool_{}.db",
            uuid::Uuid::new_v4().simple()
        )))
    }
    fn app(&self) -> Router {
        std::env::set_var("RB_JWT_SECRET", "testsecret");
        build_app(Connection::open(&self.0).unwrap(), "testtoken".into())
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let mut p = self.0.clone().into_os_string();
            p.push(suffix);
            let _ = std::fs::remove_file(std::path::PathBuf::from(p));
        }
    }
}

/// Owned args so the future is `'static` and can go into `tokio::spawn`.
async fn call_owned(
    app: Router,
    method: &'static str,
    uri: String,
    auth: Option<String>,
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
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let val = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, val)
}

async fn call(
    app: &Router,
    method: &'static str,
    uri: &str,
    auth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    call_owned(
        app.clone(),
        method,
        uri.to_string(),
        auth.map(str::to_string),
        body,
    )
    .await
}

/// `posts` with a numeric `n`, a `tag`, and two fields derived from `n`.
/// The derived fields are the partial-write detector: any record a reader sees
/// must satisfy `dbl == 2*n` and `trp == 3*n`.
async fn mkposts(app: &Router) {
    let (s, v) = call(
        app,
        "POST",
        "/api/collections",
        Some(ADMIN),
        Some(json!({
            "name": "posts",
            "schema": [
                {"name": "n", "type": "number"},
                {"name": "dbl", "type": "number"},
                {"name": "trp", "type": "number"},
                {"name": "tag", "type": "text"}
            ]
        })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "create posts collection: {v}");
}

fn post_body(n: i64, tag: &str) -> Value {
    json!({ "n": n, "dbl": n * 2, "trp": n * 3, "tag": tag })
}

/// Every record must be whole and self-consistent — no half-written row, ever.
fn assert_whole(rec: &Value) {
    assert!(rec["id"].is_string(), "record missing id: {rec}");
    assert!(rec["created"].is_string(), "record missing created: {rec}");
    assert!(rec["updated"].is_string(), "record missing updated: {rec}");
    let n = rec["n"].as_i64().unwrap_or_else(|| panic!("no n: {rec}"));
    assert_eq!(rec["dbl"].as_i64(), Some(n * 2), "torn record: {rec}");
    assert_eq!(rec["trp"].as_i64(), Some(n * 3), "torn record: {rec}");
    assert!(rec["tag"].is_string(), "record missing tag: {rec}");
}

/// All posts, one page (callers stay under the 500 perPage cap).
async fn all_posts(app: &Router) -> Vec<Value> {
    let (s, v) = call(
        app,
        "GET",
        "/api/collections/posts/records?perPage=500",
        Some(ADMIN),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "list posts: {v}");
    v["items"].as_array().cloned().unwrap_or_default()
}

fn ids(items: &[Value]) -> std::collections::HashSet<String> {
    items
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------------------

/// WAL must survive the swap. Today one connection sets it; a pool must set it
/// on EVERY connection it hands out (and `busy_timeout`, or concurrent writers
/// will start returning SQLITE_BUSY instead of waiting).
///
/// Checked from an independent connection, because `journal_mode=WAL` is
/// persisted in the file header — so this reads the server's real effect on the
/// database, not the pragma we just ran.
#[tokio::test]
async fn wal_still_enabled_on_a_file_backed_db() {
    let tmp = TempDb::new();
    let app = tmp.app();
    mkposts(&app).await;
    let (s, _) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(post_body(1, "wal")),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let probe = Connection::open(&tmp.0).unwrap();
    let mode: String = probe
        .query_row("PRAGMA journal_mode", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal", "journal_mode must stay WAL");
}

/// N concurrent creates -> N successes, N distinct ids, N rows. Nothing lost,
/// nothing duplicated, no 5xx. Under a pool these are separate connections
/// racing for the write lock, and much of the handler code `.unwrap()`s or
/// 500s on a SQLite error, so this is the headline risk of the change.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_creates_all_succeed_and_produce_exactly_n_records() {
    const N: i64 = 64;
    let app = app_mem();
    mkposts(&app).await;

    tokio::time::timeout(DEADLINE, async {
        let mut handles = Vec::new();
        for n in 0..N {
            let a = app.clone();
            handles.push(tokio::spawn(async move {
                call_owned(
                    a,
                    "POST",
                    "/api/collections/posts/records".into(),
                    Some(ADMIN.into()),
                    Some(post_body(n, "conc")),
                )
                .await
            }));
        }
        let mut created = std::collections::HashSet::new();
        for h in handles {
            let (s, v) = h.await.expect("create task panicked");
            assert_eq!(s, StatusCode::OK, "concurrent create failed: {v}");
            assert_whole(&v);
            assert!(
                created.insert(v["id"].as_str().unwrap().to_string()),
                "duplicate id handed out: {v}"
            );
        }
        assert_eq!(created.len() as i64, N);
    })
    .await
    .expect("concurrent creates did not finish within the deadline");

    let items = all_posts(&app).await;
    assert_eq!(items.len() as i64, N, "expected exactly {N} rows");
    assert_eq!(ids(&items).len() as i64, N, "ids must be distinct");
    for it in &items {
        assert_whole(it);
    }
}

/// Readers running against the DB while writers commit must never observe a
/// record that is missing fields or whose derived fields disagree with `n`.
/// With a pool the readers are on their own connections, so this is the first
/// time a read can actually land mid-write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_reads_during_writes_never_see_a_partial_record() {
    const WRITERS: i64 = 40;
    const READERS: usize = 40;
    let app = app_mem();
    mkposts(&app).await;

    let seen = Arc::new(std::sync::Mutex::new(0usize));

    tokio::time::timeout(DEADLINE, async {
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        for n in 0..WRITERS {
            let a = app.clone();
            handles.push(tokio::spawn(async move {
                let (s, v) = call_owned(
                    a,
                    "POST",
                    "/api/collections/posts/records".into(),
                    Some(ADMIN.into()),
                    Some(post_body(n, "rw")),
                )
                .await;
                assert_eq!(s, StatusCode::OK, "write during reads failed: {v}");
            }));
        }
        for _ in 0..READERS {
            let a = app.clone();
            let seen = seen.clone();
            handles.push(tokio::spawn(async move {
                let (s, v) = call_owned(
                    a,
                    "GET",
                    "/api/collections/posts/records?perPage=500".into(),
                    Some(ADMIN.into()),
                    None,
                )
                .await;
                assert_eq!(s, StatusCode::OK, "read during writes failed: {v}");
                let items = v["items"].as_array().cloned().unwrap_or_default();
                // totalItems is a separate COUNT query from the page query; it may
                // legitimately differ from items.len() when a write commits between
                // them, so only the per-record invariant is asserted here.
                for it in &items {
                    assert_whole(it);
                }
                *seen.lock().unwrap() += items.len();
            }));
        }
        for h in handles {
            h.await.expect("reader/writer task panicked");
        }
    })
    .await
    .expect("mixed read/write load did not finish within the deadline");

    let items = all_posts(&app).await;
    assert_eq!(items.len() as i64, WRITERS);
    assert!(
        *seen.lock().unwrap() > 0,
        "readers observed nothing — the load pattern is not exercising reads"
    );
}

/// Distinct rows patched concurrently: every PATCH applies, none clobbers
/// another, and the row count is unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_updates_to_distinct_records_all_apply() {
    const N: i64 = 32;
    let app = app_mem();
    mkposts(&app).await;

    let mut created = Vec::new();
    for n in 0..N {
        let (s, v) = call(
            &app,
            "POST",
            "/api/collections/posts/records",
            Some(ADMIN),
            Some(post_body(n, "pre")),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "seed: {v}");
        created.push(v["id"].as_str().unwrap().to_string());
    }

    tokio::time::timeout(DEADLINE, async {
        let mut handles = Vec::new();
        for (i, id) in created.iter().enumerate() {
            let a = app.clone();
            let uri = format!("/api/collections/posts/records/{id}");
            let n = 1000 + i as i64;
            handles.push(tokio::spawn(async move {
                call_owned(
                    a,
                    "PATCH",
                    uri,
                    Some(ADMIN.into()),
                    Some(post_body(n, "post")),
                )
                .await
            }));
        }
        for h in handles {
            let (s, v) = h.await.expect("update task panicked");
            assert_eq!(s, StatusCode::OK, "concurrent update failed: {v}");
            assert_whole(&v);
        }
    })
    .await
    .expect("concurrent updates did not finish within the deadline");

    let items = all_posts(&app).await;
    assert_eq!(items.len() as i64, N, "updates must not change row count");
    let mut ns: Vec<i64> = items.iter().map(|i| i["n"].as_i64().unwrap()).collect();
    ns.sort_unstable();
    assert_eq!(
        ns,
        (1000..1000 + N).collect::<Vec<_>>(),
        "every concurrent PATCH must have landed exactly once"
    );
    for it in &items {
        assert_eq!(it["tag"], "post");
        assert_whole(it);
    }
}

/// Concurrent deletes of half the rows: every DELETE returns 200 exactly once
/// and precisely the other half survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_deletes_leave_exactly_the_untouched_records() {
    const N: i64 = 40;
    let app = app_mem();
    mkposts(&app).await;

    let mut created = Vec::new();
    for n in 0..N {
        let (s, v) = call(
            &app,
            "POST",
            "/api/collections/posts/records",
            Some(ADMIN),
            Some(post_body(n, "del")),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "seed: {v}");
        created.push((n, v["id"].as_str().unwrap().to_string()));
    }
    let doomed: Vec<(i64, String)> = created
        .iter()
        .filter(|(n, _)| n % 2 == 0)
        .cloned()
        .collect();

    tokio::time::timeout(DEADLINE, async {
        let mut handles = Vec::new();
        for (_, id) in &doomed {
            let a = app.clone();
            let uri = format!("/api/collections/posts/records/{id}");
            handles.push(tokio::spawn(async move {
                call_owned(a, "DELETE", uri, Some(ADMIN.into()), None).await
            }));
        }
        for h in handles {
            let (s, v) = h.await.expect("delete task panicked");
            assert_eq!(s, StatusCode::OK, "concurrent delete failed: {v}");
        }
    })
    .await
    .expect("concurrent deletes did not finish within the deadline");

    let items = all_posts(&app).await;
    let mut ns: Vec<i64> = items.iter().map(|i| i["n"].as_i64().unwrap()).collect();
    ns.sort_unstable();
    assert_eq!(
        ns,
        (0..N).filter(|n| n % 2 == 1).collect::<Vec<_>>(),
        "exactly the odd-numbered records must survive"
    );
}

/// A batch holds a rusqlite `Transaction`, so it needs MUTABLE access to a
/// connection — the one place the pool cannot hand out a shared borrow. Its
/// rollback must still be total while unrelated writes are in flight on other
/// connections, and it must not take those writes down with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_rolls_back_completely_while_other_writes_are_in_flight() {
    const SOLO: i64 = 24;
    let app = app_mem();
    mkposts(&app).await;

    // sub-request 0 and 1 are valid; 2 targets a collection that does not exist
    let batch_body = json!({"requests": [
        {"method": "POST", "url": "/api/collections/posts/records", "body": post_body(1, "batch")},
        {"method": "POST", "url": "/api/collections/posts/records", "body": post_body(2, "batch")},
        {"method": "POST", "url": "/api/collections/nope/records",  "body": post_body(3, "batch")},
    ]});

    tokio::time::timeout(DEADLINE, async {
        let mut handles = Vec::new();
        for n in 100..100 + SOLO {
            let a = app.clone();
            handles.push(tokio::spawn(async move {
                call_owned(
                    a,
                    "POST",
                    "/api/collections/posts/records".into(),
                    Some(ADMIN.into()),
                    Some(post_body(n, "solo")),
                )
                .await
            }));
        }
        let b = app.clone();
        let batch = tokio::spawn(async move {
            call_owned(
                b,
                "POST",
                "/api/batch".into(),
                Some(ADMIN.into()),
                Some(batch_body),
            )
            .await
        });

        let (s, v) = batch.await.expect("batch task panicked");
        // assert the failure shape first, so a broken route cannot make the
        // "no rows written" assertion below pass vacuously
        assert_eq!(s, StatusCode::BAD_REQUEST, "batch should fail: {v}");
        assert_eq!(v["index"], 2, "failure must be reported at index 2: {v}");

        for h in handles {
            let (s, v) = h.await.expect("solo create task panicked");
            assert_eq!(s, StatusCode::OK, "solo write lost to the batch: {v}");
        }
    })
    .await
    .expect("batch + concurrent writes did not finish within the deadline");

    let items = all_posts(&app).await;
    assert!(
        items.iter().all(|i| i["tag"] == "solo"),
        "the batch must have rolled back entirely: {:?}",
        items
            .iter()
            .filter(|i| i["tag"] != "solo")
            .collect::<Vec<_>>()
    );
    assert_eq!(items.len() as i64, SOLO, "only the solo writes survive");

    // and prove sub-request 0 was valid on its own — its absence is rollback,
    // not invalidity
    let (s, v) = call(
        &app,
        "POST",
        "/api/collections/posts/records",
        Some(ADMIN),
        Some(post_body(1, "batch")),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "batch sub-request 0 was valid: {v}");
}

/// The same shape on a real file + WAL, where a pool means genuinely separate
/// SQLite write locks: a committing transaction and N individual writers must
/// all succeed (busy_timeout doing its job) and the totals must be exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn batch_commits_alongside_concurrent_writers_on_a_file_db() {
    const IN_BATCH: i64 = 20;
    const SOLO: i64 = 20;
    let tmp = TempDb::new();
    let app = tmp.app();
    mkposts(&app).await;

    let reqs: Vec<Value> = (0..IN_BATCH)
        .map(|n| {
            json!({"method": "POST", "url": "/api/collections/posts/records", "body": post_body(n, "batch")})
        })
        .collect();

    tokio::time::timeout(DEADLINE, async {
        let mut handles = Vec::new();
        for n in 100..100 + SOLO {
            let a = app.clone();
            handles.push(tokio::spawn(async move {
                call_owned(
                    a,
                    "POST",
                    "/api/collections/posts/records".into(),
                    Some(ADMIN.into()),
                    Some(post_body(n, "solo")),
                )
                .await
            }));
        }
        let b = app.clone();
        let batch = tokio::spawn(async move {
            call_owned(
                b,
                "POST",
                "/api/batch".into(),
                Some(ADMIN.into()),
                Some(json!({ "requests": reqs })),
            )
            .await
        });

        let (s, v) = batch.await.expect("batch task panicked");
        assert_eq!(s, StatusCode::OK, "batch must commit under load: {v}");
        assert_eq!(v.as_array().map(|a| a.len()), Some(IN_BATCH as usize));

        for h in handles {
            let (s, v) = h.await.expect("solo create task panicked");
            assert_eq!(s, StatusCode::OK, "solo write failed under load: {v}");
        }
    })
    .await
    .expect("batch + concurrent writers did not finish within the deadline");

    let items = all_posts(&app).await;
    assert_eq!(items.len() as i64, IN_BATCH + SOLO);
    assert_eq!(ids(&items).len() as i64, IN_BATCH + SOLO);
    assert_eq!(
        items.iter().filter(|i| i["tag"] == "batch").count() as i64,
        IN_BATCH
    );
    for it in &items {
        assert_whole(it);
    }
}

/// Mixed load on a file-backed WAL database — the configuration a pool exists
/// for. Every request must succeed (no SQLITE_BUSY leaking out as a 500) and
/// the final state must be exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn file_backed_db_stays_correct_under_mixed_concurrent_load() {
    const WRITERS: i64 = 48;
    let tmp = TempDb::new();
    let app = tmp.app();
    mkposts(&app).await;

    tokio::time::timeout(DEADLINE, async {
        let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        for n in 0..WRITERS {
            let a = app.clone();
            handles.push(tokio::spawn(async move {
                let (s, v) = call_owned(
                    a,
                    "POST",
                    "/api/collections/posts/records".into(),
                    Some(ADMIN.into()),
                    Some(post_body(n, "mix")),
                )
                .await;
                assert_eq!(s, StatusCode::OK, "write under file-db load failed: {v}");
            }));
            let a = app.clone();
            handles.push(tokio::spawn(async move {
                let (s, v) = call_owned(
                    a,
                    "GET",
                    "/api/collections/posts/records?perPage=500&sort=-created".into(),
                    Some(ADMIN.into()),
                    None,
                )
                .await;
                assert_eq!(s, StatusCode::OK, "read under file-db load failed: {v}");
                for it in v["items"].as_array().cloned().unwrap_or_default() {
                    assert_whole(&it);
                }
            }));
            let a = app.clone();
            handles.push(tokio::spawn(async move {
                let (s, v) = call_owned(
                    a,
                    "GET",
                    "/api/collections".into(),
                    Some(ADMIN.into()),
                    None,
                )
                .await;
                assert_eq!(s, StatusCode::OK, "collections read under load failed: {v}");
            }));
        }
        for h in handles {
            h.await.expect("task panicked under file-db load");
        }
    })
    .await
    .expect("mixed file-db load did not finish within the deadline");

    let items = all_posts(&app).await;
    assert_eq!(items.len() as i64, WRITERS);
    assert_eq!(ids(&items).len() as i64, WRITERS);
    let mut ns: Vec<i64> = items.iter().map(|i| i["n"].as_i64().unwrap()).collect();
    ns.sort_unstable();
    assert_eq!(ns, (0..WRITERS).collect::<Vec<_>>());
}
