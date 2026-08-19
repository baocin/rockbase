use std::ops::{Deref, DerefMut};
use std::sync::{Condvar, Mutex};

use rusqlite::{params, Connection, OpenFlags};
use serde_json::Value;

/// Run on EVERY connection the pool opens, not once per database: `busy_timeout`
/// is per-connection state, and `journal_mode` is a no-op re-assertion on a file
/// db that has already been switched to WAL.
pub fn harden(conn: &Connection) {
    conn.busy_timeout(std::time::Duration::from_millis(5000))
        .expect("busy_timeout");
    // The pragma returns the resulting mode ("wal" on file DBs, "memory" on
    // in-memory DBs — the latter is fine and needs no branching).
    let _mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .expect("set journal_mode");
}

// --------------------------------------------------------------------- pool

/// Hand-rolled: `r2d2_sqlite` wants rusqlite 0.40 and we are pinned to 0.32.
/// A stack of idle connections plus a condvar is the whole thing — checkout pops,
/// the guard's `Drop` pushes back.
pub struct Pool {
    idle: Mutex<Vec<Connection>>,
    ready: Condvar,
    /// A shared-cache in-memory database lives exactly as long as its last open
    /// connection, so the pool keeps one it never hands out. The `Mutex` is only
    /// there to make `Pool` `Sync` — the connection is never locked or used.
    _keepalive: Mutex<Connection>,
}

/// Default `available_parallelism()`, clamped; `RB_POOL_SIZE` overrides. The floor
/// of 2 keeps the pool a pool — one connection is just the old mutex with extra steps.
pub fn pool_size() -> usize {
    std::env::var("RB_POOL_SIZE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()))
        .clamp(2, 16)
}

fn open_one(spec: &str) -> Connection {
    let conn = if spec.starts_with("file:") {
        Connection::open_with_flags(spec, OpenFlags::default() | OpenFlags::SQLITE_OPEN_URI)
    } else {
        Connection::open(spec)
    }
    .unwrap_or_else(|e| panic!("open database {spec}: {e}"));
    harden(&conn);
    conn
}

impl Pool {
    /// `db` is a filesystem path or `":memory:"`.
    pub fn open(db: &str, size: usize) -> Pool {
        // N plain `:memory:` connections would be N separate EMPTY databases, so an
        // in-memory pool shares one cache under a name unique to this pool — two
        // `build_app`s in one test binary must not land in the same database.
        let (spec, in_memory) = match db {
            ":memory:" => (
                format!(
                    "file:rockbase_{}?mode=memory&cache=shared",
                    uuid::Uuid::new_v4().simple()
                ),
                true,
            ),
            path => (path.to_string(), false),
        };
        // ponytail: in-memory pools are pinned to one connection. Shared-cache
        // SQLite answers a cross-connection conflict with SQLITE_LOCKED, which
        // `busy_timeout` does NOT retry (unlike SQLITE_BUSY on a file db) — fixing
        // it needs sqlite3_unlock_notify, a rusqlite feature we cannot turn on.
        // Nothing real is lost: in-memory SQLite reports `journal_mode=memory`, so
        // there was never any WAL concurrency there to serve — use a file db for that.
        let size = if in_memory { 1 } else { size.max(1) };
        Pool {
            _keepalive: Mutex::new(open_one(&spec)),
            idle: Mutex::new((0..size).map(|_| open_one(&spec)).collect()),
            ready: Condvar::new(),
        }
    }

    /// Blocks until a connection is free. Never spins, never fails.
    pub fn get(&self) -> PoolConn<'_> {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match idle.pop() {
                Some(conn) => {
                    return PoolConn {
                        pool: self,
                        conn: Some(conn),
                    }
                }
                None => idle = self.ready.wait(idle).unwrap_or_else(|e| e.into_inner()),
            }
        }
    }
}

/// A checked-out connection. `DerefMut` exists because `batch` needs
/// `Connection::transaction`, which takes `&mut`.
pub struct PoolConn<'a> {
    pool: &'a Pool,
    conn: Option<Connection>,
}

impl Deref for PoolConn<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.conn.as_ref().expect("connection already returned")
    }
}

impl DerefMut for PoolConn<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        self.conn.as_mut().expect("connection already returned")
    }
}

impl Drop for PoolConn<'_> {
    /// Runs on every exit path a handler can take — including `?` and a panic — so
    /// an early return can never leak a connection out of the pool.
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool
                .idle
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(conn);
            self.pool.ready.notify_one();
        }
    }
}

pub fn init_db(conn: &Connection) {
    // ponytail: one records table + JSON1, not table-per-collection; real columns when perf matters
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _collections(
            name   TEXT PRIMARY KEY,
            type   TEXT NOT NULL DEFAULT 'base',
            schema TEXT NOT NULL DEFAULT '[]'
        );
        CREATE TABLE IF NOT EXISTS _params(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS records(
            collection TEXT NOT NULL,
            id         TEXT NOT NULL,
            data       TEXT NOT NULL,
            created    TEXT NOT NULL,
            updated    TEXT NOT NULL,
            PRIMARY KEY(collection, id)
        );",
    )
    .expect("init schema");
    conn.execute(
        "INSERT OR IGNORE INTO _collections(name, type, schema) VALUES('users','auth','[]')",
        [],
    )
    .expect("seed users");
    // after the users seed, so a fresh DB seeds the collection then its rules in one pass
    migrate_rules(conn);
}

/// Add the five rule columns and seed per-type defaults, once. The pragma guard means
/// re-running init never clobbers rules an admin has since edited.
fn migrate_rules(conn: &Connection) {
    let migrated: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pragma_table_info('_collections') WHERE name = 'list_rule'",
            [],
            |r| r.get(0),
        )
        .expect("check rule columns");
    if migrated > 0 {
        return;
    }
    conn.execute_batch(
        "ALTER TABLE _collections ADD COLUMN list_rule TEXT;
         ALTER TABLE _collections ADD COLUMN view_rule TEXT;
         ALTER TABLE _collections ADD COLUMN create_rule TEXT;
         ALTER TABLE _collections ADD COLUMN update_rule TEXT;
         ALTER TABLE _collections ADD COLUMN delete_rule TEXT;
         UPDATE _collections SET list_rule = '', view_rule = '',
             create_rule = '@request.auth.id != ''''',
             update_rule = '@request.auth.id != ''''',
             delete_rule = '@request.auth.id != ''''' WHERE type = 'base';
         UPDATE _collections SET create_rule = '', list_rule = NULL, view_rule = NULL,
             update_rule = 'id = @request.auth.id',
             delete_rule = 'id = @request.auth.id' WHERE type = 'auth';",
    )
    .expect("migrate rules");
}

pub fn param_get_or_create(conn: &Connection, key: &str, default: &str) -> String {
    conn.execute(
        "INSERT OR IGNORE INTO _params(key, value) VALUES(?1, ?2)",
        params![key, default],
    )
    .unwrap();
    conn.query_row("SELECT value FROM _params WHERE key = ?1", [key], |r| {
        r.get(0)
    })
    .unwrap()
}

/// A collection row. `rules` is indexed by the LIST/VIEW/CREATE/UPDATE/DELETE
/// constants in `crate::rules`; None = admin only, Some("") = public.
pub struct Col {
    pub ty: String,
    pub schema: Vec<Value>,
    pub rules: [Option<String>; 5],
}

pub fn get_collection(conn: &Connection, name: &str) -> Option<Col> {
    conn.query_row(
        "SELECT type, schema, list_rule, view_rule, create_rule, update_rule, delete_rule \
         FROM _collections WHERE name = ?1",
        [name],
        |r| {
            Ok(Col {
                ty: r.get(0)?,
                schema: serde_json::from_str(&r.get::<_, String>(1)?).unwrap_or_default(),
                rules: [r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?],
            })
        },
    )
    .ok()
}

pub fn now(conn: &Connection) -> String {
    // Millisecond resolution, fixed width, so lexicographic ordering == chronological.
    // Plain datetime('now') is second-resolution: records created in the same second
    // tied under ORDER BY created, and pagination could repeat or skip rows.
    conn.query_row("SELECT strftime('%Y-%m-%d %H:%M:%f', 'now')", [], |r| {
        r.get(0)
    })
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harden_sets_busy_timeout() {
        let conn = Connection::open_in_memory().unwrap();
        harden(&conn);
        let t: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap();
        assert_eq!(t, 5000);
    }

    /// The claim HTTP cannot make: two connections, live at the same time, in one
    /// scope. This does not even compile against a `Mutex<Connection>`.
    ///
    /// File-backed on purpose — an in-memory pool is deliberately size 1 (see
    /// `Pool::open`), so it can prove nothing about parallelism.
    #[test]
    fn pool_hands_out_two_live_independent_connections() {
        let path = std::env::temp_dir().join(format!(
            "rockbase_pooltest_{}.db",
            uuid::Uuid::new_v4().simple()
        ));
        let pool = std::sync::Arc::new(Pool::open(path.to_str().unwrap(), 2));

        // (1) both checked out at once, both usable
        let a = pool.get();
        let b = pool.get();
        a.execute_batch("CREATE TEMP TABLE only_on_a(x)")
            .expect("write on guard a");
        let one: i64 = b
            .query_row("SELECT 1", [], |r| r.get(0))
            .expect("read on b");
        assert_eq!(one, 1);

        // (2) different connections — TEMP tables are per-connection, so `a`'s is
        // invisible from `b` unless the pool handed out the same handle twice
        let seen: i64 = b
            .query_row(
                "SELECT COUNT(*) FROM temp.sqlite_master WHERE name = 'only_on_a'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(seen, 0, "both guards wrap the SAME connection");

        // (4) harden() ran on every pooled connection, not just the first
        for (which, g) in [("a", &a), ("b", &b)] {
            let t: i64 = g
                .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
                .unwrap();
            assert_eq!(t, 5000, "connection {which} was not hardened");
        }

        // (3) pool exhausted: a third checkout blocks, then succeeds once one is back
        let (tx, rx) = std::sync::mpsc::channel();
        let p = pool.clone();
        let waiter = std::thread::spawn(move || {
            let g = p.get();
            let _ = tx.send(g.query_row("SELECT 2", [], |r| r.get::<_, i64>(0)).unwrap());
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(250))
                .is_err(),
            "checkout succeeded against an exhausted pool"
        );
        drop(a);
        assert_eq!(
            rx.recv_timeout(std::time::Duration::from_secs(5))
                .expect("returning a connection must unblock the waiting checkout"),
            2
        );
        waiter.join().unwrap();

        drop(b);
        drop(pool);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }
}
