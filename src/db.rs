use rusqlite::{params, Connection};
use serde_json::Value;

// ponytail: single Mutex<Connection> stays; swap for a pool (r2d2/deadpool) if
// concurrent throughput ever matters. WAL + busy_timeout is the cheap 90%.
pub fn harden(conn: &Connection) {
    conn.busy_timeout(std::time::Duration::from_millis(5000))
        .expect("busy_timeout");
    // The pragma returns the resulting mode ("wal" on file DBs, "memory" on
    // in-memory DBs — the latter is fine and needs no branching).
    let _mode: String = conn
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .expect("set journal_mode");
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
}

pub fn param_get_or_create(conn: &Connection, key: &str, default: &str) -> String {
    conn.execute(
        "INSERT OR IGNORE INTO _params(key, value) VALUES(?1, ?2)",
        params![key, default],
    )
    .unwrap();
    conn.query_row("SELECT value FROM _params WHERE key = ?1", [key], |r| r.get(0))
        .unwrap()
}

pub fn get_collection(conn: &Connection, name: &str) -> Option<(String, Vec<Value>)> {
    conn.query_row(
        "SELECT type, schema FROM _collections WHERE name = ?1",
        [name],
        |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
    )
    .ok()
    .map(|(t, s)| (t, serde_json::from_str(&s).unwrap_or_default()))
}

pub fn now(conn: &Connection) -> String {
    conn.query_row("SELECT datetime('now')", [], |r| r.get(0)).unwrap()
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
}
