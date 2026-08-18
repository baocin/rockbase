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
    conn.query_row("SELECT value FROM _params WHERE key = ?1", [key], |r| r.get(0))
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
    conn.query_row("SELECT strftime('%Y-%m-%d %H:%M:%f', 'now')", [], |r| r.get(0))
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
}
