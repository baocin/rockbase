// Per-collection API rules (specs/rules.md).
//
// A rule is one of: NULL (admin only), "" (public), or a boolean expression in
// the same grammar `filter=` uses — comparisons joined by `&&` / `||` with
// parentheses, parsed by src/filter.rs. `@request.auth.id` is the caller's record
// id ("" for guests) and always travels as a SQL bind, never a textual splice, in
// either operand slot. Field names are whitelist-checked (ident_ok) before they
// are interpolated into json_extract. Anything that does not parse fails closed.
//
// The SQL and in-memory paths walk the SAME parse tree (filter::Node), so they
// cannot disagree about precedence, short-circuiting or numeric coercion.

use axum::{http::StatusCode, Json};
use rusqlite::types::Value as SqlValue;
use serde_json::{Map, Value};

use crate::auth::Who;
use crate::err;
use crate::filter::{parse, Mode};

pub const LIST: usize = 0;
pub const VIEW: usize = 1;
pub const CREATE: usize = 2;
pub const UPDATE: usize = 3;
pub const DELETE: usize = 4;

/// Compile a rule to a WHERE fragment (no leading AND) plus its binds, in
/// placeholder order. `None` = the rule is not a valid expression: fail closed.
pub fn compile_rule(rule: &str, auth_id: &str) -> Option<(String, Vec<SqlValue>)> {
    Some(parse(rule, Mode::Rule).ok()?.to_sql(auth_id))
}

/// Evaluate a rule against an in-memory record body — used by create, where no
/// row exists to run SQL against. Anything unparseable is false (fail closed).
pub fn eval_rule_mem(rule: &str, auth_id: &str, data: &Map<String, Value>) -> bool {
    parse(rule, Mode::Rule).is_ok_and(|n| n.eval(auth_id, data))
}

/// Guest denials are 401, authenticated ones 403.
pub fn deny(who: &Who) -> (StatusCode, Json<Value>) {
    match who {
        Who::Guest => err(StatusCode::UNAUTHORIZED, "not allowed"),
        _ => err(StatusCode::FORBIDDEN, "not allowed"),
    }
}

pub fn auth_id(who: &Who) -> &str {
    match who {
        Who::User { id, .. } => id,
        _ => "",
    }
}

/// The gate. `Ok(None)` = allowed outright (admin, or a public rule).
/// `Ok(Some(expr))` = the caller must still enforce `expr`.
pub fn check_rule(
    who: &Who,
    rule: &Option<String>,
) -> Result<Option<String>, (StatusCode, Json<Value>)> {
    match who {
        Who::Admin => Ok(None),
        _ => match rule.as_deref() {
            None => Err(deny(who)),        // NULL = admin only
            Some("") => Ok(None),          // empty = public
            Some(r) => Ok(Some(r.into())), // expression: caller enforces
        },
    }
}

/// Per-type defaults, in LIST/VIEW/CREATE/UPDATE/DELETE order. Base reproduces
/// the pre-rules behavior; auth is public signup + admin-only reads + own-record writes.
pub fn defaults(ty: &str) -> [Option<String>; 5] {
    let own = || Some("id = @request.auth.id".to_string());
    let authed = || Some("@request.auth.id != ''".to_string());
    match ty {
        "auth" => [None, None, Some(String::new()), own(), own()],
        _ => [
            Some(String::new()),
            Some(String::new()),
            authed(),
            authed(),
            authed(),
        ],
    }
}
