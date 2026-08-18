// Per-collection API rules (specs/rules.md).
//
// A rule is one of: NULL (admin only), "" (public), or a single comparison
// `lhs op rhs`. `@request.auth.id` is the caller's record id ("" for guests) and
// always travels as a SQL bind, never a textual splice — so it is safe in either
// operand slot. Field names are whitelist-checked (ident_ok) before they are
// interpolated into json_extract. Anything that does not resolve fails closed.
//
// ponytail: no SQLite type-coercion parity, single comparison only; swap for a
// shared rule VM if rules ever grow && / ||.

use axum::{http::StatusCode, Json};
use rusqlite::types::Value as SqlValue;
use serde_json::{json, Map, Value};

use crate::auth::Who;
use crate::{err, ident_ok};

pub const LIST: usize = 0;
pub const VIEW: usize = 1;
pub const CREATE: usize = 2;
pub const UPDATE: usize = 3;
pub const DELETE: usize = 4;

const TOKEN: &str = "@request.auth.id";
// two-char operators before their one-char prefixes, same order as the filter parser
const OPS: [&str; 6] = ["!=", ">=", "<=", "=", ">", "<"];

/// Split a rule into `(lhs, op, rhs)` at the first operator.
fn split_op(rule: &str) -> Option<(&str, &str, &str)> {
    let b = rule.as_bytes();
    (0..b.len()).find_map(|i| {
        OPS.into_iter()
            .find(|op| b[i..].starts_with(op.as_bytes()))
            // operators are ASCII, so `i` is always a char boundary
            .map(|op| (rule[..i].trim(), op, rule[i + op.len()..].trim()))
    })
}

/// `'x'` or `"x"` with no inner quote of the same kind. Anything else (trailing
/// SQL, a second literal) is not a literal and must not compile.
fn unquote(tok: &str) -> Option<&str> {
    let q = tok.chars().next().filter(|c| *c == '\'' || *c == '"')?;
    let inner = tok.strip_prefix(q)?.strip_suffix(q)?;
    (!inner.contains(q)).then_some(inner)
}

/// One operand: either raw SQL (a column reference) or a value to bind.
enum Side {
    Sql(String),
    Bind(SqlValue),
}

fn side_sql(tok: &str, auth_id: &str) -> Option<Side> {
    if tok == TOKEN {
        return Some(Side::Bind(auth_id.to_string().into()));
    }
    if let Some(s) = unquote(tok) {
        return Some(Side::Bind(s.to_string().into()));
    }
    match tok {
        "true" => return Some(Side::Bind(1i64.into())),
        "false" => return Some(Side::Bind(0i64.into())),
        _ => {}
    }
    if let Ok(n) = tok.parse::<i64>() {
        return Some(Side::Bind(n.into()));
    }
    if let Ok(f) = tok.parse::<f64>() {
        return Some(Side::Bind(f.into()));
    }
    match tok {
        "id" | "created" | "updated" => Some(Side::Sql(tok.to_string())),
        // ident_ok whitelists [A-Za-z0-9_], guarding this interpolation
        t if ident_ok(t) => Some(Side::Sql(format!("json_extract(data, '$.{t}')"))),
        _ => None,
    }
}

/// Compile a rule to a WHERE fragment (no leading AND) plus its binds, in
/// placeholder order. `None` = the rule is not a valid expression: fail closed.
pub fn compile_rule(rule: &str, auth_id: &str) -> Option<(String, Vec<SqlValue>)> {
    let (l, op, r) = split_op(rule)?;
    let sides = [side_sql(l, auth_id)?, side_sql(r, auth_id)?];
    let mut binds = Vec::new();
    let parts: Vec<String> = sides
        .into_iter()
        .map(|s| match s {
            Side::Sql(x) => x,
            Side::Bind(v) => {
                binds.push(v);
                "?".to_string()
            }
        })
        .collect();
    Some((format!("({} {op} {})", parts[0], parts[1]), binds))
}

fn side_mem(tok: &str, auth_id: &str, data: &Map<String, Value>) -> Option<Value> {
    if tok == TOKEN {
        return Some(json!(auth_id));
    }
    if let Some(s) = unquote(tok) {
        return Some(json!(s));
    }
    match tok {
        "true" => return Some(json!(true)),
        "false" => return Some(json!(false)),
        _ => {}
    }
    if let Ok(n) = tok.parse::<i64>() {
        return Some(json!(n));
    }
    if let Ok(f) = tok.parse::<f64>() {
        return Some(json!(f));
    }
    // id/created/updated are ordinary lookups: absent on create (the row does not
    // exist yet, so Null like any missing field), present when `data` is a full
    // record snapshot — which is what realtime gates delete events against.
    match tok {
        t if ident_ok(t) => Some(data.get(t).cloned().unwrap_or(Value::Null)),
        _ => None,
    }
}

/// Evaluate a rule against an in-memory record body — used by create, where no
/// row exists to run SQL against. Anything unresolvable is false (fail closed).
pub fn eval_rule_mem(rule: &str, auth_id: &str, data: &Map<String, Value>) -> bool {
    let Some((l, op, r)) = split_op(rule) else {
        return false;
    };
    let (Some(lv), Some(rv)) = (side_mem(l, auth_id, data), side_mem(r, auth_id, data)) else {
        return false;
    };
    match op {
        "=" => lv == rv,
        "!=" => lv != rv,
        // ordering only makes sense between two numbers
        _ => match (lv.as_f64(), rv.as_f64()) {
            (Some(a), Some(b)) => match op {
                ">" => a > b,
                ">=" => a >= b,
                "<" => a < b,
                _ => a <= b,
            },
            _ => false,
        },
    }
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
