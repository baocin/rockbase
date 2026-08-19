// PocketBase-style filter expressions compiled to parameterized SQL.
// ONE parser, two consumers: `filter=` on record lists and the per-collection API
// rules in src/rules.rs. Grammar and compilation rules: specs/filter.md.
// Parsing yields a `Node` tree with two backends — `to_sql` for the SQL paths
// (list / view / update / delete) and `eval` for the in-memory path (create, SSE),
// so both can never disagree about precedence or short-circuiting.
// Trust boundary: field names are whitelist-checked (ident_ok) before
// interpolation; values ALWAYS travel as binds, never in the SQL string.

use rusqlite::types::Value;
use serde_json::{Map, Value as Json};

use crate::ident_ok;

const MAX_LEN: usize = 2048;
const MAX_DEPTH: u32 = 32;
const TOKEN: &str = "@request.auth.id";

/// The only place the two dialects differ: a bare, unquoted, non-numeric word.
/// `title=rock` in a filter is the literal "rock"; `@request.auth.id = author`
/// in a rule is a column reference. Everything else parses identically.
#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    Filter,
    Rule,
}

pub enum Operand {
    /// ident_ok-checked field name
    Col(String),
    /// `@request.auth.id` — always a bind carrying the caller's id, never text
    Auth,
    Val(Value),
    Null,
}

pub enum Node {
    Or(Box<Node>, Box<Node>),
    And(Box<Node>, Box<Node>),
    Cmp(Operand, &'static str, Operand),
}

/// Parse an expression. Every operand is resolved here, so a successful parse
/// always compiles and always evaluates — which is what lets `read_rule` validate
/// a stored rule by parsing it once, with no caller in hand.
pub fn parse(input: &str, mode: Mode) -> Result<Node, String> {
    if input.len() > MAX_LEN {
        return Err("filter too long".into());
    }
    let mut p = Parser { b: input.as_bytes(), i: 0, mode };
    let n = p.expr(0)?;
    p.ws();
    if p.i < p.b.len() {
        return Err(format!("unexpected trailing input at byte {}", p.i));
    }
    Ok(n)
}

/// Compile a filter expression to a WHERE fragment (no leading AND) and its
/// binds, in placeholder order.
pub fn compile(input: &str) -> Result<(String, Vec<Value>), String> {
    Ok(parse(input, Mode::Filter)?.to_sql(""))
}

impl Operand {
    /// SQL text for this operand, pushing a bind if it carries a value.
    fn sql(&self, auth: &str, binds: &mut Vec<Value>) -> String {
        match self {
            // ident_ok whitelists [A-Za-z0-9_], guarding this interpolation
            Operand::Col(f) => match f.as_str() {
                "id" | "created" | "updated" => f.clone(),
                _ => format!("json_extract(data, '$.{f}')"),
            },
            Operand::Auth => {
                binds.push(Value::Text(auth.to_string()));
                "?".into()
            }
            Operand::Val(v) => {
                binds.push(v.clone());
                "?".into()
            }
            Operand::Null => "NULL".into(),
        }
    }

    /// id/created/updated are ordinary lookups: absent on create (the row does not
    /// exist yet, so Null like any missing field), present when `data` is a full
    /// record snapshot — which is what realtime gates delete events against.
    fn json(&self, auth: &str, data: &Map<String, Json>) -> Json {
        match self {
            Operand::Col(f) => data.get(f).cloned().unwrap_or(Json::Null),
            Operand::Auth => Json::String(auth.to_string()),
            Operand::Val(Value::Text(s)) => Json::String(s.clone()),
            Operand::Val(Value::Integer(n)) => (*n).into(),
            Operand::Val(Value::Real(f)) => serde_json::json!(f),
            _ => Json::Null,
        }
    }
}

/// SQLite-ish numeric view of a JSON value: booleans are 1/0, so `flag = true`
/// and `score = 1` both compare numerically — the same coercion the SQL path gets
/// for free, which is what keeps the two paths from granting different things.
fn num(v: &Json) -> Option<f64> {
    match v {
        Json::Bool(b) => Some(*b as u8 as f64),
        _ => v.as_f64(),
    }
}

fn text(v: &Json) -> String {
    match v {
        Json::String(s) => s.clone(),
        _ => v.to_string(),
    }
}

/// Escape LIKE metacharacters so a `~` value matches literally, mirroring `eval`'s
/// substring test. Paired with `ESCAPE '\\'` in the emitted SQL.
fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl Node {
    /// A WHERE fragment plus its binds, in placeholder order. Callers AND it into
    /// a larger WHERE, so a top-level OR is parenthesised here — otherwise
    /// `collection = ? AND id = ? AND a OR b` would let `b` alone grant access.
    pub fn to_sql(&self, auth_id: &str) -> (String, Vec<Value>) {
        let (mut sql, mut binds) = (String::new(), Vec::new());
        self.sql(auth_id, &mut sql, &mut binds);
        if matches!(self, Node::Or(..)) {
            sql = format!("({sql})");
        }
        (sql, binds)
    }

    fn sql(&self, auth: &str, out: &mut String, binds: &mut Vec<Value>) {
        match self {
            Node::Or(a, b) => {
                a.sql(auth, out, binds);
                out.push_str(" OR ");
                b.sql(auth, out, binds);
            }
            // SQL's own precedence matches this grammar's, so only an OR nested
            // under an AND needs parens of its own.
            Node::And(a, b) => {
                for (i, side) in [a, b].into_iter().enumerate() {
                    if i == 1 {
                        out.push_str(" AND ");
                    }
                    let paren = matches!(**side, Node::Or(..));
                    if paren {
                        out.push('(');
                    }
                    side.sql(auth, out, binds);
                    if paren {
                        out.push(')');
                    }
                }
            }
            Node::Cmp(l, op, Operand::Null) => {
                let not = if *op == "!=" { "NOT " } else { "" };
                out.push_str(&format!("({} IS {not}NULL)", l.sql(auth, binds)));
            }
            Node::Cmp(l, op @ ("~" | "!~"), r) => {
                let not = if *op == "!~" { "NOT " } else { "" };
                let pat = match r {
                    Operand::Auth => auth.to_string(),
                    Operand::Val(Value::Text(s)) => s.clone(),
                    Operand::Val(Value::Integer(n)) => n.to_string(),
                    Operand::Val(Value::Real(f)) => f.to_string(),
                    // the parser rejects every other shape on the right of a LIKE
                    _ => String::new(),
                };
                // `~` means "contains this text", so % and _ in the value are literal
                // characters, not wildcards. Without the escape the SQL backend would
                // treat them as wildcards while `eval` treats them literally, and the
                // two backends must agree — for `!~` the looser one grants access.
                out.push_str(&format!("({} {not}LIKE ? ESCAPE '\\')", l.sql(auth, binds)));
                binds.push(Value::Text(format!("%{}%", like_escape(&pat))));
            }
            Node::Cmp(l, op, r) => {
                let (ls, rs) = (l.sql(auth, binds), r.sql(auth, binds));
                out.push_str(&format!("({ls} {op} {rs})"));
            }
        }
    }

    /// Evaluate against an in-memory record body — used by create, where no row
    /// exists to run SQL against, and by realtime, whose row may already be gone.
    /// Mirrors SQLite: NULL never compares true, numbers coerce.
    pub fn eval(&self, auth: &str, data: &Map<String, Json>) -> bool {
        match self {
            Node::Or(a, b) => a.eval(auth, data) || b.eval(auth, data),
            Node::And(a, b) => a.eval(auth, data) && b.eval(auth, data),
            Node::Cmp(l, op, r) => {
                let lv = l.json(auth, data);
                // `x = null` / `x != null` are presence tests, like IS [NOT] NULL
                if matches!(r, Operand::Null) {
                    return lv.is_null() == (*op == "=");
                }
                let rv = r.json(auth, data);
                // a comparison against a missing field is never true: fail closed
                if lv.is_null() || rv.is_null() {
                    return false;
                }
                if *op == "~" || *op == "!~" {
                    // SQLite LIKE is ASCII case-insensitive and `to_sql` emits LIKE, so
                    // match that here. Case-sensitive `contains` made this backend the
                    // more permissive one for `!~`, i.e. create could grant what update
                    // refused — exactly the divergence the shared AST exists to prevent.
                    let hay = text(&lv).to_ascii_lowercase();
                    let needle = text(&rv).to_ascii_lowercase();
                    return hay.contains(&needle) == (*op == "~");
                }
                match (num(&lv), num(&rv)) {
                    (Some(a), Some(b)) => match *op {
                        "=" => a == b,
                        "!=" => a != b,
                        ">" => a > b,
                        ">=" => a >= b,
                        "<" => a < b,
                        _ => a <= b,
                    },
                    // ordering only makes sense between two numbers
                    _ => match *op {
                        "=" => lv == rv,
                        "!=" => lv != rv,
                        _ => false,
                    },
                }
            }
        }
    }
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    mode: Mode,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, tok: &str) -> bool {
        if self.b[self.i..].starts_with(tok.as_bytes()) {
            self.i += tok.len();
            true
        } else {
            false
        }
    }

    // expr := and ( "||" and )*
    fn expr(&mut self, depth: u32) -> Result<Node, String> {
        let mut n = self.and(depth)?;
        loop {
            self.ws();
            if !self.eat("||") {
                return Ok(n);
            }
            n = Node::Or(Box::new(n), Box::new(self.and(depth)?));
        }
    }

    // and := unit ( "&&" unit )*
    fn and(&mut self, depth: u32) -> Result<Node, String> {
        let mut n = self.unit(depth)?;
        loop {
            self.ws();
            if !self.eat("&&") {
                return Ok(n);
            }
            n = Node::And(Box::new(n), Box::new(self.unit(depth)?));
        }
    }

    // unit := "(" expr ")" | comparison
    fn unit(&mut self, depth: u32) -> Result<Node, String> {
        self.ws();
        if self.eat("(") {
            if depth >= MAX_DEPTH {
                return Err("filter nesting too deep".into());
            }
            let n = self.expr(depth + 1)?;
            self.ws();
            if !self.eat(")") {
                return Err(format!("expected ')' at byte {}", self.i));
            }
            return Ok(n);
        }
        self.comparison()
    }

    // comparison := (field | auth token) op value
    fn comparison(&mut self) -> Result<Node, String> {
        self.ws();
        let lhs = if self.eat(TOKEN) {
            Operand::Auth
        } else {
            let start = self.i;
            while self.i < self.b.len()
                && (self.b[self.i].is_ascii_alphanumeric() || self.b[self.i] == b'_')
            {
                self.i += 1;
            }
            // slice bounds are ASCII, so this is always valid UTF-8
            let field = std::str::from_utf8(&self.b[start..self.i]).unwrap();
            if !ident_ok(field) {
                return Err(format!("expected field name at byte {start}"));
            }
            Operand::Col(field.to_string())
        };
        self.ws();
        // two-char ops before their one-char prefixes
        let op = ["!=", "!~", ">=", "<=", "=", ">", "<", "~"]
            .into_iter()
            .find(|o| self.eat(o))
            .ok_or_else(|| format!("expected operator at byte {}", self.i))?;
        self.ws();
        let rhs = self.value()?;
        match (&rhs, op) {
            (Operand::Null, "=" | "!=") => {}
            (Operand::Null, _) => return Err(format!("null not allowed with '{op}'")),
            // LIKE needs a pattern to bind, not a second column
            (Operand::Col(_), "~" | "!~") => {
                return Err(format!("'{op}' needs a literal at byte {}", self.i))
            }
            _ => {}
        }
        Ok(Node::Cmp(lhs, op, rhs))
    }

    // value := quoted string | number | true | false | null | auth token | bareword
    fn value(&mut self) -> Result<Operand, String> {
        if self.eat("'") {
            let mut s: Vec<u8> = Vec::new();
            loop {
                match self.b.get(self.i).copied() {
                    None => return Err("unterminated string".into()),
                    Some(b'\'') => {
                        self.i += 1;
                        if !self.eat("'") {
                            // splits only at ASCII quote bytes of valid UTF-8 input
                            return Ok(Operand::Val(Value::Text(String::from_utf8(s).unwrap())));
                        }
                        s.push(b'\''); // '' escape = literal quote
                    }
                    Some(c) => {
                        s.push(c);
                        self.i += 1;
                    }
                }
            }
        }
        // bareword: maximal run of chars not in { whitespace ( ) & | ' }
        let start = self.i;
        while self.i < self.b.len()
            && !matches!(self.b[self.i], b'(' | b')' | b'&' | b'|' | b'\'')
            && !self.b[self.i].is_ascii_whitespace()
        {
            self.i += 1;
        }
        let w = std::str::from_utf8(&self.b[start..self.i]).unwrap();
        if w.is_empty() {
            return Err(format!("expected value at byte {start}"));
        }
        // checked before the bareword rules below, so it can never degrade to a literal
        if w == TOKEN {
            return Ok(Operand::Auth);
        }
        Ok(match w {
            "true" => Operand::Val(Value::Integer(1)),
            "false" => Operand::Val(Value::Integer(0)),
            "null" => Operand::Null,
            _ => {
                if let Ok(n) = w.parse::<i64>() {
                    Operand::Val(Value::Integer(n))
                } else if let Ok(f) = w.parse::<f64>() {
                    Operand::Val(Value::Real(f))
                } else if self.mode == Mode::Rule {
                    if !ident_ok(w) {
                        return Err(format!("expected field name at byte {start}"));
                    }
                    Operand::Col(w.to_string())
                } else {
                    Operand::Val(Value::Text(w.to_string()))
                }
            }
        })
    }
}
#[cfg(test)]
mod tests {
    use super::{compile, parse, Mode};
    use rusqlite::types::Value::{Integer, Text};

    #[test]
    fn backcompat_single_ops() {
        let (frag, binds) = compile("views>50").unwrap();
        assert_eq!(frag, "(json_extract(data, '$.views') > ?)");
        assert_eq!(binds, vec![Integer(50)]);

        let (_, binds) = compile("title=first").unwrap();
        assert_eq!(binds, vec![Text("first".into())]);

        let (_, binds) = compile("flag=true").unwrap();
        assert_eq!(binds, vec![Integer(1)]);
    }

    #[test]
    fn quote_escape() {
        let (_, binds) = compile("title='it''s'").unwrap();
        assert_eq!(binds, vec![Text("it's".into())]);
    }

    #[test]
    fn like_ops() {
        let (frag, binds) = compile("title~'rock'").unwrap();
        assert_eq!(frag, "(json_extract(data, '$.title') LIKE ? ESCAPE '\\')");
        assert_eq!(binds, vec![Text("%rock%".into())]);

        let (frag, binds) = compile("title!~'rock'").unwrap();
        assert_eq!(frag, "(json_extract(data, '$.title') NOT LIKE ? ESCAPE '\\')");
        assert_eq!(binds, vec![Text("%rock%".into())]);
    }

    #[test]
    fn null_ops() {
        let (frag, binds) = compile("status=null").unwrap();
        assert_eq!(frag, "(json_extract(data, '$.status') IS NULL)");
        assert!(binds.is_empty());

        let (frag, _) = compile("status!=null").unwrap();
        assert_eq!(frag, "(json_extract(data, '$.status') IS NOT NULL)");

        assert!(compile("status>null").is_err());
    }

    #[test]
    fn precedence_and_real_columns() {
        let (frag, binds) = compile("(a=1 || b=2) && id='abc'").unwrap();
        assert_eq!(
            frag,
            "((json_extract(data, '$.a') = ?) OR (json_extract(data, '$.b') = ?)) AND (id = ?)"
        );
        assert_eq!(binds, vec![Integer(1), Integer(2), Text("abc".into())]);
    }

    #[test]
    fn injection_value_never_reaches_sql() {
        let (frag, binds) = compile("title='a''); DROP TABLE records;--'").unwrap();
        assert!(!frag.contains("DROP"));
        assert!(!frag.contains("'a"));
        assert_eq!(binds, vec![Text("a'); DROP TABLE records;--".into())]);
    }

    #[test]
    fn injection_trailing_garbage_rejected() {
        assert!(compile("title='x' OR '1'='1'").is_err());
        assert!(compile("title='x'; DROP TABLE records").is_err());
    }

    #[test]
    fn bad_inputs_rejected() {
        assert!(compile("foo;bar=1").is_err());
        assert!(compile("=5").is_err());
        assert!(compile("views>").is_err());
        assert!(compile("").is_err());
    }

    // Security invariant, not cosmetics. gate_record splices a rule fragment as
    // `... AND id = ? AND {frag}`. Without the wrap, a top-level `||` reassociates to
    // `(collection AND id AND a) OR b`, so the b-disjunct matching ANY OTHER ROW grants
    // access to this one. Harmless while rules were single comparisons; a private-record
    // read the moment `||` became expressible. Wrapping here makes every emitted
    // fragment safe to AND into a larger WHERE, at the source rather than per caller.
    #[test]
    fn top_level_or_is_parenthesised_for_safe_splicing() {
        let (sql, _) = parse("a = 1 || b = 2", Mode::Rule).unwrap().to_sql("");
        assert!(
            sql.starts_with('(') && sql.ends_with(')'),
            "a top-level Or must be wrapped or it reassociates when ANDed: {sql}"
        );
        // an And root needs no wrap, and must not gain one (filter unit tests pin the SQL)
        let (sql, _) = parse("a = 1 && b = 2", Mode::Rule).unwrap().to_sql("");
        assert!(!sql.starts_with("(("), "And root should not be double-wrapped: {sql}");
    }

    // The two backends must return the same verdict for the same rule and data —
    // that is the reason they share one AST. LIKE was the last place they disagreed:
    // `eval` did case-sensitive `contains` while `to_sql` emitted case-insensitive
    // LIKE, and an unescaped % in the value was a wildcard on one side and a literal
    // on the other. For `!~` the looser backend GRANTS, so this is access control.
    #[test]
    fn like_backends_agree() {
        use serde_json::json;
        let cases = [
            ("title ~ 'ROCK'", json!({"title": "rockbase"}), true),
            ("title ~ 'rock'", json!({"title": "ROCKBASE"}), true),
            ("title !~ 'ROCK'", json!({"title": "rockbase"}), false),
            // % is a literal character in a `~` value, not a wildcard
            ("title ~ '50%'", json!({"title": "up 50% today"}), true),
            ("title ~ 'a%z'", json!({"title": "abcz"}), false),
            ("title ~ '_'", json!({"title": "abc"}), false),
        ];
        // Run BOTH backends for real: eval in memory, and to_sql against SQLite. Asserting
        // the bind string alone would only prove two separate claims, not that they agree.
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE records(data TEXT NOT NULL);").unwrap();
        for (rule, rec, want) in cases {
            let node = parse(rule, Mode::Rule).unwrap();
            let data = rec.as_object().unwrap().clone();
            assert_eq!(node.eval("", &data), want, "in-memory verdict for {rule} on {rec}");

            conn.execute("DELETE FROM records", []).unwrap();
            conn.execute("INSERT INTO records(data) VALUES(?1)", [rec.to_string()])
                .unwrap();
            let (frag, binds) = node.to_sql("");
            let hit: bool = conn
                .query_row(
                    &format!("SELECT EXISTS(SELECT 1 FROM records WHERE {frag})"),
                    rusqlite::params_from_iter(binds.iter()),
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(hit, want, "SQL verdict for {rule} on {rec} disagrees with eval");
        }
        // and the escape actually reaches the bind
        let (_, binds) = compile("title~'50%'").unwrap();
        assert_eq!(binds, vec![Text("%50\\%%".into())]);
    }
}
