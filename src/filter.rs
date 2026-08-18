// PocketBase-style filter expressions compiled to parameterized SQL.
// Grammar and compilation rules: specs/filter.md.
// Trust boundary: field names are whitelist-checked (ident_ok) before
// interpolation; values ALWAYS travel as binds, never in the SQL string.

use rusqlite::types::Value;

use crate::ident_ok;

const MAX_LEN: usize = 2048;
const MAX_DEPTH: u32 = 32;

/// Compile a filter expression to a WHERE fragment (no leading AND) and its
/// binds, in placeholder order.
pub fn compile(input: &str) -> Result<(String, Vec<Value>), String> {
    if input.len() > MAX_LEN {
        return Err("filter too long".into());
    }
    let mut p = Parser { b: input.as_bytes(), i: 0 };
    let mut sql = String::new();
    let mut binds = Vec::new();
    p.expr(&mut sql, &mut binds, 0)?;
    p.ws();
    if p.i < p.b.len() {
        return Err(format!("unexpected trailing input at byte {}", p.i));
    }
    Ok((sql, binds))
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
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
    fn expr(&mut self, sql: &mut String, binds: &mut Vec<Value>, depth: u32) -> Result<(), String> {
        self.and(sql, binds, depth)?;
        loop {
            self.ws();
            if !self.eat("||") {
                return Ok(());
            }
            sql.push_str(" OR ");
            self.and(sql, binds, depth)?;
        }
    }

    // and := unit ( "&&" unit )*
    fn and(&mut self, sql: &mut String, binds: &mut Vec<Value>, depth: u32) -> Result<(), String> {
        self.unit(sql, binds, depth)?;
        loop {
            self.ws();
            if !self.eat("&&") {
                return Ok(());
            }
            sql.push_str(" AND ");
            self.unit(sql, binds, depth)?;
        }
    }

    // unit := "(" expr ")" | comparison
    fn unit(&mut self, sql: &mut String, binds: &mut Vec<Value>, depth: u32) -> Result<(), String> {
        self.ws();
        if self.eat("(") {
            if depth >= MAX_DEPTH {
                return Err("filter nesting too deep".into());
            }
            sql.push('(');
            self.expr(sql, binds, depth + 1)?;
            self.ws();
            if !self.eat(")") {
                return Err(format!("expected ')' at byte {}", self.i));
            }
            sql.push(')');
            return Ok(());
        }
        self.comparison(sql, binds)
    }

    // comparison := field op value
    fn comparison(&mut self, sql: &mut String, binds: &mut Vec<Value>) -> Result<(), String> {
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
        // ident_ok whitelists [A-Za-z0-9_], guarding this interpolation
        let col = match field {
            "id" | "created" | "updated" => field.to_string(),
            _ => format!("json_extract(data, '$.{field}')"),
        };
        self.ws();
        // two-char ops before their one-char prefixes
        let op = ["!=", "!~", ">=", "<=", "=", ">", "<", "~"]
            .into_iter()
            .find(|o| self.eat(o))
            .ok_or_else(|| format!("expected operator at byte {}", self.i))?;
        self.ws();
        match self.value()? {
            None => match op {
                "=" => sql.push_str(&format!("({col} IS NULL)")),
                "!=" => sql.push_str(&format!("({col} IS NOT NULL)")),
                _ => return Err(format!("null not allowed with '{op}'")),
            },
            Some(v) => match op {
                "~" | "!~" => {
                    let s = match v {
                        Value::Text(s) => s,
                        Value::Integer(n) => n.to_string(),
                        Value::Real(f) => f.to_string(),
                        _ => unreachable!(),
                    };
                    let not = if op == "!~" { "NOT " } else { "" };
                    sql.push_str(&format!("({col} {not}LIKE ?)"));
                    // ponytail: % and _ inside a ~ value act as LIKE wildcards; add ESCAPE clause if it bites
                    binds.push(Value::Text(format!("%{s}%")));
                }
                _ => {
                    sql.push_str(&format!("({col} {op} ?)"));
                    binds.push(v);
                }
            },
        }
        Ok(())
    }

    // value := quoted string | number | true | false | null | bareword.
    // None means null (compiles to IS NULL / IS NOT NULL upstream).
    fn value(&mut self) -> Result<Option<Value>, String> {
        if self.eat("'") {
            let mut s: Vec<u8> = Vec::new();
            loop {
                match self.b.get(self.i).copied() {
                    None => return Err("unterminated string".into()),
                    Some(b'\'') => {
                        self.i += 1;
                        if !self.eat("'") {
                            // splits only at ASCII quote bytes of valid UTF-8 input
                            return Ok(Some(Value::Text(String::from_utf8(s).unwrap())));
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
        Ok(match w {
            "true" => Some(Value::Integer(1)),
            "false" => Some(Value::Integer(0)),
            "null" => None,
            _ => Some(if let Ok(n) = w.parse::<i64>() {
                Value::Integer(n)
            } else if let Ok(f) = w.parse::<f64>() {
                Value::Real(f)
            } else {
                Value::Text(w.to_string())
            }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::compile;
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
        assert_eq!(frag, "(json_extract(data, '$.title') LIKE ?)");
        assert_eq!(binds, vec![Text("%rock%".into())]);

        let (frag, binds) = compile("title!~'rock'").unwrap();
        assert_eq!(frag, "(json_extract(data, '$.title') NOT LIKE ?)");
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
}
