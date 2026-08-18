> **HISTORICAL — superseded by the code and tests.**
> This was a design input, written when the whole crate was a single `src/main.rs`.
> The crate is now modular (`src/lib.rs` + modules), so every file-layout claim below
> is wrong. The authoritative specification is `tests/rules.rs` plus the source.
> Do not implement from this document.

# Spec: PocketBase-style filter expression language

New module `src/filter.rs` with a small recursive-descent parser that compiles a filter
expression to a parameterized SQL fragment. `records_list` in `src/main.rs` uses it,
replacing the old single-op `parse_filter`. No new dependencies. No endpoint changes:
still `GET /api/collections/{name}/records?filter=<expr>` (URL-encoded).

## Grammar

```
expr    := and ( "||" and )*            -- || is lowest precedence
and     := unit ( "&&" unit )*          -- && binds tighter than ||
unit    := "(" expr ")" | comparison
comparison := field op value
field   := [A-Za-z0-9_]+                -- must pass ident_ok (also caps len at 64)
op      := "=" | "!=" | ">" | ">=" | "<" | "<=" | "~" | "!~"
value   := "'" chars "'"                -- single-quoted string; '' inside = literal '
         | number                       -- parse as i64, else f64 (e.g. 10, -3, 2.5)
         | "true" | "false"             -- compile to integer binds 1 / 0 (JSON1 booleans)
         | "null"                       -- only with = / !=, see below
         | bareword                     -- backcompat: maximal run of chars not in
                                        --   { whitespace ( ) & | ' } treated as a string
```

Whitespace between tokens is skipped. Bareword loses to the other value forms: try
quoted string, then number, then true/false/null, then bareword. Match two-character
operators (`!=`, `!~`, `>=`, `<=`) before their one-character prefixes (`=`, `>`, `<`, `~`).

## Compilation

`pub fn compile(input: &str) -> Result<(String, Vec<rusqlite::types::Value>), String>`

- Returns a WHERE fragment (no leading `AND`) and its binds, in placeholder order.
  Placeholders are plain `?`. Err(String) is a human-readable parse error.
- Field to SQL column: `id`, `created`, `updated` map to the real column name;
  anything else maps to `json_extract(data, '$.{field}')` — interpolation is safe
  because `ident_ok` whitelists `[A-Za-z0-9_]` (same precedent as `sort_clause`).
  Field names NEVER come from binds; values ALWAYS do.
- Op mapping: `=` `!=` `>` `>=` `<` `<=` pass through. `~` compiles to `LIKE ?` with
  the value stringified and wrapped as `%value%`; `!~` to `NOT LIKE ?` same wrapping.
  `// ponytail: % and _ inside a ~ value act as LIKE wildcards; add ESCAPE clause if it bites`
- `null`: `f = null` compiles to `col IS NULL`, `f != null` to `col IS NOT NULL`,
  zero binds. `null` with any other op is a parse error.
- Each comparison and each parenthesized group is emitted wrapped in `(...)` so
  precedence survives textually. Example:
  `(a=1 || b=2) && c!='x'` compiles to
  `((json_extract(data, '$.a') = ?) OR (json_extract(data, '$.b') = ?)) AND (json_extract(data, '$.c') != ?)`
  with binds `[1i64, 2i64, "x"]`.
- Guardrails (trust boundary, do not skip): reject input longer than 2048 bytes;
  cap paren nesting depth at 32 (recursion depth); trailing unconsumed input after a
  complete expr is an error (this is what defeats `title='x' OR '1'='1'`).

## Wiring changes in src/main.rs

1. Add `mod filter;` at the top.
2. Move `ident_ok` from main.rs into filter.rs as `pub(crate) fn ident_ok`; main.rs
   call sites (`collections_create`, `sort_clause`) switch to `filter::ident_ok`.
3. Delete `parse_filter` (lines ~301-334) and its ponytail comment.
4. In `records_list`, replace the `if let Some(f) = q.filter` block body with:
   ```rust
   let (frag, mut fbinds) = filter::compile(f)
       .map_err(|m| err(StatusCode::BAD_REQUEST, format!("invalid filter: {m}")))?;
   where_sql.push_str(&format!(" AND ({frag})"));
   binds.append(&mut fbinds);
   ```
   Everything downstream (COUNT query, page query, `params_from_iter`) is unchanged.

## Backward compatibility (must keep passing)

Old inputs keep working: `views>50` (bare number), `title=first` (bareword string),
`flag=true`, `title='first'`. One deliberate change: old code accepted
double-quoted values (`title="x"`); new grammar only single-quotes — a bareword
`"x"` would now include the quotes. Acceptable: PocketBase itself only single-quotes,
and no existing test uses double quotes. The existing `tests::full_flow` assertion
`filter=views%3E50` must still pass untouched.

## Request/response examples

```
GET /api/collections/posts/records?filter=(views%3E50%20%26%26%20title~'ro')%20%7C%7C%20draft%3Dnull
  -- decoded: (views>50 && title~'ro') || draft=null
200 {"page":1,"perPage":30,"totalItems":1,"totalPages":1,"items":[{"id":"...","title":"rock", ...}]}

GET /api/collections/posts/records?filter=title%3D'x'%20OR%201%3D1
400 {"code":400,"message":"invalid filter: unexpected trailing input at byte 9"}
```
(Error wording is free-form; status 400 and the `{code,message}` shape via `err()` are required.)

## Unit tests (in `#[cfg(test)] mod tests` inside src/filter.rs)

Assert on the returned fragment string and binds. Required cases:

1. Backcompat single ops: `views>50` → fragment `(json_extract(data, '$.views') > ?)`,
   binds `[Integer(50)]`; `title=first` → binds `[Text("first")]`; `flag=true` → `[Integer(1)]`.
2. Quote escape: `title='it''s'` → binds `[Text("it's")]`.
3. Like ops: `title~'rock'` → `... LIKE ?` with bind `Text("%rock%")`;
   `title!~'rock'` → `NOT LIKE` with same wrapping.
4. Null: `status=null` → `(json_extract(data, '$.status') IS NULL)`, zero binds;
   `status!=null` → `IS NOT NULL`; `status>null` → Err.
5. Precedence and real columns: `(a=1 || b=2) && id='abc'` → OR nested inside AND,
   `id = ?` uses the bare column (no json_extract), 3 binds.
6. Injection — value never reaches SQL: for
   `title='a''); DROP TABLE records;--'` assert `compile` is Ok, the fragment
   contains no `DROP` and no `'a`, and the whole payload sits in binds[0].
7. Injection — trailing garbage rejected: `title='x' OR '1'='1'` → Err;
   `title='x'; DROP TABLE records` → Err.
8. Bad fields rejected: `foo;bar=1` → Err; `=5` → Err; `views>` → Err; `` (empty) → Err.

One integration case in the existing `tests::full_flow` (or a sibling test fn): after
creating the two posts, `GET ...?filter=views%3E50%20%26%26%20title%3D'second'`
returns totalItems 1, and `GET ...?filter=views%3E50%20%7C%7C` returns 400.

## Acceptance checklist

- [ ] `cargo test` green; `tests::full_flow` unmodified except the added filter calls.
- [ ] All 8 unit-test cases above present in src/filter.rs.
- [ ] `grep "format!" src/filter.rs` shows field/op interpolation only — every value
      travels in the binds Vec, none is ever formatted into the SQL string.
- [ ] No new entries in Cargo.toml `[dependencies]`.
