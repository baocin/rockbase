> **HISTORICAL — superseded by the code and tests.**
> This was a design input, written when the whole crate was a single `src/main.rs`.
> The crate is now modular (`src/lib.rs` + modules), so every file-layout claim below
> is wrong. The authoritative specification is `tests/basic.rs` plus the source.
> Do not implement from this document.

# Spec: Query extras + PATCH null-required fix

Scope: multi-field `sort`, `fields` projection, `skipTotal=1` on the records list
endpoint, plus a bug fix so PATCH cannot null out a required field. All changes are
in `src/main.rs` (the whole app is one file). No new dependencies. Response shape
stays `{page, perPage, totalItems, totalPages, items}`.

## 1. GET /api/collections/{name}/records — new query params

### 1.1 `sort` accepts a comma-separated list

Today `sort_clause(s)` handles exactly one field (optional `-` prefix for DESC).
Change: `records_list` splits `q.sort` on `,` and maps each segment through the
existing per-field logic, joining with `", "`. Keep `sort_clause` as the
single-segment helper; add nothing else.

```rust
let order = match q.sort.as_deref() {
    Some(s) => s.split(',')
        .map(|seg| sort_clause(seg.trim()))
        .collect::<Option<Vec<_>>>()
        .map(|v| v.join(", "))
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "bad sort field"))?,
    None => "created ASC".to_string(),
};
```

`sort=-created,title` produces `ORDER BY created DESC, json_extract(data, '$.title') ASC`.
Any segment failing `ident_ok` (empty segment included, e.g. `sort=title,`) → 400
`bad sort field`. Interpolation stays safe: every segment passes `ident_ok`
(`[A-Za-z0-9_]`, len ≤ 64) inside `sort_clause` before entering the SQL string.

### 1.2 `fields` projects the output objects

New param: comma-separated key list. Applied per item after `record_json` builds the
full object: keep only the listed keys, plus `id` always. Keys not present on a
record are simply absent (no null padding). `created`, `updated`, `collectionName`
are droppable like any other key. Projection is post-SQL (the row is one JSON blob
anyway) — the SELECT does not change.

- Every segment must pass `ident_ok` after trim, else 400 `bad fields`.
  Note `fields=` (empty value) splits to one empty segment → 400.
- Add to `ListParams`: `fields: Option<String>`.
- In `records_list`, after building each `Value` from `record_json`:

```rust
if let Some(keep) = &keep_set { // HashSet<&str> parsed once before the loop
    if let Value::Object(m) = &mut item {
        m.retain(|k, _| k == "id" || keep.contains(k.as_str()));
    }
}
```

Example: `GET /api/collections/posts/records?fields=title,views` →
`items: [{"id": "abc...", "title": "first", "views": 10}, ...]`.

### 1.3 `skipTotal=1` skips the COUNT query

Add to `ListParams`: `#[serde(rename = "skipTotal")] skip_total: Option<String>`.
Skip when the value is `"1"` (PocketBase parity; anything else = don't skip).
When skipping, do not run the `SELECT COUNT(*)` at all and return `-1` sentinels:

```rust
let (total_items, total_pages): (i64, i64) = if skip {
    (-1, -1)
} else {
    let total: i64 = db.query_row(/* existing COUNT with same where_sql/binds */)?;
    (total, (total as u32).div_ceil(per_page) as i64)
};
```

(The current `total: u32` local becomes `i64` so `-1` fits; JSON output shape is
unchanged otherwise.) Pagination via LIMIT/OFFSET still works with `skipTotal=1`.

Response with `?skipTotal=1&perPage=2`:

```json
{ "page": 1, "perPage": 2, "totalItems": -1, "totalPages": -1, "items": [ ... ] }
```

All three params compose freely with each other and the existing `filter`/`page`/
`perPage`.

## 2. Bug fix: PATCH rejects null for required fields

Today `validate(schema, data, is_auth, partial)` wraps the whole required-field loop
in `if !partial`, so a PATCH body like `{"title": null}` passes validation and the
shallow merge in `record_update` writes `null` into a schema-required field.

Fix at the root in `validate` (covers create and update in one place — do not patch
`record_update` separately). Replace the `if !partial { ... }` block with an
always-run loop:

```rust
for f in schema {
    if f.get("required").and_then(|r| r.as_bool()).unwrap_or(false) {
        let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
        match data.get(name) {
            Some(v) if v.is_null() => return Err(format!("field '{name}' is required")),
            None if !partial => return Err(format!("field '{name}' is required")),
            _ => {}
        }
    }
}
```

Semantics: full validation (create) is unchanged — missing or null both fail.
Partial validation (PATCH) now fails on an explicit null for a required field but
still allows the field to be absent. Null remains legal for non-required fields
(the per-field type check already allows `v.is_null()`).

`PATCH /api/collections/posts/records/{id}` with `{"title": null}` (title required) →
400 `{"code": 400, "message": "field 'title' is required"}`, record unchanged.

## 3. Files / functions touched

`src/main.rs` only:

- `ListParams` (~line 292): add `fields`, `skip_total`.
- `records_list` (~line 352): multi-sort join, conditional COUNT, `-1` sentinels,
  fields parsing + per-item `retain`.
- `validate` (~line 111): required loop runs for partial too, per section 2.
- `mod tests` (bottom of file): new cases below. There is no `tests/` dir; tests
  are inline.

## 4. Acceptance tests

Seed via the existing `full_flow` pattern: admin creates `posts` with schema
`[{title: text, required}, {views: number}]`, a user signs up and logs in, then
creates posts `("b", 5)`, `("a", 5)`, `("c", 9)`.

1. `GET ...?sort=-views,title` → 200; titles in order `["c", "a", "b"]`
   (views DESC, then title ASC as tiebreak).
2. `GET ...?sort=views,bad-seg!` → 400 (message `bad sort field`). Also covers
   `sort=views,` (empty trailing segment).
3. `GET ...?fields=title` → 200; every item has exactly the keys `id` and `title`
   (no `views`, `created`, `updated`, `collectionName`).
4. `GET ...?fields=title;views` → 400 (`;` fails ident_ok → `bad fields`).
5. `GET ...?skipTotal=1&perPage=2` → 200; `totalItems == -1`, `totalPages == -1`,
   `items.len() == 2`.
6. `GET ...?filter=views%3E4&skipTotal=1&sort=-views&fields=title` → 200; params
   compose: items are title-only objects sorted views DESC.
7. `PATCH .../records/{id}` body `{"title": null}` → 400; follow-up GET shows the
   old title intact.
8. `PATCH .../records/{id}` body `{"views": null}` → 200 (non-required field may
   be nulled); response has `views == null`.

Regression: existing `full_flow` must stay green untouched (plain list responses
keep real totals; create still 400s on missing required field).
