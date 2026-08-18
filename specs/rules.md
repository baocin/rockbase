> **HISTORICAL — superseded by the code and tests.**
> This was a design input, written when the whole crate was a single `src/main.rs`.
> The crate is now modular (`src/lib.rs` + modules), so every file-layout claim below
> is wrong. The authoritative specification is `tests/rules.rs` plus the source.
> Do not implement from this document.

# Spec: Per-collection API rules

PocketBase-style access rules, simplified. All changes in `src/main.rs` (there is no
`src/filter.rs`; the existing filter code is `parse_filter()` / `sort_clause()` in main.rs).

## Semantics

Five nullable TEXT rules per collection: `list_rule, view_rule, create_rule, update_rule, delete_rule`.

| Rule value | Meaning |
|---|---|
| `NULL` | admin only |
| `''` (empty string) | public |
| other | single filter expression `lhs op rhs` (ops `!= >= <= = > <`, same list as `parse_filter`) |

Extra token `@request.auth.id` = caller's user record id (JWT `sub` claim), `''` for guests.
It binds as a SQL parameter — never textual splice — so it works in LHS or RHS position and
cannot inject. Admin (`Authorization: Admin <token>`) bypasses every rule. Denial status:
guest → 401, authed user → 403. `auth-with-password` and `/api/realtime` are NOT rule-gated
(realtime leaking records is a known hole — ponytail-comment it: per-rule SSE filtering later).

## Migration (in `init_db`)

Guard: add columns and seed defaults only on first run after upgrade, so re-running init never
clobbers rules an admin has since edited.

```rust
let migrated: i64 = conn.query_row(
    "SELECT COUNT(*) FROM pragma_table_info('_collections') WHERE name='list_rule'",
    [], |r| r.get(0)).unwrap();
if migrated == 0 {
    conn.execute_batch(
        "ALTER TABLE _collections ADD COLUMN list_rule TEXT;
         ALTER TABLE _collections ADD COLUMN view_rule TEXT;
         ALTER TABLE _collections ADD COLUMN create_rule TEXT;
         ALTER TABLE _collections ADD COLUMN update_rule TEXT;
         ALTER TABLE _collections ADD COLUMN delete_rule TEXT;
         UPDATE _collections SET list_rule='', view_rule='',
             create_rule='@request.auth.id != ''''',
             update_rule='@request.auth.id != ''''',
             delete_rule='@request.auth.id != ''''' WHERE type='base';
         UPDATE _collections SET create_rule='', list_rule=NULL, view_rule=NULL,
             update_rule='id = @request.auth.id',
             delete_rule='id = @request.auth.id' WHERE type='auth';").unwrap();
}
```

Run this AFTER the `INSERT OR IGNORE` users seed so a fresh DB seeds users then rules in one pass.
Base defaults preserve current behavior (public read, any-authed write). Auth defaults change users:
public signup, admin-only list/view, own-record update/delete (deliberate, agreed scope).

## Code changes

**`who()`** — carry the user id: `enum Who { Admin, User(String), Guest }`; on JWT success return
`Who::User(claims.claims.sub)`. Helper `auth_id(&Who) -> &str` (`""` for Guest/Admin unused).
Delete `require_writer` (replaced by rules). Keep `require_admin`.

**`get_collection`** — also select the five rule columns; return a small struct:
`struct Col { ty: String, schema: Vec<Value>, rules: [Option<String>; 5] }` (order: list, view,
create, update, delete). Update the existing callers.

**New `fn compile_rule(rule: &str, auth_id: &str) -> Option<(String, Vec<rusqlite::types::Value>)>`**
— returns SQL fragment + binds. Split on the first operator (check 2-char ops before 1-char, like
`parse_filter`). Resolve each side independently:
- `@request.auth.id` → `?`, bind `auth_id`
- quoted `'x'`/`"x"` → `?`, bind inner string
- `true`/`false` → `?`, bind 1/0; parses as f64 → `?`, bind number
- `id` | `created` | `updated` → real column name (no bind)
- passes `ident_ok` → `json_extract(data, '$.<field>')` (ident_ok whitelist-guards interpolation)
- anything else → `None` (caller answers 400 on save, 403/401 at request time — see validation)

**New `fn eval_rule_mem(rule: &str, auth_id: &str, data: &Map<String, Value>) -> bool`** — for
create only. Same side-resolution but in memory: token → auth_id string, literals as themselves,
field name → `data.get(field)` (missing = Null; `id`/`created`/`updated` don't exist yet = Null).
Compare: `=`/`!=` by JSON equality (string-vs-string, number-vs-number); `> >= < <=` only when both
sides are numbers, else false. `// ponytail: no SQLite type-coercion parity, single comparison
only; swap for a shared rule VM if rules grow && / ||`.

**New `fn check_rule(who, rule: &Option<String>) -> Result<Option<String>, (StatusCode, Json<Value>)>`**
— central gate: Admin → `Ok(None)` (bypass); rule `None` (NULL) → 401 guest / 403 user;
`Some("")` → `Ok(None)`; `Some(r)` → `Ok(Some(r))` (caller must enforce the expression).

### Handler changes

- `records_list` — add `headers: HeaderMap` param. Gate with `check_rule(list_rule)`; if it yields
  an expression, `compile_rule` it and append `" AND (<sql>)"` + binds to the existing `where_sql`
  (applies to both the COUNT and the page query). Uncompilable stored rule → 403/401 (fail closed).
- `record_view` — add `headers`. Fetch collection (404 if missing), fetch record (404 if missing),
  then gate: if expression, run
  `SELECT 1 FROM records WHERE collection = ?1 AND id = ?2 AND (<rule_sql>)`; no row → 403/401.
- `record_update` / `record_delete` — replace `require_writer` with the same fetch-then-gate as
  view, using update_rule/delete_rule. `record_delete` must now look up the collection first
  (it currently doesn't); missing collection or record stays 404.
- `record_create` — replace `require_writer`: gate with `check_rule(create_rule)`; if expression,
  `eval_rule_mem` against the incoming (validated) data map; false → 403/401. Runs before insert.

### Collections API

Rule fields ride as camelCase JSON: `listRule, viewRule, createRule, updateRule, deleteRule`;
each `null` or string. Validation on write: value must be JSON null or string; a non-empty string
must `compile_rule` with a dummy auth id, else 400 `"invalid <name>Rule"`.

- `POST /api/collections` (admin) — accept the five fields; any field absent gets the type default
  (base: `''`/`''`/`@request.auth.id != ''` ×3; auth: `''` create, NULL list/view,
  `id = @request.auth.id` update/delete — same defaults as the migration, any auth collection).
  Echo rules in the response.
- **New** `PATCH /api/collections/{name}` (admin, route added next to the existing DELETE) — body
  is a JSON object; only the five rule keys are honored; a key present with `null` sets NULL, a key
  absent is unchanged (serde_json `Map` keeps explicit nulls, so `body.get(k)` distinguishes them).
  404 unknown collection. Response = full collection JSON. Schema/type edits stay out of scope.
- `GET /api/collections` — include the five rule fields per item.

```json
PATCH /api/collections/posts   (Authorization: Admin <token>)
{"updateRule": "author = @request.auth.id", "deleteRule": null}

200 → {"name":"posts","type":"base","schema":[...],
       "listRule":"","viewRule":"","createRule":"@request.auth.id != ''",
       "updateRule":"author = @request.auth.id","deleteRule":null}
```

## Edge cases

- Guest + `@request.auth.id` → binds `''`; `owner = @request.auth.id` never matches missing
  `owner` (json_extract yields SQL NULL, `NULL = ''` is not true) — correct fail-closed.
- Rule references a field absent from a row → NULL comparison → no match → denied. Fine.
- `filter=` query param and list_rule combine with AND; user filter cannot widen access.
- JWT from a deleted user still carries an id; rules compare against it and simply won't match
  own-record rules. `// ponytail: no live user lookup per request; add if revocation matters`.
- Existing inline test `full_flow` stays green: posts defaults reproduce old behavior, and the
  users create in it uses the Admin header (bypass) — do not modify it.

## Acceptance tests (add to `mod tests`)

1. Fresh app: `GET /api/collections` (admin) shows users with `createRule:""`,
   `listRule:null`, `viewRule:null`, `updateRule/deleteRule:"id = @request.auth.id"`.
2. Public signup: `POST /api/collections/users/records` with NO auth header → 200.
3. Users privacy: `GET /api/collections/users/records` → 401 guest, 403 with Bearer, 200 admin.
4. Own record: user A `PATCH` user B's record → 403; A patches own record → 200; admin patches
   B → 200; A `DELETE` B → 403.
5. Custom rule: admin `PATCH /api/collections/posts` `{"updateRule":"author = @request.auth.id"}`;
   A creates post `{"author": <A id>, ...}`; A patch → 200, B patch → 403.
6. NULL locks: admin sets `{"deleteRule": null}` on posts; user delete → 403, guest → 401,
   admin → 200.
7. List rule filters: posts `listRule = "owner = @request.auth.id"`; A sees only rows with
   `owner = <A id>`; guest gets 200 with 0 items (empty auth id matches nothing).
8. Bad rule rejected: `PATCH /api/collections/posts` `{"listRule": "no operator here"}` → 400;
   `{"listRule": 5}` → 400.

Done = `cargo test` green including the above, no new dependencies.
