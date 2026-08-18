> **HISTORICAL — superseded by the code and tests.**
> This was a design input, written when the whole crate was a single `src/main.rs`.
> The crate is now modular (`src/lib.rs` + modules), so every file-layout claim below
> is wrong. The authoritative specification is `tests/colupdate.rs` plus the source.
> Do not implement from this document.

# Spec: Collection read + schema update

Two admin endpoints on the existing `/api/collections/{name}` route: GET (full collection
with schema and rules) and PATCH (replace schema, update rule fields). All changes live in
`src/main.rs` (the whole app is one file). Tests go in the existing inline `mod tests`.

## Storage change

`_collections` gains one column: `rules TEXT NOT NULL DEFAULT '{}'` — a JSON object holding
the five PocketBase-style rule keys (`listRule`, `viewRule`, `createRule`, `updateRule`,
`deleteRule`), each a string or null. Missing keys read as null.

In `init_db`:
1. Add `rules TEXT NOT NULL DEFAULT '{}'` to the `CREATE TABLE IF NOT EXISTS _collections` DDL
   (fresh databases get it directly).
2. After `execute_batch`, run an ignore-error migration for existing database files:

```rust
// ponytail: ignore-error ALTER as migration; a real migrations table when there are two of these
let _ = conn.execute("ALTER TABLE _collections ADD COLUMN rules TEXT NOT NULL DEFAULT '{}'", []);
```

Rules are stored and served only — enforcement stays the existing global
`require_writer` policy. Mark it:
`// ponytail: rules stored, not enforced; wire into require_writer when per-collection auth matters`.

## GET /api/collections/{name}

Admin only (`require_admin`, 401 otherwise). 404 if the collection does not exist.
Handler does its own `query_row` (do not widen `get_collection` — it has 4 callers that
don't need rules):

```sql
SELECT type, schema, rules FROM _collections WHERE name = ?1
```

Response 200 — rules flattened to top level, PocketBase-shaped:

```json
{
  "name": "posts",
  "type": "base",
  "schema": [{"name": "title", "type": "text", "required": true}],
  "listRule": null, "viewRule": null, "createRule": null, "updateRule": null, "deleteRule": null
}
```

## PATCH /api/collections/{name}

Admin only, 404 if missing. Body is a JSON object; every key is optional:

- `schema`: the **full replacement** field array. Add/remove fields, toggle `required`, and
  change a field `type` all fall out of replacement — no incremental ops. Validate exactly
  like create: each field needs `ident_ok(name)` and `type` in `text|number|bool|json`,
  else 400. `schema` present but not an array → 400.
- `listRule` / `viewRule` / `createRule` / `updateRule` / `deleteRule`: string or null,
  anything else → 400. Merged into the stored rules object (only the keys sent change).
- `name` or `type` in the body → 400 `"name/type cannot be changed"` (renames and type
  changes are out of scope; failing loudly beats silent ignore).
- Any other key: ignored.
- Empty body `{}`: valid no-op, returns the current collection.

Request/response example:

```
PATCH /api/collections/posts        Authorization: Admin <token>
{"schema": [{"name": "title", "type": "text"}, {"name": "tags", "type": "json"}],
 "listRule": ""}
```

Response 200: same shape as GET, reflecting the new schema and rules.

Persist with:

```sql
UPDATE _collections SET schema = ?1, rules = ?2 WHERE name = ?3
```

Broadcast nothing (realtime is for records only).

## Code changes in src/main.rs

1. `init_db` — DDL + migration as above.
2. New `fn schema_ok(schema: &Value) -> Result<&Vec<Value>, &'static str>` — the array check
   and per-field name/type loop lifted verbatim out of `collections_create`; `collections_create`
   calls it too (shared validation is the point: one place to change).
3. New handlers `collections_get` and `collections_update` following the existing
   `Reply` / `err()` / `app.db.lock()` patterns.
4. Route wiring in `build_app`:

```rust
.route("/api/collections/{name}",
    get(collections_get).patch(collections_update).delete(collections_delete))
```

`collections_delete` is untouched — deleting `users` stays allowed (admin's choice).

## Data semantics and edge cases

- **Existing records are never touched.** Removing a field only makes it unwritable:
  `validate()` already rejects unknown fields on record create/update, so writes to a removed
  field get 400; values already stored keep round-tripping through `record_json`. Put
  `// ponytail: removed fields linger in stored JSON; a cleanup sweep over records is the upgrade`
  in `collections_update`.
- Changing a field's type does not re-validate stored data; only future writes are checked.
- Toggling `required: true` does not backfill; record PATCH stays partial (no required check),
  record create enforces it. Both are existing `validate()` behavior — no change.
- Duplicate field names in a schema are not rejected (create doesn't either; `validate()`'s
  `find()` uses the first definition). Known parity gap, leave it.
- Auth collections: schema edits work the same; `email`/`password` are handled outside the
  schema and are unaffected.

## Acceptance tests

One new `#[tokio::test] async fn collection_update_flow` in `mod tests`, reusing `app()`
and `call()`:

1. `GET /api/collections/posts` without admin → 401; with admin on a missing name → 404.
2. Create `posts` (schema: required `title` text, `views` number); GET returns that schema,
   `type: "base"`, and all five rules null.
3. PATCH with a replacement schema (drop `views`, add `tags` json, make `title` not required)
   plus `"listRule": ""` → 200; a follow-up GET shows the new schema, `listRule: ""`, other
   rules still null.
4. A record created before the PATCH with `views: 10` still returns `views` on view/list;
   creating a new record with `views` now → 400 unknown field.
5. PATCH with a bad field type (`{"schema": [{"name": "x", "type": "blob"}]}`) → 400;
   PATCH with `{"name": "renamed"}` → 400.
6. PATCH with `{"listRule": 5}` → 400.
7. PATCH `{}` → 200 and returns the unchanged collection.
8. `DELETE /api/collections/users` with admin → 200 (still allowed).

## Out of scope (agreed)

Collection rename/type change, rule enforcement, record data cleanup or re-validation on
schema change, rules in the list/create endpoints' responses, PocketBase collection ids.
