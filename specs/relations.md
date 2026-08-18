# Spec: Relation fields + expand

All changes live in `src/main.rs` (the whole app is one file). No new dependencies, no schema
migrations (relations are just string ids inside the existing `records.data` JSON).

Scope: single-id relations, one level of expand.
`// ponytail: single-id relations only; multi-id arrays (value = ["id1","id2"], expand = array of records) is the upgrade.`

## 1. Schema: new field type `relation`

A schema field of type `relation` carries an options object naming the target collection:

```json
{"name": "author", "type": "relation", "required": false, "options": {"collection": "authors"}}
```

### `collections_create` changes

The field loop currently whitelists `["text", "number", "bool", "json"]`. Add `"relation"`, and
for relation fields require `options.collection` to be a string passing `ident_ok`:

```rust
if fty == "relation" {
    let target = f.pointer("/options/collection").and_then(|c| c.as_str()).unwrap_or("");
    if !ident_ok(target) {
        return Err(err(StatusCode::BAD_REQUEST,
            "relation fields need options.collection naming a target collection"));
    }
}
```

Update the generic error message to `text|number|bool|json|relation`. Do NOT check that the
target collection exists at schema time — record writes already fail closed (see §2), and
skipping the check allows self-relations.
`// ponytail: target existence checked per-write, not at schema time; validate here if bad-schema footguns bite.`

## 2. Record create/update: validate relation values

### `validate()` (pure, keep it DB-free)

Add a type arm: a relation value must be a string (null still allowed by the existing
`v.is_null() ||` guard):

```rust
"relation" => v.is_string(),
```

Error stays the existing shape: `field 'author' must be relation`.

### New helper `check_relations` (DB existence check)

```rust
fn check_relations(db: &Connection, schema: &[Value], data: &Map<String, Value>) -> Result<(), String> {
    for f in schema {
        if f.get("type").and_then(|t| t.as_str()) != Some("relation") { continue; }
        let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("");
        let Some(id) = data.get(name).and_then(|v| v.as_str()) else { continue }; // absent or null: fine
        let target = f.pointer("/options/collection").and_then(|c| c.as_str()).unwrap_or("");
        if fetch_record(db, target, id).is_none() {
            return Err(format!("field '{name}': no record '{id}' in '{target}'"));
        }
    }
    Ok(())
}
```

Call it in **both** `record_create` and `record_update`, immediately after the existing
`validate(...)` call, mapping errors the same way:

```rust
check_relations(&db, &schema, &data).map_err(|m| err(StatusCode::BAD_REQUEST, m))?;
```

(In `record_update` pass `&patch`, not the merged map — only fields being written are checked.)
`required: true` on a relation field is already enforced by the existing required loop in
`validate`. Deleting a target record leaves dangling ids; expand then silently omits the field.
`// ponytail: no referential integrity on delete; add a records-scan guard in record_delete if dangling ids hurt.`

## 3. Expand: `?expand=field1,field2` on list and view

`GET /api/collections/{name}/records?expand=author` and
`GET /api/collections/{name}/records/{id}?expand=author`. One level deep — expanded records are
plain records, never expanded themselves.

### Plumbing

- Add `expand: Option<String>` to `ListParams`.
- `record_view` gains a `Query(q): Query<ListParams>` extractor (reuse the struct; the unused
  fields are all `Option`, harmless).
- Both handlers already call / will call `get_collection` — `records_list` currently discards
  the result (`.is_none()` check); change it to bind `(_, schema)` when `q.expand` is set
  (or always; it's one row).

### New helper `expand_record`

```rust
fn expand_record(db: &Connection, schema: &[Value], rec: &mut Value, expand: &str) {
    let mut out = Map::new();
    for field in expand.split(',').map(str::trim) {
        let Some(def) = schema.iter().find(|f|
            f.get("name").and_then(|n| n.as_str()) == Some(field)
            && f.get("type").and_then(|t| t.as_str()) == Some("relation")) else { continue };
        let Some(id) = rec.get(field).and_then(|v| v.as_str()) else { continue };
        let target = def.pointer("/options/collection").and_then(|c| c.as_str()).unwrap_or("");
        if let Some((data, created, updated)) = fetch_record(db, target, id) {
            out.insert(field.into(), record_json(target, id, &data, &created, &updated));
        }
    }
    if !out.is_empty() {
        rec.as_object_mut().unwrap().insert("expand".into(), Value::Object(out));
    }
}
```

Unknown fields, non-relation fields, null values, and dangling ids are all silently skipped
(PocketBase parity). `record_json` already strips `password_hash`, so expanding into auth
collections leaks nothing. In `records_list`, call it on each item inside the existing
`query_map` mapping (or in a loop after collect); in `record_view`, on the single record —
only when `q.expand` is `Some`.

### Response shape (view; list items are identical inside `items`)

```json
{
  "id": "b31cd94a1f2e3d4", "collectionName": "posts",
  "title": "hello", "author": "9f8e7d6c5b4a321",
  "created": "2026-08-18 10:00:00", "updated": "2026-08-18 10:00:00",
  "expand": {
    "author": { "id": "9f8e7d6c5b4a321", "collectionName": "authors",
                "name": "Og", "created": "…", "updated": "…" }
  }
}
```

No `expand` key at all when nothing resolved.

## 4. Acceptance tests

Add one `#[tokio::test] async fn relations()` to the existing `mod tests`, same `call` helper.
Setup: admin-create `authors` (schema: `name` text) and `posts`
(schema: `title` text required; `author` relation → `authors`), sign up + login a user.

1. Create collection with `{"type":"relation"}` but no `options.collection` → 400.
2. Create author, then post with `"author": <real id>` → 200; response echoes the id string.
3. Create post with `"author": "nope"` → 400.
4. Create post with `"author": null` (field not required) → 200.
5. Create post with `"author": 42` → 400 (type check, no DB hit).
6. PATCH a post to `"author": "nope"` → 400; PATCH to another real author id → 200.
7. `GET /api/collections/posts/records/{id}?expand=author` → 200,
   `body["expand"]["author"]["name"]` matches; `?expand=title,bogus` → 200 with no `expand` key.
8. List `GET …/records?expand=author` → every item with an author has `expand.author`;
   delete the author, re-fetch with expand → 200, record keeps the dangling `author` id,
   `expand` omits it.
