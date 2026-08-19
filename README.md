# rockbase

[![CI](https://github.com/baocin/rockbase/actions/workflows/ci.yml/badge.svg)](https://github.com/baocin/rockbase/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A PocketBase-shaped backend in a single Rust binary: axum 0.8 over rusqlite, JSON
records in SQLite, dynamic collections defined at runtime, JWT auth, per-collection
API rules, file uploads, SSE realtime, transactional batch writes, and a one-file
admin UI.

It is not PocketBase. It reproduces the parts of PocketBase's HTTP shape that this
codebase implements, and nothing else. The source is ~2,500 lines across twelve
modules in `src/`; the behavior below is what those modules and the 135 tests do.

> The documents in `specs/` are historical. They describe an earlier single-file
> design, predate per-collection rules, and in three places recommend behavior that
> was deliberately overridden (most notably: file downloads are **not** unauthenticated).
> This README is the reference.

---

## Running it

```
cargo run
```

```
admin token: 3f2b91c4e8a34d0fb1c7d9e2a5468b0c
rockbase on http://127.0.0.1:8090
```

The admin token is printed once at startup. If `RB_ADMIN_TOKEN` is not set, a fresh
random one is generated on every start — restart the server and the old one stops
working. Set it explicitly for anything longer-lived than a scratch session.

| Env var | Default | Effect |
| --- | --- | --- |
| `RB_PORT` | `8090` | Listen port. An unparseable value **panics at startup** rather than falling back. |
| `RB_DIR` | `rb_data` | Data directory. Holds `data.db` and `storage/`. Created if missing. |
| `RB_ADMIN_TOKEN` | random UUID per start | The admin bearer value (`Authorization: Admin <token>`). |
| `RB_JWT_SECRET` | random UUID, persisted in the DB | HMAC secret for user JWTs. When unset, a secret is generated once and stored in the `_params` table, so user tokens survive restarts. |

The server binds `127.0.0.1` only; the address is not configurable. Every request is
logged as one line: `GET /api/health 200 1ms`.

**Admin UI:** `http://127.0.0.1:8090/_/` — a single static HTML page (`assets/admin.html`,
compiled in with `include_str!`). It serves byte-identical HTML to everyone; no secret
is ever templated into it. You paste the admin token into the login box and it is kept
in `localStorage` under `rb_admin_token`. It can create/browse collections, page through
and edit records, and shows a live event feed. The feed opens
`new EventSource('/api/realtime?token=<admin token>')` (see [Realtime](#realtime)), so it
sees every collection rather than only guest-visible ones. That is the only place the
dashboard puts the token in a URL, and it is why `?token=` is accepted on
`/api/realtime` alone and never on the REST API.

Only `/_`, `/_/` and `/_/index.html` are served. There is no wildcard under `/_/`.

---

## Authentication

Two credential shapes, both in the `Authorization` header:

- `Authorization: Admin <RB_ADMIN_TOKEN>` — full bypass of every API rule.
- `Authorization: Bearer <jwt>` — an auth-collection record. The token is HS256 with
  claims `{sub, col, exp}` and a 7-day lifetime. On every request the record named by
  the token is looked up; **a deleted user's token behaves exactly like no token.**

Anything else, including a malformed or expired token, is a guest.

`GET /api/realtime` additionally accepts `?token=<credential>` because browser
`EventSource` cannot set a header. That fallback is SSE-only — see
[Realtime](#realtime).

---

## Data model

**Collections** are rows in `_collections(name, type, schema, list_rule, view_rule,
create_rule, update_rule, delete_rule)`. Names must match `[A-Za-z0-9_]{1,64}`.
Two types:

- `base` — plain records.
- `auth` — records that can log in. Accept `email` and `password` on write in addition
  to their schema fields, enforce a valid-looking email (must contain `@`), enforce
  uniqueness of email within the collection, and require a password of at least 8
  characters, stored as bcrypt (cost 10) under `password_hash`.

A `users` auth collection with an empty schema is seeded on first start.

**Records** all live in one table: `records(collection, id, data, created, updated)`,
primary key `(collection, id)`. `data` is a JSON object; queries reach into it with
`json_extract`. Ids are the first 15 hex characters of a v4 UUID. Timestamps are
millisecond-resolution `YYYY-MM-DD HH:MM:SS.mmm` strings, so lexicographic order is
chronological. There is no table-per-collection.

**Schema fields** are `{"name": ..., "type": ..., "required": bool, "options": {...}}`.
The supported types — the exact set `schema_ok` accepts — are:

| Type | Accepted JSON | Notes |
| --- | --- | --- |
| `text` | string | |
| `number` | number | |
| `bool` | boolean | |
| `json` | anything | no validation |
| `relation` | string | an id in the target collection; requires `options.collection` naming a valid identifier |
| `file` | string | the stored value is the bare sanitized filename |

`null` is accepted for any field unless it is `required`. Unknown field names are a 400
on write. Relation targets are **not** checked to exist at schema-definition time (this
permits self-relations and forward references); they are checked on every record write.

**Reserved field names** — rejected in schemas and as multipart part names:
`id`, `created`, `updated`, `collectionName`, `password_hash`. `record_json` injects the
first four from system columns and strips the fifth, so a schema field with one of these
names would be stored but never returned, and rules would resolve it inconsistently
between the in-memory and SQL evaluators.

A returned record is its `data` object plus `id`, `collectionName`, `created`, `updated`,
minus `password_hash`.

**Schema edits are wholesale.** `PATCH /api/collections/{name}` with a `schema` key
replaces the array. Removing a field does not remove it from already-stored records — the
value lingers in the JSON but becomes unwritable and is still returned. Adding a
`required` field does not backfill existing rows.

---

## HTTP API

All error bodies are `{"code": <status>, "message": "..."}`.

CORS is permissive and unconditional: `access-control-allow-origin: *`, methods
`GET, POST, PATCH, DELETE, OPTIONS`, headers `Authorization, Content-Type`. No
credentials. `OPTIONS` on any path short-circuits to `204` before routing.

Request bodies are capped at 10 MB; larger ones are `413` while still streaming, before
anything is written.

### Routes

Auth column: **none** = open, **rule** = governed by the collection's API rules (see
[Security model](#security-model)), **user** = any valid `Bearer`, **admin** = `Admin` token only.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/api/health` | none | `{"status":"ok"}` |
| GET | `/api/collections` | admin | List every collection with its schema and five rules |
| POST | `/api/collections` | admin | Create a collection |
| GET | `/api/collections/{name}` | admin | One collection |
| PATCH | `/api/collections/{name}` | admin | Replace `schema` and/or set rules. `name`/`type` are rejected |
| DELETE | `/api/collections/{name}` | admin | Drop the collection and all its records |
| GET | `/api/collections/{name}/records` | rule (list) | Paged list: `page`, `perPage`, `sort`, `filter`, `fields`, `expand`, `skipTotal` |
| POST | `/api/collections/{name}/records` | rule (create) | Create a record. JSON or `multipart/form-data` |
| GET | `/api/collections/{name}/records/{id}` | rule (view) | One record. Accepts `expand` |
| PATCH | `/api/collections/{name}/records/{id}` | rule (update) | Shallow merge. JSON or multipart |
| DELETE | `/api/collections/{name}/records/{id}` | rule (delete) | Deletes the record and its stored files |
| POST | `/api/collections/{name}/auth-with-password` | none | Log in. Not rule-gated — login must work before you have an identity |
| POST | `/api/collections/{name}/auth-refresh` | user | Fresh 7-day token for the same collection |
| GET | `/api/files/{collection}/{id}/{filename}` | rule (view) | Download an uploaded file |
| POST | `/api/batch` | user | Up to 50 record writes in one transaction |
| GET | `/api/realtime` | any (identity from the header, or `?token=` when there is no header) | SSE change stream. `?topics=a,b` |
| GET | `/api/backups` | admin | `VACUUM INTO` snapshot of the whole database |
| GET | `/_`, `/_/`, `/_/index.html` | none | Admin UI |

### Collections

```bash
curl -X POST localhost:8090/api/collections \
  -H 'Authorization: Admin '"$TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"posts","schema":[
        {"name":"title","type":"text","required":true},
        {"name":"views","type":"number"},
        {"name":"author","type":"relation","options":{"collection":"users"}}]}'
```

The response echoes the stored shape, including the rules that were defaulted in:

```json
{"name":"posts","type":"base","schema":[...],
 "listRule":"","viewRule":"",
 "createRule":"@request.auth.id != ''",
 "updateRule":"@request.auth.id != ''",
 "deleteRule":"@request.auth.id != ''"}
```

`PATCH` is partial across the five rule keys and wholesale for `schema`. A rule key
present with `null` sets NULL; an absent key is untouched. Unknown keys are ignored.
A non-empty rule string that does not compile is a 400 and nothing is written.

### Auth records

```bash
# sign up (users.createRule is "" — public)
curl -X POST localhost:8090/api/collections/users/records \
  -H 'Content-Type: application/json' \
  -d '{"email":"og@cave.dev","password":"clubrock1"}'

# log in
curl -X POST localhost:8090/api/collections/users/auth-with-password \
  -H 'Content-Type: application/json' \
  -d '{"identity":"og@cave.dev","password":"clubrock1"}'
# => {"token":"eyJ...","record":{"id":"...","email":"...","collectionName":"users",...}}
```

`identity` is matched against the record's `email` field. Bad credentials and a
nonexistent identity both return `400 invalid credentials`. `password_hash` never
appears in any response.

`POST /api/collections/{name}/auth-refresh` requires a `Bearer` token issued for that
same collection (an `Admin` token is rejected — an admin is not an auth record) and
returns a new token plus the current record.

### Listing records

```
GET /api/collections/posts/records?filter=views>50 && title='second'&sort=-views,title&perPage=20&page=2
```

```json
{"page":2,"perPage":20,"totalItems":41,"totalPages":3,"items":[...]}
```

| Param | Default | Behavior |
| --- | --- | --- |
| `page` | `1` | clamped to `>= 1` |
| `perPage` | `30` | clamped to `1..=500` |
| `sort` | `created ASC` | comma-separated, `-` prefix for DESC. Every segment must be a valid identifier or the request is `400 bad sort field`. `rowid ASC` is always appended as a stable tiebreak |
| `filter` | none | see below. Invalid syntax is `400 invalid filter: ...` |
| `fields` | all | comma-separated projection. `id` and `expand` always survive it. A bad segment is `400 bad fields` |
| `expand` | none | comma-separated relation field names |
| `skipTotal` | off | `skipTotal=1` skips the `COUNT(*)` and returns `-1` for `totalItems` and `totalPages` |

**Filter grammar** (`src/filter.rs`), compiled to parameterized SQL — field names are
identifier-checked before interpolation, values *always* travel as binds:

```
expr := and ("||" and)*
and  := unit ("&&" unit)*
unit := "(" expr ")" | field op value
op   := = != > >= < <= ~ !~
```

`~` / `!~` become `LIKE '%value%'` / `NOT LIKE`. Values are single-quoted strings (`''`
escapes a quote), integers, floats, `true`, `false`, `null`, or barewords. `field=null`
compiles to `IS NULL`; `>` and friends reject `null`. `id`, `created` and `updated` hit
real columns, everything else goes through `json_extract`. Filters are capped at 2048
bytes and 32 levels of nesting. Trailing input is an error, so `title='x' OR '1'='1'`
is rejected rather than interpreted.

The per-collection API rules parse with the same code, in `Mode::Rule` — see
[Security model](#the-five-rules) for the one place the two dialects differ.

Known sharp edge: `%` and `_` inside a `~` value act as LIKE wildcards; there is no
`ESCAPE` clause.

### Expanding relations

`?expand=author` inlines the related record one level deep under an `expand` key:

```json
{"id":"a1b2","title":"first","author":"u9","collectionName":"posts",
 "expand":{"author":{"id":"u9","email":"og@cave.dev","collectionName":"users",...}}}
```

Every expanded row is gated by the **target** collection's view rule against the same
caller, so `expand` can never surface a record that `GET /api/collections/{target}/records/{id}`
would have refused. A hidden, dangling, null, unknown, or non-relation target is silently
omitted and the parent still returns 200; if nothing resolves there is no `expand` key at
all. `password_hash` is stripped from expanded auth records like everywhere else.

Because `users` defaults to a NULL view rule, expanding into an auth collection returns
nothing for non-admin callers until you set `viewRule` on it.

Expansion runs *before* the `fields` projection, so `?fields=id,title&expand=author`
works — the projection would otherwise have stripped the relation id it needs.

### Files

Uploads go through the normal record create/update endpoints with
`Content-Type: multipart/form-data`. A part with a filename targets a `file` schema
field; a part without one is a plain form value (parsed as JSON if it parses, otherwise
kept as a string). Text parts must be valid UTF-8 with no control characters.

```bash
curl -X POST localhost:8090/api/collections/docs/records \
  -H "Authorization: Bearer $JWT" \
  -F 'owner=me' -F 'doc=@report.pdf'
# => {"id":"7c3...","owner":"me","doc":"report.pdf",...}

curl -H "Authorization: Bearer $JWT" \
  localhost:8090/api/files/docs/7c3.../report.pdf
```

Stored at `{RB_DIR}/storage/{collection}/{id}/{filename}`. The stored field value is
the bare sanitized filename. A file part aimed at a non-`file` field is a 400. Bytes are
written only *after* the row commits, so a rule-denied write leaves nothing on disk.
Deleting a record removes its file directory, and deleting a collection removes
`{RB_DIR}/storage/{collection}/` (`files::remove_collection_files`, called after the DB
lock is dropped — never file IO under the mutex).

Downloads set `X-Content-Type-Options: nosniff` and a content type derived solely from
the extension — `jpg/jpeg`, `png`, `gif`, `webp`, `pdf`, `txt`, `json`, everything else
`application/octet-stream`. `html` and `svg` are deliberately absent from that map:
serving attacker-uploaded markup as `text/html` from the API origin is stored XSS.

### Batch

```bash
curl -X POST localhost:8090/api/batch -H "Authorization: Bearer $JWT" \
  -H 'Content-Type: application/json' -d '{"requests":[
    {"method":"POST","url":"/api/collections/posts/records","body":{"title":"a"}},
    {"method":"PATCH","url":"/api/collections/posts/records/x1","body":{"views":9}},
    {"method":"DELETE","url":"/api/collections/posts/records/x2"}]}'
```

Returns a JSON array of results in order — the created/updated record, or `{}` for a
delete. Maximum 50 sub-requests; only `POST`/`PATCH`/`DELETE` on
`/api/collections/{c}/records[/{id}]`, with no query string and no extra segments.

Everything runs in one rusqlite transaction against the *same* core functions the
standalone routes use, rules included, so a batch can never do what the standalone
route would refuse. Any failure rolls the whole thing back and returns:

```json
{"code": 400, "message": "not allowed", "index": 1}
```

Realtime events are buffered and only published after the transaction commits, so
subscribers are never told about records that were rolled back.

### Realtime

```bash
curl -N -H "Authorization: Bearer $JWT" \
  'localhost:8090/api/realtime?topics=posts,comments'
```

The first frame is `{"clientId":"<uuid>"}`. Every subsequent frame is:

```json
{"action":"create","topic":"posts","record":{"id":"a1b2","title":"first",...}}
```

`action` is `create`, `update`, or `delete`. A delete event carries the whole record so
subscribers can be gated against it after the row is gone. `topics` is a comma-separated
allowlist; empty, whitespace, or comma-only means all topics. The broadcast channel holds
64 events; a subscriber that falls further behind drops frames. Keep-alives are on.

Every event is filtered per subscriber against the topic collection's **view rule**, and
admins receive everything.

**`?token=` — the browser fallback.** `EventSource` cannot set an Authorization header,
so a subscription may carry its credential in the query string instead:

```js
new EventSource('/api/realtime?token=' + jwt + '&topics=posts')
```

The value is a bare credential with no scheme prefix — either the admin token or a user
JWT (`who_from_query_token` in `src/auth.rs` tries admin first, then JWT). A subscriber
authenticated this way is gated exactly like a header-authenticated one; nothing about
rule evaluation changes.

Four properties, each pinned by `tests/sse_token.rs`:

- **The header always wins.** If an `Authorization` header is present at all — *even a
  malformed one* — it alone decides identity and `?token=` is ignored entirely. A token
  appended by a redirect, a copy-pasted link, or an injected URL can never change who a
  request is, nor silently upgrade one whose real credential expired.
- **An invalid token is a guest, not an error.** A bad, expired, or deleted-user token
  yields `Who::Guest`. It never 401s and never grants more than a guest gets.
- **It is SSE-only.** `who_from_query_token` is wired into `/api/realtime` and nowhere
  else. `GET /api/collections?token=<admin>` is still `401`, and
  `GET /api/collections/posts/records?token=<jwt>` still lists as a guest. A credential
  in a URL must not become general-purpose auth.
- **It is not written to the request log.** `cors_and_log` logs `req.uri().path()`, which
  excludes the query string, so the token never reaches stdout —
  `request_log_redacts_the_query_token` drives the real binary and asserts it.

A credential in a URL still lands in browser history and can leak via `Referer`, so
prefer the header wherever you can set one. That is why the admin UI does not use it.

### Backups

`GET /api/backups` runs `VACUUM INTO` to a unique temp file, streams the bytes back as
`application/octet-stream` with a `rockbase_<unix-ts>.db` filename, and deletes the temp
file. The result is a complete, consistent SQLite database — open it directly. It is a
one-shot download, not PocketBase's list/create/download trio, and the whole file is read
into memory first.

---

## Security model

This is the part worth reading twice.

### The five rules

Every collection carries five rules: `listRule`, `viewRule`, `createRule`, `updateRule`,
`deleteRule`. Each is one of three things:

| Value | Meaning |
| --- | --- |
| `null` (SQL NULL) | **Admin only.** Nobody but the `Admin` token gets through. |
| `""` (empty string) | **Public.** Everyone, including guests. |
| an expression | Evaluated per request; only matching callers/records pass. |

An `Admin` token bypasses all five, unconditionally, everywhere.

**Rule expressions are full boolean expressions**, in the same grammar `filter=` uses.
`src/filter.rs` is one parser with two backends — `to_sql` for the paths that have a row
to query (list, view, update, delete, file download) and `eval` for the paths that do not
(create, realtime SSE) — so the two can never disagree about precedence, short-circuiting
or coercion.

```
owner = @request.auth.id && status = 'published'
owner = @request.auth.id || (status = 'published' && featured = true)
title ~ 'draft'                 # LIKE '%draft%'
archived = null                 # IS NULL
```

`&&` binds tighter than `||`; parentheses override that. Operators are `=`, `!=`, `>`,
`>=`, `<`, `<=`, `~`, `!~`. Operands are:

- `@request.auth.id` — the caller's record id, or `""` for a guest. It is a node in the
  parse tree, **always** a SQL bind, never spliced into the query text, and valid in
  either operand slot.
- a single-quoted literal — `'published'`, with `''` for an inner quote. Double quotes are
  not string syntax.
- `true`, `false`, an integer, or a float.
- `null`, accepted only with `=` / `!=`, compiling to `IS NULL` / `IS NOT NULL`.
- a field name — `id`, `created` and `updated` reference the real columns; anything else
  becomes `json_extract(data, '$.name')`. Field names are identifier-checked
  (`[A-Za-z0-9_]`, ≤64 chars) *before* they reach the SQL string.

Three constraints worth knowing before you write one:

- The **left-hand side must be a field name or `@request.auth.id`**. A literal on the left
  is rejected, so `1=1` does not parse and cannot be appended to a rule.
- The right of `~` / `!~` must be a literal or the auth token, never a second field.
- Rules get the same caps as `filter=`: **2048 bytes** and **32 levels of nesting**.
  Anything longer or deeper is rejected when the rule is saved.

One dialect difference from `filter=`: an unquoted, non-numeric bareword is a *field name*
in a rule and a *string literal* in a filter. In a rule, `status = published` compares two
columns — quote the literal.

Anything that does not parse **fails closed**: the write is rejected at
collection-definition time with a `400` and the stored rule left untouched, and a
stored rule that somehow no longer compiles denies the request rather than being skipped.

**A top-level `||` is parenthesised on the way into SQL, and that is load-bearing.**
`gate_record` splices the rule fragment into a larger clause — `WHERE collection = ? AND
id = ? AND <rule>`. Without the wrap, `a || b` reassociates to `(collection AND id AND a)
OR b`, so a disjunct matching *any other row* would grant access to the row being gated.
Harmless while rules were single comparisons, a private-record read the moment `||` became
expressible. `Node::to_sql` wraps at the source rather than at each call site; pinned by
`composite_rules_gate_view_update_delete` in `tests/rules_compose.rs` and by a unit test in
`src/filter.rs`.

### Where rules are enforced

Rules are not advisory and they are not applied at one chokepoint you can route around.
They gate:

- **list** — the compiled rule is `AND`-ed into *both* the `COUNT(*)` and the page query,
  so a caller-supplied `?filter=` can only ever narrow what the rule already permits.
- **view**, **create**, **update**, **delete** — per record.
- **`?expand=`** — each expanded row is re-gated against the *target* collection's view
  rule for the same caller.
- **realtime SSE** — every event is re-gated per subscriber against the topic's view rule
  before it is forwarded.
- **batch sub-requests** — each one runs the same core function as its standalone route,
  including the gate.
- **file upload** — via the create/update rule on the record write.
- **file download** — `GET /api/files/...` runs the same view gate as
  `GET /api/collections/{c}/records/{id}`. An unguessable filename is not access control.

### 401 vs 403

A denied guest gets **401**; a denied authenticated caller gets **403**. That is the whole
convention, and it holds across records, files and expansion.

One consequence to plan around: `404` is returned *before* the rule gate on view, update,
delete and file download. So a record that exists but is hidden from you returns 401/403,
while a record that does not exist returns 404 — the existence of a hidden record is
distinguishable. This is deliberate and pinned by tests, not an accident.

A second consequence: a **`listRule` expression never produces 401/403.** It compiles into
the `WHERE` clause, so a caller who matches nothing gets `200` with `totalItems: 0`. Only a
NULL `listRule` produces a status code. `viewRule` on the same collection is what produces
401/403 for a single record.

### The defaults, and why they are not a lockdown

`base` collections:

| Rule | Default | Effect |
| --- | --- | --- |
| `listRule` | `""` | anyone can list |
| `viewRule` | `""` | anyone can read |
| `createRule` | `@request.auth.id != ''` | any logged-in user |
| `updateRule` | `@request.auth.id != ''` | any logged-in user |
| `deleteRule` | `@request.auth.id != ''` | any logged-in user |

**State this plainly: out of the box, any authenticated user can create, edit, and delete
ANY record in ANY base collection, including records belonging to other users.** The
default write rule tests only that you are *somebody*, not that you are the *right*
somebody. This reproduces the pre-rules behavior of the codebase; it is a starting point,
not a policy.

Locking a collection down is one request:

```bash
curl -X PATCH localhost:8090/api/collections/posts \
  -H "Authorization: Admin $TOKEN" -H 'Content-Type: application/json' \
  -d '{"listRule":"owner = @request.auth.id",
       "viewRule":"owner = @request.auth.id",
       "updateRule":"owner = @request.auth.id",
       "deleteRule":"owner = @request.auth.id"}'
```

`auth` collections default differently:

| Rule | Default | Effect |
| --- | --- | --- |
| `listRule` | `null` | admin only |
| `viewRule` | `null` | admin only |
| `createRule` | `""` | public signup |
| `updateRule` | `id = @request.auth.id` | own record only |
| `deleteRule` | `id = @request.auth.id` | own record only |

So a fresh `users` collection is: anyone can sign up, nobody but an admin can enumerate or
read user records (not even your own — set `viewRule` to `id = @request.auth.id` if you
want self-reads), and you can only edit or delete yourself.

Defaults are applied at collection-creation time and can be overridden in the same
`POST /api/collections` call. Once set, they are never re-applied — the rule-column
migration runs once and will not clobber rules an admin has since edited.

### Filename sanitization

`sanitize_filename` is allowlist-based in two stages, and returning `None` means *reject
the request* — never "pick a different name":

1. The raw name must be entirely printable ASCII (`' '..='~'`). This rejects NUL, CR/LF,
   RTL overrides, and the Unicode separator lookalikes `U+FF0E U+FF0F U+2024 U+2215`.
2. Keep only `[A-Za-z0-9._-]`, capped at 100 characters.

Then reject the result if it is empty, dot-only, or still contains `..`.

The reason stage 1 rejects rather than filters is the interesting part. Silently deleting
disallowed characters would reshape a name built from separator lookalikes -- a filename
whose visible characters are U+FF0E U+FF0E U+FF0F followed by `pwned.txt` -- into the
perfectly innocent-looking `pwned.txt`. That does not traverse, but it is still the wrong
answer: the server would have accepted a name crafted to deceive and handed back a clean
one. Refusing is the only honest outcome.

The same function guards the read side. `GET /api/files/.../{filename}` requires
`sanitize_filename(name) == name` exactly — the URL is a key lookup, not a file browser.
Collection and record id segments go through `ident_ok` before any path is built, in one
helper (`record_dir`) that every disk path routes through, so the guard cannot be
forgotten at a call site.

### Injection posture

Two trust boundaries, handled the same way in both the filter compiler and the rule
compiler: **identifiers are allowlist-checked before interpolation; values always travel
as SQL binds.** Rule column names in `PATCH /api/collections/{name}` come from a fixed
`RULE_KEYS` table, never from the request body. The admin UI never uses `innerHTML` (a
test enforces this mechanically) and no server-side secret is templated into the page.

---

## Known limitations

Stated plainly, because each one will bite someone.

**Batch collapses 401/403 into 400, and requires auth before rules run.** `POST /api/batch`
rejects guests outright with 401 before parsing anything. So a collection with
`createRule: ""` — public creates — accepts a guest `POST .../records` directly, but the
same create inside a batch is refused. Batch is strictly more restrictive than the routes
it wraps. Inner failures also lose their real status: a sub-request that would have been a
404 or a 403 surfaces as `{"code":400,"message":...,"index":N}`.

**`?expand=` is N+1.** Roughly `4 + 2N` queries for a page of N rows with one expand field:
count, page, parent collection, one target-collection read per requested field, then a gate
query and a fetch query per (row, field). It is fine for a 30-row page and pathological for
a 500-row one. Batching into `WHERE id IN (...)` is the fix if it ever matters.

**Realtime re-reads collection rules per event, per subscriber.** `visible()` takes the DB
lock and reloads the collection row for every event it considers. There is no cache. Rule
changes take effect immediately, which is the upside; a busy broadcast on many subscribers
is the cost.

**No graceful shutdown.** `axum::serve` is called without `with_graceful_shutdown`.
`Ctrl-C` drops in-flight requests. WAL mode plus a 5-second busy timeout means the database
survives it, but a response in progress does not.

**Rules cannot reach outside the record.** They compose freely with `&&`, `||` and
parentheses, but there is no `@request.data.*`, no relation traversal like `author.owner`,
and no functions. A rule sees the record's own fields and the caller's id, nothing else.

Smaller ones, from the source:

- One `Mutex<Connection>`. All request handling serializes on it; there is no pool.
- Replacing an uploaded file leaves the old bytes on disk until the record is deleted.
- A file write that fails after the row commits leaves a record pointing at a missing file.
- `PATCH` merges shallowly; nested objects are replaced wholesale, not merged.
- Passwords can be changed with a plain `PATCH` — there is no old-password confirmation.
- Removing a schema field leaves stale values in stored records; there is no cleanup sweep.
- CORS is `*` with no credentials and no per-origin configuration.
- `~` filter values are not LIKE-escaped, so `%` and `_` in a search term act as wildcards.
- `id`, `created` and `updated` are `null` while a `createRule` is evaluated — the row does
  not exist yet — so a `createRule` of `id = @request.auth.id` can never pass.

---

## Tests

```bash
cargo test
```

135 tests, all passing: 12 unit tests inside `src/` and 123 integration tests in `tests/`.
The integration tests drive the real `Router` through `tower::ServiceExt::oneshot` against
an in-memory SQLite database, so they exercise the actual middleware stack, not a mock.

| Suite | Tests | Covers |
| --- | --- | --- |
| `tests/batch.rs` | 20 | transaction semantics, rollback, the 50-request cap, per-sub-request rule gating |
| `tests/files.rs` | 20 | multipart upload, download, traversal attempts, content-type handling, 413, rule gating on both directions, file lifecycle |
| `tests/relations.rs` | 13 | relation validation, `expand` on list and view, expand rule gating, `password_hash` never leaking |
| `tests/colupdate.rs` | 11 | collection `GET`/`PATCH`, partial rule updates, schema replacement and its effect on existing records |
| `tests/realtime.rs` | 11 | SSE frame shape, topic filtering, per-subscriber rule gating including delete events |
| `tests/rules.rs` | 10 | rule defaults per type, NULL/`""`/expression semantics, the 401/403 ladder, admin bypass, rule validation |
| `tests/rules_compose.rs` | 10 | `&&`/`\|\|`/parenthesised rules across list, view, create, update and delete; precedence; the auth token bound inside a composite; injection payloads; malformed composites rejected on write; single-comparison regression; numeric coercion agreeing on both paths |
| `tests/sse_token.rs` | 9 | SSE `?token=`: parity with the header, admin and user tokens, header precedence (including a malformed header), invalid token = guest, rule gating, the REST API still refusing it, no token in the request log |
| `tests/adminui.rs` | 7 | the three admin routes, no wildcard, no secret in the HTML, the asset's own contract |
| `tests/cli.rs` | 7 | env config, invalid `RB_PORT` aborting startup, CORS preflight, request-log format |
| `tests/basic.rs` | 5 | end-to-end CRUD, auth, query parameters, backups, WAL persistence |
| `src/` unit tests | 12 | filter compiler (9, including the top-level-`Or` parenthesisation invariant), filename sanitizer, reserved-name rejection, `busy_timeout` |

`tests/cli.rs` — and `request_log_redacts_the_query_token` in `tests/sse_token.rs` — spawn
the real binary as a subprocess and read its stdout, so they require the binary to build;
the rest run in-process.
