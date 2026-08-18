# Spec: Embedded admin dashboard

Feature: a single-file admin UI served at `/_/`, embedded in the binary with
`include_str!`. One new file `assets/admin.html` (vanilla JS + fetch, no build step,
no framework, dark CSS, under ~400 lines total), plus ~10 lines of routing in
`src/main.rs`. No SQL changes, no new dependencies. The UI only calls existing
endpoints; the server API does not change.

## Routes (src/main.rs)

- `GET /_` , `GET /_/` , `GET /_/index.html` → all return the same embedded page,
  `200 OK`, `Content-Type: text/html; charset=utf-8`, no auth required (the page
  itself is public; every API call it makes needs the admin token).

Implementation in `src/main.rs`:

1. Import: add `response::Html` to the existing `axum::` use block (~line 8).
2. Top-level const (next to the helpers):
   ```rust
   const ADMIN_HTML: &str = include_str!("../assets/admin.html");
   async fn admin_ui() -> Html<&'static str> { Html(ADMIN_HTML) }
   ```
3. In `build_app` (~line 661), before `.with_state(app)`:
   ```rust
   .route("/_", get(admin_ui))
   .route("/_/", get(admin_ui))
   .route("/_/index.html", get(admin_ui))
   ```
   (axum 0.8 treats `/_` and `/_/` as distinct paths; register both rather than redirect.)

Nothing else in the server changes. Auth already works: `who()` (~line 169) accepts
`Authorization: Admin <token>`, and `require_writer` lets Admin write records, so the
UI uses the admin token for every REST call. `GET /api/realtime` needs no auth, which
matters because `EventSource` cannot set headers.

## assets/admin.html

One HTML file: `<style>` block, markup, one `<script>` block. Dark CSS: dark
background, light text, monospace for JSON, minimal — no icons, no fonts, no images.

### Layout

- **Login view** (shown when there is no working token): one password-type input +
  "Login" button + error line. On submit: store the value in
  `localStorage.rb_admin_token`, then `GET /api/collections` with the header; 200 →
  swap to app view, anything else → clear the stored token, show "invalid token".
  On page load, if `localStorage.rb_admin_token` exists, run the same check.
  A "Logout" link in the app view removes the key and returns to login.
- **App view**, three panels:
  - Sidebar: collection list (name + type, from `GET /api/collections`, click to
    select), a delete button per collection (`confirm()` then
    `DELETE /api/collections/{name}`), and a create form: name input, type
    `<select>` (base|auth), schema `<textarea>` prefilled with `[]`, submit →
    `POST /api/collections` with `{"name":..., "type":..., "schema": <parsed>}`.
  - Main: records of the selected collection. Table columns: `id`, `data` (compact
    `JSON.stringify` of the record minus `id`/`collectionName`/`created`/`updated`,
    truncated to ~120 chars), `updated`, plus Edit/Delete buttons per row. Loaded via
    `GET /api/collections/{name}/records?page={p}&perPage=30`; below the table,
    "prev" / "page X of Y (N items)" / "next" driven by `totalPages`/`totalItems`.
    Above the table a JSON `<textarea>` + Save button + "New" button:
    - New: clear textarea to `{}`; Save → `POST .../records` with the parsed object.
    - Edit: fill textarea with the row's record **minus the four system fields**
      (the server's `validate()` rejects unknown fields, so sending `id` back = 400);
      Save → `PATCH .../records/{id}`.
    - Delete: `confirm()` then `DELETE .../records/{id}`.
    After any successful write, reload the current page of records.
  - Event feed: fixed panel with a list; `new EventSource('/api/realtime')` on app
    start, each message prepended as one line (`action`, `record.collectionName`,
    `record.id`), capped at 50 entries (drop the oldest). EventSource auto-reconnects;
    no manual retry code.

### JS contract

- One fetch helper; every REST call goes through it:
  ```js
  async function api(method, path, body) {
    const r = await fetch(path, { method,
      headers: { 'Authorization': 'Admin ' + localStorage.rb_admin_token,
                 ...(body ? { 'Content-Type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.message || 'HTTP ' + r.status);
    return j;
  }
  ```
  Callers `try/catch` and show `e.message` in a single status line element.
- **Escaping rule (hard requirement): all server data enters the DOM via
  `textContent` or `document.createElement` + `textContent`. `innerHTML` must not
  appear anywhere in the file** — build rows with `createElement`. Static markup is
  written as HTML, not injected.
- Textarea JSON is parsed with `JSON.parse` inside try/catch; parse failure shows
  "invalid JSON" in the status line and sends no request.
- No routing, no state library: module-level `let current = {name, page}` plus
  `render` functions.

## Edge cases

- Token revoked mid-session: any `api()` 401 shows the error; user hits Logout.
  (No auto-logout on 401 — one line saved, error text is clear enough.)
- Deleting the currently selected collection: clear `current`, empty the records
  panel, refresh the sidebar.
- Editing a record then Save on a stale row: server PATCHes whatever exists; a 404
  ("record not found") surfaces in the status line.
- Auth-collection records: created through the same JSON textarea
  (`{"email":..., "password":...}`); the server strips `password_hash` from
  responses already, so the edit textarea never contains it.
- `perPage` fixed at 30; `totalPages` of 0 (empty collection) renders "page 1 of 0
  (0 items)" with both pager buttons disabled — fine.
- SSE feed shows events from all collections, not just the selected one (matches
  the server: no topic filtering on the bare endpoint).

## Acceptance tests (add to `mod tests` in src/main.rs)

1. `GET /_/` with no auth header → 200 and `content-type` starts with `text/html`.
2. `GET /_` and `GET /_/index.html` → 200, body identical to `/_/`.
3. Body contains `Authorization` and `Admin ` and `rb_admin_token` (login wiring
   is present in the embedded asset).
4. Body contains `EventSource` and `/api/realtime` (live feed wired).
5. Body does NOT contain `innerHTML` (mechanical enforcement of the escaping rule).
6. Body contains `textContent` (data goes into the DOM the safe way).
7. Body line count is under 400: `ADMIN_HTML.lines().count() < 400`.
8. Existing `full_flow` test stays green untouched (no API behavior changed).

Tests 1–7 are one `#[tokio::test] async fn admin_ui_served()` using the existing
`call()` helper for 1–2 (plus a raw `oneshot` for the content-type header) and plain
string asserts on `ADMIN_HTML` for 3–7.

## Out of scope (agreed)

- Serving any other static asset, favicon, or `/_/{path}` wildcard — one HTML file only.
- Admin accounts/sessions — the raw token in localStorage is the login.
  <!-- ponytail: token sits in localStorage; move to a cookie + real admin users if this ever faces the internet -->
- Schema editing UI (field-by-field forms) — the JSON textarea is the editor.
- Filter/sort/search controls in the records table — paginate only; the API supports
  `filter`/`sort` when someone wants to add two inputs later.
