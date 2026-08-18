> **HISTORICAL — superseded, and WRONG ON SECURITY.**
> This document declares rule-aware filtering "out of scope" and accepts an open leak.
> That was overridden: `/api/realtime` had been broadcasting every record change to
> every subscriber including guests, so anyone could watch records `listRule`/`viewRule`
> hides. Events are now gated by the same rules as reads. Also written when the crate
> was a single `src/main.rs`; the layout claims are wrong.
> The authoritative specification is `tests/realtime.rs` plus the source.
> Do not implement from this document.

# Spec: Realtime topics

Feature: server-side topic filtering for the SSE stream, a `topic` field on every
broadcast payload, and an initial `clientId` event on connect. No code has been
written yet — this spec is the implementation contract. All changes live in
`src/main.rs` (the whole app is one file). No SQL/schema changes, no new dependencies.

## API

### GET /api/realtime?topics=col1,col2

- `topics` (optional query param): comma-separated collection names. Only events whose
  collection is in the list are forwarded. Missing param, empty value (`topics=`), or a
  value that is only commas/whitespace = no filtering (all events, current behavior).
- Auth: none required (unchanged). Rule-aware filtering is explicitly out of scope (see ponytail below).
- On connect, before any broadcast event, the server sends exactly one SSE event whose
  data is `{"clientId":"<32-hex-uuid>"}` (from `uuid::Uuid::new_v4().simple()`, same
  style as the JWT-secret default). No SSE `event:` name, plain `data:` line. The
  clientId is not stored or used anywhere yet.

Example session (client subscribed with `?topics=posts`):

```
data: {"clientId":"3f2c9a1b8d4e4f6a9c0b1d2e3f405162"}

data: {"action":"create","record":{"id":"a1b2c3d4e5f6789","collectionName":"posts","title":"hi","created":"2026-08-18 10:00:00","updated":"2026-08-18 10:00:00"},"topic":"posts"}
```

A create in collection `comments` produces no frame for this client (only keep-alives).

### Broadcast payload change (all subscribers)

Every event gains `"topic": "<collection name>"` at the top level:

- create/update: `{"action":"create|update","record":{...full record...},"topic":"posts"}`
- delete: `{"action":"delete","record":{"id":"...","collectionName":"posts"},"topic":"posts"}`

REST responses are unchanged.

## Implementation (src/main.rs)

### 1. Channel carries the topic — `struct App` (~line 25)

Change `events: broadcast::Sender<String>` to `broadcast::Sender<(String, String)>`
(`(collection, serialized payload)`), so the SSE filter never parses JSON. Update the
`broadcast::channel(64)` call in `build_app` accordingly (type inference handles it).

### 2. `broadcast_change` (~line 449)

```rust
fn broadcast_change(app: &App, collection: &str, action: &str, record: &Value) {
    let payload = json!({ "action": action, "record": record, "topic": collection }).to_string();
    let _ = app.events.send((collection.to_string(), payload));
}
```

Update the three call sites to pass the collection:
- `record_create` (~line 490): `broadcast_change(&app, &name, "create", &rec);`
- `record_update` (~line 543): `broadcast_change(&app, &name, "update", &rec);`
- `record_delete` (~line 563): `broadcast_change(&app, &name, "delete", &json!({ "id": id, "collectionName": name }));`

### 3. Topics parsing (new helper, next to the other helpers)

```rust
// None = no filtering (all events)
fn parse_topics(raw: Option<&str>) -> Option<std::collections::HashSet<String>> {
    let set: std::collections::HashSet<String> = raw?
        .split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect();
    if set.is_empty() { None } else { Some(set) }
}
```

Topic names are only compared as strings — never interpolated into SQL — so no
`ident_ok` guard is needed. Unknown collection names are not an error; they simply
never match. Duplicates and stray commas are harmless.

### 4. `realtime` handler (~line 629)

```rust
#[derive(Deserialize)]
struct RtParams { topics: Option<String> }

async fn realtime(
    State(app): State<S>,
    Query(q): Query<RtParams>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    // ponytail: realtime ignores per-collection rules — every subscriber sees all
    // events for its topics regardless of auth. Fix: capture who(&app, &headers) at
    // connect and evaluate the collection's read rule per event before forwarding.
    let topics = parse_topics(q.topics.as_deref());
    let client_id = uuid::Uuid::new_v4().simple().to_string();
    let hello = tokio_stream::once(Ok::<_, Infallible>(
        Event::default().data(json!({ "clientId": client_id }).to_string()),
    ));
    let rx = app.events.subscribe();
    let stream = hello.chain(BroadcastStream::new(rx).filter_map(move |m| {
        let (topic, payload) = m.ok()?; // lagged receivers drop events, as today
        topics.as_ref().map_or(true, |t| t.contains(&topic))
            .then(|| Ok(Event::default().data(payload)))
    }));
    Sse::new(stream).keep_alive(KeepAlive::default())
}
```

`tokio_stream::once` and `StreamExt::chain` are already available via the existing
`tokio_stream` import. Route registration in `build_app` is unchanged.

## Edge cases

- `topics=` / `topics=,,` / `topics= , ` → all events (parses to None).
- `topics=nope` (nonexistent collection) → connects fine, only the clientId event ever arrives.
- Subscriber connects after an event was sent → does not receive it (broadcast semantics, unchanged).
- Slow subscriber overflows the 64-slot channel → `BroadcastStream` yields `Err(Lagged)`, dropped by `m.ok()?` (unchanged behavior).
- clientId collisions/reuse: irrelevant, the id is decorative for now.

## Acceptance tests (add to `mod tests` in src/main.rs)

Pattern for SSE tests: `let resp = app.clone().oneshot(sse_req).await` returns
immediately (the handler subscribes before returning); then read frames from
`resp.into_body()` with `http_body_util::BodyExt::frame` while issuing writes through
other `app.clone().oneshot(...)` calls. Subscribe FIRST, then write — broadcast only
delivers to existing subscribers. Frame order is deterministic (broadcast preserves order).

1. `parse_topics` unit test: `None`→None, `Some("")`→None, `Some(" , ")`→None,
   `Some("a,b")`→{a,b}, `Some(" a , a ,")`→{a}.
2. Connect to `/api/realtime` (no params): first frame is `data: {"clientId":"..."}`
   where clientId is a 32-char lowercase hex string.
3. No topics: subscribe, create a record in `posts`; second frame's JSON has
   `action == "create"`, `topic == "posts"`, and `record.collectionName == "posts"`.
4. Filtering: subscribe with `?topics=posts`; create a record in `comments`, then one
   in `posts`; the frame after clientId is the posts event (comments was filtered out).
5. Two topics: subscribe with `?topics=posts,comments`; a create in either arrives.
6. Update and delete: subscribe (no topics), PATCH then DELETE a posts record; frames
   carry `action == "update"` then `action == "delete"`, both with `topic == "posts"`,
   and the delete record is `{"id": ..., "collectionName": "posts"}`.
7. Unknown topic: subscribe with `?topics=nope`, create in `posts`, then assert via a
   second unfiltered subscriber that the event was broadcast — the `nope` subscriber's
   stream yields nothing after clientId (do not block on a frame that never comes;
   verify indirectly through the unfiltered subscriber plus the `parse_topics`/filter logic).
8. Existing `full_flow` test stays green untouched (REST responses did not change).

## Out of scope (agreed)

- Rule-aware event filtering (ponytail comment in the handler covers it).
- PocketBase's real protocol (named `PB_CONNECT` event, `POST /api/realtime` to set
  subscriptions keyed by clientId). If we ever adopt it, the clientId minted here
  becomes the subscription key; the `topics` query param is the lazy stand-in.
- Per-record topics (`collection/recordId`) — add by matching `topic` against both
  `col` and `col/id` keys when someone asks.
