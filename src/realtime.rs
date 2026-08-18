use std::collections::HashSet;
use std::convert::Infallible;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::sse::{Event, KeepAlive, Sse},
};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::auth::{who, who_from_query_token, Who};
use crate::db::get_collection;
use crate::rules::{auth_id, check_rule, eval_rule_mem, VIEW};
use crate::{App, S};

#[derive(Deserialize)]
pub struct RtParams {
    topics: Option<String>,
    /// Browser `EventSource` cannot send an Authorization header, so a subscription
    /// may carry its credential here instead. Header wins whenever one is present.
    token: Option<String>,
}

/// Fail closed: forward an event only if this subscriber could read the record.
/// Reuses the same rule primitives as `records::gate_record` — in-memory rather
/// than SQL, because a delete event's row is already gone by delivery time.
fn visible(app: &App, w: &Who, topic: &str, record: &Value) -> bool {
    if matches!(w, Who::Admin) {
        return true;
    }
    let Some(data) = record.as_object() else {
        return false;
    };
    // Short synchronous lock, never held across an await — see auth::who.
    let col = get_collection(&app.db.lock().unwrap(), topic);
    let Some(col) = col else {
        return false;
    };
    match check_rule(w, &col.rules[VIEW]) {
        Ok(None) => true,                                       // admin-bypass or public
        Ok(Some(expr)) => eval_rule_mem(&expr, auth_id(w), data),
        Err(_) => false,                                        // NULL rule = admin only
    }
}

pub async fn realtime(
    State(app): State<S>,
    headers: HeaderMap,
    Query(q): Query<RtParams>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    // who() locks the db itself, so resolve identity once, up front, outside the stream.
    // An Authorization header, even a malformed one, decides identity on its own: a
    // ?token= appended by a redirect, a copy-pasted link, or an injected URL must never
    // change who a request is, nor silently upgrade one whose real credential expired.
    let w = match (headers.contains_key("authorization"), q.token.as_deref()) {
        (true, _) => who(&app, &headers),
        (false, Some(t)) => who_from_query_token(&app, t),
        (false, None) => Who::Guest,
    };
    // empty / whitespace / comma-only all mean "no filter"
    let topics: HashSet<String> = q
        .topics
        .unwrap_or_default()
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    let rx = app.events.subscribe();
    let hello = tokio_stream::once(Ok::<_, Infallible>(Event::default().data(
        json!({ "clientId": uuid::Uuid::new_v4().simple().to_string() }).to_string(),
    )));
    let changes = BroadcastStream::new(rx).filter_map(move |m| {
        let ev = m.ok()?;
        let topic = ev.get("topic")?.as_str()?.to_string();
        if !topics.is_empty() && !topics.contains(&topic) {
            return None;
        }
        visible(&app, &w, &topic, ev.get("record")?)
            .then(|| Ok(Event::default().data(ev.to_string())))
    });
    Sse::new(hello.chain(changes)).keep_alive(KeepAlive::default())
}
