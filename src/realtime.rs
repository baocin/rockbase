use std::convert::Infallible;

use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};

use crate::S;

// ponytail: NOT rule-gated — every subscriber sees every create/update/delete
// event for every collection, including rows their list/view rule would hide.
// Known hole; add per-rule SSE filtering (re-check view_rule per event) when it matters.
pub async fn realtime(
    State(app): State<S>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let rx = app.events.subscribe();
    let stream = BroadcastStream::new(rx)
        .filter_map(|m| m.ok().map(|d| Ok::<_, Infallible>(Event::default().data(d))));
    Sse::new(stream).keep_alive(KeepAlive::default())
}
