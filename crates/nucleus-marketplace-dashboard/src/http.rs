//! The thin axum SSE edge (feature `server`). It only maps the already-tested
//! [`Hub`] stream onto Server-Sent Events — no business logic lives here.
//!
//! Routes:
//! - `GET /api/events` — SSE stream. Honours `Last-Event-ID` (replays buffered
//!   events newer than that id, then the live feed). One-way fan-out ⇒ SSE, not
//!   WebSocket: native browser reconnect, plain HTTP, no upgrade handshake.
//! - `GET /api/snapshot` — the reduced [`MarketState`] for a cold client.
//! - `GET /api/receipt/{settlement_id}` — the receipt bound to a settlement, for
//!   one-click in-browser verification.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use futures::stream::{self, Stream, StreamExt};
use tokio_stream::wrappers::BroadcastStream;

use crate::event::MarketEvent;
use crate::hub::Hub;

/// Build the dashboard router over a shared [`Hub`].
pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/api/events", get(events))
        .route("/api/snapshot", get(snapshot))
        .route("/api/receipt/{settlement_id}", get(receipt))
        .with_state(hub)
}

async fn snapshot(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    Json(hub.snapshot())
}

async fn receipt(State(hub): State<Arc<Hub>>, Path(settlement_id): Path<u64>) -> impl IntoResponse {
    match hub.receipt(settlement_id) {
        Some(r) => Json(r).into_response(),
        None => (StatusCode::NOT_FOUND, "no receipt for that settlement id").into_response(),
    }
}

async fn events(
    State(hub): State<Arc<Hub>>,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let last_id = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0);

    // Subscribe FIRST so no event slips between replay and live; the replay may
    // overlap the live buffer, so the client dedups by id (it tracks max id).
    let live = BroadcastStream::new(hub.subscribe());
    let replay = hub.replay_since(last_id);

    let replay_stream = stream::iter(replay).map(|ev| to_event(&ev));
    let live_stream = live.filter_map(|res| async move {
        match res {
            Ok(ev) => Some(to_event(&ev)),
            // A lagged subscriber drops the gap here; it recovers via the
            // snapshot + Last-Event-ID replay on reconnect.
            Err(_lagged) => None,
        }
    });

    let merged = replay_stream
        .chain(live_stream)
        .map(Ok::<Event, Infallible>);
    Sse::new(merged).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// Serialise a [`MarketEvent`] to an SSE frame, carrying its id as the SSE event
/// id so `Last-Event-ID` resume works.
fn to_event(ev: &MarketEvent) -> Event {
    Event::default()
        .id(ev.id().to_string())
        .json_data(ev)
        .unwrap_or_else(|_| Event::default())
}
