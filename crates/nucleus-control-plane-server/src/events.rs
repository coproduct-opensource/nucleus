//! Per-job event broker for the SSE stream endpoint.
//!
//! Each `JobId` gets a lazily-created `tokio::sync::broadcast::Sender`.
//! Producers (`spawn_job`) publish lifecycle transitions; the SSE
//! handler subscribes and streams them.
//!
//! Late-subscriber semantics: the SSE handler reads the current state
//! from the [`JobRegistry`] *before* subscribing, so a client that
//! connects after a terminal event was published still sees that
//! state. The broker is allowed to drop channels once all subscribers
//! disconnect; the registry remains the authoritative source.
//!
//! [`JobRegistry`]: crate::registry::JobRegistry

use std::collections::HashMap;
use std::sync::RwLock;

use nucleus_control_plane::{JobId, JobState};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Channel buffer per job. Small because lifecycle transitions are
/// rare; lagging receivers will get `RecvError::Lagged` which the SSE
/// handler treats as a soft warning (we re-fetch state from the
/// registry and continue).
const PER_JOB_CHANNEL_CAPACITY: usize = 32;

/// One published event on the per-job stream.
///
/// Wire format on the SSE channel: each `JobEvent` JSON-serializes
/// into an `event: <name>\ndata: <json>\n\n` block. The `name` is the
/// snake_case tag of the enum variant; `data` is the JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum JobEvent {
    /// Job has transitioned to a new state.
    StateChanged { state: JobState },
    /// Server is closing the stream (terminal state reached or
    /// explicit close). The client SHOULD stop reconnecting.
    Closing { reason: &'static str },
}

impl JobEvent {
    /// Stable wire-format name for the `event:` line in the SSE frame.
    pub fn name(&self) -> &'static str {
        match self {
            JobEvent::StateChanged { .. } => "state_changed",
            JobEvent::Closing { .. } => "closing",
        }
    }
}

/// Broker holds one broadcast channel per active job.
pub struct JobEventBroker {
    inner: RwLock<HashMap<JobId, broadcast::Sender<JobEvent>>>,
}

impl JobEventBroker {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Publish an event for `job_id`. Lazily creates the channel if no
    /// one is subscribed yet — the event is still dropped (broadcast
    /// keeps no backlog beyond live subscribers) but the channel will
    /// exist for future subscribers.
    ///
    /// Returns the number of receivers that observed the event. Useful
    /// for tests and back-pressure reasoning; production callers can
    /// ignore.
    pub fn publish(&self, job_id: &JobId, event: JobEvent) -> usize {
        // Get or create channel.
        let sender = {
            let read = self.inner.read().expect("broker lock");
            read.get(job_id).cloned()
        };
        let sender = match sender {
            Some(s) => s,
            None => {
                let mut write = self.inner.write().expect("broker lock");
                write
                    .entry(job_id.clone())
                    .or_insert_with(|| broadcast::channel(PER_JOB_CHANNEL_CAPACITY).0)
                    .clone()
            }
        };
        sender.send(event).unwrap_or(0)
    }

    /// Subscribe to a job's event stream. Returns `None` if no channel
    /// exists yet (which is fine for callers to handle: they should
    /// fall back to polling the registry).
    pub fn subscribe(&self, job_id: &JobId) -> Option<broadcast::Receiver<JobEvent>> {
        let read = self.inner.read().expect("broker lock");
        read.get(job_id).map(|s| s.subscribe())
    }

    /// Drop the broadcast channel for a job. Call after the terminal
    /// event has been published; the registry retains the final state.
    pub fn close(&self, job_id: &JobId) {
        let mut write = self.inner.write().expect("broker lock");
        write.remove(job_id);
    }
}

impl Default for JobEventBroker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn job() -> JobId {
        JobId::new()
    }

    fn queued() -> JobState {
        JobState::Queued {
            submitted_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn subscribe_receives_published_event() {
        let broker = JobEventBroker::new();
        let id = job();
        // Publish first creates the channel.
        broker.publish(&id, JobEvent::StateChanged { state: queued() });
        // Now subscribe; receiver should NOT see the prior event (broadcast
        // has no backlog) — this is the point of the "registry catch-up"
        // pattern in the SSE handler.
        let mut rx = broker.subscribe(&id).expect("channel must exist");
        broker.publish(
            &id,
            JobEvent::Closing {
                reason: "test-close",
            },
        );
        let evt = rx.recv().await.unwrap();
        assert!(matches!(evt, JobEvent::Closing { .. }));
    }

    #[tokio::test]
    async fn subscribe_returns_none_for_unknown_job() {
        let broker = JobEventBroker::new();
        let id = job();
        assert!(broker.subscribe(&id).is_none());
    }

    #[tokio::test]
    async fn close_removes_channel() {
        let broker = JobEventBroker::new();
        let id = job();
        broker.publish(&id, JobEvent::StateChanged { state: queued() });
        assert!(broker.subscribe(&id).is_some());
        broker.close(&id);
        assert!(broker.subscribe(&id).is_none());
    }
}
