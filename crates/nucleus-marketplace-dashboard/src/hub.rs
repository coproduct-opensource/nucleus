//! The fan-out hub: a tokio broadcast channel with a monotonic seq, a bounded
//! replay ring (for `Last-Event-ID` resume), the reduced [`MarketState`], and a
//! receipt store (for one-click `/api/receipt/{seq}` verification).
//!
//! Emit is serialised under one lock so id assignment, ring/state updates, and
//! the broadcast all happen in id order — a slow subscriber that lags can still
//! recover via the snapshot + replay ring.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

use crate::clock::Clock;
use crate::event::MarketEvent;
use crate::reducer::MarketState;
use nucleus_verify_commerce::Receipt;

struct Inner {
    seq: u64,
    ring: VecDeque<MarketEvent>,
    state: MarketState,
    receipts: BTreeMap<u64, Receipt>,
}

/// The marketplace event hub.
pub struct Hub {
    tx: broadcast::Sender<MarketEvent>,
    clock: Arc<dyn Clock>,
    ring_cap: usize,
    inner: Mutex<Inner>,
}

impl Hub {
    /// Create a hub. `channel_cap` bounds the live broadcast buffer (a slow
    /// subscriber past this lags and must recover via replay); `ring_cap` bounds
    /// the replay ring and the snapshot's recent-event list.
    pub fn new(clock: Arc<dyn Clock>, channel_cap: usize, ring_cap: usize) -> Arc<Self> {
        let (tx, _rx) = broadcast::channel(channel_cap);
        Arc::new(Self {
            tx,
            clock,
            ring_cap,
            inner: Mutex::new(Inner {
                seq: 0,
                ring: VecDeque::new(),
                state: MarketState::with_cap(ring_cap),
                receipts: BTreeMap::new(),
            }),
        })
    }

    /// Stamp `ev` with the next id + current time, record it (ring + reduced
    /// state), broadcast it, and return the assigned id. Ids start at 1.
    pub fn emit(&self, mut ev: MarketEvent) -> u64 {
        let ts = self.clock.now_unix_ms();
        let mut inner = self.inner.lock().unwrap();
        inner.seq += 1;
        let id = inner.seq;
        ev.stamp(id, ts);

        inner.ring.push_back(ev.clone());
        while inner.ring.len() > self.ring_cap {
            inner.ring.pop_front();
        }
        inner.state.apply(&ev);
        // Send under the lock so subscribers observe strict id order. `send`
        // errors only when there are no receivers — fine for a fan-out hub.
        let _ = self.tx.send(ev);
        id
    }

    /// Associate a [`Receipt`] with the settlement event it binds, for retrieval
    /// by `/api/receipt/{settlement_id}`.
    pub fn store_receipt(&self, settlement_id: u64, receipt: Receipt) {
        self.inner
            .lock()
            .unwrap()
            .receipts
            .insert(settlement_id, receipt);
    }

    /// Fetch a stored receipt by its settlement id.
    pub fn receipt(&self, settlement_id: u64) -> Option<Receipt> {
        self.inner
            .lock()
            .unwrap()
            .receipts
            .get(&settlement_id)
            .cloned()
    }

    /// Subscribe to the live event stream.
    pub fn subscribe(&self) -> broadcast::Receiver<MarketEvent> {
        self.tx.subscribe()
    }

    /// Replay buffered events with id strictly greater than `last_id` (for
    /// `Last-Event-ID` resume). Bounded by `ring_cap`; very old gaps are
    /// unrecoverable by design (the client falls back to the snapshot).
    pub fn replay_since(&self, last_id: u64) -> Vec<MarketEvent> {
        self.inner
            .lock()
            .unwrap()
            .ring
            .iter()
            .filter(|e| e.id() > last_id)
            .cloned()
            .collect()
    }

    /// A consistent snapshot of the reduced state (the cold-client baseline).
    pub fn snapshot(&self) -> MarketState {
        self.inner.lock().unwrap().state.clone()
    }

    /// The highest id emitted so far.
    pub fn last_id(&self) -> u64 {
        self.inner.lock().unwrap().seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FixedClock;
    use crate::event::{AgentId, MarketEvent};

    fn call(agent: &str) -> MarketEvent {
        MarketEvent::CallStarted {
            id: 0,
            ts_unix_ms: 0,
            agent: AgentId::from(agent),
            resource: "/x".into(),
            attempt: 0,
        }
    }

    #[tokio::test]
    async fn emit_stamps_monotonic_ids_and_fixed_ts() {
        let hub = Hub::new(Arc::new(FixedClock::new(5000)), 16, 16);
        assert_eq!(hub.emit(call("a")), 1);
        assert_eq!(hub.emit(call("a")), 2);
        let snap = hub.snapshot();
        assert_eq!(snap.last_id, 2);
        assert!(snap.recent.iter().all(|e| {
            matches!(e, MarketEvent::CallStarted { ts_unix_ms, .. } if *ts_unix_ms == 5000)
        }));
    }

    #[tokio::test]
    async fn replay_since_returns_only_newer_ids() {
        let hub = Hub::new(Arc::new(FixedClock::default()), 16, 16);
        for _ in 0..5 {
            hub.emit(call("a"));
        }
        let ids: Vec<u64> = hub.replay_since(2).iter().map(|e| e.id()).collect();
        assert_eq!(ids, vec![3, 4, 5]);
        assert!(hub.replay_since(5).is_empty());
    }

    #[tokio::test]
    async fn subscriber_sees_only_post_subscribe_events_in_order() {
        let hub = Hub::new(Arc::new(FixedClock::default()), 16, 16);
        hub.emit(call("before"));
        let mut rx = hub.subscribe();
        let id_a = hub.emit(call("a"));
        let id_b = hub.emit(call("b"));
        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        assert_eq!(first.id(), id_a);
        assert_eq!(second.id(), id_b);
    }

    #[tokio::test]
    async fn slow_subscriber_lags_but_replay_recovers() {
        // channel cap 2: a subscriber that never reads will lag once we emit >2.
        let hub = Hub::new(Arc::new(FixedClock::default()), 2, 64);
        let mut rx = hub.subscribe();
        for _ in 0..5 {
            hub.emit(call("a"));
        }
        // The first recv reports the lag (events were dropped from the channel)…
        let err = rx.recv().await.unwrap_err();
        assert!(matches!(
            err,
            tokio::sync::broadcast::error::RecvError::Lagged(_)
        ));
        // …but the replay ring (cap 64) still has everything for recovery.
        assert_eq!(hub.replay_since(0).len(), 5);
    }
}
