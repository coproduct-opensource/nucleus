//! Settle, at startup, the pods a previous life of this node left registered.
//!
//! # The defect this closes
//!
//! [`super::PodAuthority::restore_from_disk`] re-allocates every `pods/<id>/authority.json` it
//! finds against its parent's ledger, so each one counts as a live child and holds its
//! allocation. A record outlives its pod whenever the node stops without releasing it: SIGKILL, a
//! crash, or a drain that hit its deadline. The container driver's startup recovery
//! (`container_recovery::drain`) releases the records of the containers it removes; nothing did
//! for the Firecracker driver. `jail_reclaim` kills the stranded VMMs, but their records stayed
//! allocated, each one holding its parent's budget and one of its `max_children_per_pod` slots
//! until an operator removed the file by hand.
//!
//! # Why every restored record is released
//!
//! No pod of a previous life runs in this one. Startup reaches this only after the driver's own
//! recovery has succeeded: under the jailer, every stranded VMM confirmed dead (`jail_reclaim`
//! refuses startup otherwise); under the container driver, every owned container removed. The
//! new life registers no pod before it serves, so every record left is a pod nothing will reap.
//! A pod that survived anyway (an unjailed VMM after SIGKILL) cannot spend through this node: its
//! caller token was derived from the previous life's secret, and releasing its record also stops
//! it delegating.
//!
//! # What each one is charged
//!
//! A pod that ran: [`ReleaseKind::Exited`], the same settlement its reaper would have applied.
//! That is its whole allocation, or, when its binding settles `metered`, what the host metered
//! into its own ledger (persisted before each charge was dispatched, so never less than what was
//! spent), at most its allocation. The settle mode is the one recorded with the pod at admission,
//! not the binding's current one.
//!
//! None is refunded as unspawned. The record is written at admission, before the spawn, and
//! nothing durable says whether the VMM then started; a refund for a pod that ran would hand back
//! budget it spent (ADR 0007 A-1). A metered pod that never ran metered nothing, so it is charged
//! nothing anyway.
//!
//! Children are released before their parents, so a child's settlement folds into its parent's
//! consumption before the parent itself is settled.

use uuid::Uuid;

use super::settle::{ReleaseKind, release};
use super::{Parent, PodAuthority};

impl PodAuthority {
    /// Release every pod restored from disk, children first, and return how many. Call once at
    /// startup, after `restore_from_disk` and the driver's recovery, before serving: it settles
    /// everything registered, so a pod admitted in this life must not be registered yet.
    pub async fn release_previous_life(&self) -> usize {
        let order = {
            let inner = self.inner.lock().await;
            let depth = |mut id: Uuid| {
                let mut d = 0usize;
                while let Some(Parent::Pod(p)) = inner.pods.get(&id).map(|e| e.parent) {
                    d += 1;
                    if d > inner.pods.len() {
                        break; // a cycle no admission can write; stop, do not spin
                    }
                    id = p;
                }
                d
            };
            let mut order: Vec<(usize, Uuid)> =
                inner.pods.keys().map(|id| (depth(*id), *id)).collect();
            order.sort_unstable_by(|a, b| b.cmp(a));
            order
        };
        for (_, id) in &order {
            tracing::info!(pod = %id, "released a pod left registered by a previous node life");
            release(&self.inner, &self.state_dir, *id, ReleaseKind::Exited).await;
        }
        order.len()
    }
}
