//! Test-only observation points on the `SHIP_RECEIPT` path, one per pod.
//!
//! A race test that orders "the receipt is mid-ship" against "cancel lands" with
//! wall-clock sleeps measures the scheduler, not the property (#3144): under load
//! the cancel can run before the bridge has read the command frame, and the test
//! collects nothing. These let the test wait for the two events themselves. The
//! whole module is `cfg(test)` and its call sites are too, so a production build
//! has neither the registry nor the calls.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use tokio::sync::Notify;

/// What the bridge reports for one pod. `Notify::notify_one` stores a permit,
/// so a signal sent before the test starts waiting is not lost.
#[derive(Default)]
pub(crate) struct ShipProbe {
    /// A connection has read a `SHIP_RECEIPT` command frame and is about to
    /// read its body: past the between-frames stop check, so committed to it.
    pub(crate) body_read_begun: Notify,
    /// The bridge has told its connections to stop and is draining them.
    pub(crate) draining: Notify,
}

/// Keyed by pod id, because tests share a process (`cargo test`) and every
/// fixture mints a fresh `Uuid::new_v4` pod.
static PROBES: LazyLock<Mutex<HashMap<uuid::Uuid, Arc<ShipProbe>>>> = LazyLock::new(Mutex::default);

fn probe(pod: uuid::Uuid) -> Option<Arc<ShipProbe>> {
    PROBES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&pod)
        .cloned()
}

/// Start observing `pod`. Install before the guest sends anything.
#[cfg(feature = "local-driver")]
pub(crate) fn install(pod: uuid::Uuid) -> Arc<ShipProbe> {
    Arc::clone(
        PROBES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(pod)
            .or_default(),
    )
}

pub(super) fn body_read_begun(pod: uuid::Uuid) {
    if let Some(p) = probe(pod) {
        p.body_read_begun.notify_one();
    }
}

pub(super) fn draining(pod: uuid::Uuid) {
    if let Some(p) = probe(pod) {
        p.draining.notify_one();
    }
}
