//! One node-wide bound on reserved upload payload storage.
use std::sync::{Arc, Mutex};

pub(crate) const DEFAULT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone)]
pub(crate) struct Budget(Arc<Mutex<u64>>);
impl Budget {
    pub(crate) fn new(bytes: u64) -> Result<Self, String> {
        if bytes == 0 {
            return Err("upload staging capacity must be nonzero".into());
        }
        Ok(Self(Arc::new(Mutex::new(bytes))))
    }

    pub(super) fn reserve(&self, bytes: u64) -> Result<Reservation, super::Refusal> {
        let mut available = self.0.lock().map_err(|_| {
            super::Refusal::Named("host upload staging accounting unavailable".into())
        })?;
        if bytes > *available {
            return Err(super::Refusal::Named(
                "host upload staging capacity exhausted; retry after active uploads finish".into(),
            ));
        }
        *available -= bytes;
        Ok(Reservation {
            budget: self.clone(),
            bytes,
        })
    }
}

/// Reserve the per-call maximum up front: an accepted upload cannot run out of
/// its node-wide reservation halfway through staging or while awaiting review.
#[must_use]
pub(super) struct Reservation {
    budget: Budget,
    bytes: u64,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut available) = self.budget.0.lock() {
            *available += self.bytes;
        }
    }
}
