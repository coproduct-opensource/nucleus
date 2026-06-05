//! Injectable clock so emitted timestamps are deterministic under test.

use std::sync::atomic::{AtomicI64, Ordering};

/// A source of wall-clock time (Unix milliseconds).
pub trait Clock: Send + Sync {
    /// Current time in Unix milliseconds.
    fn now_unix_ms(&self) -> i64;
}

/// Real wall clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    }
}

/// A deterministic, advanceable clock for tests. Every read returns the current
/// fixed value; [`FixedClock::advance`] moves it forward.
#[derive(Debug)]
pub struct FixedClock(AtomicI64);

impl FixedClock {
    /// Start at `start_ms`.
    pub fn new(start_ms: i64) -> Self {
        FixedClock(AtomicI64::new(start_ms))
    }

    /// Advance the clock by `delta_ms` and return the new value.
    pub fn advance(&self, delta_ms: i64) -> i64 {
        self.0.fetch_add(delta_ms, Ordering::SeqCst) + delta_ms
    }
}

impl Default for FixedClock {
    fn default() -> Self {
        FixedClock::new(1_700_000_000_000)
    }
}

impl Clock for FixedClock {
    fn now_unix_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_is_deterministic_and_advanceable() {
        let c = FixedClock::new(1000);
        assert_eq!(c.now_unix_ms(), 1000);
        assert_eq!(c.now_unix_ms(), 1000); // stable until advanced
        assert_eq!(c.advance(500), 1500);
        assert_eq!(c.now_unix_ms(), 1500);
    }

    #[test]
    fn system_clock_is_monotonic_ish_and_positive() {
        let c = SystemClock;
        let a = c.now_unix_ms();
        let b = c.now_unix_ms();
        assert!(a > 0 && b >= a);
    }
}
