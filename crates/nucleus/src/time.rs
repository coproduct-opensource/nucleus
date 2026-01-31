//! Monotonic time enforcement.
//!
//! Unlike `lattice_guard::TimeLattice` which uses wall clock time (`Utc::now()`),
//! `MonotonicGuard` uses `quanta` monotonic clocks. This prevents:
//!
//! - **Clock manipulation**: Changing system time cannot extend validity
//! - **Timezone issues**: Monotonic clocks don't have timezones
//! - **NTP jumps**: Monotonic clocks only move forward
//!
//! ## Limitations
//!
//! Monotonic clocks reset on reboot, so guards cannot persist across restarts.
//! For persistent time bounds, combine with wall clock checks.

use quanta::Instant;
use std::time::Duration;

use crate::error::{NucleusError, Result};
use lattice_guard::TimeLattice;

/// A monotonic time guard that cannot be bypassed by clock manipulation.
///
/// Created with a duration, the guard tracks time using a monotonic clock
/// that only moves forward and cannot be manipulated.
pub struct MonotonicGuard {
    /// When the guard was created (monotonic)
    created_at: Instant,
    /// Duration the guard is valid for
    valid_duration: Duration,
    /// Whether the guard has been explicitly expired
    expired: bool,
}

impl MonotonicGuard {
    /// Create a new guard valid for the specified duration.
    pub fn new(duration: Duration) -> Self {
        Self {
            created_at: Instant::now(),
            valid_duration: duration,
            expired: false,
        }
    }

    /// Create a guard from a `TimeLattice` policy.
    ///
    /// Note: This uses the duration between `valid_from` and `valid_until` as the
    /// monotonic duration, starting from now. The actual wall clock times in the
    /// policy are ignored for monotonic enforcement.
    pub fn from_policy(policy: &TimeLattice) -> Self {
        let duration = policy.valid_until - policy.valid_from;
        let duration = duration.to_std().unwrap_or(Duration::ZERO);

        Self::new(duration)
    }

    /// Create a guard valid for the specified number of seconds.
    pub fn seconds(secs: u64) -> Self {
        Self::new(Duration::from_secs(secs))
    }

    /// Create a guard valid for the specified number of minutes.
    pub fn minutes(mins: u64) -> Self {
        Self::new(Duration::from_secs(mins * 60))
    }

    /// Create a guard valid for the specified number of hours.
    pub fn hours(hours: u64) -> Self {
        Self::new(Duration::from_secs(hours * 3600))
    }

    /// Check if the guard is still valid.
    ///
    /// Returns `Ok(())` if valid, or an error if expired.
    pub fn check(&self) -> Result<()> {
        if self.expired {
            return Err(NucleusError::TimeViolation {
                reason: "guard has been explicitly expired".into(),
            });
        }

        let elapsed = self.created_at.elapsed();
        if elapsed > self.valid_duration {
            return Err(NucleusError::TimeViolation {
                reason: format!(
                    "guard expired: valid for {:?}, elapsed {:?}",
                    self.valid_duration, elapsed
                ),
            });
        }

        Ok(())
    }

    /// Check if the guard is still valid (returns bool).
    pub fn is_valid(&self) -> bool {
        self.check().is_ok()
    }

    /// Get the remaining duration.
    pub fn remaining(&self) -> Duration {
        let elapsed = self.created_at.elapsed();
        self.valid_duration.saturating_sub(elapsed)
    }

    /// Explicitly expire the guard.
    ///
    /// Once expired, the guard cannot be un-expired.
    pub fn expire(&mut self) {
        self.expired = true;
    }

    /// Create a sub-guard with a shorter duration.
    ///
    /// The sub-guard's duration cannot exceed the parent's remaining time.
    /// Returns `None` if the parent has expired or if the requested duration
    /// exceeds the remaining time.
    pub fn sub_guard(&self, duration: Duration) -> Option<MonotonicGuard> {
        if !self.is_valid() {
            return None;
        }

        let remaining = self.remaining();
        if duration > remaining {
            return None;
        }

        Some(MonotonicGuard::new(duration))
    }
}

/// A guard that wraps an action and only allows execution while valid.
///
/// This is the enforcement equivalent of `GuardedAction` - but instead of being
/// a proof token, it's an active guard that checks time on each access.
pub struct TimedAction<T> {
    /// The wrapped action
    action: T,
    /// The time guard
    guard: MonotonicGuard,
}

impl<T> TimedAction<T> {
    /// Create a new timed action.
    pub fn new(action: T, duration: Duration) -> Self {
        Self {
            action,
            guard: MonotonicGuard::new(duration),
        }
    }

    /// Execute a function on the action if the guard is still valid.
    pub fn with<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&T) -> R,
    {
        self.guard.check()?;
        Ok(f(&self.action))
    }

    /// Execute a mutable function on the action if the guard is still valid.
    pub fn with_mut<F, R>(&mut self, f: F) -> Result<R>
    where
        F: FnOnce(&mut T) -> R,
    {
        self.guard.check()?;
        Ok(f(&mut self.action))
    }

    /// Consume the action if the guard is still valid.
    pub fn take(self) -> Result<T> {
        self.guard.check()?;
        Ok(self.action)
    }

    /// Check if the action is still accessible.
    pub fn is_valid(&self) -> bool {
        self.guard.is_valid()
    }

    /// Get remaining time.
    pub fn remaining(&self) -> Duration {
        self.guard.remaining()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_basic_guard() {
        let guard = MonotonicGuard::seconds(10);
        assert!(guard.is_valid());
        assert!(guard.check().is_ok());
    }

    #[test]
    fn test_guard_expiration() {
        let guard = MonotonicGuard::new(Duration::from_millis(50));
        assert!(guard.is_valid());

        // Wait for expiration
        thread::sleep(Duration::from_millis(100));

        assert!(!guard.is_valid());
        assert!(guard.check().is_err());
    }

    #[test]
    fn test_explicit_expiration() {
        let mut guard = MonotonicGuard::seconds(3600);
        assert!(guard.is_valid());

        guard.expire();
        assert!(!guard.is_valid());
    }

    #[test]
    fn test_sub_guard() {
        let guard = MonotonicGuard::seconds(60);

        // Can create sub-guard with shorter duration
        let sub = guard.sub_guard(Duration::from_secs(30)).unwrap();
        assert!(sub.is_valid());

        // Cannot create sub-guard exceeding remaining time
        assert!(guard.sub_guard(Duration::from_secs(120)).is_none());
    }

    #[test]
    fn test_timed_action() {
        let action = TimedAction::new("hello", Duration::from_secs(10));

        let result = action.with(|s| s.len()).unwrap();
        assert_eq!(result, 5);
    }

    #[test]
    fn test_timed_action_expiration() {
        let action = TimedAction::new("hello", Duration::from_millis(50));

        // Wait for expiration
        thread::sleep(Duration::from_millis(100));

        let result = action.with(|s| s.len());
        assert!(result.is_err());
    }

    #[test]
    fn test_remaining_time() {
        let guard = MonotonicGuard::seconds(10);
        let remaining = guard.remaining();

        // Should be close to 10 seconds
        assert!(remaining.as_secs() >= 9);
        assert!(remaining.as_secs() <= 10);
    }
}
