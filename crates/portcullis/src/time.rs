//! Temporal bounds lattice for permission validity windows.

use chrono::{DateTime, Duration, Utc};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Temporal bounds lattice.
///
/// Controls the time window during which a permission is valid.
/// The meet operation narrows the window to the intersection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TimeLattice {
    /// Permission is not valid before this time
    pub valid_from: DateTime<Utc>,
    /// Permission expires at this time
    pub valid_until: DateTime<Utc>,
}

impl Default for TimeLattice {
    fn default() -> Self {
        Self::with_duration(Duration::hours(1))
    }
}

impl TimeLattice {
    /// Create a time lattice with the given duration from now.
    pub fn with_duration(duration: Duration) -> Self {
        let now = Utc::now();
        Self {
            valid_from: now,
            valid_until: now + duration,
        }
    }

    /// Create a time lattice valid for the given number of hours.
    pub fn hours(n: i64) -> Self {
        Self::with_duration(Duration::hours(n))
    }

    /// Create a time lattice valid for the given number of minutes.
    pub fn minutes(n: i64) -> Self {
        Self::with_duration(Duration::minutes(n))
    }

    /// Create a time lattice with specific bounds.
    pub fn between(from: DateTime<Utc>, until: DateTime<Utc>) -> Self {
        Self {
            valid_from: from,
            valid_until: until,
        }
    }

    /// Meet operation: max of valid_from, min of valid_until.
    ///
    /// The result is the intersection of both time windows.
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            valid_from: std::cmp::max(self.valid_from, other.valid_from),
            valid_until: std::cmp::min(self.valid_until, other.valid_until),
        }
    }

    /// Join operation: min of valid_from, max of valid_until.
    ///
    /// The result is the union of both time windows.
    pub fn join(&self, other: &Self) -> Self {
        Self {
            valid_from: std::cmp::min(self.valid_from, other.valid_from),
            valid_until: std::cmp::max(self.valid_until, other.valid_until),
        }
    }

    /// Check if this lattice is less than or equal to another (partial order).
    ///
    /// A time window is "less than" another if it starts later and ends earlier.
    pub fn leq(&self, other: &Self) -> bool {
        self.valid_from >= other.valid_from && self.valid_until <= other.valid_until
    }

    /// Check if the permission is currently valid.
    pub fn is_valid(&self) -> bool {
        let now = Utc::now();
        now >= self.valid_from && now < self.valid_until
    }

    /// Check if the permission has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.valid_until
    }

    /// Check if the permission is not yet valid.
    pub fn is_pending(&self) -> bool {
        Utc::now() < self.valid_from
    }

    /// Get the remaining duration until expiration.
    ///
    /// Returns None if already expired.
    pub fn remaining(&self) -> Option<Duration> {
        let now = Utc::now();
        if now >= self.valid_until {
            None
        } else {
            Some(self.valid_until - now)
        }
    }

    /// Get the total duration of the time window.
    pub fn duration(&self) -> Duration {
        self.valid_until - self.valid_from
    }

    /// Extend the validity window by the given duration.
    pub fn extend(&mut self, duration: Duration) {
        self.valid_until += duration;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_is_valid() {
        let lattice = TimeLattice::hours(1);
        assert!(lattice.is_valid());
        assert!(!lattice.is_expired());
    }

    #[test]
    fn test_time_expired() {
        let lattice = TimeLattice {
            valid_from: Utc::now() - Duration::hours(2),
            valid_until: Utc::now() - Duration::hours(1),
        };
        assert!(!lattice.is_valid());
        assert!(lattice.is_expired());
    }

    #[test]
    fn test_time_pending() {
        let lattice = TimeLattice {
            valid_from: Utc::now() + Duration::hours(1),
            valid_until: Utc::now() + Duration::hours(2),
        };
        assert!(!lattice.is_valid());
        assert!(lattice.is_pending());
    }

    #[test]
    fn test_time_meet_narrows_window() {
        let a = TimeLattice::between(Utc::now(), Utc::now() + Duration::hours(2));
        let b = TimeLattice::between(
            Utc::now() + Duration::minutes(30),
            Utc::now() + Duration::hours(1),
        );

        let result = a.meet(&b);

        // valid_from should be the later (more restrictive)
        assert!(result.valid_from >= a.valid_from);
        assert!(result.valid_from >= b.valid_from);
        // valid_until should be the earlier (more restrictive)
        assert!(result.valid_until <= a.valid_until);
        assert!(result.valid_until <= b.valid_until);
    }

    #[test]
    fn test_time_join_widens_window() {
        let a = TimeLattice::between(
            Utc::now() + Duration::minutes(30),
            Utc::now() + Duration::hours(1),
        );
        let b = TimeLattice::between(Utc::now(), Utc::now() + Duration::hours(2));

        let result = a.join(&b);

        // valid_from should be the earlier (less restrictive)
        assert!(result.valid_from <= a.valid_from);
        assert!(result.valid_from <= b.valid_from);
        // valid_until should be the later (less restrictive)
        assert!(result.valid_until >= a.valid_until);
        assert!(result.valid_until >= b.valid_until);
    }

    #[test]
    fn test_time_leq() {
        let narrow = TimeLattice::between(
            Utc::now() + Duration::minutes(10),
            Utc::now() + Duration::minutes(50),
        );
        let wide = TimeLattice::between(Utc::now(), Utc::now() + Duration::hours(1));

        assert!(narrow.leq(&wide));
        assert!(!wide.leq(&narrow));
    }

    #[test]
    fn test_time_extend() {
        let mut lattice = TimeLattice::hours(1);
        let original_end = lattice.valid_until;

        lattice.extend(Duration::hours(1));
        assert_eq!(lattice.valid_until, original_end + Duration::hours(1));
    }
}
