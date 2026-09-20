//! Three answers, not a number.
//!
//! An ECE alone invites the reading "small is good". The floor makes that
//! reading wrong at small `n`, and the tolerance makes it wrong at any `n`
//! where the floor itself is too big to answer the question asked. So the
//! verdict is a sum type with the case the field usually omits — the sample
//! could not decide — as a first-class arm rather than a pass.

use serde::{Deserialize, Serialize};

/// What this sample can say about calibration, at a tolerance.
///
/// Every arm carries the observed ECE, the floor and `n`, so a reader can see
/// the numbers the arm was decided from rather than the arm alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    /// The floor at this `n` is at or above the tolerance. Even a perfectly
    /// calibrated model would score at least the tolerance here, so no observed
    /// ECE from this sample — high or low — can establish calibration to that
    /// tolerance. **Not a pass.** Get more data, or ask a coarser question.
    CouldNotLook {
        /// The observed ECE, reported but not decisive.
        ece_micro: u64,
        /// What a perfect model scores at this `n` (95th percentile).
        floor_micro: u64,
        /// The tolerance that was asked about.
        tolerance_micro: u64,
        /// Sample size.
        n: u64,
    },
    /// The observed ECE exceeds the floor: worse than a perfectly calibrated
    /// model produces at this `n` more than one time in twenty.
    Miscalibrated {
        /// The observed ECE.
        ece_micro: u64,
        /// What a perfect model scores at this `n` (95th percentile).
        floor_micro: u64,
        /// Sample size.
        n: u64,
    },
    /// The observed ECE is within the floor, AND the floor is below the
    /// tolerance — so "within the floor" is a statement the sample can support.
    /// About this sample, at this tolerance; not a proof of calibration.
    ConsistentWithCalibrated {
        /// The observed ECE.
        ece_micro: u64,
        /// What a perfect model scores at this `n` (95th percentile).
        floor_micro: u64,
        /// Sample size.
        n: u64,
    },
}

impl Verdict {
    /// A stable tag for the arm, for receipts and logs.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::CouldNotLook { .. } => "could_not_look",
            Self::Miscalibrated { .. } => "miscalibrated",
            Self::ConsistentWithCalibrated { .. } => "consistent_with_calibrated",
        }
    }

    /// Whether this verdict supports gating a decision on the model's
    /// confidence at the tolerance asked. Only one arm does, and it is not the
    /// arm with the smallest ECE — it is the arm where the sample could tell.
    #[must_use]
    pub fn supports_gating(&self) -> bool {
        matches!(self, Self::ConsistentWithCalibrated { .. })
    }
}

/// Decide the verdict. The order is the argument: first whether the sample can
/// answer at all, then what it answers.
#[must_use]
pub fn assess(ece_micro: u64, floor_micro: u64, tolerance_micro: u64, n: u64) -> Verdict {
    if floor_micro >= tolerance_micro {
        Verdict::CouldNotLook {
            ece_micro,
            floor_micro,
            tolerance_micro,
            n,
        }
    } else if ece_micro > floor_micro {
        Verdict::Miscalibrated {
            ece_micro,
            floor_micro,
            n,
        }
    } else {
        Verdict::ConsistentWithCalibrated {
            ece_micro,
            floor_micro,
            n,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The launch-benchmark case: a small ECE that the sample cannot vouch for. The
    /// number looks good and the verdict refuses to call it good.
    #[test]
    fn a_small_ece_under_a_large_floor_is_could_not_look() {
        let v = assess(30_000, 45_000, 20_000, 60);
        assert!(matches!(v, Verdict::CouldNotLook { .. }), "{v:?}");
        assert!(!v.supports_gating());
    }

    #[test]
    fn above_the_floor_is_miscalibrated() {
        let v = assess(30_000, 10_000, 20_000, 5000);
        assert!(matches!(v, Verdict::Miscalibrated { .. }), "{v:?}");
        assert!(!v.supports_gating());
    }

    #[test]
    fn within_a_small_floor_is_consistent_and_supports_gating() {
        let v = assess(8_000, 10_000, 20_000, 5000);
        assert!(
            matches!(v, Verdict::ConsistentWithCalibrated { .. }),
            "{v:?}"
        );
        assert!(v.supports_gating());
    }

    /// The floor equal to the tolerance is still "could not look": a perfect
    /// model would score exactly the tolerance, so the sample cannot show
    /// strictly better.
    #[test]
    fn a_floor_at_the_tolerance_cannot_look() {
        assert!(matches!(
            assess(0, 20_000, 20_000, 100),
            Verdict::CouldNotLook { .. }
        ));
    }
}
