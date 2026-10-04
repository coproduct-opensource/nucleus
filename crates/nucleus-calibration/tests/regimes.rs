//! The three regimes the crate exists to tell apart, on synthetic models whose
//! true calibration is known by construction.
//!
//! These are the tests that make the verdict non-vacuous. A verdict enum with
//! three arms proves nothing if the code only ever produces one of them; each
//! test below constructs a model for which exactly one arm is the honest
//! answer, and asserts that arm.

use nucleus_calibration::{FloorParams, MICRO, Prediction, Verdict, issue, verify};
use nucleus_recompute::RecomputeOutcome;

/// A seeded generator so each synthetic model is reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn uniform_micro(&mut self) -> u64 {
        self.next() % (MICRO + 1)
    }
    fn bernoulli(&mut self, p: u64) -> bool {
        self.next() % MICRO < p
    }
}

/// A perfectly calibrated model: it reports `p`, and the outcome is drawn from
/// exactly `p`. Confidences spread across the whole range.
fn calibrated(n: usize, seed: u64) -> Vec<Prediction> {
    let mut r = Rng(seed);
    (0..n)
        .map(|_| {
            let p = r.uniform_micro();
            Prediction {
                p_micro: p,
                outcome: r.bernoulli(p),
            }
        })
        .collect()
}

/// The reported failure mode: compression toward the middle. The model's
/// reported `p` is pulled toward 50%, while outcomes follow the true `q`.
fn compressed(n: usize, seed: u64) -> Vec<Prediction> {
    let mut r = Rng(seed);
    (0..n)
        .map(|_| {
            let q = r.uniform_micro();
            // Reported p = 0.5 + 0.5·(q − 0.5): halfway to the middle.
            let half = MICRO / 2;
            let p = half + (q.abs_diff(half) / 2) * if q >= half { 1 } else { 0 }
                - (q.abs_diff(half) / 2) * if q < half { 1 } else { 0 };
            Prediction {
                p_micro: p,
                outcome: r.bernoulli(q),
            }
        })
        .collect()
}

const TOLERANCE: u64 = 20_000; // ECE < 0.02, the "well calibrated" bar

/// **The n=60 case.** A perfectly calibrated model at a small sample. The
/// floor is above the tolerance, so the honest answer is that the sample
/// cannot say — whatever the observed ECE happens to be.
#[test]
fn a_calibrated_model_at_n_60_cannot_be_told_from_a_miscalibrated_one() {
    let claim = issue(calibrated(60, 7), FloorParams::DEFAULT, TOLERANCE).unwrap();
    let v = claim.claimed.verdict;
    assert!(
        matches!(v, Verdict::CouldNotLook { .. }),
        "at n=60 the floor should swamp a 0.02 tolerance: {v:?}"
    );
    assert!(
        claim.claimed.floor_micro >= TOLERANCE,
        "floor {} must be at or above the tolerance for this arm",
        claim.claimed.floor_micro
    );
    assert!(!v.supports_gating());
    assert_eq!(verify(&claim), RecomputeOutcome::Match);
}

/// The same model with enough data. Now the floor is below the tolerance and
/// the observed ECE sits within it: the sample supports the claim.
#[test]
fn a_calibrated_model_at_n_5000_is_consistent_with_calibrated() {
    let claim = issue(calibrated(5000, 7), FloorParams::DEFAULT, TOLERANCE).unwrap();
    let v = claim.claimed.verdict;
    assert!(
        matches!(v, Verdict::ConsistentWithCalibrated { .. }),
        "a calibrated model with enough data should be consistent: {v:?}"
    );
    assert!(claim.claimed.floor_micro < TOLERANCE);
    assert!(v.supports_gating());
    assert_eq!(verify(&claim), RecomputeOutcome::Match);
}

/// The reported failure, at a sample size that can see it: compression toward
/// the middle is measurably worse than a perfect model.
#[test]
fn a_compressed_model_at_n_5000_is_miscalibrated() {
    let claim = issue(compressed(5000, 7), FloorParams::DEFAULT, TOLERANCE).unwrap();
    let v = claim.claimed.verdict;
    assert!(
        matches!(v, Verdict::Miscalibrated { .. }),
        "compression toward the middle must be caught at n=5000: {v:?}"
    );
    assert!(
        claim.claimed.ece_micro > claim.claimed.floor_micro,
        "ece {} should exceed floor {}",
        claim.claimed.ece_micro,
        claim.claimed.floor_micro
    );
    assert!(!v.supports_gating());
    assert_eq!(verify(&claim), RecomputeOutcome::Match);
}

/// The point of the floor, in one assertion: the SAME miscalibrated model at
/// n=60 gets "could not look", not "miscalibrated" and not "consistent". A
/// small sample cannot convict, and it cannot acquit either.
#[test]
fn a_compressed_model_at_n_60_also_cannot_be_told() {
    let claim = issue(compressed(60, 7), FloorParams::DEFAULT, TOLERANCE).unwrap();
    assert!(
        matches!(claim.claimed.verdict, Verdict::CouldNotLook { .. }),
        "{:?}",
        claim.claimed.verdict
    );
}

/// The non-vacuity check on the whole file: all three arms are reachable from
/// honest inputs. If a refactor collapsed the verdict, this would fail before
/// any regime test could be misread as passing.
#[test]
fn all_three_arms_are_reachable() {
    let tags: std::collections::BTreeSet<&str> = [
        issue(calibrated(60, 7), FloorParams::DEFAULT, TOLERANCE),
        issue(calibrated(5000, 7), FloorParams::DEFAULT, TOLERANCE),
        issue(compressed(5000, 7), FloorParams::DEFAULT, TOLERANCE),
    ]
    .into_iter()
    .map(|c| c.unwrap().claimed.verdict.tag())
    .collect();
    assert_eq!(tags.len(), 3, "expected all three arms, got {tags:?}");
}
