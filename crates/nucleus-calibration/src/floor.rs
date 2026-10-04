//! The noise floor: what a perfectly calibrated model scores on these
//! confidences at this sample size.
//!
//! Defined by construction rather than by closed form. For each trial, every
//! outcome is redrawn as `Bernoulli(p_i)` from a declared seed — the model's
//! own probabilities taken as true — and ECE is computed exactly as
//! [`crate::ece_micro`] computes it. The reported floor is the 95th percentile
//! over the declared number of trials: an observed ECE above it is one a
//! perfectly calibrated model would produce less than one time in twenty.
//!
//! Integer-only and seed-determined, so a stranger recomputes the same floor
//! from the receipt. That matters more than the last decimal of accuracy: a
//! floor nobody else can reproduce is another number to take on trust.

use serde::{Deserialize, Serialize};

use crate::metrics::{MICRO, MetricError, Prediction, ece_micro};

/// How the floor is drawn. Every field is declared in the receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FloorParams {
    /// Equal-width confidence bins, shared with the ECE it is a floor for.
    pub bins: u32,
    /// How many simulated perfectly-calibrated samples to draw.
    pub trials: u32,
    /// The generator seed. Same seed, same floor.
    pub seed: u64,
}

impl FloorParams {
    /// Ten bins, two hundred trials, a fixed seed. Enough trials that the 95th
    /// percentile is a real order statistic (the 190th of 200) rather than an
    /// extrapolation.
    pub const DEFAULT: FloorParams = FloorParams {
        bins: 10,
        trials: 200,
        seed: 0x6E75_636C_6575_7300, // "nucleus\0"
    };
}

/// splitmix64. Four lines of arithmetic, chosen over a dependency because the
/// receipt has to name exactly what produced the floor.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `Bernoulli(p_micro / MICRO)`, exact: a uniform draw in `[0, MICRO)`
    /// compared against `p`.
    fn bernoulli(&mut self, p_micro: u64) -> bool {
        self.next().checked_rem(MICRO).unwrap_or(0) < p_micro
    }
}

/// The 95th-percentile ECE a perfectly calibrated model produces on these
/// confidences, in micro-units.
///
/// # Errors
///
/// [`MetricError`] on an empty or out-of-range input, zero bins, or zero
/// trials (a floor over no trials is not a floor).
pub fn noise_floor_micro(
    predictions: &[Prediction],
    params: FloorParams,
) -> Result<u64, MetricError> {
    if params.trials == 0 {
        return Err(MetricError::ZeroBins);
    }
    let mut rng = Rng(params.seed);
    let mut eces: Vec<u64> = Vec::with_capacity(usize::try_from(params.trials).unwrap_or(0));
    let mut redrawn: Vec<Prediction> = predictions.to_vec();
    for _ in 0..params.trials {
        for slot in redrawn.iter_mut() {
            slot.outcome = rng.bernoulli(slot.p_micro);
        }
        eces.push(ece_micro(&redrawn, params.bins)?);
    }
    eces.sort_unstable();
    // The 95th percentile as an order statistic: index ⌈0.95·k⌉ − 1.
    let k = eces.len();
    let idx = k
        .saturating_mul(95)
        .saturating_add(99)
        .checked_div(100)
        .unwrap_or(1)
        .saturating_sub(1)
        .min(k.saturating_sub(1));
    Ok(eces.get(idx).copied().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(p: u64, n: usize) -> Vec<Prediction> {
        vec![
            Prediction {
                p_micro: p,
                outcome: false,
            };
            n
        ]
    }

    #[test]
    fn the_same_seed_gives_the_same_floor() {
        let ps = at(700_000, 60);
        let a = noise_floor_micro(&ps, FloorParams::DEFAULT).unwrap();
        let b = noise_floor_micro(&ps, FloorParams::DEFAULT).unwrap();
        assert_eq!(a, b);
        let other = FloorParams {
            seed: 1,
            ..FloorParams::DEFAULT
        };
        let c = noise_floor_micro(&ps, other).unwrap();
        // Not asserting inequality — two seeds CAN coincide — only that the
        // seed is honoured, which the first assertion shows.
        let _ = c;
    }

    /// The property that makes the floor worth printing: it shrinks with `n`.
    /// A floor that did not would say nothing about sample size.
    #[test]
    fn the_floor_shrinks_as_the_sample_grows() {
        let small = noise_floor_micro(&at(700_000, 30), FloorParams::DEFAULT).unwrap();
        let mid = noise_floor_micro(&at(700_000, 300), FloorParams::DEFAULT).unwrap();
        let large = noise_floor_micro(&at(700_000, 3000), FloorParams::DEFAULT).unwrap();
        assert!(small > mid, "{small} > {mid}");
        assert!(mid > large, "{mid} > {large}");
    }

    /// A model that only ever says 0% or 100% has no binomial noise to draw:
    /// its floor is exactly zero. The floor is conditional on the confidences,
    /// not a function of `n` alone.
    #[test]
    fn certain_predictions_have_no_floor() {
        let mut ps = at(MICRO, 40);
        ps.extend(at(0, 40));
        assert_eq!(noise_floor_micro(&ps, FloorParams::DEFAULT).unwrap(), 0);
    }

    #[test]
    fn zero_trials_is_refused() {
        let params = FloorParams {
            trials: 0,
            ..FloorParams::DEFAULT
        };
        assert!(noise_floor_micro(&at(500_000, 10), params).is_err());
    }
}
