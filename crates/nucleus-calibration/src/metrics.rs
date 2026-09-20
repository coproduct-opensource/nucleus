//! Brier and ECE, integer-exact.
//!
//! Probabilities are micro-units (`0..=1_000_000`), outcomes are `bool`, and
//! every result is in micro-units too. `u128` accumulators, no division inside
//! a bin, no floats: the estimate a stranger recomputes is the estimate we
//! issued, to the last digit.

use serde::{Deserialize, Serialize};

/// One unit of probability: `1_000_000` micro-units.
pub const MICRO: u64 = 1_000_000;

/// One prediction and what actually happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prediction {
    /// The model's probability that `outcome` would be `true`, in micro-units.
    pub p_micro: u64,
    /// What happened.
    pub outcome: bool,
}

/// Why a metric could not be computed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetricError {
    /// No predictions. A mean over nothing is not zero; it is undefined, and
    /// reporting zero would read as perfect calibration.
    #[error("no predictions to assess")]
    Empty,
    /// A probability above one.
    #[error("prediction {index} has p = {p_micro} µ, above {MICRO}")]
    ProbabilityOutOfRange {
        /// Which prediction.
        index: usize,
        /// Its declared probability.
        p_micro: u64,
    },
    /// Zero bins cannot partition anything.
    #[error("bins must be at least 1")]
    ZeroBins,
}

fn validate(predictions: &[Prediction]) -> Result<(), MetricError> {
    if predictions.is_empty() {
        return Err(MetricError::Empty);
    }
    for (index, p) in predictions.iter().enumerate() {
        if p.p_micro > MICRO {
            return Err(MetricError::ProbabilityOutOfRange {
                index,
                p_micro: p.p_micro,
            });
        }
    }
    Ok(())
}

/// Outcome as a micro-unit probability: `true` is certainty.
fn outcome_micro(o: bool) -> u64 {
    if o { MICRO } else { 0 }
}

/// **Brier score**, in micro-units: the mean squared distance between each
/// probability and its outcome. `0` is perfect; `MICRO` is always-certain and
/// always-wrong.
///
/// # Errors
///
/// [`MetricError`] on an empty or out-of-range input.
pub fn brier_micro(predictions: &[Prediction]) -> Result<u64, MetricError> {
    validate(predictions)?;
    let sum_sq: u128 = predictions.iter().fold(0u128, |acc, p| {
        let diff = u128::from(p.p_micro.abs_diff(outcome_micro(p.outcome)));
        acc.saturating_add(diff.saturating_mul(diff))
    });
    // Mean of squares in micro², then back to micro: divide by n·MICRO.
    let n = u128::from(predictions.len() as u64);
    let denom = n.saturating_mul(u128::from(MICRO));
    // `checked_div`, not `/` behind a `.max(1)`: `validate` already refused an
    // empty input, but that is a fact the lint cannot see and the type should
    // carry. `None` is unreachable and maps to `0` rather than to a panic.
    Ok(sum_sq
        .checked_div(denom)
        .and_then(|q| u64::try_from(q).ok())
        .unwrap_or(0))
}

/// Which equal-width bin a probability falls in, with `p = 1` folded into the
/// top bin.
fn bin_of(p_micro: u64, bins: u32) -> usize {
    let scaled = u128::from(p_micro)
        .saturating_mul(u128::from(bins))
        .checked_div(u128::from(MICRO))
        .unwrap_or(0);
    let top = usize::try_from(bins.saturating_sub(1)).unwrap_or(0);
    usize::try_from(scaled).unwrap_or(top).min(top)
}

/// **Expected calibration error**, in micro-units, over `bins` equal-width
/// confidence bins.
///
/// Computed as `Σ_b |Σ_{i∈b} y_i·MICRO − Σ_{i∈b} p_i| / n`, which is algebraically
/// `Σ_b (n_b/n)·|acc_b − conf_b|` with **no per-bin division** — so there is no
/// rounding inside a bin to disagree about, and the value is exact.
///
/// # Errors
///
/// [`MetricError`] on an empty or out-of-range input, or zero bins.
pub fn ece_micro(predictions: &[Prediction], bins: u32) -> Result<u64, MetricError> {
    validate(predictions)?;
    if bins == 0 {
        return Err(MetricError::ZeroBins);
    }
    let width = usize::try_from(bins).unwrap_or(usize::MAX);
    let mut sum_p: Vec<u128> = vec![0; width];
    let mut sum_y: Vec<u128> = vec![0; width];
    for p in predictions {
        let b = bin_of(p.p_micro, bins);
        if let Some(slot) = sum_p.get_mut(b) {
            *slot = slot.saturating_add(u128::from(p.p_micro));
        }
        if let Some(slot) = sum_y.get_mut(b) {
            *slot = slot.saturating_add(u128::from(outcome_micro(p.outcome)));
        }
    }
    let gap: u128 = sum_p
        .iter()
        .zip(sum_y.iter())
        .fold(0u128, |acc, (sp, sy)| acc.saturating_add(sp.abs_diff(*sy)));
    let n = u128::from(predictions.len() as u64);
    Ok(gap
        .checked_div(n)
        .and_then(|q| u64::try_from(q).ok())
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pred(p: u64, o: bool) -> Prediction {
        Prediction {
            p_micro: p,
            outcome: o,
        }
    }

    #[test]
    fn a_certain_and_right_model_scores_zero_on_both() {
        let ps = [pred(MICRO, true), pred(0, false)];
        assert_eq!(brier_micro(&ps).unwrap(), 0);
        assert_eq!(ece_micro(&ps, 10).unwrap(), 0);
    }

    #[test]
    fn a_certain_and_wrong_model_scores_the_maximum() {
        let ps = [pred(MICRO, false), pred(0, true)];
        assert_eq!(brier_micro(&ps).unwrap(), MICRO);
        assert_eq!(ece_micro(&ps, 10).unwrap(), MICRO);
    }

    /// Ten predictions at 70%, seven of which come true: perfectly calibrated
    /// in that bin, ECE exactly zero — and Brier is `0.7·0.3² + 0.3·0.7² = 0.21`.
    #[test]
    fn a_calibrated_bin_has_zero_ece_and_the_textbook_brier() {
        let mut ps = vec![pred(700_000, true); 7];
        ps.extend(vec![pred(700_000, false); 3]);
        assert_eq!(ece_micro(&ps, 10).unwrap(), 0);
        assert_eq!(brier_micro(&ps).unwrap(), 210_000);
    }

    /// The finding that motivated this crate: overstating low probabilities and
    /// understating high ones — "compression toward the middle".
    #[test]
    fn compression_toward_the_middle_is_measured() {
        // Says 40% when the truth is 10%; says 60% when the truth is 90%.
        let mut ps = vec![pred(400_000, true); 1];
        ps.extend(vec![pred(400_000, false); 9]);
        ps.extend(vec![pred(600_000, true); 9]);
        ps.extend(vec![pred(600_000, false); 1]);
        // Bin 4: |1·1e6 − 10·0.4e6| = 3e6. Bin 6: |9·1e6 − 10·0.6e6| = 3e6.
        // (3e6 + 3e6) / 20 = 300_000.
        assert_eq!(ece_micro(&ps, 10).unwrap(), 300_000);
    }

    #[test]
    fn empty_is_an_error_not_a_perfect_score() {
        assert_eq!(brier_micro(&[]), Err(MetricError::Empty));
        assert_eq!(ece_micro(&[], 10), Err(MetricError::Empty));
    }

    #[test]
    fn a_probability_above_one_is_refused() {
        let r = ece_micro(&[pred(MICRO + 1, true)], 10);
        assert!(matches!(
            r,
            Err(MetricError::ProbabilityOutOfRange { index: 0, .. })
        ));
    }

    #[test]
    fn one_folds_into_the_top_bin() {
        assert_eq!(bin_of(MICRO, 10), 9);
        assert_eq!(bin_of(0, 10), 0);
        assert_eq!(bin_of(999_999, 10), 9);
        assert_eq!(bin_of(100_000, 10), 1);
    }
}
