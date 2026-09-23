//! The receipt: declared inputs beside claimed outputs, and a verifier that
//! recomputes the outputs from the inputs.
//!
//! Same shape as `nucleus_recompute::ClearingReceipt`, same verdict enum, same
//! domain-tagged canonical bytes → SHA-256 content hash — so a lineage edge can
//! bind to a calibration claim exactly the way it binds to a clearing, and the
//! same offline verifier discipline applies: hold the bytes, recompute, compare.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use nucleus_recompute::RecomputeOutcome;

use crate::floor::{FloorParams, noise_floor_micro};
use crate::metrics::{MetricError, Prediction, brier_micro, ece_micro};
use crate::verdict::{Verdict, assess};

/// Domain separation for the content hash, so a calibration receipt's hash can
/// never collide with a clearing receipt's over the same bytes.
const RECEIPT_DOMAIN: &[u8] = b"nucleus-calibration/receipt/v1\0";

/// The claimed outputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    /// Brier score, micro-units.
    pub brier_micro: u64,
    /// Expected calibration error, micro-units.
    pub ece_micro: u64,
    /// The noise floor, micro-units.
    pub floor_micro: u64,
    /// The verdict, with its numbers.
    pub verdict: Verdict,
}

/// A calibration claim: everything needed to recompute it, and what it claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationClaim {
    /// Declared input: the predictions and their outcomes.
    pub predictions: Vec<Prediction>,
    /// Declared input: how the floor was drawn (and how ECE was binned).
    pub floor: FloorParams,
    /// Declared input: the tolerance the verdict was decided against.
    pub tolerance_micro: u64,
    /// Claimed output.
    pub claimed: Assessment,
}

/// Compute the assessment from declared inputs. The one decider — `issue` and
/// `verify` both call it, so they cannot disagree about what the inputs mean.
fn compute(
    predictions: &[Prediction],
    floor: FloorParams,
    tolerance_micro: u64,
) -> Result<Assessment, MetricError> {
    let brier = brier_micro(predictions)?;
    let ece = ece_micro(predictions, floor.bins)?;
    let floor_micro = noise_floor_micro(predictions, floor)?;
    let n = predictions.len() as u64;
    Ok(Assessment {
        brier_micro: brier,
        ece_micro: ece,
        floor_micro,
        verdict: assess(ece, floor_micro, tolerance_micro, n),
    })
}

/// Issue a claim over `predictions`.
///
/// # Errors
///
/// [`MetricError`] if the inputs cannot be assessed.
pub fn issue(
    predictions: Vec<Prediction>,
    floor: FloorParams,
    tolerance_micro: u64,
) -> Result<CalibrationClaim, MetricError> {
    let claimed = compute(&predictions, floor, tolerance_micro)?;
    Ok(CalibrationClaim {
        predictions,
        floor,
        tolerance_micro,
        claimed,
    })
}

/// Recompute a claim from its declared inputs and compare, field by field.
///
/// `Invalid` when the declared inputs cannot be assessed at all — there is no
/// baseline to compare against, so the claim neither stands nor falls. That
/// arm is never a pass.
#[must_use]
pub fn verify(claim: &CalibrationClaim) -> RecomputeOutcome {
    let recomputed = match compute(&claim.predictions, claim.floor, claim.tolerance_micro) {
        Ok(a) => a,
        Err(e) => return RecomputeOutcome::Invalid(e.to_string()),
    };
    let c = &claim.claimed;
    if c.brier_micro != recomputed.brier_micro {
        return mismatch("brier_micro", c.brier_micro, recomputed.brier_micro);
    }
    if c.ece_micro != recomputed.ece_micro {
        return mismatch("ece_micro", c.ece_micro, recomputed.ece_micro);
    }
    if c.floor_micro != recomputed.floor_micro {
        return mismatch("floor_micro", c.floor_micro, recomputed.floor_micro);
    }
    if c.verdict != recomputed.verdict {
        return mismatch("verdict", c.verdict.tag(), recomputed.verdict.tag());
    }
    RecomputeOutcome::Match
}

fn mismatch<A: std::fmt::Debug, B: std::fmt::Debug>(
    field: &'static str,
    claimed: A,
    recomputed: B,
) -> RecomputeOutcome {
    RecomputeOutcome::Mismatch {
        field,
        claimed: format!("{claimed:?}"),
        recomputed: format!("{recomputed:?}"),
    }
}

/// Canonical, domain-tagged bytes. The claim types contain no maps, so serde's
/// field order is stable and the bytes are deterministic.
///
/// Returns `None` only if serialization fails, which for these concrete
/// map-free types it does not — but the type says it can, and this crate does
/// not `expect` its way past a type.
#[must_use]
pub fn canonical_bytes(claim: &CalibrationClaim) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(RECEIPT_DOMAIN.len().saturating_add(256));
    out.extend_from_slice(RECEIPT_DOMAIN);
    serde_json::to_writer(&mut out, claim).ok()?;
    Some(out)
}

/// SHA-256 over [`canonical_bytes`], hex — the value a lineage edge's
/// `content_hash_hex` carries for a calibration claim.
#[must_use]
pub fn content_hash_hex(claim: &CalibrationClaim) -> Option<String> {
    let bytes = canonical_bytes(claim)?;
    let mut h = Sha256::new();
    h.update(bytes);
    Some(hex::encode(h.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::MICRO;

    fn calibrated_at(p: u64, n: usize, seed: u64) -> Vec<Prediction> {
        // Outcomes drawn Bernoulli(p) from a seed, so the sample IS calibrated.
        let mut s = seed;
        (0..n)
            .map(|_| {
                s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = s;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^= z >> 31;
                Prediction {
                    p_micro: p,
                    outcome: z % MICRO < p,
                }
            })
            .collect()
    }

    #[test]
    fn an_issued_claim_verifies() {
        let c = issue(calibrated_at(700_000, 500, 1), FloorParams::DEFAULT, 20_000).unwrap();
        assert_eq!(verify(&c), RecomputeOutcome::Match);
    }

    /// A-19 for the verifier: each claimed field, tampered, is caught by name.
    #[test]
    fn every_tampered_field_is_caught_by_name() {
        let base = issue(calibrated_at(700_000, 500, 1), FloorParams::DEFAULT, 20_000).unwrap();

        let mut c = base.clone();
        c.claimed.brier_micro = c.claimed.brier_micro.wrapping_add(1);
        assert!(matches!(
            verify(&c),
            RecomputeOutcome::Mismatch {
                field: "brier_micro",
                ..
            }
        ));

        let mut c = base.clone();
        c.claimed.ece_micro = c.claimed.ece_micro.wrapping_add(1);
        assert!(matches!(
            verify(&c),
            RecomputeOutcome::Mismatch {
                field: "ece_micro",
                ..
            }
        ));

        let mut c = base.clone();
        c.claimed.floor_micro = c.claimed.floor_micro.wrapping_add(1);
        assert!(matches!(
            verify(&c),
            RecomputeOutcome::Mismatch {
                field: "floor_micro",
                ..
            }
        ));

        // The verdict is the field someone would most want to forge: promote
        // "could not look" to "consistent". Caught even when the numbers match.
        let mut c = base;
        c.claimed.verdict = Verdict::ConsistentWithCalibrated {
            ece_micro: c.claimed.ece_micro,
            floor_micro: c.claimed.floor_micro,
            n: 500,
        };
        if verify(&c) == RecomputeOutcome::Match {
            // Only possible if the honest verdict already was Consistent; then
            // forge the other way.
            c.claimed.verdict = Verdict::CouldNotLook {
                ece_micro: c.claimed.ece_micro,
                floor_micro: c.claimed.floor_micro,
                tolerance_micro: 20_000,
                n: 500,
            };
        }
        assert!(matches!(
            verify(&c),
            RecomputeOutcome::Mismatch {
                field: "verdict",
                ..
            }
        ));
    }

    #[test]
    fn a_claim_over_no_predictions_is_invalid_not_matched() {
        let c = CalibrationClaim {
            predictions: Vec::new(),
            floor: FloorParams::DEFAULT,
            tolerance_micro: 20_000,
            claimed: Assessment {
                brier_micro: 0,
                ece_micro: 0,
                floor_micro: 0,
                verdict: Verdict::ConsistentWithCalibrated {
                    ece_micro: 0,
                    floor_micro: 0,
                    n: 0,
                },
            },
        };
        assert!(matches!(verify(&c), RecomputeOutcome::Invalid(_)));
    }

    #[test]
    fn the_content_hash_is_stable_and_moves_with_the_claim() {
        let a = issue(calibrated_at(700_000, 100, 1), FloorParams::DEFAULT, 20_000).unwrap();
        let h1 = content_hash_hex(&a).unwrap();
        let h2 = content_hash_hex(&a).unwrap();
        assert_eq!(h1, h2);
        let mut b = a;
        b.tolerance_micro = 30_000;
        assert_ne!(h1, content_hash_hex(&b).unwrap());
    }
}
