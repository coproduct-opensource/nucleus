//! Pigouvian-VCG re-weighting — hand-translated Aeneas-style
//! extraction from `formal/Nucleus/Auctions/PigouvianVcg.lean`.
//!
//! **Pigouvian U3.** Mirrors the Lean primitive
//! `Nucleus.Auctions.PigouvianVcg.effectivePigou`:
//!
//! ```text
//! effectivePigou b rate ext scale = b - rate * ext / scale   (saturating Nat)
//! ```
//!
//! Aeneas's plan is to auto-extract Lean `Nat` arithmetic to Rust
//! `u64` saturating arithmetic per the discipline established by
//! `extracted/vcg_aeneas.rs` (closes A4 with `greedy_pack`). Until
//! the auto-pipeline lands, this hand-translation is the wedge —
//! byte-faithful to the Lean definition.
//!
//! U4 binds this function to the kernel's
//! `effective_minus_pigou_micro` via a differential proptest in
//! `tests/pigou_parity.rs`.

/// Lean-extracted single-dimension Pigouvian re-weighting. Mirrors
/// the Lean primitive bit-for-bit on the `Nat`-saturating-subtraction
/// path:
///
/// ```text
/// pigouvian_re_weight(bid, rate, ext, scale)
///     = bid.saturating_sub(rate * ext / scale)
/// ```
///
/// The multi-dimension `effective_minus_pigou_micro` in
/// `crate::vcg_pigou` folds this primitive over the K = 7 resource
/// dimensions.
pub fn pigouvian_re_weight(
    bid_micro_usd: u64,
    rate_micro_usd_per_unit: u64,
    ext_units_micro: u64,
    scale: u64,
) -> u64 {
    if scale == 0 {
        // Lean's Nat division `x / 0 = 0` semantics; mirror that.
        return bid_micro_usd;
    }
    // u128 intermediate to avoid 64-bit-overflow on the rate * ext
    // product. Saturating cast back to u64 matches the Lean Nat
    // behavior (Lean Nat doesn't overflow but Rust u64 does).
    let prod = (rate_micro_usd_per_unit as u128).saturating_mul(ext_units_micro as u128);
    let tax = prod / (scale as u128);
    let tax_u64 = u64::try_from(tax).unwrap_or(u64::MAX);
    bid_micro_usd.saturating_sub(tax_u64)
}

/// Sum of `r * e / scale` over a list of (rate, ext) pairs.
/// Mirrors Lean `PigouvianVcgMultiDim.sumContribs` bit-for-bit.
///
/// u128 intermediates + saturating cast back to u64 — same pattern
/// as the single-dim `pigouvian_re_weight`. Lean's `Nat` doesn't
/// overflow but Rust `u64` does, so we follow the established
/// discipline: compute in u128, saturate at the boundary.
fn sum_contribs(pairs: &[(u64, u64)], scale: u64) -> u64 {
    if scale == 0 {
        return 0;
    }
    let scale128 = u128::from(scale);
    let mut total: u128 = 0;
    for (rate, ext) in pairs {
        let prod = u128::from(*rate).saturating_mul(u128::from(*ext));
        let contrib = prod / scale128;
        total = total.saturating_add(contrib);
    }
    u64::try_from(total).unwrap_or(u64::MAX)
}

/// **Multi-dim Pigouvian re-weighting.** Mirrors Lean
/// `PigouvianVcgMultiDim.effectivePigouMultiDim` bit-for-bit on the
/// Nat-saturating-subtraction + unbounded-add path:
///
/// ```text
/// effectivePigouMultiDim(bid, scale, taxes, subsidies)
///   = (bid - Σ taxes) + Σ subsidies
/// ```
///
/// `taxes` carries (rate, ext_units) pairs for negative-externality
/// dimensions (gpu_seconds, co2_grams, ...). `subsidies` carries
/// the positive-externality dimensions (knowledge_spillover, ...).
///
/// This is the Rust function the kernel's `effective_minus_pigou_micro`
/// reduces to once you flatten the `ExternalityProfile.dimensions`
/// BTreeMap into two `(rate, units)` lists keyed on
/// `is_positive_externality`. The parity proptest in
/// `tests/pigou_parity.rs::multi_dim_matches_kernel` pins that
/// reduction at 256 random multi-dim profiles.
pub fn pigouvian_re_weight_multi_dim(
    bid_micro_usd: u64,
    scale: u64,
    taxes: &[(u64, u64)],
    subsidies: &[(u64, u64)],
) -> u64 {
    let tax_total = sum_contribs(taxes, scale);
    let sub_total = sum_contribs(subsidies, scale);
    let after_tax = bid_micro_usd.saturating_sub(tax_total);
    after_tax.saturating_add(sub_total)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors `zero_rate_is_identity` from `PigouvianVcg.lean`.
    #[test]
    fn zero_rate_is_identity() {
        assert_eq!(
            pigouvian_re_weight(1_000_000, 0, 5_000_000, 1_000_000),
            1_000_000
        );
    }

    /// Mirrors `zero_externality_is_identity` from `PigouvianVcg.lean`.
    #[test]
    fn zero_externality_is_identity() {
        assert_eq!(pigouvian_re_weight(1_000_000, 100, 0, 1_000_000), 1_000_000);
    }

    /// Mirrors `pigouvian_welfare_optimal_on_lattice`: result ≤ bid.
    #[test]
    fn result_is_bounded_above_by_bid() {
        for bid in [0, 1, 1000, 1_000_000, u64::MAX] {
            for rate in [0, 1, 100, 1_000_000] {
                for ext in [0, 1, 5_000_000] {
                    let result = pigouvian_re_weight(bid, rate, ext, 1_000_000);
                    assert!(
                        result <= bid,
                        "bid={bid} rate={rate} ext={ext} result={result}"
                    );
                }
            }
        }
    }

    /// Mirrors `effectivePigou_monotone_in_bid`: a ≤ b → f(a) ≤ f(b).
    #[test]
    fn monotone_in_bid() {
        let rate = 100;
        let ext = 1_000_000;
        let scale = 1_000_000;
        for a in [0u64, 50, 100, 200, 1000, 100_000] {
            for delta in [0u64, 1, 50, 100] {
                let b = a.saturating_add(delta);
                let fa = pigouvian_re_weight(a, rate, ext, scale);
                let fb = pigouvian_re_weight(b, rate, ext, scale);
                assert!(fa <= fb, "f({a})={fa} > f({b})={fb}");
            }
        }
    }
}
