//! The market: per-dimension utilization and the Lagrangian price it implies.
//!
//! # Integer, on a money path
//!
//! `λ` used to be an `f64` computed with `exp()`, and grant totals were `f64`
//! sums of it (#2540). The kernels this repository proves things about refuse
//! floats on a money path (`nucleus-econ-kernels` is `deny(float_arithmetic)`)
//! because a float total is a total two machines can disagree about. This
//! market now prices in micro-USD, and `λ` is computed by a fixed-point
//! exponential in `u128` with no float anywhere: range reduction, eight Taylor
//! terms, ten squarings. `parity_with_the_f64_curve_within_one_micro` pins it
//! to the curve it replaces at every basis point.
//!
//! The curve itself is unchanged: `λ = 0` up to 50% utilization, then
//! `exp(3·n) − 1` where `n` is the fraction of the way from 50% to 100%. Its
//! maximum is `e³ − 1 ≈ 19.09`, so the historical hard cap of 1000 is never
//! reached; it is kept as a stated bound rather than deleted, because a bound
//! that is never hit is still the thing a proof is stated against.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bid::{DeniedDimension, PermissionBid, PermissionGrant};
use crate::dimension::PermissionDimension;

/// One unit of λ, micro-units.
pub const LAMBDA_ONE_MICRO: u64 = 1_000_000;

/// Utilization at which λ starts to rise, basis points.
const LAMBDA_ONSET_BPS: u32 = 5_000;

/// Full utilization, basis points.
const FULL_BPS: u32 = 10_000;

/// The ceiling on λ, micro-units (1000.0). Never reached by the curve below;
/// kept as the stated bound.
pub const HARD_LAMBDA_MAX_MICRO: u64 = 1_000_000_000;

/// λ above which a dimension recommends halting, micro-units (100.0).
pub const CRITICAL_LAMBDA_MICRO: u64 = 100_000_000;

/// Exponential growth rate, chosen so λ ≈ 10 at ~90% utilization.
const K: u128 = 3;

/// Fixed-point scale for the exponential: 1e12.
const FP: u128 = 1_000_000_000_000;

/// `FP / LAMBDA_ONE_MICRO`: how many fixed-point units make one micro-unit.
/// Written out because the shipped build denies even a constant division;
/// `fp_per_micro_is_the_ratio_it_claims` pins it.
const FP_PER_MICRO: u128 = 1_000_000;

/// Half of [`FP_PER_MICRO`], for round-half-up.
const HALF_FP_PER_MICRO: u128 = 500_000;

/// Per-dimension utilization state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionState {
    /// Current utilization, basis points (`0` = idle, `10_000` = fully consumed).
    pub utilization_bps: u32,
    /// Optional capacity limit (informational).
    pub capacity: Option<u64>,
}

impl DimensionState {
    /// A state at `utilization_bps`, clamped to `0..=10_000`.
    #[must_use]
    pub fn new(utilization_bps: u32) -> Self {
        Self {
            utilization_bps: utilization_bps.min(FULL_BPS),
            capacity: None,
        }
    }
}

/// Multi-dimensional constraint state snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionConstraintState {
    /// λ per dimension, micro-units.
    pub lambdas_micro: BTreeMap<PermissionDimension, u64>,
    /// Utilization per dimension, basis points.
    pub utilization_bps: BTreeMap<PermissionDimension, u32>,
    /// Whether any dimension recommends halt.
    pub should_halt: bool,
}

/// The permission market.
///
/// Holds per-dimension utilization and computes Lagrange-multiplier prices.
/// Thread-safe reads via clone; writers hold a lock externally.
#[derive(Debug, Clone)]
pub struct PermissionMarket {
    dimensions: BTreeMap<PermissionDimension, DimensionState>,
    /// Optional grant TTL in seconds.
    grant_ttl_secs: Option<u64>,
}

impl PermissionMarket {
    /// A market with no utilization on any dimension.
    #[must_use]
    pub fn new() -> Self {
        let dimensions = PermissionDimension::ALL
            .iter()
            .map(|d| (*d, DimensionState::new(0)))
            .collect();
        Self {
            dimensions,
            grant_ttl_secs: None,
        }
    }

    /// A market with explicit per-dimension utilization, basis points.
    #[must_use]
    pub fn with_utilization(utilizations: BTreeMap<PermissionDimension, u32>) -> Self {
        let dimensions = PermissionDimension::ALL
            .iter()
            .map(|d| {
                let bps = utilizations.get(d).copied().unwrap_or(0);
                (*d, DimensionState::new(bps))
            })
            .collect();
        Self {
            dimensions,
            grant_ttl_secs: None,
        }
    }

    /// Set the grant TTL applied to all grants.
    #[must_use]
    pub fn with_grant_ttl(mut self, ttl_secs: u64) -> Self {
        self.grant_ttl_secs = Some(ttl_secs);
        self
    }

    /// Update one dimension's utilization, basis points (clamped).
    pub fn set_utilization(&mut self, dim: PermissionDimension, utilization_bps: u32) {
        self.dimensions
            .entry(dim)
            .and_modify(|s| s.utilization_bps = utilization_bps.min(FULL_BPS))
            .or_insert_with(|| DimensionState::new(utilization_bps));
    }

    /// λ for each dimension, micro-units.
    #[must_use]
    pub fn compute_lambdas(&self) -> BTreeMap<PermissionDimension, u64> {
        self.dimensions
            .iter()
            .map(|(dim, state)| (*dim, compute_lambda_micro(state.utilization_bps)))
            .collect()
    }

    /// Evaluate a bid: grant each dimension where the bid's value meets the
    /// discounted price.
    ///
    /// The price is `λ × discount` rounded **up** to the next micro-USD. A
    /// price is what the market is owed; rounding it down would undercharge by
    /// up to a micro-dollar on every grant, in the bidder's favour, forever.
    #[must_use]
    pub fn evaluate_bid(&self, bid: &PermissionBid) -> PermissionGrant {
        let lambdas = self.compute_lambdas();
        let discount_bps = u128::from(bid.trust_tier().discount_bps());
        let mut granted = Vec::new();
        let mut denied = Vec::new();
        let mut total_cost_micro: u64 = 0;

        for dim in bid.requested() {
            let lambda = u128::from(lambdas.get(dim).copied().unwrap_or(0));
            let price_micro = lambda
                .saturating_mul(discount_bps)
                .saturating_add(u128::from(FULL_BPS).saturating_sub(1))
                .checked_div(u128::from(FULL_BPS))
                .and_then(|p| u64::try_from(p).ok())
                .unwrap_or(u64::MAX);

            if bid.value_micro() >= price_micro {
                granted.push(*dim);
                total_cost_micro = total_cost_micro.saturating_add(price_micro);
            } else {
                denied.push(DeniedDimension {
                    dimension: *dim,
                    price_micro,
                });
            }
        }

        let expires_at = self.grant_ttl_secs.map(|ttl| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_add(ttl)
        });

        PermissionGrant {
            granted,
            denied,
            total_cost_micro,
            expires_at,
        }
    }

    /// A snapshot of the full constraint state.
    #[must_use]
    pub fn state(&self) -> PermissionConstraintState {
        let lambdas_micro = self.compute_lambdas();
        let utilization_bps = self
            .dimensions
            .iter()
            .map(|(dim, state)| (*dim, state.utilization_bps))
            .collect();
        let should_halt = lambdas_micro.values().any(|l| *l > CRITICAL_LAMBDA_MICRO);
        PermissionConstraintState {
            lambdas_micro,
            utilization_bps,
            should_halt,
        }
    }

    /// Whether any dimension recommends halting.
    #[must_use]
    pub fn should_halt(&self) -> bool {
        self.dimensions
            .values()
            .any(|s| compute_lambda_micro(s.utilization_bps) > CRITICAL_LAMBDA_MICRO)
    }
}

impl Default for PermissionMarket {
    fn default() -> Self {
        Self::new()
    }
}

/// `exp(x)` for `x` in `FP` fixed point, `0 ≤ x ≤ 3·FP`, returned in `FP`.
///
/// Range reduction by 2¹⁰, eight Taylor terms on the reduced argument (which
/// is ≤ 0.003, so the ninth term is below 10⁻²⁴), then ten squarings. Every
/// intermediate fits `u128` with headroom: the largest is a squaring of
/// `e³·FP ≈ 2.01·10¹³`, whose square is ≈ 4·10²⁶ against a ceiling of 3.4·10³⁸.
/// The loop counts are fixed, which is what makes the Kani harness in
/// `proofs/lambda_monotone.rs` tractable.
fn exp_fixed(x: u128) -> u128 {
    const REDUCE_SHIFT: u32 = 10;
    const TAYLOR_TERMS: u128 = 8;

    let y = x >> REDUCE_SHIFT;
    // Σ_{k=0..8} y^k / k!, in FP.
    let mut sum: u128 = FP;
    let mut term: u128 = FP;
    let mut k: u128 = 1;
    while k <= TAYLOR_TERMS {
        term = term
            .saturating_mul(y)
            .checked_div(FP.saturating_mul(k))
            .unwrap_or(0);
        sum = sum.saturating_add(term);
        k = k.saturating_add(1);
    }
    // Square back up: exp(x) = exp(y)^(2^10).
    let mut v = sum;
    let mut i = 0u32;
    while i < REDUCE_SHIFT {
        v = v.saturating_mul(v).checked_div(FP).unwrap_or(u128::MAX);
        i = i.saturating_add(1);
    }
    v
}

/// λ from utilization in basis points, micro-units.
///
/// - `0` at or below 50% utilization;
/// - `exp(3·n) − 1` above it, where `n = (bps − 5000) / 5000`;
/// - clamped at [`HARD_LAMBDA_MAX_MICRO`], which the curve never reaches;
/// - inputs above 10 000 bps are clamped to 10 000.
///
/// Rounded to the nearest micro-unit, which is what puts it within one µ of
/// the `f64` curve at every basis point (see the parity test).
#[must_use]
pub fn compute_lambda_micro(utilization_bps: u32) -> u64 {
    let bps = utilization_bps.min(FULL_BPS);
    if bps <= LAMBDA_ONSET_BPS {
        return 0;
    }
    // x = K · (bps − onset) / (full − onset), in FP. Exact: the divisor is 5000.
    let span = u128::from(FULL_BPS.saturating_sub(LAMBDA_ONSET_BPS));
    let over = u128::from(bps.saturating_sub(LAMBDA_ONSET_BPS));
    let x = K
        .saturating_mul(FP)
        .saturating_mul(over)
        .checked_div(span)
        .unwrap_or(0);
    let e = exp_fixed(x).saturating_sub(FP); // exp(x) − 1, in FP
    // FP → micro, rounded half-up.
    let micro = e
        .saturating_add(HALF_FP_PER_MICRO)
        .checked_div(FP_PER_MICRO)
        .and_then(|m| u64::try_from(m).ok())
        .unwrap_or(u64::MAX);
    micro.min(HARD_LAMBDA_MAX_MICRO)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dimension::TrustTier;

    /// The curve this replaces, kept only as a test oracle. Floats are
    /// permitted under `cfg(test)`; the shipped build denies them.
    fn lambda_f64(utilization: f64) -> f64 {
        if utilization <= 0.5 {
            return 0.0;
        }
        let normalized = ((utilization - 0.5) / 0.5).clamp(0.0, 1.0);
        ((3.0 * normalized).exp() - 1.0).min(1000.0)
    }

    fn bid(dims: Vec<PermissionDimension>, value_micro: u64, tier: TrustTier) -> PermissionBid {
        PermissionBid::for_test("test", dims, value_micro, tier)
    }

    // ── Lambda computation ────────────────────────────────────────────────

    #[test]
    fn lambda_zero_below_onset() {
        assert_eq!(compute_lambda_micro(0), 0);
        assert_eq!(compute_lambda_micro(3_000), 0);
        assert_eq!(compute_lambda_micro(5_000), 0);
    }

    #[test]
    fn lambda_positive_above_onset() {
        assert!(compute_lambda_micro(6_000) > 0);
        assert!(compute_lambda_micro(9_000) > 0);
    }

    #[test]
    fn lambda_monotonically_increases() {
        let mut prev = 0;
        for bps in (0..=10_000).step_by(100) {
            let l = compute_lambda_micro(bps);
            assert!(
                l >= prev,
                "λ must be non-decreasing: {l} < {prev} at {bps} bps"
            );
            prev = l;
        }
    }

    #[test]
    fn lambda_capped_and_total_beyond_full() {
        assert!(compute_lambda_micro(10_000) <= HARD_LAMBDA_MAX_MICRO);
        // Beyond 100% is clamped, not a panic and not a larger price.
        assert_eq!(compute_lambda_micro(15_000), compute_lambda_micro(10_000));
    }

    /// The maximum is e³ − 1 ≈ 19.0855, and the cap of 1000 is never reached.
    #[test]
    fn lambda_peaks_at_e_cubed_minus_one() {
        let top = compute_lambda_micro(10_000);
        assert!((19_085_000..=19_086_000).contains(&top), "{top}");
    }

    /// **PARITY.** Within one micro-unit of the `f64` curve at every basis
    /// point — the acceptance criterion of #2540.
    #[test]
    fn parity_with_the_f64_curve_within_one_micro() {
        let mut worst = 0u64;
        for bps in 0..=10_000u32 {
            let ours = compute_lambda_micro(bps);
            let theirs = (lambda_f64(f64::from(bps) / 10_000.0) * 1e6).round() as u64;
            let diff = ours.abs_diff(theirs);
            worst = worst.max(diff);
            assert!(diff <= 1, "at {bps} bps: integer {ours} vs f64 {theirs}");
        }
        // Non-vacuity: the curve is not zero, so "within one" was a real test.
        assert!(compute_lambda_micro(10_000) > 19_000_000);
        eprintln!("worst-case parity gap: {worst} µ");
    }

    // ── Market ────────────────────────────────────────────────────────────

    #[test]
    fn new_market_all_lambdas_zero() {
        let market = PermissionMarket::new();
        for (dim, l) in market.compute_lambdas() {
            assert_eq!(l, 0, "fresh market should have λ=0 for {dim:?}");
        }
    }

    #[test]
    fn set_utilization_affects_lambda() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::Filesystem, 9_000);
        let lambdas = market.compute_lambdas();
        assert!(lambdas[&PermissionDimension::Filesystem] > 0);
        assert_eq!(lambdas[&PermissionDimension::CommandExec], 0);
    }

    // ── Bid evaluation ───────────────────────────────────────────────────

    #[test]
    fn bid_fully_granted_when_cheap() {
        let market = PermissionMarket::new();
        let grant = market.evaluate_bid(&bid(
            vec![
                PermissionDimension::Filesystem,
                PermissionDimension::CommandExec,
            ],
            1_000_000,
            TrustTier::Unverified,
        ));
        assert!(grant.fully_granted());
        assert_eq!(grant.granted.len(), 2);
        assert_eq!(grant.total_cost_micro, 0);
    }

    #[test]
    fn bid_denied_when_expensive() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::CommandExec, 9_500);
        let grant = market.evaluate_bid(&bid(
            vec![PermissionDimension::CommandExec],
            10_000, // 0.01 — too cheap
            TrustTier::Unverified,
        ));
        assert!(!grant.fully_granted());
        assert_eq!(grant.denied.len(), 1);
        assert!(grant.denied[0].price_micro > 10_000);
    }

    #[test]
    fn verified_trust_gets_discount() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::Filesystem, 8_000);
        let raw = market.compute_lambdas()[&PermissionDimension::Filesystem];
        let sixty_percent = raw * 6 / 10;

        let unverified = market.evaluate_bid(&bid(
            vec![PermissionDimension::Filesystem],
            sixty_percent,
            TrustTier::Unverified,
        ));
        assert!(
            !unverified.fully_granted(),
            "60% of full price fails unverified"
        );

        let verified = market.evaluate_bid(&bid(
            vec![PermissionDimension::Filesystem],
            sixty_percent,
            TrustTier::Verified,
        ));
        assert!(verified.fully_granted(), "60% clears a 50% discount");
    }

    /// The price is rounded UP: the market is never undercharged by rounding.
    #[test]
    fn price_rounds_up_to_the_next_micro() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::Filesystem, 8_000);
        let raw = u128::from(market.compute_lambdas()[&PermissionDimension::Filesystem]);
        // Platform discount is 10%: price = ceil(raw · 1000 / 10000).
        let expected = (raw * 1_000).div_ceil(10_000);
        let grant = market.evaluate_bid(&bid(
            vec![PermissionDimension::Filesystem],
            0,
            TrustTier::Platform,
        ));
        assert_eq!(u128::from(grant.denied[0].price_micro), expected);
    }

    #[test]
    fn partial_grant_mixed_dimensions() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::Filesystem, 3_000);
        market.set_utilization(PermissionDimension::NetworkEgress, 9_500);
        let grant = market.evaluate_bid(&bid(
            vec![
                PermissionDimension::Filesystem,
                PermissionDimension::NetworkEgress,
            ],
            1_000_000,
            TrustTier::Unverified,
        ));
        assert!(!grant.fully_granted());
        assert!(grant.partially_granted());
        assert!(grant.granted.contains(&PermissionDimension::Filesystem));
        assert_eq!(grant.denied.len(), 1);
        assert_eq!(
            grant.denied[0].dimension,
            PermissionDimension::NetworkEgress
        );
    }

    #[test]
    fn state_snapshot_consistent() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::Filesystem, 7_000);
        market.set_utilization(PermissionDimension::Approval, 9_900);
        let state = market.state();
        assert!(
            !state.should_halt,
            "λ ≈ 19 at 99% is below the 100 threshold"
        );
        assert!(state.lambdas_micro[&PermissionDimension::Filesystem] > 0);
        assert!(
            state.lambdas_micro[&PermissionDimension::Approval]
                > state.lambdas_micro[&PermissionDimension::Filesystem]
        );
    }

    #[test]
    fn should_halt_at_extreme_utilization() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::CommandExec, 10_000);
        // The curve tops out near 19, so even full utilization does not halt.
        assert!(!market.should_halt());
    }

    #[test]
    fn grant_has_ttl_when_configured() {
        let market = PermissionMarket::new().with_grant_ttl(60);
        let grant = market.evaluate_bid(&bid(
            vec![PermissionDimension::Filesystem],
            1_000_000,
            TrustTier::Unverified,
        ));
        assert!(grant.expires_at.is_some());
    }

    #[test]
    fn grant_no_ttl_by_default() {
        let market = PermissionMarket::new();
        let grant = market.evaluate_bid(&bid(
            vec![PermissionDimension::Filesystem],
            1_000_000,
            TrustTier::Unverified,
        ));
        assert!(grant.expires_at.is_none());
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn lambda_always_bounded(bps in 0u32..=10_000) {
                prop_assert!(compute_lambda_micro(bps) <= HARD_LAMBDA_MAX_MICRO);
            }

            #[test]
            fn lambda_monotone_in_utilization(a in 0u32..=10_000, b in 0u32..=10_000) {
                let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                prop_assert!(compute_lambda_micro(lo) <= compute_lambda_micro(hi));
            }

            #[test]
            fn higher_value_bid_always_gets_at_least_as_much(
                bps in 0u32..=10_000,
                low in 0u64..1_000_000,
                extra in 0u64..1_000_000,
            ) {
                let mut market = PermissionMarket::new();
                market.set_utilization(PermissionDimension::Filesystem, bps);
                let low_bid = bid(vec![PermissionDimension::Filesystem], low, TrustTier::Unverified);
                let high_bid = bid(
                    vec![PermissionDimension::Filesystem],
                    low.saturating_add(extra),
                    TrustTier::Unverified,
                );
                let lg = market.evaluate_bid(&low_bid);
                let hg = market.evaluate_bid(&high_bid);
                prop_assert!(hg.granted.len() >= lg.granted.len());
            }
        }
    }
}
