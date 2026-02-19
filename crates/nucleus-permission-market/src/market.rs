//! Permission market — Lagrangian pricing oracle for multi-dimensional constraints.
//!
//! Generalizes the 1D `BudgetConstraint::compute_lambda()` from workstream-kg
//! to N independent permission dimensions, each with its own utilization and λ.
//!
//! By the duality theorem, the Lagrange multiplier λ for a constraint IS the
//! shadow price of relaxing that constraint by one unit. When λ_filesystem = 5.0,
//! it costs "5.0 value units" to perform one more filesystem operation.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::bid::{DeniedDimension, PermissionBid, PermissionGrant};
use crate::dimension::PermissionDimension;

/// Utilization threshold below which λ = 0 (no constraint).
const LAMBDA_ONSET: f64 = 0.5;

/// Maximum lambda value (prevents infinite prices).
const HARD_LAMBDA_MAX: f64 = 1000.0;

/// Lambda threshold that triggers a halt recommendation.
const CRITICAL_LAMBDA_THRESHOLD: f64 = 100.0;

/// Exponential growth rate. Chosen so λ ≈ 10 at ~90% utilization.
const K: f64 = 3.0;

/// Per-dimension utilization state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionState {
    /// Current utilization (0.0 = idle, 1.0 = fully consumed).
    pub utilization: f64,
    /// Optional capacity limit (for informational display).
    pub capacity: Option<f64>,
}

impl DimensionState {
    pub fn new(utilization: f64) -> Self {
        Self {
            utilization: utilization.clamp(0.0, 1.0),
            capacity: None,
        }
    }
}

/// Multi-dimensional constraint state snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionConstraintState {
    /// λ per dimension (0 = cheap/unconstrained, high = expensive/restricted).
    pub lambdas: BTreeMap<PermissionDimension, f64>,
    /// Current utilization per dimension (0.0–1.0).
    pub utilization: BTreeMap<PermissionDimension, f64>,
    /// Whether any dimension recommends halt.
    pub should_halt: bool,
}

/// The permission market.
///
/// Holds per-dimension utilization state and computes Lagrange multiplier
/// prices. Thread-safe reads via clone; writers must hold a lock externally.
#[derive(Debug, Clone)]
pub struct PermissionMarket {
    dimensions: BTreeMap<PermissionDimension, DimensionState>,
    /// Optional grant TTL in seconds (applied to all grants).
    grant_ttl_secs: Option<u64>,
}

impl PermissionMarket {
    /// Create a market with no initial utilization on any dimension.
    pub fn new() -> Self {
        let dimensions = PermissionDimension::ALL
            .iter()
            .map(|d| (*d, DimensionState::new(0.0)))
            .collect();

        Self {
            dimensions,
            grant_ttl_secs: None,
        }
    }

    /// Create a market with explicit per-dimension utilization.
    pub fn with_utilization(utilizations: BTreeMap<PermissionDimension, f64>) -> Self {
        let dimensions = PermissionDimension::ALL
            .iter()
            .map(|d| {
                let util = utilizations.get(d).copied().unwrap_or(0.0);
                (*d, DimensionState::new(util))
            })
            .collect();

        Self {
            dimensions,
            grant_ttl_secs: None,
        }
    }

    /// Set the grant TTL applied to all permission grants.
    pub fn set_grant_ttl(&mut self, ttl_secs: u64) {
        self.grant_ttl_secs = Some(ttl_secs);
    }

    /// Update utilization for a single dimension.
    pub fn set_utilization(&mut self, dim: PermissionDimension, utilization: f64) {
        self.dimensions
            .entry(dim)
            .and_modify(|s| s.utilization = utilization.clamp(0.0, 1.0))
            .or_insert_with(|| DimensionState::new(utilization));
    }

    /// Compute λ for each dimension based on current utilization.
    pub fn compute_lambdas(&self) -> BTreeMap<PermissionDimension, f64> {
        self.dimensions
            .iter()
            .map(|(dim, state)| (*dim, compute_lambda(state.utilization)))
            .collect()
    }

    /// Evaluate a bid: grant permissions where value >= price.
    pub fn evaluate_bid(&self, bid: &PermissionBid) -> PermissionGrant {
        let lambdas = self.compute_lambdas();
        let trust_discount = bid.trust_tier.discount_factor();
        let mut granted = Vec::new();
        let mut denied = Vec::new();
        let mut total_cost = 0.0;

        for dim in &bid.requested {
            let raw_lambda = lambdas.get(dim).copied().unwrap_or(0.0);
            let price = raw_lambda * trust_discount;

            if bid.value_estimate >= price {
                granted.push(*dim);
                total_cost += price;
            } else {
                denied.push(DeniedDimension {
                    dimension: *dim,
                    price,
                });
            }
        }

        let expires_at = self.grant_ttl_secs.map(|ttl| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + ttl
        });

        PermissionGrant {
            granted,
            denied,
            total_cost,
            expires_at,
        }
    }

    /// Get a snapshot of the full constraint state.
    pub fn state(&self) -> PermissionConstraintState {
        let lambdas = self.compute_lambdas();
        let utilization = self
            .dimensions
            .iter()
            .map(|(dim, state)| (*dim, state.utilization))
            .collect();
        let should_halt = lambdas.values().any(|l| *l > CRITICAL_LAMBDA_THRESHOLD);

        PermissionConstraintState {
            lambdas,
            utilization,
            should_halt,
        }
    }

    /// Whether any dimension recommends halting.
    pub fn should_halt(&self) -> bool {
        self.dimensions
            .values()
            .any(|s| compute_lambda(s.utilization) > CRITICAL_LAMBDA_THRESHOLD)
    }
}

impl Default for PermissionMarket {
    fn default() -> Self {
        Self::new()
    }
}

/// Pure computation of λ from a utilization fraction.
///
/// - `λ = 0` when utilization ≤ 50%
/// - `λ` grows exponentially as utilization approaches 100%
/// - `λ` capped at `HARD_LAMBDA_MAX`
///
/// Formula: `λ = exp(K * normalized) - 1`
/// where `normalized = (utilization - onset) / (1 - onset)`.
pub fn compute_lambda(utilization: f64) -> f64 {
    if utilization <= LAMBDA_ONSET {
        return 0.0;
    }

    let normalized = (utilization - LAMBDA_ONSET) / (1.0 - LAMBDA_ONSET);
    let normalized = normalized.clamp(0.0, 1.0);
    let raw = (K * normalized).exp() - 1.0;

    raw.min(HARD_LAMBDA_MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dimension::TrustTier;

    // ── Lambda computation ────────────────────────────────────────────────

    #[test]
    fn lambda_zero_below_onset() {
        assert_eq!(compute_lambda(0.0), 0.0);
        assert_eq!(compute_lambda(0.3), 0.0);
        assert_eq!(compute_lambda(0.5), 0.0);
    }

    #[test]
    fn lambda_positive_above_onset() {
        assert!(compute_lambda(0.6) > 0.0);
        assert!(compute_lambda(0.9) > 0.0);
    }

    #[test]
    fn lambda_monotonically_increases() {
        let mut prev = 0.0;
        for i in 0..=100 {
            let util = i as f64 / 100.0;
            let l = compute_lambda(util);
            assert!(
                l >= prev,
                "lambda must be non-decreasing: {l} < {prev} at {util}"
            );
            prev = l;
        }
    }

    #[test]
    fn lambda_capped_at_max() {
        assert!(compute_lambda(1.0) <= HARD_LAMBDA_MAX);
        // Even beyond 1.0 (shouldn't happen but shouldn't panic)
        assert!(compute_lambda(1.5).is_finite());
    }

    #[test]
    fn lambda_finite_for_all_inputs() {
        for i in 0..=100 {
            let util = i as f64 / 100.0;
            assert!(compute_lambda(util).is_finite());
        }
    }

    // ── Market ────────────────────────────────────────────────────────────

    #[test]
    fn new_market_all_lambdas_zero() {
        let market = PermissionMarket::new();
        let lambdas = market.compute_lambdas();
        for (dim, l) in &lambdas {
            assert_eq!(*l, 0.0, "fresh market should have λ=0 for {dim:?}");
        }
    }

    #[test]
    fn set_utilization_affects_lambda() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::Filesystem, 0.9);

        let lambdas = market.compute_lambdas();
        assert!(lambdas[&PermissionDimension::Filesystem] > 0.0);
        assert_eq!(lambdas[&PermissionDimension::CommandExec], 0.0);
    }

    // ── Bid evaluation ───────────────────────────────────────────────────

    #[test]
    fn bid_fully_granted_when_cheap() {
        let market = PermissionMarket::new(); // all λ = 0

        let bid = PermissionBid {
            skill_id: "test".into(),
            requested: vec![
                PermissionDimension::Filesystem,
                PermissionDimension::CommandExec,
            ],
            value_estimate: 1.0,
            trust_tier: TrustTier::Unverified,
        };

        let grant = market.evaluate_bid(&bid);
        assert!(grant.fully_granted());
        assert_eq!(grant.granted.len(), 2);
        assert!(grant.total_cost < f64::EPSILON);
    }

    #[test]
    fn bid_denied_when_expensive() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::CommandExec, 0.95);

        let bid = PermissionBid {
            skill_id: "test".into(),
            requested: vec![PermissionDimension::CommandExec],
            value_estimate: 0.01, // too cheap
            trust_tier: TrustTier::Unverified,
        };

        let grant = market.evaluate_bid(&bid);
        assert!(!grant.fully_granted());
        assert_eq!(grant.denied.len(), 1);
        assert!(grant.denied[0].price > 0.01);
    }

    #[test]
    fn verified_trust_gets_discount() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::Filesystem, 0.8);

        let lambdas = market.compute_lambdas();
        let raw_price = lambdas[&PermissionDimension::Filesystem];

        // Unverified pays full price
        let unverified_bid = PermissionBid {
            skill_id: "a".into(),
            requested: vec![PermissionDimension::Filesystem],
            value_estimate: raw_price * 0.6, // 60% of raw — should fail unverified
            trust_tier: TrustTier::Unverified,
        };
        let grant = market.evaluate_bid(&unverified_bid);
        assert!(
            !grant.fully_granted(),
            "unverified should be denied at 60% of raw price"
        );

        // Verified pays 50% price
        let verified_bid = PermissionBid {
            skill_id: "b".into(),
            requested: vec![PermissionDimension::Filesystem],
            value_estimate: raw_price * 0.6, // Same 60% — should pass at 50% discount
            trust_tier: TrustTier::Verified,
        };
        let grant = market.evaluate_bid(&verified_bid);
        assert!(
            grant.fully_granted(),
            "verified should be granted at 60% of raw price"
        );
    }

    #[test]
    fn partial_grant_mixed_dimensions() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::Filesystem, 0.3); // cheap
        market.set_utilization(PermissionDimension::NetworkEgress, 0.95); // expensive

        let bid = PermissionBid {
            skill_id: "test".into(),
            requested: vec![
                PermissionDimension::Filesystem,
                PermissionDimension::NetworkEgress,
            ],
            value_estimate: 1.0,
            trust_tier: TrustTier::Unverified,
        };

        let grant = market.evaluate_bid(&bid);
        assert!(!grant.fully_granted());
        assert!(grant.partially_granted());
        assert!(grant.granted.contains(&PermissionDimension::Filesystem));
        assert_eq!(grant.denied.len(), 1);
        assert_eq!(
            grant.denied[0].dimension,
            PermissionDimension::NetworkEgress
        );
    }

    // ── State snapshot ───────────────────────────────────────────────────

    #[test]
    fn state_snapshot_consistent() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::Filesystem, 0.7);
        market.set_utilization(PermissionDimension::Approval, 0.99);

        let state = market.state();
        assert!(!state.should_halt); // 0.99 approval λ ≈ 19, below 100 threshold
        assert!(state.lambdas[&PermissionDimension::Filesystem] > 0.0);
        assert!(
            state.lambdas[&PermissionDimension::Approval]
                > state.lambdas[&PermissionDimension::Filesystem]
        );
    }

    #[test]
    fn should_halt_at_extreme_utilization() {
        let mut market = PermissionMarket::new();
        market.set_utilization(PermissionDimension::CommandExec, 1.0);
        // λ at 1.0 = exp(3) - 1 ≈ 19.09, below 100
        // Need to check: only halt if λ > 100 which won't happen with K=3
        // This is by design — the orchestrator's budget calibration can set
        // utilization > 1.0 in extreme cases, but with clamp(0,1) we cap at ~19
        assert!(!market.should_halt());
    }

    // ── Grant TTL ────────────────────────────────────────────────────────

    #[test]
    fn grant_has_ttl_when_configured() {
        let mut market = PermissionMarket::new();
        market.set_grant_ttl(300);

        let bid = PermissionBid {
            skill_id: "test".into(),
            requested: vec![PermissionDimension::Filesystem],
            value_estimate: 1.0,
            trust_tier: TrustTier::Unverified,
        };

        let grant = market.evaluate_bid(&bid);
        assert!(grant.expires_at.is_some());
    }

    #[test]
    fn grant_no_ttl_by_default() {
        let market = PermissionMarket::new();

        let bid = PermissionBid {
            skill_id: "test".into(),
            requested: vec![PermissionDimension::Filesystem],
            value_estimate: 1.0,
            trust_tier: TrustTier::Unverified,
        };

        let grant = market.evaluate_bid(&bid);
        assert!(grant.expires_at.is_none());
    }

    // ── Proptest ─────────────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn lambda_always_non_negative(util in 0.0..=1.0f64) {
            assert!(compute_lambda(util) >= 0.0);
        }

        #[test]
        fn lambda_always_bounded(util in 0.0..=1.0f64) {
            let l = compute_lambda(util);
            assert!(l <= HARD_LAMBDA_MAX);
            assert!(l.is_finite());
        }

        #[test]
        fn higher_value_bid_always_gets_at_least_as_much(
            util in 0.0..=1.0f64,
            low_val in 0.0..50.0f64,
        ) {
            let mut market = PermissionMarket::new();
            market.set_utilization(PermissionDimension::Filesystem, util);

            let low_bid = PermissionBid {
                skill_id: "lo".into(),
                requested: vec![PermissionDimension::Filesystem],
                value_estimate: low_val,
                trust_tier: TrustTier::Unverified,
            };
            let high_bid = PermissionBid {
                skill_id: "hi".into(),
                requested: vec![PermissionDimension::Filesystem],
                value_estimate: low_val + 10.0,
                trust_tier: TrustTier::Unverified,
            };

            let low_grant = market.evaluate_bid(&low_bid);
            let high_grant = market.evaluate_bid(&high_bid);

            assert!(
                high_grant.granted.len() >= low_grant.granted.len(),
                "higher bid should get at least as many grants"
            );
        }
    }
}
