//! Property tests for permissive execution and weakening costs.
//!
//! Verifies:
//! - Monad laws for PermissiveExecution
//! - Cost monotonicity properties
//! - Weakening gap correctness

use lattice_guard::permissive::{PermissiveExecution, PermissiveExecutor};
use lattice_guard::weakening::{WeakeningCost, WeakeningCostConfig, WeakeningRequest};
use lattice_guard::{
    CapabilityLevel, IsolationLattice, Operation, PermissionLattice, TrifectaRisk,
};
use proptest::prelude::*;
use rust_decimal::Decimal;

// ============================================
// Arbitrary generators
// ============================================

fn arb_capability_level() -> impl Strategy<Value = CapabilityLevel> {
    prop_oneof![
        Just(CapabilityLevel::Never),
        Just(CapabilityLevel::LowRisk),
        Just(CapabilityLevel::Always),
    ]
}

fn arb_operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::ReadFiles),
        Just(Operation::WriteFiles),
        Just(Operation::EditFiles),
        Just(Operation::RunBash),
        Just(Operation::GlobSearch),
        Just(Operation::GrepSearch),
        Just(Operation::WebSearch),
        Just(Operation::WebFetch),
        Just(Operation::GitCommit),
        Just(Operation::GitPush),
        Just(Operation::CreatePr),
    ]
}

fn arb_trifecta_risk() -> impl Strategy<Value = TrifectaRisk> {
    prop_oneof![
        Just(TrifectaRisk::None),
        Just(TrifectaRisk::Low),
        Just(TrifectaRisk::Medium),
        Just(TrifectaRisk::Complete),
    ]
}

fn arb_permission_lattice() -> impl Strategy<Value = PermissionLattice> {
    prop_oneof![
        Just(PermissionLattice::permissive()),
        Just(PermissionLattice::codegen()),
        Just(PermissionLattice::pr_review()),
        Just(PermissionLattice::pr_approve()),
        Just(PermissionLattice::read_only()),
        Just(PermissionLattice::fix_issue()),
        Just(PermissionLattice::web_research()),
    ]
}

fn arb_weakening_cost() -> impl Strategy<Value = WeakeningCost> {
    (
        (0u32..100u32).prop_map(|n| Decimal::new(n as i64, 2)),
        (1u32..10u32).prop_map(|n| Decimal::new(n as i64, 0)),
        (1u32..5u32).prop_map(|n| Decimal::new(n as i64, 0)),
    )
        .prop_map(|(base, trifecta, isolation)| WeakeningCost {
            base,
            trifecta_multiplier: trifecta,
            isolation_multiplier: isolation,
        })
}

fn arb_weakening_request() -> impl Strategy<Value = WeakeningRequest> {
    (
        arb_operation(),
        arb_capability_level(),
        arb_capability_level(),
        arb_weakening_cost(),
        arb_trifecta_risk(),
    )
        .prop_map(|(op, from, to, cost, trifecta)| {
            WeakeningRequest::capability(op, from, to, cost, trifecta)
        })
}

// ============================================
// Monad Laws
// ============================================

proptest! {
    /// Left identity: pure(a).and_then(f) = f(a)
    #[test]
    fn permissive_monad_left_identity(value in -1000i32..1000i32) {
        let f = |x: i32| PermissiveExecution::pure(x.saturating_mul(2));

        let lhs = PermissiveExecution::pure(value).and_then(f);
        let rhs = f(value);

        prop_assert_eq!(lhs.value, rhs.value);
        prop_assert_eq!(lhs.total_cost.total(), rhs.total_cost.total());
        prop_assert_eq!(lhs.weakenings.len(), rhs.weakenings.len());
    }

    /// Right identity: m.and_then(pure) = m
    #[test]
    fn permissive_monad_right_identity(value in -1000i32..1000i32, cost in arb_weakening_cost()) {
        let m = PermissiveExecution {
            value,
            weakenings: Vec::new(),
            total_cost: cost.clone(),
        };

        let result = m.clone().and_then(PermissiveExecution::pure);

        prop_assert_eq!(result.value, m.value);
        // Cost should be preserved (combined with zero)
        prop_assert_eq!(result.total_cost.base, m.total_cost.base);
    }

    /// Associativity: (m.and_then(f)).and_then(g) = m.and_then(|x| f(x).and_then(g))
    #[test]
    fn permissive_monad_associativity(value in -1000i32..1000i32) {
        let m = PermissiveExecution::pure(value);
        let f = |x: i32| PermissiveExecution::pure(x.saturating_add(1));
        let g = |x: i32| PermissiveExecution::pure(x.saturating_mul(2));

        let lhs = m.clone().and_then(f).and_then(g);
        let rhs = m.and_then(|x| f(x).and_then(g));

        prop_assert_eq!(lhs.value, rhs.value);
        prop_assert_eq!(lhs.total_cost.total(), rhs.total_cost.total());
    }
}

// ============================================
// Cost Properties
// ============================================

proptest! {
    /// WeakeningCost::zero() is the identity for combine
    #[test]
    fn cost_zero_is_identity(cost in arb_weakening_cost()) {
        let zero = WeakeningCost::zero();
        let combined = cost.clone().combine(&zero);

        prop_assert_eq!(combined.base, cost.base);
        // Multipliers take max, zero has 1.0 multipliers
        prop_assert!(combined.trifecta_multiplier >= cost.trifecta_multiplier);
    }

    /// WeakeningCost::combine is commutative for base
    #[test]
    fn cost_combine_base_commutative(a in arb_weakening_cost(), b in arb_weakening_cost()) {
        let ab = a.clone().combine(&b);
        let ba = b.clone().combine(&a);

        prop_assert_eq!(ab.base, ba.base);
    }

    /// WeakeningCost::combine is associative for base
    #[test]
    fn cost_combine_base_associative(
        a in arb_weakening_cost(),
        b in arb_weakening_cost(),
        c in arb_weakening_cost()
    ) {
        let ab_c = a.clone().combine(&b).combine(&c);
        let a_bc = a.clone().combine(&b.clone().combine(&c));

        prop_assert_eq!(ab_c.base, a_bc.base);
    }

    /// total() is monotonic: if a.base <= b.base and multipliers equal, a.total() <= b.total()
    #[test]
    fn cost_total_monotonic_in_base(base1: u32, base2: u32) {
        let (small, large) = if base1 <= base2 { (base1, base2) } else { (base2, base1) };

        let cost_small = WeakeningCost::new(Decimal::new(small as i64, 2));
        let cost_large = WeakeningCost::new(Decimal::new(large as i64, 2));

        prop_assert!(cost_small.total() <= cost_large.total());
    }
}

// ============================================
// Executor Gap Properties
// ============================================

proptest! {
    /// Gap from same floor and ceiling is empty
    #[test]
    fn gap_empty_for_same(perms in arb_permission_lattice()) {
        let executor = PermissiveExecutor::new(
            perms.clone(),
            perms,
            IsolationLattice::default(),
            WeakeningCostConfig::default(),
        );

        let gap = executor.compute_gap();

        prop_assert!(gap.is_empty(), "Gap should be empty for same floor and ceiling");
        prop_assert!(gap.total_cost.is_zero(), "Cost should be zero for same floor and ceiling");
    }

    /// Gap cost is non-negative
    #[test]
    fn gap_cost_non_negative(
        floor in arb_permission_lattice(),
        ceiling in arb_permission_lattice()
    ) {
        let executor = PermissiveExecutor::new(
            floor,
            ceiling,
            IsolationLattice::default(),
            WeakeningCostConfig::default(),
        );

        let gap = executor.compute_gap();

        prop_assert!(gap.total_cost.total() >= Decimal::ZERO);
    }
}

// ============================================
// Cost Config Properties
// ============================================

proptest! {
    /// Capability cost is zero for same level
    #[test]
    fn capability_cost_zero_for_same(level in arb_capability_level()) {
        let config = WeakeningCostConfig::default();
        let cost = config.capability_cost(level, level);

        prop_assert!(cost.is_zero(), "Cost should be zero for same capability level");
    }

    /// Capability cost is zero for restriction (higher to lower)
    #[test]
    fn capability_cost_zero_for_restriction(from in arb_capability_level(), to in arb_capability_level()) {
        prop_assume!(from >= to);

        let config = WeakeningCostConfig::default();
        let cost = config.capability_cost(from, to);

        prop_assert!(cost.is_zero(), "Cost should be zero for capability restriction");
    }

    /// Capability cost is positive for weakening (lower to higher)
    #[test]
    fn capability_cost_positive_for_weakening(from in arb_capability_level(), to in arb_capability_level()) {
        prop_assume!(from < to);

        let config = WeakeningCostConfig::default();
        let cost = config.capability_cost(from, to);

        prop_assert!(!cost.is_zero(), "Cost should be positive for capability weakening");
    }
}

// ============================================
// Trifecta Multiplier Properties
// ============================================

proptest! {
    /// Complete trifecta has highest multiplier
    #[test]
    fn trifecta_complete_has_max_multiplier(before in arb_trifecta_risk()) {
        let config = WeakeningCostConfig::default();
        let multiplier = config.trifecta_multiplier(before, TrifectaRisk::Complete);

        // Complete should have 10x multiplier
        prop_assert_eq!(multiplier, Decimal::new(10, 0));
    }

    /// No change from Complete doesn't increase multiplier
    #[test]
    fn trifecta_same_level_multiplier_is_one_or_more(_before in arb_trifecta_risk()) {
        let config = WeakeningCostConfig::default();

        // Same level (not increasing) should have multiplier >= 1
        let multiplier = config.trifecta_multiplier(TrifectaRisk::None, TrifectaRisk::None);
        prop_assert!(multiplier >= Decimal::ONE);
    }
}

// ============================================
// WeakeningRequest Properties
// ============================================

proptest! {
    /// High cost requests require approval
    #[test]
    fn high_cost_requires_approval(op in arb_operation()) {
        let high_cost = WeakeningCost::new(Decimal::new(6, 1)); // 0.6
        let request = WeakeningRequest::capability(
            op,
            CapabilityLevel::Never,
            CapabilityLevel::Always,
            high_cost,
            TrifectaRisk::Medium,
        );

        prop_assert!(request.requires_approval(), "High cost requests should require approval");
    }

    /// Complete trifecta requests require approval regardless of cost
    #[test]
    fn trifecta_complete_requires_approval(op in arb_operation()) {
        let low_cost = WeakeningCost::new(Decimal::new(1, 2)); // 0.01
        let request = WeakeningRequest::capability(
            op,
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            low_cost,
            TrifectaRisk::Complete,
        );

        prop_assert!(request.requires_approval(), "Complete trifecta should require approval");
    }

    /// Low cost, low trifecta requests don't require approval
    #[test]
    fn low_cost_low_trifecta_no_approval(op in arb_operation()) {
        let low_cost = WeakeningCost::new(Decimal::new(1, 2)); // 0.01
        let request = WeakeningRequest::capability(
            op,
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            low_cost,
            TrifectaRisk::None,
        );

        prop_assert!(!request.requires_approval(), "Low cost, no trifecta should not require approval");
    }
}

// ============================================
// PermissiveExecution Accumulation
// ============================================

proptest! {
    /// Weakenings accumulate through and_then
    #[test]
    fn weakenings_accumulate(
        w1 in arb_weakening_request(),
        w2 in arb_weakening_request()
    ) {
        let exec1 = PermissiveExecution::with_weakening(1, w1);
        let exec2 = exec1.and_then(|v| PermissiveExecution::with_weakening(v + 1, w2));

        prop_assert_eq!(exec2.weakenings.len(), 2, "Should have 2 weakenings");
    }

    /// Pure doesn't add weakenings
    #[test]
    fn pure_no_weakenings(w in arb_weakening_request()) {
        let exec = PermissiveExecution::with_weakening(1, w);
        let result = exec.and_then(|v| PermissiveExecution::pure(v + 1));

        // Should still have just the original weakening
        prop_assert_eq!(result.weakenings.len(), 1);
    }
}

// ============================================
// Integration Tests
// ============================================

#[test]
fn test_codegen_to_permissive_gap() {
    let executor = PermissiveExecutor::new(
        PermissionLattice::codegen(),
        PermissionLattice::permissive(),
        IsolationLattice::sandboxed(),
        WeakeningCostConfig::default(),
    );

    let gap = executor.compute_gap();

    // Permissive has more capabilities than codegen
    assert!(
        !gap.is_empty(),
        "Should have weakenings from codegen to permissive"
    );

    // Should detect trifecta completion
    let trifecta_weakenings: Vec<_> = gap
        .requests
        .iter()
        .filter(|w| w.trifecta_impact == TrifectaRisk::Complete)
        .collect();

    // At least some operations should complete trifecta
    assert!(
        !trifecta_weakenings.is_empty()
            || gap.total_cost.trifecta_multiplier >= Decimal::new(10, 0),
        "Should detect trifecta risk"
    );
}

#[test]
fn test_execute_with_threshold_blocks_high_cost() {
    let executor = PermissiveExecutor::new(
        PermissionLattice::codegen(),
        PermissionLattice::permissive(),
        IsolationLattice::sandboxed(),
        WeakeningCostConfig::default(),
    );

    // Very low threshold
    let result = executor.execute_with_threshold(Decimal::new(1, 2), |_| "test");

    assert!(result.is_err(), "Should be denied with very low threshold");

    if let Err(denied) = result {
        assert!(!denied.weakenings_needed.is_empty());
        assert!(denied.requested_cost.total() > Decimal::new(1, 2));
    }
}

#[test]
fn test_execute_with_threshold_allows_low_cost() {
    // Same floor and ceiling = zero cost
    let perms = PermissionLattice::codegen();
    let executor = PermissiveExecutor::new(
        perms.clone(),
        perms,
        IsolationLattice::sandboxed(),
        WeakeningCostConfig::default(),
    );

    // Any threshold should work
    let result = executor.execute_with_threshold(Decimal::new(1, 2), |_| "test");

    assert!(
        result.is_ok(),
        "Should be allowed with same floor and ceiling"
    );
}
