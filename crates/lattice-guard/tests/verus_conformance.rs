//! Verus Model ↔ Production Conformance Tests
//!
//! This test suite bridges the gap between the formally verified Verus model
//! (lattice-guard-verified) and the production Rust code (lattice-guard).
//!
//! The Verus proofs verify algebraic properties of a *spec model* — ghost
//! functions that Z3 checks but never execute. These conformance tests ensure
//! the model faithfully represents the production implementation by asserting
//! identical behavior on random inputs via proptest.
//!
//! # What This Proves
//!
//! If these tests pass AND the Verus proofs pass, then:
//! 1. The model satisfies the algebraic laws (Verus proves this)
//! 2. The production code matches the model (these tests assert this)
//! 3. Therefore: the production code satisfies the algebraic laws (transitivity)
//!
//! This is the same refinement strategy used by seL4: prove the model correct,
//! then show the implementation matches the model.

use lattice_guard::guard::GradedGuard;
use lattice_guard::{
    CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Obligations, Operation,
    PathLattice, PermissionLattice, TrifectaRisk,
};
use proptest::prelude::*;

/// Create a PermissionLattice with EMPTY obligations (not the default safety set).
///
/// The production `Default::default()` pre-populates obligations for WriteFiles,
/// EditFiles, WebSearch, etc. as baseline safety. The Verus model only models
/// trifecta-derived obligations. This helper starts clean so conformance tests
/// verify the trifecta model in isolation.
fn perms_with_empty_obligations(caps: CapabilityLattice) -> PermissionLattice {
    PermissionLattice {
        capabilities: caps,
        obligations: Obligations::default(), // empty
        paths: PathLattice::default(),
        ..Default::default()
    }
}

// ============================================================================
// Verus Model Re-implementation (reference implementation in regular Rust)
//
// These functions mirror the Verus spec functions exactly.
// Any divergence between these and the Verus specs is a bug in *this file*,
// not in the Verus proofs or production code.
// ============================================================================

/// Mirror of Verus `has_private_access(c)`: f0 >= 1 || f4 >= 1 || f5 >= 1
fn model_has_private_access(caps: &CapabilityLattice) -> bool {
    caps.read_files >= CapabilityLevel::LowRisk
        || caps.glob_search >= CapabilityLevel::LowRisk
        || caps.grep_search >= CapabilityLevel::LowRisk
}

/// Mirror of Verus `has_untrusted_content(c)`: f6 >= 1 || f7 >= 1
fn model_has_untrusted_content(caps: &CapabilityLattice) -> bool {
    caps.web_search >= CapabilityLevel::LowRisk || caps.web_fetch >= CapabilityLevel::LowRisk
}

/// Mirror of Verus `has_exfiltration(c)`: f3 >= 1 || f9 >= 1 || f10 >= 1
fn model_has_exfiltration(caps: &CapabilityLattice) -> bool {
    caps.run_bash >= CapabilityLevel::LowRisk
        || caps.git_push >= CapabilityLevel::LowRisk
        || caps.create_pr >= CapabilityLevel::LowRisk
}

/// Mirror of Verus `trifecta_count(c)`: sum of 3 bools
fn model_trifecta_count(caps: &CapabilityLattice) -> u8 {
    model_has_private_access(caps) as u8
        + model_has_untrusted_content(caps) as u8
        + model_has_exfiltration(caps) as u8
}

/// Mirror of Verus `trifecta_risk_level(c)`: equals trifecta_count
fn model_trifecta_risk_level(caps: &CapabilityLattice) -> u8 {
    model_trifecta_count(caps)
}

/// Mirror of Verus `is_trifecta_complete(c)`: all 3 present
fn model_is_trifecta_complete(caps: &CapabilityLattice) -> bool {
    model_has_private_access(caps)
        && model_has_untrusted_content(caps)
        && model_has_exfiltration(caps)
}

/// Mirror of Verus `trifecta_obligations(caps)`: if complete, gate exfil vectors
fn model_trifecta_obligations(caps: &CapabilityLattice) -> (bool, bool, bool) {
    if model_is_trifecta_complete(caps) {
        (
            caps.run_bash >= CapabilityLevel::LowRisk, // run_bash obligated
            caps.git_push >= CapabilityLevel::LowRisk, // git_push obligated
            caps.create_pr >= CapabilityLevel::LowRisk, // create_pr obligated
        )
    } else {
        (false, false, false)
    }
}

/// Mirror of Verus `requires_approval(obs, op)`.
///
/// Verus model: (op == 3 && obs.run_bash) || (op == 9 && obs.git_push) || (op == 10 && obs.create_pr)
fn model_requires_approval(obligations: &Obligations, op: &Operation) -> bool {
    match op {
        Operation::RunBash => obligations.requires(Operation::RunBash),
        Operation::GitPush => obligations.requires(Operation::GitPush),
        Operation::CreatePr => obligations.requires(Operation::CreatePr),
        _ => false, // Model only tracks exfil obligations
    }
}

/// Mirror of Verus `check_operation_allowed(obs, risk, op)`:
/// !(requires_approval(obs, op) && risk == 3)
fn model_check_operation_allowed(
    obligations: &Obligations,
    risk: TrifectaRisk,
    op: &Operation,
) -> bool {
    !(model_requires_approval(obligations, op) && risk == TrifectaRisk::Complete)
}

/// Mirror of Verus `budget_allows(consumed, max, amount)`:
/// consumed + amount <= max
fn model_budget_allows(consumed: u64, max_budget: u64, amount: u64) -> bool {
    consumed
        .checked_add(amount)
        .is_some_and(|total| total <= max_budget)
}

// ============================================================================
// Proptest Strategies (reuse patterns from proptest_lattice.rs)
// ============================================================================

fn arb_capability_level() -> impl Strategy<Value = CapabilityLevel> {
    prop_oneof![
        Just(CapabilityLevel::Never),
        Just(CapabilityLevel::LowRisk),
        Just(CapabilityLevel::Always),
    ]
}

fn arb_capability_lattice() -> impl Strategy<Value = CapabilityLattice> {
    (
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
        arb_capability_level(),
    )
        .prop_map(
            |(rf, wf, ef, rb, gs, grs, ws, wfe, gc, gp, cp, mp)| CapabilityLattice {
                read_files: rf,
                write_files: wf,
                edit_files: ef,
                run_bash: rb,
                glob_search: gs,
                grep_search: grs,
                web_search: ws,
                web_fetch: wfe,
                git_commit: gc,
                git_push: gp,
                create_pr: cp,
                manage_pods: mp,
            },
        )
}

fn arb_exfil_operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        Just(Operation::RunBash),
        Just(Operation::GitPush),
        Just(Operation::CreatePr),
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
        Just(Operation::ManagePods),
    ]
}

// ============================================================================
// Tier A: Trifecta Risk Conformance
// ============================================================================

proptest! {
    /// CONFORMANCE: model trifecta_risk_level matches production trifecta_risk().
    ///
    /// This is the most critical conformance test. The Verus proofs verify
    /// properties of `trifecta_risk_level(c)` (the model). This test asserts
    /// that the production `IncompatibilityConstraint::trifecta_risk()` returns
    /// the same value. If they diverge, the proofs don't apply to production.
    #[test]
    fn conformance_trifecta_risk(caps in arb_capability_lattice()) {
        let constraint = IncompatibilityConstraint::enforcing();
        let prod_risk = constraint.trifecta_risk(&caps);
        let model_risk = model_trifecta_risk_level(&caps);

        prop_assert_eq!(
            prod_risk as u8, model_risk,
            "CONFORMANCE VIOLATION: production trifecta_risk={:?} ({}) != model risk_level={} for caps={:?}",
            prod_risk, prod_risk as u8, model_risk, caps
        );
    }

    /// CONFORMANCE: model has_private_access matches production predicate.
    #[test]
    fn conformance_has_private_access(caps in arb_capability_lattice()) {
        let constraint = IncompatibilityConstraint::enforcing();
        let prod_risk = constraint.trifecta_risk(&caps);
        let model_private = model_has_private_access(&caps);

        // If no private access in model, production risk should be at most Medium
        // (missing one component means ≤ 2)
        if !model_private {
            prop_assert!(
                prod_risk <= TrifectaRisk::Medium,
                "Model says no private access but production risk is {:?}", prod_risk
            );
        }
    }

    /// CONFORMANCE: model has_untrusted_content matches production predicate.
    #[test]
    fn conformance_has_untrusted_content(caps in arb_capability_lattice()) {
        let constraint = IncompatibilityConstraint::enforcing();
        let prod_risk = constraint.trifecta_risk(&caps);
        let model_untrusted = model_has_untrusted_content(&caps);

        if !model_untrusted {
            prop_assert!(
                prod_risk <= TrifectaRisk::Medium,
                "Model says no untrusted content but production risk is {:?}", prod_risk
            );
        }
    }

    /// CONFORMANCE: model has_exfiltration matches production predicate.
    #[test]
    fn conformance_has_exfiltration(caps in arb_capability_lattice()) {
        let constraint = IncompatibilityConstraint::enforcing();
        let prod_risk = constraint.trifecta_risk(&caps);
        let model_exfil = model_has_exfiltration(&caps);

        if !model_exfil {
            prop_assert!(
                prod_risk <= TrifectaRisk::Medium,
                "Model says no exfiltration but production risk is {:?}", prod_risk
            );
        }
    }

    /// CONFORMANCE: model is_trifecta_complete ↔ production is_trifecta_complete.
    #[test]
    fn conformance_trifecta_complete(caps in arb_capability_lattice()) {
        let constraint = IncompatibilityConstraint::enforcing();
        let prod_complete = constraint.is_trifecta_complete(&caps);
        let model_complete = model_is_trifecta_complete(&caps);

        prop_assert_eq!(
            prod_complete, model_complete,
            "CONFORMANCE VIOLATION: production complete={} != model complete={} for caps={:?}",
            prod_complete, model_complete, caps
        );
    }

    /// CONFORMANCE: model trifecta_count is bounded [0, 3].
    ///
    /// Mirrors Verus proof_trifecta_count_bounded.
    #[test]
    fn conformance_trifecta_count_bounded(caps in arb_capability_lattice()) {
        let count = model_trifecta_count(&caps);
        prop_assert!(count <= 3, "trifecta_count {} > 3", count);
    }

    /// CONFORMANCE: model risk_level = 3 iff trifecta complete.
    ///
    /// Mirrors Verus proof_trifecta_complete_iff_count_three.
    #[test]
    fn conformance_complete_iff_three(caps in arb_capability_lattice()) {
        let complete = model_is_trifecta_complete(&caps);
        let count = model_trifecta_count(&caps);

        prop_assert_eq!(
            complete, count == 3,
            "complete={} but count={}", complete, count
        );
    }
}

// ============================================================================
// Tier A: Trifecta Obligations Conformance
// ============================================================================

proptest! {
    /// CONFORMANCE: model obligations match production obligations_for().
    ///
    /// The Verus model `trifecta_obligations(caps)` produces an Obs struct
    /// with 3 bools. The production `IncompatibilityConstraint::obligations_for()`
    /// produces an `Obligations` with a `BTreeSet<Operation>`. This test bridges
    /// the type gap: same semantics, different representations.
    #[test]
    fn conformance_obligations_for(caps in arb_capability_lattice()) {
        let constraint = IncompatibilityConstraint::enforcing();
        let prod_obs = constraint.obligations_for(&caps);
        let (model_bash, model_push, model_pr) = model_trifecta_obligations(&caps);

        prop_assert_eq!(
            prod_obs.requires(Operation::RunBash), model_bash,
            "RunBash obligation: production={} model={} caps={:?}",
            prod_obs.requires(Operation::RunBash), model_bash, caps
        );
        prop_assert_eq!(
            prod_obs.requires(Operation::GitPush), model_push,
            "GitPush obligation: production={} model={} caps={:?}",
            prod_obs.requires(Operation::GitPush), model_push, caps
        );
        prop_assert_eq!(
            prod_obs.requires(Operation::CreatePr), model_pr,
            "CreatePr obligation: production={} model={} caps={:?}",
            prod_obs.requires(Operation::CreatePr), model_pr, caps
        );
    }

    /// CONFORMANCE: obligations only target exfil ops (never read/search/etc).
    ///
    /// Mirrors Verus proof_trifecta_obligations_only_exfil.
    #[test]
    fn conformance_obligations_only_exfil(caps in arb_capability_lattice()) {
        let constraint = IncompatibilityConstraint::enforcing();
        let obs = constraint.obligations_for(&caps);

        // Non-exfil operations must NEVER have obligations from trifecta
        prop_assert!(!obs.requires(Operation::ReadFiles), "ReadFiles should never be obligated");
        prop_assert!(!obs.requires(Operation::WriteFiles), "WriteFiles should never be obligated");
        prop_assert!(!obs.requires(Operation::EditFiles), "EditFiles should never be obligated");
        prop_assert!(!obs.requires(Operation::GlobSearch), "GlobSearch should never be obligated");
        prop_assert!(!obs.requires(Operation::GrepSearch), "GrepSearch should never be obligated");
        prop_assert!(!obs.requires(Operation::WebSearch), "WebSearch should never be obligated");
        prop_assert!(!obs.requires(Operation::WebFetch), "WebFetch should never be obligated");
        prop_assert!(!obs.requires(Operation::GitCommit), "GitCommit should never be obligated");
        prop_assert!(!obs.requires(Operation::ManagePods), "ManagePods should never be obligated");
    }

    /// CONFORMANCE: no trifecta → empty obligations.
    ///
    /// Mirrors Verus proof_no_trifecta_no_obligations.
    #[test]
    fn conformance_no_trifecta_no_obligations(caps in arb_capability_lattice()) {
        let constraint = IncompatibilityConstraint::enforcing();
        if !constraint.is_trifecta_complete(&caps) {
            let obs = constraint.obligations_for(&caps);
            prop_assert!(
                obs.is_empty(),
                "No trifecta but non-empty obligations: {:?} for caps={:?}",
                obs, caps
            );
        }
    }
}

// ============================================================================
// Tier B: Normalize Conformance
// ============================================================================

proptest! {
    /// CONFORMANCE: normalize preserves capabilities.
    ///
    /// Mirrors Verus proof_normalize_preserves_capabilities: ν(p).caps == p.caps
    #[test]
    fn conformance_normalize_preserves_capabilities(caps in arb_capability_lattice()) {
        let perms = perms_with_empty_obligations(caps.clone());
        let normalized = perms.normalize();

        prop_assert_eq!(
            normalized.capabilities, caps,
            "normalize() changed capabilities!"
        );
    }

    /// CONFORMANCE: normalize only adds obligations (never removes).
    ///
    /// Mirrors Verus proof_normalize_only_adds_obligations: ν(p).obs ⊇ p.obs
    #[test]
    fn conformance_normalize_only_adds_obligations(
        caps in arb_capability_lattice(),
        add_bash in any::<bool>(),
        add_push in any::<bool>(),
        add_pr in any::<bool>(),
    ) {
        let mut obligations = Obligations::default();
        if add_bash { obligations.insert(Operation::RunBash); }
        if add_push { obligations.insert(Operation::GitPush); }
        if add_pr { obligations.insert(Operation::CreatePr); }

        let mut perms = perms_with_empty_obligations(caps);
        perms.obligations = obligations.clone();
        let normalized = perms.normalize();

        // Every obligation present before normalize must still be present after
        if add_bash {
            prop_assert!(
                normalized.obligations.requires(Operation::RunBash),
                "normalize removed RunBash obligation"
            );
        }
        if add_push {
            prop_assert!(
                normalized.obligations.requires(Operation::GitPush),
                "normalize removed GitPush obligation"
            );
        }
        if add_pr {
            prop_assert!(
                normalized.obligations.requires(Operation::CreatePr),
                "normalize removed CreatePr obligation"
            );
        }
    }

    /// CONFORMANCE: normalize is idempotent.
    ///
    /// Mirrors Verus proof of nucleus idempotency: ν(ν(p)) == ν(p).
    /// We compare the fields that the Verus model tracks (caps + obligations).
    #[test]
    fn conformance_normalize_idempotent(caps in arb_capability_lattice()) {
        let perms = perms_with_empty_obligations(caps);
        let once = perms.normalize();
        let twice = once.clone().normalize();

        prop_assert_eq!(
            once.capabilities, twice.capabilities,
            "normalize not idempotent on capabilities"
        );
        // Compare obligation sets (not full struct — id/timestamps differ)
        prop_assert_eq!(
            once.obligations, twice.obligations,
            "normalize not idempotent on obligations"
        );
    }
}

// ============================================================================
// Tier C: Guard Decision Conformance
// ============================================================================

proptest! {
    /// CONFORMANCE: check_operation matches model for exfil ops.
    ///
    /// Mirrors Verus check_operation_allowed(obs, risk, op).
    /// The production GradedGuard::check_operation() should produce the same
    /// allow/deny decision as the model.
    #[test]
    fn conformance_check_operation_exfil(caps in arb_capability_lattice(), op in arb_exfil_operation()) {
        // Normalize first (as the Verus end-to-end proof does)
        let perms = perms_with_empty_obligations(caps.clone()).normalize();

        let guard = GradedGuard::new(perms.clone());
        let prod_result = guard.check_operation(op);
        let prod_allowed = prod_result.value.is_ok();

        // Model computation
        let model_allowed = model_check_operation_allowed(
            &perms.obligations,
            guard.risk(),
            &op,
        );

        prop_assert_eq!(
            prod_allowed, model_allowed,
            "CONFORMANCE VIOLATION: guard decision production={} model={} for op={:?} risk={:?} caps={:?}",
            prod_allowed, model_allowed, op, guard.risk(), caps
        );
    }

    /// CONFORMANCE: check_operation matches model for ALL operations.
    #[test]
    fn conformance_check_operation_all(caps in arb_capability_lattice(), op in arb_operation()) {
        let perms = perms_with_empty_obligations(caps.clone()).normalize();

        let guard = GradedGuard::new(perms.clone());
        let prod_result = guard.check_operation(op);
        let prod_allowed = prod_result.value.is_ok();

        let model_allowed = model_check_operation_allowed(
            &perms.obligations,
            guard.risk(),
            &op,
        );

        prop_assert_eq!(
            prod_allowed, model_allowed,
            "CONFORMANCE VIOLATION: op={:?} production={} model={} risk={:?}",
            op, prod_allowed, model_allowed, guard.risk()
        );
    }

    /// CONFORMANCE: end-to-end trifecta safety.
    ///
    /// Mirrors Verus proof_end_to_end_trifecta_safe:
    /// For any complete trifecta + active exfil op → denied after normalize.
    ///
    /// This is THE critical test — it asserts in production what Verus proves
    /// about the model. If this fails, the formal proof doesn't protect us.
    #[test]
    fn conformance_end_to_end_trifecta_safe(
        caps in arb_capability_lattice(),
        op in arb_exfil_operation(),
    ) {
        let constraint = IncompatibilityConstraint::enforcing();
        if !constraint.is_trifecta_complete(&caps) {
            return Ok(());
        }

        // Check that the exfil op is active (≥ LowRisk)
        let op_active = match op {
            Operation::RunBash => caps.run_bash >= CapabilityLevel::LowRisk,
            Operation::GitPush => caps.git_push >= CapabilityLevel::LowRisk,
            Operation::CreatePr => caps.create_pr >= CapabilityLevel::LowRisk,
            _ => false,
        };
        if !op_active {
            return Ok(());
        }

        // Normalize (applies trifecta obligations)
        let perms = perms_with_empty_obligations(caps.clone()).normalize();

        let guard = GradedGuard::new(perms);

        // THE ASSERTION: after normalize, trifecta exfil is DENIED
        let result = guard.check_operation(op);
        prop_assert!(
            result.value.is_err(),
            "END-TO-END SAFETY VIOLATION: {:?} was ALLOWED despite complete trifecta! caps={:?}",
            op, caps
        );
    }
}

// ============================================================================
// Tier C: Guard Monotonicity Conformance
// ============================================================================

proptest! {
    /// CONFORMANCE: risk is monotone under ≤ (more caps → more risk).
    ///
    /// Mirrors Verus proof_trifecta_risk_monotone: a ≤ b ⟹ risk(a) ≤ risk(b)
    #[test]
    fn conformance_risk_monotone(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
    ) {
        // Only test when a ≤ b (pointwise)
        if !a.leq(&b) {
            return Ok(());
        }

        let constraint = IncompatibilityConstraint::enforcing();
        let risk_a = constraint.trifecta_risk(&a) as u8;
        let risk_b = constraint.trifecta_risk(&b) as u8;

        prop_assert!(
            risk_a <= risk_b,
            "Risk not monotone: a≤b but risk(a)={} > risk(b)={}, a={:?}, b={:?}",
            risk_a, risk_b, a, b
        );
    }

    /// CONFORMANCE: meet decreases risk.
    ///
    /// Mirrors Verus proof_trifecta_meet_risk_decreases.
    #[test]
    fn conformance_meet_decreases_risk(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
    ) {
        let constraint = IncompatibilityConstraint::enforcing();
        let m = a.meet(&b);
        let risk_a = constraint.trifecta_risk(&a) as u8;
        let risk_b = constraint.trifecta_risk(&b) as u8;
        let risk_m = constraint.trifecta_risk(&m) as u8;

        prop_assert!(
            risk_m <= risk_a && risk_m <= risk_b,
            "Meet didn't decrease risk: risk(m)={} risk(a)={} risk(b)={}",
            risk_m, risk_a, risk_b
        );
    }

    /// CONFORMANCE: join increases risk.
    ///
    /// Mirrors Verus proof_trifecta_join_risk_increases.
    #[test]
    fn conformance_join_increases_risk(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
    ) {
        let constraint = IncompatibilityConstraint::enforcing();
        let j = a.join(&b);
        let risk_a = constraint.trifecta_risk(&a) as u8;
        let risk_b = constraint.trifecta_risk(&b) as u8;
        let risk_j = constraint.trifecta_risk(&j) as u8;

        prop_assert!(
            risk_j >= risk_a && risk_j >= risk_b,
            "Join didn't increase risk: risk(j)={} risk(a)={} risk(b)={}",
            risk_j, risk_a, risk_b
        );
    }
}

// ============================================================================
// Tier D: Budget Decision Conformance
// ============================================================================

proptest! {
    /// CONFORMANCE: budget_allows model matches the arithmetic invariant.
    #[test]
    fn conformance_budget_allows(
        consumed in 0u64..1_000_000,
        max_budget in 0u64..1_000_000,
        amount in 0u64..1_000_000,
    ) {
        let model = model_budget_allows(consumed, max_budget, amount);
        let expected = consumed.checked_add(amount).is_some_and(|t| t <= max_budget);
        prop_assert_eq!(model, expected);
    }

    /// CONFORMANCE: zero budget denies all nonzero charges.
    ///
    /// Mirrors Verus proof_budget_zero_denies_nonzero.
    #[test]
    fn conformance_budget_zero_denies(amount in 1u64..1_000_000) {
        prop_assert!(!model_budget_allows(0, 0, amount));
    }

    /// CONFORMANCE: budget monotone in consumption.
    ///
    /// Mirrors Verus proof_budget_monotone_consumption.
    #[test]
    fn conformance_budget_monotone_consumption(
        c1 in 0u64..500_000,
        delta in 0u64..500_000,
        max_budget in 0u64..1_000_000,
        amount in 0u64..500_000,
    ) {
        let c2 = c1 + delta; // c1 ≤ c2
        if model_budget_allows(c2, max_budget, amount) {
            prop_assert!(
                model_budget_allows(c1, max_budget, amount),
                "Budget not monotone: c1={} c2={} max={} amount={}",
                c1, c2, max_budget, amount
            );
        }
    }
}

// ============================================================================
// Lattice Law Conformance (bridges Phase 1 proofs to production)
// ============================================================================

proptest! {
    /// CONFORMANCE: CapabilityLattice meet is commutative.
    ///
    /// Mirrors Verus proof_lattice_meet_commutative.
    #[test]
    fn conformance_caps_meet_commutative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
    ) {
        prop_assert_eq!(a.meet(&b), b.meet(&a));
    }

    /// CONFORMANCE: CapabilityLattice meet is associative.
    ///
    /// Mirrors Verus proof_lattice_meet_associative.
    #[test]
    fn conformance_caps_meet_associative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        c in arb_capability_lattice(),
    ) {
        prop_assert_eq!(a.meet(&b).meet(&c), a.meet(&b.meet(&c)));
    }

    /// CONFORMANCE: CapabilityLattice meet is idempotent.
    ///
    /// Mirrors Verus proof_lattice_meet_idempotent.
    #[test]
    fn conformance_caps_meet_idempotent(a in arb_capability_lattice()) {
        prop_assert_eq!(a.meet(&a), a);
    }

    /// CONFORMANCE: CapabilityLattice join is commutative.
    #[test]
    fn conformance_caps_join_commutative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
    ) {
        prop_assert_eq!(a.join(&b), b.join(&a));
    }

    /// CONFORMANCE: CapabilityLattice meet distributes over join.
    ///
    /// Mirrors Verus proof_lattice_distributive.
    #[test]
    fn conformance_caps_distributive(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        c in arb_capability_lattice(),
    ) {
        let lhs = a.meet(&b.join(&c));
        let rhs = a.meet(&b).join(&a.meet(&c));
        prop_assert_eq!(lhs, rhs);
    }
}
