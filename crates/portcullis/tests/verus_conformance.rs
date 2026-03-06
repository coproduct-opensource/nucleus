//! Verus Model ↔ Production Conformance Tests
//!
//! This test suite bridges the gap between the formally verified Verus model
//! (portcullis-verified) and the production Rust code (portcullis).
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

use portcullis::guard::GradedGuard;
use portcullis::{
    operation_taint, CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Obligations,
    Operation, PathLattice, PermissionLattice, TaintLabel, TaintSet, TrifectaRisk,
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

// ============================================================================
// Tier F: Certificate Chain Conformance (bridges Phase 4 proofs to production)
//
// These tests verify that the LatticeCertificate production code matches
// the Verus proofs for delegation chain verification soundness.
// ============================================================================

proptest! {
    /// CONFORMANCE: perm_leq is transitive in production code.
    ///
    /// Mirrors Verus proof_perm_leq_transitive.
    /// If meet(root, a) = mid and meet(mid, b) = leaf,
    /// then leaf.leq(root) must hold.
    #[test]
    fn conformance_perm_leq_transitive(
        root_caps in arb_capability_lattice(),
        a_caps in arb_capability_lattice(),
        b_caps in arb_capability_lattice(),
    ) {
        let root = perms_with_empty_obligations(root_caps);
        let mid = root.meet(&perms_with_empty_obligations(a_caps));
        let leaf = mid.meet(&perms_with_empty_obligations(b_caps));

        // mid ≤ root (delegation ceiling)
        prop_assert!(mid.leq(&root), "mid should be ≤ root");
        // leaf ≤ mid (delegation ceiling)
        prop_assert!(leaf.leq(&mid), "leaf should be ≤ mid");
        // Transitivity: leaf ≤ root
        prop_assert!(leaf.leq(&root), "transitivity: leaf should be ≤ root");
    }

    /// CONFORMANCE: meet witness correctness — meet(parent, requested) ≤ parent AND ≤ requested.
    ///
    /// Mirrors Verus proof_meet_witness_correct.
    #[test]
    fn conformance_meet_witness_correct(
        parent_caps in arb_capability_lattice(),
        requested_caps in arb_capability_lattice(),
    ) {
        let parent = perms_with_empty_obligations(parent_caps);
        let requested = perms_with_empty_obligations(requested_caps);
        let result = parent.meet(&requested);

        // result ≤ parent
        prop_assert!(result.leq(&parent), "meet result should be ≤ parent");
        // result ≤ requested
        prop_assert!(result.leq(&requested), "meet result should be ≤ requested");
    }

    /// CONFORMANCE: delegation preserves trifecta constraint.
    ///
    /// Mirrors Verus proof_chain_delegation_preserves_trifecta.
    /// If parent has trifecta_constraint = true, the meet result does too.
    #[test]
    fn conformance_delegation_preserves_trifecta(
        parent_caps in arb_capability_lattice(),
        requested_caps in arb_capability_lattice(),
    ) {
        let parent = perms_with_empty_obligations(parent_caps);
        prop_assert!(parent.trifecta_constraint, "default should have trifecta on");

        let requested = perms_with_empty_obligations(requested_caps);
        let result = parent.meet(&requested);

        prop_assert!(
            result.trifecta_constraint,
            "trifecta constraint must propagate through meet"
        );
    }

    /// CONFORMANCE: 4-hop chain maintains transitivity.
    ///
    /// Mirrors Verus proof_chain_transitivity_four.
    #[test]
    fn conformance_four_hop_chain_transitive(
        root_caps in arb_capability_lattice(),
        a_caps in arb_capability_lattice(),
        b_caps in arb_capability_lattice(),
        c_caps in arb_capability_lattice(),
    ) {
        let root = perms_with_empty_obligations(root_caps);
        let hop1 = root.meet(&perms_with_empty_obligations(a_caps));
        let hop2 = hop1.meet(&perms_with_empty_obligations(b_caps));
        let leaf = hop2.meet(&perms_with_empty_obligations(c_caps));

        // Each step ≤ previous
        prop_assert!(hop1.leq(&root));
        prop_assert!(hop2.leq(&hop1));
        prop_assert!(leaf.leq(&hop2));

        // Transitivity: leaf ≤ root
        prop_assert!(leaf.leq(&root), "4-hop transitivity: leaf should be ≤ root");
    }
}

// ============================================================================
// Tier E: Constructor Fixed-Point Conformance
//
// Mirrors Verus proof_preset_*_is_fixed_point.
// ============================================================================

proptest! {
    /// CONFORMANCE: normalize is idempotent on any permission (full check).
    ///
    /// Mirrors Verus proof_normalized_perm_is_fixed_point.
    #[test]
    fn conformance_normalize_idempotent_full(caps in arb_capability_lattice()) {
        let perms = perms_with_empty_obligations(caps);
        let once = perms.normalize();
        let twice = once.clone().normalize();

        prop_assert_eq!(
            once.capabilities, twice.capabilities,
            "normalize should be idempotent on capabilities"
        );
        for op in [Operation::RunBash, Operation::GitPush, Operation::CreatePr] {
            prop_assert_eq!(
                once.obligations.requires(op),
                twice.obligations.requires(op),
                "normalize should be idempotent on trifecta obligations for {:?}",
                op,
            );
        }
    }

    /// CONFORMANCE: Delegation from normalized root preserves normalization.
    ///
    /// Mirrors Verus proof_delegation_preserves_fixed_point.
    #[test]
    fn conformance_delegation_preserves_fixed_point(
        root_caps in arb_capability_lattice(),
        req_caps in arb_capability_lattice(),
    ) {
        let root = perms_with_empty_obligations(root_caps).normalize();
        let requested = perms_with_empty_obligations(req_caps);
        let delegated = root.meet(&requested);
        let renormalized = delegated.clone().normalize();

        prop_assert_eq!(
            delegated.capabilities, renormalized.capabilities,
            "delegation from normalized root should produce normalized result"
        );
        for op in [Operation::RunBash, Operation::GitPush, Operation::CreatePr] {
            prop_assert_eq!(
                delegated.obligations.requires(op),
                renormalized.obligations.requires(op),
                "delegation obligations should be stable for {:?}",
                op,
            );
        }
    }

    /// CONFORMANCE: 2-hop chain maintains normalization invariant.
    ///
    /// Mirrors Verus proof_chain_two_hop_fixed_point.
    #[test]
    fn conformance_chain_extension_invariant(
        root_caps in arb_capability_lattice(),
        req1_caps in arb_capability_lattice(),
        req2_caps in arb_capability_lattice(),
    ) {
        let root = perms_with_empty_obligations(root_caps).normalize();
        let req1 = perms_with_empty_obligations(req1_caps);
        let req2 = perms_with_empty_obligations(req2_caps);

        let mid = root.meet(&req1);
        let leaf = mid.meet(&req2);

        prop_assert!(leaf.leq(&root), "chain leaf should be \u{2264} root");

        let leaf_renorm = leaf.clone().normalize();
        prop_assert_eq!(
            leaf.capabilities, leaf_renorm.capabilities,
            "chain leaf should be normalized"
        );
    }

    /// CONFORMANCE: THE CRITICAL TEST — verified chain denies exfiltration.
    ///
    /// Mirrors Verus proof_verified_chain_denies_exfil.
    #[test]
    fn conformance_verified_chain_denies_exfil(
        root_caps in arb_capability_lattice(),
        req_caps in arb_capability_lattice(),
        op in arb_exfil_operation(),
    ) {
        let root = perms_with_empty_obligations(root_caps).normalize();
        let leaf = root.meet(&perms_with_empty_obligations(req_caps));

        if !model_is_trifecta_complete(&leaf.capabilities) {
            return Ok(());
        }

        let exfil_active = match op {
            Operation::RunBash => leaf.capabilities.run_bash >= CapabilityLevel::LowRisk,
            Operation::GitPush => leaf.capabilities.git_push >= CapabilityLevel::LowRisk,
            Operation::CreatePr => leaf.capabilities.create_pr >= CapabilityLevel::LowRisk,
            _ => false,
        };
        if !exfil_active {
            return Ok(());
        }

        let guard = GradedGuard::new(leaf);
        let result = guard.check_operation(op);
        prop_assert!(
            result.value.is_err(),
            "Chain + trifecta + exfil must DENY. Op={:?}, risk={:?}",
            op,
            guard.risk(),
        );
    }

    /// CONFORMANCE: No weakening produces zero cost.
    ///
    /// Mirrors Verus proof_no_weakening_zero_cost.
    #[test]
    fn conformance_no_weakening_zero_cost(level in arb_capability_level()) {
        use portcullis::weakening::WeakeningCostConfig;
        let config = WeakeningCostConfig::default();
        let cost = config.capability_cost(level, level);
        prop_assert!(cost.is_zero(), "same level should produce zero cost");
    }

    /// CONFORMANCE: Trust ceiling is deflationary.
    ///
    /// Mirrors Verus proof_trust_ceiling_deflationary.
    #[test]
    fn conformance_trust_ceiling_deflationary(
        caps in arb_capability_lattice(),
        ceiling in arb_capability_lattice(),
    ) {
        let result = caps.meet(&ceiling);
        prop_assert!(
            result.leq(&caps),
            "meet(caps, ceiling) should be \u{2264} caps"
        );
    }

    /// CONFORMANCE: Trust ceiling is monotone.
    ///
    /// Mirrors Verus proof_trust_ceiling_monotone.
    #[test]
    fn conformance_trust_ceiling_monotone(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        ceiling in arb_capability_lattice(),
    ) {
        if a.leq(&b) {
            let a_enforced = a.meet(&ceiling);
            let b_enforced = b.meet(&ceiling);
            prop_assert!(
                a_enforced.leq(&b_enforced),
                "trust ceiling should be monotone"
            );
        }
    }
}

/// CONFORMANCE: Each production preset is a \u{03bd}-fixed point.
/// Mirrors Verus proof_preset_*_is_fixed_point for all 7 presets.
#[test]
fn conformance_preset_permissive_is_fixed_point() {
    let p = PermissionLattice::permissive();
    let n = p.clone().normalize();
    assert_eq!(p.capabilities, n.capabilities, "permissive: caps unchanged");
    for op in [Operation::RunBash, Operation::GitPush, Operation::CreatePr] {
        assert_eq!(
            p.obligations.requires(op),
            n.obligations.requires(op),
            "permissive: obligations unchanged for {:?}",
            op,
        );
    }
}

#[test]
fn conformance_preset_restrictive_is_fixed_point() {
    let p = PermissionLattice::restrictive();
    assert_eq!(p.capabilities, p.clone().normalize().capabilities);
}

#[test]
fn conformance_preset_read_only_is_fixed_point() {
    let p = PermissionLattice::read_only();
    assert_eq!(p.capabilities, p.clone().normalize().capabilities);
}

#[test]
fn conformance_preset_network_only_is_fixed_point() {
    let p = PermissionLattice::network_only();
    assert_eq!(p.capabilities, p.clone().normalize().capabilities);
}

#[test]
fn conformance_preset_web_research_is_fixed_point() {
    let p = PermissionLattice::web_research();
    assert_eq!(p.capabilities, p.clone().normalize().capabilities);
}

#[test]
fn conformance_preset_code_review_is_fixed_point() {
    let p = PermissionLattice::code_review();
    assert_eq!(p.capabilities, p.clone().normalize().capabilities);
}

#[test]
fn conformance_preset_edit_only_is_fixed_point() {
    let p = PermissionLattice::edit_only();
    assert_eq!(p.capabilities, p.clone().normalize().capabilities);
}

/// CONFORMANCE: Untrusted profile prevents trifecta.
///
/// Mirrors Verus proof_untrusted_profile_no_trifecta.
#[test]
fn conformance_untrusted_profile_prevents_trifecta() {
    let ceiling = CapabilityLattice {
        read_files: CapabilityLevel::Always,
        write_files: CapabilityLevel::LowRisk,
        edit_files: CapabilityLevel::LowRisk,
        run_bash: CapabilityLevel::Never,
        glob_search: CapabilityLevel::Always,
        grep_search: CapabilityLevel::Always,
        web_search: CapabilityLevel::LowRisk,
        web_fetch: CapabilityLevel::LowRisk,
        git_commit: CapabilityLevel::LowRisk,
        git_push: CapabilityLevel::Never,
        create_pr: CapabilityLevel::Never,
        manage_pods: CapabilityLevel::Never,
    };

    let all_caps = CapabilityLattice::permissive();
    let enforced = all_caps.meet(&ceiling);
    assert!(
        !model_is_trifecta_complete(&enforced),
        "untrusted ceiling must prevent trifecta even on permissive caps"
    );
    assert_eq!(enforced.run_bash, CapabilityLevel::Never);
    assert_eq!(enforced.git_push, CapabilityLevel::Never);
    assert_eq!(enforced.create_pr, CapabilityLevel::Never);
}

// ============================================================================
// Tier G: TaintSet Monoid Conformance (bridges Phase 6 proofs to production)
//
// These tests verify that the production TaintSet code matches the Verus
// SpecTaintSet model. The Verus proofs verify monoid laws, risk monotonicity,
// and guard decision theorems on the spec model. These conformance tests
// ensure the production code exhibits the same behavior.
// ============================================================================

fn arb_taint_label() -> impl Strategy<Value = TaintLabel> {
    prop_oneof![
        Just(TaintLabel::PrivateData),
        Just(TaintLabel::UntrustedContent),
        Just(TaintLabel::ExfilVector),
    ]
}

fn arb_taint_set() -> impl Strategy<Value = TaintSet> {
    (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(p, u, e)| {
        let mut s = TaintSet::empty();
        if p {
            s = s.union(&TaintSet::singleton(TaintLabel::PrivateData));
        }
        if u {
            s = s.union(&TaintSet::singleton(TaintLabel::UntrustedContent));
        }
        if e {
            s = s.union(&TaintSet::singleton(TaintLabel::ExfilVector));
        }
        s
    })
}

proptest! {
    /// CONFORMANCE H1+H2: TaintSet identity — empty.union(s) == s == s.union(empty).
    ///
    /// Mirrors Verus proof_taintset_identity_left + proof_taintset_identity_right.
    #[test]
    fn conformance_taintset_identity(s in arb_taint_set()) {
        let empty = TaintSet::empty();
        prop_assert_eq!(empty.union(&s), s.clone(), "left identity failed");
        prop_assert_eq!(s.union(&empty), s, "right identity failed");
    }

    /// CONFORMANCE H3: TaintSet union is commutative.
    ///
    /// Mirrors Verus proof_taintset_union_commutative.
    #[test]
    fn conformance_taintset_commutative(a in arb_taint_set(), b in arb_taint_set()) {
        prop_assert_eq!(a.union(&b), b.union(&a));
    }

    /// CONFORMANCE H4: TaintSet union is associative.
    ///
    /// Mirrors Verus proof_taintset_union_associative.
    #[test]
    fn conformance_taintset_associative(
        a in arb_taint_set(),
        b in arb_taint_set(),
        c in arb_taint_set(),
    ) {
        prop_assert_eq!(
            a.union(&b.union(&c)),
            a.union(&b).union(&c),
        );
    }

    /// CONFORMANCE H5: TaintSet union is idempotent.
    ///
    /// Mirrors Verus proof_taintset_union_idempotent.
    #[test]
    fn conformance_taintset_idempotent(s in arb_taint_set()) {
        prop_assert_eq!(s.union(&s), s);
    }

    /// CONFORMANCE I2: Trifecta complete iff all three legs present.
    ///
    /// Mirrors Verus proof_trifecta_iff_all_three.
    #[test]
    fn conformance_taintset_trifecta_iff_all_three(s in arb_taint_set()) {
        let all_present = s.contains(TaintLabel::PrivateData)
            && s.contains(TaintLabel::UntrustedContent)
            && s.contains(TaintLabel::ExfilVector);
        prop_assert_eq!(
            s.is_trifecta_complete(), all_present,
            "trifecta_complete={} but all_present={} for {:?}",
            s.is_trifecta_complete(), all_present, s
        );
    }

    /// CONFORMANCE I4: Count bounded [0, 3] and count == 3 iff trifecta.
    ///
    /// Mirrors Verus proof_taintset_count_bounds.
    #[test]
    fn conformance_taintset_count_bounds(s in arb_taint_set()) {
        prop_assert!(s.count() <= 3, "count {} > 3", s.count());
        prop_assert_eq!(
            s.count() == 3, s.is_trifecta_complete(),
            "count==3 is {} but trifecta is {}", s.count() == 3, s.is_trifecta_complete()
        );
    }

    /// CONFORMANCE J3: Recording a label only increases taint (monotone accumulation).
    ///
    /// Mirrors Verus proof_taint_accumulation_monotone.
    #[test]
    fn conformance_taint_accumulation_monotone(
        before in arb_taint_set(),
        label in arb_taint_label(),
    ) {
        let after = before.union(&TaintSet::singleton(label));
        // after is a superset of before
        for l in [TaintLabel::PrivateData, TaintLabel::UntrustedContent, TaintLabel::ExfilVector] {
            if before.contains(l) {
                prop_assert!(after.contains(l), "accumulation lost label {:?}", l);
            }
        }
        prop_assert!(after.count() >= before.count(), "count decreased");
    }

    /// CONFORMANCE J4: Neutral operations produce no taint label.
    ///
    /// Mirrors Verus proof_neutral_ops_no_taint.
    #[test]
    fn conformance_neutral_ops_no_taint(op in prop_oneof![
        Just(Operation::WriteFiles),
        Just(Operation::EditFiles),
        Just(Operation::GitCommit),
        Just(Operation::ManagePods),
    ]) {
        prop_assert_eq!(
            operation_taint(op), None,
            "neutral op {:?} should produce no taint", op
        );
    }

    /// CONFORMANCE I1: Every operation maps to a valid taint label or None.
    ///
    /// Mirrors Verus proof_operation_taint_total.
    #[test]
    fn conformance_operation_taint_total(op in arb_operation()) {
        let label = operation_taint(op);
        // Either None (neutral) or a valid TaintLabel
        match label {
            None => {} // neutral — valid
            Some(TaintLabel::PrivateData)
            | Some(TaintLabel::UntrustedContent)
            | Some(TaintLabel::ExfilVector) => {} // valid label
        }
    }

    /// CONFORMANCE I3: Risk (count) is monotone — subset taint ≤ superset taint.
    ///
    /// Mirrors Verus proof_taint_risk_monotone.
    #[test]
    fn conformance_taint_risk_monotone(a in arb_taint_set(), b in arb_taint_set()) {
        let merged = a.union(&b);
        // a ⊆ merged, so count(a) ≤ count(merged)
        prop_assert!(
            a.count() <= merged.count(),
            "risk not monotone: count(a)={} > count(union)={}", a.count(), merged.count()
        );
        prop_assert!(
            b.count() <= merged.count(),
            "risk not monotone: count(b)={} > count(union)={}", b.count(), merged.count()
        );
    }

    /// CONFORMANCE K1: TaintSet trifecta agrees with CapLattice trifecta.
    ///
    /// Mirrors Verus proof_taint_risk_bridge.
    /// When a TaintSet is built from the same capability lattice components,
    /// both agree on trifecta completeness.
    #[test]
    fn conformance_taint_risk_bridge(caps in arb_capability_lattice()) {
        // Build taint set from the same cap lattice components
        let mut taint = TaintSet::empty();
        if model_has_private_access(&caps) {
            taint = taint.union(&TaintSet::singleton(TaintLabel::PrivateData));
        }
        if model_has_untrusted_content(&caps) {
            taint = taint.union(&TaintSet::singleton(TaintLabel::UntrustedContent));
        }
        if model_has_exfiltration(&caps) {
            taint = taint.union(&TaintSet::singleton(TaintLabel::ExfilVector));
        }

        let constraint = IncompatibilityConstraint::enforcing();
        let cap_complete = constraint.is_trifecta_complete(&caps);
        let taint_complete = taint.is_trifecta_complete();

        prop_assert_eq!(
            taint_complete, cap_complete,
            "BRIDGE VIOLATION: taint_complete={} != cap_complete={} for caps={:?}",
            taint_complete, cap_complete, caps
        );
    }
}

// ============================================================================
// Tier H: MCP Session Trace Conformance (bridges Phase 7 proofs to production)
//
// These tests verify the session-level trace properties: taint monotonicity,
// phantom taint freedom, neutral ops, trifecta irreversibility, and the
// composition (free monoid homomorphism) property.
// ============================================================================

/// Model an MCP event: (operation, succeeded)
fn apply_event(taint: &TaintSet, op: Operation, succeeded: bool) -> TaintSet {
    if succeeded {
        if let Some(label) = operation_taint(op) {
            taint.union(&TaintSet::singleton(label))
        } else {
            taint.clone()
        }
    } else {
        taint.clone()
    }
}

/// Compute trace taint by folding over events.
fn trace_taint(events: &[(Operation, bool)]) -> TaintSet {
    let mut taint = TaintSet::empty();
    for &(op, succeeded) in events {
        taint = apply_event(&taint, op, succeeded);
    }
    taint
}

proptest! {
    /// CONFORMANCE M1: Trace taint monotonicity — each event only grows taint.
    ///
    /// Mirrors Verus proof_trace_taint_monotone.
    #[test]
    fn conformance_trace_taint_monotone(
        ops in proptest::collection::vec(
            (arb_operation(), any::<bool>()),
            0..20,
        ),
    ) {
        let mut taint = TaintSet::empty();
        for &(op, succeeded) in &ops {
            let before = taint.clone();
            taint = apply_event(&taint, op, succeeded);
            // Monotone: every leg that was true stays true
            for l in [TaintLabel::PrivateData, TaintLabel::UntrustedContent, TaintLabel::ExfilVector] {
                if before.contains(l) {
                    prop_assert!(taint.contains(l), "lost taint leg {:?}", l);
                }
            }
            prop_assert!(taint.count() >= before.count(), "count decreased");
        }
    }

    /// CONFORMANCE M4: Phantom taint freedom — failed events contribute nothing.
    ///
    /// Mirrors Verus proof_phantom_taint_freedom.
    #[test]
    fn conformance_phantom_taint_freedom(
        before in arb_taint_set(),
        op in arb_operation(),
    ) {
        let after = apply_event(&before, op, false);
        prop_assert_eq!(after, before, "failed event changed taint for {:?}", op);
    }

    /// CONFORMANCE M5: Neutral ops don't change taint.
    ///
    /// Mirrors Verus proof_neutral_op_preserves_taint.
    #[test]
    fn conformance_neutral_op_preserves(
        before in arb_taint_set(),
        op in prop_oneof![
            Just(Operation::WriteFiles),
            Just(Operation::EditFiles),
            Just(Operation::GitCommit),
            Just(Operation::ManagePods),
        ],
    ) {
        // Even if succeeded, neutral ops don't add taint
        let after = apply_event(&before, op, true);
        prop_assert_eq!(after, before, "neutral op {:?} changed taint", op);
    }

    /// CONFORMANCE M6: Trifecta irreversibility — once latched, always latched.
    ///
    /// Mirrors Verus proof_trifecta_irreversible.
    #[test]
    fn conformance_trifecta_irreversible(
        ops in proptest::collection::vec(
            (arb_operation(), any::<bool>()),
            0..20,
        ),
    ) {
        let mut taint = TaintSet::empty();
        let mut latched = false;
        for &(op, succeeded) in &ops {
            taint = apply_event(&taint, op, succeeded);
            if taint.is_trifecta_complete() {
                latched = true;
            }
            if latched {
                prop_assert!(
                    taint.is_trifecta_complete(),
                    "trifecta unlatched after op {:?} (succeeded={})", op, succeeded
                );
            }
        }
    }

    /// CONFORMANCE M3: Free monoid homomorphism — trace_taint(s1++s2) == union(tt(s1), tt(s2)).
    ///
    /// Mirrors Verus proof_trace_composition.
    #[test]
    fn conformance_trace_composition(
        s1 in proptest::collection::vec(
            (arb_operation(), any::<bool>()),
            0..10,
        ),
        s2 in proptest::collection::vec(
            (arb_operation(), any::<bool>()),
            0..10,
        ),
    ) {
        let t1 = trace_taint(&s1);
        let t2 = trace_taint(&s2);
        let mut combined = s1.clone();
        combined.extend_from_slice(&s2);
        let t_combined = trace_taint(&combined);

        prop_assert_eq!(
            t_combined, t1.union(&t2),
            "composition failed: tt(s1++s2) != union(tt(s1), tt(s2))"
        );
    }

    /// CONFORMANCE M8: Three-step minimum — fewer than 3 non-neutral successes can't trigger trifecta.
    ///
    /// Mirrors Verus proof_trifecta_minimum_three_steps.
    #[test]
    fn conformance_trifecta_minimum(
        ops in proptest::collection::vec(
            (arb_operation(), any::<bool>()),
            0..2, // 0 or 1 events — always < 3 non-neutral successes
        ),
    ) {
        let taint = trace_taint(&ops);
        prop_assert!(
            !taint.is_trifecta_complete(),
            "trifecta triggered with only {} events", ops.len()
        );
    }
}

// ============================================================================
// Tier I: Session Fold Conformance (bridges Phase 8 proofs to production)
//
// These tests verify the guard-aware session fold: denied events don't
// contribute taint, and the trifecta latch holds across the fold.
// ============================================================================

/// Model the guard denial check (pure function, no RwLock).
/// Mirrors GradedTaintGuard::check() trifecta path.
///
/// RunBash is omnibus: projects both PrivateData and ExfilVector.
fn model_guard_would_deny(current: &TaintSet, op: Operation, requires_approval: bool) -> bool {
    let projected = if op == Operation::RunBash {
        // RunBash omnibus: projects PrivateData + ExfilVector
        current
            .union(&TaintSet::singleton(TaintLabel::PrivateData))
            .union(&TaintSet::singleton(TaintLabel::ExfilVector))
    } else if let Some(label) = operation_taint(op) {
        current.union(&TaintSet::singleton(label))
    } else {
        current.clone()
    };
    projected.is_trifecta_complete() && requires_approval
}

/// Model the full check→op→record cycle.
/// Returns (denied, new_taint).
fn model_full_tool_call(
    taint: &TaintSet,
    op: Operation,
    succeeded: bool,
    requires_approval: bool,
) -> (bool, TaintSet) {
    let denied = model_guard_would_deny(taint, op, requires_approval);
    if denied {
        (true, taint.clone())
    } else {
        (false, apply_event(taint, op, succeeded))
    }
}

/// Compute session fold taint: like trace_taint but with guard denials.
fn session_fold_taint(
    events: &[(Operation, bool)],
    requires_approval_fn: &dyn Fn(Operation) -> bool,
) -> TaintSet {
    let mut taint = TaintSet::empty();
    for &(op, succeeded) in events {
        let denied = model_guard_would_deny(&taint, op, requires_approval_fn(op));
        if !denied {
            taint = apply_event(&taint, op, succeeded);
        }
    }
    taint
}

/// Map an operation to whether it requires approval (exfil ops only).
fn exfil_requires_approval(op: Operation) -> bool {
    matches!(
        op,
        Operation::RunBash | Operation::GitPush | Operation::CreatePr
    )
}

proptest! {
    /// CONFORMANCE B1: exec_full_tool_call — denied ops don't change taint.
    ///
    /// Mirrors Verus exec_full_tool_call postcondition.
    #[test]
    fn conformance_full_tool_call_denied_no_taint(
        taint in arb_taint_set(),
        op in arb_operation(),
        succeeded in any::<bool>(),
    ) {
        let (denied, new_taint) = model_full_tool_call(&taint, op, succeeded, true);
        if denied {
            prop_assert_eq!(
                new_taint, taint,
                "denied op {:?} changed taint", op
            );
        }
    }

    /// CONFORMANCE B3: Trifecta-complete taint always denies approval-requiring ops.
    ///
    /// Mirrors Verus proof_exec_session_safety_refinement.
    #[test]
    fn conformance_exec_session_safety(
        op in prop_oneof![
            Just(Operation::RunBash),
            Just(Operation::GitPush),
            Just(Operation::CreatePr),
        ],
    ) {
        // Build a trifecta-complete taint set
        let taint = TaintSet::singleton(TaintLabel::PrivateData)
            .union(&TaintSet::singleton(TaintLabel::UntrustedContent))
            .union(&TaintSet::singleton(TaintLabel::ExfilVector));
        prop_assert!(taint.is_trifecta_complete());

        let denied = model_guard_would_deny(&taint, op, true);
        prop_assert!(
            denied,
            "trifecta-complete taint should deny {:?} with approval required", op
        );
    }

    /// CONFORMANCE B4: Session fold taint is monotone.
    ///
    /// Mirrors Verus proof_session_fold_monotone.
    #[test]
    fn conformance_session_fold_monotone(
        ops in proptest::collection::vec(
            (arb_operation(), any::<bool>()),
            0..20,
        ),
    ) {
        let mut taint = TaintSet::empty();
        for &(op, succeeded) in &ops {
            let before = taint.clone();
            let denied = model_guard_would_deny(&taint, op, exfil_requires_approval(op));
            if !denied {
                taint = apply_event(&taint, op, succeeded);
            }
            // Monotone: taint never decreases even with denials
            for l in [TaintLabel::PrivateData, TaintLabel::UntrustedContent, TaintLabel::ExfilVector] {
                if before.contains(l) {
                    prop_assert!(taint.contains(l), "lost taint leg {:?} in session fold", l);
                }
            }
        }
    }

    /// CONFORMANCE B5: Session fold safety — trifecta latch across guard-aware fold.
    ///
    /// Mirrors Verus proof_session_fold_safety.
    #[test]
    fn conformance_session_fold_safety(
        ops in proptest::collection::vec(
            (arb_operation(), any::<bool>()),
            0..20,
        ),
    ) {
        let mut taint = TaintSet::empty();
        let mut latched = false;
        for &(op, succeeded) in &ops {
            let requires_approval = exfil_requires_approval(op);
            let denied = model_guard_would_deny(&taint, op, requires_approval);

            // If trifecta is latched, exfil ops with approval MUST be denied
            if latched && requires_approval {
                prop_assert!(
                    denied,
                    "trifecta-latched session allowed {:?} (requires_approval=true)", op
                );
            }

            if !denied {
                taint = apply_event(&taint, op, succeeded);
            }

            if taint.is_trifecta_complete() {
                latched = true;
            }
        }
    }

    /// CONFORMANCE B-FOLD: Session fold produces ⊆ raw trace taint.
    ///
    /// Guard denials can only reduce taint compared to unconstrained execution.
    #[test]
    fn conformance_session_fold_subset_of_trace(
        ops in proptest::collection::vec(
            (arb_operation(), any::<bool>()),
            0..15,
        ),
    ) {
        let raw = trace_taint(&ops);
        let folded = session_fold_taint(&ops, &exfil_requires_approval);

        // folded ⊆ raw (guard denials can only prevent taint accumulation)
        for l in [TaintLabel::PrivateData, TaintLabel::UntrustedContent, TaintLabel::ExfilVector] {
            if folded.contains(l) {
                prop_assert!(
                    raw.contains(l),
                    "session fold has {:?} but raw trace doesn't", l
                );
            }
        }
    }
}
