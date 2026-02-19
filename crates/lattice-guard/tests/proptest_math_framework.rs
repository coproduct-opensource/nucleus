//! Property-based tests for the mathematical framework extensions.
//!
//! These tests verify the algebraic laws for:
//! - Frame and nucleus properties
//! - Heyting algebra adjunction
//! - Graded monad laws

#[cfg(feature = "cel")]
use lattice_guard::constraint::{Constraint, Policy, PolicyContext};
use lattice_guard::{
    frame::{BoundedLattice, Lattice, Nucleus, TrifectaQuotient},
    graded::{Graded, RiskGrade},
    heyting::HeytingAlgebra,
    isolation::{FileIsolation, IsolationLattice, NetworkIsolation, ProcessIsolation},
    CapabilityLattice, CapabilityLevel, Operation, PermissionLattice, TrifectaRisk,
};
use proptest::prelude::*;

// ============================================
// Strategies
// ============================================

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
            |(
                read_files,
                write_files,
                edit_files,
                run_bash,
                glob_search,
                grep_search,
                web_search,
                web_fetch,
                git_commit,
                git_push,
                create_pr,
                manage_pods,
            )| {
                CapabilityLattice {
                    read_files,
                    write_files,
                    edit_files,
                    run_bash,
                    glob_search,
                    grep_search,
                    web_search,
                    web_fetch,
                    git_commit,
                    git_push,
                    create_pr,
                    manage_pods,
                }
            },
        )
}

fn arb_trifecta_risk() -> impl Strategy<Value = TrifectaRisk> {
    prop_oneof![
        Just(TrifectaRisk::None),
        Just(TrifectaRisk::Low),
        Just(TrifectaRisk::Medium),
        Just(TrifectaRisk::Complete),
    ]
}

fn arb_process_isolation() -> impl Strategy<Value = ProcessIsolation> {
    prop_oneof![
        Just(ProcessIsolation::Shared),
        Just(ProcessIsolation::Namespaced),
        Just(ProcessIsolation::MicroVM),
    ]
}

fn arb_file_isolation() -> impl Strategy<Value = FileIsolation> {
    prop_oneof![
        Just(FileIsolation::Unrestricted),
        Just(FileIsolation::Sandboxed),
        Just(FileIsolation::ReadOnly),
        Just(FileIsolation::Ephemeral),
    ]
}

fn arb_network_isolation() -> impl Strategy<Value = NetworkIsolation> {
    prop_oneof![
        Just(NetworkIsolation::Host),
        Just(NetworkIsolation::Namespaced),
        Just(NetworkIsolation::Filtered),
        Just(NetworkIsolation::Airgapped),
    ]
}

fn arb_isolation_lattice() -> impl Strategy<Value = IsolationLattice> {
    (
        arb_process_isolation(),
        arb_file_isolation(),
        arb_network_isolation(),
    )
        .prop_map(|(process, file, network)| IsolationLattice {
            process,
            file,
            network,
        })
}

fn arb_permission_lattice() -> impl Strategy<Value = PermissionLattice> {
    prop_oneof![
        Just(PermissionLattice::permissive()),
        Just(PermissionLattice::restrictive()),
        Just(PermissionLattice::default()),
        Just(PermissionLattice::read_only()),
        Just(PermissionLattice::codegen()),
        Just(PermissionLattice::pr_review()),
        Just(PermissionLattice::fix_issue()),
    ]
}

proptest! {
    // ============================================
    // Frame: Bounded Lattice Laws
    // ============================================

    #[test]
    fn permission_top_is_identity_for_meet(a in arb_permission_lattice()) {
        let top = PermissionLattice::top();
        let result = a.meet(&top);
        // a ∧ ⊤ should have same capabilities as a
        prop_assert_eq!(result.capabilities, a.capabilities);
    }

    #[test]
    fn permission_bottom_is_identity_for_join(a in arb_permission_lattice()) {
        let bottom = PermissionLattice::bottom();
        let result = a.join(&bottom);
        // a ∨ ⊥ should have same capabilities as a
        prop_assert_eq!(result.capabilities, a.capabilities);
    }

    // ============================================
    // Nucleus Laws
    // ============================================

    #[test]
    fn nucleus_is_idempotent(perms in arb_permission_lattice()) {
        let nucleus = TrifectaQuotient::new();
        let once = nucleus.apply(&perms);
        let twice = nucleus.apply(&once);

        // j(j(x)) = j(x)
        prop_assert_eq!(once.capabilities, twice.capabilities);
        prop_assert_eq!(once.obligations, twice.obligations);
    }

    #[test]
    fn nucleus_is_deflationary(perms in arb_permission_lattice()) {
        let nucleus = TrifectaQuotient::new();
        let projected = nucleus.apply(&perms);

        // j(x) ≤ x in terms of capabilities (permissions can only decrease or stay same)
        // and obligations (can only increase or stay same, which is ≤ in obligation ordering)
        prop_assert!(projected.capabilities.leq(&perms.capabilities));
    }

    #[test]
    fn nucleus_preserves_meets(
        a in arb_permission_lattice(),
        b in arb_permission_lattice()
    ) {
        let nucleus = TrifectaQuotient::new();

        // j(a ∧ b) = j(a) ∧ j(b)
        let lhs = nucleus.apply(&a.meet(&b));
        let rhs = nucleus.apply(&a).meet(&nucleus.apply(&b));

        // Check both capabilities AND obligations for full nucleus property
        prop_assert_eq!(lhs.capabilities, rhs.capabilities, "Nucleus must preserve meets (capabilities)");
        prop_assert_eq!(lhs.obligations, rhs.obligations, "Nucleus must preserve meets (obligations)");
    }

    // ============================================
    // Heyting Algebra Laws
    // ============================================

    #[test]
    fn heyting_adjunction(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        c in arb_capability_lattice()
    ) {
        // The key adjunction: (c ∧ a) ≤ b  ⟺  c ≤ (a → b)
        let implication = a.implies(&b);

        let lhs = c.meet(&a).leq(&b);
        let rhs = c.leq(&implication);

        prop_assert_eq!(lhs, rhs, "Heyting adjunction failed for a={:?}, b={:?}, c={:?}", a, b, c);
    }

    #[test]
    fn heyting_identity_implies_top(a in arb_capability_lattice()) {
        // a → a = ⊤
        let result = a.implies(&a);
        prop_assert_eq!(result, CapabilityLattice::top());
    }

    #[test]
    fn heyting_top_implies_identity(a in arb_capability_lattice()) {
        // ⊤ → a = a
        let result = CapabilityLattice::top().implies(&a);
        prop_assert_eq!(result, a);
    }

    #[test]
    fn heyting_bottom_implies_anything(a in arb_capability_lattice()) {
        // ⊥ → a = ⊤ (ex falso quodlibet)
        let result = CapabilityLattice::bottom().implies(&a);
        prop_assert_eq!(result, CapabilityLattice::top());
    }

    // ============================================
    // Graded Monad Laws
    // ============================================

    #[test]
    fn graded_left_identity(a in -1000i32..1000i32, g in arb_trifecta_risk()) {
        // pure(a).and_then(f) = f(a)
        let f = move |x: i32| Graded::new(g, x * 2);

        let lhs = Graded::<TrifectaRisk, _>::pure(a).and_then(f);
        let rhs = f(a);

        prop_assert_eq!(lhs.value, rhs.value);
        prop_assert_eq!(lhs.grade, rhs.grade);
    }

    #[test]
    fn graded_right_identity(a in -1000i32..1000i32, g in arb_trifecta_risk()) {
        // m.and_then(pure) = m
        let m = Graded::new(g, a);
        let result = m.clone().and_then(Graded::pure);

        prop_assert_eq!(result.value, m.value);
        prop_assert_eq!(result.grade, m.grade);
    }

    #[test]
    fn graded_associativity(
        a in -1000i32..1000i32,
        g1 in arb_trifecta_risk(),
        g2 in arb_trifecta_risk(),
        g3 in arb_trifecta_risk()
    ) {
        // (m.and_then(f)).and_then(g) = m.and_then(|x| f(x).and_then(g))
        let m = Graded::new(g1, a);
        let f = move |x: i32| Graded::new(g2, x * 2);
        let g = move |x: i32| Graded::new(g3, x + 1);

        let lhs = m.clone().and_then(f).and_then(g);
        let rhs = m.and_then(|x| f(x).and_then(g));

        prop_assert_eq!(lhs.value, rhs.value);
        prop_assert_eq!(lhs.grade, rhs.grade);
    }

    // ============================================
    // Risk Grade Monoid Laws
    // ============================================

    #[test]
    fn risk_grade_left_identity(g in arb_trifecta_risk()) {
        // identity * g = g
        prop_assert_eq!(TrifectaRisk::identity().compose(&g), g);
    }

    #[test]
    fn risk_grade_right_identity(g in arb_trifecta_risk()) {
        // g * identity = g
        prop_assert_eq!(g.compose(&TrifectaRisk::identity()), g);
    }

    #[test]
    fn risk_grade_associativity(
        a in arb_trifecta_risk(),
        b in arb_trifecta_risk(),
        c in arb_trifecta_risk()
    ) {
        // (a * b) * c = a * (b * c)
        let lhs = a.compose(&b).compose(&c);
        let rhs = a.compose(&b.compose(&c));
        prop_assert_eq!(lhs, rhs);
    }

    // ============================================
    // Lattice Laws for CapabilityLattice (Heyting impl)
    // ============================================

    #[test]
    fn capability_heyting_meet_is_commutative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        prop_assert_eq!(Lattice::meet(&a, &b), Lattice::meet(&b, &a));
    }

    #[test]
    fn capability_heyting_meet_is_associative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        c in arb_capability_lattice()
    ) {
        let ab_c = Lattice::meet(&Lattice::meet(&a, &b), &c);
        let a_bc = Lattice::meet(&a, &Lattice::meet(&b, &c));
        prop_assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn capability_heyting_meet_is_idempotent(a in arb_capability_lattice()) {
        prop_assert_eq!(Lattice::meet(&a, &a), a);
    }

    #[test]
    fn capability_heyting_join_is_commutative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        prop_assert_eq!(Lattice::join(&a, &b), Lattice::join(&b, &a));
    }

    #[test]
    fn capability_heyting_join_is_associative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        c in arb_capability_lattice()
    ) {
        let ab_c = Lattice::join(&Lattice::join(&a, &b), &c);
        let a_bc = Lattice::join(&a, &Lattice::join(&b, &c));
        prop_assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn capability_heyting_join_is_idempotent(a in arb_capability_lattice()) {
        prop_assert_eq!(Lattice::join(&a, &a), a);
    }

    // Absorption laws
    #[test]
    fn capability_heyting_absorption_meet_join(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        // a ∧ (a ∨ b) = a
        let result = Lattice::meet(&a, &Lattice::join(&a, &b));
        prop_assert_eq!(result, a);
    }

    #[test]
    fn capability_heyting_absorption_join_meet(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        // a ∨ (a ∧ b) = a
        let result = Lattice::join(&a, &Lattice::meet(&a, &b));
        prop_assert_eq!(result, a);
    }

    // Distributivity
    #[test]
    fn capability_heyting_distributivity_meet_over_join(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        c in arb_capability_lattice()
    ) {
        // a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c)
        let lhs = Lattice::meet(&a, &Lattice::join(&b, &c));
        let rhs = Lattice::join(&Lattice::meet(&a, &b), &Lattice::meet(&a, &c));
        prop_assert_eq!(lhs, rhs);
    }
}

// ============================================
// Constraint Nucleus Laws (CEL feature)
// ============================================

#[cfg(feature = "cel")]
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

#[cfg(feature = "cel")]
fn arb_policy_context() -> impl Strategy<Value = PolicyContext> {
    (
        arb_operation(),
        arb_capability_lattice(),
        arb_trifecta_risk(),
        0.0f64..=1.0f64,
        prop::bool::ANY,
        0u32..100u32,
        arb_isolation_lattice(),
    )
        .prop_map(|(op, caps, risk, budget, approval, rate, isolation)| {
            PolicyContext::new(op)
                .with_capabilities(caps)
                .with_trifecta_risk(risk)
                .with_budget(budget)
                .with_approval(approval)
                .with_request_rate(rate)
                .with_isolation(isolation)
        })
}

#[cfg(feature = "cel")]
proptest! {
    // ============================================
    // Constraint: Nucleus Laws
    // ============================================

    /// A constraint's evaluate is **idempotent**: once obligations are added,
    /// re-evaluating doesn't change them.
    #[test]
    fn constraint_is_idempotent(ctx in arb_policy_context()) {
        // Use a constraint that always triggers
        let constraint = Constraint::new("always", "true")
            .unwrap()
            .with_obligation(Operation::WriteFiles);

        let once = constraint.evaluate(&ctx).unwrap();
        // Re-evaluate with same context - should get same result
        let twice = constraint.evaluate(&ctx).unwrap();

        prop_assert_eq!(once, twice, "Constraint evaluate must be idempotent");
    }

    /// A constraint is **deflationary**: it can only add obligations, never remove them.
    #[test]
    fn constraint_is_deflationary(ctx in arb_policy_context()) {
        let constraint = Constraint::new("always", "true")
            .unwrap()
            .with_obligation(Operation::WriteFiles);

        let result_obligations = constraint.evaluate(&ctx).unwrap();

        // Deflationary: when condition triggers, obligations are added
        // A "true" condition always triggers, so WriteFiles should always be present
        prop_assert!(
            result_obligations.requires(Operation::WriteFiles),
            "Deflationary constraint must add its obligations when triggered"
        );
    }

    /// A constraint's condition evaluation is **pure**: same input, same output.
    #[test]
    fn constraint_is_pure(ctx in arb_policy_context()) {
        let constraint = Constraint::new("check-op", r#"operation == "write_files""#)
            .unwrap()
            .with_obligation(Operation::WriteFiles);

        let result1 = constraint.evaluate(&ctx).unwrap();
        let result2 = constraint.evaluate(&ctx).unwrap();

        prop_assert_eq!(result1, result2, "Constraint evaluate must be pure");
    }

    /// Policy evaluation accumulates obligations from all constraints.
    #[test]
    fn policy_accumulates_obligations(ctx in arb_policy_context()) {
        let policy = Policy::new("test")
            .with_constraint(
                Constraint::new("c1", "true")
                    .unwrap()
                    .with_obligation(Operation::ReadFiles)
            )
            .with_constraint(
                Constraint::new("c2", "true")
                    .unwrap()
                    .with_obligation(Operation::WriteFiles)
            );

        let obligations = policy.evaluate(&ctx).unwrap();

        // Both obligations should be present
        prop_assert!(obligations.requires(Operation::ReadFiles), "Policy should accumulate ReadFiles");
        prop_assert!(obligations.requires(Operation::WriteFiles), "Policy should accumulate WriteFiles");
    }

    /// Policy evaluation is idempotent: evaluating twice gives same result.
    #[test]
    fn policy_is_idempotent(ctx in arb_policy_context()) {
        let policy = Policy::new("test")
            .with_constraint(
                Constraint::new("c1", "true")
                    .unwrap()
                    .with_obligation(Operation::GitPush)
            );

        let once = policy.evaluate(&ctx).unwrap();
        let twice = policy.evaluate(&ctx).unwrap();

        prop_assert_eq!(once, twice, "Policy evaluate must be idempotent");
    }

    /// Trifecta detection: when all three trifecta capabilities are present,
    /// exfiltration operations should require approval.
    #[test]
    fn trifecta_adds_obligations_when_complete(
        op in arb_operation(),
        budget in 0.0f64..=1.0f64
    ) {
        // Full trifecta: read + web + push
        let caps = CapabilityLattice {
            read_files: CapabilityLevel::Always,
            web_fetch: CapabilityLevel::LowRisk,
            git_push: CapabilityLevel::LowRisk,
            ..Default::default()
        };

        let ctx = PolicyContext::new(op)
            .with_capabilities(caps)
            .with_trifecta_risk(TrifectaRisk::Complete)
            .with_budget(budget);

        // Default policy enforces trifecta
        let policy = Policy::new("secure");
        let obligations = policy.evaluate(&ctx).unwrap();

        // With full trifecta, git_push should require approval
        prop_assert!(
            obligations.requires(Operation::GitPush),
            "Full trifecta should require approval for git_push"
        );
    }
}

// ============================================
// Isolation Lattice Laws
// ============================================

proptest! {
    // ============================================
    // Meet Laws
    // ============================================

    #[test]
    fn isolation_meet_is_commutative(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice()
    ) {
        prop_assert_eq!(a.meet(&b), b.meet(&a));
    }

    #[test]
    fn isolation_meet_is_associative(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice(),
        c in arb_isolation_lattice()
    ) {
        let ab_c = a.meet(&b).meet(&c);
        let a_bc = a.meet(&b.meet(&c));
        prop_assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn isolation_meet_is_idempotent(a in arb_isolation_lattice()) {
        prop_assert_eq!(a.meet(&a), a);
    }

    // ============================================
    // Join Laws
    // ============================================

    #[test]
    fn isolation_join_is_commutative(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice()
    ) {
        prop_assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn isolation_join_is_associative(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice(),
        c in arb_isolation_lattice()
    ) {
        let ab_c = a.join(&b).join(&c);
        let a_bc = a.join(&b.join(&c));
        prop_assert_eq!(ab_c, a_bc);
    }

    #[test]
    fn isolation_join_is_idempotent(a in arb_isolation_lattice()) {
        prop_assert_eq!(a.join(&a), a);
    }

    // ============================================
    // Absorption Laws
    // ============================================

    #[test]
    fn isolation_absorption_meet_join(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice()
    ) {
        // a ∧ (a ∨ b) = a
        let result = a.meet(&a.join(&b));
        prop_assert_eq!(result, a);
    }

    #[test]
    fn isolation_absorption_join_meet(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice()
    ) {
        // a ∨ (a ∧ b) = a
        let result = a.join(&a.meet(&b));
        prop_assert_eq!(result, a);
    }

    // ============================================
    // Bounded Lattice Laws
    // ============================================

    #[test]
    fn isolation_top_is_identity_for_meet(a in arb_isolation_lattice()) {
        let top = IsolationLattice::top();
        // a ∧ ⊤ = a
        prop_assert_eq!(a.meet(&top), a);
    }

    #[test]
    fn isolation_bottom_is_identity_for_join(a in arb_isolation_lattice()) {
        let bottom = IsolationLattice::bottom();
        // a ∨ ⊥ = a
        prop_assert_eq!(a.join(&bottom), a);
    }

    #[test]
    fn isolation_top_is_annihilator_for_join(a in arb_isolation_lattice()) {
        let top = IsolationLattice::top();
        // a ∨ ⊤ = ⊤
        prop_assert_eq!(a.join(&top), top);
    }

    #[test]
    fn isolation_bottom_is_annihilator_for_meet(a in arb_isolation_lattice()) {
        let bottom = IsolationLattice::bottom();
        // a ∧ ⊥ = ⊥
        prop_assert_eq!(a.meet(&bottom), bottom);
    }

    // ============================================
    // Partial Order Laws
    // ============================================

    #[test]
    fn isolation_leq_is_reflexive(a in arb_isolation_lattice()) {
        prop_assert!(a.leq(&a));
    }

    #[test]
    fn isolation_leq_is_antisymmetric(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice()
    ) {
        // If a ≤ b and b ≤ a, then a = b
        if a.leq(&b) && b.leq(&a) {
            prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn isolation_leq_is_transitive(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice(),
        c in arb_isolation_lattice()
    ) {
        // If a ≤ b and b ≤ c, then a ≤ c
        if a.leq(&b) && b.leq(&c) {
            prop_assert!(a.leq(&c));
        }
    }

    // ============================================
    // Lattice-Order Connection
    // ============================================

    #[test]
    fn isolation_meet_gives_lower_bound(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice()
    ) {
        let meet = a.meet(&b);
        // a ∧ b ≤ a and a ∧ b ≤ b
        prop_assert!(meet.leq(&a), "meet should be ≤ first operand");
        prop_assert!(meet.leq(&b), "meet should be ≤ second operand");
    }

    #[test]
    fn isolation_join_gives_upper_bound(
        a in arb_isolation_lattice(),
        b in arb_isolation_lattice()
    ) {
        let join = a.join(&b);
        // a ≤ a ∨ b and b ≤ a ∨ b
        prop_assert!(a.leq(&join), "first operand should be ≤ join");
        prop_assert!(b.leq(&join), "second operand should be ≤ join");
    }
}
