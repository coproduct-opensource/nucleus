//! Property-based tests for the mathematical framework extensions.
//!
//! These tests verify the algebraic laws for:
//! - Frame and nucleus properties
//! - Heyting algebra adjunction
//! - Graded monad laws

use lattice_guard::{
    frame::{BoundedLattice, Frame, Lattice, Nucleus, TrifectaQuotient},
    graded::{Graded, RiskGrade},
    heyting::HeytingAlgebra,
    CapabilityLattice, CapabilityLevel, PermissionLattice, TrifectaRisk,
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
