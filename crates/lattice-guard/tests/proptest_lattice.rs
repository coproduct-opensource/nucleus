//! Property-based tests for lattice laws.
//!
//! These tests use proptest to verify that the lattice operations
//! satisfy the required algebraic properties.

use lattice_guard::{
    BudgetLattice, CapabilityLattice, CapabilityLevel, CommandLattice, Operation, PathLattice,
    PermissionLattice, TimeLattice,
};
use proptest::prelude::*;
use rust_decimal::Decimal;

// Strategy for generating arbitrary CapabilityLevel
fn arb_capability_level() -> impl Strategy<Value = CapabilityLevel> {
    prop_oneof![
        Just(CapabilityLevel::Never),
        Just(CapabilityLevel::LowRisk),
        Just(CapabilityLevel::Always),
    ]
}

// Strategy for generating arbitrary CapabilityLattice
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

// Strategy for generating arbitrary BudgetLattice
fn arb_budget_lattice() -> impl Strategy<Value = BudgetLattice> {
    (
        1u64..1000u64,
        0u64..1000u64,
        1000u64..1_000_000u64,
        100u64..100_000u64,
    )
        .prop_map(
            |(max_cost, consumed, max_input, max_output)| BudgetLattice {
                max_cost_usd: Decimal::from(max_cost),
                consumed_usd: Decimal::from(consumed.min(max_cost)),
                max_input_tokens: max_input,
                max_output_tokens: max_output,
            },
        )
}

proptest! {
    // ============================================
    // CapabilityLattice Meet Laws
    // ============================================

    #[test]
    fn capability_meet_is_commutative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        prop_assert_eq!(a.meet(&b), b.meet(&a));
    }

    #[test]
    fn capability_meet_is_associative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        c in arb_capability_lattice()
    ) {
        prop_assert_eq!(a.meet(&b).meet(&c), a.meet(&b.meet(&c)));
    }

    #[test]
    fn capability_meet_is_idempotent(a in arb_capability_lattice()) {
        prop_assert_eq!(a.meet(&a), a);
    }

    // ============================================
    // CapabilityLattice Join Laws
    // ============================================

    #[test]
    fn capability_join_is_commutative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        prop_assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn capability_join_is_associative(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        c in arb_capability_lattice()
    ) {
        prop_assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
    }

    #[test]
    fn capability_join_is_idempotent(a in arb_capability_lattice()) {
        prop_assert_eq!(a.join(&a), a);
    }

    // ============================================
    // Absorption Laws (connects meet and join)
    // ============================================

    #[test]
    fn capability_absorption_meet_join(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        // a ∧ (a ∨ b) = a
        prop_assert_eq!(a.meet(&a.join(&b)), a);
    }

    #[test]
    fn capability_absorption_join_meet(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        // a ∨ (a ∧ b) = a
        prop_assert_eq!(a.join(&a.meet(&b)), a);
    }

    // ============================================
    // Partial Order (leq) Properties
    // ============================================

    #[test]
    fn capability_leq_is_reflexive(a in arb_capability_lattice()) {
        prop_assert!(a.leq(&a));
    }

    #[test]
    fn capability_leq_is_antisymmetric(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        if a.leq(&b) && b.leq(&a) {
            prop_assert_eq!(a, b);
        }
    }

    #[test]
    fn capability_leq_is_transitive(
        a in arb_capability_lattice(),
        b in arb_capability_lattice(),
        c in arb_capability_lattice()
    ) {
        if a.leq(&b) && b.leq(&c) {
            prop_assert!(a.leq(&c));
        }
    }

    #[test]
    fn capability_meet_is_glb(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        let m = a.meet(&b);
        // m ≤ a and m ≤ b
        prop_assert!(m.leq(&a));
        prop_assert!(m.leq(&b));
    }

    #[test]
    fn capability_join_is_lub(
        a in arb_capability_lattice(),
        b in arb_capability_lattice()
    ) {
        let j = a.join(&b);
        // a ≤ j and b ≤ j
        prop_assert!(a.leq(&j));
        prop_assert!(b.leq(&j));
    }

    // ============================================
    // BudgetLattice Laws
    // ============================================

    #[test]
    fn budget_meet_is_commutative(
        a in arb_budget_lattice(),
        b in arb_budget_lattice()
    ) {
        prop_assert_eq!(a.meet(&b), b.meet(&a));
    }

    #[test]
    fn budget_meet_is_associative(
        a in arb_budget_lattice(),
        b in arb_budget_lattice(),
        c in arb_budget_lattice()
    ) {
        prop_assert_eq!(a.meet(&b).meet(&c), a.meet(&b.meet(&c)));
    }

    #[test]
    fn budget_meet_is_idempotent(a in arb_budget_lattice()) {
        prop_assert_eq!(a.meet(&a), a);
    }

    #[test]
    fn budget_join_is_commutative(
        a in arb_budget_lattice(),
        b in arb_budget_lattice()
    ) {
        prop_assert_eq!(a.join(&b), b.join(&a));
    }

    #[test]
    fn budget_join_is_idempotent(a in arb_budget_lattice()) {
        prop_assert_eq!(a.join(&a), a);
    }

    #[test]
    fn budget_leq_is_reflexive(a in arb_budget_lattice()) {
        prop_assert!(a.leq(&a));
    }

    #[test]
    fn budget_meet_is_glb(
        a in arb_budget_lattice(),
        b in arb_budget_lattice()
    ) {
        let m = a.meet(&b);
        prop_assert!(m.leq(&a));
        prop_assert!(m.leq(&b));
    }

    // ============================================
    // Trifecta Constraint Invariants
    // ============================================

    #[test]
    fn trifecta_constraint_obligations_only_exfil(a in arb_capability_lattice()) {
        use lattice_guard::IncompatibilityConstraint;

        let constraint = IncompatibilityConstraint::enforcing();
        let obligations = constraint.obligations_for(&a);

        for op in obligations.approvals.iter() {
            prop_assert!(matches!(
                op,
                Operation::GitPush | Operation::CreatePr | Operation::RunBash
            ));
        }

        if !constraint.is_trifecta_complete(&a) {
            prop_assert!(obligations.approvals.is_empty());
        } else {
            if a.git_push >= CapabilityLevel::LowRisk {
                prop_assert!(obligations.requires(Operation::GitPush));
            }
            if a.create_pr >= CapabilityLevel::LowRisk {
                prop_assert!(obligations.requires(Operation::CreatePr));
            }
            if a.run_bash >= CapabilityLevel::LowRisk {
                prop_assert!(obligations.requires(Operation::RunBash));
            }
        }
    }

    #[test]
    fn permission_normalize_is_idempotent(
        a in arb_capability_lattice(),
        enforce in any::<bool>()
    ) {
        let perms = PermissionLattice {
            capabilities: a,
            obligations: Default::default(),
            trifecta_constraint: enforce,
            ..PermissionLattice::default()
        };

        let once = perms.clone().normalize();
        let twice = once.clone().normalize();

        prop_assert_eq!(once, twice);
    }

    #[test]
    fn permission_normalize_is_deflationary_when_enforced(
        a in arb_capability_lattice()
    ) {
        let perms = PermissionLattice {
            capabilities: a,
            obligations: Default::default(),
            trifecta_constraint: true,
            ..PermissionLattice::default()
        };

        let normalized = perms.clone().normalize();
        prop_assert!(normalized.leq(&perms));
    }
}

// ============================================
// TimeLattice (needs special handling due to DateTime)
// ============================================

mod time_tests {
    use super::*;
    use chrono::{Duration, Utc};

    proptest! {
        #[test]
        fn time_meet_is_commutative(
            hours_a in 1i64..100i64,
            hours_b in 1i64..100i64
        ) {
            let now = Utc::now();
            let a = TimeLattice::between(now, now + Duration::hours(hours_a));
            let b = TimeLattice::between(now, now + Duration::hours(hours_b));

            prop_assert_eq!(a.meet(&b), b.meet(&a));
        }

        #[test]
        fn time_meet_is_idempotent(hours in 1i64..100i64) {
            let now = Utc::now();
            let a = TimeLattice::between(now, now + Duration::hours(hours));

            prop_assert_eq!(a.meet(&a), a);
        }

        #[test]
        fn time_join_is_commutative(
            hours_a in 1i64..100i64,
            hours_b in 1i64..100i64
        ) {
            let now = Utc::now();
            let a = TimeLattice::between(now, now + Duration::hours(hours_a));
            let b = TimeLattice::between(now, now + Duration::hours(hours_b));

            prop_assert_eq!(a.join(&b), b.join(&a));
        }

        #[test]
        fn time_join_is_idempotent(hours in 1i64..100i64) {
            let now = Utc::now();
            let a = TimeLattice::between(now, now + Duration::hours(hours));

            prop_assert_eq!(a.join(&a), a);
        }
    }
}

// ============================================
// CommandLattice
// ============================================

mod command_tests {
    use super::*;

    fn arb_command_lattice() -> impl Strategy<Value = CommandLattice> {
        let allowed_set = prop::collection::hash_set("cargo (test|build|check)", 0..5);
        let blocked_set = prop::collection::hash_set("(rm -rf|sudo|chmod)", 0..3);

        (allowed_set, blocked_set).prop_map(|(allowed, blocked)| CommandLattice {
            allowed,
            blocked,
            allowed_rules: Vec::new(),
            blocked_rules: Vec::new(),
        })
    }

    proptest! {
        #[test]
        fn command_meet_is_commutative(
            a in arb_command_lattice(),
            b in arb_command_lattice()
        ) {
            prop_assert_eq!(a.meet(&b), b.meet(&a));
        }

        #[test]
        fn command_meet_is_idempotent(a in arb_command_lattice()) {
            prop_assert_eq!(a.meet(&a), a);
        }

        #[test]
        fn command_join_is_commutative(
            a in arb_command_lattice(),
            b in arb_command_lattice()
        ) {
            prop_assert_eq!(a.join(&b), b.join(&a));
        }

        #[test]
        fn command_join_is_idempotent(a in arb_command_lattice()) {
            prop_assert_eq!(a.join(&a), a);
        }

        #[test]
        fn command_blocked_grows_in_meet(
            a in arb_command_lattice(),
            b in arb_command_lattice()
        ) {
            let m = a.meet(&b);
            // blocked should be union (superset of both)
            prop_assert!(a.blocked.is_subset(&m.blocked));
            prop_assert!(b.blocked.is_subset(&m.blocked));
        }
    }
}

// ============================================
// PathLattice
// ============================================

mod path_tests {
    use super::*;

    fn arb_path_lattice() -> impl Strategy<Value = PathLattice> {
        let allowed_set = prop::collection::hash_set("(src|tests|lib)/.+", 0..3);
        let blocked_set = prop::collection::hash_set("(\\.env.*|\\.key|secrets/.*)", 0..3);

        (allowed_set, blocked_set).prop_map(|(allowed, blocked)| PathLattice {
            allowed,
            blocked,
            work_dir: None,
        })
    }

    proptest! {
        #[test]
        fn path_meet_is_commutative(
            a in arb_path_lattice(),
            b in arb_path_lattice()
        ) {
            prop_assert_eq!(a.meet(&b), b.meet(&a));
        }

        #[test]
        fn path_meet_is_idempotent(a in arb_path_lattice()) {
            prop_assert_eq!(a.meet(&a), a);
        }

        #[test]
        fn path_join_is_commutative(
            a in arb_path_lattice(),
            b in arb_path_lattice()
        ) {
            prop_assert_eq!(a.join(&b), b.join(&a));
        }

        #[test]
        fn path_join_is_idempotent(a in arb_path_lattice()) {
            prop_assert_eq!(a.join(&a), a);
        }

        #[test]
        fn path_blocked_grows_in_meet(
            a in arb_path_lattice(),
            b in arb_path_lattice()
        ) {
            let m = a.meet(&b);
            prop_assert!(a.blocked.is_subset(&m.blocked));
            prop_assert!(b.blocked.is_subset(&m.blocked));
        }
    }
}
