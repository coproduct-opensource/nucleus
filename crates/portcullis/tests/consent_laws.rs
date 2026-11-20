//! The consent composition laws (Program A contract), as properties.
//!
//! - **meet**: obligated if either side obligates; otherwise autonomous only if
//!   autonomous on both sides.
//! - **join**: consent from the side(s) where the op is above `Never`; with
//!   both, obligated only if both obligate.
//! - **normalize** only adds obligations (autonomous → obligated), and is
//!   idempotent.
//! - The declaration invariant holds after `normalize`, `meet`, `join` and
//!   `delegate_to` — even when an input's declaration was broken, the output
//!   is fully declared, and narrowing never drops consent.
//! - `leq` agrees with `meet`.
//!
//! The uninhabitable-state closure may add obligations to a meet or a join;
//! the laws are stated modulo that closure, which is the one thing allowed to
//! make a result stricter than the per-op rule.

use portcullis::{
    CapabilityLattice, CapabilityLevel, ConsentMode, IncompatibilityConstraint, Operation,
    PermissionLattice,
};
use proptest::prelude::*;

fn arb_level() -> impl Strategy<Value = CapabilityLevel> {
    prop_oneof![
        Just(CapabilityLevel::Never),
        Just(CapabilityLevel::LowRisk),
        Just(CapabilityLevel::Always),
    ]
}

fn caps_from(levels: &[CapabilityLevel]) -> CapabilityLattice {
    let mut caps = CapabilityLattice::restrictive();
    for (op, level) in Operation::ALL.into_iter().zip(levels) {
        *caps.level_mut(op) = *level;
    }
    caps
}

/// A declared lattice: `levels`, with each permitted op obligated when its
/// bit in `obligated` is set and autonomous otherwise. Every non-consent
/// dimension comes from one shared base, so `meet`/`leq` compare consent and
/// capabilities only.
fn declared(
    base: &PermissionLattice,
    levels: &[CapabilityLevel],
    obligated: u16,
) -> PermissionLattice {
    let mut l = base
        .clone()
        .with_capabilities(caps_from(levels), ConsentMode::Autonomous);
    for (i, op) in Operation::ALL.into_iter().enumerate() {
        if obligated & (1 << i) != 0 && l.capabilities.level_for(op) > CapabilityLevel::Never {
            l.declare(op, ConsentMode::RequiresApproval);
        }
    }
    l.normalize()
}

fn arb_declared() -> impl Strategy<Value = (Vec<CapabilityLevel>, u16)> {
    (prop::collection::vec(arb_level(), 13), any::<u16>())
}

fn base() -> PermissionLattice {
    PermissionLattice::permissive()
}

fn closure(caps: &CapabilityLattice) -> portcullis::Obligations {
    IncompatibilityConstraint::enforcing().obligations_for(caps)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn every_operation_preserves_the_declaration(
        (la, oa) in arb_declared(),
        (lb, ob) in arb_declared(),
    ) {
        let base = base();
        let a = declared(&base, &la, oa);
        let b = declared(&base, &lb, ob);
        prop_assert_eq!(a.check_consent(), Ok(()));
        prop_assert_eq!(b.check_consent(), Ok(()));
        prop_assert_eq!(a.meet(&b).check_consent(), Ok(()), "meet");
        prop_assert_eq!(a.join(&b).check_consent(), Ok(()), "join");
        prop_assert_eq!(a.clone().normalize().check_consent(), Ok(()), "normalize");
        let delegated = a.delegate_to(&b, "law").expect("same budget, not expired");
        prop_assert_eq!(delegated.check_consent(), Ok(()), "delegate_to");
    }

    /// A broken input — an op raised through the public field, undeclared —
    /// still yields a fully declared meet, with that op obligated.
    #[test]
    fn meet_declares_what_a_broken_input_left_undeclared(
        (la, oa) in arb_declared(),
        (lb, ob) in arb_declared(),
        raised in 0usize..13,
    ) {
        let base = base();
        let mut a = declared(&base, &la, oa);
        let b = declared(&base, &lb, ob);
        let op = Operation::ALL[raised];
        // A raw obligation on a forbidden op would declare it once raised.
        if a.capabilities.level_for(op) == CapabilityLevel::Never && !a.obligations.requires(op) {
            *a.capabilities.level_mut(op) = CapabilityLevel::Always;
            prop_assert!(a.check_consent().is_err(), "precondition: undeclared");
            prop_assert!(a.requires_approval(op), "undeclared is decided RequiresApproval");
            let m = a.meet(&b);
            prop_assert_eq!(m.check_consent(), Ok(()));
            if m.capabilities.level_for(op) > CapabilityLevel::Never {
                prop_assert!(m.requires_approval(op), "narrowing kept the consent");
            }
        }
    }

    #[test]
    fn meet_unions_obligations(
        (la, oa) in arb_declared(),
        (lb, ob) in arb_declared(),
    ) {
        let base = base();
        let a = declared(&base, &la, oa);
        let b = declared(&base, &lb, ob);
        let m = a.meet(&b);
        let closed = closure(&m.capabilities);
        for op in Operation::ALL {
            if m.capabilities.level_for(op) == CapabilityLevel::Never {
                continue;
            }
            let either = a.requires_approval(op) || b.requires_approval(op);
            prop_assert_eq!(
                m.requires_approval(op),
                either || closed.requires(op),
                "op {:?}: obligated iff either side obligates (or the closure does)", op
            );
        }
    }

    #[test]
    fn join_takes_consent_from_the_permitting_sides(
        (la, oa) in arb_declared(),
        (lb, ob) in arb_declared(),
    ) {
        let base = base();
        let a = declared(&base, &la, oa);
        let b = declared(&base, &lb, ob);
        let j = a.join(&b);
        let closed = closure(&j.capabilities);
        for op in Operation::ALL {
            let pa = a.capabilities.level_for(op) > CapabilityLevel::Never;
            let pb = b.capabilities.level_for(op) > CapabilityLevel::Never;
            let expected = match (pa, pb) {
                (false, false) => continue,
                (true, false) => a.requires_approval(op),
                (false, true) => b.requires_approval(op),
                (true, true) => a.requires_approval(op) && b.requires_approval(op),
            };
            prop_assert_eq!(
                j.requires_approval(op),
                expected || closed.requires(op),
                "op {:?}", op
            );
        }
    }

    /// Delegation is a meet with the parent: whatever the parent obligates and
    /// the child may still do, the child is obligated for.
    #[test]
    fn narrowing_never_drops_consent(
        (la, oa) in arb_declared(),
        (lb, ob) in arb_declared(),
    ) {
        let base = base();
        let parent = declared(&base, &la, oa);
        let requested = declared(&base, &lb, ob);
        let child = parent.delegate_to(&requested, "law").expect("delegates");
        for op in Operation::ALL {
            if child.capabilities.level_for(op) > CapabilityLevel::Never
                && (parent.requires_approval(op) || requested.requires_approval(op))
            {
                prop_assert!(child.requires_approval(op), "op {:?} lost its obligation", op);
            }
        }
        prop_assert!(child.leq(&parent));
    }

    #[test]
    fn normalize_only_adds_obligations_and_is_idempotent(
        (la, oa) in arb_declared(),
    ) {
        // Built unnormalized, so normalize has work to do.
        let mut x = base().with_capabilities(caps_from(&la), ConsentMode::Autonomous);
        for (i, op) in Operation::ALL.into_iter().enumerate() {
            if oa & (1 << i) != 0 && x.capabilities.level_for(op) > CapabilityLevel::Never {
                x.declare(op, ConsentMode::RequiresApproval);
            }
        }
        let once = x.clone().normalize();
        for op in Operation::ALL {
            if x.requires_approval(op) {
                prop_assert!(once.requires_approval(op), "normalize dropped {:?}", op);
            }
        }
        let twice = once.clone().normalize();
        prop_assert_eq!(&twice, &once);
        prop_assert_eq!(&twice.obligations, &once.obligations);
        prop_assert_eq!(twice.autonomous(), once.autonomous());
    }

    #[test]
    fn leq_agrees_with_meet(
        (la, oa) in arb_declared(),
        (lb, ob) in arb_declared(),
    ) {
        let base = base();
        let a = declared(&base, &la, oa);
        let b = declared(&base, &lb, ob);
        prop_assert_eq!(a.leq(&b), a.meet(&b) == a, "a ≤ b ⟺ a ∧ b = a");
        // And a meet is below both sides.
        let m = a.meet(&b);
        prop_assert!(m.leq(&a) && m.leq(&b));
    }
}
