//! Exhaustive ALGEBRAIC-CLOSURE ground truth (groundtruth-suite Layer A, slice A3).
//!
//! The Lean side PROVES the IFC algebra + gate over a *model* (IFCSemilatticeProofs:
//! full `Lattice`/`OrderBot`/`OrderTop` IFCLabel2; DecidePureProofs: gate verdicts +
//! monotonicity). The cross-language tie to the *runtime Rust* was, per the exemplar
//! audit, "sampled parity, not proof" (nucleus-ifc/src/decision.rs). This test closes
//! that residual FOR THE FINITE CARRIER: it enumerates the WHOLE conf×integ subspace
//! and ALL (capability × operation) and checks the runtime Rust agrees with the
//! Lean-proven model. Cedar's verification-guided Lean↔Rust differential (arXiv
//! 2407.01688) does this RANDOMLY (millions of inputs); a finite carrier lets us do
//! it EXHAUSTIVELY — complete, not sampled, so it is ground truth not evidence.

use portcullis_core::{
    decide_pure, should_gate, CapabilityLevel, ConfLevel, ExposureSet, IFCLabel, IntegLevel,
    Operation, PureVerdict,
};

const CONFS: [ConfLevel; 3] = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
const INTEGS: [IntegLevel; 3] =
    [IntegLevel::Adversarial, IntegLevel::Untrusted, IntegLevel::Trusted];

/// An IFCLabel varying only the (conf, integ) axes — the IFCLabel2 subspace the
/// Lean lattice instance models; the other axes are pinned at `bottom()`, so
/// `join`/`flows_to` reduce to the proven Biba product over conf×integ.
fn label(c: ConfLevel, i: IntegLevel) -> IFCLabel {
    IFCLabel { confidentiality: c, integrity: i, ..IFCLabel::bottom() }
}
fn carrier() -> Vec<IFCLabel> {
    let mut v = Vec::with_capacity(9);
    for &c in &CONFS {
        for &i in &INTEGS {
            v.push(label(c, i));
        }
    }
    v
}

#[test]
fn ifc_lattice_laws_exhaustive() {
    let ls = carrier();
    for &a in &ls {
        assert_eq!(a.join(a), a, "join idempotent");
        assert_eq!(a.meet(a), a, "meet idempotent");
        for &b in &ls {
            assert_eq!(a.join(b), b.join(a), "join commutative");
            assert_eq!(a.meet(b), b.meet(a), "meet commutative");
            assert_eq!(a.join(a.meet(b)), a, "absorption a ⊔ (a ⊓ b) = a");
            assert_eq!(a.meet(a.join(b)), a, "absorption a ⊓ (a ⊔ b) = a");
            for &c in &ls {
                assert_eq!(a.join(b).join(c), a.join(b.join(c)), "join associative");
                assert_eq!(a.meet(b).meet(c), a.meet(b.meet(c)), "meet associative");
            }
        }
    }
}

#[test]
fn flows_to_is_partial_order_exhaustive() {
    let ls = carrier();
    for &a in &ls {
        assert!(a.flows_to(a), "flows_to reflexive");
    }
    for &a in &ls {
        for &b in &ls {
            if a.flows_to(b) && b.flows_to(a) {
                assert_eq!(a, b, "flows_to antisymmetric");
            }
            for &c in &ls {
                if a.flows_to(b) && b.flows_to(c) {
                    assert!(a.flows_to(c), "flows_to transitive");
                }
            }
        }
    }
}

#[test]
fn flows_to_join_is_supremum_exhaustive() {
    // join is the least upper bound under flows_to (covariant order)
    let ls = carrier();
    for &a in &ls {
        for &b in &ls {
            let j = a.join(b);
            assert!(a.flows_to(j), "a ⤳ a⊔b");
            assert!(b.flows_to(j), "b ⤳ a⊔b");
        }
    }
}

#[test]
fn decide_pure_matches_lean_model_exhaustive() {
    // Mirrors DecidePureProofs over ALL operations at the empty (safe) exposure:
    //   Never  → DenyCapability        (never_always_denies)
    //   LowRisk→ RequiresApproval      (lowrisk_always_requires_approval)
    //   Always → Allow iff !should_gate, GateExfil iff should_gate
    //            (allow_requires_always_and_no_gate + gate_exfil_iff)
    let e = ExposureSet::empty();
    for &op in &Operation::ALL {
        assert_eq!(
            decide_pure(CapabilityLevel::Never, &e, op),
            PureVerdict::DenyCapability,
            "Never denies for {op:?}"
        );
        assert_eq!(
            decide_pure(CapabilityLevel::LowRisk, &e, op),
            PureVerdict::RequiresApproval,
            "LowRisk requires approval for {op:?}"
        );
        let expected = if should_gate(&e, op) {
            PureVerdict::GateExfil
        } else {
            PureVerdict::Allow
        };
        assert_eq!(
            decide_pure(CapabilityLevel::Always, &e, op),
            expected,
            "Always verdict for {op:?}"
        );
    }
}
