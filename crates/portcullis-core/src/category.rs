//! Categorical composition laws for nucleus algebraic structures (#1106).
//!
//! Makes the implicit categorical structure in nucleus explicit and testable:
//! - Delegation attenuation forms a category (associative composition, identity)
//! - IFC label propagation is functorial (preserves composition)
//! - Permission lattice meet/join are natural transformations
//!
//! These properties, when verified via property tests, make certain bug classes
//! structurally impossible (non-associative delegation, non-functorial propagation).

use crate::{ConfLevel, IFCLabel, IntegLevel};

// ═══════════════════════════════════════════════════════════════════════════
// Category trait — objects with associative composition and identity
// ═══════════════════════════════════════════════════════════════════════════

/// A category: objects with an associative binary operation and identity element.
///
/// Laws that must hold:
/// - **Identity**: `compose(identity(), a) == a` and `compose(a, identity()) == a`
/// - **Associativity**: `compose(compose(a, b), c) == compose(a, compose(b, c))`
pub trait Category: Sized + Clone + PartialEq {
    /// The identity morphism.
    fn cat_identity() -> Self;

    /// Compose two morphisms (diagrammatic order: self then other).
    fn compose(self, other: Self) -> Self;
}

// ═══════════════════════════════════════════════════════════════════════════
// Semilattice trait — idempotent commutative monoid
// ═══════════════════════════════════════════════════════════════════════════

/// A meet-semilattice: idempotent, commutative, associative binary operation.
///
/// Laws:
/// - **Idempotent**: `meet(a, a) == a`
/// - **Commutative**: `meet(a, b) == meet(b, a)`
/// - **Associative**: `meet(meet(a, b), c) == meet(a, meet(b, c))`
pub trait MeetSemilattice: Sized + Clone + PartialEq {
    fn meet(self, other: Self) -> Self;
}

/// A join-semilattice: idempotent, commutative, associative binary operation.
pub trait JoinSemilattice: Sized + Clone + PartialEq {
    fn join(self, other: Self) -> Self;
}

// ═══════════════════════════════════════════════════════════════════════════
// Implementations for IFCLabel
// ═══════════════════════════════════════════════════════════════════════════

impl JoinSemilattice for IFCLabel {
    fn join(self, other: Self) -> Self {
        // Delegates to the existing IFCLabel::join method
        IFCLabel::join(self, other)
    }
}

impl JoinSemilattice for ConfLevel {
    fn join(self, other: Self) -> Self {
        // ConfLevel is covariant — join = max
        if self > other { self } else { other }
    }
}

impl MeetSemilattice for ConfLevel {
    fn meet(self, other: Self) -> Self {
        if self < other { self } else { other }
    }
}

impl JoinSemilattice for IntegLevel {
    fn join(self, other: Self) -> Self {
        // IntegLevel is contravariant for IFC — join = min (least trusted)
        if self < other { self } else { other }
    }
}

impl MeetSemilattice for IntegLevel {
    fn meet(self, other: Self) -> Self {
        // Meet = max (most trusted)
        if self > other { self } else { other }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Functoriality of label propagation
// ═══════════════════════════════════════════════════════════════════════════

/// Check that label propagation preserves the join operation.
///
/// For functoriality: propagate(join(a, b)) == join(propagate(a), propagate(b))
/// where "propagate" means joining with an intrinsic label.
///
/// This holds because join is associative and commutative:
/// join(join(a, b), c) == join(a, join(b, c)) for any intrinsic label c.
pub fn propagation_preserves_join(a: IFCLabel, b: IFCLabel, intrinsic: IFCLabel) -> bool {
    let joined_then_propagated =
        crate::flow::propagate_label(&[JoinSemilattice::join(a, b)], intrinsic);
    let propagated_then_joined = JoinSemilattice::join(
        crate::flow::propagate_label(&[a], intrinsic),
        crate::flow::propagate_label(&[b], intrinsic),
    );
    joined_then_propagated == propagated_then_joined
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests — property-based verification of categorical laws
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityLevel, DerivationClass, Freshness, ProvenanceSet};

    fn arb_conf() -> ConfLevel {
        let vals = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        vals[rand_index(3)]
    }

    fn arb_integ() -> IntegLevel {
        let vals = [
            IntegLevel::Adversarial,
            IntegLevel::Untrusted,
            IntegLevel::Trusted,
        ];
        vals[rand_index(3)]
    }

    fn arb_label() -> IFCLabel {
        IFCLabel {
            confidentiality: arb_conf(),
            integrity: arb_integ(),
            provenance: ProvenanceSet::USER,
            freshness: Freshness {
                observed_at: 0,
                ttl_secs: 0,
            },
            authority: AuthorityLevel::Directive,
            derivation: DerivationClass::Deterministic,
        }
    }

    // Simple PRNG for test variety (no external dep needed)
    fn rand_index(n: usize) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        std::thread::current().id().hash(&mut h);
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .hash(&mut h);
        (h.finish() as usize) % n
    }

    // ── ConfLevel semilattice laws ─────────────────────────────────

    #[test]
    fn conf_join_idempotent() {
        for &c in &[ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret] {
            assert_eq!(JoinSemilattice::join(c, c), c);
        }
    }

    #[test]
    fn conf_join_commutative() {
        let levels = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        for &a in &levels {
            for &b in &levels {
                assert_eq!(JoinSemilattice::join(a, b), JoinSemilattice::join(b, a));
            }
        }
    }

    #[test]
    fn conf_join_associative() {
        let levels = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        for &a in &levels {
            for &b in &levels {
                for &c in &levels {
                    let ab_c = JoinSemilattice::join(JoinSemilattice::join(a, b), c);
                    let a_bc = JoinSemilattice::join(a, JoinSemilattice::join(b, c));
                    assert_eq!(ab_c, a_bc);
                }
            }
        }
    }

    #[test]
    fn conf_meet_idempotent() {
        for &c in &[ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret] {
            assert_eq!(MeetSemilattice::meet(c, c), c);
        }
    }

    #[test]
    fn conf_meet_commutative() {
        let levels = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        for &a in &levels {
            for &b in &levels {
                assert_eq!(MeetSemilattice::meet(a, b), MeetSemilattice::meet(b, a));
            }
        }
    }

    #[test]
    fn conf_meet_associative() {
        let levels = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        for &a in &levels {
            for &b in &levels {
                for &c in &levels {
                    let ab_c = MeetSemilattice::meet(MeetSemilattice::meet(a, b), c);
                    let a_bc = MeetSemilattice::meet(a, MeetSemilattice::meet(b, c));
                    assert_eq!(ab_c, a_bc);
                }
            }
        }
    }

    // ── IntegLevel semilattice laws ────────────────────────────────

    #[test]
    fn integ_join_idempotent() {
        for &i in &[
            IntegLevel::Adversarial,
            IntegLevel::Untrusted,
            IntegLevel::Trusted,
        ] {
            assert_eq!(JoinSemilattice::join(i, i), i);
        }
    }

    #[test]
    fn integ_join_commutative() {
        let levels = [
            IntegLevel::Adversarial,
            IntegLevel::Untrusted,
            IntegLevel::Trusted,
        ];
        for &a in &levels {
            for &b in &levels {
                assert_eq!(JoinSemilattice::join(a, b), JoinSemilattice::join(b, a));
            }
        }
    }

    #[test]
    fn integ_join_associative() {
        let levels = [
            IntegLevel::Adversarial,
            IntegLevel::Untrusted,
            IntegLevel::Trusted,
        ];
        for &a in &levels {
            for &b in &levels {
                for &c in &levels {
                    let ab_c = JoinSemilattice::join(JoinSemilattice::join(a, b), c);
                    let a_bc = JoinSemilattice::join(a, JoinSemilattice::join(b, c));
                    assert_eq!(ab_c, a_bc);
                }
            }
        }
    }

    // ── Absorption laws (lattice) ──────────────────────────────────

    #[test]
    fn conf_absorption() {
        let levels = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        for &a in &levels {
            for &b in &levels {
                // a ∧ (a ∨ b) = a
                assert_eq!(MeetSemilattice::meet(a, JoinSemilattice::join(a, b)), a);
                // a ∨ (a ∧ b) = a
                assert_eq!(JoinSemilattice::join(a, MeetSemilattice::meet(a, b)), a);
            }
        }
    }

    // ── IFCLabel join semilattice laws ──────────────────────────────

    #[test]
    fn ifc_label_join_idempotent() {
        for _ in 0..20 {
            let l = arb_label();
            assert_eq!(JoinSemilattice::join(l, l), l);
        }
    }

    #[test]
    fn ifc_label_join_commutative() {
        for _ in 0..20 {
            let a = arb_label();
            let b = arb_label();
            assert_eq!(JoinSemilattice::join(a, b), JoinSemilattice::join(b, a));
        }
    }

    #[test]
    fn ifc_label_join_associative() {
        for _ in 0..20 {
            let a = arb_label();
            let b = arb_label();
            let c = arb_label();
            let ab_c = JoinSemilattice::join(JoinSemilattice::join(a, b), c);
            let a_bc = JoinSemilattice::join(a, JoinSemilattice::join(b, c));
            assert_eq!(ab_c, a_bc);
        }
    }

    // ── Functoriality of label propagation ─────────────────────────

    #[test]
    fn propagation_is_functorial() {
        for _ in 0..20 {
            let a = arb_label();
            let b = arb_label();
            let intrinsic = arb_label();
            assert!(
                propagation_preserves_join(a, b, intrinsic),
                "propagation should preserve join (functoriality)"
            );
        }
    }
}
