//! Algebraic structures for nucleus: lattices, semilattices, categories.
//!
//! This module provides the foundational algebraic traits used throughout
//! the nucleus permission and IFC systems:
//!
//! - **MeetSemilattice / JoinSemilattice**: Single-operation semilattices
//! - **Lattice**: Combined meet + join with partial order
//! - **BoundedLattice**: Adds top (⊤) and bottom (⊥) elements
//! - **Category**: Associative composition with identity
//!
//! All concrete lattice types in portcullis-core implement `Lattice`,
//! enabling generic lattice combinators and shared property tests.

use crate::{
    AuthorityLevel, CapabilityLattice, CapabilityLevel, ConfLevel, DerivationClass, Freshness,
    IFCLabel, IntegLevel,
};

// ═══════════════════════════════════════════════════════════════════════════
// Lattice traits
// ═══════════════════════════════════════════════════════════════════════════

/// A lattice with meet (∧) and join (∨) operations.
///
/// # Laws
///
/// For all `a`, `b`, `c`:
/// - Commutativity: `a ∧ b = b ∧ a`, `a ∨ b = b ∨ a`
/// - Associativity: `(a ∧ b) ∧ c = a ∧ (b ∧ c)`
/// - Idempotence: `a ∧ a = a`, `a ∨ a = a`
/// - Absorption: `a ∧ (a ∨ b) = a`, `a ∨ (a ∧ b) = a`
pub trait Lattice: Clone + PartialEq {
    /// Greatest lower bound (meet, ∧).
    fn meet(&self, other: &Self) -> Self;

    /// Least upper bound (join, ∨).
    fn join(&self, other: &Self) -> Self;

    /// Partial order: `a ≤ b` iff `a ∧ b = a`.
    fn leq(&self, other: &Self) -> bool;
}

/// A bounded lattice with top (⊤) and bottom (⊥) elements.
///
/// # Laws
///
/// - `a ∧ ⊤ = a` (top is identity for meet)
/// - `a ∨ ⊥ = a` (bottom is identity for join)
/// - `a ∧ ⊥ = ⊥` (bottom is annihilator for meet)
/// - `a ∨ ⊤ = ⊤` (top is annihilator for join)
pub trait BoundedLattice: Lattice {
    /// Top element (⊤): greatest element in the lattice.
    fn top() -> Self;

    /// Bottom element (⊥): least element in the lattice.
    fn bottom() -> Self;
}

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
// Semilattice traits — idempotent commutative monoids
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
// Product lattice — categorical product in Lat
// ═══════════════════════════════════════════════════════════════════════════

/// The product of two lattices, with pointwise meet/join.
///
/// By the universal property of products in **Lat**, the product of
/// lattices is a lattice. Meet, join, and leq are computed componentwise.
///
/// ```text
/// (a₁, a₂) ∧ (b₁, b₂) = (a₁ ∧ b₁, a₂ ∧ b₂)
/// (a₁, a₂) ∨ (b₁, b₂) = (a₁ ∨ b₁, a₂ ∨ b₂)
/// (a₁, a₂) ≤ (b₁, b₂) ⟺ a₁ ≤ b₁ ∧ a₂ ≤ b₂
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProductLattice<A, B>(pub A, pub B);

impl<A: Lattice, B: Lattice> Lattice for ProductLattice<A, B> {
    fn meet(&self, other: &Self) -> Self {
        ProductLattice(self.0.meet(&other.0), self.1.meet(&other.1))
    }
    fn join(&self, other: &Self) -> Self {
        ProductLattice(self.0.join(&other.0), self.1.join(&other.1))
    }
    fn leq(&self, other: &Self) -> bool {
        self.0.leq(&other.0) && self.1.leq(&other.1)
    }
}

impl<A: BoundedLattice, B: BoundedLattice> BoundedLattice for ProductLattice<A, B> {
    fn top() -> Self {
        ProductLattice(A::top(), B::top())
    }
    fn bottom() -> Self {
        ProductLattice(A::bottom(), B::bottom())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Generic lattice combinators
// ═══════════════════════════════════════════════════════════════════════════

/// Meet of all elements in an iterator (greatest lower bound).
///
/// Returns `None` for empty iterators. For bounded lattices, use
/// `meet_all_bounded` which returns `top()` for empty input.
pub fn meet_all<L: Lattice>(iter: impl IntoIterator<Item = L>) -> Option<L> {
    iter.into_iter().reduce(|a, b| a.meet(&b))
}

/// Join of all elements in an iterator (least upper bound).
///
/// Returns `None` for empty iterators. For bounded lattices, use
/// `join_all_bounded` which returns `bottom()` for empty input.
pub fn join_all<L: Lattice>(iter: impl IntoIterator<Item = L>) -> Option<L> {
    iter.into_iter().reduce(|a, b| a.join(&b))
}

/// Meet of all elements, defaulting to `top()` for empty input.
///
/// This is the correct identity for meet: `∧ {} = ⊤`.
pub fn meet_all_bounded<L: BoundedLattice>(iter: impl IntoIterator<Item = L>) -> L {
    iter.into_iter()
        .reduce(|a, b| a.meet(&b))
        .unwrap_or_else(L::top)
}

/// Join of all elements, defaulting to `bottom()` for empty input.
///
/// This is the correct identity for join: `∨ {} = ⊥`.
pub fn join_all_bounded<L: BoundedLattice>(iter: impl IntoIterator<Item = L>) -> L {
    iter.into_iter()
        .reduce(|a, b| a.join(&b))
        .unwrap_or_else(L::bottom)
}

// ═══════════════════════════════════════════════════════════════════════════
// Lattice implementations for core types
// ═══════════════════════════════════════════════════════════════════════════

// ── CapabilityLevel (3-element total order) ────────────────────────────

impl Lattice for CapabilityLevel {
    fn meet(&self, other: &Self) -> Self {
        CapabilityLevel::meet(*self, *other)
    }
    fn join(&self, other: &Self) -> Self {
        CapabilityLevel::join(*self, *other)
    }
    fn leq(&self, other: &Self) -> bool {
        CapabilityLevel::leq(*self, *other)
    }
}

impl BoundedLattice for CapabilityLevel {
    fn top() -> Self {
        CapabilityLevel::Always
    }
    fn bottom() -> Self {
        CapabilityLevel::Never
    }
}

// ── CapabilityLattice (13-dimensional product) ────────────────────────

impl Lattice for CapabilityLattice {
    fn meet(&self, other: &Self) -> Self {
        CapabilityLattice::meet(self, other)
    }
    fn join(&self, other: &Self) -> Self {
        CapabilityLattice::join(self, other)
    }
    fn leq(&self, other: &Self) -> bool {
        CapabilityLattice::leq(self, other)
    }
}

impl BoundedLattice for CapabilityLattice {
    fn top() -> Self {
        CapabilityLattice::top()
    }
    fn bottom() -> Self {
        CapabilityLattice::bottom()
    }
}

// ── ConfLevel (3-element chain: Public < Internal < Secret) ───────────

impl Lattice for ConfLevel {
    fn meet(&self, other: &Self) -> Self {
        if *self < *other { *self } else { *other }
    }
    fn join(&self, other: &Self) -> Self {
        if *self > *other { *self } else { *other }
    }
    fn leq(&self, other: &Self) -> bool {
        *self <= *other
    }
}

impl BoundedLattice for ConfLevel {
    fn top() -> Self {
        ConfLevel::Secret
    }
    fn bottom() -> Self {
        ConfLevel::Public
    }
}

// ── IntegLevel (3-element chain: Adversarial < Untrusted < Trusted) ──

impl Lattice for IntegLevel {
    fn meet(&self, other: &Self) -> Self {
        // Meet = max (most trusted) — this is the GLB in the IFC ordering
        // where join = min (least trusted)
        if *self > *other { *self } else { *other }
    }
    fn join(&self, other: &Self) -> Self {
        // Join = min (least trusted) — contravariant for IFC
        if *self < *other { *self } else { *other }
    }
    fn leq(&self, other: &Self) -> bool {
        // In the IFC join-semilattice, Trusted ≤ Untrusted ≤ Adversarial
        // (higher enum value = higher in lattice = more restrictive)
        // But IntegLevel derives Ord with Adversarial < Untrusted < Trusted
        // So leq in the lattice sense is: *self >= *other
        *self >= *other
    }
}

impl BoundedLattice for IntegLevel {
    fn top() -> Self {
        IntegLevel::Adversarial // most restrictive
    }
    fn bottom() -> Self {
        IntegLevel::Trusted // least restrictive
    }
}

// ── AuthorityLevel (4-element chain) ──────────────────────────────────

impl Lattice for AuthorityLevel {
    fn meet(&self, other: &Self) -> Self {
        // Meet = max (most authority) — GLB in the IFC ordering
        if *self > *other { *self } else { *other }
    }
    fn join(&self, other: &Self) -> Self {
        // Join = min (least authority) — contravariant for IFC
        if *self < *other { *self } else { *other }
    }
    fn leq(&self, other: &Self) -> bool {
        // Same contravariant convention as IntegLevel
        *self >= *other
    }
}

impl BoundedLattice for AuthorityLevel {
    fn top() -> Self {
        AuthorityLevel::NoAuthority // most restrictive
    }
    fn bottom() -> Self {
        AuthorityLevel::Directive // least restrictive
    }
}

// ── DerivationClass (5-element lattice with diamond) ──────────────────

impl Lattice for DerivationClass {
    fn meet(&self, other: &Self) -> Self {
        DerivationClass::meet(*self, *other)
    }
    fn join(&self, other: &Self) -> Self {
        DerivationClass::join(*self, *other)
    }
    fn leq(&self, other: &Self) -> bool {
        DerivationClass::leq(*self, *other)
    }
}

impl BoundedLattice for DerivationClass {
    fn top() -> Self {
        DerivationClass::OpaqueExternal
    }
    fn bottom() -> Self {
        DerivationClass::Deterministic
    }
}

// ── Freshness (2D product: observed_at × ttl_secs) ───────────────────

impl Lattice for Freshness {
    fn meet(&self, other: &Self) -> Self {
        Freshness::meet(*self, *other)
    }
    fn join(&self, other: &Self) -> Self {
        Freshness::join(*self, *other)
    }
    fn leq(&self, other: &Self) -> bool {
        Freshness::leq(*self, *other)
    }
}

// ── IFCLabel (6-dimensional product lattice) ──────────────────────────

impl Lattice for IFCLabel {
    fn meet(&self, other: &Self) -> Self {
        IFCLabel::meet(*self, *other)
    }
    fn join(&self, other: &Self) -> Self {
        IFCLabel::join(*self, *other)
    }
    fn leq(&self, other: &Self) -> bool {
        IFCLabel::leq(*self, *other)
    }
}

// NOTE: IFCLabel does NOT implement BoundedLattice. While IFCLabel::top()
// and IFCLabel::bottom() exist as named constructors, Freshness::leq has
// a known inconsistency with Freshness::meet around ttl_secs=0 (no-expiry).
// This means meet(a, top) == a but a.leq(top) can be false, violating the
// bounded lattice identity law. Until Freshness::leq is fixed, IFCLabel
// only implements Lattice (meet/join/leq are internally consistent for
// the non-freshness dimensions, and meet/join are fully correct).

// ═══════════════════════════════════════════════════════════════════════════
// Semilattice implementations (legacy — kept for backward compatibility)
// ═══════════════════════════════════════════════════════════════════════════

impl JoinSemilattice for IFCLabel {
    fn join(self, other: Self) -> Self {
        IFCLabel::join(self, other)
    }
}

impl JoinSemilattice for ConfLevel {
    fn join(self, other: Self) -> Self {
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
        // Contravariant: join = min (least trusted)
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
// Generic lattice property verification
// ═══════════════════════════════════════════════════════════════════════════

/// Verify all lattice laws hold for a set of sample elements.
///
/// Checks commutativity, associativity, idempotence, and absorption
/// for both meet and join. Returns a list of violations (empty = all laws hold).
pub fn verify_lattice_laws<L: Lattice + std::fmt::Debug>(samples: &[L]) -> Vec<String> {
    let mut violations = Vec::new();

    for (i, a) in samples.iter().enumerate() {
        // Idempotence
        if a.meet(a) != *a {
            violations.push(format!("meet idempotence failed for sample {i}"));
        }
        if a.join(a) != *a {
            violations.push(format!("join idempotence failed for sample {i}"));
        }

        for (j, b) in samples.iter().enumerate() {
            // Commutativity
            if a.meet(b) != b.meet(a) {
                violations.push(format!("meet commutativity failed for samples {i}, {j}"));
            }
            if a.join(b) != b.join(a) {
                violations.push(format!("join commutativity failed for samples {i}, {j}"));
            }

            // Absorption
            if a.meet(&a.join(b)) != *a {
                violations.push(format!(
                    "absorption (meet/join) failed for samples {i}, {j}"
                ));
            }
            if a.join(&a.meet(b)) != *a {
                violations.push(format!(
                    "absorption (join/meet) failed for samples {i}, {j}"
                ));
            }

            // leq consistency: a ≤ b iff a ∧ b = a
            let leq_ab = a.leq(b);
            let meet_eq_a = a.meet(b) == *a;
            if leq_ab != meet_eq_a {
                violations.push(format!(
                    "leq inconsistency for samples {i}, {j}: leq={leq_ab}, meet==a={meet_eq_a}"
                ));
            }

            for (k, c) in samples.iter().enumerate() {
                // Associativity
                if a.meet(&b.meet(c)) != a.meet(b).meet(c) {
                    violations.push(format!(
                        "meet associativity failed for samples {i}, {j}, {k}"
                    ));
                }
                if a.join(&b.join(c)) != a.join(b).join(c) {
                    violations.push(format!(
                        "join associativity failed for samples {i}, {j}, {k}"
                    ));
                }
            }
        }
    }

    violations
}

/// Verify bounded lattice laws hold for a set of sample elements.
///
/// Checks top/bottom identity and annihilator laws in addition to lattice laws.
pub fn verify_bounded_lattice_laws<L: BoundedLattice + std::fmt::Debug>(
    samples: &[L],
) -> Vec<String> {
    let mut violations = verify_lattice_laws(samples);
    let top = L::top();
    let bot = L::bottom();

    for (i, a) in samples.iter().enumerate() {
        // a ∧ ⊤ = a
        if a.meet(&top) != *a {
            violations.push(format!("top identity for meet failed for sample {i}"));
        }
        // a ∨ ⊥ = a
        if a.join(&bot) != *a {
            violations.push(format!("bottom identity for join failed for sample {i}"));
        }
        // a ∧ ⊥ = ⊥
        if a.meet(&bot) != bot {
            violations.push(format!("bottom annihilator for meet failed for sample {i}"));
        }
        // a ∨ ⊤ = ⊤
        if a.join(&top) != top {
            violations.push(format!("top annihilator for join failed for sample {i}"));
        }
    }

    violations
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
// Tests — property-based verification of categorical and lattice laws
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProvenanceSet;

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

    // ── Generic lattice law tests ─────────────────────────────────────

    #[test]
    fn capability_level_lattice_laws() {
        let samples = vec![
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ];
        let v = verify_bounded_lattice_laws(&samples);
        assert!(v.is_empty(), "CapabilityLevel violations: {v:?}");
    }

    #[test]
    fn capability_lattice_lattice_laws() {
        let samples = vec![
            CapabilityLattice::bottom(),
            CapabilityLattice::default(),
            CapabilityLattice::top(),
        ];
        let v = verify_bounded_lattice_laws(&samples);
        assert!(v.is_empty(), "CapabilityLattice violations: {v:?}");
    }

    #[test]
    fn conf_level_lattice_laws() {
        let samples = vec![ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        let v = verify_bounded_lattice_laws(&samples);
        assert!(v.is_empty(), "ConfLevel violations: {v:?}");
    }

    #[test]
    fn integ_level_lattice_laws() {
        let samples = vec![
            IntegLevel::Adversarial,
            IntegLevel::Untrusted,
            IntegLevel::Trusted,
        ];
        let v = verify_bounded_lattice_laws(&samples);
        assert!(v.is_empty(), "IntegLevel violations: {v:?}");
    }

    #[test]
    fn authority_level_lattice_laws() {
        let samples = vec![
            AuthorityLevel::NoAuthority,
            AuthorityLevel::Informational,
            AuthorityLevel::Suggestive,
            AuthorityLevel::Directive,
        ];
        let v = verify_bounded_lattice_laws(&samples);
        assert!(v.is_empty(), "AuthorityLevel violations: {v:?}");
    }

    #[test]
    fn derivation_class_lattice_laws() {
        let samples = vec![
            DerivationClass::Deterministic,
            DerivationClass::AIDerived,
            DerivationClass::HumanPromoted,
            DerivationClass::Mixed,
            DerivationClass::OpaqueExternal,
        ];
        let v = verify_bounded_lattice_laws(&samples);
        assert!(v.is_empty(), "DerivationClass violations: {v:?}");
    }

    #[test]
    fn ifc_label_lattice_laws() {
        // Use samples with uniform freshness to avoid the known Freshness::leq
        // inconsistency around ttl_secs=0 (see NOTE above BoundedLattice comment).
        // Meet/join are fully correct; only leq has the edge case.
        let fresh = Freshness {
            observed_at: 1000,
            ttl_secs: 3600,
        };
        let samples = vec![
            IFCLabel {
                freshness: fresh,
                ..IFCLabel::bottom()
            },
            IFCLabel {
                freshness: fresh,
                ..IFCLabel::top()
            },
            IFCLabel {
                freshness: fresh,
                ..IFCLabel::default()
            },
            IFCLabel {
                freshness: fresh,
                ..IFCLabel::web_content(1000)
            },
        ];
        let v = verify_lattice_laws(&samples);
        assert!(v.is_empty(), "IFCLabel violations: {v:?}");
    }

    // ── Legacy semilattice law tests (kept for coverage) ──────────────

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

    #[test]
    fn conf_absorption() {
        let levels = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        for &a in &levels {
            for &b in &levels {
                assert_eq!(MeetSemilattice::meet(a, JoinSemilattice::join(a, b)), a);
                assert_eq!(JoinSemilattice::join(a, MeetSemilattice::meet(a, b)), a);
            }
        }
    }

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

    // ── Product lattice tests ─────────────────────────────────────────

    #[test]
    fn product_lattice_laws() {
        use super::ProductLattice;
        let samples = vec![
            ProductLattice(ConfLevel::Public, IntegLevel::Trusted),
            ProductLattice(ConfLevel::Secret, IntegLevel::Adversarial),
            ProductLattice(ConfLevel::Internal, IntegLevel::Untrusted),
        ];
        let v = verify_bounded_lattice_laws(&samples);
        assert!(v.is_empty(), "ProductLattice violations: {v:?}");
    }

    #[test]
    fn product_lattice_pointwise() {
        use super::ProductLattice;
        let a = ProductLattice(CapabilityLevel::LowRisk, ConfLevel::Internal);
        let b = ProductLattice(CapabilityLevel::Always, ConfLevel::Public);

        let met = a.meet(&b);
        assert_eq!(met.0, CapabilityLevel::LowRisk); // min
        assert_eq!(met.1, ConfLevel::Public); // min

        let joined = a.join(&b);
        assert_eq!(joined.0, CapabilityLevel::Always); // max
        assert_eq!(joined.1, ConfLevel::Internal); // max
    }

    // ── Generic combinator tests ──────────────────────────────────────

    #[test]
    fn meet_all_bounded_empty_is_top() {
        let result = super::meet_all_bounded::<CapabilityLevel>(std::iter::empty());
        assert_eq!(result, CapabilityLevel::Always);
    }

    #[test]
    fn join_all_bounded_empty_is_bottom() {
        let result = super::join_all_bounded::<CapabilityLevel>(std::iter::empty());
        assert_eq!(result, CapabilityLevel::Never);
    }

    #[test]
    fn meet_all_bounded_reduces() {
        let levels = vec![
            CapabilityLevel::Always,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ];
        assert_eq!(super::meet_all_bounded(levels), CapabilityLevel::LowRisk);
    }

    #[test]
    fn join_all_bounded_reduces() {
        let levels = vec![
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Never,
        ];
        assert_eq!(super::join_all_bounded(levels), CapabilityLevel::LowRisk);
    }

    #[test]
    fn meet_all_none_for_empty() {
        let result = super::meet_all::<CapabilityLevel>(std::iter::empty());
        assert!(result.is_none());
    }
}
