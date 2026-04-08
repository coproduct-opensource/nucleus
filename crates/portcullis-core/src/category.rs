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

/// A distributive lattice where meet distributes over join.
///
/// # Law
///
/// `a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c)`
///
/// Equivalently, join distributes over meet:
/// `a ∨ (b ∧ c) = (a ∨ b) ∧ (a ∨ c)`
///
/// Every total order is a distributive lattice. Products of distributive
/// lattices are distributive. This is the key property that makes the
/// Heyting implication `a → b = max{c | c ∧ a ≤ b}` well-defined.
pub trait DistributiveLattice: Lattice {}

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
// Monotone maps — morphisms in the category of lattices
// ═══════════════════════════════════════════════════════════════════════════

/// A monotone map between two lattices: `a ≤ b ⟹ f(a) ≤ f(b)`.
///
/// Monotone maps are the morphisms in **Lat** (the category of lattices).
/// In nucleus, nearly every transformation is supposed to be monotone:
/// - Taint propagation: more tainted input → more tainted output
/// - Delegation narrowing: wider parent → wider child ceiling
/// - Exposure classification: more operations → more exposure
/// - Budget consumption: more cost → less remaining budget
///
/// This trait makes the property testable via [`verify_monotone`].
///
/// # Example
///
/// ```rust
/// use portcullis_core::category::{MonotoneMap, Lattice};
/// use portcullis_core::CapabilityLevel;
///
/// struct Negate;
/// // CapabilityLevel::complement is antitone, not monotone.
/// // This trait catches that at test time.
/// ```
pub trait MonotoneMap<A: Lattice, B: Lattice> {
    /// Apply the map.
    fn apply(&self, x: &A) -> B;
}

/// A join-preserving map (lattice homomorphism for join):
/// `f(a ∨ b) = f(a) ∨ f(b)`.
///
/// Join-preservation implies monotonicity (in a lattice), so this is
/// strictly stronger. Useful for taint propagation, which must preserve
/// the join-semilattice structure.
pub trait JoinPreserving<A: Lattice, B: Lattice>: MonotoneMap<A, B> {}

/// Verify that a map is monotone over a set of samples.
///
/// Checks: for all pairs (a, b) where `a ≤ b`, `f(a) ≤ f(b)`.
/// Returns a list of violations (empty = monotone on the sample set).
pub fn verify_monotone<A: Lattice + std::fmt::Debug, B: Lattice + std::fmt::Debug>(
    f: &dyn MonotoneMap<A, B>,
    samples: &[A],
) -> Vec<String> {
    let mut violations = Vec::new();
    for (i, a) in samples.iter().enumerate() {
        for (j, b) in samples.iter().enumerate() {
            if a.leq(b) {
                let fa = f.apply(a);
                let fb = f.apply(b);
                if !fa.leq(&fb) {
                    violations.push(format!(
                        "monotonicity violated: samples[{i}] ≤ samples[{j}] but f(samples[{i}]) > f(samples[{j}]): \
                         f({a:?}) = {fa:?}, f({b:?}) = {fb:?}"
                    ));
                }
            }
        }
    }
    violations
}

/// Verify that a map preserves joins over a set of samples.
///
/// Checks: `f(a ∨ b) = f(a) ∨ f(b)` for all pairs.
pub fn verify_join_preserving<A: Lattice + std::fmt::Debug, B: Lattice + std::fmt::Debug>(
    f: &dyn MonotoneMap<A, B>,
    samples: &[A],
) -> Vec<String> {
    let mut violations = Vec::new();
    for (i, a) in samples.iter().enumerate() {
        for (j, b) in samples.iter().enumerate() {
            let f_join = f.apply(&a.join(b));
            let join_f = f.apply(a).join(&f.apply(b));
            if f_join != join_f {
                violations.push(format!(
                    "join-preservation violated for samples[{i}], samples[{j}]: \
                     f(a∨b) = {f_join:?}, f(a)∨f(b) = {join_f:?}"
                ));
            }
        }
    }
    violations
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
// DistributiveLattice implementations
// ═══════════════════════════════════════════════════════════════════════════
//
// Every total order is a distributive lattice. Products of distributive
// lattices are distributive. All core types satisfy this.

impl DistributiveLattice for CapabilityLevel {} // 3-element chain
impl DistributiveLattice for CapabilityLattice {} // product of 13 chains
impl DistributiveLattice for ConfLevel {} // 3-element chain
impl DistributiveLattice for IntegLevel {} // 3-element chain
impl DistributiveLattice for AuthorityLevel {} // 4-element chain
impl DistributiveLattice for DerivationClass {} // 5-element lattice (distributive)
impl DistributiveLattice for Freshness {} // product of 2 chains
impl DistributiveLattice for IFCLabel {} // product of distributive lattices

impl<A: DistributiveLattice, B: DistributiveLattice> DistributiveLattice for ProductLattice<A, B> {}

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

/// Verify distributive lattice law: `a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c)`.
///
/// Also checks the dual: `a ∨ (b ∧ c) = (a ∨ b) ∧ (a ∨ c)`.
pub fn verify_distributive_laws<L: Lattice + std::fmt::Debug>(samples: &[L]) -> Vec<String> {
    let mut violations = Vec::new();
    for (i, a) in samples.iter().enumerate() {
        for (j, b) in samples.iter().enumerate() {
            for (k, c) in samples.iter().enumerate() {
                // a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c)
                let lhs = a.meet(&b.join(c));
                let rhs = a.meet(b).join(&a.meet(c));
                if lhs != rhs {
                    violations.push(format!(
                        "meet-over-join distributivity failed for samples {i}, {j}, {k}"
                    ));
                }
                // a ∨ (b ∧ c) = (a ∨ b) ∧ (a ∨ c)
                let lhs2 = a.join(&b.meet(c));
                let rhs2 = a.join(b).meet(&a.join(c));
                if lhs2 != rhs2 {
                    violations.push(format!(
                        "join-over-meet distributivity failed for samples {i}, {j}, {k}"
                    ));
                }
            }
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

    // ── Distributive lattice tests ────────────────────────────────────

    #[test]
    fn capability_level_distributive() {
        let samples = vec![
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ];
        let v = super::verify_distributive_laws(&samples);
        assert!(
            v.is_empty(),
            "CapabilityLevel distributivity violations: {v:?}"
        );
    }

    #[test]
    fn conf_level_distributive() {
        let samples = vec![ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];
        let v = super::verify_distributive_laws(&samples);
        assert!(v.is_empty(), "ConfLevel distributivity violations: {v:?}");
    }

    #[test]
    fn integ_level_distributive() {
        let samples = vec![
            IntegLevel::Adversarial,
            IntegLevel::Untrusted,
            IntegLevel::Trusted,
        ];
        let v = super::verify_distributive_laws(&samples);
        assert!(v.is_empty(), "IntegLevel distributivity violations: {v:?}");
    }

    #[test]
    fn derivation_class_distributive() {
        let samples = vec![
            DerivationClass::Deterministic,
            DerivationClass::AIDerived,
            DerivationClass::HumanPromoted,
            DerivationClass::Mixed,
            DerivationClass::OpaqueExternal,
        ];
        let v = super::verify_distributive_laws(&samples);
        assert!(
            v.is_empty(),
            "DerivationClass distributivity violations: {v:?}"
        );
    }

    #[test]
    fn product_lattice_distributive() {
        use super::ProductLattice;
        let samples = vec![
            ProductLattice(ConfLevel::Public, IntegLevel::Trusted),
            ProductLattice(ConfLevel::Secret, IntegLevel::Adversarial),
            ProductLattice(ConfLevel::Internal, IntegLevel::Untrusted),
        ];
        let v = super::verify_distributive_laws(&samples);
        assert!(
            v.is_empty(),
            "ProductLattice distributivity violations: {v:?}"
        );
    }

    // ── Monotone map tests ────────────────────────────────────────────

    /// Joining with a fixed label is a monotone endomorphism on IFCLabel.
    /// This is the core taint propagation invariant: if input A ≤ input B,
    /// then (A ⊔ taint) ≤ (B ⊔ taint).
    struct JoinWith(IFCLabel);

    impl super::MonotoneMap<IFCLabel, IFCLabel> for JoinWith {
        fn apply(&self, x: &IFCLabel) -> IFCLabel {
            Lattice::join(x, &self.0)
        }
    }

    #[test]
    fn join_with_trusted_is_monotone() {
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
        ];
        let taint = IFCLabel::web_content(1000);
        let v = super::verify_monotone(&JoinWith(taint), &samples);
        assert!(
            v.is_empty(),
            "join-with-taint monotonicity violations: {v:?}"
        );
    }

    #[test]
    fn join_with_taint_is_join_preserving() {
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
        ];
        let taint = IFCLabel::web_content(1000);
        let v = super::verify_join_preserving(&JoinWith(taint), &samples);
        assert!(
            v.is_empty(),
            "join-with-taint join-preservation violations: {v:?}"
        );
    }

    /// CapabilityLevel::meet with a fixed level is monotone (delegation narrowing).
    struct MeetWithCap(CapabilityLevel);

    impl super::MonotoneMap<CapabilityLevel, CapabilityLevel> for MeetWithCap {
        fn apply(&self, x: &CapabilityLevel) -> CapabilityLevel {
            Lattice::meet(x, &self.0)
        }
    }

    #[test]
    fn delegation_narrowing_is_monotone() {
        let samples = vec![
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ];
        // Narrowing to LowRisk: a parent's ceiling constrains children
        let v = super::verify_monotone(&MeetWithCap(CapabilityLevel::LowRisk), &samples);
        assert!(
            v.is_empty(),
            "delegation narrowing monotonicity violations: {v:?}"
        );
    }
}
