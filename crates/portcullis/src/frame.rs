//! Frame-theoretic foundations for permission lattices.
//!
//! This module provides the categorical foundation for the permission system:
//!
//! - **Lattice**: Basic meet/join operations with partial order
//! - **BoundedLattice**: Adds top (⊤) and bottom (⊥) elements
//! - **DistributiveLattice**: Meet distributes over join
//! - **Frame**: Complete lattice where finite meets distribute over arbitrary joins
//! - **Nucleus**: Closure operator that preserves meets, defining quotient frames
//!
//! # Mathematical Background
//!
//! A **frame** is a complete lattice where binary meets distribute over arbitrary joins:
//! ```text
//! a ∧ (⋁ᵢ bᵢ) = ⋁ᵢ (a ∧ bᵢ)
//! ```
//!
//! A **nucleus** `j: L → L` on a frame L satisfies:
//! 1. `j(j(x)) = j(x)` (idempotent)
//! 2. `x ≤ j(x)` (inflationary) OR `j(x) ≤ x` (deflationary)
//! 3. `j(x ∧ y) = j(x) ∧ j(y)` (preserves meets)
//!
//! The fixed points `Lⱼ = { x : j(x) = x }` form a frame (the quotient frame).
//!
//! **Note on `UninhabitableQuotient`**: this operator satisfies (1) and (2) but
//! NOT (3). It is a **kernel operator** (deflationary + idempotent), not a full
//! frame-theoretic nucleus. The independent Verus prover in `portcullis-verified`
//! formally disproves meet-preservation (`proof_nucleus_not_meet_preserving`).
//! Fixed points remain closed under the **quotient meet** (`PermissionLattice::meet`
//! which re-normalizes internally), not under the raw lattice meet.
//!
//! # Example
//!
//! ```rust
//! use portcullis::frame::{Lattice, BoundedLattice, Nucleus, UninhabitableQuotient};
//! use portcullis::PermissionLattice;
//!
//! // The uninhabitable_state quotient is a nucleus on the permission lattice
//! let nucleus = UninhabitableQuotient::new();
//!
//! let perms = PermissionLattice::permissive();
//! let safe = nucleus.apply(&perms);
//!
//! // The nucleus is idempotent
//! assert_eq!(safe, nucleus.apply(&safe));
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::capability::IncompatibilityConstraint;
use crate::PermissionLattice;

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
/// Note: In a distributive lattice, join also distributes over meet:
/// `a ∨ (b ∧ c) = (a ∨ b) ∧ (a ∨ c)`
pub trait DistributiveLattice: Lattice {}

/// A complete lattice with arbitrary meets and joins.
///
/// # Laws
///
/// - Every subset has a greatest lower bound (meet)
/// - Every subset has a least upper bound (join)
pub trait CompleteLattice: BoundedLattice {
    /// Meet of all elements in an iterator.
    fn meet_all<I: IntoIterator<Item = Self>>(iter: I) -> Self;

    /// Join of all elements in an iterator.
    fn join_all<I: IntoIterator<Item = Self>>(iter: I) -> Self;
}

/// A frame: a complete lattice where finite meets distribute over arbitrary joins.
///
/// Frames are the "algebras of open sets" - they capture the algebraic structure
/// of topology. In our context, they provide the foundation for quotient lattices
/// via nuclei.
///
/// # Law
///
/// `a ∧ (⋁ᵢ bᵢ) = ⋁ᵢ (a ∧ bᵢ)` for all a and arbitrary families {bᵢ}
pub trait Frame: CompleteLattice + DistributiveLattice {}

/// A closure operator on a frame: deflationary and idempotent.
///
/// This trait models a **kernel operator** (also called a deflationary
/// closure operator). In the frame-theoretic literature a full nucleus also
/// requires meet-preservation (`j(x ∧ y) = j(x) ∧ j(y)`), but
/// `UninhabitableQuotient` does **not** satisfy that property — it is
/// formally disproven by the independent Verus proof in `portcullis-verified`
/// (`proof_nucleus_not_meet_preserving`).
///
/// # Properties satisfied by `UninhabitableQuotient`
///
/// 1. **Idempotent**: `j(j(x)) = j(x)`
/// 2. **Deflationary**: `j(x) ≤ x`
///
/// # Property NOT satisfied
///
/// 3. **Meet-preserving** `j(x ∧ y) = j(x) ∧ j(y)` — this does **NOT** hold
///    for `UninhabitableQuotient`. Counterexample (see Verus proof):
///    `a` = full caps (uninhabitable-complete), empty obligations;
///    `b` = no-private-access caps, empty obligations.
///    `j(a∧b)` adds no obligations (meet caps are not uninhabitable),
///    but `j(a)∧j(b)` retains `j(a)`'s exfiltration-approval obligations.
///
/// # Why `SafePermissionLattice::meet` is still safe
///
/// `PermissionLattice::meet` is the **quotient meet** — it re-applies the
/// uninhabitable_state constraint internally (via `obligations_for`). Fixed
/// points are therefore closed under the quotient meet even without
/// meet-preservation of the raw operator.
///
/// # Security Application
///
/// The uninhabitable_state constraint is modeled as this kernel operator.
/// The quotient contains only configurations where uninhabitable_state is
/// either absent or gated by approval obligations.
pub trait Nucleus<L: Frame> {
    /// Apply the nucleus operator.
    fn apply(&self, x: &L) -> L;

    /// Check if an element is a fixed point of this nucleus.
    fn is_fixed_point(&self, x: &L) -> bool {
        self.apply(x) == *x
    }

    /// Check if the nucleus is deflationary: j(x) ≤ x.
    fn is_deflationary(&self, x: &L) -> bool {
        self.apply(x).leq(x)
    }
}

/// The uninhabitable_state quotient nucleus.
///
/// This nucleus projects the permission lattice onto the quotient of safe
/// configurations. When the uninhabitable_state (private data + untrusted content +
/// exfiltration) is detected, approval obligations are added to break the uninhabitable_state.
///
/// # Mathematical Structure
///
/// ```text
/// L  = Full permission lattice (unrestricted)
/// L' = { x ∈ L : j(x) = x }  (safe quotient)
///
/// j(x) = x with approval obligations for exfiltration if uninhabitable_state detected
/// ```
#[derive(Debug, Clone, Default)]
pub struct UninhabitableQuotient {
    constraint: IncompatibilityConstraint,
}

impl UninhabitableQuotient {
    /// Create a new uninhabitable_state quotient nucleus.
    pub fn new() -> Self {
        Self {
            constraint: IncompatibilityConstraint::enforcing(),
        }
    }

    /// Create a disabled quotient (identity nucleus).
    ///
    /// # Security Warning
    ///
    /// This creates a nucleus that does NOT enforce the uninhabitable_state constraint.
    /// Only available with the `testing` feature enabled.
    ///
    /// **DO NOT** use in production code.
    #[cfg(feature = "testing")]
    pub fn disabled() -> Self {
        Self {
            constraint: IncompatibilityConstraint::default(),
        }
    }

    /// Check if the constraint is enforcing.
    pub fn is_enforcing(&self) -> bool {
        self.constraint.enforce_uninhabitable
    }
}

impl Nucleus<PermissionLattice> for UninhabitableQuotient {
    fn apply(&self, x: &PermissionLattice) -> PermissionLattice {
        if !self.constraint.enforce_uninhabitable {
            return x.clone();
        }

        let mut result = x.clone();
        result.uninhabitable_constraint = true;
        result.normalize()
    }
}

/// A permission lattice guaranteed to be in the safe quotient.
///
/// This newtype provides a compile-time guarantee that the permission
/// configuration is a fixed point of the uninhabitable_state nucleus. The only way
/// to construct a `SafePermissionLattice` is through the nucleus projection.
///
/// # Example
///
/// ```rust
/// use portcullis::frame::{SafePermissionLattice, UninhabitableQuotient, Nucleus};
/// use portcullis::PermissionLattice;
///
/// let nucleus = UninhabitableQuotient::new();
/// let perms = PermissionLattice::permissive();
///
/// // Project through the nucleus to get a safe lattice
/// let safe = SafePermissionLattice::from_nucleus(&nucleus, perms);
///
/// // The inner permissions are guaranteed to be uninhabitable_state-safe
/// assert!(nucleus.is_fixed_point(safe.inner()));
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SafePermissionLattice(PermissionLattice);

impl SafePermissionLattice {
    /// Create a safe permission lattice by projecting through a nucleus.
    ///
    /// This is the canonical way to construct a `SafePermissionLattice`,
    /// ensuring the uninhabitable_state invariant holds.
    pub fn from_nucleus<N: Nucleus<PermissionLattice>>(
        nucleus: &N,
        perms: PermissionLattice,
    ) -> Self {
        Self(nucleus.apply(&perms))
    }

    /// Create a safe permission lattice from a pre-normalized lattice.
    ///
    /// # Panics
    ///
    /// Panics if the lattice is not a fixed point of the uninhabitable_state nucleus.
    /// This check runs in both debug AND release builds for security.
    ///
    /// # Security Note
    ///
    /// Prefer using `from_nucleus` which guarantees safety by construction.
    /// This method is provided for deserialization and interop scenarios
    /// where the lattice is known to be normalized.
    pub fn from_normalized(perms: PermissionLattice) -> Self {
        // SECURITY: Runtime check that cannot be stripped in release builds.
        // This prevents bypassing the uninhabitable_state safety guarantee.
        assert!(
            perms.uninhabitable_constraint,
            "SafePermissionLattice::from_normalized called on unnormalized lattice - \
             this is a security violation. Use from_nucleus() instead."
        );
        Self(perms)
    }

    /// Access the inner permission lattice.
    pub fn inner(&self) -> &PermissionLattice {
        &self.0
    }

    /// Consume and return the inner permission lattice.
    pub fn into_inner(self) -> PermissionLattice {
        self.0
    }

    /// Meet of two safe permission lattices.
    ///
    /// The result is safe because `PermissionLattice::meet` is the **quotient
    /// meet** — it re-applies the uninhabitable_state normalization internally
    /// (via `IncompatibilityConstraint::obligations_for`). This is distinct
    /// from the meet-preservation property `j(x∧y) = j(x)∧j(y)`, which does
    /// NOT hold for the raw `UninhabitableQuotient` nucleus operator (see
    /// `proof_nucleus_not_meet_preserving` in `portcullis-verified`).
    pub fn meet(&self, other: &Self) -> Self {
        Self(self.0.meet(&other.0))
    }

    /// Delegate to another agent, producing a safe permission lattice.
    pub fn delegate_to(
        &self,
        requested: &PermissionLattice,
        reason: &str,
    ) -> Result<Self, crate::DelegationError> {
        self.0.delegate_to(requested, reason).map(Self)
    }
}

// Implement Lattice for PermissionLattice (delegate to existing methods)
impl Lattice for PermissionLattice {
    fn meet(&self, other: &Self) -> Self {
        PermissionLattice::meet(self, other)
    }

    fn join(&self, other: &Self) -> Self {
        PermissionLattice::join(self, other)
    }

    fn leq(&self, other: &Self) -> bool {
        PermissionLattice::leq(self, other)
    }
}

impl BoundedLattice for PermissionLattice {
    fn top() -> Self {
        PermissionLattice::permissive()
    }

    fn bottom() -> Self {
        PermissionLattice::restrictive()
    }
}

impl DistributiveLattice for PermissionLattice {}

impl CompleteLattice for PermissionLattice {
    fn meet_all<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        iter.into_iter()
            .reduce(|a, b| a.meet(&b))
            .unwrap_or_else(Self::top)
    }

    fn join_all<I: IntoIterator<Item = Self>>(iter: I) -> Self {
        iter.into_iter()
            .reduce(|a, b| a.join(&b))
            .unwrap_or_else(Self::bottom)
    }
}

impl Frame for PermissionLattice {}

/// A composed nucleus: `j₂ ∘ j₁`.
///
/// Given nuclei `j₁` and `j₂`, the composition `j₂(j₁(x))` is itself a
/// nucleus when both nuclei commute (j₁ ∘ j₂ = j₂ ∘ j₁). This combinator
/// applies them in sequence and re-applies until a fixed point is reached,
/// guaranteeing idempotency.
///
/// # Convergence
///
/// The stabilization loop applies at most `max_iterations` rounds of
/// `j₂(j₁(x))` until `x` stops changing. For finite lattices (like
/// `PermissionLattice`), convergence is guaranteed by monotonicity.
pub struct ComposedNucleus<L: Frame, N1: Nucleus<L>, N2: Nucleus<L>> {
    first: N1,
    second: N2,
    max_iterations: usize,
    _phantom: std::marker::PhantomData<L>,
}

impl<L: Frame, N1: Nucleus<L>, N2: Nucleus<L>> ComposedNucleus<L, N1, N2> {
    /// Compose two nuclei: `second ∘ first`.
    pub fn new(first: N1, second: N2) -> Self {
        Self {
            first,
            second,
            max_iterations: 10,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<L: Frame, N1: Nucleus<L>, N2: Nucleus<L>> Nucleus<L> for ComposedNucleus<L, N1, N2> {
    fn apply(&self, x: &L) -> L {
        let mut current = self.second.apply(&self.first.apply(x));
        // Stabilize: keep applying until fixed point (guarantees idempotency)
        for _ in 0..self.max_iterations {
            let next = self.second.apply(&self.first.apply(&current));
            if next == current {
                break;
            }
            current = next;
        }
        current
    }
}

/// Errors from nucleus law verification.
#[derive(Debug, Clone)]
pub struct NucleusLawViolation {
    /// Which law was violated.
    pub law: NucleusLaw,
    /// Human-readable description of the violation.
    pub description: String,
    /// Which sample index triggered the violation.
    pub sample_index: usize,
}

/// Verifiable properties of a kernel/nucleus operator.
///
/// **Note on `MeetPreservation`**: the frame-theoretic nucleus axiom
/// `j(x∧y) = j(x)∧j(y)` is listed here for completeness, but
/// `UninhabitableQuotient` does **not** satisfy it. The independent Verus
/// proof `proof_nucleus_not_meet_preserving` in `portcullis-verified`
/// provides a concrete witness. Do not assert `MeetPreservation` passes for
/// `UninhabitableQuotient` — see `proof_nucleus_counterexample_witness` in
/// `portcullis/src/kani.rs` for the regression harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NucleusLaw {
    /// `j(j(x)) = j(x)`
    Idempotency,
    /// `j(x) ≤ x` (deflationary)
    Deflation,
    /// `j(x ∧ y) = j(x) ∧ j(y)` — NOT satisfied by `UninhabitableQuotient`.
    /// Only holds for certain input pairs (e.g., both already fixed points).
    MeetPreservation,
}

impl std::fmt::Display for NucleusLaw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idempotency => write!(f, "Idempotency: j(j(x)) = j(x)"),
            Self::Deflation => write!(f, "Deflation: j(x) ≤ x"),
            Self::MeetPreservation => write!(f, "Meet preservation: j(x ∧ y) = j(x) ∧ j(y)"),
        }
    }
}

impl std::fmt::Display for NucleusLawViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Nucleus law violation ({}): {} [sample {}]",
            self.law, self.description, self.sample_index
        )
    }
}

/// Verify that a nucleus satisfies idempotency and deflation against sample inputs.
///
/// This checks idempotency (`j(j(x)) = j(x)`), deflation (`j(x) ≤ x`), and
/// optionally meet-preservation (`j(x∧y) = j(x)∧j(y)`) across the provided
/// samples. Meet-preservation violations are **expected** for
/// `UninhabitableQuotient` when samples include inputs with full capabilities
/// and empty obligations — see `proof_nucleus_counterexample_witness` in
/// `portcullis/src/kani.rs`.
///
/// The sample set `[permissive, restrictive, default, codegen]` happens to
/// avoid the meet-preservation counterexample because `permissive()` and
/// `restrictive()` both call `normalize()`, which pre-populates obligations
/// before any nucleus application. Raw inputs with empty obligations (as the
/// Verus witness uses) are needed to trigger the violation.
///
/// # Example
///
/// ```rust
/// use portcullis::frame::{UninhabitableQuotient, NucleusLaw, verify_nucleus_laws};
/// use portcullis::PermissionLattice;
///
/// let nucleus = UninhabitableQuotient::new();
/// let samples = vec![
///     PermissionLattice::permissive(),
///     PermissionLattice::restrictive(),
///     PermissionLattice::default(),
/// ];
///
/// let violations = verify_nucleus_laws(&nucleus, &samples);
/// // Idempotency and deflation always hold; meet-preservation does NOT hold
/// // in general for UninhabitableQuotient (Verus-proven counterexample exists).
/// let hard_violations: Vec<_> = violations.iter()
///     .filter(|v| v.law != NucleusLaw::MeetPreservation)
///     .collect();
/// assert!(hard_violations.is_empty(), "Idempotency/deflation violated: {:?}", hard_violations);
/// ```
pub fn verify_nucleus_laws<N: Nucleus<PermissionLattice>>(
    nucleus: &N,
    samples: &[PermissionLattice],
) -> Vec<NucleusLawViolation> {
    let mut violations = Vec::new();

    for (i, x) in samples.iter().enumerate() {
        let jx = nucleus.apply(x);

        // Law 1: Idempotency — j(j(x)) = j(x)
        let jjx = nucleus.apply(&jx);
        if jjx.capabilities != jx.capabilities || jjx.obligations != jx.obligations {
            violations.push(NucleusLawViolation {
                law: NucleusLaw::Idempotency,
                description: format!(
                    "j(j(x)) ≠ j(x): capabilities or obligations differ for sample '{}'",
                    x.description
                ),
                sample_index: i,
            });
        }

        // Law 2: Deflation — j(x) ≤ x
        if !jx.capabilities.leq(&x.capabilities) {
            violations.push(NucleusLawViolation {
                law: NucleusLaw::Deflation,
                description: format!("j(x) > x in capabilities for sample '{}'", x.description),
                sample_index: i,
            });
        }

        // Law 3: Meet preservation — j(x ∧ y) = j(x) ∧ j(y) for all pairs
        for (j, y) in samples.iter().enumerate() {
            if j <= i {
                continue; // avoid duplicate pairs
            }
            let jx_meet_jy = nucleus.apply(x).meet(&nucleus.apply(y));
            let j_x_meet_y = nucleus.apply(&x.meet(y));

            if j_x_meet_y.capabilities != jx_meet_jy.capabilities
                || j_x_meet_y.obligations != jx_meet_jy.obligations
            {
                violations.push(NucleusLawViolation {
                    law: NucleusLaw::MeetPreservation,
                    description: format!(
                        "j(x∧y) ≠ j(x)∧j(y) for samples '{}' and '{}'",
                        x.description, y.description
                    ),
                    sample_index: i,
                });
            }
        }
    }

    violations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityLevel, Operation};

    #[test]
    fn test_nucleus_is_idempotent() {
        let nucleus = UninhabitableQuotient::new();
        let perms = PermissionLattice::permissive();

        let once = nucleus.apply(&perms);
        let twice = nucleus.apply(&once);

        assert_eq!(once, twice, "Nucleus must be idempotent");
    }

    #[test]
    fn test_nucleus_is_deflationary() {
        let nucleus = UninhabitableQuotient::new();

        // A permissive lattice with uninhabitable_state
        let mut perms = PermissionLattice::permissive();
        perms.capabilities.read_files = CapabilityLevel::Always;
        perms.capabilities.web_fetch = CapabilityLevel::LowRisk;
        perms.capabilities.git_push = CapabilityLevel::LowRisk;

        let projected = nucleus.apply(&perms);

        // The projection should be ≤ original (more obligations)
        assert!(
            nucleus.is_deflationary(&perms),
            "Nucleus should be deflationary"
        );
        // Specifically, exfiltration should now require approval
        assert!(projected.requires_approval(Operation::GitPush));
    }

    /// Verify that j(a∧b) = j(a)∧j(b) for the specific (permissive, restrictive)
    /// pair. These inputs both go through `normalize()` which pre-populates
    /// obligations, and happen to avoid the meet-preservation counterexample.
    /// This test does NOT prove general meet-preservation — see
    /// `test_nucleus_does_not_preserve_meets_counterexample` for the violation.
    #[test]
    fn test_nucleus_quotient_meet_fixed_points_for_normalized_inputs() {
        let nucleus = UninhabitableQuotient::new();

        let a = PermissionLattice::permissive();
        let b = PermissionLattice::restrictive();

        // For pre-normalized inputs (both from constructors that call normalize()),
        // j(a∧b) and j(a)∧j(b) agree because the quotient meet re-normalizes.
        let lhs = nucleus.apply(&a.meet(&b));
        let rhs = nucleus.apply(&a).meet(&nucleus.apply(&b));

        assert_eq!(
            lhs.capabilities, rhs.capabilities,
            "Quotient meet must agree for normalized inputs (capabilities)"
        );
        assert_eq!(
            lhs.obligations, rhs.obligations,
            "Quotient meet must agree for normalized inputs (obligations)"
        );
    }

    /// Regression test: the raw `UninhabitableQuotient` nucleus does NOT preserve
    /// meets in general. This is the concrete counterexample from the Verus proof
    /// `proof_nucleus_not_meet_preserving` in `portcullis-verified`.
    ///
    /// Witness:
    /// - `a` = full caps (uninhabitable-complete), empty obligations
    /// - `b` = no private-access caps (read_files/glob/grep = Never), empty obligations
    ///
    /// - `j(a∧b)`: meet caps lose private access → not uninhabitable → no obligations added.
    /// - `j(a)∧j(b)`: j(a) has exfil-approval obligations; those persist in the meet.
    ///   So `j(a∧b) ≠ j(a)∧j(b)`.
    #[test]
    fn test_nucleus_does_not_preserve_meets_counterexample() {
        use crate::CapabilityLevel;

        let nucleus = UninhabitableQuotient::new();

        // a: full capabilities, uninhabitable-complete, empty obligations (not pre-normalized)
        let mut a = PermissionLattice::default();
        a.capabilities.read_files = CapabilityLevel::Always;
        a.capabilities.write_files = CapabilityLevel::Always;
        a.capabilities.edit_files = CapabilityLevel::Always;
        a.capabilities.run_bash = CapabilityLevel::Always;
        a.capabilities.glob_search = CapabilityLevel::Always;
        a.capabilities.grep_search = CapabilityLevel::Always;
        a.capabilities.web_search = CapabilityLevel::Always;
        a.capabilities.web_fetch = CapabilityLevel::Always;
        a.capabilities.git_commit = CapabilityLevel::Always;
        a.capabilities.git_push = CapabilityLevel::Always;
        a.capabilities.create_pr = CapabilityLevel::Always;
        a.capabilities.manage_pods = CapabilityLevel::Always;
        a.obligations = crate::capability::Obligations::default(); // empty
        a.uninhabitable_constraint = true;

        // b: no private-access capabilities (read/glob/grep = Never), empty obligations
        let mut b = a.clone();
        b.capabilities.read_files = CapabilityLevel::Never;
        b.capabilities.glob_search = CapabilityLevel::Never;
        b.capabilities.grep_search = CapabilityLevel::Never;
        b.obligations = crate::capability::Obligations::default(); // empty

        let ja = nucleus.apply(&a); // full caps + exfil-approval obligations
        let jb = nucleus.apply(&b); // no private access → not uninhabitable → same as b

        // j(a) should have obligations (uninhabitable-complete)
        assert!(
            !ja.obligations.is_empty(),
            "j(a) must add obligations for uninhabitable-complete caps"
        );
        // j(b) should have no obligations (not uninhabitable)
        assert!(
            jb.obligations.is_empty(),
            "j(b) must not add obligations when private access is absent"
        );

        // j(a ∧ b): meet caps = no private access → not uninhabitable → no obligations added
        let j_a_meet_b = nucleus.apply(&a.meet(&b));
        // j(a) ∧ j(b): j(a)'s obligations persist in the meet result
        let ja_meet_jb = ja.meet(&jb);

        // The counterexample: they must differ in obligations
        assert_ne!(
            j_a_meet_b.obligations, ja_meet_jb.obligations,
            "Counterexample regression: j(a∧b) should NOT equal j(a)∧j(b) in obligations \
             (UninhabitableQuotient does not preserve meets — Verus proof_nucleus_not_meet_preserving)"
        );
    }

    #[test]
    fn test_safe_permission_lattice_from_nucleus() {
        let nucleus = UninhabitableQuotient::new();
        let perms = PermissionLattice::permissive();

        let safe = SafePermissionLattice::from_nucleus(&nucleus, perms);

        // The inner lattice should be a fixed point
        assert!(nucleus.is_fixed_point(safe.inner()));
    }

    #[test]
    fn test_safe_permission_lattice_meet_is_safe() {
        let nucleus = UninhabitableQuotient::new();

        let safe_a = SafePermissionLattice::from_nucleus(&nucleus, PermissionLattice::permissive());
        let safe_b = SafePermissionLattice::from_nucleus(&nucleus, PermissionLattice::codegen());

        let result = safe_a.meet(&safe_b);

        // Meet of safe lattices should be safe
        assert!(nucleus.is_fixed_point(result.inner()));
    }

    #[test]
    fn test_bounded_lattice_properties() {
        let top = PermissionLattice::top();
        let bottom = PermissionLattice::bottom();
        let a = PermissionLattice::default();

        // a ∧ ⊤ = a (top is identity for meet)
        assert_eq!(a.meet(&top).capabilities, a.capabilities);

        // a ∨ ⊥ = a (bottom is identity for join)
        assert_eq!(a.join(&bottom).capabilities, a.capabilities);
    }

    #[test]
    fn test_complete_lattice_meet_all() {
        let lattices = vec![
            PermissionLattice::permissive(),
            PermissionLattice::default(),
            PermissionLattice::restrictive(),
        ];

        let result = PermissionLattice::meet_all(lattices);

        // Meet of all should have capabilities ≤ each individual lattice
        assert!(result
            .capabilities
            .leq(&PermissionLattice::permissive().capabilities));
        assert!(result
            .capabilities
            .leq(&PermissionLattice::restrictive().capabilities));
    }

    /// Verify idempotency and deflation hold for UninhabitableQuotient on the
    /// standard sample set. These normalized inputs happen to avoid the
    /// meet-preservation counterexample (all call `normalize()` which
    /// pre-populates obligations). Meet-preservation is intentionally not
    /// asserted as a hard requirement here.
    #[test]
    fn test_verify_nucleus_laws_uninhabitable_quotient() {
        let nucleus = UninhabitableQuotient::new();
        let samples = vec![
            PermissionLattice::permissive(),
            PermissionLattice::restrictive(),
            PermissionLattice::default(),
            PermissionLattice::codegen(),
        ];

        let violations = verify_nucleus_laws(&nucleus, &samples);

        // Only idempotency and deflation are hard requirements.
        // Meet-preservation does NOT hold for UninhabitableQuotient in general
        // (see proof_nucleus_not_meet_preserving in portcullis-verified).
        let hard_violations: Vec<_> = violations
            .iter()
            .filter(|v| v.law != NucleusLaw::MeetPreservation)
            .collect();
        assert!(
            hard_violations.is_empty(),
            "UninhabitableQuotient violated idempotency/deflation: {:?}",
            hard_violations
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_composed_nucleus_is_idempotent() {
        let n1 = UninhabitableQuotient::new();
        let n2 = UninhabitableQuotient::new();
        let composed = ComposedNucleus::new(n1, n2);

        let perms = PermissionLattice::permissive();
        let once = composed.apply(&perms);
        let twice = composed.apply(&once);

        assert_eq!(once.capabilities, twice.capabilities);
        assert_eq!(once.obligations, twice.obligations);
    }

    #[test]
    fn test_composed_nucleus_laws() {
        let n1 = UninhabitableQuotient::new();
        let n2 = UninhabitableQuotient::new();
        let composed = ComposedNucleus::new(n1, n2);

        let samples = vec![
            PermissionLattice::permissive(),
            PermissionLattice::restrictive(),
            PermissionLattice::default(),
        ];

        let violations = verify_nucleus_laws(&composed, &samples);
        assert!(
            violations.is_empty(),
            "ComposedNucleus violated {} law(s): {:?}",
            violations.len(),
            violations.iter().map(|v| v.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    #[cfg(feature = "testing")]
    fn test_disabled_nucleus_is_identity() {
        let nucleus = UninhabitableQuotient::disabled();

        let mut perms = PermissionLattice::permissive();
        perms.uninhabitable_constraint = false;

        let result = nucleus.apply(&perms);

        // Disabled nucleus should be identity
        assert_eq!(result.capabilities, perms.capabilities);
    }
}
