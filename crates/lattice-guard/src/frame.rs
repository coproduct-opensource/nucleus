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
//! # Example
//!
//! ```rust
//! use lattice_guard::frame::{Lattice, BoundedLattice, Nucleus, TrifectaQuotient};
//! use lattice_guard::PermissionLattice;
//!
//! // The trifecta quotient is a nucleus on the permission lattice
//! let nucleus = TrifectaQuotient::new();
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

/// A nucleus on a frame: a closure operator that preserves meets.
///
/// Nuclei define quotient frames. The fixed points of a nucleus form a frame,
/// and the nucleus provides the projection from the original frame to the quotient.
///
/// # Properties
///
/// 1. **Idempotent**: `j(j(x)) = j(x)`
/// 2. **Inflationary** (standard) or **Deflationary** (our case): `j(x) ≤ x`
/// 3. **Meet-preserving**: `j(x ∧ y) = j(x) ∧ j(y)`
///
/// # Security Application
///
/// The trifecta constraint is modeled as a nucleus. The quotient frame
/// contains only "safe" configurations where the lethal trifecta is
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

/// The trifecta quotient nucleus.
///
/// This nucleus projects the permission lattice onto the quotient of safe
/// configurations. When the lethal trifecta (private data + untrusted content +
/// exfiltration) is detected, approval obligations are added to break the trifecta.
///
/// # Mathematical Structure
///
/// ```text
/// L  = Full permission lattice (unrestricted)
/// L' = { x ∈ L : j(x) = x }  (safe quotient)
///
/// j(x) = x with approval obligations for exfiltration if trifecta detected
/// ```
#[derive(Debug, Clone, Default)]
pub struct TrifectaQuotient {
    constraint: IncompatibilityConstraint,
}

impl TrifectaQuotient {
    /// Create a new trifecta quotient nucleus.
    pub fn new() -> Self {
        Self {
            constraint: IncompatibilityConstraint::enforcing(),
        }
    }

    /// Create a disabled quotient (identity nucleus).
    ///
    /// # Security Warning
    ///
    /// This creates a nucleus that does NOT enforce the trifecta constraint.
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
        self.constraint.enforce_trifecta
    }
}

impl Nucleus<PermissionLattice> for TrifectaQuotient {
    fn apply(&self, x: &PermissionLattice) -> PermissionLattice {
        if !self.constraint.enforce_trifecta {
            return x.clone();
        }

        let mut result = x.clone();
        result.trifecta_constraint = true;
        result.normalize()
    }
}

/// A permission lattice guaranteed to be in the safe quotient.
///
/// This newtype provides a compile-time guarantee that the permission
/// configuration is a fixed point of the trifecta nucleus. The only way
/// to construct a `SafePermissionLattice` is through the nucleus projection.
///
/// # Example
///
/// ```rust
/// use lattice_guard::frame::{SafePermissionLattice, TrifectaQuotient, Nucleus};
/// use lattice_guard::PermissionLattice;
///
/// let nucleus = TrifectaQuotient::new();
/// let perms = PermissionLattice::permissive();
///
/// // Project through the nucleus to get a safe lattice
/// let safe = SafePermissionLattice::from_nucleus(&nucleus, perms);
///
/// // The inner permissions are guaranteed to be trifecta-safe
/// assert!(nucleus.is_fixed_point(safe.inner()));
/// ```
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SafePermissionLattice(PermissionLattice);

impl SafePermissionLattice {
    /// Create a safe permission lattice by projecting through a nucleus.
    ///
    /// This is the canonical way to construct a `SafePermissionLattice`,
    /// ensuring the trifecta invariant holds.
    pub fn from_nucleus<N: Nucleus<PermissionLattice>>(nucleus: &N, perms: PermissionLattice) -> Self {
        Self(nucleus.apply(&perms))
    }

    /// Create a safe permission lattice from a pre-normalized lattice.
    ///
    /// # Panics
    ///
    /// Panics if the lattice is not a fixed point of the trifecta nucleus.
    /// This check runs in both debug AND release builds for security.
    ///
    /// # Security Note
    ///
    /// Prefer using `from_nucleus` which guarantees safety by construction.
    /// This method is provided for deserialization and interop scenarios
    /// where the lattice is known to be normalized.
    pub fn from_normalized(perms: PermissionLattice) -> Self {
        // SECURITY: Runtime check that cannot be stripped in release builds.
        // This prevents bypassing the trifecta safety guarantee.
        assert!(
            perms.trifecta_constraint,
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
    /// The result is automatically safe because the meet of fixed points
    /// is a fixed point (nuclei preserve meets).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityLevel, Operation};

    #[test]
    fn test_nucleus_is_idempotent() {
        let nucleus = TrifectaQuotient::new();
        let perms = PermissionLattice::permissive();

        let once = nucleus.apply(&perms);
        let twice = nucleus.apply(&once);

        assert_eq!(once, twice, "Nucleus must be idempotent");
    }

    #[test]
    fn test_nucleus_is_deflationary() {
        let nucleus = TrifectaQuotient::new();

        // A permissive lattice with trifecta
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

    #[test]
    fn test_nucleus_preserves_meets() {
        let nucleus = TrifectaQuotient::new();

        let a = PermissionLattice::permissive();
        let b = PermissionLattice::restrictive();

        // j(a ∧ b) should equal j(a) ∧ j(b)
        let lhs = nucleus.apply(&a.meet(&b));
        let rhs = nucleus.apply(&a).meet(&nucleus.apply(&b));

        // Check both capabilities AND obligations for full lattice equality
        assert_eq!(
            lhs.capabilities, rhs.capabilities,
            "Nucleus must preserve meets (capabilities)"
        );
        assert_eq!(
            lhs.obligations, rhs.obligations,
            "Nucleus must preserve meets (obligations)"
        );
    }

    #[test]
    fn test_safe_permission_lattice_from_nucleus() {
        let nucleus = TrifectaQuotient::new();
        let perms = PermissionLattice::permissive();

        let safe = SafePermissionLattice::from_nucleus(&nucleus, perms);

        // The inner lattice should be a fixed point
        assert!(nucleus.is_fixed_point(safe.inner()));
    }

    #[test]
    fn test_safe_permission_lattice_meet_is_safe() {
        let nucleus = TrifectaQuotient::new();

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
        assert!(result.capabilities.leq(&PermissionLattice::permissive().capabilities));
        assert!(result.capabilities.leq(&PermissionLattice::restrictive().capabilities));
    }

    #[test]
    #[cfg(feature = "testing")]
    fn test_disabled_nucleus_is_identity() {
        let nucleus = TrifectaQuotient::disabled();

        let mut perms = PermissionLattice::permissive();
        perms.trifecta_constraint = false;

        let result = nucleus.apply(&perms);

        // Disabled nucleus should be identity
        assert_eq!(result.capabilities, perms.capabilities);
    }
}
