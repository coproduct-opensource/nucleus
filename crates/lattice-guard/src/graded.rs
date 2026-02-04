//! Graded monad for composable risk tracking.
//!
//! A **graded monad** `M` indexed by a monoid `(G, *, 1)` provides:
//! - `pure: A → M₁(A)` (pure computations have unit grade)
//! - `bind: Mₘ(A) → (A → Mₕ(B)) → M_{g*h}(B)` (grades compose via monoid operation)
//!
//! # Security Applications
//!
//! The `TrifectaRisk` enum (`None < Low < Medium < Complete`) is already a graded
//! structure. Formalizing it as a graded monad enables:
//!
//! - **Composable risk tracking**: Risk accumulates correctly through operation chains
//! - **Type-level documentation**: Function signatures show risk levels
//! - **Foundation for compile-time analysis**: With const generics evolution
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::graded::{Graded, RiskGrade};
//! use lattice_guard::TrifectaRisk;
//!
//! // Pure computation with no risk
//! let safe: Graded<TrifectaRisk, i32> = Graded::pure(42);
//! assert_eq!(safe.grade, TrifectaRisk::None);
//!
//! // Chain computations, accumulating risk
//! let result = safe
//!     .and_then(|x| Graded::new(TrifectaRisk::Low, x * 2))
//!     .and_then(|x| Graded::new(TrifectaRisk::Medium, x + 1));
//!
//! // Risk composes to the maximum
//! assert_eq!(result.grade, TrifectaRisk::Medium);
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::capability::{IncompatibilityConstraint, TrifectaRisk};
use crate::PermissionLattice;

/// A monoid structure for grading computations.
///
/// # Monoid Laws
///
/// - Identity: `compose(identity(), g) = g = compose(g, identity())`
/// - Associativity: `compose(compose(a, b), c) = compose(a, compose(b, c))`
pub trait RiskGrade: Sized + Clone + PartialEq + Eq + PartialOrd + Ord + Default {
    /// Identity element (no risk).
    fn identity() -> Self;

    /// Compose two grades (typically max/join for risk).
    fn compose(&self, other: &Self) -> Self;

    /// Check if this grade requires human intervention.
    fn requires_intervention(&self) -> bool;
}

impl RiskGrade for TrifectaRisk {
    fn identity() -> Self {
        TrifectaRisk::None
    }

    fn compose(&self, other: &Self) -> Self {
        // Risk composition is join (maximum)
        self.join(other)
    }

    fn requires_intervention(&self) -> bool {
        TrifectaRisk::requires_intervention(self)
    }
}

/// A graded computation tracking risk level.
///
/// This is a graded monad where the grade is a risk level and the
/// value is the result of the computation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Graded<G: RiskGrade, A> {
    /// The risk grade of this computation
    pub grade: G,
    /// The computed value
    pub value: A,
}

impl<G: RiskGrade, A> Graded<G, A> {
    /// Create a graded value with a specific grade.
    pub fn new(grade: G, value: A) -> Self {
        Self { grade, value }
    }

    /// Pure computation with identity (no) risk.
    ///
    /// This is the `pure` operation of the graded monad.
    pub fn pure(value: A) -> Self {
        Self {
            grade: G::identity(),
            value,
        }
    }

    /// Map a function over the value, preserving the grade.
    ///
    /// This is the `fmap` operation (functor).
    pub fn map<B, F: FnOnce(A) -> B>(self, f: F) -> Graded<G, B> {
        Graded {
            grade: self.grade,
            value: f(self.value),
        }
    }

    /// Chain computations, composing grades.
    ///
    /// This is the `bind` (>>=) operation of the graded monad.
    /// The resulting grade is the composition of both grades.
    pub fn and_then<B, F>(self, f: F) -> Graded<G, B>
    where
        F: FnOnce(A) -> Graded<G, B>,
    {
        let result = f(self.value);
        Graded {
            grade: self.grade.compose(&result.grade),
            value: result.value,
        }
    }

    /// Check if this computation requires intervention.
    pub fn requires_intervention(&self) -> bool {
        self.grade.requires_intervention()
    }

    /// Elevate the risk grade (can only increase, never decrease).
    pub fn elevate(self, new_grade: G) -> Self {
        Self {
            grade: self.grade.compose(&new_grade),
            value: self.value,
        }
    }

    /// Extract the value, discarding the grade.
    pub fn into_value(self) -> A {
        self.value
    }

    /// Get a reference to the value.
    pub fn value(&self) -> &A {
        &self.value
    }
}

impl<G: RiskGrade, A: Clone> Graded<G, A> {
    /// Clone the value out of the graded computation.
    pub fn clone_value(&self) -> A {
        self.value.clone()
    }
}

impl<G: RiskGrade, A: Default> Default for Graded<G, A> {
    fn default() -> Self {
        Self::pure(A::default())
    }
}

/// Evaluate an operation and track its trifecta risk.
///
/// This is the primary way to enter the graded monad from a permission context.
pub fn evaluate_with_risk<A, F>(perms: &PermissionLattice, operation: F) -> Graded<TrifectaRisk, A>
where
    F: FnOnce(&PermissionLattice) -> A,
{
    let constraint = IncompatibilityConstraint::enforcing();
    let grade = constraint.trifecta_risk(&perms.capabilities);
    let value = operation(perms);

    Graded { grade, value }
}

/// Sequence multiple graded computations, accumulating risk.
///
/// This is useful when you have multiple independent graded values
/// and want to combine them into one.
pub fn sequence<G: RiskGrade, A>(graded_values: Vec<Graded<G, A>>) -> Graded<G, Vec<A>> {
    let mut grade = G::identity();
    let mut values = Vec::with_capacity(graded_values.len());

    for g in graded_values {
        grade = grade.compose(&g.grade);
        values.push(g.value);
    }

    Graded {
        grade,
        value: values,
    }
}

/// Traverse a list with a graded function, accumulating risk.
pub fn traverse<G: RiskGrade, A, B, F>(items: Vec<A>, f: F) -> Graded<G, Vec<B>>
where
    F: Fn(A) -> Graded<G, B>,
{
    let graded_values: Vec<_> = items.into_iter().map(f).collect();
    sequence(graded_values)
}

/// A graded permission check result.
///
/// Combines the result of a permission check with its risk grade.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GradedPermissionCheck {
    /// Whether the permission check passed
    pub allowed: bool,
    /// The risk grade of the operation
    pub risk: TrifectaRisk,
    /// Human-readable reason for the decision
    pub reason: String,
}

impl GradedPermissionCheck {
    /// Create a new graded permission check.
    pub fn new(allowed: bool, risk: TrifectaRisk, reason: impl Into<String>) -> Self {
        Self {
            allowed,
            risk,
            reason: reason.into(),
        }
    }

    /// Create an allowed check with a given risk.
    pub fn allow(risk: TrifectaRisk, reason: impl Into<String>) -> Self {
        Self::new(true, risk, reason)
    }

    /// Create a denied check.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::new(false, TrifectaRisk::Complete, reason)
    }

    /// Check if this result requires escalation.
    pub fn requires_escalation(&self) -> bool {
        self.risk.requires_intervention() && self.allowed
    }
}

/// Evaluate a permission check with risk grading.
pub fn check_permission_with_risk(
    perms: &PermissionLattice,
    operation: crate::capability::Operation,
) -> GradedPermissionCheck {
    let constraint = IncompatibilityConstraint::enforcing();
    let risk = constraint.trifecta_risk(&perms.capabilities);

    let requires_approval = perms.requires_approval(operation);
    let allowed = !requires_approval || risk != TrifectaRisk::Complete;

    let reason = if requires_approval {
        format!("{:?} requires approval (risk: {:?})", operation, risk)
    } else {
        format!("{:?} allowed (risk: {:?})", operation, risk)
    };

    GradedPermissionCheck::new(allowed, risk, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_graded_pure() {
        let g: Graded<TrifectaRisk, i32> = Graded::pure(42);
        assert_eq!(g.grade, TrifectaRisk::None);
        assert_eq!(g.value, 42);
    }

    #[test]
    fn test_graded_map() {
        let g = Graded::new(TrifectaRisk::Low, 10);
        let mapped = g.map(|x| x * 2);

        assert_eq!(mapped.grade, TrifectaRisk::Low);
        assert_eq!(mapped.value, 20);
    }

    #[test]
    fn test_graded_and_then_composes_risk() {
        let g1 = Graded::new(TrifectaRisk::Low, 10);
        let g2 = g1.and_then(|x| Graded::new(TrifectaRisk::Medium, x * 2));

        // Risk should be composed (max of Low and Medium)
        assert_eq!(g2.grade, TrifectaRisk::Medium);
        assert_eq!(g2.value, 20);
    }

    #[test]
    fn test_graded_monad_left_identity() {
        // pure(a).and_then(f) = f(a)
        let a = 42;
        let f = |x: i32| Graded::new(TrifectaRisk::Low, x * 2);

        let lhs = Graded::<TrifectaRisk, _>::pure(a).and_then(f);
        let rhs = f(a);

        assert_eq!(lhs.value, rhs.value);
        // Grade: identity * g = g
        assert_eq!(lhs.grade, rhs.grade);
    }

    #[test]
    fn test_graded_monad_right_identity() {
        // m.and_then(pure) = m
        let m = Graded::new(TrifectaRisk::Medium, 42);
        let result = m.clone().and_then(Graded::pure);

        assert_eq!(result.value, m.value);
        // Grade: g * identity = g
        assert_eq!(result.grade, m.grade);
    }

    #[test]
    fn test_graded_monad_associativity() {
        // (m.and_then(f)).and_then(g) = m.and_then(|x| f(x).and_then(g))
        let m = Graded::new(TrifectaRisk::Low, 10);
        let f = |x: i32| Graded::new(TrifectaRisk::Low, x * 2);
        let g = |x: i32| Graded::new(TrifectaRisk::Medium, x + 1);

        let lhs = m.clone().and_then(f).and_then(g);
        let rhs = m.and_then(|x| f(x).and_then(g));

        assert_eq!(lhs.value, rhs.value);
        assert_eq!(lhs.grade, rhs.grade);
    }

    #[test]
    fn test_risk_grade_identity() {
        let g = TrifectaRisk::Medium;

        // identity * g = g
        assert_eq!(TrifectaRisk::identity().compose(&g), g);

        // g * identity = g
        assert_eq!(g.compose(&TrifectaRisk::identity()), g);
    }

    #[test]
    fn test_risk_grade_associativity() {
        let a = TrifectaRisk::Low;
        let b = TrifectaRisk::Medium;
        let c = TrifectaRisk::Complete;

        // (a * b) * c = a * (b * c)
        let lhs = a.compose(&b).compose(&c);
        let rhs = a.compose(&b.compose(&c));

        assert_eq!(lhs, rhs);
    }

    #[test]
    fn test_sequence() {
        let graded_values = vec![
            Graded::new(TrifectaRisk::None, 1),
            Graded::new(TrifectaRisk::Low, 2),
            Graded::new(TrifectaRisk::Medium, 3),
        ];

        let result = sequence(graded_values);

        // Grade should be the composition (max) of all
        assert_eq!(result.grade, TrifectaRisk::Medium);
        assert_eq!(result.value, vec![1, 2, 3]);
    }

    #[test]
    fn test_traverse() {
        let items = vec![1, 2, 3];
        let f = |x: i32| {
            let risk = if x > 2 {
                TrifectaRisk::Medium
            } else {
                TrifectaRisk::Low
            };
            Graded::new(risk, x * 2)
        };

        let result = traverse(items, f);

        assert_eq!(result.grade, TrifectaRisk::Medium); // max of all
        assert_eq!(result.value, vec![2, 4, 6]);
    }

    #[test]
    fn test_evaluate_with_risk() {
        let perms = PermissionLattice::permissive();
        let result = evaluate_with_risk(&perms, |p| p.description.clone());

        // Permissive has trifecta, so risk should be Complete
        assert_eq!(result.grade, TrifectaRisk::Complete);
    }

    #[test]
    fn test_evaluate_with_risk_safe_profile() {
        let perms = PermissionLattice::read_only();
        let result = evaluate_with_risk(&perms, |p| p.description.clone());

        // read_only has 1 trifecta component (read_files: Always = private data access)
        // so risk is Low, not None
        assert_eq!(result.grade, TrifectaRisk::Low);
    }

    #[test]
    fn test_graded_permission_check() {
        use crate::capability::Operation;

        let perms = PermissionLattice::fix_issue();
        let check = check_permission_with_risk(&perms, Operation::GitPush);

        // fix_issue should have trifecta risk for git_push
        assert!(check.risk >= TrifectaRisk::Medium);
    }

    #[test]
    fn test_elevate() {
        let g = Graded::new(TrifectaRisk::Low, 42);
        let elevated = g.elevate(TrifectaRisk::Medium);

        assert_eq!(elevated.grade, TrifectaRisk::Medium);
        assert_eq!(elevated.value, 42);
    }

    #[test]
    fn test_requires_intervention() {
        let safe = Graded::new(TrifectaRisk::None, 42);
        let risky = Graded::new(TrifectaRisk::Complete, 42);

        assert!(!safe.requires_intervention());
        assert!(risky.requires_intervention());
    }
}
