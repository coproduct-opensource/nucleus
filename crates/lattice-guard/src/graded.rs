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
use crate::weakening::WeakeningCost;
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

/// Product grade combining trifecta risk and weakening cost.
///
/// The monoid structure is `(max, combine)`:
/// - Risk composes via `max`/join (lattice join)
/// - Cost composes via `combine` (additive base, max multipliers)
///
/// This enables tracking *both* the security risk level and the accumulated
/// cost of permission weakenings through a single graded monad.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RiskCost {
    /// The trifecta risk level
    pub risk: TrifectaRisk,
    /// The accumulated weakening cost
    pub cost: WeakeningCost,
}

impl RiskCost {
    /// Create a new RiskCost from risk and cost components.
    pub fn new(risk: TrifectaRisk, cost: WeakeningCost) -> Self {
        Self { risk, cost }
    }

    /// Create a RiskCost with only risk (zero cost).
    pub fn from_risk(risk: TrifectaRisk) -> Self {
        Self {
            risk,
            cost: WeakeningCost::zero(),
        }
    }

    /// Create a RiskCost with only cost (no risk).
    pub fn from_cost(cost: WeakeningCost) -> Self {
        Self {
            risk: TrifectaRisk::None,
            cost,
        }
    }
}

impl Default for RiskCost {
    fn default() -> Self {
        Self {
            risk: TrifectaRisk::None,
            cost: WeakeningCost::zero(),
        }
    }
}

impl PartialOrd for RiskCost {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RiskCost {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Primary: risk level. Secondary: cost total.
        self.risk
            .cmp(&other.risk)
            .then_with(|| self.cost.cmp(&other.cost))
    }
}

impl RiskGrade for RiskCost {
    fn identity() -> Self {
        RiskCost {
            risk: TrifectaRisk::None,
            cost: WeakeningCost::zero(),
        }
    }

    fn compose(&self, other: &Self) -> Self {
        RiskCost {
            risk: self.risk.compose(&other.risk),
            cost: self.cost.combine(&other.cost),
        }
    }

    fn requires_intervention(&self) -> bool {
        self.risk.requires_intervention()
    }
}

impl std::fmt::Display for RiskCost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "risk={:?}, cost={}", self.risk, self.cost)
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

/// Type alias for the escalation callback in [`GradedPipeline`].
type EscalationCallback<G> = Box<dyn Fn(&G) + Send + Sync>;

/// A graded computation pipeline with an optional escalation callback.
///
/// `GradedPipeline` wraps graded computations to provide:
/// - **Automatic escalation**: fires a callback when the grade crosses the
///   intervention threshold (`requires_intervention() == true`)
/// - **Composable chaining**: `and_then` composes grades and checks escalation
///   after each step
///
/// The pipeline is vendor-agnostic: the callback receives only the grade `G`,
/// not any vendor-specific types. Orchestrators wire their own escalation
/// mechanisms (e.g., SSE events, gRPC notifications) through the callback.
///
/// # Example
///
/// ```rust
/// use lattice_guard::graded::{Graded, GradedPipeline};
/// use lattice_guard::TrifectaRisk;
/// use std::sync::atomic::{AtomicBool, Ordering};
/// use std::sync::Arc;
///
/// let escalated = Arc::new(AtomicBool::new(false));
/// let flag = escalated.clone();
///
/// let pipeline = GradedPipeline::new()
///     .with_escalation(move |risk: &TrifectaRisk| {
///         flag.store(true, Ordering::SeqCst);
///     });
///
/// // Safe computation -- no escalation
/// let safe = Graded::new(TrifectaRisk::Low, 42);
/// let result = pipeline.run(safe);
/// assert!(!escalated.load(Ordering::SeqCst));
///
/// // Risky computation -- triggers escalation
/// let risky = Graded::new(TrifectaRisk::Complete, 99);
/// let result = pipeline.run(risky);
/// assert!(escalated.load(Ordering::SeqCst));
/// ```
pub struct GradedPipeline<G: RiskGrade> {
    on_escalation: Option<EscalationCallback<G>>,
}

impl<G: RiskGrade> GradedPipeline<G> {
    /// Create a new pipeline with no escalation callback.
    pub fn new() -> Self {
        Self {
            on_escalation: None,
        }
    }

    /// Attach an escalation callback that fires when the grade crosses the
    /// intervention threshold.
    pub fn with_escalation(mut self, f: impl Fn(&G) + Send + Sync + 'static) -> Self {
        self.on_escalation = Some(Box::new(f));
        self
    }

    /// Run a graded computation through the pipeline, triggering escalation
    /// if the grade requires intervention.
    ///
    /// The computation is returned unchanged; this method only observes.
    pub fn run<A>(&self, computation: Graded<G, A>) -> Graded<G, A> {
        if computation.grade.requires_intervention() {
            if let Some(ref f) = self.on_escalation {
                f(&computation.grade);
            }
        }
        computation
    }

    /// Chain a computation through the pipeline, composing grades and checking
    /// escalation after the bind.
    ///
    /// Equivalent to `self.run(input.and_then(f))`.
    pub fn and_then<A, B>(
        &self,
        input: Graded<G, A>,
        f: impl FnOnce(A) -> Graded<G, B>,
    ) -> Graded<G, B> {
        let result = input.and_then(f);
        self.run(result)
    }

    /// Check whether the pipeline has an escalation callback attached.
    pub fn has_escalation(&self) -> bool {
        self.on_escalation.is_some()
    }
}

impl<G: RiskGrade> Default for GradedPipeline<G> {
    fn default() -> Self {
        Self::new()
    }
}

impl<G: RiskGrade> std::fmt::Debug for GradedPipeline<G> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GradedPipeline")
            .field("has_escalation", &self.on_escalation.is_some())
            .finish()
    }
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

    // ═══════════════════════════════════════════════════════════════════
    // RiskCost tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_risk_cost_identity() {
        let id = RiskCost::identity();
        assert_eq!(id.risk, TrifectaRisk::None);
        assert!(id.cost.is_zero());
    }

    #[test]
    fn test_risk_cost_compose_risk_is_max() {
        let a = RiskCost::from_risk(TrifectaRisk::Low);
        let b = RiskCost::from_risk(TrifectaRisk::Medium);
        let composed = a.compose(&b);

        assert_eq!(composed.risk, TrifectaRisk::Medium);
    }

    #[test]
    fn test_risk_cost_compose_cost_combines() {
        use rust_decimal::Decimal;

        let a = RiskCost::from_cost(WeakeningCost::new(Decimal::new(1, 1))); // 0.1
        let b = RiskCost::from_cost(WeakeningCost::new(Decimal::new(2, 1))); // 0.2
        let composed = a.compose(&b);

        assert_eq!(composed.cost.base, Decimal::new(3, 1)); // 0.3
    }

    #[test]
    fn test_risk_cost_compose_full() {
        use rust_decimal::Decimal;

        let a = RiskCost::new(
            TrifectaRisk::Low,
            WeakeningCost::with_trifecta(Decimal::new(1, 1), Decimal::new(2, 0)),
        );
        let b = RiskCost::new(
            TrifectaRisk::Medium,
            WeakeningCost::with_trifecta(Decimal::new(3, 1), Decimal::new(5, 0)),
        );
        let composed = a.compose(&b);

        assert_eq!(composed.risk, TrifectaRisk::Medium);
        assert_eq!(composed.cost.base, Decimal::new(4, 1)); // 0.1 + 0.3
        assert_eq!(composed.cost.trifecta_multiplier, Decimal::new(5, 0)); // max(2, 5)
    }

    #[test]
    fn test_risk_cost_monoid_identity_law() {
        use rust_decimal::Decimal;

        let g = RiskCost::new(TrifectaRisk::Medium, WeakeningCost::new(Decimal::new(5, 1)));

        // identity * g = g
        let left = RiskCost::identity().compose(&g);
        assert_eq!(left.risk, g.risk);
        assert_eq!(left.cost.base, g.cost.base);

        // g * identity = g
        let right = g.compose(&RiskCost::identity());
        assert_eq!(right.risk, g.risk);
        assert_eq!(right.cost.base, g.cost.base);
    }

    #[test]
    fn test_risk_cost_monoid_associativity() {
        use rust_decimal::Decimal;

        let a = RiskCost::new(TrifectaRisk::Low, WeakeningCost::new(Decimal::new(1, 1)));
        let b = RiskCost::new(TrifectaRisk::Medium, WeakeningCost::new(Decimal::new(2, 1)));
        let c = RiskCost::new(
            TrifectaRisk::Complete,
            WeakeningCost::new(Decimal::new(3, 1)),
        );

        // (a * b) * c = a * (b * c)
        let lhs = a.compose(&b).compose(&c);
        let rhs = a.compose(&b.compose(&c));

        assert_eq!(lhs.risk, rhs.risk);
        assert_eq!(lhs.cost.base, rhs.cost.base);
        assert_eq!(lhs.cost.trifecta_multiplier, rhs.cost.trifecta_multiplier);
        assert_eq!(lhs.cost.isolation_multiplier, rhs.cost.isolation_multiplier);
    }

    #[test]
    fn test_risk_cost_requires_intervention() {
        let safe = RiskCost::from_risk(TrifectaRisk::Medium);
        let risky = RiskCost::from_risk(TrifectaRisk::Complete);

        assert!(!safe.requires_intervention());
        assert!(risky.requires_intervention());
    }

    #[test]
    fn test_risk_cost_ordering() {
        use rust_decimal::Decimal;

        let low_cheap = RiskCost::new(TrifectaRisk::Low, WeakeningCost::new(Decimal::new(1, 1)));
        let low_expensive =
            RiskCost::new(TrifectaRisk::Low, WeakeningCost::new(Decimal::new(9, 1)));
        let medium_cheap =
            RiskCost::new(TrifectaRisk::Medium, WeakeningCost::new(Decimal::new(1, 1)));

        // Risk is primary ordering
        assert!(low_cheap < medium_cheap);
        assert!(low_expensive < medium_cheap);

        // Cost is secondary within same risk
        assert!(low_cheap < low_expensive);
    }

    #[test]
    fn test_risk_cost_graded_monad_pure() {
        let g: Graded<RiskCost, i32> = Graded::pure(42);
        assert_eq!(g.grade.risk, TrifectaRisk::None);
        assert!(g.grade.cost.is_zero());
        assert_eq!(g.value, 42);
    }

    #[test]
    fn test_risk_cost_graded_monad_and_then() {
        use rust_decimal::Decimal;

        let g1 = Graded::new(
            RiskCost::new(TrifectaRisk::Low, WeakeningCost::new(Decimal::new(1, 1))),
            10,
        );
        let g2 = g1.and_then(|x| {
            Graded::new(
                RiskCost::new(TrifectaRisk::Medium, WeakeningCost::new(Decimal::new(2, 1))),
                x * 2,
            )
        });

        assert_eq!(g2.grade.risk, TrifectaRisk::Medium);
        assert_eq!(g2.grade.cost.base, Decimal::new(3, 1)); // 0.1 + 0.2
        assert_eq!(g2.value, 20);
    }

    #[test]
    fn test_risk_cost_sequence() {
        use rust_decimal::Decimal;

        let values = vec![
            Graded::new(
                RiskCost::new(TrifectaRisk::None, WeakeningCost::new(Decimal::new(1, 1))),
                1,
            ),
            Graded::new(
                RiskCost::new(TrifectaRisk::Low, WeakeningCost::new(Decimal::new(2, 1))),
                2,
            ),
            Graded::new(
                RiskCost::new(TrifectaRisk::Medium, WeakeningCost::new(Decimal::new(3, 1))),
                3,
            ),
        ];

        let result = sequence(values);

        assert_eq!(result.grade.risk, TrifectaRisk::Medium);
        assert_eq!(result.grade.cost.base, Decimal::new(6, 1)); // 0.1 + 0.2 + 0.3
        assert_eq!(result.value, vec![1, 2, 3]);
    }

    // ═══════════════════════════════════════════════════════════════════
    // GradedPipeline tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn test_pipeline_no_escalation_callback() {
        let pipeline: GradedPipeline<TrifectaRisk> = GradedPipeline::new();
        assert!(!pipeline.has_escalation());

        // Should pass through without panic even with Complete risk
        let risky = Graded::new(TrifectaRisk::Complete, 42);
        let result = pipeline.run(risky);
        assert_eq!(result.grade, TrifectaRisk::Complete);
        assert_eq!(result.value, 42);
    }

    #[test]
    fn test_pipeline_escalation_fires_on_intervention() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let fired = Arc::new(AtomicBool::new(false));
        let flag = fired.clone();

        let pipeline = GradedPipeline::new().with_escalation(move |_: &TrifectaRisk| {
            flag.store(true, Ordering::SeqCst);
        });

        // Below intervention threshold: should NOT fire
        let safe = Graded::new(TrifectaRisk::Medium, 42);
        let _ = pipeline.run(safe);
        assert!(!fired.load(Ordering::SeqCst));

        // At intervention threshold: should fire
        let risky = Graded::new(TrifectaRisk::Complete, 99);
        let _ = pipeline.run(risky);
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn test_pipeline_escalation_does_not_fire_below_threshold() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        let count = Arc::new(AtomicU32::new(0));
        let counter = count.clone();

        let pipeline = GradedPipeline::new().with_escalation(move |_: &TrifectaRisk| {
            counter.fetch_add(1, Ordering::SeqCst);
        });

        // None, Low, Medium: all below intervention
        for risk in [TrifectaRisk::None, TrifectaRisk::Low, TrifectaRisk::Medium] {
            let g = Graded::new(risk, 42);
            let _ = pipeline.run(g);
        }

        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_pipeline_and_then_composes_and_checks() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let fired = Arc::new(AtomicBool::new(false));
        let flag = fired.clone();

        let pipeline = GradedPipeline::new().with_escalation(move |_: &TrifectaRisk| {
            flag.store(true, Ordering::SeqCst);
        });

        // Start below threshold, compose to above threshold
        let start = Graded::new(TrifectaRisk::Medium, 10);
        let result = pipeline.and_then(start, |x| Graded::new(TrifectaRisk::Complete, x * 2));

        assert_eq!(result.grade, TrifectaRisk::Complete);
        assert_eq!(result.value, 20);
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn test_pipeline_and_then_no_escalation_when_safe() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let fired = Arc::new(AtomicBool::new(false));
        let flag = fired.clone();

        let pipeline = GradedPipeline::new().with_escalation(move |_: &TrifectaRisk| {
            flag.store(true, Ordering::SeqCst);
        });

        let start = Graded::new(TrifectaRisk::Low, 10);
        let result = pipeline.and_then(start, |x| Graded::new(TrifectaRisk::Low, x + 5));

        assert_eq!(result.grade, TrifectaRisk::Low);
        assert_eq!(result.value, 15);
        assert!(!fired.load(Ordering::SeqCst));
    }

    #[test]
    fn test_pipeline_with_risk_cost() {
        use rust_decimal::Decimal;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let fired = Arc::new(AtomicBool::new(false));
        let flag = fired.clone();

        let pipeline = GradedPipeline::new().with_escalation(move |grade: &RiskCost| {
            // Callback receives the full RiskCost
            assert_eq!(grade.risk, TrifectaRisk::Complete);
            flag.store(true, Ordering::SeqCst);
        });

        let start = Graded::new(
            RiskCost::new(TrifectaRisk::Medium, WeakeningCost::new(Decimal::new(2, 1))),
            "hello",
        );

        let result = pipeline.and_then(start, |s| {
            Graded::new(
                RiskCost::new(
                    TrifectaRisk::Complete,
                    WeakeningCost::new(Decimal::new(5, 1)),
                ),
                format!("{} world", s),
            )
        });

        assert_eq!(result.grade.risk, TrifectaRisk::Complete);
        assert_eq!(result.grade.cost.base, Decimal::new(7, 1)); // 0.2 + 0.5
        assert_eq!(result.value, "hello world");
        assert!(fired.load(Ordering::SeqCst));
    }

    #[test]
    fn test_pipeline_default() {
        let pipeline: GradedPipeline<TrifectaRisk> = GradedPipeline::default();
        assert!(!pipeline.has_escalation());
    }

    #[test]
    fn test_pipeline_debug() {
        let pipeline: GradedPipeline<TrifectaRisk> = GradedPipeline::new();
        let debug = format!("{:?}", pipeline);
        assert!(debug.contains("GradedPipeline"));
        assert!(debug.contains("has_escalation"));
    }

    #[test]
    fn test_risk_cost_display() {
        use rust_decimal::Decimal;

        let rc = RiskCost::new(TrifectaRisk::Medium, WeakeningCost::new(Decimal::new(5, 1)));
        let display = format!("{}", rc);
        assert!(display.contains("Medium"));
        assert!(display.contains("0.5")); // base cost in display
    }
}
