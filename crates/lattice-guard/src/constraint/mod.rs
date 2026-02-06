//! Constraint algebra for composable policy nuclei.
//!
//! A **constraint** is a predicate that, when true, adds obligations to the
//! permission lattice. Constraints compose into **policies**, which are
//! nuclei on the permission frame.
//!
//! # Mathematical Foundation
//!
//! A policy is a nucleus ν : L → L satisfying:
//!
//! - **Idempotent:** ν(ν(x)) = ν(x)
//! - **Deflationary:** ν(x) ≤ x (obligations can only increase)
//! - **Meet-preserving:** ν(x ∧ y) = ν(x) ∧ ν(y)
//!
//! Policies compose via function composition: (ν₁ ∘ ν₂)(x) = ν₁(ν₂(x))
//!
//! # Example
//!
//! ```rust,ignore
//! use lattice_guard::constraint::{Constraint, Policy, PolicyContext};
//! use lattice_guard::{Operation, PermissionLattice};
//! use lattice_guard::frame::Nucleus;
//!
//! // Create a policy with a custom constraint
//! let policy = Policy::new("secure")
//!     .with_constraint(
//!         Constraint::new("workspace-only",
//!             r#"operation == "write_files" && !path.startsWith("/workspace/")"#
//!         )?.with_obligation(Operation::WriteFiles)
//!     );
//!
//! // Apply as a nucleus
//! let perms = PermissionLattice::permissive();
//! let safe = policy.apply(&perms);
//! ```

mod context;
#[cfg(feature = "spec")]
pub mod spec;

pub use context::*;

use crate::capability::IncompatibilityConstraint;
#[cfg(feature = "cel")]
use crate::capability::TrifectaRisk;
use crate::frame::Nucleus;
use crate::{Obligations, Operation, PermissionLattice};

/// A constraint that gates operations based on a condition.
///
/// When the condition evaluates to `true`, the specified obligations are added.
/// This is **deflationary**: constraints can only add obligations, never remove them.
///
/// # CEL Expressions
///
/// With the `cel` feature, conditions are CEL expressions. Available variables:
///
/// | Variable | Type | Description |
/// |----------|------|-------------|
/// | `operation` | string | Current operation (e.g., "write_files") |
/// | `path` | string | File path being accessed |
/// | `url` | string | URL being fetched |
/// | `trifecta_risk` | string | "none", "low", "medium", "complete" |
/// | `budget_remaining` | float | Budget fraction (0.0-1.0) |
/// | `has_approval` | bool | Whether approval was granted |
/// | `request_rate` | int | Requests per minute |
#[derive(Debug, Clone)]
pub struct Constraint {
    /// Name for debugging/auditing.
    name: String,
    /// Description of what this constraint does.
    description: Option<String>,
    /// The CEL condition source.
    #[cfg(feature = "cel")]
    condition: String,
    /// Obligations to add when condition is true.
    obligations: Obligations,
}

impl Constraint {
    /// Create a new constraint with a CEL condition.
    ///
    /// The condition is validated at construction time to ensure it compiles.
    ///
    /// # Errors
    ///
    /// Returns `CelError::Compile` if the CEL expression is invalid.
    #[cfg(feature = "cel")]
    pub fn new(name: impl Into<String>, condition: impl Into<String>) -> Result<Self, CelError> {
        let condition = condition.into();
        cel_interpreter::Program::compile(&condition)
            .map_err(|e| CelError::Compile(e.to_string()))?;

        Ok(Self {
            name: name.into(),
            description: None,
            condition,
            obligations: Obligations::default(),
        })
    }

    /// Create a constraint that always triggers (no CEL required).
    pub fn always(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            #[cfg(feature = "cel")]
            condition: "true".to_string(),
            obligations: Obligations::default(),
        }
    }

    /// Set a description for auditing.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Add an obligation when this constraint triggers.
    pub fn with_obligation(mut self, op: Operation) -> Self {
        self.obligations.insert(op);
        self
    }

    /// Set all obligations at once.
    pub fn with_obligations(mut self, obligations: Obligations) -> Self {
        self.obligations = obligations;
        self
    }

    /// Get the constraint name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the description.
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Get the obligations that will be added when triggered.
    pub fn obligations(&self) -> &Obligations {
        &self.obligations
    }

    /// Evaluate the constraint against a context.
    ///
    /// Returns the obligations to add if the condition matches, or empty
    /// obligations if it doesn't match.
    #[cfg(feature = "cel")]
    pub fn evaluate(&self, ctx: &PolicyContext) -> Result<Obligations, CelError> {
        if self.matches(ctx)? {
            Ok(self.obligations.clone())
        } else {
            Ok(Obligations::default())
        }
    }

    /// Check if the constraint condition matches the context.
    #[cfg(feature = "cel")]
    pub fn matches(&self, ctx: &PolicyContext) -> Result<bool, CelError> {
        use cel_interpreter::{Context, Program, Value};

        let program =
            Program::compile(&self.condition).map_err(|e| CelError::Compile(e.to_string()))?;

        let mut cel_ctx = Context::default();
        ctx.populate_cel_context(&mut cel_ctx);

        let result = program
            .execute(&cel_ctx)
            .map_err(|e| CelError::Execute(e.to_string()))?;

        match result {
            Value::Bool(b) => Ok(b),
            other => Err(CelError::Type {
                expected: "bool".into(),
                got: format!("{:?}", other),
            }),
        }
    }
}

/// A policy is a nucleus composed of constraints.
///
/// The policy first applies the built-in trifecta constraint (unless disabled),
/// then applies all user-defined constraints in order. Obligations accumulate
/// monotonically (deflationary).
///
/// # As a Nucleus
///
/// `Policy` implements `Nucleus<PermissionLattice>`, making it composable with
/// other nuclei via the frame-theoretic machinery.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Policy name for auditing.
    name: String,
    /// User-defined constraints.
    constraints: Vec<Constraint>,
    /// Whether to apply the built-in trifecta constraint.
    enforce_trifecta: bool,
}

impl Policy {
    /// Create a new policy with trifecta enforcement enabled by default.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            constraints: Vec::new(),
            enforce_trifecta: true,
        }
    }

    /// Add a constraint to the policy.
    pub fn with_constraint(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Disable the built-in trifecta constraint.
    ///
    /// # Security Warning
    ///
    /// This allows the lethal trifecta (private data + untrusted content +
    /// exfiltration) to operate without approval obligations. Only disable
    /// when you have external enforcement mechanisms.
    #[cfg(feature = "testing")]
    pub fn without_trifecta(mut self) -> Self {
        self.enforce_trifecta = false;
        self
    }

    /// Get the policy name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get all constraints.
    pub fn constraints(&self) -> &[Constraint] {
        &self.constraints
    }

    /// Check if trifecta enforcement is enabled.
    pub fn enforces_trifecta(&self) -> bool {
        self.enforce_trifecta
    }

    /// Evaluate the policy against a context, returning accumulated obligations.
    ///
    /// This applies:
    /// 1. The trifecta constraint (if enabled)
    /// 2. All user-defined constraints in order
    ///
    /// Obligations accumulate monotonically via union.
    #[cfg(feature = "cel")]
    pub fn evaluate(&self, ctx: &PolicyContext) -> Result<Obligations, CelError> {
        let mut obligations = Obligations::default();

        // Apply trifecta constraint
        if self.enforce_trifecta {
            let trifecta_obs = self.trifecta_obligations(ctx);
            obligations = obligations.union(&trifecta_obs);
        }

        // Apply user-defined constraints
        for constraint in &self.constraints {
            let obs = constraint.evaluate(ctx)?;
            obligations = obligations.union(&obs);
        }

        Ok(obligations)
    }

    /// Compute trifecta obligations from context.
    #[cfg(feature = "cel")]
    fn trifecta_obligations(&self, ctx: &PolicyContext) -> Obligations {
        let constraint = IncompatibilityConstraint::enforcing();
        let risk = constraint.trifecta_risk(&ctx.capabilities);

        if risk == TrifectaRisk::Complete {
            constraint.obligations_for(&ctx.capabilities)
        } else {
            Obligations::default()
        }
    }
}

/// Policy implements Nucleus, making it composable with the frame machinery.
///
/// When applied to a PermissionLattice:
/// 1. Creates a PolicyContext from the lattice's capabilities
/// 2. Evaluates all constraints
/// 3. Unions the resulting obligations with the lattice's existing obligations
///
/// # Note
///
/// This implementation has limited context (no path/url/etc.) since it only
/// receives the PermissionLattice. For full context evaluation, use
/// `Policy::evaluate()` with a complete `PolicyContext`.
impl Nucleus<PermissionLattice> for Policy {
    fn apply(&self, x: &PermissionLattice) -> PermissionLattice {
        let mut result = x.clone();

        // Apply trifecta constraint
        if self.enforce_trifecta {
            let constraint = IncompatibilityConstraint::enforcing();
            let trifecta_obs = constraint.obligations_for(&result.capabilities);
            result.obligations = result.obligations.union(&trifecta_obs);
        }

        // Apply user-defined constraints (with limited context)
        #[cfg(feature = "cel")]
        {
            let ctx = PolicyContext::new(Operation::ReadFiles)
                .with_capabilities(result.capabilities.clone());

            for constraint in &self.constraints {
                if let Ok(obs) = constraint.evaluate(&ctx) {
                    result.obligations = result.obligations.union(&obs);
                }
            }
        }

        result
    }
}

/// Error type for constraint evaluation.
#[cfg(feature = "cel")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CelError {
    /// CEL expression failed to compile.
    Compile(String),
    /// CEL expression failed to execute.
    Execute(String),
    /// CEL expression returned unexpected type.
    Type {
        /// Expected type (always "bool" for constraints).
        expected: String,
        /// Actual type returned.
        got: String,
    },
}

#[cfg(feature = "cel")]
impl std::fmt::Display for CelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CelError::Compile(msg) => write!(f, "CEL compile error: {}", msg),
            CelError::Execute(msg) => write!(f, "CEL execute error: {}", msg),
            CelError::Type { expected, got } => {
                write!(f, "CEL type error: expected {}, got {}", expected, got)
            }
        }
    }
}

#[cfg(feature = "cel")]
impl std::error::Error for CelError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityLattice, CapabilityLevel};

    #[test]
    fn test_constraint_always() {
        let c = Constraint::always("test").with_obligation(Operation::WriteFiles);
        assert_eq!(c.name(), "test");
        assert!(c.obligations().requires(Operation::WriteFiles));
    }

    #[test]
    #[cfg(feature = "cel")]
    fn test_constraint_cel_valid() {
        let c = Constraint::new("test", r#"operation == "read_files""#);
        assert!(c.is_ok());
    }

    #[test]
    #[cfg(feature = "cel")]
    fn test_constraint_cel_invalid() {
        let c = Constraint::new("test", "invalid {{ cel }}");
        assert!(c.is_err());
    }

    #[test]
    #[cfg(feature = "cel")]
    fn test_constraint_evaluate_true() {
        let c = Constraint::new("test", r#"operation == "write_files""#)
            .unwrap()
            .with_obligation(Operation::WriteFiles);

        let ctx = PolicyContext::new(Operation::WriteFiles);
        let obs = c.evaluate(&ctx).unwrap();

        assert!(obs.requires(Operation::WriteFiles));
    }

    #[test]
    #[cfg(feature = "cel")]
    fn test_constraint_evaluate_false() {
        let c = Constraint::new("test", r#"operation == "write_files""#)
            .unwrap()
            .with_obligation(Operation::WriteFiles);

        let ctx = PolicyContext::new(Operation::ReadFiles);
        let obs = c.evaluate(&ctx).unwrap();

        assert!(!obs.requires(Operation::WriteFiles));
    }

    #[test]
    #[cfg(feature = "cel")]
    fn test_constraint_path_check() {
        let c = Constraint::new("workspace", r#"!path.startsWith("/workspace/")"#)
            .unwrap()
            .with_obligation(Operation::WriteFiles);

        // Outside workspace - triggers
        let ctx = PolicyContext::new(Operation::WriteFiles).with_path("/etc/passwd");
        assert!(c.evaluate(&ctx).unwrap().requires(Operation::WriteFiles));

        // Inside workspace - does not trigger
        let ctx = PolicyContext::new(Operation::WriteFiles).with_path("/workspace/src/main.rs");
        assert!(!c.evaluate(&ctx).unwrap().requires(Operation::WriteFiles));
    }

    #[test]
    #[cfg(feature = "cel")]
    fn test_policy_accumulates_obligations() {
        let policy = Policy::new("test")
            .with_constraint(
                Constraint::new("c1", "true")
                    .unwrap()
                    .with_obligation(Operation::ReadFiles),
            )
            .with_constraint(
                Constraint::new("c2", "true")
                    .unwrap()
                    .with_obligation(Operation::WriteFiles),
            );

        let ctx = PolicyContext::new(Operation::ReadFiles);
        let obs = policy.evaluate(&ctx).unwrap();

        assert!(obs.requires(Operation::ReadFiles));
        assert!(obs.requires(Operation::WriteFiles));
    }

    #[test]
    #[cfg(feature = "cel")]
    fn test_policy_with_trifecta() {
        let policy = Policy::new("test");

        // Context with full trifecta
        let ctx = PolicyContext::new(Operation::GitPush)
            .with_capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::LowRisk,
                git_push: CapabilityLevel::LowRisk,
                ..Default::default()
            })
            .with_trifecta_risk(TrifectaRisk::Complete);

        let obs = policy.evaluate(&ctx).unwrap();

        // Trifecta should add git_push obligation
        assert!(obs.requires(Operation::GitPush));
    }

    #[test]
    fn test_policy_as_nucleus() {
        use crate::frame::Nucleus;

        let policy = Policy::new("test");

        // Permissive lattice with trifecta
        let perms = PermissionLattice::builder()
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::LowRisk,
                git_push: CapabilityLevel::LowRisk,
                ..Default::default()
            })
            .build();

        let result = policy.apply(&perms);

        // Trifecta should be enforced
        assert!(result.requires_approval(Operation::GitPush));
    }

    #[test]
    fn test_policy_nucleus_is_idempotent() {
        use crate::frame::Nucleus;

        let policy = Policy::new("test");
        let perms = PermissionLattice::permissive();

        let once = policy.apply(&perms);
        let twice = policy.apply(&once);

        assert_eq!(once.capabilities, twice.capabilities);
        assert_eq!(once.obligations, twice.obligations);
    }

    #[test]
    fn test_policy_nucleus_is_deflationary() {
        use crate::frame::Nucleus;

        let policy = Policy::new("test");
        let perms = PermissionLattice::permissive();

        let result = policy.apply(&perms);

        // Deflationary: obligations can only increase (more = smaller in lattice)
        assert!(result.obligations.len() >= perms.obligations.len());
    }
}
