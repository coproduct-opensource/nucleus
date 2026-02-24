//! # Lattice Guard
//!
//! A quotient lattice for AI agent permissions that prevents the "lethal trifecta".
//!
//! ## The Lethal Trifecta
//!
//! The [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) describes
//! three capabilities that, when combined in an AI agent, create critical security vulnerabilities:
//!
//! 1. **Access to private data** - reading files, credentials, secrets
//! 2. **Exposure to untrusted content** - web search, fetching URLs, processing external input
//! 3. **External communication** - git push, PR creation, API calls, command execution
//!
//! When an agent has all three at autonomous levels, prompt injection attacks can exfiltrate
//! private data without human oversight.
//!
//! ## Solution: Quotient Lattice
//!
//! This crate models permissions as a product lattice L with a **nucleus** operator
//! that projects onto the quotient lattice L' of safe configurations:
//!
//! ```text
//! L  = Capabilities × Paths × Budget × Commands × Time
//! L' = { x ∈ L : ν(x) = x }  (safe configurations)
//!
//! The nucleus operator ν:
//! • Is idempotent: ν(ν(x)) = ν(x)
//! • Is deflationary: ν(x) ≤ x
//! • Preserves meets: ν(x ∧ y) = ν(x) ∧ ν(y)
//! ```
//!
//! When the trifecta is detected, exfiltration operations gain approval
//! obligations. The quotient L' contains only configurations where this
//! invariant holds.
//!
//! ## Quick Start
//!
//! ```rust
//! use lattice_guard::{Operation, PermissionLattice, CapabilityLevel};
//!
//! // Create a permission set with dangerous capabilities
//! let mut perms = PermissionLattice::default();
//! perms.capabilities.read_files = CapabilityLevel::Always;    // Private data
//! perms.capabilities.web_fetch = CapabilityLevel::LowRisk;    // Untrusted content
//! perms.capabilities.git_push = CapabilityLevel::LowRisk;     // Exfiltration
//!
//! // The meet operation detects the trifecta and adds approval obligations
//! let safe = perms.meet(&perms);
//! assert!(safe.requires_approval(Operation::GitPush));
//! ```
//!
//! ## Integration with Claude Code / OpenClaw
//!
//! See the `examples/` directory for integration patterns with popular AI agent frameworks.
//!
//! ## Security Model
//!
//! See `THREAT_MODEL.md` for a complete description of what this crate prevents
//! and what it does not prevent.
//!
//! ## User-Defined Policies (CEL)
//!
//! With the `cel` feature enabled, you can define policies with CEL constraints:
//!
//! ```rust,ignore
//! use lattice_guard::constraint::{Constraint, Policy, PolicyContext};
//! use lattice_guard::frame::Nucleus;
//! use lattice_guard::{Operation, PermissionLattice};
//!
//! // Create a policy with custom constraints
//! let policy = Policy::new("secure-workspace")
//!     .with_constraint(
//!         Constraint::new(
//!             "workspace-only",
//!             r#"operation == "write_files" && !path.startsWith("/workspace/")"#,
//!         )?.with_obligation(Operation::WriteFiles)
//!     );
//!
//! // Apply the policy as a nucleus
//! let perms = PermissionLattice::permissive();
//! let safe = policy.apply(&perms);
//! ```

#![deny(missing_docs)]
#![deny(unsafe_code)]

pub mod audit;
#[cfg(feature = "serde")]
pub mod audit_backend;
mod budget;
mod capability;
mod command;
pub mod constraint;
pub mod delegation;
pub mod escalation;
pub mod frame;
pub mod galois;
pub mod graded;
pub mod guard;
pub mod heyting;
pub mod identity;
pub mod isolation;
mod lattice;
pub mod metrics;
pub mod modal;
mod path;
pub mod permissive;
mod time;
pub mod weakening;

#[cfg(kani)]
mod kani;

pub use budget::BudgetLattice;
pub use capability::{
    CapabilityLattice, CapabilityLevel, IncompatibilityConstraint, Obligations, Operation,
    TrifectaRisk,
};
pub use command::{ArgPattern, CommandLattice, CommandPattern};
pub use frame::{
    BoundedLattice, CompleteLattice, DistributiveLattice, Frame, Lattice, Nucleus,
    SafePermissionLattice, TrifectaQuotient,
};
pub use galois::{GaloisConnection, GaloisVerificationError, TrustDomainBridge};
pub use graded::{Graded, GradedPermissionCheck, RiskGrade};
pub use guard::{CompositeGuard, GuardError, GuardFn, GuardedAction, PermissionGuard};
pub use heyting::{ConditionalPermission, HeytingAlgebra};
pub use isolation::{FileIsolation, IsolationLattice, NetworkIsolation, ProcessIsolation};
pub use lattice::{
    DelegationError, EffectivePermissions, PermissionLattice, PermissionLatticeBuilder,
};
pub use modal::{CapabilityModal, ModalContext, ModalPermissions};
pub use path::PathLattice;
pub use permissive::{
    ExecutionDenied, PermissiveExecution, PermissiveExecutionResult, PermissiveExecutor,
    PermissiveExecutorBuilder,
};
pub use time::TimeLattice;
pub use weakening::{
    WeakeningCost, WeakeningCostConfig, WeakeningDimension, WeakeningGap, WeakeningRequest,
};

// Re-export key audit and metrics types
pub use audit::{
    AuditEntry, AuditLog, ChainVerificationError, IdentityAuditSummary, PermissionEvent,
    RetentionPolicy,
};
pub use delegation::{
    meet_with_justification, DelegationChain, DelegationLink, MeetJustification, RestrictionDetail,
    RestrictionReason,
};
pub use metrics::{
    build_deviation_report, DeviationDetail, DeviationReport, InMemoryMetrics, MetricEvent,
    MetricsCollector, MetricsReport, ReputationMetrics, ReputationWeights,
};

/// Check if a glob pattern matches a path.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    path::glob_match(pattern, path)
}
