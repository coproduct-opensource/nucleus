//! # Lattice Guard
//!
//! A quotient lattice for AI agent permissions that prevents uninhabitable states.
//!
//! ## The Uninhabitable State
//!
//! The [uninhabitable state](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
//! (originally termed "lethal trifecta" by Simon Willison) describes
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
//! When the uninhabitable_state is detected, exfiltration operations gain approval
//! obligations. The quotient L' contains only configurations where this
//! invariant holds.
//!
//! ## Quick Start
//!
//! ```rust
//! use portcullis::{Operation, PermissionLattice, CapabilityLevel};
//!
//! // Create a permission set with dangerous capabilities
//! let mut perms = PermissionLattice::default();
//! perms.capabilities.read_files = CapabilityLevel::Always;    // Private data
//! perms.capabilities.web_fetch = CapabilityLevel::LowRisk;    // Untrusted content
//! perms.capabilities.git_push = CapabilityLevel::LowRisk;     // Exfiltration
//!
//! // The meet operation detects the uninhabitable_state and adds approval obligations
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
//! use portcullis::constraint::{Constraint, Policy, PolicyContext};
//! use portcullis::frame::Nucleus;
//! use portcullis::{Operation, PermissionLattice};
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
#[cfg(feature = "cedar")]
pub mod cedar_bridge;
#[cfg(feature = "crypto")]
pub mod certificate;
mod command;
pub mod constraint;
pub mod uninhabitable_state;

/// Kernel decision engine — complete mediation with monotone session state.
#[cfg(all(feature = "serde", feature = "crypto"))]
/// Platform adapters — I/O abstraction for cross-platform deployment.
pub mod adapter;
pub mod delegation;
pub mod dropout;
/// Bash command egress analysis — detect network exfiltration.
pub mod egress;
/// Egress policy — config loader and host pattern matching for outbound traffic control.
///
/// Requires the `spec` feature (includes `serde`, `toml`).
#[cfg(feature = "spec")]
pub mod egress_extract;
#[cfg(feature = "spec")]
pub mod egress_policy;
pub mod escalation;
pub mod exposure_core;
pub mod flow_graph;
pub mod frame;
pub mod galois;
pub mod graded;
pub mod guard;
pub mod heyting;
/// Verified hook adapter — pure decision pipeline for Claude Code hooks.
pub mod hook_adapter;
pub mod kernel;
/// Manifest behavioral enforcement — detect lying manifests post-execution.
pub mod manifest_enforcement;
/// MCP mediation: classify and gate arbitrary MCP tool calls against the
/// permission lattice with exposure tracking.
///
/// Requires the `spec` feature (includes `serde`, `serde_yaml`, `toml`).
#[cfg(feature = "spec")]
pub mod manifest_registry;
#[cfg(feature = "spec")]
pub mod mcp_mediation;
/// Progressive discovery: observe agent behavior and generate minimal policies.
///
/// Requires the `spec` feature (includes `serde`, `serde_yaml`, `toml`).
#[cfg(feature = "spec")]
pub mod observe;
/// Declarative profile specification and canonical profile registry.
///
/// Requires the `spec` feature (includes `serde`, `cel`, `serde_yaml`, `toml`).
#[cfg(feature = "spec")]
pub mod policy;
#[cfg(feature = "spec")]
pub mod profile;
/// Attenuation tokens — compact delegation credentials for wire transport.
///
/// Requires the `serde` feature for serialization.
/// Append-only receipt chain with hash-chain integrity enforcement.
pub mod receipt_chain;
#[cfg(feature = "crypto")]
pub mod receipt_sign;
#[cfg(feature = "remote-audit")]
pub mod s3_audit_backend;
#[cfg(feature = "crypto")]
pub mod token;
/// MCP tool schema pinning: rug-pull detection for MCP servers.
///
/// Stores SHA-256 hashes of approved tool schemas and detects silent
/// mutations post-approval.
pub mod tool_schema;

pub mod identity;
pub mod intent;
pub mod isolation;
mod lattice;
pub mod metrics;
pub mod modal;
mod path;
pub mod permissive;
pub mod pipeline;
pub mod progress;
pub mod region;
mod time;
pub mod trust;
pub mod verdict_sink;
pub mod weakening;
pub mod workspace;

#[cfg(kani)]
mod kani;

pub use budget::BudgetLattice;
pub use capability::{
    default_sink_class, CapabilityLattice, CapabilityLevel, ExtensionOperation,
    IncompatibilityConstraint, Obligations, Operation, OperationParseError, SinkClass, StateRisk,
};
pub use command::{ArgPattern, CommandLattice, CommandPattern};
pub use exposure_core::{apply_record, classify_operation, project_exposure, should_deny};
pub use frame::{
    verify_nucleus_laws, BoundedLattice, CompleteLattice, ComposedNucleus, DistributiveLattice,
    Frame, Lattice, Nucleus, NucleusLaw, NucleusLawViolation, SafePermissionLattice,
    UninhabitableQuotient,
};
pub use galois::{
    Composable, GaloisConnection, GaloisVerificationError, TranslationReport, TranslationStep,
    TrustDomainBridge,
};
pub use graded::{Graded, GradedPermissionCheck, GradedPipeline, RiskCost, RiskGrade};
#[allow(deprecated)]
pub use guard::{
    operation_exposure, CheckProof, CompositeGuard, ExecuteError, ExposureLabel, ExposureSet,
    ExtensionExposureLabel, GradedExposureGuard, GradedGuard, GuardError, GuardFn, GuardedAction,
    PermissionGuard, RuntimeStateGuard, ToolCallGuard,
};
pub use heyting::{ConditionalPermission, HeytingAlgebra};
pub use intent::{IntentKind, WorkIntent};
pub use isolation::{FileIsolation, IsolationLattice, NetworkIsolation, ProcessIsolation};
pub use lattice::{
    DelegationError, EffectivePermissions, PermissionLattice, PermissionLatticeBuilder,
};
pub use modal::{CapabilityModal, EscalationPath, EscalationStep, ModalContext, ModalPermissions};
pub use path::PathLattice;
pub use permissive::{
    ExecutionDenied, PermissiveExecution, PermissiveExecutionResult, PermissiveExecutor,
    PermissiveExecutorBuilder,
};
pub use progress::{ProgressDimension, ProgressLattice, ProgressLevel};
pub use region::CodeRegion;
pub use time::TimeLattice;
pub use trust::{EnforcementResult, TrustProfile};
pub use weakening::{
    WeakeningCost, WeakeningCostConfig, WeakeningDimension, WeakeningGap, WeakeningRequest,
};
pub use workspace::WorkspaceGuard;

// Re-export pipeline types
pub use pipeline::{
    algebraic_gap, evaluate_and_escalate, full_pipeline, justify_necessity, require_or_escalate,
    translate_with_cost, AlgebraicWeakeningGap, CostAnnotatedTranslation, EscalationTrigger,
    HopCost, IntentRegionMapping, ModalJustification, ModalJustificationEntry, PipelineTrace,
    RiskEvaluation,
};

// Re-export key audit and metrics types
pub use audit::{
    AuditEntry, AuditLog, ChainVerificationError, IdentityAuditSummary, PermissionEvent,
    RetentionPolicy,
};
#[cfg(feature = "crypto")]
pub use certificate::{
    canonical_permissions_hash, verify_certificate, CertificateDelegationError, CertificateError,
    LatticeCertificate, VerifiedPermissions,
};
pub use delegation::{
    meet_with_justification, DelegationChain, DelegationLink, MeetJustification, RestrictionDetail,
    RestrictionReason,
};
#[cfg(feature = "spec")]
pub use egress_extract::{extract_egress_destinations, EgressDestination};
#[cfg(feature = "spec")]
pub use egress_policy::{EgressPolicy, EgressPolicyError, EgressVerdict, HostPattern};
pub use metrics::{
    build_deviation_report, DeviationDetail, DeviationReport, InMemoryMetrics, MetricEvent,
    MetricsCollector, MetricsReport, ReputationMetrics, ReputationWeights,
};
#[cfg(feature = "serde")]
pub use portcullis_core::policy_rules::PolicyLoadError;
pub use portcullis_core::policy_rules::{
    AdmissibilityRule, LabelPredicate, PolicyEvaluation, PolicyRuleSet, RuleVerdict,
};
#[cfg(feature = "serde")]
pub use receipt_chain::verify_exported_chain;
pub use receipt_chain::{
    ChainAppendError, ChainVerifyError, ReceiptChain, VerdictReceipt, VerifyReport,
};
#[cfg(feature = "crypto")]
pub use token::{AttenuationToken, SessionProvenance, TokenError};
pub use tool_schema::{ApprovedToolSchema, SchemaError, ToolSchemaRegistry};
pub use uninhabitable_state::{ConstraintNucleus, CoreExposureRequirement, UninhabitableState};
pub use verdict_sink::{ActorIdentity, SinkError, VerdictContext, VerdictOutcome, VerdictSink};

/// Check if a glob pattern matches a path.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    path::glob_match(pattern, path)
}
