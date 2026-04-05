//! Obligation discharge as typed evidence — `Discharged<O>` witness system.
//!
//! This module implements the architectural invariant described in issue #1206:
//! policy obligation checking must be **structurally enforced** at the type
//! level, not by convention. Callers that skip `preflight_action` cannot
//! satisfy effect-site signatures that require a [`DischargedBundle`].
//!
//! ## Design
//!
//! ```text
//! ActionTerm ──► preflight_action ──► PreflightResult
//!                                           │
//!                              ┌────────────┴──────────────┐
//!                         Allowed(bundle)            Denied / RequiresApproval
//!                              │
//!                              ▼
//!                        DischargedBundle  ──►  effect_fn(&term, &bundle)
//! ```
//!
//! `DischargedBundle` is **sealed** — its constructor is private to this
//! module. The only code path that produces one is a successful
//! `preflight_action` call. Receiving a `DischargedBundle` is a compile-time
//! proof that all five obligations passed.
//!
//! ## Obligations checked
//!
//! | Token | Obligation |
//! |---|---|
//! | `Discharged<IntegrityGate>` | Artifact integrity ≥ sink minimum |
//! | `Discharged<PathAllowed>` | Operation is structurally permitted for this sink |
//! | `Discharged<DerivationClear>` | Derivation class is compatible with this sink |
//! | `Discharged<NoAdversarialAncestry>` | No source label has `Adversarial` integrity |
//! | `Discharged<BudgetNotExceeded>` | Estimated cost is within budget |
//!
//! ## Sealing
//!
//! `Discharged<O>` contains a private `Seal` field that cannot be named
//! outside this module. External code cannot forge a `Discharged<T>` or
//! a `DischargedBundle` — the only path is through `preflight_action`.

use std::marker::PhantomData;

use crate::storage_lane::StorageLane;
use crate::{IFCLabel, IntegLevel, Operation, SinkClass};

// ═══════════════════════════════════════════════════════════════════════════
// Sealing infrastructure
// ═══════════════════════════════════════════════════════════════════════════

/// Private sentinel type. Cannot be named by external code.
///
/// Presence of `Seal` as a field in `Discharged` and `DischargedBundle`
/// prevents any external code from constructing those types.
struct Seal;

mod obligation_sealed {
    /// Sealing supertrait — prevents external `ProofObligation` impls.
    pub trait ObligationSealed {}
}

// ═══════════════════════════════════════════════════════════════════════════
// ProofObligation — named policy obligations
// ═══════════════════════════════════════════════════════════════════════════

/// Marker trait for named policy obligations.
///
/// Each implementing type represents a distinct safety property that must
/// be checked before an effect is permitted. All implementations live in
/// this crate; external code cannot define new obligations (sealed via
/// [`obligation_sealed::ObligationSealed`]).
pub trait ProofObligation: obligation_sealed::ObligationSealed {}

// ── Built-in obligation types ────────────────────────────────────────────────

/// Obligation: the artifact IFC integrity label meets the sink's minimum.
///
/// For example, `GitPush` and `GitCommit` sinks require at least `Untrusted`
/// integrity; `Adversarial`-integrity content is blocked.
pub struct IntegrityGate;
impl obligation_sealed::ObligationSealed for IntegrityGate {}
impl ProofObligation for IntegrityGate {}

/// Obligation: the operation is structurally permitted for this sink class.
///
/// Prevents mismatches such as a `GitPush` operation being submitted with a
/// `WorkspaceWrite` sink — the operation/sink pair must be consistent.
pub struct PathAllowed;
impl obligation_sealed::ObligationSealed for PathAllowed {}
impl ProofObligation for PathAllowed {}

/// Obligation: the artifact derivation class is compatible with this sink.
///
/// `GitPush`, `GitCommit`, and `PRCommentWrite` sinks require `Deterministic`
/// or `HumanPromoted` derivation. AI-derived content is blocked at these
/// verified sinks.
pub struct DerivationClear;
impl obligation_sealed::ObligationSealed for DerivationClear {}
impl ProofObligation for DerivationClear {}

/// Obligation: no source label carries `Adversarial` integrity.
///
/// Ensures that adversarially-controlled inputs (web scraping, public issue
/// bodies) cannot contaminate verified-sink writes.
pub struct NoAdversarialAncestry;
impl obligation_sealed::ObligationSealed for NoAdversarialAncestry {}
impl ProofObligation for NoAdversarialAncestry {}

/// Obligation: the estimated cost fits within the budget gate.
///
/// For zero-cost operations this always passes. Non-zero costs require a
/// budget evaluator (wired at the application layer in `portcullis-effects`).
pub struct BudgetNotExceeded;
impl obligation_sealed::ObligationSealed for BudgetNotExceeded {}
impl ProofObligation for BudgetNotExceeded {}

// ═══════════════════════════════════════════════════════════════════════════
// Discharged<O> — zero-sized proof token
// ═══════════════════════════════════════════════════════════════════════════

/// A zero-sized proof that obligation `O` was checked and passed.
///
/// Can only be constructed by [`preflight_action`] (the `_seal` field
/// contains a private [`Seal`] type that external code cannot name).
///
/// Presence of a `Discharged<O>` is a compile-time witness that the
/// corresponding obligation check ran and produced `Allow`.
pub struct Discharged<O: ProofObligation> {
    _marker: PhantomData<O>,
    _seal: Seal,
}

impl<O: ProofObligation> Discharged<O> {
    /// Mint a discharge token. Only callable within this module.
    fn mint() -> Self {
        Self {
            _marker: PhantomData,
            _seal: Seal,
        }
    }
}

impl<O: ProofObligation> std::fmt::Debug for Discharged<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Discharged<{}>", std::any::type_name::<O>())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DischargedBundle — the full authorization package
// ═══════════════════════════════════════════════════════════════════════════

/// The result of a successful [`preflight_action`] call.
///
/// Holds typed discharge witnesses for all five policy obligations. Effect
/// functions require a `&DischargedBundle` to proceed; there is **no other
/// way to construct one** — the `_seal` field is private to this module.
///
/// # Sealing guarantee
///
/// ```compile_fail
/// // This code does NOT compile — Seal is not accessible outside this module.
/// use portcullis_core::discharge::{DischargedBundle, IntegrityGate, Discharged};
/// let bundle = DischargedBundle {
///     integrity_gate: Discharged::mint(),  // mint() is private
///     // ...
/// };
/// ```
///
/// Receiving a `DischargedBundle` is proof that `preflight_action` ran and
/// all obligations passed.
#[must_use = "a DischargedBundle must be passed to the effect function it authorizes"]
pub struct DischargedBundle {
    /// Artifact integrity ≥ sink minimum.
    pub integrity_gate: Discharged<IntegrityGate>,
    /// Operation is structurally permitted for this sink.
    pub path_allowed: Discharged<PathAllowed>,
    /// Derivation class is compatible with this sink.
    pub derivation_clear: Discharged<DerivationClear>,
    /// No source label carries adversarial integrity.
    pub no_adversarial_ancestry: Discharged<NoAdversarialAncestry>,
    /// Estimated cost fits within the budget gate.
    pub budget_not_exceeded: Discharged<BudgetNotExceeded>,
    _seal: Seal,
}

impl DischargedBundle {
    /// Private constructor — only callable from within this module.
    fn new() -> Self {
        Self {
            integrity_gate: Discharged::mint(),
            path_allowed: Discharged::mint(),
            derivation_clear: Discharged::mint(),
            no_adversarial_ancestry: Discharged::mint(),
            budget_not_exceeded: Discharged::mint(),
            _seal: Seal,
        }
    }
}

impl std::fmt::Debug for DischargedBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DischargedBundle")
            .field("integrity_gate", &self.integrity_gate)
            .field("path_allowed", &self.path_allowed)
            .field("derivation_clear", &self.derivation_clear)
            .field("no_adversarial_ancestry", &self.no_adversarial_ancestry)
            .field("budget_not_exceeded", &self.budget_not_exceeded)
            .finish()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ActionTerm — the proposed action to evaluate
// ═══════════════════════════════════════════════════════════════════════════

/// A proposed action to be evaluated by [`preflight_action`].
///
/// Carries the full context needed to run all obligation checks:
/// the operation being attempted, the IFC labels on data inputs,
/// the target sink class, and the subject identity.
///
/// # Example
///
/// ```rust
/// use portcullis_core::discharge::ActionTerm;
/// use portcullis_core::{Operation, SinkClass, IFCLabel};
///
/// let term = ActionTerm {
///     operation: Operation::GitCommit,
///     sink_class: SinkClass::GitCommit,
///     source_labels: vec![],
///     artifact_label: IFCLabel::default(),
///     subject: "spiffe://nucleus/agent/ci-bot".to_string(),
///     estimated_cost_micro_usd: 0,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ActionTerm {
    /// The operation being attempted.
    pub operation: Operation,
    /// The target sink class for this action.
    pub sink_class: SinkClass,
    /// IFC labels on the data inputs feeding this action.
    pub source_labels: Vec<IFCLabel>,
    /// The propagated IFC label of the artifact being written or sent.
    pub artifact_label: IFCLabel,
    /// SPIFFE or session identity of the subject requesting this action.
    pub subject: String,
    /// Estimated cost of this action in micro-USD (0 = free / unknown).
    ///
    /// When non-zero, a budget gate must be wired at the application layer
    /// (in `portcullis-effects`). Passing non-zero cost through `preflight_action`
    /// without a budget gate produces a `Denied` result.
    pub estimated_cost_micro_usd: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// PreflightResult — outcome of preflight_action
// ═══════════════════════════════════════════════════════════════════════════

/// The outcome of a [`preflight_action`] evaluation.
///
/// Only [`PreflightResult::Allowed`] contains a [`DischargedBundle`] that
/// authorizes the effect to proceed. `Denied` and `RequiresApproval` must
/// never reach an effect call site.
#[must_use = "PreflightResult must be checked before executing any effect"]
#[derive(Debug)]
pub enum PreflightResult {
    /// All obligations passed. The bundle authorizes the effect.
    Allowed(DischargedBundle),
    /// At least one obligation failed. Contains a human-readable reason.
    Denied(String),
    /// The action requires explicit human approval before it may proceed.
    RequiresApproval { reason: String },
}

impl PreflightResult {
    /// Returns `true` if the preflight check passed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed(_))
    }

    /// Returns `true` if the preflight check was denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied(_))
    }

    /// Returns `true` if human approval is required.
    pub fn requires_approval(&self) -> bool {
        matches!(self, Self::RequiresApproval { .. })
    }

    /// Unwrap the [`DischargedBundle`], panicking if not `Allowed`.
    ///
    /// **Only use in tests** or code where the outcome is statically known.
    /// Production code must exhaustively match all variants.
    #[track_caller]
    pub fn unwrap_bundle(self) -> DischargedBundle {
        match self {
            Self::Allowed(bundle) => bundle,
            Self::Denied(reason) => panic!("preflight denied: {reason}"),
            Self::RequiresApproval { reason } => {
                panic!("preflight requires approval: {reason}")
            }
        }
    }

    /// Extract the denial reason, or `None` if not `Denied`.
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::Denied(reason) => Some(reason.as_str()),
            _ => None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// preflight_action — the obligation evaluator
// ═══════════════════════════════════════════════════════════════════════════

/// Evaluates all policy obligations for a proposed action.
///
/// This is the **only** function that can produce a [`DischargedBundle`].
/// Callers must call this before executing any effect and pass the resulting
/// bundle to the effect function.
///
/// # Obligation evaluation order
///
/// 1. **IntegrityGate** — artifact integrity ≥ sink minimum requirement
/// 2. **PathAllowed** — operation/sink class pair is structurally consistent
/// 3. **DerivationClear** — derivation class is compatible with this sink
/// 4. **NoAdversarialAncestry** — no source label carries `Adversarial` integrity
/// 5. **BudgetNotExceeded** — zero-cost always passes; non-zero requires budget gate
///
/// Checks short-circuit on the first denial for latency. All non-denial
/// states are fully evaluated before the bundle is minted.
///
/// # Example
///
/// ```rust
/// use portcullis_core::discharge::{ActionTerm, preflight_action, PreflightResult};
/// use portcullis_core::{Operation, SinkClass, IFCLabel};
///
/// let term = ActionTerm {
///     operation: Operation::WriteFiles,
///     sink_class: SinkClass::WorkspaceWrite,
///     source_labels: vec![],
///     artifact_label: IFCLabel::default(),
///     subject: "spiffe://nucleus/agent/test".to_string(),
///     estimated_cost_micro_usd: 0,
/// };
///
/// match preflight_action(&term) {
///     PreflightResult::Allowed(_bundle) => { /* pass bundle to effect fn */ }
///     PreflightResult::Denied(reason) => { /* log and abort */ }
///     PreflightResult::RequiresApproval { reason } => { /* await approval */ }
/// }
/// ```
pub fn preflight_action(term: &ActionTerm) -> PreflightResult {
    // 1. IntegrityGate: artifact integrity must meet the sink minimum.
    let min_integ = sink_min_integrity(term.sink_class);
    if term.artifact_label.integrity < min_integ {
        return PreflightResult::Denied(format!(
            "IntegrityGate: artifact integrity {:?} below minimum {:?} required for {:?}",
            term.artifact_label.integrity, min_integ, term.sink_class
        ));
    }

    // 2. PathAllowed: operation/sink pair must be structurally consistent.
    if !operation_allowed_for_sink(term.operation, term.sink_class) {
        return PreflightResult::Denied(format!(
            "PathAllowed: operation {:?} is not permitted for sink {:?}",
            term.operation, term.sink_class
        ));
    }

    // 3. DerivationClear: derivation class must be compatible with the sink.
    if sink_requires_verified_derivation(term.sink_class)
        && !StorageLane::Verified.accepts(term.artifact_label.derivation)
    {
        return PreflightResult::Denied(format!(
            "DerivationClear: {:?} derivation is not permitted at verified sink {:?} \
             (requires Deterministic or HumanPromoted)",
            term.artifact_label.derivation, term.sink_class
        ));
    }

    // 4. NoAdversarialAncestry: no source label may carry Adversarial integrity.
    for label in &term.source_labels {
        if label.integrity == IntegLevel::Adversarial {
            return PreflightResult::Denied(format!(
                "NoAdversarialAncestry: adversarial-integrity source label present \
                 in action by subject '{}'",
                term.subject
            ));
        }
    }

    // 5. BudgetNotExceeded: non-zero cost requires a wired budget gate.
    //
    // At the portcullis-core layer there is no budget evaluator — that is
    // wired in portcullis-effects. Zero-cost operations always pass. Non-zero
    // cost operations fail here until a budget gate is integrated at the
    // application layer. This is intentionally fail-closed: an unbounded
    // operation must explicitly declare zero cost or wire a gate.
    if term.estimated_cost_micro_usd > 0 {
        return PreflightResult::Denied(format!(
            "BudgetNotExceeded: non-zero cost {}µUSD requires a budget gate \
             (wire BudgetGate via portcullis-effects before submitting non-zero-cost terms)",
            term.estimated_cost_micro_usd
        ));
    }

    PreflightResult::Allowed(DischargedBundle::new())
}

// ═══════════════════════════════════════════════════════════════════════════
// Policy helper functions
// ═══════════════════════════════════════════════════════════════════════════

/// Returns the minimum `IntegLevel` required to write to `sink`.
///
/// Sinks that publish or persist data to external/shared systems require
/// at least `Untrusted` integrity (no adversarial-tainted data).
/// Local workspace writes accept any integrity level.
fn sink_min_integrity(sink: SinkClass) -> IntegLevel {
    match sink {
        // High-trust publish sinks — no adversarial input.
        SinkClass::GitPush
        | SinkClass::GitCommit
        | SinkClass::PRCommentWrite
        | SinkClass::EmailSend
        | SinkClass::HTTPEgress
        | SinkClass::MCPWrite
        | SinkClass::CloudMutation
        | SinkClass::VerifiedTableWrite
        | SinkClass::TicketWrite => IntegLevel::Untrusted,

        // Memory persistence — adversarial writes create cross-session laundering.
        SinkClass::MemoryPersist => IntegLevel::Untrusted,

        // Agent spawning — adversarial instructions would propagate to child.
        SinkClass::AgentSpawn => IntegLevel::Untrusted,

        // System writes — no adversarial data to system files.
        SinkClass::SystemWrite => IntegLevel::Untrusted,

        // Local / low-trust sinks — accept any integrity (including Adversarial).
        SinkClass::WorkspaceWrite
        | SinkClass::BashExec
        | SinkClass::ProposedTableWrite
        | SinkClass::SearchIndexWrite
        | SinkClass::CacheWrite
        | SinkClass::AuditLogAppend
        | SinkClass::SecretRead => IntegLevel::Adversarial,
    }
}

/// Returns `true` if the operation/sink pairing is structurally consistent.
///
/// This is the `PathAllowed` gate: it ensures that the `Operation` variant
/// in the `ActionTerm` is compatible with the declared `SinkClass`. A mismatch
/// indicates a caller bug (e.g., submitting `Operation::GitPush` with
/// `SinkClass::WorkspaceWrite`).
///
/// Returns `true` (permissive) for combinations not explicitly restricted,
/// so adding new `Operation` or `SinkClass` variants does not break existing
/// callers by default.
fn operation_allowed_for_sink(op: Operation, sink: SinkClass) -> bool {
    match op {
        Operation::WriteFiles => {
            matches!(
                sink,
                SinkClass::WorkspaceWrite
                    | SinkClass::SystemWrite
                    | SinkClass::ProposedTableWrite
                    | SinkClass::VerifiedTableWrite
                    | SinkClass::CacheWrite
                    | SinkClass::SearchIndexWrite
                    | SinkClass::AuditLogAppend
            )
        }
        Operation::EditFiles => {
            matches!(sink, SinkClass::WorkspaceWrite | SinkClass::SystemWrite)
        }
        Operation::GitCommit => matches!(sink, SinkClass::GitCommit),
        Operation::GitPush => matches!(sink, SinkClass::GitPush),
        Operation::CreatePr => matches!(sink, SinkClass::PRCommentWrite),
        Operation::RunBash => matches!(sink, SinkClass::BashExec),
        Operation::WebSearch | Operation::WebFetch => matches!(sink, SinkClass::HTTPEgress),
        Operation::SpawnAgent => matches!(sink, SinkClass::AgentSpawn),
        Operation::ManagePods => matches!(sink, SinkClass::CloudMutation | SinkClass::AgentSpawn),
        // Read-only operations: structurally they produce no writes.
        // Accept AuditLogAppend and MemoryPersist (reading can trigger audit events
        // or cache population). All other write sinks are incoherent for reads.
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => matches!(
            sink,
            SinkClass::AuditLogAppend | SinkClass::MemoryPersist | SinkClass::CacheWrite
        ),
    }
}

/// Returns `true` if this sink class requires `Deterministic` or `HumanPromoted`
/// derivation (i.e., the sink participates in the verified storage lane).
///
/// This mirrors the Rule 6 check in [`crate::flow`] but at the discharge layer,
/// ensuring that obligation checking and flow checking are consistent.
fn sink_requires_verified_derivation(sink: SinkClass) -> bool {
    matches!(
        sink,
        SinkClass::GitPush | SinkClass::GitCommit | SinkClass::PRCommentWrite
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityLevel, ConfLevel, DerivationClass, Freshness, ProvenanceSet};

    fn trusted_label() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            authority: AuthorityLevel::Directive,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            derivation: DerivationClass::Deterministic,
        }
    }

    fn adversarial_label() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Public,
            integrity: IntegLevel::Adversarial,
            authority: AuthorityLevel::NoAuthority,
            provenance: ProvenanceSet::WEB,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            derivation: DerivationClass::OpaqueExternal,
        }
    }

    fn ai_derived_label() -> IFCLabel {
        IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            authority: AuthorityLevel::Directive,
            provenance: ProvenanceSet::MODEL,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            derivation: DerivationClass::AIDerived,
        }
    }

    fn human_promoted_label() -> IFCLabel {
        IFCLabel {
            derivation: DerivationClass::HumanPromoted,
            ..trusted_label()
        }
    }

    fn workspace_write_term() -> ActionTerm {
        ActionTerm {
            operation: Operation::WriteFiles,
            sink_class: SinkClass::WorkspaceWrite,
            source_labels: vec![],
            artifact_label: trusted_label(),
            subject: "spiffe://nucleus/agent/test".to_string(),
            estimated_cost_micro_usd: 0,
        }
    }

    // ── Happy path ──────────────────────────────────────────────────────────

    #[test]
    fn workspace_write_with_trusted_label_allowed() {
        let result = preflight_action(&workspace_write_term());
        assert!(result.is_allowed(), "workspace write should be allowed");
    }

    #[test]
    fn git_commit_with_deterministic_label_allowed() {
        let term = ActionTerm {
            operation: Operation::GitCommit,
            sink_class: SinkClass::GitCommit,
            artifact_label: trusted_label(),
            ..workspace_write_term()
        };
        assert!(preflight_action(&term).is_allowed());
    }

    #[test]
    fn git_push_with_human_promoted_label_allowed() {
        let term = ActionTerm {
            operation: Operation::GitPush,
            sink_class: SinkClass::GitPush,
            artifact_label: human_promoted_label(),
            ..workspace_write_term()
        };
        assert!(preflight_action(&term).is_allowed());
    }

    #[test]
    fn create_pr_with_deterministic_label_allowed() {
        let term = ActionTerm {
            operation: Operation::CreatePr,
            sink_class: SinkClass::PRCommentWrite,
            artifact_label: trusted_label(),
            ..workspace_write_term()
        };
        assert!(preflight_action(&term).is_allowed());
    }

    // ── IntegrityGate denials ───────────────────────────────────────────────

    #[test]
    fn git_push_with_adversarial_artifact_denied_integrity_gate() {
        let term = ActionTerm {
            operation: Operation::GitPush,
            sink_class: SinkClass::GitPush,
            artifact_label: adversarial_label(),
            ..workspace_write_term()
        };
        let result = preflight_action(&term);
        assert!(
            result.is_denied(),
            "adversarial artifact at GitPush should be denied"
        );
        let reason = result.denial_reason().unwrap();
        assert!(
            reason.contains("IntegrityGate"),
            "denial should mention IntegrityGate, got: {reason}"
        );
    }

    #[test]
    fn memory_persist_adversarial_artifact_denied_integrity_gate() {
        let term = ActionTerm {
            operation: Operation::WriteFiles,
            sink_class: SinkClass::MemoryPersist,
            artifact_label: adversarial_label(),
            ..workspace_write_term()
        };
        let result = preflight_action(&term);
        assert!(result.is_denied());
        assert!(result.denial_reason().unwrap().contains("IntegrityGate"));
    }

    // ── PathAllowed denials ─────────────────────────────────────────────────

    #[test]
    fn git_push_operation_to_workspace_sink_denied_path() {
        let term = ActionTerm {
            operation: Operation::GitPush,
            sink_class: SinkClass::WorkspaceWrite, // wrong sink for GitPush
            artifact_label: trusted_label(),
            ..workspace_write_term()
        };
        let result = preflight_action(&term);
        assert!(
            result.is_denied(),
            "GitPush to WorkspaceWrite should be denied"
        );
        let reason = result.denial_reason().unwrap();
        assert!(
            reason.contains("PathAllowed"),
            "denial should mention PathAllowed, got: {reason}"
        );
    }

    #[test]
    fn run_bash_operation_to_git_push_sink_denied_path() {
        let term = ActionTerm {
            operation: Operation::RunBash,
            sink_class: SinkClass::GitPush, // wrong sink for RunBash
            artifact_label: trusted_label(),
            ..workspace_write_term()
        };
        let result = preflight_action(&term);
        assert!(result.is_denied());
        assert!(result.denial_reason().unwrap().contains("PathAllowed"));
    }

    // ── DerivationClear denials ─────────────────────────────────────────────

    #[test]
    fn ai_derived_artifact_at_git_push_denied_derivation() {
        let term = ActionTerm {
            operation: Operation::GitPush,
            sink_class: SinkClass::GitPush,
            artifact_label: ai_derived_label(),
            ..workspace_write_term()
        };
        let result = preflight_action(&term);
        assert!(
            result.is_denied(),
            "AI-derived artifact at GitPush should be denied"
        );
        let reason = result.denial_reason().unwrap();
        assert!(
            reason.contains("DerivationClear"),
            "denial should mention DerivationClear, got: {reason}"
        );
    }

    #[test]
    fn ai_derived_artifact_at_git_commit_denied_derivation() {
        let term = ActionTerm {
            operation: Operation::GitCommit,
            sink_class: SinkClass::GitCommit,
            artifact_label: ai_derived_label(),
            ..workspace_write_term()
        };
        assert!(preflight_action(&term).is_denied());
    }

    #[test]
    fn ai_derived_artifact_at_workspace_write_allowed() {
        // WorkspaceWrite does NOT require verified derivation.
        let term = ActionTerm {
            operation: Operation::WriteFiles,
            sink_class: SinkClass::WorkspaceWrite,
            artifact_label: ai_derived_label(),
            ..workspace_write_term()
        };
        assert!(preflight_action(&term).is_allowed());
    }

    // ── NoAdversarialAncestry denials ───────────────────────────────────────

    #[test]
    fn adversarial_source_label_denied_ancestry() {
        let term = ActionTerm {
            operation: Operation::WriteFiles,
            sink_class: SinkClass::WorkspaceWrite,
            source_labels: vec![adversarial_label()],
            artifact_label: trusted_label(),
            ..workspace_write_term()
        };
        let result = preflight_action(&term);
        assert!(result.is_denied(), "adversarial source should be denied");
        let reason = result.denial_reason().unwrap();
        assert!(
            reason.contains("NoAdversarialAncestry"),
            "denial should mention NoAdversarialAncestry, got: {reason}"
        );
    }

    #[test]
    fn mixed_sources_with_one_adversarial_denied() {
        let term = ActionTerm {
            operation: Operation::WriteFiles,
            sink_class: SinkClass::WorkspaceWrite,
            source_labels: vec![trusted_label(), adversarial_label()],
            artifact_label: trusted_label(),
            ..workspace_write_term()
        };
        assert!(preflight_action(&term).is_denied());
    }

    #[test]
    fn trusted_source_labels_allowed() {
        let term = ActionTerm {
            source_labels: vec![trusted_label(), trusted_label()],
            ..workspace_write_term()
        };
        assert!(preflight_action(&term).is_allowed());
    }

    // ── BudgetNotExceeded denials ───────────────────────────────────────────

    #[test]
    fn non_zero_cost_without_budget_gate_denied() {
        let term = ActionTerm {
            estimated_cost_micro_usd: 1_000, // 0.001 USD
            ..workspace_write_term()
        };
        let result = preflight_action(&term);
        assert!(
            result.is_denied(),
            "non-zero cost without budget gate should be denied"
        );
        let reason = result.denial_reason().unwrap();
        assert!(
            reason.contains("BudgetNotExceeded"),
            "denial should mention BudgetNotExceeded, got: {reason}"
        );
    }

    #[test]
    fn zero_cost_always_passes_budget() {
        let term = ActionTerm {
            estimated_cost_micro_usd: 0,
            ..workspace_write_term()
        };
        assert!(preflight_action(&term).is_allowed());
    }

    // ── Sealing: DischargedBundle cannot be forged ──────────────────────────

    #[test]
    fn discharged_bundle_only_obtainable_via_preflight() {
        // This test validates the sealing contract: the only way to get a
        // DischargedBundle is through a successful preflight_action call.
        // The compile-fail aspect is verified by the doc-test on DischargedBundle.
        let bundle = preflight_action(&workspace_write_term()).unwrap_bundle();
        // We can inspect the bundle debug output, confirming fields are present.
        let debug_str = format!("{bundle:?}");
        assert!(debug_str.contains("DischargedBundle"));
        assert!(debug_str.contains("IntegrityGate"));
        assert!(debug_str.contains("DerivationClear"));
    }

    // ── PreflightResult helpers ─────────────────────────────────────────────

    #[test]
    fn preflight_result_is_denied_and_is_allowed_are_exclusive() {
        let allowed = preflight_action(&workspace_write_term());
        assert!(allowed.is_allowed());
        assert!(!allowed.is_denied());
        assert!(!allowed.requires_approval());

        let term = ActionTerm {
            operation: Operation::GitPush,
            sink_class: SinkClass::GitPush,
            artifact_label: adversarial_label(),
            ..workspace_write_term()
        };
        let denied = preflight_action(&term);
        assert!(!denied.is_allowed());
        assert!(denied.is_denied());
        assert!(!denied.requires_approval());
    }

    #[test]
    fn denial_reason_present_on_denied_result() {
        let term = ActionTerm {
            operation: Operation::GitPush,
            sink_class: SinkClass::GitPush,
            artifact_label: ai_derived_label(),
            ..workspace_write_term()
        };
        let result = preflight_action(&term);
        assert!(result.denial_reason().is_some());
        assert!(!result.denial_reason().unwrap().is_empty());
    }

    #[test]
    fn denial_reason_none_on_allowed_result() {
        let result = preflight_action(&workspace_write_term());
        assert!(result.denial_reason().is_none());
    }

    // ── Obligation ordering: earlier checks take precedence ─────────────────

    #[test]
    fn integrity_gate_fires_before_derivation_check() {
        // Artifact is both adversarial AND AI-derived.
        // IntegrityGate (check 1) should fire before DerivationClear (check 3).
        let term = ActionTerm {
            operation: Operation::GitPush,
            sink_class: SinkClass::GitPush,
            artifact_label: IFCLabel {
                integrity: IntegLevel::Adversarial,
                derivation: DerivationClass::AIDerived,
                ..trusted_label()
            },
            ..workspace_write_term()
        };
        let result = preflight_action(&term);
        assert!(result.is_denied());
        assert!(
            result.denial_reason().unwrap().contains("IntegrityGate"),
            "IntegrityGate should fire first"
        );
    }

    // ── Helper function unit tests ──────────────────────────────────────────

    #[test]
    fn git_push_sink_requires_verified_derivation() {
        assert!(sink_requires_verified_derivation(SinkClass::GitPush));
        assert!(sink_requires_verified_derivation(SinkClass::GitCommit));
        assert!(sink_requires_verified_derivation(SinkClass::PRCommentWrite));
    }

    #[test]
    fn workspace_write_does_not_require_verified_derivation() {
        assert!(!sink_requires_verified_derivation(
            SinkClass::WorkspaceWrite
        ));
        assert!(!sink_requires_verified_derivation(SinkClass::BashExec));
        assert!(!sink_requires_verified_derivation(SinkClass::HTTPEgress));
    }

    #[test]
    fn git_push_sink_requires_untrusted_min_integrity() {
        assert_eq!(
            sink_min_integrity(SinkClass::GitPush),
            IntegLevel::Untrusted
        );
        assert_eq!(
            sink_min_integrity(SinkClass::GitCommit),
            IntegLevel::Untrusted
        );
        assert_eq!(
            sink_min_integrity(SinkClass::PRCommentWrite),
            IntegLevel::Untrusted
        );
    }

    #[test]
    fn workspace_write_accepts_adversarial_min_integrity() {
        assert_eq!(
            sink_min_integrity(SinkClass::WorkspaceWrite),
            IntegLevel::Adversarial
        );
    }

    #[test]
    fn operation_sink_consistency_git_operations() {
        assert!(operation_allowed_for_sink(
            Operation::GitPush,
            SinkClass::GitPush
        ));
        assert!(!operation_allowed_for_sink(
            Operation::GitPush,
            SinkClass::WorkspaceWrite
        ));
        assert!(operation_allowed_for_sink(
            Operation::GitCommit,
            SinkClass::GitCommit
        ));
        assert!(!operation_allowed_for_sink(
            Operation::GitCommit,
            SinkClass::GitPush
        ));
        assert!(operation_allowed_for_sink(
            Operation::CreatePr,
            SinkClass::PRCommentWrite
        ));
    }
}
