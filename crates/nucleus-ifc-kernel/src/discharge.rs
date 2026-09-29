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
//! proof that all eight obligations passed — obligation 4 for the pairs it is
//! charged to (see [`ActionKind`]).
//!
//! ## Obligations checked
//!
//! | Token | Obligation |
//! |---|---|
//! | `Discharged<IntegrityGate>` | Artifact integrity ≥ sink minimum — `Adversarial` (never refuses) for an [`ActionKind::AuthorityReducing`] pair |
//! | `Discharged<PathAllowed>` | Operation is structurally permitted for this sink |
//! | `Discharged<DerivationClear>` | Derivation class is compatible with this sink |
//! | `Discharged<NoAdversarialAncestry>` | No source label has `Adversarial` integrity — charged to [`ActionKind::Acting`] pairs; a [`ActionKind::PureRead`] pair (a read verb, or pod observe, at `AuditLogAppend`) or [`ActionKind::AuthorityReducing`] pair (pod teardown) mints it without the check |
//! | `Discharged<BudgetNotExceeded>` | Estimated cost is within budget |
//! | `Discharged<WithinDelegationCeiling>` | Requested capability ≤ policy ceiling for the op |
//! | `Discharged<InScopeWithTask>` | Operation is within the verified task token's scope |
//! | `Discharged<InputsAuthorized>` | Every action input is content-addressed (present) |
//!
//! ## Seam notes (cross-layer obligation correspondence)
//!
//! These document how the discharge vocabulary lines up with the upstream
//! `portcullis::action_term` obligation set — no code, just the mapping a
//! reviewer needs:
//!
//! - **`VerifiedSinkCompatible`** (upstream) is witnessed here by
//!   `Discharged<DerivationClear>`: the discharge `DerivationClear` check
//!   (`sink_requires_verified_derivation` ∧ `StorageLane::Verified.accepts`)
//!   is the canonical form of "a verified sink only accepts Deterministic /
//!   HumanPromoted derivation". There is deliberately **no** separate
//!   `VerifiedSinkCompatible` field — it would be redundant with
//!   `DerivationClear`.
//! - **`NoAdversarialAncestry`** canonical semantics = the discharge
//!   source-label check (`no source label carries `IntegLevel::Adversarial``).
//!   Upstream keys off input `DerivationClass`; the discharge layer keys off
//!   the propagated IFC integrity label, which is the source of truth. Since
//!   2026-09-27 the discharge layer charges it only to [`ActionKind::Acting`]
//!   pairs; upstream has no notion of kind yet, so a pure read on a tainted
//!   session is refused there and admitted here. That is a known G-1 residue
//!   (two deciders), pinned by `cross_layer_discharge_consistency`.
//! - **`InputsAuthorized`** (upstream) fails if any input's `source_hash` is
//!   empty (`term.inputs.any(|i| i.source_hash.trim().is_empty())`). The
//!   discharge layer attests the same property structurally: a kernel
//!   [`ContentHash`] is a 32-byte recomputed digest **by construction** (bricks
//!   3+4 recompute ingest hashes from bytes), so there is no "empty hash" state
//!   to check per-element — the discharge obligation attests *presence*. A
//!   `content_addressed_inputs` of `None` is the un-plumbed state and is
//!   **denied** fail-closed; `Some(inputs)` mints the witness (an empty vec = an
//!   action with no inputs = vacuously authorized, matching upstream's
//!   `!any(empty_hash)` returning satisfied for zero inputs).
//!
//! ## Sealing
//!
//! `Discharged<O>` contains a private `Seal` field that cannot be named
//! outside this module. External code cannot forge a `Discharged<T>` or
//! a `DischargedBundle` — the only path is through `preflight_action`.

use std::marker::PhantomData;

use crate::storage_lane::StorageLane;
use crate::{
    CapabilityLevel, ContentHash, DerivationClass, IFCLabel, IntegLevel, Operation, SinkClass,
};

// ═══════════════════════════════════════════════════════════════════════════
// RepairHint — structured self-repair targets (#1189)
// ═══════════════════════════════════════════════════════════════════════════

/// A machine-readable hint telling the agent exactly what to change to
/// satisfy a failed obligation.
///
/// Instead of parsing English error messages, an agent receiving a
/// `RepairHint` can:
/// - Route to human approval automatically
/// - Substitute a cleaner data source
/// - Narrow its operation scope
/// - Reduce its capability request
///
/// Each [`ProofObligation`] variant produces a distinct `RepairHint`
/// on failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairHint {
    /// Artifact integrity is too low for the sink. Either:
    /// - Use a higher-integrity data source, or
    /// - Route through human review to promote the label.
    RaiseIntegrity {
        /// The artifact's current integrity level.
        actual: IntegLevel,
        /// The minimum integrity the sink requires.
        required: IntegLevel,
        /// The sink class that imposed the requirement.
        sink: SinkClass,
    },
    /// The operation/sink pair is structurally inconsistent.
    /// Use the correct sink class for this operation.
    CorrectOperationSinkPair {
        operation: Operation,
        declared_sink: SinkClass,
    },
    /// The artifact's derivation class is incompatible with the sink.
    /// Either promote the derivation (human review) or write to a
    /// non-verified sink.
    PromoteDerivation {
        /// The artifact's current derivation class.
        actual: DerivationClass,
        /// The sink that requires verified derivation.
        sink: SinkClass,
    },
    /// A source label carries adversarial integrity. Either:
    /// - Remove the adversarial source from the action's inputs, or
    /// - Declassify the source through human review.
    DeclassifyOrReplaceInput {
        /// The subject that submitted the action.
        subject: String,
    },
    /// The action has non-zero cost but no budget gate is wired.
    /// Either set `estimated_cost_micro_usd` to 0 or wire a
    /// `BudgetGate` at the application layer.
    WireBudgetGate {
        /// The cost that triggered the denial.
        cost_micro_usd: u64,
    },
    /// Agent must route this action through human approval before retrying.
    ObtainHumanApproval {
        /// Why approval is needed.
        reason: String,
    },
    /// Capability ceiling exceeded; request a lower privilege level.
    ReduceCapabilityRequest {
        /// The requested capability level.
        requested: CapabilityLevel,
        /// The policy ceiling for this dimension.
        ceiling: CapabilityLevel,
    },
    /// The operation is outside the verified task token's scope (or no
    /// verified scope was supplied). Either narrow the operation to one the
    /// task authorizes, or obtain a task token whose scope covers it.
    OutOfTaskScope {
        /// The operation that fell outside scope.
        operation: Operation,
        /// The subject that submitted the action.
        subject: String,
    },
    /// The action's inputs are not content-addressed (the `content_addressed_inputs`
    /// channel is un-plumbed, `None`). Plumb the FlowTracker content hashes onto
    /// the term (`Some(..)`) before retrying — the discharge layer will not mint
    /// `Discharged<InputsAuthorized>` from an absent inputs channel.
    ProvideContentAddressedInputs {
        /// The subject that submitted the action.
        subject: String,
    },
}

impl std::fmt::Display for RepairHint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RaiseIntegrity {
                actual,
                required,
                sink,
            } => write!(
                f,
                "raise artifact integrity from {actual:?} to at least {required:?} \
                 (required by {sink:?})"
            ),
            Self::CorrectOperationSinkPair {
                operation,
                declared_sink,
            } => write!(
                f,
                "operation {operation:?} is not valid for sink {declared_sink:?} — \
                 use the correct sink class"
            ),
            Self::PromoteDerivation { actual, sink } => write!(
                f,
                "promote derivation from {actual:?} to Deterministic or HumanPromoted \
                 (required by verified sink {sink:?})"
            ),
            Self::DeclassifyOrReplaceInput { subject } => write!(
                f,
                "remove adversarial-integrity source labels from action by '{subject}', \
                 or declassify through human review"
            ),
            Self::WireBudgetGate { cost_micro_usd } => write!(
                f,
                "wire a BudgetGate before submitting actions with cost ({cost_micro_usd}µUSD)"
            ),
            Self::ObtainHumanApproval { reason } => {
                write!(f, "obtain human approval: {reason}")
            }
            Self::ReduceCapabilityRequest { requested, ceiling } => write!(
                f,
                "reduce capability request from {requested:?} to at most {ceiling:?}"
            ),
            Self::OutOfTaskScope { operation, subject } => write!(
                f,
                "operation {operation:?} by '{subject}' is outside the verified task scope — \
                 narrow the operation or obtain a task token that authorizes it"
            ),
            Self::ProvideContentAddressedInputs { subject } => write!(
                f,
                "action by '{subject}' has un-plumbed inputs — populate \
                 content_addressed_inputs from the FlowTracker before retrying"
            ),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Repair — program rewriting via RepairHint
// ═══════════════════════════════════════════════════════════════════════════

/// The result of applying a [`RepairHint`] to a denied [`ActionTerm`].
///
/// A repair is a *type-directed program transformation*: the denied term
/// is rewritten into one that passes the specific obligation check that
/// failed. The rewrite only modifies fields that the failing check examines.
///
/// ```text
/// deny : ActionTerm → (reason, RepairHint)
/// try_repair : RepairHint × ActionTerm → Option<Repair>
/// preflight(repair.term()) = Allowed   (for the check that originally denied)
/// ```
///
/// This is a retraction in the category of ActionTerms: `try_repair` is a
/// right inverse of the specific check that produced the denial.
#[derive(Debug, Clone)]
pub enum Repair {
    /// The term was automatically rewritten and can be retried without
    /// human intervention. The rewrite is sound: the repaired term passes
    /// the obligation check that denied the original.
    Automatic(ActionTerm),
    /// The term requires human approval before retry. The repaired term
    /// has the approval gate inserted; the caller must route it through
    /// the named gate before execution.
    NeedsApproval {
        /// The rewritten term (with approval-gated fields adjusted).
        term: ActionTerm,
        /// Human-readable description of what approval is needed.
        gate: String,
    },
}

impl Repair {
    /// The rewritten term, regardless of whether it's automatic or gated.
    pub fn term(&self) -> &ActionTerm {
        match self {
            Self::Automatic(t) | Self::NeedsApproval { term: t, .. } => t,
        }
    }

    /// Returns `true` if the repair can proceed without human intervention.
    pub fn is_automatic(&self) -> bool {
        matches!(self, Self::Automatic(_))
    }
}

impl RepairHint {
    /// Attempt to rewrite a denied [`ActionTerm`] into one that passes
    /// the obligation check this hint represents.
    ///
    /// Returns `None` for structural mismatches (`CorrectOperationSinkPair`)
    /// where no automatic rewrite is meaningful — the caller must fix the
    /// operation/sink pairing manually.
    ///
    /// # Soundness
    ///
    /// For each `RepairHint` variant, the repaired term is guaranteed to
    /// pass the corresponding obligation check in `preflight_action`,
    /// *assuming all other checks still pass*. The repair modifies only
    /// the fields examined by the failing check.
    ///
    /// # Example
    ///
    /// ```rust
    /// use nucleus_ifc_kernel::discharge::{preflight_action, ActionTerm, PreflightResult};
    /// use nucleus_ifc_kernel::{Operation, SinkClass, IFCLabel, IntegLevel};
    ///
    /// let mut term = ActionTerm {
    ///     operation: Operation::WriteFiles,
    ///     sink_class: SinkClass::WorkspaceWrite,
    ///     source_labels: vec![],
    ///     artifact_label: IFCLabel::default(),
    ///     subject: "agent".to_string(),
    ///     estimated_cost_micro_usd: 500, // non-zero cost, no budget gate
    ///     capability_ceiling: None,
    ///     requested_capability: None,
    ///     verified_scope: None,
    ///     content_addressed_inputs: Some(vec![]),
    /// };
    ///
    /// let result = preflight_action(&term);
    /// if let PreflightResult::Denied { hint, .. } = result {
    ///     if let Some(repair) = hint.try_repair(&term) {
    ///         // The repair zeroed the cost but requires approval
    ///         assert!(!repair.is_automatic());
    ///         assert_eq!(repair.term().estimated_cost_micro_usd, 0);
    ///     }
    /// }
    /// ```
    pub fn try_repair(&self, term: &ActionTerm) -> Option<Repair> {
        let mut repaired = term.clone();
        match self {
            // IntegrityGate: raise artifact integrity to the required minimum.
            // This requires human review — we can't fabricate integrity.
            Self::RaiseIntegrity { required, sink, .. } => {
                repaired.artifact_label.integrity = *required;
                Some(Repair::NeedsApproval {
                    term: repaired,
                    gate: format!(
                        "human review required to attest artifact integrity \
                         at {:?} for sink {:?}",
                        required, sink
                    ),
                })
            }

            // PathAllowed: structural mismatch — no automatic rewrite.
            // The caller must fix the operation/sink pairing.
            Self::CorrectOperationSinkPair { .. } => None,

            // DerivationClear: promote derivation to HumanPromoted.
            // Requires human attestation.
            Self::PromoteDerivation { sink, .. } => {
                repaired.artifact_label.derivation = DerivationClass::HumanPromoted;
                Some(Repair::NeedsApproval {
                    term: repaired,
                    gate: format!(
                        "human attestation required to promote derivation \
                         to HumanPromoted for verified sink {:?}",
                        sink
                    ),
                })
            }

            // NoAdversarialAncestry: strip adversarial source labels.
            // NeedsApproval: stripping adversarial ancestry is a
            // security-significant declassification — a naive agent loop
            // must not auto-launder tainted inputs without human review.
            Self::DeclassifyOrReplaceInput { subject } => {
                repaired
                    .source_labels
                    .retain(|l| l.integrity != IntegLevel::Adversarial);
                Some(Repair::NeedsApproval {
                    term: repaired,
                    gate: format!(
                        "human review required: adversarial source labels stripped from '{}' — \
                         verify the action was re-derived from clean sources",
                        subject
                    ),
                })
            }

            // BudgetNotExceeded: zero the cost requires approval — silently
            // zeroing cost to bypass budget enforcement is policy-significant.
            Self::WireBudgetGate { cost_micro_usd } => {
                repaired.estimated_cost_micro_usd = 0;
                Some(Repair::NeedsApproval {
                    term: repaired,
                    gate: format!(
                        "budget gate required: cost {}µ¢ zeroed — \
                         wire a real budget tracker or obtain approval to waive cost",
                        cost_micro_usd
                    ),
                })
            }

            // ObtainHumanApproval: the term itself is fine, just needs approval.
            Self::ObtainHumanApproval { reason } => Some(Repair::NeedsApproval {
                term: repaired,
                gate: reason.clone(),
            }),

            // ReduceCapabilityRequest: lower the requested level to the ceiling.
            Self::ReduceCapabilityRequest { ceiling, .. } => {
                // We can't change the operation's capability from here
                // (that's in the CapabilityLattice, not the ActionTerm).
                // But we flag it as needing a policy change.
                Some(Repair::NeedsApproval {
                    term: repaired,
                    gate: format!(
                        "policy change required: raise capability ceiling \
                         to at least {:?}",
                        ceiling
                    ),
                })
            }

            // OutOfTaskScope: structural — the operation is not authorized by
            // the verified task token. There is no automatic rewrite (we cannot
            // widen a token from here — that would be exactly the forgery the
            // token system prevents). The caller must obtain a broader token.
            Self::OutOfTaskScope { operation, .. } => Some(Repair::NeedsApproval {
                term: repaired,
                gate: format!(
                    "task token change required: obtain a verified task token whose \
                     scope authorizes operation {:?}",
                    operation
                ),
            }),

            // InputsAuthorized: the inputs channel is un-plumbed (`None`). This is
            // a wiring defect, not a policy decision — we cannot fabricate the
            // FlowTracker content hashes here (that would be exactly the vacuous
            // witness the fail-closed check exists to prevent). No automatic
            // rewrite; the caller must populate `content_addressed_inputs` from the
            // term-building seam. Structural, like `CorrectOperationSinkPair`.
            Self::ProvideContentAddressedInputs { .. } => None,
        }
    }
}

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

/// Obligation: the requested capability level is within the policy ceiling for
/// this operation.
///
/// Lifts the upstream `WithinDelegationCeiling` check
/// (`portcullis::action_term`): a requested authority must not exceed the level
/// the capability lattice grants for the operation. Fail-closed — if
/// either the ceiling or the requested level is absent, the obligation is
/// **denied**, never minted (see [`preflight_action`]).
pub struct WithinDelegationCeiling;
impl obligation_sealed::ObligationSealed for WithinDelegationCeiling {}
impl ProofObligation for WithinDelegationCeiling {}

/// Obligation: the operation is within the verified task token's scope.
///
/// Lifts the upstream `InScopeWithTask` check (`portcullis::action_term`): the
/// operation must be a member of the verified token's `allowed_operations`.
/// Fail-closed — if no [`VerifiedScope`] is present (no verified token), the
/// obligation is **denied**, never minted (the NO-VACUOUS-WITNESS guard). See
/// [`preflight_action`].
pub struct InScopeWithTask;
impl obligation_sealed::ObligationSealed for InScopeWithTask {}
impl ProofObligation for InScopeWithTask {}

/// Obligation: every input feeding this action is content-addressed.
///
/// Lifts the upstream `InputsAuthorized` check (`portcullis::action_term`),
/// which fails when any input carries an empty `source_hash`. The discharge
/// layer attests the same property *structurally*: the content-addressed inputs
/// flow onto the [`ActionTerm`] as kernel [`ContentHash`]es, and a `ContentHash`
/// is a 32-byte recomputed digest **by construction** (bricks 3+4 recompute
/// ingest hashes from bytes) — so there is no empty-hash state to reject
/// per-element; the obligation attests *presence*. Fail-closed — if the
/// [`ActionTerm`]'s `content_addressed_inputs` is `None` (the un-plumbed state),
/// the obligation is **denied**, never minted (the NO-VACUOUS-WITNESS guard). A
/// `Some(vec![])` (an action with no inputs) mints vacuously, matching upstream's
/// `!inputs.any(empty_hash)` returning satisfied for zero inputs. See
/// [`preflight_action`].
pub struct InputsAuthorized;
impl obligation_sealed::ObligationSealed for InputsAuthorized {}
impl ProofObligation for InputsAuthorized {}

// ═══════════════════════════════════════════════════════════════════════════
// VerifiedScope — dependency-free carrier for the verified task-token scope
// ═══════════════════════════════════════════════════════════════════════════

/// The verified effective scope of a task capability token, mirrored locally.
///
/// This is a **fallback carrier** for the shape of
/// `nucleus_provenance_memory::taskref_token::TokenScope`
/// (`allowed_operations` + `allowed_paths`). The canonical `TokenScope` lives in
/// `nucleus-provenance-memory`, which depends on `portcullis-core`, which
/// re-exports **this** crate — so `nucleus-ifc-kernel` cannot depend on
/// `nucleus-provenance-memory` without forming the cycle
/// `nucleus-ifc-kernel → nucleus-provenance-memory → portcullis-core →
/// nucleus-ifc-kernel`. The dependency-free Aeneas kernel must stay acyclic, so
/// the scope is carried in this local struct and `portcullis-effects` converts
/// `TokenScope → VerifiedScope` at the term-building seam (`build_term_scoped`).
///
/// Only the `allowed_operations` dimension is enforced by
/// [`InScopeWithTask`] today: the discharge [`ActionTerm`] carries no path, so
/// `allowed_paths` is retained for completeness/audit but not checked here (this
/// mirrors upstream's behavior when `action_path()` is `None`). A follow-up that
/// adds a path to the discharge term can lift the path dimension too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedScope {
    /// Operations the verified token authorizes (allowlist; empty = none).
    pub allowed_operations: Vec<Operation>,
    /// Path patterns the token authorizes. Retained for audit; not enforced by
    /// `InScopeWithTask` because the discharge `ActionTerm` carries no path.
    pub allowed_paths: Vec<String>,
}

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
/// Holds typed discharge witnesses for all eight policy obligations. Effect
/// functions require a `&DischargedBundle` to proceed; there is **no other
/// way to construct one** — the `_seal` field is private to this module.
///
/// # Sealing guarantee
///
/// The `_seal` field is unnameable outside this module, so **no**
/// `DischargedBundle` struct literal compiles externally — even one that names
/// every one of the eight public obligation fields (the missing `_seal` alone
/// is fatal, and `Discharged::mint()` is private too):
///
/// ```compile_fail
/// // This code does NOT compile — neither Seal nor mint() is accessible.
/// use nucleus_ifc_kernel::discharge::{
///     DischargedBundle, Discharged, IntegrityGate, PathAllowed, DerivationClear,
///     NoAdversarialAncestry, BudgetNotExceeded, WithinDelegationCeiling, InScopeWithTask,
///     InputsAuthorized,
/// };
/// let bundle = DischargedBundle {
///     integrity_gate: Discharged::<IntegrityGate>::mint(),  // mint() is private
///     path_allowed: Discharged::<PathAllowed>::mint(),
///     derivation_clear: Discharged::<DerivationClear>::mint(),
///     no_adversarial_ancestry: Discharged::<NoAdversarialAncestry>::mint(),
///     budget_not_exceeded: Discharged::<BudgetNotExceeded>::mint(),
///     within_delegation_ceiling: Discharged::<WithinDelegationCeiling>::mint(),
///     in_scope_with_task: Discharged::<InScopeWithTask>::mint(),
///     inputs_authorized: Discharged::<InputsAuthorized>::mint(),
///     // no `_seal`: the field is private — and even with all eight fields
///     // above this literal cannot be completed outside the module.
/// };
/// ```
///
/// Receiving a `DischargedBundle` is proof that `preflight_action` ran and
/// all obligations passed.
#[must_use = "a DischargedBundle must be passed to the effect function it authorizes"]
pub struct DischargedBundle {
    /// Artifact integrity ≥ the floor for this pair's kind at its sink.
    pub integrity_gate: Discharged<IntegrityGate>,
    /// Operation is structurally permitted for this sink.
    pub path_allowed: Discharged<PathAllowed>,
    /// Derivation class is compatible with this sink.
    pub derivation_clear: Discharged<DerivationClear>,
    /// No source label carries adversarial integrity — or, for a
    /// [`ActionKind::PureRead`] or [`ActionKind::AuthorityReducing`] pair, the
    /// check does not apply: neither carries anything outward.
    /// [`DischargedBundle::kind`] says which.
    pub no_adversarial_ancestry: Discharged<NoAdversarialAncestry>,
    /// Estimated cost fits within the budget gate.
    pub budget_not_exceeded: Discharged<BudgetNotExceeded>,
    /// Requested capability ≤ policy ceiling for the operation.
    pub within_delegation_ceiling: Discharged<WithinDelegationCeiling>,
    /// Operation is within the verified task token's scope.
    pub in_scope_with_task: Discharged<InScopeWithTask>,
    /// Every action input is content-addressed (present on the term).
    pub inputs_authorized: Discharged<InputsAuthorized>,
    /// The operation this bundle was discharged FOR.
    ///
    /// Without this the bundle proved only "a preflight ran somewhere", never
    /// "a preflight ran for THIS action" — the effect functions take it as
    /// `_proof`, an unused type-level token, so a bundle earned for a workspace
    /// write was structurally usable to authorise a shell spawn. That is the
    /// confused deputy, and the standard remedy is to bind the token to the
    /// approved operation and scope (the macaroon "request-hash caveat"
    /// pattern).
    operation: Operation,
    /// The sink class this bundle was discharged FOR.
    sink_class: SinkClass,
    /// The subject this bundle was discharged FOR.
    ///
    /// `operation` and `sink_class` bind the *kind* of action. They do not bind
    /// which one: a bundle earned to run `ls` is `(RunBash, BashExec)`, and so
    /// is a bundle earned to run `rm -rf /`. The confused-deputy argument above
    /// applies one level deeper than it was applied, and this closes it — the
    /// "request-hash caveat" is about the request, not its category.
    ///
    /// Set from `ActionTerm::subject` at the single point a bundle can be
    /// built. Nothing else reads `subject` on the term: the kernel uses it only
    /// in denial messages, so binding it here changes no obligation.
    subject: String,
    _seal: Seal,
}

impl DischargedBundle {
    /// Private constructor — only callable from within this module.
    fn new(operation: Operation, sink_class: SinkClass, subject: String) -> Self {
        Self {
            integrity_gate: Discharged::mint(),
            path_allowed: Discharged::mint(),
            derivation_clear: Discharged::mint(),
            no_adversarial_ancestry: Discharged::mint(),
            budget_not_exceeded: Discharged::mint(),
            within_delegation_ceiling: Discharged::mint(),
            in_scope_with_task: Discharged::mint(),
            inputs_authorized: Discharged::mint(),
            operation,
            sink_class,
            subject,
            _seal: Seal,
        }
    }

    /// The operation this bundle authorises. Read-only: the scope is fixed at
    /// discharge and cannot be widened afterwards.
    pub fn operation(&self) -> Operation {
        self.operation
    }

    /// The sink class this bundle authorises.
    pub fn sink_class(&self) -> SinkClass {
        self.sink_class
    }

    /// What this bundle's pair does — derived from the sealed
    /// `(operation, sink_class)`, never stored and never supplied by a caller.
    /// See [`ActionKind`] for why a [`ActionKind::PureRead`] bundle cannot pay
    /// for anything but a read.
    #[must_use]
    pub fn kind(&self) -> ActionKind {
        action_kind(self.operation, self.sink_class)
    }

    /// The subject this bundle authorises — the target, not its category.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// **Does this bundle authorise `op` at `sink`?**
    ///
    /// The check the effect functions never made. Each effect knows which
    /// operation IT is, so it can ask this without needing the original
    /// `ActionTerm` threaded through its signature — the reason the binding is
    /// on (operation, sink_class) rather than a full term hash. It is the
    /// binding the 2026 confused-deputy guidance recommends: bind the token to
    /// the approved operation and scope, so a bundle earned for one action
    /// cannot be presented for another.
    #[must_use]
    pub fn authorizes(&self, op: Operation, sink: SinkClass) -> bool {
        self.operation == op && self.sink_class == sink
    }

    /// **Does this bundle authorise `op` at `sink`, on `subject`?**
    ///
    /// [`authorizes`](Self::authorizes) answers for the *kind* of action. This
    /// answers for the action. A caller that can name what it is about to do —
    /// the command it will spawn, the remote it will push to — should ask this
    /// one, because the other cannot tell `ls` from `rm -rf /`.
    #[must_use]
    pub fn authorizes_subject(&self, op: Operation, sink: SinkClass, subject: &str) -> bool {
        self.authorizes(op, sink) && self.subject == subject
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
            .field("within_delegation_ceiling", &self.within_delegation_ceiling)
            .field("in_scope_with_task", &self.in_scope_with_task)
            .field("inputs_authorized", &self.inputs_authorized)
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
/// use nucleus_ifc_kernel::discharge::ActionTerm;
/// use nucleus_ifc_kernel::{Operation, SinkClass, IFCLabel};
///
/// let term = ActionTerm {
///     operation: Operation::GitCommit,
///     sink_class: SinkClass::GitCommit,
///     source_labels: vec![],
///     artifact_label: IFCLabel::default(),
///     subject: "spiffe://nucleus/agent/ci-bot".to_string(),
///     estimated_cost_micro_usd: 0,
///     capability_ceiling: None,
///     requested_capability: None,
///     verified_scope: None,
///     content_addressed_inputs: Some(vec![]),
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
    ///
    /// **Known gap (#1362)**: All current callsites pass 0 because no cost
    /// estimation is wired yet. The `BudgetNotExceeded` obligation is
    /// structurally sound but operationally dormant until a cost estimator
    /// is integrated (e.g., LLM token pricing, API call metering).
    pub estimated_cost_micro_usd: u64,
    /// The policy ceiling: the capability level the capability lattice
    /// grants for `operation`. `None` when unknown — which **denies**
    /// [`WithinDelegationCeiling`] fail-closed (never mints a vacuous witness).
    pub capability_ceiling: Option<CapabilityLevel>,
    /// The capability level this action requests for `operation`. `None` denies
    /// [`WithinDelegationCeiling`] fail-closed. Callers building real terms set
    /// this to the operation's inherent floor (see `build_term` in
    /// `portcullis-effects`); the ceiling check is `requested ≤ ceiling`.
    pub requested_capability: Option<CapabilityLevel>,
    /// The verified effective scope of the session's task capability token, if
    /// any. `None` denies [`InScopeWithTask`] fail-closed — the
    /// NO-VACUOUS-WITNESS guard: an action with no verified scope can never mint
    /// `Discharged<InScopeWithTask>`.
    pub verified_scope: Option<VerifiedScope>,
    /// The content-addressed inputs feeding this action, one [`ContentHash`] per
    /// source node that carries a recorded digest (InputsAuthorized bricks 1+3).
    ///
    /// `None` is the **un-plumbed** state and denies [`InputsAuthorized`]
    /// fail-closed (the NO-VACUOUS-WITNESS guard: no witness is minted from an
    /// absent inputs channel). `Some(inputs)` mints the witness — every
    /// `ContentHash` is a 32-byte recomputed digest by construction, so the
    /// discharge layer attests *presence*, not per-element validity. A
    /// `Some(vec![])` (an action with no inputs) mints vacuously. Callers building
    /// real terms collect these from the FlowTracker (see `build_term_scoped` in
    /// `portcullis-effects`).
    pub content_addressed_inputs: Option<Vec<ContentHash>>,
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
    /// At least one obligation failed. Contains a human-readable reason
    /// and a machine-readable [`RepairHint`] for automated self-repair.
    Denied {
        /// Human-readable explanation of the denial.
        reason: String,
        /// Structured repair target — tells the agent exactly what to fix.
        hint: RepairHint,
    },
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
        matches!(self, Self::Denied { .. })
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
            Self::Denied { reason, .. } => panic!("preflight denied: {reason}"),
            Self::RequiresApproval { reason } => {
                panic!("preflight requires approval: {reason}")
            }
        }
    }

    /// Extract the denial reason, or `None` if not `Denied`.
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::Denied { reason, .. } => Some(reason.as_str()),
            _ => None,
        }
    }

    /// Extract the repair hint, or `None` if not `Denied`.
    pub fn repair_hint(&self) -> Option<&RepairHint> {
        match self {
            Self::Denied { hint, .. } => Some(hint),
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
/// 4. **NoAdversarialAncestry** — no source label carries `Adversarial` integrity;
///    charged to [`ActionKind::Acting`] pairs only — a [`ActionKind::PureRead`]
///    or [`ActionKind::AuthorityReducing`] pair skips it (see [`ActionKind`]).
///    Obligation 1's floor is also per kind (`integrity_floor`). Every other
///    obligation applies to every kind.
/// 5. **BudgetNotExceeded** — zero-cost always passes; non-zero requires budget gate
/// 6. **WithinDelegationCeiling** — requested capability ≤ policy ceiling for the op;
///    fail-closed if either level is absent
/// 7. **InScopeWithTask** — operation is within the verified task token's scope;
///    fail-closed if no verified scope is present (NO-VACUOUS-WITNESS guard)
/// 8. **InputsAuthorized** — every action input is content-addressed (present);
///    fail-closed if the inputs channel is un-plumbed (`None`) — NO-VACUOUS-WITNESS
///
/// Checks short-circuit on the first denial for latency. All non-denial
/// states are fully evaluated before the bundle is minted.
///
/// # Example
///
/// ```rust
/// use nucleus_ifc_kernel::discharge::{ActionTerm, VerifiedScope, preflight_action, PreflightResult};
/// use nucleus_ifc_kernel::{CapabilityLevel, Operation, SinkClass, IFCLabel};
///
/// let term = ActionTerm {
///     operation: Operation::WriteFiles,
///     sink_class: SinkClass::WorkspaceWrite,
///     source_labels: vec![],
///     artifact_label: IFCLabel::default(),
///     subject: "spiffe://nucleus/agent/test".to_string(),
///     estimated_cost_micro_usd: 0,
///     // Fail-closed inputs for the two new obligations: without these the
///     // action is denied (WithinDelegationCeiling / InScopeWithTask).
///     capability_ceiling: Some(CapabilityLevel::LowRisk),
///     requested_capability: Some(CapabilityLevel::LowRisk),
///     verified_scope: Some(VerifiedScope {
///         allowed_operations: vec![Operation::WriteFiles],
///         allowed_paths: vec![],
///     }),
///     // Inputs channel plumbed (no inputs → vacuously authorized).
///     content_addressed_inputs: Some(vec![]),
/// };
///
/// match preflight_action(&term) {
///     PreflightResult::Allowed(_bundle) => { /* pass bundle to effect fn */ }
///     PreflightResult::Denied { reason, hint } => { /* log and abort */ }
///     PreflightResult::RequiresApproval { reason } => { /* await approval */ }
/// }
/// ```
/// Test helpers for producing `DischargedBundle`s in tests.
///
/// These run a real `preflight_action` on a known-good term, so they mint
/// nothing that was not earned — but a production build has no business being
/// able to obtain a bundle it did not discharge itself, and "only use in tests"
/// in a doc comment is a convention, not an enforcement.
///
/// GATED behind `test-helpers` (2026-07-26). `#[cfg(test)]` alone cannot work
/// here: three crates consume this ACROSS the crate boundary, where `cfg(test)`
/// is false because the kernel is compiled as a dependency rather than as the
/// crate under test. A feature is the only gate that reaches them, and it keeps
/// the helper out of any build that does not ask for it by name.
#[doc(hidden)]
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use crate::{
        AuthorityLevel, ConfLevel, DerivationClass, Freshness, IntegLevel, Operation,
        ProvenanceSet, SinkClass,
    };

    /// Produce a bundle scoped to a specific operation, sink **and subject**.
    ///
    /// The subject-less forms mint `"test-helper"`, which is right for a test
    /// asserting something about the `(operation, sink)` pair and wrong for one
    /// that spends the authority: a spend binds the target, so the bundle must
    /// have been earned for it. Panics if the pair is not earnable.
    pub fn bundle_for_subject(
        operation: Operation,
        sink_class: SinkClass,
        subject: &str,
    ) -> DischargedBundle {
        try_bundle_for_subject(operation, sink_class, subject).unwrap_or_else(|| {
            panic!("test_helpers::bundle_for_subject: {operation:?}/{sink_class:?} is not earnable")
        })
    }

    /// Produce a bundle scoped to a SPECIFIC operation and sink.
    ///
    /// `allowed_bundle` mints a WriteFiles/WorkspaceWrite bundle, and tests were
    /// using it to authorise shell spawns — the confused deputy, sitting in the
    /// test suite. Now that a bundle is bound to what it was earned for, a test
    /// that needs to authorise a shell spawn must mint a shell-scoped bundle.
    pub fn bundle_for(operation: Operation, sink_class: SinkClass) -> DischargedBundle {
        let term = ActionTerm {
            operation,
            sink_class,
            source_labels: vec![],
            artifact_label: crate::IFCLabel {
                confidentiality: ConfLevel::Internal,
                integrity: IntegLevel::Trusted,
                authority: AuthorityLevel::Directive,
                provenance: ProvenanceSet::SYSTEM,
                freshness: Freshness {
                    observed_at: 1000,
                    ttl_secs: 0,
                },
                derivation: DerivationClass::Deterministic,
            },
            subject: "test-helper".to_string(),
            estimated_cost_micro_usd: 0,
            capability_ceiling: Some(crate::CapabilityLevel::LowRisk),
            requested_capability: Some(crate::CapabilityLevel::LowRisk),
            verified_scope: Some(VerifiedScope {
                allowed_operations: vec![operation],
                allowed_paths: vec![],
            }),
            content_addressed_inputs: Some(vec![]),
        };
        match preflight_action(&term) {
            PreflightResult::Allowed(bundle) => bundle,
            other => panic!("test_helpers::bundle_for: expected Allowed, got {other:?}"),
        }
    }

    /// Like [`bundle_for`], but `None` instead of a panic when the pair is not
    /// dischargeable.
    ///
    /// Not every `(Operation, SinkClass)` pair is structurally permitted —
    /// `PathAllowed` rejects e.g. `ReadFiles`/`WorkspaceWrite`. A test that wants
    /// to sweep the whole product needs to distinguish "this pair cannot be
    /// earned" from "this pair was earned and then misused", which the panicking
    /// form cannot express.
    pub fn try_bundle_for(operation: Operation, sink_class: SinkClass) -> Option<DischargedBundle> {
        try_bundle_for_subject(operation, sink_class, "test-helper")
    }

    /// Like [`try_bundle_for`], with the subject the bundle is discharged for.
    ///
    /// A bundle binds its subject, so a test that spends one against a real
    /// target needs a bundle minted for that target. The subject-less forms
    /// mint `"test-helper"`, which is the right default for a test asserting
    /// something about the `(operation, sink)` pair and the wrong one for a
    /// test that spends.
    pub fn try_bundle_for_subject(
        operation: Operation,
        sink_class: SinkClass,
        subject: &str,
    ) -> Option<DischargedBundle> {
        let term = ActionTerm {
            operation,
            sink_class,
            source_labels: vec![],
            artifact_label: crate::IFCLabel {
                confidentiality: ConfLevel::Internal,
                integrity: IntegLevel::Trusted,
                authority: AuthorityLevel::Directive,
                provenance: ProvenanceSet::SYSTEM,
                freshness: Freshness {
                    observed_at: 1000,
                    ttl_secs: 0,
                },
                derivation: DerivationClass::Deterministic,
            },
            subject: subject.to_string(),
            estimated_cost_micro_usd: 0,
            capability_ceiling: Some(crate::CapabilityLevel::LowRisk),
            requested_capability: Some(crate::CapabilityLevel::LowRisk),
            verified_scope: Some(VerifiedScope {
                allowed_operations: vec![operation],
                allowed_paths: vec![],
            }),
            content_addressed_inputs: Some(vec![]),
        };
        match preflight_action(&term) {
            PreflightResult::Allowed(bundle) => Some(bundle),
            _ => None,
        }
    }

    /// Produce a `DischargedBundle` by running preflight on a known-good term.
    pub fn allowed_bundle() -> DischargedBundle {
        let term = ActionTerm {
            operation: Operation::WriteFiles,
            sink_class: SinkClass::WorkspaceWrite,
            source_labels: vec![],
            artifact_label: crate::IFCLabel {
                confidentiality: ConfLevel::Internal,
                integrity: IntegLevel::Trusted,
                authority: AuthorityLevel::Directive,
                provenance: ProvenanceSet::SYSTEM,
                freshness: Freshness {
                    observed_at: 1000,
                    ttl_secs: 0,
                },
                derivation: DerivationClass::Deterministic,
            },
            subject: "test-helper".to_string(),
            estimated_cost_micro_usd: 0,
            // Happy-path inputs for the two new obligations (widen 5 → 7):
            // the op is granted at LowRisk and is in the verified token scope.
            capability_ceiling: Some(crate::CapabilityLevel::LowRisk),
            requested_capability: Some(crate::CapabilityLevel::LowRisk),
            verified_scope: Some(VerifiedScope {
                allowed_operations: vec![Operation::WriteFiles],
                allowed_paths: vec![],
            }),
            // Happy-path input for the widen 7 → 8 obligation (InputsAuthorized):
            // the inputs channel is plumbed (no inputs → vacuously authorized).
            content_addressed_inputs: Some(vec![]),
        };
        match preflight_action(&term) {
            PreflightResult::Allowed(bundle) => bundle,
            other => panic!("test_helpers::allowed_bundle: expected Allowed, got {other:?}"),
        }
    }
}

pub fn preflight_action(term: &ActionTerm) -> PreflightResult {
    // The kind is derived from the pair once, here, and never read from the
    // term (G-1). Obligations 1 and 4 are the only two it changes.
    let kind = action_kind(term.operation, term.sink_class);

    // 1. IntegrityGate: artifact integrity must meet the sink minimum — the
    //    floor for this KIND at this sink (see `integrity_floor`).
    let min_integ = integrity_floor(kind, term.sink_class);
    if term.artifact_label.integrity < min_integ {
        return PreflightResult::Denied {
            reason: format!(
                "IntegrityGate: artifact integrity {:?} below minimum {:?} required for {:?}",
                term.artifact_label.integrity, min_integ, term.sink_class
            ),
            hint: RepairHint::RaiseIntegrity {
                actual: term.artifact_label.integrity,
                required: min_integ,
                sink: term.sink_class,
            },
        };
    }

    // 2. PathAllowed: operation/sink pair must be structurally consistent.
    if !operation_allowed_for_sink(term.operation, term.sink_class) {
        return PreflightResult::Denied {
            reason: format!(
                "PathAllowed: operation {:?} is not permitted for sink {:?}",
                term.operation, term.sink_class
            ),
            hint: RepairHint::CorrectOperationSinkPair {
                operation: term.operation,
                declared_sink: term.sink_class,
            },
        };
    }

    // 3. DerivationClear: derivation class must be compatible with the sink.
    if sink_requires_verified_derivation(term.sink_class)
        && !StorageLane::Verified.accepts(term.artifact_label.derivation)
    {
        return PreflightResult::Denied {
            reason: format!(
                "DerivationClear: {:?} derivation is not permitted at verified sink {:?} \
                 (requires Deterministic or HumanPromoted)",
                term.artifact_label.derivation, term.sink_class
            ),
            hint: RepairHint::PromoteDerivation {
                actual: term.artifact_label.derivation,
                sink: term.sink_class,
            },
        };
    }

    // 4. NoAdversarialAncestry: no source label may carry Adversarial integrity
    //    — for a pair that can act. A pure read carries nothing outward, and the
    //    bytes it returns are observed back into the session graph, so every
    //    later Acting pair still pays this for them (see `ActionKind`). An
    //    AuthorityReducing pair skips it too: stopping a child carries nothing
    //    outward either, and refusing it is what left a tainted parent unable
    //    to stop the children it started.
    match kind {
        ActionKind::Acting => {
            for label in &term.source_labels {
                if label.integrity == IntegLevel::Adversarial {
                    return PreflightResult::Denied {
                        reason: format!(
                            "NoAdversarialAncestry: adversarial-integrity source label present \
                             in action by subject '{}'",
                            term.subject
                        ),
                        hint: RepairHint::DeclassifyOrReplaceInput {
                            subject: term.subject.clone(),
                        },
                    };
                }
            }
        }
        ActionKind::PureRead | ActionKind::AuthorityReducing => {}
    }

    // 5. BudgetNotExceeded: non-zero cost requires a wired budget gate.
    if term.estimated_cost_micro_usd > 0 {
        return PreflightResult::Denied {
            reason: format!(
                "BudgetNotExceeded: non-zero cost {}µUSD requires a budget gate \
                 (wire BudgetGate via portcullis-effects before submitting non-zero-cost terms)",
                term.estimated_cost_micro_usd
            ),
            hint: RepairHint::WireBudgetGate {
                cost_micro_usd: term.estimated_cost_micro_usd,
            },
        };
    }

    // 6. WithinDelegationCeiling: the requested capability must not exceed the
    //    policy ceiling for this operation. FAIL-CLOSED — if either the ceiling
    //    or the requested level is absent, DENY (never mint a vacuous witness).
    //    Mirrors `portcullis::action_term`'s `requested_level > available` gate
    //    (level_for(op) is the ceiling); with the runtime's inherent per-op
    //    floor for `requested`, this denies exactly the operations the policy
    //    forbids (ceiling == Never).
    match (term.capability_ceiling, term.requested_capability) {
        (Some(ceiling), Some(requested)) => {
            if requested > ceiling {
                return PreflightResult::Denied {
                    reason: format!(
                        "WithinDelegationCeiling: requested capability {requested:?} exceeds \
                         policy ceiling {ceiling:?} for operation {:?}",
                        term.operation
                    ),
                    hint: RepairHint::ReduceCapabilityRequest { requested, ceiling },
                };
            }
        }
        _ => {
            return PreflightResult::Denied {
                reason: format!(
                    "WithinDelegationCeiling: missing capability ceiling/request for \
                     operation {:?} — denied fail-closed (no vacuous witness)",
                    term.operation
                ),
                hint: RepairHint::ReduceCapabilityRequest {
                    // No known request/ceiling: surface the strictest hint (Never
                    // ceiling) so any non-Never request is flagged.
                    requested: term.requested_capability.unwrap_or(CapabilityLevel::Always),
                    ceiling: term.capability_ceiling.unwrap_or(CapabilityLevel::Never),
                },
            };
        }
    }

    // 7. InScopeWithTask: the operation must be within the verified task token's
    //    scope. FAIL-CLOSED — if no VerifiedScope is present (no verified token),
    //    DENY and never mint (the NO-VACUOUS-WITNESS guard). Mirrors
    //    `portcullis::action_term`'s `InScopeWithTask`: op ∈ allowed_operations.
    //    (The discharge ActionTerm carries no path, so the allowed_paths
    //    dimension is not enforced here — see `VerifiedScope`.)
    match &term.verified_scope {
        Some(scope) if scope.allowed_operations.contains(&term.operation) => {
            // in scope — fall through to mint.
        }
        _ => {
            return PreflightResult::Denied {
                reason: format!(
                    "InScopeWithTask: operation {:?} is not within the verified task scope \
                     (or no verified scope present) for subject '{}'",
                    term.operation, term.subject
                ),
                hint: RepairHint::OutOfTaskScope {
                    operation: term.operation,
                    subject: term.subject.clone(),
                },
            };
        }
    }

    // 8. InputsAuthorized: every input feeding this action must be
    //    content-addressed. FAIL-CLOSED — if `content_addressed_inputs` is `None`
    //    (the un-plumbed state), DENY and never mint (the NO-VACUOUS-WITNESS
    //    guard). `Some(inputs)` mints: each `ContentHash` is a 32-byte recomputed
    //    digest by construction (bricks 3+4 recompute ingest hashes from bytes),
    //    so the discharge layer attests PRESENCE — there is no empty-hash state to
    //    reject per-element. An empty vec = an action with no inputs = vacuously
    //    authorized = mint, matching `portcullis::action_term`'s
    //    `!inputs.any(|i| i.source_hash.is_empty())` returning satisfied for zero
    //    inputs.
    if term.content_addressed_inputs.is_none() {
        return PreflightResult::Denied {
            reason: format!(
                "InputsAuthorized: content-addressed inputs channel is un-plumbed (None) \
                 for operation {:?} by subject '{}' — denied fail-closed (no vacuous witness)",
                term.operation, term.subject
            ),
            hint: RepairHint::ProvideContentAddressedInputs {
                subject: term.subject.clone(),
            },
        };
    }

    PreflightResult::Allowed(DischargedBundle::new(
        term.operation,
        term.sink_class,
        term.subject.clone(),
    ))
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

/// The integrity floor obligation 1 charges a pair of this `kind` at `sink`.
///
/// **Why the kind enters obligation 1 (2026-09-27).** Teardown is
/// `(ManagePods, CloudMutation)`, and `CloudMutation` is a publish sink with an
/// `Untrusted` floor — correct for a pair that creates or changes cloud state,
/// and wrong for one that can only remove it. A session that had read one
/// hostile page carried an `Adversarial` artifact label, failed this floor, and
/// could no longer cancel the pods it had spawned: the taint that should make
/// an agent *more* willing to stop things made stopping them impossible. An
/// [`ActionKind::AuthorityReducing`] pair's floor is `Adversarial`, i.e. this
/// obligation never refuses it on integrity.
///
/// It is safe because of what the pair reaches, not what it claims: the node
/// resolves a cancel through `get_pod_for_caller`, which admits only the
/// calling pod itself and its direct children, over HTTP and gRPC alike. The
/// worst a steered cancel can do is stop work this session started.
///
/// Exhaustive over [`ActionKind`] (no `bool`, no `_ =>`): a fourth kind must
/// decide its floor here before it compiles.
fn integrity_floor(kind: ActionKind, sink: SinkClass) -> IntegLevel {
    match kind {
        ActionKind::Acting | ActionKind::PureRead => sink_min_integrity(sink),
        ActionKind::AuthorityReducing => IntegLevel::Adversarial,
    }
}

/// Returns `true` if the operation/sink pairing is structurally consistent.
///
/// This is the `PathAllowed` gate: it ensures that the `Operation` variant
/// in the `ActionTerm` is compatible with the declared `SinkClass`. A mismatch
/// indicates a caller bug (e.g., submitting `Operation::GitPush` with
/// `SinkClass::WorkspaceWrite`).
///
/// **Restrictive, not permissive** (SECURITY_TODO #23). The doc here used to
/// claim the opposite — *"returns `true` (permissive) for combinations not
/// explicitly restricted, so adding new `Operation` or `SinkClass` variants does
/// not break existing callers by default"* — and the code has never behaved that
/// way. The `match` is exhaustive over `Operation` and every arm is a `matches!`
/// against a closed list of sinks, so an unlisted pairing returns `false`.
///
/// Which direction the mismatch runs matters. Adding an `Operation` is a compile
/// error (good). Adding a `SinkClass` silently makes it **undischargeable** —
/// safe, but invisible, and the doc promised the opposite so nobody looked.
///
/// Four sinks are unreachable today for exactly that reason, and it is a gap in
/// the `Operation` vocabulary rather than a policy decision: there is no verb for
/// reading a secret, calling an MCP tool, sending email, or writing a ticket.
/// They are enumerated in `SINKS_WITH_NO_OPERATION` below, and
/// `every_sink_is_reachable_or_documented` fails if that list drifts from
/// reality in either direction — so a sink becoming reachable, or a new sink
/// quietly becoming unreachable, is a test failure rather than a silent one.
/// Sinks that no `Operation` can currently be paired with, each with the reason.
///
/// This is a **gap in the `Operation` vocabulary**, not a policy judgement: the
/// enum has thirteen verbs and none of them denotes reading a secret, invoking
/// an MCP tool, sending mail, or filing a ticket. Until `Effect` carries a
/// target (the Tier-3 collapse), an `ActionTerm` naming one of these cannot be
/// constructed from any operation, so the pairing gate refuses it.
///
/// Being unreachable is the SAFE direction — nothing can discharge to them — so
/// this is documented rather than "fixed" by inventing a mapping. What was not
/// safe was that it was invisible, and that the doc on
/// [`operation_allowed_for_sink`] asserted the opposite.
#[cfg(test)] // the expectation table for `every_sink_is_reachable_or_documented`
const SINKS_WITH_NO_OPERATION: [(SinkClass, &str); 4] = [
    (
        SinkClass::SecretRead,
        "no Operation denotes reading a secret; env/secret access is untyped",
    ),
    (
        SinkClass::MCPWrite,
        "an MCP tool call is classified INTO an Operation, it is not one itself",
    ),
    (SinkClass::EmailSend, "no Operation denotes sending mail"),
    (
        SinkClass::TicketWrite,
        "no Operation denotes filing a ticket",
    ),
];

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
                    // Agent memory (2026-09-27). `/v1/memory/write` had no pair
                    // to discharge, so it ran on a dropped `DecisionToken`
                    // instead. Acting: memory outlives the session, so a write
                    // pays `NoAdversarialAncestry` and the `Untrusted` floor.
                    | SinkClass::MemoryPersist
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
        // CloudMutation is TEARDOWN only (cancel), AgentSpawn is create, and
        // AuditLogAppend (2026-09-27) is observe — list, status, logs. Before
        // the observe pair existed a pod read had nothing to discharge, so the
        // proxy's list and logs routes ran on a decision nothing consumed.
        Operation::ManagePods => matches!(
            sink,
            SinkClass::CloudMutation | SinkClass::AgentSpawn | SinkClass::AuditLogAppend
        ),
        // Read-only operations: structurally they produce no writes.
        // Accept AuditLogAppend and MemoryPersist (reading can trigger audit events
        // or cache population). All other write sinks are incoherent for reads.
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => matches!(
            sink,
            SinkClass::AuditLogAppend | SinkClass::MemoryPersist | SinkClass::CacheWrite
        ),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ActionKind — what an admitted pair does to the world
// ═══════════════════════════════════════════════════════════════════════════

/// What an `(Operation, SinkClass)` pair does, as far as the obligations care.
///
/// **Why this exists (2026-09-27).** `NoAdversarialAncestry` is the
/// non-interference clause — adversarial content must not steer an effect —
/// and it ran for every pair. So the first hostile web page an agent fetched
/// refused every later file read: `/v1/read`, `/v1/artifact`, MCP `read` and
/// `grep`, and `NucleusRuntime::preflight_read` all discharge a read at
/// `AuditLogAppend`, and all failed #4 for the rest of the session. A read
/// carries nothing outward. The taint is still recorded when its bytes come
/// back in (the ingest observe paths join them into the session graph), and
/// every pair that could carry them out is [`ActionKind::Acting`] and still
/// pays #4. Refusing the read protected nothing and blinded the agent.
///
/// **Never an input, never stored.** [`ActionTerm`] gains no field and the
/// bundle holds no kind: [`DischargedBundle::kind`] recomputes it from the
/// `(operation, sink_class)` the bundle already seals. So a caller cannot
/// *claim* a pure read — it can only discharge a pair, and the pair decides
/// (G-1: one decider for the fact).
///
/// **Why a pure-read bundle cannot pay for a write.** Nothing about binding
/// changed: [`DischargedBundle::authorizes`] is still pair equality, and the
/// Aeneas-extracted `scope_admits` mirror of it is untouched. The table below
/// keys on the operation first, so `(WriteFiles, AuditLogAppend)` — admissible,
/// and a write — is Acting even though its sink is the read sink. A table that
/// keyed on the sink alone would have made it a pure read;
/// `adversarial_ancestry_still_blocks_a_write_to_the_audit_log` is the test
/// that sees the difference.
///
/// Three variants, not a `bool` (A-1). The third, [`ActionKind::AuthorityReducing`]
/// (2026-09-27), is teardown: `(ManagePods, CloudMutation)`, which the proxy
/// spends only on cancel. It is why this was never a `bool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    /// The pair can change the world or carry data outward. Every obligation
    /// applies. This is the default for any pair not named below.
    Acting,
    /// The pair only brings bytes in. `NoAdversarialAncestry` is not charged;
    /// every other obligation is, unchanged.
    PureRead,
    /// The pair can only take authority away — stop a pod this session may
    /// manage. `NoAdversarialAncestry` is not charged and the integrity floor
    /// is `Adversarial` (see `integrity_floor`); scope, ceiling, inputs,
    /// budget and derivation are charged unchanged, so a session whose task
    /// token does not name `ManagePods` still cannot cancel anything.
    AuthorityReducing,
}

/// The single decider of [`ActionKind`].
///
/// Exhaustive over `Operation` so a new verb is a compile error here, not a
/// silent classification. The three read verbs are PureRead at
/// `AuditLogAppend` only: a read whose result is persisted (`MemoryPersist`,
/// `CacheWrite`) outlives the session and is Acting. `ManagePods` is split by
/// sink: observe (`AuditLogAppend`) is PureRead, teardown (`CloudMutation`) is
/// AuthorityReducing, and create (`AgentSpawn`) is Acting — a spawned child
/// runs whatever it was told, so creating one is the most Acting pair there
/// is. Every inner fallthrough yields `Acting` (B-3: a catch-all arm never
/// grants).
fn action_kind(op: Operation, sink: SinkClass) -> ActionKind {
    match op {
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => match sink {
            SinkClass::AuditLogAppend => ActionKind::PureRead,
            _ => ActionKind::Acting,
        },
        Operation::ManagePods => match sink {
            SinkClass::AuditLogAppend => ActionKind::PureRead,
            SinkClass::CloudMutation => ActionKind::AuthorityReducing,
            _ => ActionKind::Acting,
        },
        Operation::WriteFiles
        | Operation::EditFiles
        | Operation::RunBash
        | Operation::GitCommit
        | Operation::GitPush
        | Operation::CreatePr
        | Operation::WebSearch
        | Operation::WebFetch
        | Operation::SpawnAgent => ActionKind::Acting,
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
#[path = "discharge_tests.rs"]
mod tests;
