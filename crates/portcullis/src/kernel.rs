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

    /// Record a data-source observation in the causal DAG.
    ///
    /// Returns the `NodeId` for use as a parent in subsequent `observe()`
    /// or `decide_with_parents()` calls. Observations are not flow-checked —
    /// they just record what data entered the session.
    ///
    /// Panics if `enable_flow_graph()` was not called.
    pub fn observe(
        &mut self,
        kind: portcullis_core::flow::NodeKind,
        parents: &[u64],
    ) -> Option<u64> {
        let graph = self
            .flow_graph
            .as_mut()
            .expect("enable_flow_graph() not called");
        let now = chrono::Utc::now().timestamp() as u64;
        graph.insert_observation(kind, parents, now).ok()
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
                .map(|r| r.display_chain());
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
        // (budget, capability, path, command, exposure, approvals)
        let mut result = self.decide(operation, subject);
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
        if let Some(ref mut flow_label) = self.flow_label {
            use portcullis_core::flow;

            let now_unix = now.timestamp() as u64;

            // Phase A: check the action against the current (pre-taint) label
            let node = flow::FlowNode {
                id: self.next_seq,
                kind: flow::NodeKind::OutboundAction,
                label: *flow_label,
                parent_count: 0,
                parents: [0; flow::MAX_PARENTS],
                operation: Some(operation),
            };

            match flow::check_flow(&node, now_unix) {
                flow::FlowVerdict::Deny(reason) => {
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
                flow::FlowVerdict::Allow => {
                    // Phase B: taint the session label with the operation's intrinsic
                    let intrinsic = flow::intrinsic_label(Self::node_kind_for(operation), now_unix);
                    *flow_label = flow_label.join(intrinsic);
                }
            }
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
            | Operation::ManagePods => NodeKind::OutboundAction,
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
        Operation::RunBash | Operation::GitPush | Operation::CreatePr
    )
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
}
