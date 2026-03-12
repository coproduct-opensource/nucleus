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
//! taint(dᵢ) ⊆ taint(dᵢ₊₁)          // taint only grows
//! ```
//!
//! Authority never increases. Taint never decreases. Budget is consumed.
//! Time advances. The trace is append-only.
//!
//! # Runtime Taint Tracking
//!
//! The kernel tracks a [`TaintSet`] accumulator across the session. Each
//! allowed operation contributes its taint label (if any) to the set.
//! When the accumulated taint would complete the lethal trifecta
//! (private data + untrusted content + exfiltration vector), the kernel
//! **dynamically gates** exfiltration operations — requiring approval
//! even if the static lattice doesn't mandate it.
//!
//! This is the "tainted-to-sink gating" described in the North Star:
//! static obligations catch structural risks, while runtime taint catches
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
//! // Reading is allowed
//! let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
//! assert!(matches!(d.verdict, Verdict::Allow));
//!
//! // Git push is structurally denied
//! let d = kernel.decide(Operation::GitPush, "origin/main");
//! assert!(matches!(d.verdict, Verdict::Deny(_)));
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
use crate::guard::{TaintLabel, TaintSet};
use crate::isolation::{IsolationLattice, NetworkIsolation};
use crate::lattice::PermissionLattice;
use crate::taint_core;

/// A single decision made by the kernel.
///
/// Captures the operation, subject, verdict, and a snapshot of the
/// permission state before and after the decision — including taint.
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
    /// Taint state transition caused by this decision.
    pub taint_transition: TaintTransition,
}

/// Records the taint state before and after a decision.
///
/// For allowed operations that carry a taint label, `post` will have
/// that label added. For denied operations, taint does not advance
/// (the operation didn't execute).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TaintTransition {
    /// Taint legs active before this decision.
    pub pre_count: u8,
    /// Taint legs active after this decision.
    pub post_count: u8,
    /// The taint label contributed by this operation, if any.
    pub contributed_label: Option<TaintLabel>,
    /// Whether the trifecta was completed by this decision.
    pub trifecta_completed: bool,
    /// Whether a dynamic taint gate was applied (RequiresApproval
    /// due to runtime taint, not static obligations).
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
}

/// The source of a RequiresApproval verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "source", rename_all = "snake_case"))]
pub enum ApprovalSource {
    /// Static obligation from the permission lattice (trifecta in lattice structure).
    StaticObligation,
    /// Dynamic taint gate — runtime taint accumulation completed the trifecta.
    DynamicTaint {
        /// The taint label that would complete the trifecta.
        completing_label: TaintLabel,
    },
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
    /// Runtime taint accumulator — monotonically growing.
    ///
    /// Records which trifecta legs have been touched by allowed operations.
    /// When this reaches trifecta-complete, exfil operations get dynamically gated.
    taint: TaintSet,
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
            taint: TaintSet::empty(),
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
    /// 7. **Dynamic taint gate**: Would this op complete the trifecta at runtime?
    ///
    /// For allowed operations, taint is recorded in the accumulator.
    /// The decision (including taint transition) is recorded in the append-only trace.
    pub fn decide(&mut self, operation: Operation, subject: &str) -> Decision {
        let pre_hash = self.effective.checksum();
        let pre_taint_count = self.taint.count();
        let contributed_label = taint_core::classify_operation(operation);

        // 0. Isolation minimum check — does runtime isolation meet policy requirement?
        if let Some(ref minimum) = self.effective.minimum_isolation {
            if !self.isolation.at_least(minimum) {
                return self.record_with_taint(
                    operation,
                    subject,
                    Verdict::Deny(DenyReason::IsolationInsufficient {
                        required: format!("{}", minimum),
                        actual: format!("{}", self.isolation),
                    }),
                    &pre_hash,
                    pre_taint_count,
                    contributed_label,
                    false,
                    false,
                );
            }
        }

        // 1. Time check
        let now = Utc::now();
        if now > self.effective.time.valid_until {
            return self.record_with_taint(
                operation,
                subject,
                Verdict::Deny(DenyReason::TimeExpired {
                    expired_at: self.effective.time.valid_until,
                }),
                &pre_hash,
                pre_taint_count,
                contributed_label,
                false,
                false,
            );
        }

        // 2. Budget check
        if self.consumed_usd >= self.effective.budget.max_cost_usd {
            return self.record_with_taint(
                operation,
                subject,
                Verdict::Deny(DenyReason::BudgetExhausted {
                    remaining_usd: (self.effective.budget.max_cost_usd - self.consumed_usd)
                        .to_string(),
                }),
                &pre_hash,
                pre_taint_count,
                contributed_label,
                false,
                false,
            );
        }

        // 3. Capability level check
        let level = self.effective.capabilities.level_for(operation);
        if level == CapabilityLevel::Never {
            return self.record_with_taint(
                operation,
                subject,
                Verdict::Deny(DenyReason::InsufficientCapability),
                &pre_hash,
                pre_taint_count,
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
            return self.record_with_taint(
                operation,
                subject,
                Verdict::Deny(DenyReason::IsolationGated {
                    dimension: "network=airgapped".to_string(),
                }),
                &pre_hash,
                pre_taint_count,
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
            return self.record_with_taint(
                operation,
                subject,
                Verdict::Deny(DenyReason::PathBlocked {
                    path: subject.to_string(),
                }),
                &pre_hash,
                pre_taint_count,
                contributed_label,
                false,
                false,
            );
        }

        // 5. Command check (for exec operations)
        if operation == Operation::RunBash && !self.effective.commands.can_execute(subject) {
            return self.record_with_taint(
                operation,
                subject,
                Verdict::Deny(DenyReason::CommandBlocked {
                    command: subject.to_string(),
                }),
                &pre_hash,
                pre_taint_count,
                contributed_label,
                false,
                false,
            );
        }

        // 6. Static approval check (obligations from lattice structure)
        if self.effective.requires_approval(operation) {
            if self.consume_approval(operation) {
                // Approved — record taint from this allowed operation
                self.taint = taint_core::apply_record(&self.taint, operation);
                let trifecta_completed =
                    !TaintSet::empty().is_trifecta_complete() && self.taint.is_trifecta_complete();
                return self.record_with_taint(
                    operation,
                    subject,
                    Verdict::Allow,
                    &pre_hash,
                    pre_taint_count,
                    contributed_label,
                    trifecta_completed,
                    false,
                );
            }
            return self.record_with_taint(
                operation,
                subject,
                Verdict::RequiresApproval,
                &pre_hash,
                pre_taint_count,
                contributed_label,
                false,
                false,
            );
        }

        // 7. Dynamic taint gate — runtime trifecta detection.
        //
        // Project what the taint WOULD be after this operation.
        // If the projected taint completes the trifecta and this op
        // is an exfil vector, gate it with RequiresApproval.
        let projected = taint_core::project_taint(&self.taint, operation);
        if !self.taint.is_trifecta_complete()
            && projected.is_trifecta_complete()
            && is_exfil_operation(operation)
        {
            // Check if there's a pre-granted approval
            if self.consume_approval(operation) {
                self.taint = taint_core::apply_record(&self.taint, operation);
                return self.record_with_taint(
                    operation,
                    subject,
                    Verdict::Allow,
                    &pre_hash,
                    pre_taint_count,
                    contributed_label,
                    true,
                    true,
                );
            }
            return self.record_with_taint(
                operation,
                subject,
                Verdict::RequiresApproval,
                &pre_hash,
                pre_taint_count,
                contributed_label,
                false,
                true,
            );
        }

        // All checks passed — record taint and allow
        let pre_complete = self.taint.is_trifecta_complete();
        self.taint = taint_core::apply_record(&self.taint, operation);
        let trifecta_completed = !pre_complete && self.taint.is_trifecta_complete();

        self.record_with_taint(
            operation,
            subject,
            Verdict::Allow,
            &pre_hash,
            pre_taint_count,
            contributed_label,
            trifecta_completed,
            false,
        )
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

    /// Get the current runtime taint accumulator.
    ///
    /// This reflects which trifecta legs have been touched by allowed
    /// operations during this session. Taint only grows — it is never
    /// reset or reduced.
    pub fn taint(&self) -> &TaintSet {
        &self.taint
    }

    // ── Internal ──────────────────────────────────────────────────────

    /// Record a decision with taint transition in the trace and return it.
    #[allow(clippy::too_many_arguments)]
    fn record_with_taint(
        &mut self,
        operation: Operation,
        subject: &str,
        verdict: Verdict,
        pre_hash: &str,
        pre_taint_count: u8,
        contributed_label: Option<TaintLabel>,
        trifecta_completed: bool,
        dynamic_gate_applied: bool,
    ) -> Decision {
        let post_hash = self.effective.checksum();
        let post_taint_count = self.taint.count();
        let seq = self.next_seq;
        self.next_seq += 1;

        let decision = Decision {
            id: Uuid::new_v4(),
            sequence: seq,
            operation,
            subject: subject.to_string(),
            verdict,
            timestamp: Utc::now(),
            pre_permissions_hash: pre_hash.to_string(),
            post_permissions_hash: post_hash,
            taint_transition: TaintTransition {
                pre_count: pre_taint_count,
                post_count: post_taint_count,
                contributed_label,
                trifecta_completed,
                dynamic_gate_applied,
            },
        };

        self.trace.push(decision.clone());
        decision
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

        let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(d.verdict.is_allowed());
        assert_eq!(d.sequence, 0);
    }

    #[test]
    fn test_capability_deny() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        // safe_pr_fixer has git_push=Never
        let d = kernel.decide(Operation::GitPush, "origin/main");
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
        let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(matches!(
            d.verdict,
            Verdict::Deny(DenyReason::BudgetExhausted { .. })
        ));
    }

    #[test]
    fn test_approval_grant_and_consume() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        // run_bash requires approval in safe_pr_fixer (trifecta mitigation)
        let d = kernel.decide(Operation::RunBash, "cargo test");
        assert!(
            matches!(d.verdict, Verdict::RequiresApproval),
            "should require approval, got {:?}",
            d.verdict
        );

        // Grant 2 approvals
        kernel.grant_approval(Operation::RunBash, 2);

        // First use: approved
        let d = kernel.decide(Operation::RunBash, "cargo test");
        assert!(d.verdict.is_allowed());

        // Second use: approved
        let d = kernel.decide(Operation::RunBash, "cargo build");
        assert!(d.verdict.is_allowed());

        // Third use: no more approvals
        let d = kernel.decide(Operation::RunBash, "cargo check");
        assert!(matches!(d.verdict, Verdict::RequiresApproval));
    }

    #[test]
    fn test_path_blocked() {
        let perms = PermissionLattice::safe_pr_fixer(); // blocks sensitive paths
        let mut kernel = Kernel::new(perms);

        // .ssh is blocked by path lattice
        let d = kernel.decide(Operation::ReadFiles, "/home/user/.ssh/id_rsa");
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
            let d = kernel.decide(op, "test-subject");
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

        let d1 = kernel.decide(Operation::ReadFiles, "/a");
        let d2 = kernel.decide(Operation::ReadFiles, "/b");

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
            .verdict
            .is_allowed());

        // Can write
        let d = kernel.decide(Operation::WriteFiles, "/workspace/docs/guide.md");
        assert!(
            d.verdict.is_allowed() || matches!(d.verdict, Verdict::RequiresApproval),
            "write should be allowed or require approval"
        );

        // Cannot run bash
        assert!(kernel
            .decide(Operation::RunBash, "make docs")
            .verdict
            .is_denied());

        // Cannot push
        assert!(kernel
            .decide(Operation::GitPush, "origin/main")
            .verdict
            .is_denied());

        // Cannot fetch web
        assert!(kernel
            .decide(Operation::WebFetch, "https://example.com")
            .verdict
            .is_denied());
    }

    #[test]
    fn test_monotone_sequence_property() {
        // After attenuation, previously-allowed operations may become denied
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::new(perms);

        // Initially allowed
        let d = kernel.decide(Operation::GitPush, "origin/main");
        // permissive has trifecta so push requires approval, but capability is present
        assert!(!matches!(
            d.verdict,
            Verdict::Deny(DenyReason::InsufficientCapability)
        ));

        // Attenuate to read-only
        let ceiling = PermissionLattice::read_only();
        kernel.attenuate(&ceiling).unwrap();

        // Now denied
        let d = kernel.decide(Operation::GitPush, "origin/main");
        assert!(matches!(
            d.verdict,
            Verdict::Deny(DenyReason::InsufficientCapability)
        ));
    }

    // ── Taint plumbing tests ──────────────────────────────────────────

    #[test]
    fn test_taint_starts_empty() {
        let perms = PermissionLattice::default();
        let kernel = Kernel::new(perms);

        assert_eq!(kernel.taint().count(), 0);
        assert!(!kernel.taint().is_trifecta_complete());
    }

    #[test]
    fn test_taint_accumulates_on_allow() {
        // Use a profile that allows reads and web_fetch without trifecta obligations
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

        // ReadFiles → PrivateData taint
        let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(d.verdict.is_allowed());
        assert!(kernel.taint().contains(TaintLabel::PrivateData));
        assert_eq!(kernel.taint().count(), 1);
        assert_eq!(d.taint_transition.pre_count, 0);
        assert_eq!(d.taint_transition.post_count, 1);
        assert_eq!(
            d.taint_transition.contributed_label,
            Some(TaintLabel::PrivateData)
        );

        // WebFetch → UntrustedContent taint
        let d = kernel.decide(Operation::WebFetch, "https://example.com");
        assert!(d.verdict.is_allowed());
        assert!(kernel.taint().contains(TaintLabel::UntrustedContent));
        assert_eq!(kernel.taint().count(), 2);
        assert_eq!(d.taint_transition.pre_count, 1);
        assert_eq!(d.taint_transition.post_count, 2);
    }

    #[test]
    fn test_taint_does_not_accumulate_on_deny() {
        let perms = PermissionLattice::safe_pr_fixer();
        let mut kernel = Kernel::new(perms);

        // git_push=Never → denied, no taint recorded
        let d = kernel.decide(Operation::GitPush, "origin/main");
        assert!(d.verdict.is_denied());
        assert_eq!(kernel.taint().count(), 0);
        assert_eq!(d.taint_transition.post_count, 0);
    }

    #[test]
    fn test_taint_monotone_never_decreases() {
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

        // Build up taint
        kernel.decide(Operation::ReadFiles, "/a");
        kernel.decide(Operation::WebFetch, "https://b.com");

        // Neutral operation (WriteFiles) should not reduce taint
        kernel.decide(Operation::WriteFiles, "/c");
        assert_eq!(kernel.taint().count(), 2);

        // Denied operation should not reduce taint
        kernel.decide(Operation::RunBash, "echo hi");
        assert_eq!(kernel.taint().count(), 2);
    }

    #[test]
    fn test_dynamic_taint_gate_blocks_exfil() {
        // Build a profile that allows ALL operations (no static obligations).
        // No trifecta obligations in the lattice because we construct one
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

        // Step 1: Read private data → taint PrivateData
        let d = kernel.decide(Operation::ReadFiles, "/etc/passwd");
        assert!(d.verdict.is_allowed());

        // Step 2: Fetch untrusted content → taint UntrustedContent
        let d = kernel.decide(Operation::WebFetch, "https://evil.com/payload");
        assert!(d.verdict.is_allowed());

        // Step 3: Try to push → trifecta would complete → dynamic gate!
        let d = kernel.decide(Operation::GitPush, "origin/main");
        assert!(
            matches!(d.verdict, Verdict::RequiresApproval),
            "dynamic taint gate should block exfil, got {:?}",
            d.verdict
        );
        assert!(d.taint_transition.dynamic_gate_applied);

        // Taint should NOT have advanced (operation was gated, not allowed)
        assert!(!kernel.taint().is_trifecta_complete());
        assert_eq!(kernel.taint().count(), 2);
    }

    #[test]
    fn test_dynamic_taint_gate_with_pre_approval() {
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

        // Accumulate taint
        kernel.decide(Operation::ReadFiles, "/etc/passwd");
        kernel.decide(Operation::WebFetch, "https://evil.com/payload");

        // Push with pre-approval should be allowed through the dynamic gate
        let d = kernel.decide(Operation::GitPush, "origin/main");
        assert!(
            d.verdict.is_allowed(),
            "pre-approved exfil should pass dynamic gate, got {:?}",
            d.verdict
        );
        assert!(d.taint_transition.dynamic_gate_applied);
        assert!(d.taint_transition.trifecta_completed);
        assert!(kernel.taint().is_trifecta_complete());
    }

    #[test]
    fn test_dynamic_taint_gate_does_not_affect_non_exfil() {
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

        // Neutral ops should still be allowed even with high taint
        let d = kernel.decide(Operation::WriteFiles, "/workspace/out.txt");
        assert!(d.verdict.is_allowed());
        assert!(!d.taint_transition.dynamic_gate_applied);

        // git_commit is not an exfil op — should be allowed
        let d = kernel.decide(Operation::GitCommit, "fix: stuff");
        assert!(d.verdict.is_allowed());
        assert!(!d.taint_transition.dynamic_gate_applied);
    }

    #[test]
    fn test_taint_transition_in_decision_trace() {
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

        // First read: taint 0→1
        assert_eq!(trace[0].taint_transition.pre_count, 0);
        assert_eq!(trace[0].taint_transition.post_count, 1);
        assert_eq!(
            trace[0].taint_transition.contributed_label,
            Some(TaintLabel::PrivateData)
        );

        // Second read: taint stays at 1 (already has PrivateData)
        assert_eq!(trace[1].taint_transition.pre_count, 1);
        assert_eq!(trace[1].taint_transition.post_count, 1);

        // Denied write: taint stays at 1 (denied ops don't contribute)
        assert_eq!(trace[2].taint_transition.pre_count, 1);
        assert_eq!(trace[2].taint_transition.post_count, 1);
    }

    #[test]
    fn test_runbash_dynamic_gate_omnibus() {
        // RunBash is special: it projects both PrivateData + ExfilVector.
        // If we've already ingested untrusted content, RunBash should
        // be dynamically gated because it's an exfil vector that would
        // complete the trifecta (it projects PrivateData too).
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
        assert!(kernel.taint().contains(TaintLabel::UntrustedContent));

        // RunBash with a permitted command — trifecta would complete via omnibus
        let d = kernel.decide(Operation::RunBash, "cargo test");
        assert!(
            matches!(d.verdict, Verdict::RequiresApproval),
            "RunBash omnibus projection should trigger dynamic gate, got {:?}",
            d.verdict
        );
        assert!(d.taint_transition.dynamic_gate_applied);
    }

    // ── Isolation tests ─────────────────────────────────────────────

    #[test]
    fn test_isolation_minimum_met() {
        // Policy requires namespaced, runtime is MicroVM — should pass
        let perms = PermissionLattice::safe_pr_fixer()
            .with_minimum_isolation(IsolationLattice::sandboxed());
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm());

        let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
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

        let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
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

        let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
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

        let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
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

        let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
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

        let d = kernel.decide(Operation::WebFetch, "https://example.com");
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

        let d = kernel.decide(Operation::WebSearch, "rust async");
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

        let d = kernel.decide(Operation::ReadFiles, "/workspace/main.rs");
        assert!(d.verdict.is_allowed(), "airgapped should allow file reads");

        let d = kernel.decide(Operation::GlobSearch, "**/*.rs");
        assert!(d.verdict.is_allowed(), "airgapped should allow glob search");
    }

    #[test]
    fn test_filtered_network_allows_web_ops() {
        // Filtered network (not airgapped) should allow web operations
        let perms = PermissionLattice::permissive();
        let mut kernel = Kernel::with_isolation(perms, IsolationLattice::microvm_with_network());

        let d = kernel.decide(Operation::WebFetch, "https://example.com");
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
}
