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
//! ```
//!
//! Authority never increases. Budget is consumed. Time advances.
//! The trace is append-only.
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
use crate::lattice::PermissionLattice;

/// A single decision made by the kernel.
///
/// Captures the operation, subject, verdict, and a snapshot of the
/// permission state before and after the decision.
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
    /// Append-only session trace.
    trace: Vec<Decision>,
    /// Next sequence number.
    next_seq: u64,
    /// Budget consumed so far (USD).
    consumed_usd: Decimal,
    /// Pre-granted approvals: operation → remaining count.
    approvals: std::collections::BTreeMap<Operation, u32>,
}

impl Kernel {
    /// Create a new kernel with the given initial permissions.
    ///
    /// The initial permissions set the ceiling — effective permissions
    /// can only stay the same or decrease from here.
    pub fn new(initial: PermissionLattice) -> Self {
        let initial_hash = initial.checksum();
        Self {
            session_id: Uuid::new_v4(),
            effective: initial,
            initial_hash,
            trace: Vec::new(),
            next_seq: 0,
            consumed_usd: Decimal::ZERO,
            approvals: std::collections::BTreeMap::new(),
        }
    }

    /// The core decision function. Complete mediation.
    ///
    /// Every operation the agent attempts must pass through this function.
    /// The kernel checks:
    ///
    /// 1. **Time**: Is the session still within its validity window?
    /// 2. **Budget**: Has the cost ceiling been reached?
    /// 3. **Capability**: Is the operation allowed at the current level?
    /// 4. **Path**: Is the subject path accessible?
    /// 5. **Approval**: Does this operation require (and have) approval?
    ///
    /// The decision is recorded in the append-only trace.
    pub fn decide(&mut self, operation: Operation, subject: &str) -> Decision {
        let pre_hash = self.effective.checksum();

        // 1. Time check
        let now = Utc::now();
        if now > self.effective.time.valid_until {
            return self.record(
                operation,
                subject,
                Verdict::Deny(DenyReason::TimeExpired {
                    expired_at: self.effective.time.valid_until,
                }),
                &pre_hash,
            );
        }

        // 2. Budget check
        if self.consumed_usd >= self.effective.budget.max_cost_usd {
            return self.record(
                operation,
                subject,
                Verdict::Deny(DenyReason::BudgetExhausted {
                    remaining_usd: (self.effective.budget.max_cost_usd - self.consumed_usd)
                        .to_string(),
                }),
                &pre_hash,
            );
        }

        // 3. Capability level check
        let level = self.effective.capabilities.level_for(operation);
        if level == CapabilityLevel::Never {
            return self.record(
                operation,
                subject,
                Verdict::Deny(DenyReason::InsufficientCapability),
                &pre_hash,
            );
        }

        // 4. Path check (for file operations)
        if is_path_operation(operation)
            && !self
                .effective
                .paths
                .can_access(std::path::Path::new(subject))
        {
            return self.record(
                operation,
                subject,
                Verdict::Deny(DenyReason::PathBlocked {
                    path: subject.to_string(),
                }),
                &pre_hash,
            );
        }

        // 5. Command check (for exec operations)
        if operation == Operation::RunBash && !self.effective.commands.can_execute(subject) {
            return self.record(
                operation,
                subject,
                Verdict::Deny(DenyReason::CommandBlocked {
                    command: subject.to_string(),
                }),
                &pre_hash,
            );
        }

        // 6. Approval check
        if self.effective.requires_approval(operation) {
            if self.consume_approval(operation) {
                return self.record(operation, subject, Verdict::Allow, &pre_hash);
            }
            return self.record(operation, subject, Verdict::RequiresApproval, &pre_hash);
        }

        // All checks passed
        self.record(operation, subject, Verdict::Allow, &pre_hash)
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

    // ── Internal ──────────────────────────────────────────────────────

    /// Record a decision in the trace and return it.
    fn record(
        &mut self,
        operation: Operation,
        subject: &str,
        verdict: Verdict,
        pre_hash: &str,
    ) -> Decision {
        let post_hash = self.effective.checksum();
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
}
