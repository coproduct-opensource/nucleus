//! Audit logging primitives for permission tracking.
//!
//! This module provides append-only audit logging for permission requests,
//! enabling downstream reputation systems to track agent behavior.
//!
//! # Design
//!
//! The audit system is intentionally minimal - it captures the facts needed
//! for reputation scoring without implementing reputation itself. This allows:
//!
//! - Nucleus to remain vendor-agnostic
//! - Reputation systems to evolve independently
//! - Different scoring algorithms for different use cases
//!
//! # Example
//!
//! ```rust
//! use lattice_guard::audit::{AuditLog, AuditEntry, PermissionEvent};
//! use lattice_guard::{Operation, CapabilityLevel, TrifectaRisk};
//!
//! // Create an in-memory audit log
//! let mut log = AuditLog::in_memory();
//!
//! // Record a permission request
//! log.record(AuditEntry::new(
//!     "spiffe://nucleus.local/ns/default/sa/coder-001",
//!     PermissionEvent::OperationRequested {
//!         operation: Operation::GitPush,
//!         declared_level: CapabilityLevel::Never,
//!         requested_level: CapabilityLevel::Always,
//!     },
//! ));
//!
//! // Query entries for analysis
//! let entries = log.entries_for_identity("spiffe://nucleus.local/ns/default/sa/coder-001");
//! ```

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use crate::capability::{Operation, TrifectaRisk};
use crate::weakening::{WeakeningCost, WeakeningRequest};
use crate::CapabilityLevel;

/// An audit entry recording a permission-related event.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AuditEntry {
    /// Unique identifier for this entry (monotonic).
    pub sequence: u64,
    /// Timestamp when the event occurred.
    pub timestamp: SystemTime,
    /// SPIFFE ID of the agent.
    pub identity: String,
    /// The event that occurred.
    pub event: PermissionEvent,
    /// Optional correlation ID for linking related events.
    pub correlation_id: Option<String>,
    /// Optional task/session identifier.
    pub session_id: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry with the current timestamp.
    pub fn new(identity: impl Into<String>, event: PermissionEvent) -> Self {
        Self {
            sequence: 0, // Set by the log
            timestamp: SystemTime::now(),
            identity: identity.into(),
            event,
            correlation_id: None,
            session_id: None,
        }
    }

    /// Set the correlation ID.
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set the session ID.
    pub fn with_session_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = Some(id.into());
        self
    }

    /// Check if this event represents a deviation from declared permissions.
    pub fn is_deviation(&self) -> bool {
        match &self.event {
            PermissionEvent::WeakeningRequested { .. } => true,
            PermissionEvent::OperationRequested {
                declared_level,
                requested_level,
                ..
            } => requested_level > declared_level,
            _ => false,
        }
    }

    /// Get the trifecta impact if applicable.
    pub fn trifecta_impact(&self) -> Option<TrifectaRisk> {
        match &self.event {
            PermissionEvent::WeakeningRequested {
                trifecta_impact, ..
            } => Some(*trifecta_impact),
            PermissionEvent::TrifectaStateChanged { after, .. } => Some(*after),
            _ => None,
        }
    }
}

/// Events that can be recorded in the audit log.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PermissionEvent {
    /// Agent declared its expected permissions at session start.
    PermissionsDeclared {
        /// Human-readable description of declared permissions.
        description: String,
        /// Trifecta risk of declared permissions.
        trifecta_risk: TrifectaRisk,
    },

    /// Agent requested an operation.
    OperationRequested {
        /// The operation requested.
        operation: Operation,
        /// The declared capability level for this operation.
        declared_level: CapabilityLevel,
        /// The actual level being requested.
        requested_level: CapabilityLevel,
    },

    /// A specific weakening was requested.
    WeakeningRequested {
        /// The weakening request details.
        request: WeakeningRequest,
        /// The trifecta impact of this weakening.
        trifecta_impact: TrifectaRisk,
    },

    /// The trifecta state changed.
    TrifectaStateChanged {
        /// Previous trifecta risk level.
        before: TrifectaRisk,
        /// New trifecta risk level.
        after: TrifectaRisk,
        /// What triggered the change.
        trigger: String,
    },

    /// Execution completed with a cost summary.
    ExecutionCompleted {
        /// Total cost incurred.
        total_cost: WeakeningCost,
        /// Number of weakenings.
        weakening_count: usize,
        /// Whether the trifecta was completed.
        trifecta_completed: bool,
    },

    /// Approval was requested from a human.
    ApprovalRequested {
        /// The operation needing approval.
        operation: Operation,
        /// Reason for requiring approval.
        reason: String,
    },

    /// Approval was granted.
    ApprovalGranted {
        /// The operation that was approved.
        operation: Operation,
        /// Who approved (if known).
        approver: Option<String>,
    },

    /// Approval was denied.
    ApprovalDenied {
        /// The operation that was denied.
        operation: Operation,
        /// Reason for denial (if provided).
        reason: Option<String>,
    },

    /// Execution was blocked due to policy.
    ExecutionBlocked {
        /// The operation that was blocked.
        operation: Operation,
        /// Why it was blocked.
        reason: String,
        /// The cost threshold that was exceeded (if applicable).
        threshold_exceeded: Option<rust_decimal::Decimal>,
    },
}

/// Append-only audit log for permission events.
///
/// Thread-safe and designed for high-throughput logging.
#[derive(Debug)]
pub struct AuditLog {
    inner: Arc<RwLock<AuditLogInner>>,
}

#[derive(Debug)]
struct AuditLogInner {
    entries: Vec<AuditEntry>,
    next_sequence: u64,
    retention_policy: RetentionPolicy,
}

/// Policy for how long to retain audit entries.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RetentionPolicy {
    /// Maximum number of entries to keep per identity.
    pub max_entries_per_identity: Option<usize>,
    /// Maximum age of entries to keep.
    pub max_age: Option<Duration>,
    /// Total maximum entries across all identities.
    pub max_total_entries: Option<usize>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_entries_per_identity: Some(10_000),
            max_age: Some(Duration::from_secs(7 * 24 * 60 * 60)), // 7 days
            max_total_entries: Some(1_000_000),
        }
    }
}

impl RetentionPolicy {
    /// Create a policy with no limits (useful for testing).
    pub fn unlimited() -> Self {
        Self {
            max_entries_per_identity: None,
            max_age: None,
            max_total_entries: None,
        }
    }
}

impl Clone for AuditLog {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::in_memory()
    }
}

impl AuditLog {
    /// Create a new in-memory audit log.
    pub fn in_memory() -> Self {
        Self::with_retention(RetentionPolicy::default())
    }

    /// Create an audit log with a specific retention policy.
    pub fn with_retention(policy: RetentionPolicy) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AuditLogInner {
                entries: Vec::new(),
                next_sequence: 1,
                retention_policy: policy,
            })),
        }
    }

    /// Record an audit entry.
    ///
    /// Returns the sequence number assigned to the entry.
    pub fn record(&self, mut entry: AuditEntry) -> u64 {
        let mut inner = self.inner.write().expect("lock poisoned");

        let sequence = inner.next_sequence;
        entry.sequence = sequence;
        inner.next_sequence += 1;
        inner.entries.push(entry);

        // Apply retention policy
        Self::apply_retention(&mut inner);

        sequence
    }

    /// Record multiple entries atomically.
    ///
    /// Returns the sequence numbers assigned.
    pub fn record_batch(&self, entries: Vec<AuditEntry>) -> Vec<u64> {
        let mut inner = self.inner.write().expect("lock poisoned");

        let sequences: Vec<u64> = entries
            .into_iter()
            .map(|mut entry| {
                let sequence = inner.next_sequence;
                entry.sequence = sequence;
                inner.next_sequence += 1;
                inner.entries.push(entry);
                sequence
            })
            .collect();

        Self::apply_retention(&mut inner);

        sequences
    }

    /// Get all entries for a specific identity.
    pub fn entries_for_identity(&self, identity: &str) -> Vec<AuditEntry> {
        let inner = self.inner.read().expect("lock poisoned");
        inner
            .entries
            .iter()
            .filter(|e| e.identity == identity)
            .cloned()
            .collect()
    }

    /// Get entries within a time window.
    pub fn entries_in_window(&self, start: SystemTime, end: SystemTime) -> Vec<AuditEntry> {
        let inner = self.inner.read().expect("lock poisoned");
        inner
            .entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Get all deviation events.
    pub fn deviations(&self) -> Vec<AuditEntry> {
        let inner = self.inner.read().expect("lock poisoned");
        inner
            .entries
            .iter()
            .filter(|e| e.is_deviation())
            .cloned()
            .collect()
    }

    /// Get deviations for a specific identity.
    pub fn deviations_for_identity(&self, identity: &str) -> Vec<AuditEntry> {
        let inner = self.inner.read().expect("lock poisoned");
        inner
            .entries
            .iter()
            .filter(|e| e.identity == identity && e.is_deviation())
            .cloned()
            .collect()
    }

    /// Count total entries.
    pub fn total_entries(&self) -> usize {
        let inner = self.inner.read().expect("lock poisoned");
        inner.entries.len()
    }

    /// Count entries for a specific identity.
    pub fn entries_count_for_identity(&self, identity: &str) -> usize {
        let inner = self.inner.read().expect("lock poisoned");
        inner
            .entries
            .iter()
            .filter(|e| e.identity == identity)
            .count()
    }

    /// Get entries by correlation ID.
    pub fn entries_by_correlation(&self, correlation_id: &str) -> Vec<AuditEntry> {
        let inner = self.inner.read().expect("lock poisoned");
        inner
            .entries
            .iter()
            .filter(|e| e.correlation_id.as_deref() == Some(correlation_id))
            .cloned()
            .collect()
    }

    /// Get the latest N entries.
    pub fn latest(&self, n: usize) -> Vec<AuditEntry> {
        let inner = self.inner.read().expect("lock poisoned");
        inner
            .entries
            .iter()
            .rev()
            .take(n)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    /// Apply retention policy.
    fn apply_retention(inner: &mut AuditLogInner) {
        // Apply max total entries
        if let Some(max) = inner.retention_policy.max_total_entries {
            if inner.entries.len() > max {
                let excess = inner.entries.len() - max;
                inner.entries.drain(0..excess);
            }
        }

        // Apply max age
        if let Some(max_age) = inner.retention_policy.max_age {
            let cutoff = SystemTime::now() - max_age;
            inner.entries.retain(|e| e.timestamp >= cutoff);
        }

        // Note: max_entries_per_identity is not enforced here for efficiency
        // It could be enforced on reads or via periodic cleanup
    }

    /// Export all entries (for backup/analysis).
    pub fn export(&self) -> Vec<AuditEntry> {
        let inner = self.inner.read().expect("lock poisoned");
        inner.entries.clone()
    }

    /// Clear all entries (primarily for testing).
    pub fn clear(&self) {
        let mut inner = self.inner.write().expect("lock poisoned");
        inner.entries.clear();
    }
}

/// A summary of audit data for a specific identity.
///
/// This is the data that reputation systems would consume.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IdentityAuditSummary {
    /// The SPIFFE ID.
    pub identity: String,
    /// Total number of operations requested.
    pub total_operations: usize,
    /// Number of deviations from declared permissions.
    pub deviation_count: usize,
    /// Number of times trifecta was completed.
    pub trifecta_completions: usize,
    /// Number of approvals requested.
    pub approvals_requested: usize,
    /// Number of approvals granted.
    pub approvals_granted: usize,
    /// Number of approvals denied.
    pub approvals_denied: usize,
    /// Number of executions blocked.
    pub executions_blocked: usize,
    /// Total weakening cost incurred.
    pub total_weakening_cost: rust_decimal::Decimal,
    /// Time window covered.
    pub window_start: SystemTime,
    /// End of time window.
    pub window_end: SystemTime,
}

impl AuditLog {
    /// Generate a summary for a specific identity.
    pub fn summarize_identity(&self, identity: &str) -> IdentityAuditSummary {
        let entries = self.entries_for_identity(identity);

        let mut summary = IdentityAuditSummary {
            identity: identity.to_string(),
            total_operations: 0,
            deviation_count: 0,
            trifecta_completions: 0,
            approvals_requested: 0,
            approvals_granted: 0,
            approvals_denied: 0,
            executions_blocked: 0,
            total_weakening_cost: rust_decimal::Decimal::ZERO,
            window_start: SystemTime::now(),
            window_end: SystemTime::UNIX_EPOCH,
        };

        for entry in &entries {
            // Update time window
            if entry.timestamp < summary.window_start {
                summary.window_start = entry.timestamp;
            }
            if entry.timestamp > summary.window_end {
                summary.window_end = entry.timestamp;
            }

            // Count events
            match &entry.event {
                PermissionEvent::OperationRequested { .. } => {
                    summary.total_operations += 1;
                }
                PermissionEvent::WeakeningRequested { .. } => {
                    summary.deviation_count += 1;
                }
                PermissionEvent::TrifectaStateChanged {
                    after: TrifectaRisk::Complete,
                    ..
                } => {
                    summary.trifecta_completions += 1;
                }
                PermissionEvent::ExecutionCompleted {
                    total_cost,
                    trifecta_completed,
                    ..
                } => {
                    summary.total_weakening_cost += total_cost.total();
                    if *trifecta_completed {
                        summary.trifecta_completions += 1;
                    }
                }
                PermissionEvent::ApprovalRequested { .. } => {
                    summary.approvals_requested += 1;
                }
                PermissionEvent::ApprovalGranted { .. } => {
                    summary.approvals_granted += 1;
                }
                PermissionEvent::ApprovalDenied { .. } => {
                    summary.approvals_denied += 1;
                }
                PermissionEvent::ExecutionBlocked { .. } => {
                    summary.executions_blocked += 1;
                }
                _ => {}
            }
        }

        // Handle empty case
        if entries.is_empty() {
            summary.window_start = SystemTime::UNIX_EPOCH;
        }

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_record() {
        let log = AuditLog::in_memory();

        let seq1 = log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::OperationRequested {
                operation: Operation::GitPush,
                declared_level: CapabilityLevel::Never,
                requested_level: CapabilityLevel::Always,
            },
        ));

        let seq2 = log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::ApprovalRequested {
                operation: Operation::GitPush,
                reason: "Trifecta detected".to_string(),
            },
        ));

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(log.total_entries(), 2);
    }

    #[test]
    fn test_entries_for_identity() {
        let log = AuditLog::in_memory();

        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::PermissionsDeclared {
                description: "Codegen".to_string(),
                trifecta_risk: TrifectaRisk::Low,
            },
        ));

        log.record(AuditEntry::new(
            "spiffe://test/agent-2",
            PermissionEvent::PermissionsDeclared {
                description: "Permissive".to_string(),
                trifecta_risk: TrifectaRisk::Complete,
            },
        ));

        let agent1_entries = log.entries_for_identity("spiffe://test/agent-1");
        assert_eq!(agent1_entries.len(), 1);

        let agent2_entries = log.entries_for_identity("spiffe://test/agent-2");
        assert_eq!(agent2_entries.len(), 1);
    }

    #[test]
    fn test_deviations() {
        let log = AuditLog::in_memory();

        // Non-deviation
        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::Always,
                requested_level: CapabilityLevel::Always,
            },
        ));

        // Deviation
        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::OperationRequested {
                operation: Operation::GitPush,
                declared_level: CapabilityLevel::Never,
                requested_level: CapabilityLevel::Always,
            },
        ));

        let deviations = log.deviations();
        assert_eq!(deviations.len(), 1);
        assert!(matches!(
            deviations[0].event,
            PermissionEvent::OperationRequested {
                operation: Operation::GitPush,
                ..
            }
        ));
    }

    #[test]
    fn test_summarize_identity() {
        let log = AuditLog::in_memory();
        let identity = "spiffe://test/agent-1";

        log.record(AuditEntry::new(
            identity,
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::Always,
                requested_level: CapabilityLevel::Always,
            },
        ));

        log.record(AuditEntry::new(
            identity,
            PermissionEvent::WeakeningRequested {
                request: WeakeningRequest::capability(
                    Operation::GitPush,
                    CapabilityLevel::Never,
                    CapabilityLevel::Always,
                    WeakeningCost::new(rust_decimal::Decimal::new(5, 1)),
                    TrifectaRisk::Complete,
                ),
                trifecta_impact: TrifectaRisk::Complete,
            },
        ));

        log.record(AuditEntry::new(
            identity,
            PermissionEvent::ApprovalRequested {
                operation: Operation::GitPush,
                reason: "Trifecta".to_string(),
            },
        ));

        log.record(AuditEntry::new(
            identity,
            PermissionEvent::ApprovalGranted {
                operation: Operation::GitPush,
                approver: Some("human".to_string()),
            },
        ));

        let summary = log.summarize_identity(identity);

        assert_eq!(summary.total_operations, 1);
        assert_eq!(summary.deviation_count, 1);
        assert_eq!(summary.approvals_requested, 1);
        assert_eq!(summary.approvals_granted, 1);
        assert_eq!(summary.approvals_denied, 0);
    }

    #[test]
    fn test_correlation_id() {
        let log = AuditLog::in_memory();

        log.record(
            AuditEntry::new(
                "spiffe://test/agent-1",
                PermissionEvent::OperationRequested {
                    operation: Operation::GitPush,
                    declared_level: CapabilityLevel::Never,
                    requested_level: CapabilityLevel::Always,
                },
            )
            .with_correlation_id("task-123"),
        );

        log.record(
            AuditEntry::new(
                "spiffe://test/agent-1",
                PermissionEvent::ApprovalRequested {
                    operation: Operation::GitPush,
                    reason: "Trifecta".to_string(),
                },
            )
            .with_correlation_id("task-123"),
        );

        let correlated = log.entries_by_correlation("task-123");
        assert_eq!(correlated.len(), 2);
    }

    #[test]
    fn test_retention_policy() {
        let policy = RetentionPolicy {
            max_total_entries: Some(3),
            max_age: None,
            max_entries_per_identity: None,
        };
        let log = AuditLog::with_retention(policy);

        for i in 0..5 {
            log.record(AuditEntry::new(
                format!("spiffe://test/agent-{}", i),
                PermissionEvent::PermissionsDeclared {
                    description: "Test".to_string(),
                    trifecta_risk: TrifectaRisk::None,
                },
            ));
        }

        // Should only keep 3 entries
        assert_eq!(log.total_entries(), 3);
    }
}
