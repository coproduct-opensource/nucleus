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
use sha2::{Digest, Sha256};
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
    /// SHA-256 hash of the previous entry, forming a tamper-evident chain.
    /// `None` for the first entry in the log.
    pub prev_hash: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry with the current timestamp.
    ///
    /// # Security Note
    /// The identity should be a valid SPIFFE ID (format: `spiffe://trust-domain/path`).
    /// While format validation is performed, callers should ensure the identity
    /// comes from a trusted source (e.g., SPIFFE runtime).
    pub fn new(identity: impl Into<String>, event: PermissionEvent) -> Self {
        let identity_str = identity.into();

        // Validate SPIFFE ID format to prevent injection attacks
        if !Self::is_valid_spiffe_id(&identity_str) {
            tracing::warn!(
                "audit entry with invalid SPIFFE format: '{}' (expected spiffe://trust-domain/path)",
                identity_str
            );
        }

        Self {
            sequence: 0, // Set by the log
            timestamp: SystemTime::now(),
            identity: identity_str,
            event,
            correlation_id: None,
            session_id: None,
            prev_hash: None, // Set by the log during record()
        }
    }

    /// Check if an identity string matches SPIFFE ID format.
    /// Format: `spiffe://[trust-domain]/[path-components]`
    fn is_valid_spiffe_id(identity: &str) -> bool {
        // Must start with spiffe://
        if !identity.starts_with("spiffe://") {
            return false;
        }

        let remainder = &identity[9..]; // After "spiffe://"

        // Must have at least a trust domain (no empty identities)
        if remainder.is_empty() {
            return false;
        }

        // Trust domain must be followed by / or be at end (for root workloads)
        // Valid examples: spiffe://example.com, spiffe://example.com/sa/default
        let parts: Vec<&str> = remainder.split('/').collect();

        // At minimum, trust domain should exist and not be empty
        !parts.is_empty() && !parts[0].is_empty()
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

    /// Compute the SHA-256 hash of this entry for chain linkage.
    ///
    /// The hash covers all fields including `prev_hash`, making the chain
    /// tamper-evident: modifying any entry invalidates all subsequent hashes.
    ///
    /// Uses deterministic serialization (serde) to ensure the hash is stable
    /// across Rust compiler versions and system restarts.
    pub fn content_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.sequence.to_le_bytes());

        // Encode timestamp as duration since UNIX_EPOCH in nanoseconds.
        // Returns error if timestamp is before UNIX_EPOCH, ensuring deterministic hashing.
        let ts = self
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("timestamp must be after UNIX_EPOCH (1970-01-01)");
        hasher.update(ts.as_nanos().to_le_bytes());

        hasher.update(self.identity.as_bytes());

        // Use deterministic JSON serialization instead of Debug format.
        // This ensures hashes remain consistent across Rust versions and compilers.
        #[cfg(feature = "serde")]
        {
            let event_json = serde_json::to_string(&self.event)
                .unwrap_or_else(|_| String::from("error_serializing_event"));
            hasher.update(event_json.as_bytes());
        }
        #[cfg(not(feature = "serde"))]
        {
            // Fallback for non-serde builds: use the original Debug format
            // (not ideal but maintains compatibility)
            hasher.update(format!("{:?}", self.event).as_bytes());
        }

        if let Some(ref cid) = self.correlation_id {
            hasher.update(cid.as_bytes());
        }
        if let Some(ref sid) = self.session_id {
            hasher.update(sid.as_bytes());
        }
        if let Some(ref ph) = self.prev_hash {
            hasher.update(ph.as_bytes());
        }
        hex::encode(hasher.finalize())
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
/// Optionally backed by a persistent [`AuditBackend`](crate::audit_backend::AuditBackend).
#[derive(Debug)]
pub struct AuditLog {
    inner: Arc<RwLock<AuditLogInner>>,
}

#[derive(Debug)]
struct AuditLogInner {
    entries: Vec<AuditEntry>,
    next_sequence: u64,
    retention_policy: RetentionPolicy,
    /// Hash of the most recent entry, used for chain linkage.
    tail_hash: Option<String>,
    /// Optional persistent backend.
    #[cfg(feature = "serde")]
    backend: Option<Box<dyn crate::audit_backend::AuditBackend>>,
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

/// Errors from hash chain verification.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ChainVerificationError {
    /// The first entry has a non-None prev_hash.
    InvalidGenesisEntry {
        /// Sequence number of the invalid entry.
        sequence: u64,
    },
    /// An entry's prev_hash doesn't match the computed hash of the preceding entry.
    HashMismatch {
        /// Sequence number of the mismatched entry.
        sequence: u64,
        /// Expected hash (computed from previous entry).
        expected: String,
        /// Actual prev_hash stored in the entry.
        actual: String,
    },
    /// An entry (other than the first) is missing its prev_hash.
    MissingPrevHash {
        /// Sequence number of the entry missing prev_hash.
        sequence: u64,
    },
}

impl std::fmt::Display for ChainVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGenesisEntry { sequence } => {
                write!(f, "genesis entry (seq={}) has non-None prev_hash", sequence)
            }
            Self::HashMismatch {
                sequence,
                expected,
                actual,
            } => write!(
                f,
                "hash mismatch at seq={}: expected {}, got {}",
                sequence, expected, actual
            ),
            Self::MissingPrevHash { sequence } => {
                write!(f, "entry (seq={}) missing prev_hash", sequence)
            }
        }
    }
}

impl std::error::Error for ChainVerificationError {}

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
                tail_hash: None,
                #[cfg(feature = "serde")]
                backend: None,
            })),
        }
    }

    /// Create an audit log backed by a persistent backend.
    ///
    /// Entries are written to both the in-memory log and the backend.
    /// Use [`recover_from_file`](crate::audit_backend::recover_from_file) to
    /// restore entries from a file backend after restart.
    #[cfg(feature = "serde")]
    pub fn with_backend(
        policy: RetentionPolicy,
        backend: Box<dyn crate::audit_backend::AuditBackend>,
    ) -> Self {
        Self {
            inner: Arc::new(RwLock::new(AuditLogInner {
                entries: Vec::new(),
                next_sequence: 1,
                retention_policy: policy,
                tail_hash: None,
                backend: Some(backend),
            })),
        }
    }

    /// Create an audit log restored from a backend's persisted entries.
    ///
    /// Loads all entries from the backend, restores the in-memory state
    /// (sequence numbers, tail hash), and continues appending new entries
    /// to both memory and the backend.
    #[cfg(feature = "serde")]
    pub fn recover_from_backend(
        policy: RetentionPolicy,
        backend: Box<dyn crate::audit_backend::AuditBackend>,
    ) -> Result<Self, crate::audit_backend::AuditBackendError> {
        let entries = backend.load_all()?;
        let next_sequence = entries.last().map(|e| e.sequence + 1).unwrap_or(1);
        let tail_hash = entries.last().map(|e| e.content_hash());

        Ok(Self {
            inner: Arc::new(RwLock::new(AuditLogInner {
                entries,
                next_sequence,
                retention_policy: policy,
                tail_hash,
                backend: Some(backend),
            })),
        })
    }

    /// Record an audit entry.
    ///
    /// Sets the entry's `prev_hash` to the hash of the most recent entry,
    /// forming a tamper-evident chain. Returns the sequence number assigned.
    pub fn record(&self, mut entry: AuditEntry) -> u64 {
        let mut inner = self.inner.write().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned during audit record; recovering");
            poisoned.into_inner()
        });

        let sequence = inner.next_sequence;
        entry.sequence = sequence;
        entry.prev_hash = inner.tail_hash.clone();
        inner.next_sequence += 1;

        // Compute this entry's hash and update the tail
        let entry_hash = entry.content_hash();
        inner.tail_hash = Some(entry_hash);

        // Write to persistent backend if configured
        #[cfg(feature = "serde")]
        if let Some(ref mut backend) = inner.backend {
            if let Err(e) = backend.append(&entry) {
                tracing::error!("audit backend write failed: {}", e);
            }
        }

        inner.entries.push(entry);

        // Apply retention policy
        Self::apply_retention(&mut inner);

        sequence
    }

    /// Record multiple entries atomically.
    ///
    /// Each entry's `prev_hash` is set to the hash of the preceding entry
    /// in the batch (or the current tail for the first entry).
    /// Returns the sequence numbers assigned.
    pub fn record_batch(&self, entries: Vec<AuditEntry>) -> Vec<u64> {
        let mut inner = self.inner.write().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned during audit record_batch; recovering");
            poisoned.into_inner()
        });

        let sequences: Vec<u64> = entries
            .into_iter()
            .map(|mut entry| {
                let sequence = inner.next_sequence;
                entry.sequence = sequence;
                entry.prev_hash = inner.tail_hash.clone();
                inner.next_sequence += 1;

                let entry_hash = entry.content_hash();
                inner.tail_hash = Some(entry_hash);

                #[cfg(feature = "serde")]
                if let Some(ref mut backend) = inner.backend {
                    if let Err(e) = backend.append(&entry) {
                        tracing::error!("audit backend batch write failed: {}", e);
                    }
                }

                inner.entries.push(entry);
                sequence
            })
            .collect();

        Self::apply_retention(&mut inner);

        sequences
    }

    /// Get all entries for a specific identity.
    pub fn entries_for_identity(&self, identity: &str) -> Vec<AuditEntry> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned during audit read; recovering");
            poisoned.into_inner()
        });
        inner
            .entries
            .iter()
            .filter(|e| e.identity == identity)
            .cloned()
            .collect()
    }

    /// Get entries within a time window.
    pub fn entries_in_window(&self, start: SystemTime, end: SystemTime) -> Vec<AuditEntry> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned during audit read; recovering");
            poisoned.into_inner()
        });
        inner
            .entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Get all deviation events.
    pub fn deviations(&self) -> Vec<AuditEntry> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
        inner
            .entries
            .iter()
            .filter(|e| e.is_deviation())
            .cloned()
            .collect()
    }

    /// Get deviations for a specific identity.
    pub fn deviations_for_identity(&self, identity: &str) -> Vec<AuditEntry> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
        inner
            .entries
            .iter()
            .filter(|e| e.identity == identity && e.is_deviation())
            .cloned()
            .collect()
    }

    /// Count total entries.
    pub fn total_entries(&self) -> usize {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
        inner.entries.len()
    }

    /// Count entries for a specific identity.
    pub fn entries_count_for_identity(&self, identity: &str) -> usize {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
        inner
            .entries
            .iter()
            .filter(|e| e.identity == identity)
            .count()
    }

    /// Get entries by correlation ID.
    pub fn entries_by_correlation(&self, correlation_id: &str) -> Vec<AuditEntry> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
        inner
            .entries
            .iter()
            .filter(|e| e.correlation_id.as_deref() == Some(correlation_id))
            .cloned()
            .collect()
    }

    /// Get the latest N entries.
    pub fn latest(&self, n: usize) -> Vec<AuditEntry> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
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

        // Note: max_entries_per_identity is intentionally not enforced here.
        // Enforcing it on every write would require a linear scan over all entries.
        // Use entries_count_for_identity() to check manually if needed.
    }

    /// Export all entries (for backup/analysis).
    pub fn export(&self) -> Vec<AuditEntry> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
        inner.entries.clone()
    }

    /// Clear all entries.
    ///
    /// Only available in test builds. Production audit logs are append-only;
    /// use retention policies to manage log size.
    #[cfg(any(test, feature = "testing"))]
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
        inner.entries.clear();
        inner.tail_hash = None;
    }

    /// Get the hash of the most recent entry in the chain.
    ///
    /// Returns `None` if the log is empty.
    pub fn tail_hash(&self) -> Option<String> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
        inner.tail_hash.clone()
    }

    /// Verify the integrity of the hash chain.
    ///
    /// Walks all entries and checks that each entry's `prev_hash` matches
    /// the `content_hash()` of the preceding entry. Returns `Ok(())` if
    /// the chain is valid, or an error describing the first broken link.
    pub fn verify_chain(&self) -> Result<(), ChainVerificationError> {
        let inner = self.inner.read().unwrap_or_else(|poisoned| {
            tracing::error!("RwLock poisoned; recovering");
            poisoned.into_inner()
        });
        let entries = &inner.entries;

        if entries.is_empty() {
            return Ok(());
        }

        // First entry should have prev_hash = None
        if entries[0].prev_hash.is_some() {
            return Err(ChainVerificationError::InvalidGenesisEntry {
                sequence: entries[0].sequence,
            });
        }

        // Walk the chain verifying linkage
        for i in 1..entries.len() {
            let expected_prev_hash = entries[i - 1].content_hash();
            match &entries[i].prev_hash {
                Some(actual) if *actual == expected_prev_hash => {}
                Some(actual) => {
                    return Err(ChainVerificationError::HashMismatch {
                        sequence: entries[i].sequence,
                        expected: expected_prev_hash,
                        actual: actual.clone(),
                    });
                }
                None => {
                    return Err(ChainVerificationError::MissingPrevHash {
                        sequence: entries[i].sequence,
                    });
                }
            }
        }

        Ok(())
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
    fn test_hash_chain_linkage() {
        let log = AuditLog::in_memory();

        let seq1 = log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::PermissionsDeclared {
                description: "Codegen".to_string(),
                trifecta_risk: TrifectaRisk::Low,
            },
        ));

        let seq2 = log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::Always,
                requested_level: CapabilityLevel::Always,
            },
        ));

        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);

        let entries = log.export();
        // First entry has no prev_hash
        assert!(entries[0].prev_hash.is_none());
        // Second entry's prev_hash matches first entry's content_hash
        assert_eq!(
            entries[1].prev_hash.as_deref(),
            Some(entries[0].content_hash().as_str())
        );

        // Chain verification should pass
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn test_hash_chain_tamper_detection() {
        let log = AuditLog::in_memory();

        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::PermissionsDeclared {
                description: "Codegen".to_string(),
                trifecta_risk: TrifectaRisk::Low,
            },
        ));

        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::Always,
                requested_level: CapabilityLevel::Always,
            },
        ));

        // Tamper with the first entry's identity
        {
            let mut inner = log.inner.write().unwrap();
            inner.entries[0].identity = "spiffe://test/TAMPERED".to_string();
        }

        // Chain verification should fail
        let result = log.verify_chain();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(
            err,
            ChainVerificationError::HashMismatch { sequence: 2, .. }
        ));
    }

    #[test]
    fn test_hash_chain_batch() {
        let log = AuditLog::in_memory();

        let entries = vec![
            AuditEntry::new(
                "spiffe://test/agent-1",
                PermissionEvent::PermissionsDeclared {
                    description: "Batch 1".to_string(),
                    trifecta_risk: TrifectaRisk::None,
                },
            ),
            AuditEntry::new(
                "spiffe://test/agent-1",
                PermissionEvent::PermissionsDeclared {
                    description: "Batch 2".to_string(),
                    trifecta_risk: TrifectaRisk::Low,
                },
            ),
            AuditEntry::new(
                "spiffe://test/agent-1",
                PermissionEvent::PermissionsDeclared {
                    description: "Batch 3".to_string(),
                    trifecta_risk: TrifectaRisk::Medium,
                },
            ),
        ];

        let seqs = log.record_batch(entries);
        assert_eq!(seqs, vec![1, 2, 3]);

        // All entries should be properly chained
        assert!(log.verify_chain().is_ok());

        let exported = log.export();
        assert!(exported[0].prev_hash.is_none());
        assert!(exported[1].prev_hash.is_some());
        assert!(exported[2].prev_hash.is_some());
    }

    #[test]
    fn test_tail_hash() {
        let log = AuditLog::in_memory();
        assert!(log.tail_hash().is_none());

        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::PermissionsDeclared {
                description: "test".to_string(),
                trifecta_risk: TrifectaRisk::None,
            },
        ));

        let tail = log.tail_hash();
        assert!(tail.is_some());
        assert_eq!(tail.unwrap().len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_empty_log_verification() {
        let log = AuditLog::in_memory();
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn test_single_entry_chain_verification() {
        let log = AuditLog::in_memory();

        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::PermissionsDeclared {
                description: "Single entry".to_string(),
                trifecta_risk: TrifectaRisk::Low,
            },
        ));

        // Single entry: no prev_hash, chain should be valid
        assert!(log.verify_chain().is_ok());

        let entries = log.export();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].prev_hash.is_none());
    }

    #[test]
    fn test_genesis_entry_with_prev_hash_fails_verification() {
        let log = AuditLog::in_memory();

        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::PermissionsDeclared {
                description: "First".to_string(),
                trifecta_risk: TrifectaRisk::None,
            },
        ));

        // Corrupt the genesis entry by setting a prev_hash
        {
            let mut inner = log.inner.write().unwrap();
            inner.entries[0].prev_hash = Some("fake-hash".to_string());
        }

        let result = log.verify_chain();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ChainVerificationError::InvalidGenesisEntry { sequence: 1 }
        ));
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

    #[test]
    fn test_spiffe_identity_validation() {
        // Valid SPIFFE IDs should be accepted
        assert!(AuditEntry::is_valid_spiffe_id("spiffe://example.com"));
        assert!(AuditEntry::is_valid_spiffe_id("spiffe://example.com/sa/default"));
        assert!(AuditEntry::is_valid_spiffe_id("spiffe://trust-domain.local/ns/ns1/sa/agent-1"));

        // Invalid SPIFFE IDs should be rejected
        assert!(!AuditEntry::is_valid_spiffe_id("invalid"));
        assert!(!AuditEntry::is_valid_spiffe_id("https://example.com")); // Wrong scheme
        assert!(!AuditEntry::is_valid_spiffe_id("spiffe://")); // Empty trust domain
        assert!(!AuditEntry::is_valid_spiffe_id("")); // Empty string
    }

    #[test]
    fn test_deterministic_hash_with_serde() {
        // Test that hashing is deterministic across invocations
        let entry1 = AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::OperationRequested {
                operation: Operation::GitPush,
                declared_level: CapabilityLevel::Never,
                requested_level: CapabilityLevel::Always,
            },
        );

        let entry2 = AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::OperationRequested {
                operation: Operation::GitPush,
                declared_level: CapabilityLevel::Never,
                requested_level: CapabilityLevel::Always,
            },
        );

        // Identical entries should produce identical hashes
        assert_eq!(entry1.content_hash(), entry2.content_hash());
    }
}
