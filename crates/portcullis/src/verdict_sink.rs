//! VerdictSink -- single convergence point for all tool call outcomes.
//!
//! Every tool call in every transport (HTTP, MCP, future gRPC) MUST flow
//! through a VerdictSink before returning. This trait is the security audit
//! boundary -- it enforces lockdown, records audit entries, and emits telemetry.
//!
//! # Design
//!
//! The trait is intentionally synchronous (`&self` + `Result`) so that it can
//! be called from both async handlers (HTTP) and synchronous closures (MCP
//! `execute_and_record`). Async audit backends (S3, webhook) should buffer
//! internally and flush on a background task.
//!
//! # Lockdown semantics
//!
//! `preflight()` checks whether a fleet lockdown is active *before* any
//! capability guard or sandbox I/O. If locked, the caller MUST short-circuit
//! with a deny verdict and never touch the filesystem or network.

use std::collections::BTreeMap;

use crate::capability::Operation;

/// Outcome of a single tool call (before audit recording).
#[derive(Debug, Clone)]
pub enum VerdictOutcome {
    /// The operation was permitted and completed successfully.
    Allow,
    /// The operation was denied by policy, lockdown, or capability guard.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
    },
    /// The operation failed due to a runtime error (I/O, timeout, etc.).
    Error {
        /// Human-readable error description.
        error: String,
    },
}

/// Identity of the actor requesting the tool call.
#[derive(Debug, Clone)]
pub enum ActorIdentity {
    /// Authenticated via SPIFFE SVID or mTLS certificate.
    Authenticated {
        /// SPIFFE ID string (e.g. `spiffe://nucleus.local/pod/abc`).
        spiffe_id: String,
    },
    /// Stdio guest process inside the pod (MCP transport).
    StdioGuest,
    /// Identity could not be determined.
    Unknown,
}

/// Full context for a single verdict to be recorded.
#[derive(Debug)]
pub struct VerdictContext {
    /// The operation that was attempted (e.g. `ReadFiles`, `RunBash`).
    pub operation: Operation,
    /// Subject of the operation (file path, command, URL, etc.).
    pub subject: String,
    /// Outcome of the operation.
    pub outcome: VerdictOutcome,
    /// Identity of the requesting actor.
    pub actor: ActorIdentity,
    /// Optional policy rule that governed this decision.
    pub policy_rule: Option<String>,
    /// Arbitrary key-value extensions for domain-specific metadata.
    pub extensions: BTreeMap<String, String>,
}

/// Errors from the verdict sink.
#[derive(Debug)]
pub enum SinkError {
    /// Fleet lockdown is active -- all tool calls must be blocked.
    Locked,
    /// Audit recording failed (should not block the caller in most impls).
    AuditFailed(String),
}

impl std::fmt::Display for SinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SinkError::Locked => write!(f, "LOCKDOWN ACTIVE: all tool calls are blocked"),
            SinkError::AuditFailed(e) => write!(f, "audit recording failed: {e}"),
        }
    }
}

impl std::error::Error for SinkError {}

/// Single mandatory convergence point for all tool call outcomes.
///
/// Implementations MUST:
/// 1. Check fleet lockdown state and return `SinkError::Locked` if active.
/// 2. Emit telemetry (tracing event / OTLP span) for observability.
/// 3. (Future) Record an audit entry in the append-only log.
///
/// The trait is object-safe and synchronous so it can be used behind
/// `Arc<dyn VerdictSink>` from both async and sync call sites.
pub trait VerdictSink: Send + Sync {
    /// Record a completed tool call verdict.
    ///
    /// Called after the operation has finished (or been denied). Returns
    /// `Err(SinkError::Locked)` if lockdown was activated between preflight
    /// and completion -- the caller should treat this as a late deny.
    fn record(&self, ctx: VerdictContext) -> Result<(), SinkError>;

    /// Pre-flight lockdown check before any I/O.
    ///
    /// Call this at the very top of every tool handler. If it returns
    /// `Err(SinkError::Locked)`, skip all capability checks and I/O.
    fn preflight(&self, operation: Operation) -> Result<(), SinkError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A no-op sink for testing -- never locked, always succeeds.
    struct NoopSink;

    impl VerdictSink for NoopSink {
        fn record(&self, _ctx: VerdictContext) -> Result<(), SinkError> {
            Ok(())
        }
        fn preflight(&self, _operation: Operation) -> Result<(), SinkError> {
            Ok(())
        }
    }

    /// A sink that always reports locked.
    struct LockedSink;

    impl VerdictSink for LockedSink {
        fn record(&self, _ctx: VerdictContext) -> Result<(), SinkError> {
            Err(SinkError::Locked)
        }
        fn preflight(&self, _operation: Operation) -> Result<(), SinkError> {
            Err(SinkError::Locked)
        }
    }

    #[test]
    fn noop_sink_allows_preflight() {
        let sink = NoopSink;
        assert!(sink.preflight(Operation::ReadFiles).is_ok());
    }

    #[test]
    fn noop_sink_records_verdict() {
        let sink = NoopSink;
        let ctx = VerdictContext {
            operation: Operation::WriteFiles,
            subject: "/workspace/test.txt".to_string(),
            outcome: VerdictOutcome::Allow,
            actor: ActorIdentity::StdioGuest,
            policy_rule: None,
            extensions: BTreeMap::new(),
        };
        assert!(sink.record(ctx).is_ok());
    }

    #[test]
    fn locked_sink_denies_preflight() {
        let sink = LockedSink;
        let err = sink.preflight(Operation::RunBash).unwrap_err();
        assert!(matches!(err, SinkError::Locked));
    }

    #[test]
    fn locked_sink_denies_record() {
        let sink = LockedSink;
        let ctx = VerdictContext {
            operation: Operation::WebFetch,
            subject: "https://example.com".to_string(),
            outcome: VerdictOutcome::Allow,
            actor: ActorIdentity::Unknown,
            policy_rule: None,
            extensions: BTreeMap::new(),
        };
        let err = sink.record(ctx).unwrap_err();
        assert!(matches!(err, SinkError::Locked));
    }

    #[test]
    fn sink_error_display() {
        let locked = SinkError::Locked;
        assert_eq!(
            locked.to_string(),
            "LOCKDOWN ACTIVE: all tool calls are blocked"
        );

        let audit = SinkError::AuditFailed("disk full".to_string());
        assert_eq!(audit.to_string(), "audit recording failed: disk full");
    }

    #[test]
    fn verdict_context_deny_and_error_variants() {
        let deny = VerdictOutcome::Deny {
            reason: "lockdown".to_string(),
        };
        assert!(matches!(deny, VerdictOutcome::Deny { .. }));

        let error = VerdictOutcome::Error {
            error: "I/O timeout".to_string(),
        };
        assert!(matches!(error, VerdictOutcome::Error { .. }));
    }

    #[test]
    fn actor_identity_variants() {
        let auth = ActorIdentity::Authenticated {
            spiffe_id: "spiffe://nucleus.local/pod/test".to_string(),
        };
        assert!(matches!(auth, ActorIdentity::Authenticated { .. }));

        let guest = ActorIdentity::StdioGuest;
        assert!(matches!(guest, ActorIdentity::StdioGuest));

        let unknown = ActorIdentity::Unknown;
        assert!(matches!(unknown, ActorIdentity::Unknown));
    }

    #[test]
    fn trait_object_safety() {
        // VerdictSink must be object-safe for Arc<dyn VerdictSink>.
        let sink: Box<dyn VerdictSink> = Box::new(NoopSink);
        assert!(sink.preflight(Operation::ReadFiles).is_ok());
    }
}
