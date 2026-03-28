//! Concrete VerdictSink for the tool-proxy process.
//!
//! Bridges the portcullis `VerdictSink` trait to the tool-proxy's existing
//! lockdown flags and telemetry infrastructure. PR 1 covers lockdown
//! enforcement and telemetry emission; audit log integration follows in PR 2.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use portcullis::verdict_sink::{
    ActorIdentity, SinkError, VerdictContext, VerdictOutcome, VerdictSink,
};
use portcullis::{CapabilityLattice, GradedExposureGuard, Operation};

use crate::telemetry;

/// Concrete VerdictSink wired to tool-proxy lockdown + telemetry.
///
/// Holds the same lockdown flags and policy fields as `AppState`, but
/// without requiring the full `AppState` (keeps the trait decoupled).
pub struct ToolProxyVerdictSink {
    file_lockdown: Arc<AtomicBool>,
    stream_lockdown: Arc<AtomicBool>,
    capabilities: CapabilityLattice,
    exposure_guard: Arc<std::sync::RwLock<Option<Arc<GradedExposureGuard>>>>,
    policy_checksum: String,
    session_id: String,
}

impl ToolProxyVerdictSink {
    /// Build from the same fields already present on `AppState`.
    pub fn new(
        file_lockdown: Arc<AtomicBool>,
        stream_lockdown: Arc<AtomicBool>,
        capabilities: CapabilityLattice,
        exposure_guard: Arc<std::sync::RwLock<Option<Arc<GradedExposureGuard>>>>,
        policy_checksum: String,
        session_id: String,
    ) -> Self {
        Self {
            file_lockdown,
            stream_lockdown,
            capabilities,
            exposure_guard,
            policy_checksum,
            session_id,
        }
    }

    /// OR-semantics: locked if EITHER signal file OR gRPC stream says locked.
    /// Mirrors `is_locked()` in main.rs.
    fn is_locked(&self) -> bool {
        self.file_lockdown.load(Ordering::Acquire) || self.stream_lockdown.load(Ordering::Acquire)
    }

    /// Map Operation to the short string names used by emit_verdict / audit log.
    fn operation_name(op: Operation) -> &'static str {
        match op {
            Operation::ReadFiles => "read",
            Operation::WriteFiles => "write",
            Operation::EditFiles => "edit",
            Operation::RunBash => "run",
            Operation::GlobSearch => "glob",
            Operation::GrepSearch => "grep",
            Operation::WebSearch => "web_search",
            Operation::WebFetch => "web_fetch",
            Operation::GitCommit => "git_commit",
            Operation::GitPush => "git_push",
            Operation::CreatePr => "create_pr",
            Operation::ManagePods => "manage_pods",
        }
    }

    /// Map a VerdictOutcome to the result string expected by emit_verdict.
    fn outcome_to_result(outcome: &VerdictOutcome) -> String {
        match outcome {
            VerdictOutcome::Allow => "ok".to_string(),
            VerdictOutcome::Deny { reason } => format!("denied:{reason}"),
            VerdictOutcome::Error { error } => format!("denied:{error}"),
        }
    }

    /// Extract the agent identity string for telemetry, if available.
    fn actor_identity(actor: &ActorIdentity) -> Option<&str> {
        match actor {
            ActorIdentity::Authenticated { spiffe_id } => Some(spiffe_id.as_str()),
            ActorIdentity::StdioGuest => Some("stdio-guest"),
            ActorIdentity::Unknown => None,
        }
    }
}

impl VerdictSink for ToolProxyVerdictSink {
    fn record(&self, ctx: VerdictContext) -> Result<(), SinkError> {
        // 1. Check lockdown (may have been activated between preflight and now)
        if self.is_locked() {
            // Still emit telemetry so the late-lockdown event is visible
            telemetry::emit_verdict(
                Self::operation_name(ctx.operation),
                &ctx.subject,
                "denied:LOCKDOWN ACTIVE",
                &self.capabilities,
                &self.exposure_guard,
                true, // lockdown_active
                &self.policy_checksum,
                Self::actor_identity(&ctx.actor),
                &self.session_id,
            );
            return Err(SinkError::Locked);
        }

        // 2. Emit telemetry for the actual outcome
        let result_str = Self::outcome_to_result(&ctx.outcome);
        telemetry::emit_verdict(
            Self::operation_name(ctx.operation),
            &ctx.subject,
            &result_str,
            &self.capabilities,
            &self.exposure_guard,
            false, // not locked
            &self.policy_checksum,
            Self::actor_identity(&ctx.actor),
            &self.session_id,
        );

        // 3. Audit log integration deferred to PR 2 (requires async + AuditLog)
        Ok(())
    }

    fn preflight(&self, _operation: Operation) -> Result<(), SinkError> {
        if self.is_locked() {
            Err(SinkError::Locked)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn make_sink(file_locked: bool, stream_locked: bool) -> ToolProxyVerdictSink {
        ToolProxyVerdictSink::new(
            Arc::new(AtomicBool::new(file_locked)),
            Arc::new(AtomicBool::new(stream_locked)),
            CapabilityLattice::default(),
            Arc::new(std::sync::RwLock::new(None)),
            "test-checksum".to_string(),
            "test-session".to_string(),
        )
    }

    #[test]
    fn preflight_passes_when_unlocked() {
        let sink = make_sink(false, false);
        assert!(sink.preflight(Operation::ReadFiles).is_ok());
    }

    #[test]
    fn preflight_fails_when_file_locked() {
        let sink = make_sink(true, false);
        assert!(matches!(
            sink.preflight(Operation::ReadFiles).unwrap_err(),
            SinkError::Locked
        ));
    }

    #[test]
    fn preflight_fails_when_stream_locked() {
        let sink = make_sink(false, true);
        assert!(matches!(
            sink.preflight(Operation::RunBash).unwrap_err(),
            SinkError::Locked
        ));
    }

    #[test]
    fn preflight_fails_when_both_locked() {
        let sink = make_sink(true, true);
        assert!(matches!(
            sink.preflight(Operation::WebFetch).unwrap_err(),
            SinkError::Locked
        ));
    }

    #[test]
    fn record_passes_when_unlocked() {
        let sink = make_sink(false, false);
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
    fn record_denied_when_locked() {
        let sink = make_sink(true, false);
        let ctx = VerdictContext {
            operation: Operation::ReadFiles,
            subject: "/workspace/secret.txt".to_string(),
            outcome: VerdictOutcome::Allow,
            actor: ActorIdentity::StdioGuest,
            policy_rule: None,
            extensions: BTreeMap::new(),
        };
        assert!(matches!(sink.record(ctx).unwrap_err(), SinkError::Locked));
    }

    #[test]
    fn operation_name_mapping() {
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::ReadFiles),
            "read"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::WriteFiles),
            "write"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::EditFiles),
            "edit"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::RunBash),
            "run"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::GlobSearch),
            "glob"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::GrepSearch),
            "grep"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::WebSearch),
            "web_search"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::WebFetch),
            "web_fetch"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::GitCommit),
            "git_commit"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::GitPush),
            "git_push"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::CreatePr),
            "create_pr"
        );
        assert_eq!(
            ToolProxyVerdictSink::operation_name(Operation::ManagePods),
            "manage_pods"
        );
    }

    #[test]
    fn outcome_to_result_mapping() {
        assert_eq!(
            ToolProxyVerdictSink::outcome_to_result(&VerdictOutcome::Allow),
            "ok"
        );
        assert_eq!(
            ToolProxyVerdictSink::outcome_to_result(&VerdictOutcome::Deny {
                reason: "lockdown".into()
            }),
            "denied:lockdown"
        );
        assert_eq!(
            ToolProxyVerdictSink::outcome_to_result(&VerdictOutcome::Error {
                error: "I/O timeout".into()
            }),
            "denied:I/O timeout"
        );
    }

    #[test]
    fn actor_identity_extraction() {
        assert_eq!(
            ToolProxyVerdictSink::actor_identity(&ActorIdentity::Authenticated {
                spiffe_id: "spiffe://test".into()
            }),
            Some("spiffe://test")
        );
        assert_eq!(
            ToolProxyVerdictSink::actor_identity(&ActorIdentity::StdioGuest),
            Some("stdio-guest")
        );
        assert_eq!(
            ToolProxyVerdictSink::actor_identity(&ActorIdentity::Unknown),
            None
        );
    }
}
