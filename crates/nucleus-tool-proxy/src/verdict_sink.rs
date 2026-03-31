//! Concrete VerdictSink for the tool-proxy process.
//!
//! Bridges the portcullis `VerdictSink` trait to the tool-proxy's existing
//! lockdown flags and telemetry infrastructure. Each verdict becomes a
//! `tracing::info_span!` with duration and trace context propagation.
//! When the `otel` feature is active, spans flow to OTLP backends as
//! proper OpenTelemetry spans with parent-child relationships.

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

    /// Map Operation to the short string names used by the audit log.
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
            Operation::SpawnAgent => "spawn_agent",
        }
    }

    /// Extract the agent identity string for telemetry.
    fn actor_str(actor: &ActorIdentity) -> &str {
        match actor {
            ActorIdentity::Authenticated { spiffe_id } => spiffe_id.as_str(),
            ActorIdentity::StdioGuest => "stdio-guest",
            ActorIdentity::Unknown => "unknown",
        }
    }

    /// Read current exposure state from the guard.
    fn read_exposure(&self) -> telemetry::VerdictExposure {
        if let Ok(guard_opt) = self.exposure_guard.read() {
            if let Some(ref guard) = *guard_opt {
                let exp = guard.exposure();
                telemetry::VerdictExposure {
                    private_data: exp.contains(portcullis::guard::ExposureLabel::PrivateData),
                    untrusted_content: exp
                        .contains(portcullis::guard::ExposureLabel::UntrustedContent),
                    exfil_vector: exp.contains(portcullis::guard::ExposureLabel::ExfilVector),
                    is_uninhabitable: exp.is_uninhabitable(),
                }
            } else {
                telemetry::VerdictExposure::default()
            }
        } else {
            tracing::error!("exposure_guard RwLock poisoned — reporting uninhabitable");
            telemetry::VerdictExposure {
                private_data: true,
                untrusted_content: true,
                exfil_vector: true,
                is_uninhabitable: true,
            }
        }
    }
}

impl VerdictSink for ToolProxyVerdictSink {
    fn record(&self, ctx: VerdictContext) -> Result<(), SinkError> {
        // 1. Check lockdown (may have been activated between preflight and now)
        let lockdown_active = self.is_locked();

        let (verdict_str, deny_reason) = if lockdown_active {
            // Lockdown applies read-only lattice projection: reads pass, writes/exfil blocked.
            // Check if this operation is a read (allowed under lockdown).
            let is_read_op = matches!(
                ctx.operation,
                Operation::ReadFiles
                    | Operation::GlobSearch
                    | Operation::GrepSearch
                    | Operation::WebSearch
                    | Operation::WebFetch
            );
            if is_read_op && matches!(ctx.outcome, VerdictOutcome::Allow) {
                ("allow", String::new())
            } else {
                ("deny", "LOCKDOWN: read-only mode active".to_string())
            }
        } else {
            match &ctx.outcome {
                VerdictOutcome::Allow => ("allow", String::new()),
                VerdictOutcome::Deny { reason } => ("deny", reason.clone()),
                VerdictOutcome::Error { error } => ("error", error.clone()),
            }
        };

        let caps = telemetry::VerdictCapabilities::from(&self.capabilities);
        let exposure = self.read_exposure();
        let actor = Self::actor_str(&ctx.actor);
        let operation = Self::operation_name(ctx.operation);
        let is_ok = verdict_str == "allow";

        // 2. Emit a proper span (not an event) so it has duration and
        //    propagates trace context.  When the `otel` layer is active,
        //    `tracing-opentelemetry` exports this as an OTLP span with
        //    parent-child relationships.
        let span = tracing::info_span!(
            target: "nucleus_permission",
            "tool_call",
            otel.kind = "INTERNAL",
            otel.status_code = if is_ok { "OK" } else { "ERROR" },
            nucleus.verdict = verdict_str,
            nucleus.operation = operation,
            nucleus.subject = %ctx.subject,
            nucleus.deny_reason = %deny_reason,
            nucleus.actor = actor,
            // All 12 capability dimensions
            cap.read_files = caps.read_files,
            cap.write_files = caps.write_files,
            cap.edit_files = caps.edit_files,
            cap.run_bash = caps.run_bash,
            cap.glob_search = caps.glob_search,
            cap.grep_search = caps.grep_search,
            cap.web_fetch = caps.web_fetch,
            cap.web_search = caps.web_search,
            cap.git_commit = caps.git_commit,
            cap.git_push = caps.git_push,
            cap.create_pr = caps.create_pr,
            cap.manage_pods = caps.manage_pods,
            // Exposure state
            exposure.private_data = exposure.private_data,
            exposure.untrusted_content = exposure.untrusted_content,
            exposure.exfil_vector = exposure.exfil_vector,
            exposure.uninhabitable = exposure.is_uninhabitable,
            // Context
            nucleus.lockdown_active = lockdown_active,
            nucleus.lattice_checksum = %self.policy_checksum,
            nucleus.session_id = %self.session_id,
        );
        let _enter = span.enter();
        // Span duration = time spent in record(), giving it meaningful timing.

        // 3. Return lockdown error after emitting telemetry so the event is visible.
        if lockdown_active {
            return Err(SinkError::Locked);
        }

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
    fn actor_str_extraction() {
        assert_eq!(
            ToolProxyVerdictSink::actor_str(&ActorIdentity::Authenticated {
                spiffe_id: "spiffe://test".into()
            }),
            "spiffe://test"
        );
        assert_eq!(
            ToolProxyVerdictSink::actor_str(&ActorIdentity::StdioGuest),
            "stdio-guest"
        );
        assert_eq!(
            ToolProxyVerdictSink::actor_str(&ActorIdentity::Unknown),
            "unknown"
        );
    }
}
