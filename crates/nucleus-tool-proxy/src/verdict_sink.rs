//! Concrete VerdictSink for the tool-proxy process.
//!
//! Bridges the portcullis `VerdictSink` trait to the tool-proxy's existing
//! lockdown flags and telemetry infrastructure. Each verdict becomes a
//! `tracing::info_span!` with duration and trace context propagation.
//! When the `otel` feature is active, spans flow to OTLP backends as
//! proper OpenTelemetry spans with parent-child relationships.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use portcullis::trace_monitor::TraceMonitor;
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
    /// Whether DLC-D verified admission is provisioned on this pod's kernels.
    /// When true, every `Allow` this sink records has — by kernel construction
    /// (the dlc gate is consulted before any Allow can emerge from
    /// `decide_term_with_flow`, and complete mediation routes every tool call
    /// through the kernel) — passed the issuer-credential check.
    dlc_provisioned: bool,
}

/// Build the process's verdict sink, already wrapped in its monitor.
///
/// # Why this is the only constructor
///
/// `ToolProxyVerdictSink::new` is private to this module, so no caller can
/// obtain an *unmonitored* sink. That is deliberate, and is the same move
/// `mediation::decide_and_record` makes for the decision: the property "the
/// live sink chain is monitored" holds because of a module boundary, not
/// because a call site in `main.rs` remembers to wrap.
///
/// The alternative — construct the sink, then wrap it at the call site — is
/// precisely the shape that has failed repeatedly here: an artifact attached to
/// the live path by an edit that a later edit can silently undo, with every test
/// still green. There is nothing to undo if there is nothing else to return.
///
/// Returns `(sink, monitor)`. Both handles refer to the same object; the second
/// exists so the process can read violations back out at `/v1/health` and at
/// exit.
#[allow(clippy::too_many_arguments)]
pub fn build_monitored_sink(
    file_lockdown: Arc<AtomicBool>,
    stream_lockdown: Arc<AtomicBool>,
    capabilities: CapabilityLattice,
    exposure_guard: Arc<std::sync::RwLock<Option<Arc<GradedExposureGuard>>>>,
    policy_checksum: String,
    session_id: String,
    dlc_provisioned: bool,
    art12_log: Option<Arc<crate::art12::Art12Log>>,
    art12_shipper: Option<Arc<crate::art12_shipper::Art12Shipper>>,
) -> (Arc<dyn VerdictSink>, Arc<TraceMonitor>) {
    let inner: Arc<dyn VerdictSink> = Arc::new(ToolProxyVerdictSink::new(
        file_lockdown,
        stream_lockdown,
        capabilities,
        exposure_guard,
        policy_checksum.clone(),
        session_id.clone(),
        dlc_provisioned,
    ));

    // Article 12 record-keeping, when configured. INSIDE the monitor, so the
    // monitor still observes every record; and inside this constructor, so
    // there is no way to assemble a chain that skips it.
    let inner = match art12_log {
        Some(log) => Arc::new(crate::art12_sink::Art12Sink::new(
            inner,
            log,
            session_id,
            policy_checksum,
            dlc_provisioned,
            art12_shipper,
            // Opt-in: emits signed MediationReceipts only when a mediator key is
            // configured (NUCLEUS_MEDIATION_SIGNING_KEY / _SPIFFE_ID); else None.
            crate::art12_sink::ReceiptSigner::from_env(),
        )) as Arc<dyn VerdictSink>,
        None => inner,
    };

    let monitor = Arc::new(TraceMonitor::new(inner));
    (monitor.clone(), monitor)
}

impl ToolProxyVerdictSink {
    /// Build from the same fields already present on `AppState`.
    ///
    /// Private: see [`build_monitored_sink`]. The unit tests below construct
    /// bare sinks because their subject is the sink's own behaviour; the live
    /// path cannot.
    #[allow(clippy::too_many_arguments)]
    fn new(
        file_lockdown: Arc<AtomicBool>,
        stream_lockdown: Arc<AtomicBool>,
        capabilities: CapabilityLattice,
        exposure_guard: Arc<std::sync::RwLock<Option<Arc<GradedExposureGuard>>>>,
        policy_checksum: String,
        session_id: String,
        dlc_provisioned: bool,
    ) -> Self {
        Self {
            file_lockdown,
            stream_lockdown,
            capabilities,
            exposure_guard,
            policy_checksum,
            session_id,
            dlc_provisioned,
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
                // A deferral is NOT a refusal — kept distinct so the Article 14
                // human-oversight event is legible in telemetry and evidence.
                VerdictOutcome::RequiresApproval { reason } => {
                    ("requires_approval", reason.clone())
                }
                VerdictOutcome::Deny { reason } => ("deny", reason.clone()),
                VerdictOutcome::Error { error } => ("error", error.clone()),
                // `VerdictOutcome` is #[non_exhaustive]. An outcome this build
                // does not know must not silently read as "allow": record it as
                // an error naming the gap, so unclassified evidence is visible
                // rather than flattering.
                other => ("error", format!("unclassified verdict outcome: {other:?}")),
            }
        };

        let caps = telemetry::VerdictCapabilities::from(&self.capabilities);
        let exposure = self.read_exposure();
        let actor = Self::actor_str(&ctx.actor);
        let operation = Self::operation_name(ctx.operation);
        let is_ok = verdict_str == "allow";
        // Attestation of the verified-admission state, per tool call: "admitted"
        // is only ever emitted when admission is provisioned AND the kernel
        // allowed (see the `dlc_provisioned` field docs for why that implies
        // the credential check passed); otherwise the span says so honestly.
        let dlc_admission = if self.dlc_provisioned {
            if is_ok {
                "admitted"
            } else {
                "not-admitted"
            }
        } else {
            "unprovisioned"
        };

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
            nucleus.dlc_admission = dlc_admission,
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

/// Emit one evidence record for a kernel decision — **the single
/// implementation, used by both transports.**
///
/// EU AI Act Article 12 requires post-hoc reconstruction of an individual
/// decision, so the kernel fields ride `VerdictContext.extensions`: which
/// permissions were in force before and after, whether a dynamic exposure gate
/// fired, the machine-stable refusal code, and the decision sequence that joins
/// this record to the terminal outcome for the same operation.
///
/// # Why one function rather than one per transport
///
/// The HTTP and MCP paths reach the kernel through different chokepoints, and
/// implementing this twice is how the two evidence streams silently diverge —
/// the same failure mode as a duplicated canonical preimage. The transport is a
/// parameter, not a copy.
///
/// Best-effort by design: a failure to record must not fail the call, because at
/// most call sites the effect has already happened and returning an error would
/// invite a retry that doubles it. The gap is surfaced as a warning and, once
/// the durable log is wired, counted so it is explicit rather than silent.
///
pub(crate) fn record_kernel_decision(
    sink: &dyn VerdictSink,
    decision: &portcullis::kernel::Decision,
    operation: Operation,
    subject: &str,
    actor: ActorIdentity,
    transport: &str,
) {
    use portcullis::gate_class;
    use portcullis::kernel::Verdict;
    use std::collections::BTreeMap;

    let mut extensions = BTreeMap::new();
    extensions.insert("transport".to_string(), transport.to_string());
    extensions.insert(
        "decision_sequence".to_string(),
        decision.sequence.to_string(),
    );
    extensions.insert(
        "gate_class".to_string(),
        gate_class::classify(&decision.verdict, &decision.exposure_transition)
            .as_str()
            .to_string(),
    );
    extensions.insert(
        "pre_permissions_hash".to_string(),
        decision.pre_permissions_hash.clone(),
    );
    extensions.insert(
        "post_permissions_hash".to_string(),
        decision.post_permissions_hash.clone(),
    );
    extensions.insert(
        "dynamic_gate_applied".to_string(),
        decision
            .exposure_transition
            .dynamic_gate_applied
            .to_string(),
    );

    let outcome = match &decision.verdict {
        Verdict::Allow => VerdictOutcome::Allow,
        Verdict::RequiresApproval => VerdictOutcome::RequiresApproval {
            reason: "approval required before this operation may proceed".to_string(),
        },
        Verdict::Deny(reason) => {
            // The machine-stable serde tag, never `Debug` — an auditor's saved
            // query keys on this, and `Debug` shifts when a variant changes.
            extensions.insert(
                "deny_code".to_string(),
                gate_class::deny_code(reason).to_string(),
            );
            VerdictOutcome::Deny {
                reason: format!("{reason:?}"),
            }
        }
    };

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: subject.to_string(),
        outcome,
        actor,
        policy_rule: None,
        extensions,
    }) {
        tracing::warn!(error = %e, ?operation, subject, "kernel-decision recording failed -- audit gap");
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
            false,
        )
    }

    fn built() -> (Arc<dyn VerdictSink>, Arc<TraceMonitor>) {
        build_monitored_sink(
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            CapabilityLattice::default(),
            Arc::new(std::sync::RwLock::new(None)),
            "test-checksum".to_string(),
            "test-session".to_string(),
            false,
            None,
            None,
        )
    }

    /// **The acceptance test for the wiring.** Not "a TraceMonitor works" —
    /// #2141 proved that — but "the sink this process actually uses is the
    /// monitored one". It asserts on what the monitor OBSERVED, so it cannot
    /// pass if the chain is unwired.
    ///
    /// Perturbation (run 2026-08-01): return the bare `ToolProxyVerdictSink`
    /// from `build_monitored_sink` and this REDs on the count, naming the
    /// defect.
    #[test]
    fn records_flowing_through_the_built_sink_reach_the_monitor() {
        let (sink, monitor) = built();
        assert!(
            monitor.violations().is_empty(),
            "a fresh monitor must be clean, or the assertion below proves nothing"
        );

        // A terminal Allow with no preceding kernel decision: an effect that
        // nothing on the record authorised.
        sink.record(VerdictContext {
            operation: Operation::RunBash,
            subject: "unmediated".to_string(),
            outcome: VerdictOutcome::Allow,
            actor: ActorIdentity::Unknown,
            policy_rule: None,
            extensions: BTreeMap::new(),
        })
        .unwrap();

        assert_eq!(
            monitor.violations().len(),
            1,
            "the sink handed to the process must be monitored; the monitor saw nothing"
        );
    }

    /// Monitoring must not change what the sink does. A locked sink still
    /// refuses through the wrapper, so wiring the monitor cannot have opened a
    /// path that lockdown used to close.
    #[test]
    fn the_built_sink_still_enforces_lockdown() {
        let locked = build_monitored_sink(
            Arc::new(AtomicBool::new(true)),
            Arc::new(AtomicBool::new(false)),
            CapabilityLattice::default(),
            Arc::new(std::sync::RwLock::new(None)),
            "test-checksum".to_string(),
            "test-session".to_string(),
            false,
            None,
            None,
        )
        .0;
        assert!(matches!(
            locked.preflight(Operation::ReadFiles).unwrap_err(),
            SinkError::Locked
        ));
    }

    /// A sink that keeps what it was handed, so a test can assert on what the
    /// recording RECEIVED rather than on what was available to it.
    #[derive(Default)]
    struct CapturingSink(std::sync::Mutex<Vec<VerdictContext>>);
    impl VerdictSink for CapturingSink {
        fn record(&self, ctx: VerdictContext) -> Result<(), SinkError> {
            self.0.lock().unwrap().push(ctx);
            Ok(())
        }
        fn preflight(&self, _op: Operation) -> Result<(), SinkError> {
            Ok(())
        }
    }

    fn sample_decision() -> portcullis::kernel::Decision {
        portcullis::kernel::Decision {
            id: uuid::Uuid::nil(),
            sequence: 7,
            operation: Operation::WebFetch,
            subject: "s".to_string(),
            verdict: portcullis::kernel::Verdict::Allow,
            timestamp: chrono::Utc::now(),
            pre_permissions_hash: "pre".to_string(),
            post_permissions_hash: "post".to_string(),
            exposure_transition: portcullis::kernel::ExposureTransition {
                pre_count: 0,
                post_count: 0,
                contributed_label: None,
                state_uninhabitable: false,
                dynamic_gate_applied: false,
            },
            flow_node_id: None,
            action_term: None,
            preflight_result: None,
        }
    }

    /// The kernel decision is recorded as durable evidence — the discipline that
    /// reframed this chokepoint: a verdict (allow or refusal) must reach the sink,
    /// never just a log line. `record_kernel_decision` is the same call the live
    /// HTTP and MCP paths make.
    #[test]
    fn the_kernel_decision_reaches_the_record() {
        let sink = CapturingSink::default();
        record_kernel_decision(
            &sink,
            &sample_decision(),
            Operation::WebFetch,
            "s",
            ActorIdentity::Unknown,
            "http",
        );
        let recorded = sink.0.lock().unwrap();
        assert_eq!(
            recorded.len(),
            1,
            "the decision must be recorded exactly once"
        );
        let ext = &recorded[0].extensions;
        assert_eq!(ext.get("transport").map(String::as_str), Some("http"));
        assert_eq!(ext.get("decision_sequence").map(String::as_str), Some("7"));
        assert!(
            ext.contains_key("gate_class"),
            "the verdict's gate class must be in the evidence"
        );
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
