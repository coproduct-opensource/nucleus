//! Concrete VerdictSink for the tool-proxy process.
//!
//! Bridges the portcullis `VerdictSink` trait to the tool-proxy's existing
//! lockdown flags and telemetry infrastructure. Each verdict becomes a
//! `tracing::info_span!` with duration and trace context propagation.
//! When the `otel` feature is active, spans flow to OTLP backends as
//! proper OpenTelemetry spans with parent-child relationships.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
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
    /// Consecutive denied operations. Reset by any allow.
    ///
    /// See [`ToolProxyVerdictSink::note_outcome_for_breaker`].
    consecutive_denials: AtomicU32,
    /// How many consecutive denials trip lockdown. `0` disables the breaker.
    denial_budget: u32,
}

/// Consecutive denials that trip the breaker when `NUCLEUS_DENIAL_BUDGET` is
/// unset.
///
/// Ten is chosen to sit well above legitimate behaviour and well below a
/// productive attack. Because the count is CONSECUTIVE and any allow resets it,
/// an agent doing real work — which interleaves successful calls with the
/// occasional refusal — never approaches it; ten refusals in a row with nothing
/// succeeding in between is not an agent working, it is an agent probing.
pub(crate) const DEFAULT_DENIAL_BUDGET: u32 = 10;

/// Read the configured denial budget. `0` (or an unparseable value) disables it.
fn denial_budget_from_env() -> u32 {
    match std::env::var("NUCLEUS_DENIAL_BUDGET") {
        Ok(v) => v.trim().parse().unwrap_or(DEFAULT_DENIAL_BUDGET),
        Err(_) => DEFAULT_DENIAL_BUDGET,
    }
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
    mediation_receipt_log: Option<std::path::PathBuf>,
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
            // The path (when given) is where the full signed receipts are
            // persisted for offline verification — opened only once a key exists.
            crate::art12_sink::ReceiptSigner::from_env(mediation_receipt_log.as_deref()),
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
            consecutive_denials: AtomicU32::new(0),
            denial_budget: denial_budget_from_env(),
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

    /// The **behavioural circuit breaker**: trip lockdown after
    /// [`denial_budget`](Self::denial_budget) consecutive denials.
    ///
    /// Lockdown could already be entered two ways — an operator writing the
    /// signal file, and a fleet command over the gRPC stream — and both are a
    /// *human* deciding something is wrong. Nothing let the pod reach that
    /// conclusion by itself, so an agent "operating outside policy while still
    /// appearing legitimate" (OWASP ASI10, Rogue Agents) could hammer the policy
    /// wall indefinitely: every individual call was correctly refused, and the
    /// pattern across calls was nobody's job to notice.
    ///
    /// This does not introduce a new way to deny. It sets the SAME
    /// `file_lockdown` flag the operator path sets, so the deny happens through
    /// the existing, already-enforced `preflight`/`record` gate. One lockdown
    /// state, three ways in; clearing it stays a human action.
    ///
    /// **Consecutive**, and reset by any allow — that choice is what makes the
    /// default safe. Real work interleaves successes with the occasional
    /// refusal, so it never accumulates; a run of denials with nothing
    /// succeeding in between is a different shape of session.
    ///
    /// Returns `true` if this call tripped the breaker (for tests and logging).
    fn note_outcome_for_breaker(&self, verdict: &str) -> bool {
        if self.denial_budget == 0 {
            return false; // explicitly disabled
        }
        if verdict == "allow" {
            self.consecutive_denials.store(0, Ordering::Release);
            return false;
        }
        // `requires_approval` is a deferral, not a refusal: it means a human was
        // asked, which is the system working. Counting it would trip the breaker
        // on well-behaved sessions that use approvals.
        if verdict != "deny" {
            return false;
        }
        let n = self.consecutive_denials.fetch_add(1, Ordering::AcqRel) + 1;
        if n < self.denial_budget {
            return false;
        }
        // Trip. Idempotent: already-locked sessions just stay locked.
        let already = self.file_lockdown.swap(true, Ordering::AcqRel);
        if !already {
            tracing::error!(
                target: "nucleus_permission",
                consecutive_denials = n,
                budget = self.denial_budget,
                session_id = %self.session_id,
                "CIRCUIT BREAKER TRIPPED: {n} consecutive denials — entering lockdown. \
                 The agent is being refused repeatedly with nothing succeeding in between; \
                 clearing lockdown is a human action."
            );
        }
        !already
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

        // The behavioural breaker sees the verdict BEFORE telemetry, so the span
        // below reports the lockdown state this call may itself have caused.
        let breaker_tripped = self.note_outcome_for_breaker(verdict_str);
        let lockdown_active = lockdown_active || breaker_tripped;

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

    /// The behavioural circuit breaker (ASI10, Rogue Agents).
    ///
    /// Every test here drives `note_outcome_for_breaker` directly rather than
    /// through `record`, because `record`'s span emission needs no fixture and
    /// the breaker's *decision* is the subject.
    mod circuit_breaker {
        use super::*;

        fn sink_with_budget(budget: u32) -> ToolProxyVerdictSink {
            let mut s = make_sink(false, false);
            s.denial_budget = budget;
            s
        }

        #[test]
        fn consecutive_denials_trip_lockdown() {
            let s = sink_with_budget(3);
            assert!(!s.is_locked(), "must start unlocked or this proves nothing");

            assert!(!s.note_outcome_for_breaker("deny"));
            assert!(!s.note_outcome_for_breaker("deny"));
            assert!(!s.is_locked(), "must not trip before the budget");

            assert!(s.note_outcome_for_breaker("deny"), "the third trips it");
            assert!(
                s.is_locked(),
                "the breaker must enter the SAME lockdown state"
            );
        }

        #[test]
        fn an_allow_resets_the_run() {
            // The property that makes the default safe: real work interleaves
            // successes, so it never accumulates toward the budget.
            let s = sink_with_budget(3);
            for _ in 0..10 {
                s.note_outcome_for_breaker("deny");
                s.note_outcome_for_breaker("deny");
                s.note_outcome_for_breaker("allow");
            }
            assert!(
                !s.is_locked(),
                "20 denials interleaved with allows must NOT trip a budget of 3"
            );
        }

        #[test]
        fn approvals_are_deferrals_not_refusals() {
            // `requires_approval` means a human was asked — the system working.
            // Counting it would trip the breaker on well-behaved sessions.
            let s = sink_with_budget(3);
            for _ in 0..20 {
                s.note_outcome_for_breaker("requires_approval");
            }
            assert!(!s.is_locked());
        }

        #[test]
        fn a_zero_budget_disables_the_breaker() {
            let s = sink_with_budget(0);
            for _ in 0..100 {
                s.note_outcome_for_breaker("deny");
            }
            assert!(!s.is_locked(), "budget 0 must be off, not instant");
        }

        #[test]
        fn tripping_is_idempotent() {
            let s = sink_with_budget(1);
            assert!(
                s.note_outcome_for_breaker("deny"),
                "first trip reports true"
            );
            assert!(
                !s.note_outcome_for_breaker("deny"),
                "an already-locked session must not re-report a trip"
            );
            assert!(s.is_locked());
        }

        #[test]
        fn a_tripped_breaker_denies_through_the_existing_gate() {
            // The point of setting `file_lockdown` rather than inventing a new
            // deny: enforcement is the path that already existed and is already
            // tested. If this failed, the breaker would be setting a flag nobody
            // reads — the exact "control that isn't wired" shape.
            let s = sink_with_budget(1);
            assert!(
                s.preflight(Operation::RunBash).is_ok(),
                "must be permitted before the trip, or the assertion below is vacuous"
            );
            s.note_outcome_for_breaker("deny");
            assert!(matches!(
                s.preflight(Operation::RunBash),
                Err(SinkError::Locked)
            ));
        }

        #[test]
        fn the_default_budget_is_a_real_number() {
            // Guards against a default of 0 (off) or 1 (trips on one refusal).
            const { assert!(DEFAULT_DENIAL_BUDGET >= 5, "too twitchy for real sessions") };
            const { assert!(DEFAULT_DENIAL_BUDGET <= 50, "too loose to catch probing") };
        }
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
