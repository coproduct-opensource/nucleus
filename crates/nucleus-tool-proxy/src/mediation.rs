//! Mapping kernel refusals onto the HTTP error surface.
//!
//! Extracted from `main.rs` to stay under the line ratchet, and because this is
//! a coherent unit on its own: it is the one place that decides how a kernel
//! `DenyReason` is described to a caller. The match is deliberately EXHAUSTIVE —
//! a new refusal reason must be given a surfacing here before it can compile,
//! rather than silently becoming a generic capability error.

use nucleus::portcullis::kernel::DenyReason;
use nucleus::portcullis::{CapabilityLevel, Operation};

use nucleus::portcullis::action_term::ActionTerm;
use nucleus::portcullis::kernel::{Decision, DecisionToken, Kernel, Verdict};
use nucleus::portcullis::verdict_sink::{ActorIdentity, VerdictSink};
use nucleus::portcullis::FlowTracker;
use nucleus::NucleusError;
use tracing::{info, warn};

use crate::ApiError;

/// Translate a kernel [`DenyReason`] into the HTTP error surface, preserving
/// what the kernel actually said.
///
/// Each arm maps to a reason the response mapping already models, so a caller
/// sees `path_denied` / `budget_exhausted` / `command_denied` rather than a
/// blanket capability error. `InsufficientCapability` is the ONLY reason that
/// still produces `InsufficientCapability` — that is the one case where it is
/// true.
///
/// The catch-all keeps the reason text rather than discarding it: a new
/// `DenyReason` variant should surface as an unfamiliar-but-accurate message,
/// not silently become a capability claim.
pub(crate) fn kernel_denial_to_api_error(
    operation: Operation,
    subject: &str,
    reason: DenyReason,
) -> ApiError {
    match reason {
        DenyReason::InsufficientCapability => {
            ApiError::Nucleus(NucleusError::InsufficientCapability {
                capability: format!("{operation:?}"),
                actual: CapabilityLevel::Never,
                required: CapabilityLevel::LowRisk,
            })
        }
        DenyReason::PathBlocked { path } => ApiError::Nucleus(NucleusError::PathDenied {
            path: std::path::PathBuf::from(path),
            reason: "blocked by the path lattice".to_string(),
        }),
        DenyReason::CommandBlocked { command } => ApiError::Nucleus(NucleusError::CommandDenied {
            command,
            reason: "blocked by the command lattice".to_string(),
        }),
        // Everything else keeps the kernel's own words, and is listed
        // EXHAUSTIVELY rather than behind `_`.
        //
        // The sibling mapping on the MCP path (`nucleus_mcp::format_deny_reason`)
        // is exhaustive for the same reason, and it is the better discipline: a
        // security surface should not acquire a new refusal reason without
        // somebody deciding how it surfaces. Behind a catch-all, a future
        // `DenyReason` variant silently becomes `kernel_denied` forever;
        // exhaustive, it is a compile error until someone chooses.
        //
        // Deliberately NOT promoted to richer types where that needs an invented
        // field: `NucleusError::BudgetExhausted` requires `requested`, and
        // `DenyReason::BudgetExhausted` carries only `remaining_usd`.
        // Synthesising the missing number is precisely the defect this function
        // exists to remove.
        other @ (DenyReason::BudgetExhausted { .. }
        | DenyReason::TimeExpired { .. }
        | DenyReason::IsolationInsufficient { .. }
        | DenyReason::IsolationGated { .. }
        | DenyReason::FlowViolation { .. }
        | DenyReason::EgressBlocked { .. }
        | DenyReason::PolicyDenied { .. }
        | DenyReason::EnterpriseBlocked { .. }
        | DenyReason::DelegationDenied { .. }
        | DenyReason::InvalidDeclassification { .. }
        | DenyReason::DeclassificationReplayed { .. }
        | DenyReason::ActionTermRejected { .. }
        | DenyReason::SinkScopeDenied { .. }
        | DenyReason::IfcUnsafe { .. }
        | DenyReason::CedarDenied { .. }
        | DenyReason::DlcAdmissionDenied { .. }) => {
            ApiError::KernelDenied(format!("{other:?} (operation {operation:?} on {subject})"))
        }
    }
}

/// Pure reference monitor for the HTTP path: kernel decision + information-flow
/// consult, mapped to the HTTP error surface. Split out from [`http_kernel_decide`]
/// so it is unit-testable with a bare [`Kernel`] + [`FlowTracker`] (no `AppState`).
/// Private to this module: see [`decide_and_record`] for why.
///
/// This is the single source of truth for HTTP mediation (#1194, #1633): it
/// routes through [`Kernel::decide_term_with_flow`] — the same taint-aware path
/// the MCP server uses — so once the session has ingested adversarial (web)
/// content, outbound operations are denied with [`DenyReason::IfcUnsafe`] before
/// any side effect. The deprecated capability-only `Kernel::decide()` is no
/// longer reachable from the HTTP handlers.
///
/// The decision used to be dropped here, which meant a refusal left no trace:
/// every caller reaches this through `?`, so on `Deny` the handler returns
/// before any `sink.record(...)` runs, and the sink never observed
/// `DlcAdmissionDenied`, `IfcUnsafe`, `PathBlocked`, `CommandBlocked`,
/// `FlowViolation` or `RequiresApproval` at all. A durable evidence log wired
/// on top of that would have recorded **only allows** — non-empty, plausible,
/// and wrong in the most dangerous possible direction for an EU AI Act Article
/// 12 record. Handing the decision back lets the chokepoint record it before
/// propagating the error.
fn decide_with_flow_mapped(
    kernel: &mut Kernel,
    flow: &FlowTracker,
    operation: Operation,
    subject: &str,
) -> (Decision, Result<DecisionToken, ApiError>) {
    let term = ActionTerm::from_operation(operation, subject);
    let (decision, token) = kernel.decide_term_with_flow(term, Some(flow));
    let mapped = match decision.verdict.clone() {
        Verdict::Allow => Ok(token.expect("Allow verdict always produces token")),
        Verdict::Deny(DenyReason::IfcUnsafe { detail }) => {
            warn!(?operation, subject, %detail, "HTTP IFC denied outbound action (lethal trifecta)");
            Err(ApiError::IfcDenied(detail))
        }
        // Report the reason the kernel actually gave.
        //
        // Both of these arms used to return
        // `InsufficientCapability { capability: format!("{operation:?}"),
        //  actual: Never, required: LowRisk }` — where `Never` is a **constant
        // written here**, not a reading of the policy. So a pod whose profile
        // sets `read_files: Always` was told "'ReadFiles' level is Never" for a
        // blocked path, an exhausted budget, an expired session, or a request
        // that merely needed approval. Measured on a booted pod: the guest's
        // resolved runtime was `demo` with `read_files = Always` while the wire
        // said `Never`. That is a control stating a confident falsehood about
        // why it refused — the same shape as a seccomp check reporting mode 0
        // for a process that had already exited.
        //
        // The capability name was also the Debug of the *Operation*
        // (`ReadFiles`), not a capability, which is what made the mismatch
        // visible: nothing in the lattice is spelled that way.
        Verdict::Deny(reason) => {
            warn!(?operation, subject, ?reason, "HTTP kernel denied operation");
            Err(kernel_denial_to_api_error(operation, subject, reason))
        }
        Verdict::RequiresApproval => {
            info!(
                ?operation,
                subject,
                exposure = decision.exposure_transition.post_count,
                "HTTP kernel requires approval (no auto-approve channel)"
            );
            // `approval_required`, which the response mapping already models and
            // which tells the caller something true and actionable: this is not
            // "you may never do this", it is "this needs an approval you have
            // not presented".
            Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("{operation:?} {subject}"),
            }))
        }
    };
    (decision, mapped)
}

/// Decide, record, and map — in that order, indivisibly.
///
/// The recording is inside this function rather than at the call site because
/// the defect it fixes was *an early return*: every caller reaches the verdict
/// through `?`, so any refusal skipped a recording step written after the call.
/// Keeping `decide_with_flow_mapped` private to this module means a `Decision`
/// cannot be produced anywhere else, so it cannot escape unrecorded. That is a
/// property of the module boundary, not of a test that must remember to check.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decide_and_record(
    sink: &dyn VerdictSink,
    kernel: &mut Kernel,
    flow: &FlowTracker,
    operation: Operation,
    subject: &str,
    actor: ActorIdentity,
    transport: &str,
) -> Result<DecisionToken, ApiError> {
    let (decision, mapped) = decide_with_flow_mapped(kernel, flow, operation, subject);

    // Second opinion from the causal DAG. Inside this function, beside the
    // recording, for the same reason the recording is here: a step written at
    // the call site is a step a refusal's `?` can skip.
    let flow_check = cross_check_flow(flow, &decision, operation);
    if let Some(result) = &flow_check {
        if *result
            != FlowCrossCheck::Checked(nucleus::portcullis::flow::VerificationResult::Confirmed)
        {
            warn!(
                ?operation,
                subject,
                ?result,
                verdict = ?decision.verdict,
                "flow cross-check did not confirm the kernel verdict"
            );
        }
    }

    crate::verdict_sink::record_kernel_decision(
        sink, &decision, operation, subject, actor, transport, flow_check,
    );
    mapped
}

#[cfg(test)]
mod cross_check_tests {
    use super::*;
    use nucleus::portcullis::flow::VerificationResult;
    use nucleus::portcullis::kernel::ExposureTransition;
    use nucleus::portcullis::NodeKind;

    fn decision_with(verdict: Verdict) -> Decision {
        Decision {
            id: uuid::Uuid::nil(),
            sequence: 1,
            operation: Operation::WebFetch,
            subject: "https://example.invalid".to_string(),
            verdict,
            timestamp: chrono::Utc::now(),
            pre_permissions_hash: String::new(),
            post_permissions_hash: String::new(),
            exposure_transition: ExposureTransition {
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

    /// **The bound that keeps this off the hot path.** A clean session has no
    /// adversarial node, so the answer is `Allow` by construction and the
    /// O(nodes) snapshot would buy nothing. Skipping is not an optimisation
    /// that loses information; there is no information there.
    #[test]
    fn a_clean_session_is_not_cross_checked() {
        let mut flow = FlowTracker::new();
        flow.observe(NodeKind::UserPrompt).expect("observe");
        assert!(
            cross_check_flow(&flow, &decision_with(Verdict::Allow), Operation::WebFetch).is_none(),
            "an untainted session should not pay for a check whose answer is fixed"
        );
    }

    /// **The finding this exists to produce.** An allow on a tainted session,
    /// heading for an exfil sink, is exactly what the causal graph should
    /// refuse to confirm.
    #[test]
    fn an_allow_on_a_tainted_exfil_path_is_not_confirmed() {
        let mut flow = FlowTracker::new();
        flow.observe(NodeKind::WebContent).expect("observe");

        let result = cross_check_flow(&flow, &decision_with(Verdict::Allow), Operation::WebFetch)
            .expect("a tainted session must be checked");
        assert!(
            matches!(
                result,
                FlowCrossCheck::Checked(VerificationResult::Mismatch { .. })
            ),
            "the graph should refuse to confirm this Allow; got {result:?}"
        );
    }

    /// The complement: an IFC refusal on the same session IS confirmed, so the
    /// check is not simply reporting Mismatch for everything tainted.
    #[test]
    fn an_ifc_refusal_on_the_same_session_is_confirmed() {
        let mut flow = FlowTracker::new();
        flow.observe(NodeKind::WebContent).expect("observe");

        let denied = decision_with(Verdict::Deny(DenyReason::IfcUnsafe {
            detail: "lethal trifecta".to_string(),
        }));
        assert_eq!(
            cross_check_flow(&flow, &denied, Operation::WebFetch),
            Some(FlowCrossCheck::Checked(VerificationResult::Confirmed)),
            "the graph agrees this should be denied; the check must say so"
        );
    }

    /// A capability refusal is not a flow refusal. Conflating them would make
    /// every budget or path denial look like an IFC finding, which is how a
    /// real signal gets ignored.
    #[test]
    fn a_capability_refusal_is_judged_on_the_flow_axis_only() {
        let mut flow = FlowTracker::new();
        flow.observe(NodeKind::UserPrompt).expect("observe");
        flow.observe(NodeKind::WebContent).expect("observe");

        // Same session, same operation: a non-IFC denial must be treated as
        // "flow was fine, something else stopped it" — i.e. compared against
        // Allow, exactly as the Allow case above.
        let cap_denied = decision_with(Verdict::Deny(DenyReason::InsufficientCapability));
        let allowed = decision_with(Verdict::Allow);
        assert_eq!(
            cross_check_flow(&flow, &cap_denied, Operation::WebFetch),
            cross_check_flow(&flow, &allowed, Operation::WebFetch),
            "a capability refusal must not be scored differently on the flow axis"
        );
    }

    /// **No silent caps.** Above the ceiling the check does not run — and must
    /// say so distinctly, because "we did not look" read as "we looked and it
    /// was fine" is the worst possible reading of an evidence field.
    #[test]
    fn an_oversized_graph_is_skipped_visibly_not_silently() {
        let mut flow = FlowTracker::new();
        flow.observe(NodeKind::WebContent).expect("observe");
        while flow.node_count() <= MAX_CROSS_CHECK_NODES {
            flow.observe(NodeKind::UserPrompt).expect("observe");
        }

        let result = cross_check_flow(&flow, &decision_with(Verdict::Allow), Operation::WebFetch)
            .expect("an oversized graph must still report something");
        assert_eq!(
            result,
            FlowCrossCheck::SkippedGraphTooLarge,
            "the skip must be distinguishable from a confirmation"
        );
        assert_ne!(
            result,
            FlowCrossCheck::Checked(VerificationResult::Confirmed),
            "a skipped check must never read as confirmed"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Independent re-derivation of the flow verdict (the ZkFlowInput producer)
// ═══════════════════════════════════════════════════════════════════════════

/// Cross-check the kernel's IFC verdict against the session's causal DAG.
///
/// # What this is
///
/// `verify_noninterference` walks the DAG, propagates labels from parents to
/// children, and evaluates `check_flow` on the action node. Until now it had a
/// zkVM guest, a CLI subcommand, and **no producer** — it only ever ran on
/// hand-written fixtures. This is the producer, and it makes the function a live
/// second opinion: the kernel decides, and an independent evaluator over the
/// graph says whether the graph implies the same thing.
///
/// A `Mismatch` is a real finding either way round. The kernel allowed something
/// the causal graph says it should not have, or refused something the graph does
/// not justify.
///
/// # Only the IFC axis
///
/// The kernel's `Verdict` covers capabilities, budget, approval and flow. Only
/// the last is comparable to a `FlowVerdict`, so a capability refusal maps to
/// `FlowVerdict::Allow` here — the flow was fine, something else stopped it.
/// Conflating the two would make every budget denial look like an IFC finding.
///
/// # Measured cost, and why there is a ceiling
///
/// The check is O(nodes): it snapshots the DAG and re-walks it. Measured on this
/// machine (release, 100 iterations per point):
///
/// | nodes  | per decision |
/// |--------|--------------|
/// | 10     | 460 ns       |
/// | 100    | 3.1 µs       |
/// | 1 000  | 33 µs        |
/// | 10 000 | 458 µs       |
///
/// Half a millisecond per decision on a long-lived session is not a cost to take
/// silently, so above [`MAX_CROSS_CHECK_NODES`] the check is SKIPPED and says so
/// — `skipped:graph_too_large`, which is neither a confirmation nor a finding.
/// Truncating the graph instead was rejected: a smaller graph can confirm a
/// verdict the full graph would refuse, which is a false assurance rather than a
/// slower one.
///
/// # Why only on tainted sessions
///
/// On a session with no adversarial node the action has no parents, its label is
/// the intrinsic label of an outbound action, and the answer is `Allow` by
/// construction — confirming it costs an O(nodes) snapshot to learn nothing.
/// The check runs where its answer can differ.
/// Graph size above which the cross-check is skipped rather than paid for.
/// ~135 µs per decision at this size, by the measurement in
/// [`cross_check_flow`].
pub(crate) const MAX_CROSS_CHECK_NODES: usize = 4096;

/// Outcome of the cross-check, including the reasons it did not run.
///
/// A three-way answer rather than `Option<VerificationResult>` so that "we did
/// not look" can never be read as "we looked and it was fine".
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FlowCrossCheck {
    /// The DAG was consulted; this is what it said.
    Checked(nucleus::portcullis::flow::VerificationResult),
    /// The graph exceeded [`MAX_CROSS_CHECK_NODES`].
    SkippedGraphTooLarge,
}

pub(crate) fn cross_check_flow(
    flow: &FlowTracker,
    decision: &Decision,
    operation: Operation,
) -> Option<FlowCrossCheck> {
    use nucleus::portcullis::flow::{FlowVerdict, ZkFlowInput};

    if !flow.is_tainted() {
        return None;
    }
    if flow.node_count() > MAX_CROSS_CHECK_NODES {
        return Some(FlowCrossCheck::SkippedGraphTooLarge);
    }

    // The kernel's verdict, projected onto the flow axis.
    let expected = match &decision.verdict {
        Verdict::Deny(DenyReason::IfcUnsafe { .. }) => {
            // The DAG must agree that SOMETHING is denied; which reason the two
            // paths name is not required to match, since the kernel's detail
            // string and `FlowDenyReason` are different vocabularies.
            None
        }
        _ => Some(FlowVerdict::Allow),
    };

    let parents: Vec<u64> = flow.latest_adversarial_node().into_iter().collect();
    let input = ZkFlowInput::for_action(
        flow.snapshot(),
        operation,
        Some(nucleus::portcullis::default_sink_class(operation)),
        &parents,
        expected.unwrap_or(FlowVerdict::Allow),
    );

    let result = nucleus::portcullis::flow::verify_noninterference(&input);

    match (&expected, &result) {
        // Kernel said IFC-deny and the graph agrees it is not an Allow.
        (
            None,
            nucleus::portcullis::flow::VerificationResult::Mismatch {
                computed: FlowVerdict::Deny(_),
                ..
            },
        ) => Some(FlowCrossCheck::Checked(
            nucleus::portcullis::flow::VerificationResult::Confirmed,
        )),
        _ => Some(FlowCrossCheck::Checked(result)),
    }
}
