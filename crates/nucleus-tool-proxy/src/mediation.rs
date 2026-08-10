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
use nucleus::portcullis::flow_graph::FlowGraph;
use nucleus::portcullis::kernel::{Decision, DecisionToken, Kernel, Verdict};
use nucleus::portcullis::verdict_sink::{ActorIdentity, VerdictSink};
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
/// so it is unit-testable with a bare [`Kernel`] + [`FlowGraph`] (no `AppState`).
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
    graph: &FlowGraph,
    operation: Operation,
    subject: &str,
) -> (Decision, Result<DecisionToken, ApiError>) {
    let term = ActionTerm::from_operation(operation, subject);
    // The single authoritative `FlowGraph` backs the egress verdict (its
    // `is_poisoned` / `is_tainted` / `session_exfiltration_check` aggregates carry
    // the lethal-trifecta taint). The `FlowTracker` oracle it was cross-checked
    // against during the Phase 2 cutover has been retired.
    let (decision, token) = kernel.decide_term_with_flow(term, Some(graph));
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
pub(crate) fn decide_and_record(
    sink: &dyn VerdictSink,
    kernel: &mut Kernel,
    graph: &FlowGraph,
    operation: Operation,
    subject: &str,
    actor: ActorIdentity,
    transport: &str,
) -> Result<DecisionToken, ApiError> {
    // The live egress verdict is read from the single authoritative `FlowGraph`
    // (Phase 2 retirement: the retained `FlowTracker` oracle and its divergence
    // canary are gone — there is one graph now, so there is nothing left to
    // diverge from). The graph's `is_poisoned` / `is_tainted` /
    // `session_exfiltration_check` aggregates carry the lethal-trifecta taint, and
    // on absence/error the kernel path denies fail-closed.
    let (decision, mapped) = decide_with_flow_mapped(kernel, graph, operation, subject);

    crate::verdict_sink::record_kernel_decision(
        sink, &decision, operation, subject, actor, transport,
    );

    mapped
}
