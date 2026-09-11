//! Mapping kernel refusals onto the HTTP error surface.
//!
//! Extracted from `main.rs` to stay under the line ratchet, and because this is
//! a coherent unit on its own: it is the one place that decides how a kernel
//! `DenyReason` is described to a caller. The match is deliberately EXHAUSTIVE —
//! a new refusal reason must be given a surfacing here before it can compile,
//! rather than silently becoming a generic capability error.

use nucleus::portcullis::grant_usage::operation_name;
use nucleus::portcullis::kernel::DenyReason;
use nucleus::portcullis::{CapabilityLevel, Operation};

use nucleus::NucleusError;
use nucleus::portcullis::action_term::ActionTerm;
use nucleus::portcullis::flow_graph::FlowGraph;
use nucleus::portcullis::kernel::{Decision, DecisionToken, Kernel, Verdict};
use nucleus::portcullis::verdict_sink::{ActorIdentity, VerdictSink};
use tracing::{info, warn};

use crate::ApiError;

/// Whether a human approval is already on file for an operation key.
///
/// The kernel can return [`Verdict::RequiresApproval`], which is a deferral to a
/// person, not a refusal. Something has to answer "did that person answer yet",
/// and in the proxy that answer lives in the `ApprovalRegistry` that
/// `/v1/approve` writes to. This trait is how the reference monitor asks,
/// without `mediation` having to know about `AppState` — the module stays
/// unit-testable against a bare `Kernel` + `FlowGraph`, which is why
/// `decide_with_flow_mapped` was split out in the first place.
///
/// The method PEEKS. See `ApprovalRegistry::is_granted` for why the spend
/// belongs to the last gate rather than this one.
pub(crate) trait ApprovalGrants {
    /// Whether a live, unexpired grant exists for this operation key.
    fn is_granted(&self, operation: &str) -> bool;
}

/// No approvals are on file. What every mediation test uses unless it is
/// testing approval; production always has the real `ApprovalRegistry`, so this
/// is `cfg(test)` rather than a default a handler could reach for by accident.
#[cfg(test)]
pub(crate) struct NoGrants;

#[cfg(test)]
impl ApprovalGrants for NoGrants {
    fn is_granted(&self, _operation: &str) -> bool {
        false
    }
}

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
        // The lattice says WHICH restriction refused this. "blocked by the path
        // lattice" names a layer, and the three things that layer can mean have
        // three different fixes -- a reader who is told only the layer goes and
        // inspects the blocklist even when the blocklist was not involved.
        //
        // `PathDenial`'s own rendering is what reaches the caller, and it
        // deliberately withholds the sandbox root while naming a matched glob:
        // the guest can map the blocklist by probing paths regardless, but it
        // cannot otherwise learn host layout.
        DenyReason::PathBlocked { path, denial } => ApiError::Nucleus(NucleusError::PathDenied {
            path: std::path::PathBuf::from(path),
            reason: denial
                .map(|d| d.to_string())
                .unwrap_or_else(|| "blocked by the path lattice".to_string()),
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
            // `{other:?}` used to reach the wire here, so sixteen of nineteen
            // refusals arrived as Rust struct literals —
            // `EgressBlocked { host: "api.github.com", policy_reason: "not in
            // allowlist" }` — while a hand-written sentence for every one of
            // them already existed in the same workspace crate and was
            // reachable only after the run had ended. One producer now
            // (`DenyReason::describe`), and the operation is passed because
            // this call site has it.
            ApiError::KernelDenied(format!(
                "{} (operation {} on {subject})",
                other.describe(Some(operation)),
                operation_name(operation)
            ))
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
    grants: &dyn ApprovalGrants,
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
            // The operation key is the string the registry is keyed on, and it
            // is also what the caller is handed back and feeds to `/v1/approve`
            // verbatim. One spelling, built once, so the layer that asks and the
            // layer that answers cannot disagree about what was approved.
            let key = format!("{operation:?} {subject}");
            if grants.is_granted(&key) {
                // A person already answered this deferral. Issuing the token is
                // the whole point of `Kernel::issue_approved_token`, which
                // exists for exactly this shape — `decide()` said
                // `RequiresApproval`, an external mechanism authorized it, and
                // the caller needs a token for the sandbox I/O that follows.
                // Re-running `decide()` would double-count the operation in the
                // exposure accumulator; this does not.
                //
                // This is NOT a widening path. The kernel already decided the
                // operation is one a person MAY authorize; nothing here can turn
                // a `Deny` into an allow, and with no grant on file the arm
                // below refuses exactly as before. The grant is not spent here
                // (see `ApprovalRegistry::is_granted`) — the sandbox approver
                // spends it, once.
                info!(
                    ?operation,
                    subject,
                    exposure = decision.exposure_transition.post_count,
                    "HTTP kernel required approval and a human grant is on file; \
                     issuing an approved token (#2406)"
                );
                Ok(kernel.issue_approved_token(operation, subject))
            } else {
                info!(
                    ?operation,
                    subject,
                    exposure = decision.exposure_transition.post_count,
                    "HTTP kernel requires approval and no grant is on file"
                );
                // `approval_required`, which the response mapping already
                // models. The caller is told which operation to approve, and
                // presenting one through `/v1/approve` now satisfies this layer
                // — which it did not before #2406 was fixed: this decision
                // returned before `sandbox.write`, so it never reached the only
                // code that consulted grants, and an operator who approved got
                // a 200 and no effect.
                Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                    operation: key,
                }))
            }
        }
    };
    (decision, mapped)
}

/// Everything a decision is recorded and resolved *in*, as opposed to what it
/// is *about*.
///
/// Grouped because these four travel together and are set once per transport:
/// the sink the verdict is written to, the actor it is attributed to, the
/// transport it arrived on, and the approvals already on file. Keeping them
/// apart from `(operation, subject)` also keeps the two halves of a call site
/// readable — which of eight positional arguments was the subject was not.
pub(crate) struct MediationEnv<'a> {
    /// Where the verdict is recorded. Never optional: a refusal with no
    /// evidence is the defect `decide_and_record` exists to prevent.
    pub sink: &'a dyn VerdictSink,
    /// Who the decision is attributed to.
    pub actor: ActorIdentity,
    /// Which surface the request arrived on (`"http"`, `"mcp"`).
    pub transport: &'a str,
    /// Approvals a person has already given.
    pub grants: &'a dyn ApprovalGrants,
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
    env: MediationEnv<'_>,
    kernel: &mut Kernel,
    graph: &FlowGraph,
    operation: Operation,
    subject: &str,
) -> Result<DecisionToken, ApiError> {
    let MediationEnv {
        sink,
        actor,
        transport,
        grants,
    } = env;
    // The live egress verdict is read from the single authoritative `FlowGraph`
    // (Phase 2 retirement: the retained `FlowTracker` oracle and its divergence
    // canary are gone — there is one graph now, so there is nothing left to
    // diverge from). The graph's `is_poisoned` / `is_tainted` /
    // `session_exfiltration_check` aggregates carry the lethal-trifecta taint, and
    // on absence/error the kernel path denies fail-closed.
    let (decision, mapped) = decide_with_flow_mapped(kernel, graph, operation, subject, grants);

    crate::verdict_sink::record_kernel_decision(
        sink,
        &decision,
        operation,
        subject,
        actor.clone(),
        transport,
    );

    // A deferral that a human grant satisfied is TWO governance events, and the
    // record has to carry both: the system escalated to a person (recorded just
    // above as `RequiresApproval`, the Article 14 evidence), and then it went
    // ahead. Recording only the first would leave an evidence log in which
    // approved operations look pending forever; recording only the second would
    // erase that a person was ever consulted.
    if matches!(decision.verdict, Verdict::RequiresApproval) && mapped.is_ok() {
        use nucleus::portcullis::verdict_sink::{VerdictContext, VerdictOutcome};
        use std::collections::BTreeMap;
        let mut extensions = BTreeMap::new();
        extensions.insert("transport".to_string(), transport.to_string());
        extensions.insert(
            "satisfied_by".to_string(),
            "human_approval_grant".to_string(),
        );
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: subject.to_string(),
            outcome: VerdictOutcome::Allow,
            actor,
            policy_rule: None,
            extensions,
        }) {
            warn!(error = %e, ?operation, subject,
                  "verdict recording failed for an approved deferral -- audit gap");
        }
    }

    mapped
}
