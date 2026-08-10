//! Pure decision kernel for exposure-based guard logic.
//!
//! These functions contain the core decision logic extracted from
//! [`GradedExposureGuard`](crate::guard::GradedExposureGuard) as pure,
//! side-effect-free functions. No `RwLock`, no `sha2`, no I/O — just
//! the boolean decision math.
//!
//! ## Verified Shared Core
//!
//! The Kani proofs in `kani.rs` verify executable spec
//! functions (`exec_guard_check`, `exec_apply_event`, etc.) that are
//! structurally identical to these production functions. The CI
//! conformance tests in `verus_conformance.rs` exhaustively verify
//! that these production functions agree with the Verus exec functions
//! on all inputs — establishing a structural bisimulation between the
//! verified model and the production code.
//!
//! This is the closest we can get to seL4-style refinement without
//! running the full portcullis dependency tree through Verus's modified
//! rustc (which doesn't support `sha2`, `ring`, `regex`, etc.).

use crate::capability::Operation;
use crate::guard::{ExposureLabel, ExposureSet};
use portcullis_core::flow::NodeKind;
use portcullis_core::ifc_api::{FlowTracker, SafetyCheck};
use portcullis_core::ConfLevel;

/// The three session aggregates the live egress gate consults.
///
/// Implemented by BOTH the legacy [`FlowTracker`] and the proven
/// [`FlowGraph`](crate::flow_graph::FlowGraph) so [`ifc_egress_verdict`] is ONE
/// gate reading whichever graph the caller supplies — never a second copy of the
/// rule that could drift (the exact failure mode the "two aligned graphs"
/// approach carries, and the reason this migration collapses onto one graph).
///
/// Fail-closed by construction: every method returns a conservative,
/// deny-biasing answer, and the gate treats poison and taint as denials. The
/// tool-proxy reads the [`FlowGraph`](crate::flow_graph::FlowGraph) through this
/// trait for its live verdict (Phase 2) while retaining the [`FlowTracker`] as a
/// dual-written oracle for the divergence canary.
pub trait EgressAggregates {
    /// A dropped observation ⇒ taint state unprovable ⇒ deny everything (#3).
    fn is_poisoned(&self) -> bool;
    /// `true` if any observation in this session carried adversarial integrity.
    fn is_tainted(&self) -> bool;
    /// Session confidentiality-ceiling downflow check for an outbound sink (#4).
    fn session_exfiltration_check(&self, sink_max_conf: ConfLevel) -> SafetyCheck;

    /// Scope-aware integrity taint for a specific operation (Phase 4.5). Defaults
    /// to the operation-agnostic [`is_tainted`](Self::is_tainted), so an
    /// implementor with no per-node scopes (e.g. `FlowTracker`) is byte-identical
    /// to the historical gate. `FlowGraph` overrides it to honor per-node declass
    /// scopes, refining the answer DOWNWARD only under full node visibility.
    fn effective_is_tainted(&self, _op: Operation) -> bool {
        self.is_tainted()
    }

    /// Scope-aware confidentiality downflow check for a specific operation
    /// (Phase 4.5). Defaults to the operation-agnostic
    /// [`session_exfiltration_check`](Self::session_exfiltration_check), so an
    /// implementor with no per-node scopes is byte-identical to the historical
    /// gate. `FlowGraph` overrides it to honor per-node declass scopes.
    fn effective_exfiltration_check(&self, _op: Operation, cap: ConfLevel) -> SafetyCheck {
        self.session_exfiltration_check(cap)
    }
}

impl EgressAggregates for FlowTracker {
    #[inline]
    fn is_poisoned(&self) -> bool {
        FlowTracker::is_poisoned(self)
    }
    #[inline]
    fn is_tainted(&self) -> bool {
        FlowTracker::is_tainted(self)
    }
    #[inline]
    fn session_exfiltration_check(&self, sink_max_conf: ConfLevel) -> SafetyCheck {
        FlowTracker::session_exfiltration_check(self, sink_max_conf)
    }
}

impl EgressAggregates for crate::flow_graph::FlowGraph {
    #[inline]
    fn is_poisoned(&self) -> bool {
        crate::flow_graph::FlowGraph::is_poisoned(self)
    }
    #[inline]
    fn is_tainted(&self) -> bool {
        crate::flow_graph::FlowGraph::is_tainted(self)
    }
    #[inline]
    fn session_exfiltration_check(&self, sink_max_conf: ConfLevel) -> SafetyCheck {
        crate::flow_graph::FlowGraph::session_exfiltration_check(self, sink_max_conf)
    }
    #[inline]
    fn effective_is_tainted(&self, op: Operation) -> bool {
        crate::flow_graph::FlowGraph::effective_is_tainted(self, op)
    }
    #[inline]
    fn effective_exfiltration_check(&self, op: Operation, cap: ConfLevel) -> SafetyCheck {
        crate::flow_graph::FlowGraph::effective_exfiltration_check(self, op, cap)
    }
}

/// Classify an operation into its exposure label.
///
/// Pure mirror of [`operation_exposure`](crate::guard::operation_exposure).
/// Maps each operation to the exposure leg it contributes to.
///
/// Verus equivalent: `operation_exposure_label(op: nat) -> nat`
///   - 0 = PrivateData, 1 = UntrustedContent, 2 = ExfilVector, 3 = Neutral
#[inline]
pub fn classify_operation(op: Operation) -> Option<ExposureLabel> {
    match op {
        // Leg 1: Private data access
        Operation::ReadFiles | Operation::GlobSearch | Operation::GrepSearch => {
            Some(ExposureLabel::PrivateData)
        }
        // Leg 2: Untrusted content ingestion
        Operation::WebFetch | Operation::WebSearch => Some(ExposureLabel::UntrustedContent),
        // Leg 3: Exfiltration vectors. Local sinks (WriteFiles/EditFiles/
        // GitCommit/ManagePods) ARE exfil legs (most-paranoid #4): a tainted
        // secret written to a file or committed is an exfiltration channel, so
        // they complete the uninhabitable trifecta rather than being "neutral".
        Operation::RunBash
        | Operation::GitPush
        | Operation::CreatePr
        | Operation::SpawnAgent
        | Operation::WriteFiles
        | Operation::EditFiles
        | Operation::GitCommit
        | Operation::ManagePods => Some(ExposureLabel::ExfilVector),
    }
}

/// Whether an operation is an exfiltration vector (single source of truth).
///
/// Mirrors the `ExfilVector` arm of [`classify_operation`]; used by the kernel
/// uninhabitable-state gate (most-paranoid #4).
#[inline]
pub fn is_exfil_operation(op: Operation) -> bool {
    matches!(classify_operation(op), Some(ExposureLabel::ExfilVector))
}

/// The maximum confidentiality an operation's sink may emit (most-paranoid #4).
///
/// True egress operations (data crosses the trust boundary) cap at `Internal`,
/// so a `Secret`-confidentiality session is blocked from them. Local operations
/// cap at `Secret` (data stays in the sandbox — no confidentiality restriction).
/// Calibrated so that, since env-vars/secrets carry `Secret` confidentiality, a
/// secret-bearing session can still write/edit/commit locally but cannot push,
/// open a PR, spawn an agent, or manage pods.
#[inline]
pub fn sink_max_conf_for(op: Operation) -> ConfLevel {
    match op {
        Operation::GitPush
        | Operation::CreatePr
        | Operation::SpawnAgent
        | Operation::ManagePods
        // WebFetch/WebSearch send an agent-chosen URL to an external server, and
        // a URL carries a query string. That is data crossing the trust boundary
        // — the exact criterion this function's own docstring states — so their
        // omission left the check inert: `ConfLevel` tops out at `Secret`, so a
        // `Secret` cap can never be exceeded and `session_exfiltration_check`
        // could never fire for them.
        | Operation::WebFetch
        | Operation::WebSearch => ConfLevel::Internal,
        _ => ConfLevel::Secret,
    }
}

/// Three-way outcome of the egress gate.
///
/// `ifc_egress_denial` returns `Option<String>` and so can only say deny-or-not.
/// Grading needs a third answer, because the whole point is that a refusal at a
/// cheap sink should become a question for a human rather than a dead end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressVerdict {
    /// The gate has nothing to say; fall through to the normal decision path.
    Pass,
    /// Refuse.
    Deny(String),
    /// Defer to a human. Only ever produced when grading is enabled.
    RequireApproval(String),
}

/// The egress gate, with the taint response optionally graded by sink
/// consequence (Option C).
///
/// `graded = false` reproduces the historical behaviour EXACTLY: any integrity
/// taint denies every outbound action. That is the default, so enabling the
/// grading is a config change and disabling it is a config rollback — the one
/// change here that can let through something previously refused stays a flag
/// flip, not a redeploy.
///
/// `graded = true` keeps the DETECTION identical (the session ceiling still
/// decides whether taint is present — no lineage, no trusting the agent's
/// account of its own data flow) and grades only the RESPONSE, via
/// [`graded_taint_response`]. Measured over the sink-consequence corpus: of the
/// refusals caused purely by taint, expensive sinks stay denied, pod-local
/// reversible ones become approvable, and nothing is silently permitted.
///
/// The confidentiality check is NOT graded. A session holding secrets must not
/// emit them regardless of how cheap the sink looks, and unlike integrity there
/// is no "the session already lost this" argument to make.
pub fn ifc_egress_verdict<F: EgressAggregates + ?Sized>(
    flow: &F,
    op: Operation,
    kind: NodeKind,
    graded: bool,
) -> EgressVerdict {
    let is_outbound_action = kind == NodeKind::OutboundAction;
    let carries_data_out =
        is_outbound_action || crate::capability::default_sink_class(op).is_exfil_vector();
    if !carries_data_out {
        return EgressVerdict::Pass;
    }

    if is_outbound_action && flow.effective_is_tainted(op) {
        let detail = format!(
            "session carries adversarial integrity (untrusted/web content was \
             observed); outbound operation {op:?} blocked to prevent exfiltration \
             of, or action on, injected content"
        );
        if !graded {
            return EgressVerdict::Deny(detail);
        }
        match graded_taint_response(op) {
            TaintResponse::Deny => return EgressVerdict::Deny(detail),
            TaintResponse::RequireApproval => {
                return EgressVerdict::RequireApproval(format!(
                    "{detail}; sink is pod-local and reversible, so this is \
                     deferred for human approval rather than refused"
                ))
            }
            // Fall through to the confidentiality check — an Allow here means
            // "integrity does not block this", never "nothing else might".
            TaintResponse::Allow => {}
        }
    }

    if flow
        .effective_exfiltration_check(op, sink_max_conf_for(op))
        .is_denied()
    {
        return EgressVerdict::Deny(format!(
            "session confidentiality ceiling exceeds what {op:?} may emit; \
             outbound operation blocked to prevent secret exfiltration"
        ));
    }
    EgressVerdict::Pass
}

/// Clock-free IFC egress denial check for the live kernel gate (most-paranoid
/// #1/#4). Returns `Some(detail)` when an outbound operation must be denied:
/// either the session is integrity-tainted (adversarial content observed) or its
/// confidentiality ceiling exceeds what the sink may emit (secret exfiltration).
/// `None` ⇒ the gate falls through to the normal decision path.
pub fn ifc_egress_denial<F: EgressAggregates + ?Sized>(
    flow: &F,
    op: Operation,
    kind: NodeKind,
) -> Option<String> {
    // Delegates rather than duplicating: two copies of an enforcement rule are
    // two things that can drift, and this one has already drifted once (the
    // web-egress bypass). `graded = false` is the historical behaviour.
    match ifc_egress_verdict(flow, op, kind, false) {
        EgressVerdict::Deny(d) => Some(d),
        // Unreachable with `graded = false`, but mapped to a denial rather than
        // to `None` so that a future edit which starts producing it here fails
        // closed instead of silently permitting.
        EgressVerdict::RequireApproval(d) => Some(d),
        EgressVerdict::Pass => None,
    }
}

/// Project what the exposure set WOULD be if this operation executes.
///
/// RunBash is treated as **omnibus**: it conservatively projects both
/// `PrivateData` and `ExfilVector` because bash can read arbitrary
/// files (`cat /etc/passwd`) AND exfiltrate data (`curl`).
///
/// Verus equivalent: the projection arm of `guard_would_deny(obs, exposure, op)`
#[inline]
pub fn project_exposure(current: &ExposureSet, operation: Operation) -> ExposureSet {
    if operation == Operation::RunBash {
        // RunBash is omnibus: projects PrivateData + ExfilVector
        current
            .union(&ExposureSet::singleton(ExposureLabel::PrivateData))
            .union(&ExposureSet::singleton(ExposureLabel::ExfilVector))
    } else if let Some(label) = classify_operation(operation) {
        current.union(&ExposureSet::singleton(label))
    } else {
        current.clone()
    }
}

/// Pure denial decision: should this operation be denied?
///
/// This is the extracted decision kernel from `GradedExposureGuard::check()`.
/// It returns `true` if the operation should be denied.
///
/// The logic:
///   1. Project exposure (what would the exposure be after this op?)
///   2. If projected exposure is uninhabitable AND the operation
///      requires approval under uninhabitable_state constraint → **deny**
///
/// Verus equivalent: `guard_would_deny(obs, exposure, op) -> bool`
#[inline]
pub fn should_deny(
    current: &ExposureSet,
    operation: Operation,
    requires_approval: bool,
    uninhabitable_constraint: bool,
) -> bool {
    if !uninhabitable_constraint {
        return false;
    }
    let projected = project_exposure(current, operation);
    projected.is_uninhabitable() && requires_approval
}

/// Apply a successful operation's exposure to the accumulator.
///
/// Returns the new exposure set after recording this operation.
/// Only non-neutral operations modify the exposure.
///
/// ## Intentional asymmetry with `project_exposure` for RunBash
///
/// `project_exposure` conservatively adds `{PrivateData, ExfilVector}` for
/// RunBash because bash *can* read files and exfiltrate data. This is the
/// pre-check over-approximation: deny anything that *might* complete the
/// uninhabitable state.
///
/// `apply_record` adds only `ExfilVector` (the actual classification from
/// `classify_operation`), because the post-check records what the operation
/// *actually contributed*, not what it theoretically could have done.
///
/// This asymmetry is by design (Trail of Bits finding #2):
/// - **Pre-check (project_exposure)**: conservative for safety — blocks
///   operations that *could* complete the uninhabitable state.
/// - **Post-check (apply_record)**: precise for accuracy — records the
///   actual exposure leg so that subsequent pre-checks start from an
///   accurate baseline rather than an inflated one.
///
/// If `apply_record` used the omnibus projection, a single RunBash call
/// would inflate the exposure to `{PrivateData, ExfilVector}` even if
/// the command was `echo hello`. This would make subsequent web_fetch
/// calls trigger uninhabitable_state warnings incorrectly.
///
/// Verus equivalent: `apply_event_exposure(exposure, McpEvent{op, succeeded: true})`
#[inline]
pub fn apply_record(current: &ExposureSet, operation: Operation) -> ExposureSet {
    if let Some(label) = classify_operation(operation) {
        current.union(&ExposureSet::singleton(label))
    } else {
        current.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tainted_mcp_tool_result_blocks_privileged_action() {
        // most-paranoid #2: a tainted (adversarial) MCP tool result must block a
        // subsequent privileged outbound action via the live egress gate.
        use portcullis_core::flow::NodeKind;
        use portcullis_core::ifc_api::FlowTracker;
        let mut flow = FlowTracker::new();
        flow.observe(NodeKind::McpToolResult).unwrap();
        assert!(
            ifc_egress_denial(&flow, Operation::GitPush, NodeKind::OutboundAction).is_some(),
            "tainted tool result must block git push"
        );
        assert!(
            ifc_egress_denial(&flow, Operation::RunBash, NodeKind::OutboundAction).is_some(),
            "tainted tool result must block a subsequent run"
        );
        // Negative control (honest scoping): WebFetch is classified as a SOURCE
        // (WebContent), not a gated sink, so taint does not block it — web egress
        // is governed by the DNS/URL allowlist instead.
        assert!(
            ifc_egress_denial(&flow, Operation::WebFetch, NodeKind::WebContent).is_none(),
            "web_fetch is a source, not a taint-gated sink"
        );
    }

    #[test]
    fn test_classify_operation_coverage() {
        // Every operation variant maps to something
        let ops = [
            (Operation::ReadFiles, Some(ExposureLabel::PrivateData)),
            // Local sinks are now exfil legs (most-paranoid #4).
            (Operation::WriteFiles, Some(ExposureLabel::ExfilVector)),
            (Operation::EditFiles, Some(ExposureLabel::ExfilVector)),
            (Operation::RunBash, Some(ExposureLabel::ExfilVector)),
            (Operation::GlobSearch, Some(ExposureLabel::PrivateData)),
            (Operation::GrepSearch, Some(ExposureLabel::PrivateData)),
            (Operation::WebSearch, Some(ExposureLabel::UntrustedContent)),
            (Operation::WebFetch, Some(ExposureLabel::UntrustedContent)),
            (Operation::GitCommit, Some(ExposureLabel::ExfilVector)),
            (Operation::GitPush, Some(ExposureLabel::ExfilVector)),
            (Operation::CreatePr, Some(ExposureLabel::ExfilVector)),
            (Operation::ManagePods, Some(ExposureLabel::ExfilVector)),
            (Operation::SpawnAgent, Some(ExposureLabel::ExfilVector)),
        ];
        for (op, expected) in ops {
            assert_eq!(classify_operation(op), expected, "mismatch for {:?}", op);
        }
    }

    #[test]
    fn test_project_exposure_runbash_omnibus() {
        let empty = ExposureSet::empty();
        let projected = project_exposure(&empty, Operation::RunBash);
        assert!(projected.contains(ExposureLabel::PrivateData));
        assert!(projected.contains(ExposureLabel::ExfilVector));
        assert!(!projected.contains(ExposureLabel::UntrustedContent));
    }

    #[test]
    fn test_project_exposure_normal_op() {
        let empty = ExposureSet::empty();
        let projected = project_exposure(&empty, Operation::ReadFiles);
        assert!(projected.contains(ExposureLabel::PrivateData));
        assert!(!projected.contains(ExposureLabel::UntrustedContent));
        assert!(!projected.contains(ExposureLabel::ExfilVector));
    }

    #[test]
    fn test_project_exposure_write_is_exfil() {
        // WriteFiles is now an exfil leg (most-paranoid #4): projecting it onto a
        // PrivateData session adds ExfilVector.
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData);
        let projected = project_exposure(&exposure, Operation::WriteFiles);
        assert!(projected.contains(ExposureLabel::PrivateData));
        assert!(projected.contains(ExposureLabel::ExfilVector));
    }

    #[test]
    fn test_should_deny_uninhabitable_complete() {
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        // GitPush would complete the uninhabitable_state
        assert!(should_deny(&exposure, Operation::GitPush, true, true));
    }

    #[test]
    fn test_should_deny_no_approval() {
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        // Even if uninhabitable_state would complete, no approval required → allow
        assert!(!should_deny(&exposure, Operation::GitPush, false, true));
    }

    #[test]
    fn test_should_deny_constraint_disabled() {
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        //  UninhabitableState constraint disabled → always allow
        assert!(!should_deny(&exposure, Operation::GitPush, true, false));
    }

    #[test]
    fn test_apply_record_does_not_omnibus() {
        let empty = ExposureSet::empty();
        let recorded = apply_record(&empty, Operation::RunBash);
        // Record only adds ExfilVector, NOT the omnibus PrivateData
        assert!(recorded.contains(ExposureLabel::ExfilVector));
        assert!(!recorded.contains(ExposureLabel::PrivateData));
    }

    #[test]
    fn test_apply_record_write_is_exfil() {
        // WriteFiles records an ExfilVector leg now (most-paranoid #4).
        let exposure = ExposureSet::singleton(ExposureLabel::PrivateData);
        let recorded = apply_record(&exposure, Operation::WriteFiles);
        assert!(recorded.contains(ExposureLabel::PrivateData));
        assert!(recorded.contains(ExposureLabel::ExfilVector));
    }

    // ════════════════════════════════════════════════════════════════════
    // Core ↔ Production conformance tests
    //
    // The portcullis-core crate defines independent ExposureLabel,
    // ExposureSet, and classification functions for Aeneas translation.
    // These tests verify the core types agree with the production types
    // on all inputs — establishing structural bisimulation.
    // ════════════════════════════════════════════════════════════════════

    /// Translate a core ExposureLabel to a production ExposureLabel.
    fn core_to_prod_label(core: portcullis_core::ExposureLabel) -> ExposureLabel {
        match core {
            portcullis_core::ExposureLabel::PrivateData => ExposureLabel::PrivateData,
            portcullis_core::ExposureLabel::UntrustedContent => ExposureLabel::UntrustedContent,
            portcullis_core::ExposureLabel::ExfilVector => ExposureLabel::ExfilVector,
        }
    }

    #[test]
    fn conformance_classify_operation_agrees() {
        // Operation is the same type (re-exported from core), so we just
        // verify that core::classify_operation and production classify_operation
        // agree for all 12 operations.
        for op in Operation::ALL {
            let core_result = portcullis_core::classify_operation(op);
            let prod_result = classify_operation(op);

            match (core_result, prod_result) {
                (None, None) => {}
                (Some(core_label), Some(prod_label)) => {
                    assert_eq!(
                        core_to_prod_label(core_label),
                        prod_label,
                        "classify_operation disagrees for {:?}",
                        op
                    );
                }
                _ => panic!(
                    "classify_operation disagrees for {:?}: core={:?}, prod={:?}",
                    op, core_result, prod_result
                ),
            }
        }
    }

    #[test]
    fn conformance_exposure_set_uninhabitable_agrees() {
        // Exhaustively check all 8 combinations of 3 booleans
        let labels = [
            ExposureLabel::PrivateData,
            ExposureLabel::UntrustedContent,
            ExposureLabel::ExfilVector,
        ];
        let core_labels = [
            portcullis_core::ExposureLabel::PrivateData,
            portcullis_core::ExposureLabel::UntrustedContent,
            portcullis_core::ExposureLabel::ExfilVector,
        ];

        for mask in 0u8..8 {
            let mut prod_set = ExposureSet::empty();
            let mut core_set = portcullis_core::ExposureSet::empty();

            for i in 0..3 {
                if mask & (1 << i) != 0 {
                    prod_set = prod_set.union(&ExposureSet::singleton(labels[i]));
                    core_set =
                        core_set.union(&portcullis_core::ExposureSet::singleton(core_labels[i]));
                }
            }

            assert_eq!(
                core_set.is_uninhabitable(),
                prod_set.is_uninhabitable(),
                "is_uninhabitable disagrees for mask={:03b}",
                mask
            );
            assert_eq!(
                core_set.count(),
                prod_set.count(),
                "count disagrees for mask={:03b}",
                mask
            );
        }
    }

    #[test]
    fn conformance_project_exposure_agrees() {
        // For each starting state (8 combos) x each operation (12),
        // verify core and production project_exposure agree.
        let labels = [
            ExposureLabel::PrivateData,
            ExposureLabel::UntrustedContent,
            ExposureLabel::ExfilVector,
        ];
        let core_labels = [
            portcullis_core::ExposureLabel::PrivateData,
            portcullis_core::ExposureLabel::UntrustedContent,
            portcullis_core::ExposureLabel::ExfilVector,
        ];

        for mask in 0u8..8 {
            let mut prod_set = ExposureSet::empty();
            let mut core_set = portcullis_core::ExposureSet::empty();

            for i in 0..3 {
                if mask & (1 << i) != 0 {
                    prod_set = prod_set.union(&ExposureSet::singleton(labels[i]));
                    core_set =
                        core_set.union(&portcullis_core::ExposureSet::singleton(core_labels[i]));
                }
            }

            for op in Operation::ALL {
                let prod_projected = project_exposure(&prod_set, op);
                let core_projected = portcullis_core::project_exposure(&core_set, op);

                // Compare is_uninhabitable (the key safety property)
                // Note: production project_exposure has RunBash omnibus behavior
                // (adds PrivateData + ExfilVector), while core does not.
                // This is intentional — the core models the simple classification.
                // We check count and uninhabitable status rather than exact bit match.
                //
                // For non-RunBash ops, they should agree exactly.
                if op != Operation::RunBash {
                    assert_eq!(
                        core_projected.is_uninhabitable(),
                        prod_projected.is_uninhabitable(),
                        "project_exposure uninhabitable disagrees for mask={:03b}, op={:?}",
                        mask,
                        op
                    );
                }
            }
        }
    }

    #[test]
    fn conformance_should_gate_vs_should_deny() {
        // Core's should_gate and production's should_deny have different
        // signatures (production takes approval/constraint bools).
        // Verify they agree when constraint=true and requires_approval=true
        // for the exfil operations.
        let labels = [
            ExposureLabel::PrivateData,
            ExposureLabel::UntrustedContent,
            ExposureLabel::ExfilVector,
        ];
        let core_labels = [
            portcullis_core::ExposureLabel::PrivateData,
            portcullis_core::ExposureLabel::UntrustedContent,
            portcullis_core::ExposureLabel::ExfilVector,
        ];

        for mask in 0u8..8 {
            let mut prod_set = ExposureSet::empty();
            let mut core_set = portcullis_core::ExposureSet::empty();

            for i in 0..3 {
                if mask & (1 << i) != 0 {
                    prod_set = prod_set.union(&ExposureSet::singleton(labels[i]));
                    core_set =
                        core_set.union(&portcullis_core::ExposureSet::singleton(core_labels[i]));
                }
            }

            // Check non-RunBash exfil operations (GitPush, CreatePr)
            // RunBash diverges intentionally (omnibus in production)
            for op in [Operation::GitPush, Operation::CreatePr] {
                let core_gated = portcullis_core::should_gate(&core_set, op);
                let prod_denied = should_deny(&prod_set, op, true, true);
                assert_eq!(
                    core_gated, prod_denied,
                    "should_gate vs should_deny disagrees for mask={:03b}, op={:?}",
                    mask, op
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Graded taint response (Option C) — NOT YET WIRED
// ═══════════════════════════════════════════════════════════════════════════

/// What a *tainted* session should do about an outbound action, graded by the
/// consequence of the sink it targets.
///
/// Today `ifc_egress_denial` is all-or-nothing: once any adversarial content is
/// observed, every outbound action is denied for the rest of the session. That
/// is sound — it needs no lineage and trusts nobody's declaration — but it was
/// measured to refuse 100% of outbound actions after a single web fetch, and
/// the only escape (`reset_session_ceiling`) has no callers and writes a field
/// the gate never reads.
///
/// This grades the *response* rather than weakening the *detection*. The session
/// ceiling still decides whether taint is present; the sink decides what that
/// costs. Crucially this needs **no derivation edges**: it does not ask whether
/// this action descends from the tainted node, only how expensive the action is.
/// That matters because per-node checks are vacuous while every production flow
/// node is observed with no parents — a per-node gate would pass trivially and
/// silently remove the protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintResponse {
    /// Refuse outright — external, irreversible, or capable of arbitrary egress.
    Deny,
    /// Defer to a human. Where an approval channel exists this is real EU AI Act
    /// Article 14 oversight; where none is configured the caller surfaces it as a
    /// refusal, which is still strictly better than today's opaque block because
    /// it names a path that could exist.
    RequireApproval,
    /// Permit — reads and append-only audit sinks mutate nothing an attacker
    /// benefits from.
    Allow,
}

/// Grade a tainted session's response by sink consequence.
///
/// The tiers below are a POLICY, stated as data so a reader can dispute a row
/// rather than infer it from behaviour. Two rules decided the assignment:
///
/// 1. Anything that can move bytes out of the trust boundary, or that leaves an
///    externally-visible artifact which is hard to retract, is `Deny`. These are
///    `SinkClass::is_exfil_vector` and `requires_verified_derivation` — nucleus's
///    own predicates, not a scheme invented here.
/// 2. `BashExec` is `Deny` despite being neither, because a shell can `curl`.
///    Classifying it by what it *is* rather than what it *can reach* would be the
///    kind of mistake this whole exercise exists to catch.
///
/// Everything else mutates only pod-local, reversible state inside an ephemeral
/// microVM, so it defers to a human rather than failing closed outright.
pub fn graded_taint_response(op: Operation) -> TaintResponse {
    use portcullis_core::SinkClass;

    let sink = portcullis_core::default_sink_class(op);

    // Read-only and append-only: nothing an attacker gains from.
    if matches!(sink, SinkClass::SecretRead | SinkClass::AuditLogAppend) {
        return TaintResponse::Allow;
    }
    // A shell reaches every sink, so it inherits the worst one.
    if matches!(sink, SinkClass::BashExec) {
        return TaintResponse::Deny;
    }
    // External or hard-to-retract.
    if sink.is_exfil_vector() || sink.requires_verified_derivation() {
        return TaintResponse::Deny;
    }
    TaintResponse::RequireApproval
}

#[cfg(test)]
mod graded_taint_tests {
    use super::*;

    /// Every operation must be graded — a new one must not silently land in the
    /// most permissive tier.
    #[test]
    fn every_operation_is_graded() {
        for op in Operation::ALL {
            let _ = graded_taint_response(op);
        }
    }

    /// The load-bearing property: nothing that can move data out, or that leaves
    /// an artifact someone else can see, is ever permitted under taint.
    #[test]
    fn no_exfil_or_irreversible_sink_is_ever_allowed_under_taint() {
        for op in Operation::ALL {
            let sink = portcullis_core::default_sink_class(op);
            if sink.is_exfil_vector() || sink.requires_verified_derivation() {
                assert_eq!(
                    graded_taint_response(op),
                    TaintResponse::Deny,
                    "{op:?} -> {sink:?} is externally visible and must be denied"
                );
            }
        }
    }

    /// A shell is denied even though its sink class is neither an exfil vector
    /// nor hard-to-revoke — it can reach both.
    #[test]
    fn bash_is_denied_despite_a_benign_looking_sink_class() {
        let sink = portcullis_core::default_sink_class(Operation::RunBash);
        assert!(
            !sink.is_exfil_vector() && !sink.requires_verified_derivation(),
            "if BashExec ever becomes exfil/irreversible this test stops proving anything"
        );
        assert_eq!(
            graded_taint_response(Operation::RunBash),
            TaintResponse::Deny
        );
    }

    /// The grading must actually discriminate. If every operation landed in one
    /// tier, this would be the all-or-nothing gate wearing a new type.
    #[test]
    fn the_grading_discriminates() {
        let responses: std::collections::BTreeSet<_> = Operation::ALL
            .iter()
            .map(|op| format!("{:?}", graded_taint_response(*op)))
            .collect();
        assert!(
            responses.len() >= 2,
            "grading collapsed to a single tier: {responses:?}"
        );
    }

    /// Reads stay available: a tainted session that cannot even read is
    /// indistinguishable from a terminated one.
    #[test]
    fn reads_remain_available_under_taint() {
        for op in [
            Operation::ReadFiles,
            Operation::GlobSearch,
            Operation::GrepSearch,
        ] {
            assert_eq!(graded_taint_response(op), TaintResponse::Allow, "{op:?}");
        }
    }
}

#[cfg(test)]
mod web_egress_bypass_tests {
    use super::*;
    use portcullis_core::flow::NodeKind;
    use portcullis_core::ifc_api::FlowTracker;

    /// Adversarial integrity only — the ordinary research session.
    fn tainted() -> FlowTracker {
        let mut f = FlowTracker::new();
        f.observe(NodeKind::WebContent)
            .expect("observe web content");
        f
    }

    /// A session that has read secrets.
    fn secret_bearing() -> FlowTracker {
        let mut f = FlowTracker::new();
        f.observe(NodeKind::Secret).expect("observe a secret");
        f
    }

    /// **The bypass, pinned on the axis that matters.** A session holding secrets
    /// must not put them in a URL. Before the fix this was unreachable twice
    /// over: `ifc_egress_denial` returned early for any kind that was not
    /// `OutboundAction`, and even had it not, `sink_max_conf_for(WebFetch)` was
    /// `Secret` — the top of the lattice — so the ceiling could never be exceeded.
    #[test]
    fn a_secret_bearing_session_cannot_fetch_a_url() {
        let flow = secret_bearing();
        let kind = NodeKind::WebContent; // what node_kind_for(WebFetch) returns
        assert!(
            ifc_egress_denial(&flow, Operation::WebFetch, kind).is_some(),
            "a secret-bearing session must not send an agent-chosen URL outbound"
        );
        assert!(
            ifc_egress_denial(&flow, Operation::WebSearch, kind).is_some(),
            "web search is the same channel"
        );
    }

    /// The counterpart, and the reason the fix is two-axis rather than blunt: a
    /// session tainted by web content but holding no secrets may keep fetching.
    /// Reading page 2 adds no integrity the session has already lost, and denying
    /// it would end multi-page research for no security gain.
    #[test]
    fn a_tainted_but_secretless_session_may_still_fetch() {
        let flow = tainted();
        assert!(
            ifc_egress_denial(&flow, Operation::WebFetch, NodeKind::WebContent).is_none(),
            "integrity taint alone must not stop further reading"
        );
    }

    /// The two axes must genuinely differ, or the split above is decoration:
    /// under the SAME integrity taint an outbound ACTION is refused while an
    /// ingest is not.
    #[test]
    fn integrity_stops_actions_while_confidentiality_stops_egress() {
        let flow = tainted();
        assert!(
            ifc_egress_denial(&flow, Operation::WriteFiles, NodeKind::OutboundAction).is_some(),
            "an outbound action under taint is still refused"
        );
        assert!(
            ifc_egress_denial(&flow, Operation::WebFetch, NodeKind::WebContent).is_none(),
            "an ingest under the same taint is not"
        );
    }

    /// Reads carry nothing out and stay available under both conditions —
    /// without this, the denials above could be a gate that refuses everything.
    #[test]
    fn reads_stay_available() {
        for flow in [tainted(), secret_bearing()] {
            for op in [
                Operation::ReadFiles,
                Operation::GlobSearch,
                Operation::GrepSearch,
            ] {
                assert!(
                    ifc_egress_denial(&flow, op, NodeKind::FileRead).is_none(),
                    "{op:?} moves no data out and must remain available"
                );
            }
        }
    }

    /// A clean session may fetch — the denial must come from session state, not
    /// from the operation being newly forbidden outright.
    #[test]
    fn a_clean_session_may_still_fetch() {
        let flow = FlowTracker::new();
        assert!(
            ifc_egress_denial(&flow, Operation::WebFetch, NodeKind::WebContent).is_none(),
            "fetching is gated by session state, not banned"
        );
    }

    /// `sink_max_conf_for` must actually cap web egress below the top of the
    /// lattice. At `Secret` the check is inert, which is how the hole survived.
    #[test]
    fn web_egress_is_capped_below_the_top_of_the_lattice() {
        for op in [Operation::WebFetch, Operation::WebSearch] {
            assert!(
                sink_max_conf_for(op) < ConfLevel::Secret,
                "{op:?} capped at {:?}: a Secret cap can never be exceeded",
                sink_max_conf_for(op)
            );
        }
    }
}

#[cfg(test)]
mod graded_gate_tests {
    use super::*;
    use portcullis_core::flow::NodeKind;
    use portcullis_core::ifc_api::FlowTracker;

    fn tainted() -> FlowTracker {
        let mut f = FlowTracker::new();
        f.observe(NodeKind::WebContent).expect("observe");
        f
    }

    /// **The rollback guarantee.** With grading off, every outcome must be
    /// byte-identical to the historical gate. If this ever fails, the flag is
    /// not a safe default and the change is not a config rollback.
    #[test]
    fn ungraded_matches_the_historical_gate_on_every_operation() {
        let flow = tainted();
        for op in Operation::ALL {
            for kind in [
                NodeKind::OutboundAction,
                NodeKind::WebContent,
                NodeKind::FileRead,
            ] {
                let legacy = ifc_egress_denial(&flow, op, kind);
                let ungraded = ifc_egress_verdict(&flow, op, kind, false);
                match (&legacy, &ungraded) {
                    (Some(a), EgressVerdict::Deny(b)) => assert_eq!(a, b, "{op:?}/{kind:?}"),
                    (None, EgressVerdict::Pass) => {}
                    other => panic!("{op:?}/{kind:?} diverged: {other:?}"),
                }
            }
        }
    }

    /// Grading must never produce an approval for a sink that can move data out
    /// or leave an artifact someone else can see. This is the property that
    /// makes the flag safe to turn on at all.
    #[test]
    fn grading_never_defers_an_expensive_sink() {
        let flow = tainted();
        for op in Operation::ALL {
            let sink = portcullis_core::default_sink_class(op);
            if !(sink.is_exfil_vector() || sink.requires_verified_derivation()) {
                continue;
            }
            let v = ifc_egress_verdict(&flow, op, NodeKind::OutboundAction, true);
            assert!(
                !matches!(v, EgressVerdict::RequireApproval(_)),
                "{op:?} -> {sink:?} is externally visible; got {v:?}"
            );
        }
    }

    /// Grading must actually change something, or the flag is decoration.
    #[test]
    fn grading_defers_at_least_one_operation_the_old_gate_refused() {
        let flow = tainted();
        let deferred: Vec<_> = Operation::ALL
            .iter()
            .filter(|op| {
                ifc_egress_denial(&flow, **op, NodeKind::OutboundAction).is_some()
                    && matches!(
                        ifc_egress_verdict(&flow, **op, NodeKind::OutboundAction, true),
                        EgressVerdict::RequireApproval(_)
                    )
            })
            .collect();
        assert!(!deferred.is_empty(), "grading changed nothing");
    }

    /// Confidentiality is NOT graded: a secret-bearing session is refused even
    /// at a sink the grading would otherwise defer. Without this, enabling the
    /// flag would open the exfiltration path the previous PR just closed.
    #[test]
    fn grading_does_not_relax_the_confidentiality_check() {
        let mut flow = FlowTracker::new();
        flow.observe(NodeKind::Secret).expect("observe a secret");
        for op in [Operation::WebFetch, Operation::WebSearch] {
            let v = ifc_egress_verdict(&flow, op, NodeKind::WebContent, true);
            assert!(
                matches!(v, EgressVerdict::Deny(_)),
                "{op:?} must stay denied for a secret-bearing session even when graded, got {v:?}"
            );
        }
    }

    /// A clean session is unaffected by the flag in either position.
    #[test]
    fn a_clean_session_is_unaffected_by_grading() {
        let flow = FlowTracker::new();
        for op in Operation::ALL {
            assert_eq!(
                ifc_egress_verdict(&flow, op, NodeKind::OutboundAction, false),
                ifc_egress_verdict(&flow, op, NodeKind::OutboundAction, true),
                "{op:?} differs on a clean session"
            );
        }
    }
}
