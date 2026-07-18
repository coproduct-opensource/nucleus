//! Sealed discharge preflight for the RunBash spawn path (#2038 / PR-2).
//!
//! Both the MCP `run` handler ([`crate::mcp`], feature-gated) and the HTTP
//! `/v1/run` handler ([`crate::run_command`], always compiled) must mint a
//! sealed [`DischargedBundle`] before they may reach `Executor::run_args` — the
//! executor-proof gate makes an un-preflighted spawn a *compile* error. Because
//! the MCP module is behind `#[cfg(feature = "mcp")]` but the HTTP path is not,
//! the shared preflight lives here, in an always-compiled module, so neither
//! caller depends on the other's feature.

use portcullis::{CapabilityLevel, FlowTracker, Operation};

use nucleus_ifc_kernel::discharge::{
    self, preflight_action, DischargedBundle, PreflightResult, VerifiedScope,
};
use nucleus_ifc_kernel::{IFCLabel, SinkClass};
use nucleus_provenance_memory::TokenScope;

/// The sealed discharge preflight for the live RunBash path (#2038).
///
/// Builds the discharge [`ActionTerm`](discharge::ActionTerm) for
/// `RunBash`/`BashExec` and runs [`preflight_action`]. Returning
/// [`PreflightResult::Allowed`] hands back a [`DischargedBundle`] — the sealed
/// 8-witness proof that the operation is authorized. There is no other way to
/// construct that bundle, so a caller that reaches `run_args` only past an
/// `Allowed` arm is a compile-time-checked precondition.
///
/// Fail-closed / no-vacuous-witness:
/// - `verified_scope == None` (session token `Missing`/`Invalid`) ⇒
///   `InScopeWithTask` DENIES. We pass `None` straight through — never a
///   permissive default.
/// - `RunBash ∉ scope.allowed_operations` ⇒ `InScopeWithTask` DENIES.
///
/// HONESTY (what actually bites, #2038): for the `BashExec` sink the five
/// original discharge obligations are structurally satisfied by the honest
/// inputs below and do not add enforcement here:
/// - IntegrityGate: `sink_min_integrity(BashExec)` is `Adversarial` (the floor),
///   so any integrity passes;
/// - PathAllowed: the fixed `RunBash`/`BashExec` pair is always structurally OK;
/// - DerivationClear: `BashExec` is not a verified-lane sink, so it is skipped;
/// - NoAdversarialAncestry: passes whenever the session carries no
///   adversarial-integrity source label (with an empty [`FlowTracker`], vacuous);
/// - BudgetNotExceeded: cost is 0 (no cost estimator wired, #1362);
/// - WithinDelegationCeiling: `requested == ceiling == level_for(RunBash)`, the
///   runtime's honest no-escalation claim, so `requested ≤ ceiling` holds by
///   construction (sound-but-dormant, mirrors `build_term_scoped`).
/// - InputsAuthorized: the content-addressed inputs channel is plumbed from the
///   session [`FlowTracker`] (`Some(..)`, never a `None` default), so the
///   obligation is minted — vacuously on a clean session with no
///   content-addressed inputs (empty vec), and for real once bricks 1+3 record
///   digests on the session's source nodes.
///
/// So the real added enforcement of this brick is **`InScopeWithTask`** (gated by
/// the verified session task token) plus the fail-closed ceiling. The IFC labels
/// ARE fed honestly from the session's real [`FlowTracker`] (not `default()`), so
/// `NoAdversarialAncestry`/`IntegrityGate` bite for real once web/adversarial
/// content is in the session — they are simply vacuous on a clean session.
pub(crate) fn preflight_runbash(
    verified_scope: Option<&TokenScope>,
    run_bash_ceiling: CapabilityLevel,
    subject: &str,
    flow: &FlowTracker,
) -> PreflightResult {
    // Real source labels from the session flow tracker (#1633 taint state) —
    // NOT fabricated defaults. Mirrors `build_term_scoped` in portcullis-effects.
    // In the same pass, collect the per-node content hash (InputsAuthorized
    // bricks 1+3): one `ContentHash` per node that carries a recorded digest. The
    // channel is `Some(..)` (plumbed) here, so `InputsAuthorized` is minted — an
    // empty vec (clean session with no content-addressed inputs) is vacuously
    // authorized. `None` (fail-closed deny) is reserved for un-plumbed callers.
    let mut source_labels = Vec::new();
    let mut content_addressed_inputs = Vec::new();
    for node_id in 1..=flow.node_count() as u64 {
        if let Some(label) = flow.label(node_id) {
            source_labels.push(*label);
        }
        if let Some(hash) = flow.content_hash(node_id) {
            content_addressed_inputs.push(hash);
        }
    }
    // Artifact label: join of all source labels (most restrictive composite); an
    // empty (clean) session yields the default label.
    let artifact_label = if source_labels.is_empty() {
        IFCLabel::default()
    } else {
        source_labels
            .iter()
            .skip(1)
            .fold(source_labels[0], |acc, l| acc.join(*l))
    };

    // Convert the verified `TokenScope` into the kernel's local `VerifiedScope`
    // carrier field-for-field (the kernel is dependency-free and cannot name
    // `TokenScope`). `None` ⇒ `InScopeWithTask` denied fail-closed.
    let term_scope = verified_scope.map(|s| VerifiedScope {
        allowed_operations: s.allowed_operations.clone(),
        allowed_paths: s.allowed_paths.clone(),
    });

    let term = discharge::ActionTerm {
        operation: Operation::RunBash,
        sink_class: SinkClass::BashExec,
        source_labels,
        artifact_label,
        subject: subject.to_string(),
        estimated_cost_micro_usd: 0,
        // Honest no-escalation: request exactly what the policy grants for the op.
        capability_ceiling: Some(run_bash_ceiling),
        requested_capability: Some(run_bash_ceiling),
        verified_scope: term_scope,
        // Plumbed inputs channel → InputsAuthorized minted (empty on a clean
        // session = vacuously authorized). Never a `None` default.
        content_addressed_inputs: Some(content_addressed_inputs),
    };

    preflight_action(&term)
}

/// Consume a [`DischargedBundle`] into an audit-record string.
///
/// Satisfies the bundle's `#[must_use]` by reading it, and threads the sealed
/// 8-witness proof into the verdict record so it is not dead.
pub(crate) fn discharge_witness(bundle: &DischargedBundle) -> String {
    format!("{bundle:?}")
}
