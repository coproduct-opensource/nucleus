//! Sealed discharge preflight for the RunBash spawn path (#2038 / PR-2).
//!
//! Both the MCP `run` handler ([`crate::mcp`], feature-gated) and the HTTP
//! `/v1/run` handler ([`crate::run_command`], always compiled) must mint a
//! sealed [`DischargedBundle`] before they may reach `Executor::run_args` — the
//! executor-proof gate makes an un-preflighted spawn a *compile* error. Because
//! the MCP module is behind `#[cfg(feature = "mcp")]` but the HTTP path is not,
//! the shared preflight lives here, in an always-compiled module, so neither
//! caller depends on the other's feature.

use portcullis::flow_graph::FlowGraph;
use portcullis::{CapabilityLevel, Operation};

use nucleus_ifc_kernel::discharge::{
    self, DischargedBundle, PreflightResult, VerifiedScope, preflight_action,
};
use nucleus_ifc_kernel::{IFCLabel, SinkClass};
use nucleus_provenance_memory::TokenScope;

/// The two INDEPENDENTLY-sourced inputs to `WithinDelegationCeiling`.
///
/// Every caller used to pass one level for both — the policy's — so
/// `requested ≤ ceiling` held by construction and the obligation could not
/// fire on a live term. With a pod certificate the ceiling is the
/// certificate's level and the request is the on-disk policy's: two
/// sources that CAN disagree, which is what makes the witness non-vacuous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateLevels {
    /// The authority ceiling: the certificate's level for the op, or the
    /// policy's own when the pod holds no certificate.
    pub ceiling: CapabilityLevel,
    /// The requested level: what the resolved policy grants for the op.
    pub requested: CapabilityLevel,
}

impl GateLevels {
    /// `ceiling == requested`: the honest no-escalation claim, exactly what
    /// every caller passed before certificates. Production always goes
    /// through [`levels_for`]; this is the tests' constructor.
    #[cfg(test)]
    pub fn honest(level: CapabilityLevel) -> Self {
        Self {
            ceiling: level,
            requested: level,
        }
    }
}

/// [`GateLevels`] for `op` on this pod: the certificate's level as the
/// ceiling, the resolved policy's as the request. They agree for an honest
/// pod (boot refuses a spec that disagrees with its certificate), so a
/// disagreement here is a widened policy — denied by the obligation.
///
/// `estimated_cost_micro_usd` stays 0: in the extracted kernel a non-zero cost
/// with no budget gate is an unconditional deny (#1362), so a real estimate
/// is a kernel change. Budget is conserved at spawn (the node's ledger) and
/// per command (`AtomicBudget`), not through this obligation.
pub(crate) fn levels_for(state: &crate::AppState, op: Operation) -> GateLevels {
    let requested = state.runtime.policy().capabilities.level_for(op);
    let ceiling = state
        .pod_cert
        .as_ref()
        .map(|c| c.effective.capabilities.level_for(op))
        .unwrap_or(requested);
    GateLevels { ceiling, requested }
}

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
///   adversarial-integrity source label (with an empty [`FlowGraph`], vacuous);
/// - BudgetNotExceeded: cost is 0 (no cost estimator wired, #1362);
/// - WithinDelegationCeiling: `ceiling` is the pod CERTIFICATE's level and
///   `requested` the on-disk policy's ([`GateLevels`]); equal on an honest
///   pod, so it bites only when the policy claims more than the certificate
///   grants (pinned by `a_request_above_the_certificate_ceiling_is_denied_by_the_ceiling_obligation`).
/// - InputsAuthorized: the content-addressed inputs channel is plumbed from the
///   session [`FlowGraph`] (`Some(..)`, never a `None` default), so the
///   obligation is minted — vacuously on a clean session with no
///   content-addressed inputs (empty vec), and for real once bricks 1+3 record
///   digests on the session's source nodes.
///
/// So the real added enforcement of this brick is **`InScopeWithTask`** (gated by
/// the verified session task token) plus the fail-closed ceiling. The IFC labels
/// ARE fed honestly from the session's real [`FlowGraph`] (not `default()`), so
/// `NoAdversarialAncestry`/`IntegrityGate` bite for real once web/adversarial
/// content is in the session — they are simply vacuous on a clean session.
pub(crate) fn preflight_runbash(
    verified_scope: Option<&TokenScope>,
    levels: GateLevels,
    subject: &str,
    flow: &FlowGraph,
) -> PreflightResult {
    preflight_scoped(
        Operation::RunBash,
        SinkClass::BashExec,
        verified_scope,
        levels,
        subject,
        flow,
    )
}

/// The sealed discharge preflight for the live agent NET-EGRESS path
/// (`web_fetch` / `web_search`, B5).
///
/// The net analogue of [`preflight_runbash`]: builds the discharge
/// [`ActionTerm`](discharge::ActionTerm) for the given net `operation`
/// ([`Operation::WebFetch`] or [`Operation::WebSearch`]) at the
/// [`SinkClass::HTTPEgress`] sink and runs [`preflight_action`]. Returning
/// [`PreflightResult::Allowed`] hands back the sealed [`DischargedBundle`] the
/// handler must present to the sealed [`NetEffect::fetch`](portcullis_effects) —
/// there is no other way to construct that bundle, so an un-preflighted agent
/// egress is a compile-time-checked impossibility.
///
/// Fail-closed / no-vacuous-witness — identical structure to the RunBash gate:
/// - `verified_scope == None` (session token `Missing`/`Invalid`) ⇒
///   `InScopeWithTask` DENIES (we pass `None` straight through);
/// - net op ∉ `scope.allowed_operations` ⇒ `InScopeWithTask` DENIES.
///
/// STRONGER than the RunBash gate on the integrity axis: `HTTPEgress` has a
/// `sink_min_integrity` of `Untrusted` (vs `BashExec`'s `Adversarial` floor), so
/// once web/adversarial content taints the session the honest `artifact_label`
/// (joined from the real [`FlowGraph`] source labels) drops to `Adversarial`
/// and both `IntegrityGate` and `NoAdversarialAncestry` DENY the egress — the
/// lethal-trifecta guard biting for real. On a clean session the default label
/// is `Untrusted`, which meets the floor, so a valid in-scope token ALLOWS.
pub(crate) fn preflight_web(
    operation: Operation,
    verified_scope: Option<&TokenScope>,
    levels: GateLevels,
    subject: &str,
    flow: &FlowGraph,
) -> PreflightResult {
    debug_assert!(
        matches!(operation, Operation::WebFetch | Operation::WebSearch),
        "preflight_web is only for the net-egress operations",
    );
    preflight_scoped(
        operation,
        SinkClass::HTTPEgress,
        verified_scope,
        levels,
        subject,
        flow,
    )
}

/// The sealed discharge preflight for the live agent FILESYSTEM-WRITE path
/// (`write_file`, B6).
///
/// The fs analogue of [`preflight_runbash`]/[`preflight_web`]: builds the
/// discharge [`ActionTerm`](discharge::ActionTerm) for the given fs-write
/// `operation` ([`Operation::WriteFiles`] or [`Operation::EditFiles`]) at the
/// [`SinkClass::WorkspaceWrite`] sink and runs [`preflight_action`]. Returning
/// [`PreflightResult::Allowed`] hands back the sealed [`DischargedBundle`] the
/// handler must present to the `_proof`-gated
/// [`Sandbox::write`](nucleus::Sandbox) — there is no other way to construct
/// that bundle, so an un-preflighted agent fs write is a compile-time-checked
/// impossibility, closing the last agent effect class (spawn ✓, net ✓, fs ✓).
///
/// Fail-closed / no-vacuous-witness — identical structure to the RunBash and net
/// gates:
/// - `verified_scope == None` (session token `Missing`/`Invalid`) ⇒
///   `InScopeWithTask` DENIES (we pass `None` straight through);
/// - fs op ∉ `scope.allowed_operations` ⇒ `InScopeWithTask` DENIES.
///
/// On the integrity axis `WorkspaceWrite` has a `sink_min_integrity` of
/// `Adversarial` (the floor, like `BashExec`), so any session integrity passes
/// and `InScopeWithTask` is the discriminating gate — this brick is
/// class-coverage for the fs-write effect, not a new integrity constraint. The
/// cap-std root confinement enforced inside `Sandbox::write` is retained and
/// unchanged (dual-stack).
pub(crate) fn preflight_fs(
    operation: Operation,
    verified_scope: Option<&TokenScope>,
    levels: GateLevels,
    subject: &str,
    flow: &FlowGraph,
) -> PreflightResult {
    debug_assert!(
        matches!(operation, Operation::WriteFiles | Operation::EditFiles),
        "preflight_fs is only for the filesystem-write operations",
    );
    preflight_scoped(
        operation,
        SinkClass::WorkspaceWrite,
        verified_scope,
        levels,
        subject,
        flow,
    )
}

/// Discharge obligations for a sandbox READ.
///
/// The sibling of [`preflight_fs`] for the read side. Reads were previously
/// unmediated at this layer — the HTTP read path went straight from
/// `http_kernel_decide` to `Sandbox::read_to_string` with no discharge — so the
/// eight obligations never reached a file read even though `FileEffect::read`
/// required them on the other filesystem path.
///
/// `AuditLogAppend` is the sink a read is structurally permitted against
/// (`operation_allowed_for_sink`), matching `NucleusRuntime::preflight_read`.
pub(crate) fn preflight_read_fs(
    verified_scope: Option<&TokenScope>,
    levels: GateLevels,
    subject: &str,
    flow: &FlowGraph,
) -> PreflightResult {
    preflight_scoped(
        Operation::ReadFiles,
        SinkClass::AuditLogAppend,
        verified_scope,
        levels,
        subject,
        flow,
    )
}

/// Discharge obligations for one grep/search file read.
///
/// Separate from [`preflight_read_fs`] because the operation differs
/// (`GrepSearch`, not `ReadFiles`) and the discharge is scope-bound to it.
///
/// Called once PER FILE. That is the affine model working as designed, not an
/// oversight: an `Authority` buys one read, so a search over N files needs N
/// discharges. The alternative — one authority covering a whole directory walk —
/// is exactly the replay the by-value cutover removed.
/// Only the MCP search tool greps, and `mod mcp` is feature-gated, so this is
/// dead code without it — `-D warnings` in the musl type-check job caught that.
#[cfg(feature = "mcp")]
pub(crate) fn preflight_grep_fs(
    verified_scope: Option<&TokenScope>,
    levels: GateLevels,
    subject: &str,
    flow: &FlowGraph,
) -> PreflightResult {
    preflight_scoped(
        Operation::GrepSearch,
        SinkClass::AuditLogAppend,
        verified_scope,
        levels,
        subject,
        flow,
    )
}

/// Shared term-builder + preflight for the sealed live paths (RunBash spawn, net
/// egress, and filesystem write). Feeds the discharge
/// [`ActionTerm`](discharge::ActionTerm) the session's REAL IFC labels + content
/// hashes (never fabricated defaults) and the honest no-escalation ceiling
/// (`requested == ceiling`), then runs [`preflight_action`].
/// `operation`/`sink_class` select which effect class the obligations are minted
/// for; everything else is identical across the three callers so the fail-closed
/// guarantees cannot drift between them.
fn preflight_scoped(
    operation: Operation,
    sink_class: SinkClass,
    verified_scope: Option<&TokenScope>,
    levels: GateLevels,
    subject: &str,
    flow: &FlowGraph,
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
    // FlowGraph node ids are sparse under compaction, so walk the id space and
    // skip tombstoned (None) slots. `node_count()` is the backing-Vec length
    // (id 0 is the sentinel), so the real ids are `1..node_count()`.
    for node_id in 1..flow.node_count() as u64 {
        if let Some(node) = flow.get(node_id) {
            source_labels.push(node.label);
        }
        if let Some(hash) = flow.content_hash(node_id) {
            content_addressed_inputs.push(hash);
        }
    }
    // Fold in compaction-preserved labels so tombstoning cannot launder the
    // adversarial ancestry a compacted node carried (fail-closed: taint is only
    // ever ADDED to the artifact join). FlowTracker never compacted, so this is a
    // strict superset of its per-node scan.
    for rec in flow.compaction_log() {
        source_labels.push(rec.preserved_label);
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
        operation,
        sink_class,
        source_labels,
        artifact_label,
        subject: subject.to_string(),
        estimated_cost_micro_usd: 0,
        // Two sources (see `GateLevels`): the certificate's ceiling, the
        // policy's request. Equal on an honest pod; a widened policy is denied.
        capability_ceiling: Some(levels.ceiling),
        requested_capability: Some(levels.requested),
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

// ═══════════════════════════════════════════════════════════════════════════
// Tests — the live NET-EGRESS discharge gate (B5)
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_provenance_memory::TokenScope;

    // `preflight_web` is the sole precondition standing between a web_fetch /
    // web_search request and the sealed `NetEffect::fetch`: the handler only
    // reaches the send past its `Allowed` arm. Anything else means the handler
    // returns its error early and NEVER fetches. A clean session
    // (`FlowGraph::new()`) is used so the integrity/ancestry obligations are
    // met (default label = Untrusted, meeting the HTTPEgress floor) and
    // `InScopeWithTask` is the discriminating gate. Exact ceiling is immaterial
    // (`requested == ceiling`).
    const WEB_CEILING: CapabilityLevel = CapabilityLevel::LowRisk;

    /// `WithinDelegationCeiling` now has two sources. A policy that claims
    /// more than the certificate grants is denied BY THAT OBLIGATION — and
    /// with an honest ceiling the identical inputs mint the bundle, so the
    /// denial is the obligation firing, not an earlier gate.
    #[test]
    fn a_request_above_the_certificate_ceiling_is_denied_by_the_ceiling_obligation() {
        let flow = FlowGraph::new();
        let scope = TokenScope::new(vec![Operation::RunBash], vec![]);
        let widened = GateLevels {
            ceiling: CapabilityLevel::Never,
            requested: CapabilityLevel::LowRisk,
        };
        let result = preflight_runbash(Some(&scope), widened, "cargo test", &flow);
        assert!(result.is_denied(), "got {result:?}");
        assert!(
            result
                .denial_reason()
                .unwrap()
                .contains("DelegationCeiling"),
            "denial must be WithinDelegationCeiling: {result:?}"
        );
        let honest = GateLevels::honest(CapabilityLevel::LowRisk);
        assert!(
            preflight_runbash(Some(&scope), honest, "cargo test", &flow).is_allowed(),
            "non-vacuity: the same inputs with an honest ceiling must mint"
        );
    }

    // (a) Missing/Invalid session token ⇒ verified_scope() is None ⇒ DENY
    //     fail-closed (no-vacuous-witness) ⇒ no fetch. Both net ops.
    #[test]
    fn web_denies_when_session_token_missing_or_invalid() {
        for op in [Operation::WebFetch, Operation::WebSearch] {
            let flow = FlowGraph::new();
            let result = preflight_web(
                op,
                None,
                GateLevels::honest(WEB_CEILING),
                "https://evil.example",
                &flow,
            );
            assert!(
                result.is_denied(),
                "no verified scope must DENY {op:?} (fail-closed), got {result:?}"
            );
            assert!(
                result.denial_reason().unwrap().contains("InScopeWithTask"),
                "denial must be the InScopeWithTask no-vacuous-witness guard: {result:?}"
            );
            assert!(!result.is_allowed(), "must not mint a bundle ⇒ no fetch");
        }
    }

    // (b) A verified token whose scope does NOT include the net op ⇒
    //     InScopeWithTask DENIES ⇒ no fetch.
    #[test]
    fn web_denies_when_out_of_token_scope() {
        for op in [Operation::WebFetch, Operation::WebSearch] {
            let flow = FlowGraph::new();
            // Verified, but the net op ∉ allowed_operations.
            let scope = TokenScope::new(
                vec![Operation::ReadFiles, Operation::RunBash],
                vec!["/workspace/**".to_string()],
            );
            let result = preflight_web(
                op,
                Some(&scope),
                GateLevels::honest(WEB_CEILING),
                "https://api.example",
                &flow,
            );
            assert!(
                result.is_denied(),
                "{op:?} out of token scope must DENY, got {result:?}"
            );
            assert!(
                result.denial_reason().unwrap().contains("InScopeWithTask"),
                "denial must be InScopeWithTask: {result:?}"
            );
            assert!(!result.is_allowed(), "must not mint a bundle ⇒ no fetch");
        }
    }

    // (c) A verified, in-scope token on a clean session ⇒ ALLOW and mint the
    //     sealed `DischargedBundle` ⇒ the handler proceeds to the sealed fetch.
    #[test]
    fn web_succeeds_with_valid_in_scope_token() {
        for op in [Operation::WebFetch, Operation::WebSearch] {
            let flow = FlowGraph::new();
            let scope = TokenScope::new(
                vec![Operation::WebFetch, Operation::WebSearch],
                vec!["/workspace/**".to_string()],
            );
            let result = preflight_web(
                op,
                Some(&scope),
                GateLevels::honest(WEB_CEILING),
                "https://api.example",
                &flow,
            );
            assert!(
                result.is_allowed(),
                "valid in-scope token must ALLOW {op:?} (reach fetch), got {result:?}"
            );
            let bundle = result.unwrap_bundle();
            assert!(
                discharge_witness(&bundle).contains("in_scope_with_task"),
                "bundle must carry the InScopeWithTask witness"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Tests — the live FILESYSTEM-WRITE discharge gate (B6)
    // ═══════════════════════════════════════════════════════════════════════

    // `preflight_fs` is the sole precondition standing between a write_file
    // request and the `_proof`-gated `Sandbox::write`: the handler only reaches
    // the write past its `Allowed` arm. Anything else means the handler returns
    // its error early and NEVER writes. A clean session (`FlowGraph::new()`) is
    // used so `WorkspaceWrite`'s Adversarial-floor integrity is met and
    // `InScopeWithTask` is the discriminating gate. Exact ceiling is immaterial
    // (`requested == ceiling`).
    const FS_CEILING: CapabilityLevel = CapabilityLevel::LowRisk;

    // (a) Missing/Invalid session token ⇒ verified_scope() is None ⇒ DENY
    //     fail-closed (no-vacuous-witness) ⇒ no write.
    #[test]
    fn fs_denies_when_session_token_missing_or_invalid() {
        let flow = FlowGraph::new();
        let result = preflight_fs(
            Operation::WriteFiles,
            None,
            GateLevels::honest(FS_CEILING),
            "/workspace/out.txt",
            &flow,
        );
        assert!(
            result.is_denied(),
            "no verified scope must DENY WriteFiles (fail-closed), got {result:?}"
        );
        assert!(
            result.denial_reason().unwrap().contains("InScopeWithTask"),
            "denial must be the InScopeWithTask no-vacuous-witness guard: {result:?}"
        );
        assert!(!result.is_allowed(), "must not mint a bundle ⇒ no write");
    }

    // (b) A verified token whose scope does NOT include WriteFiles ⇒
    //     InScopeWithTask DENIES ⇒ no write.
    #[test]
    fn fs_denies_when_out_of_token_scope() {
        let flow = FlowGraph::new();
        // Verified, but WriteFiles ∉ allowed_operations.
        let scope = TokenScope::new(
            vec![Operation::ReadFiles, Operation::RunBash],
            vec!["/workspace/**".to_string()],
        );
        let result = preflight_fs(
            Operation::WriteFiles,
            Some(&scope),
            GateLevels::honest(FS_CEILING),
            "/workspace/out.txt",
            &flow,
        );
        assert!(
            result.is_denied(),
            "WriteFiles out of token scope must DENY, got {result:?}"
        );
        assert!(
            result.denial_reason().unwrap().contains("InScopeWithTask"),
            "denial must be InScopeWithTask: {result:?}"
        );
        assert!(!result.is_allowed(), "must not mint a bundle ⇒ no write");
    }

    // (c) A verified, in-scope token on a clean session ⇒ ALLOW and mint the
    //     sealed `DischargedBundle` ⇒ the handler proceeds to the sealed write.
    #[test]
    fn fs_succeeds_with_valid_in_scope_token() {
        let flow = FlowGraph::new();
        let scope = TokenScope::new(
            vec![Operation::WriteFiles],
            vec!["/workspace/**".to_string()],
        );
        let result = preflight_fs(
            Operation::WriteFiles,
            Some(&scope),
            GateLevels::honest(FS_CEILING),
            "/workspace/out.txt",
            &flow,
        );
        assert!(
            result.is_allowed(),
            "valid in-scope token must ALLOW WriteFiles (reach write), got {result:?}"
        );
        let bundle = result.unwrap_bundle();
        assert!(
            discharge_witness(&bundle).contains("in_scope_with_task"),
            "bundle must carry the InScopeWithTask witness"
        );
    }
}
