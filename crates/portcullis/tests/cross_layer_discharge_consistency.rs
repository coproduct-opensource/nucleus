//! Cross-layer consistency guard (PR-B regression guard (a)).
//!
//! The discharge layer (`portcullis_core::discharge`, the sealed 8-obligation
//! vocabulary in `nucleus-ifc-kernel`) LIFTS two obligations from the upstream
//! `portcullis::action_term` checker: `WithinDelegationCeiling` and
//! `InScopeWithTask`. This test pins the two layers together: for a corpus of
//! matched terms, the upstream verdict (all obligations satisfied) must agree
//! with the discharge verdict (`preflight_action == Allowed`) **on the shared /
//! lifted obligations**.
//!
//! ## Why this lives in the `portcullis` crate
//!
//! `portcullis` is the only crate that sees BOTH checkers: it depends on
//! `portcullis-core` (which re-exports `nucleus_ifc_kernel::discharge`) and it
//! IS the home of the upstream `action_term` checker. Neither
//! `nucleus-ifc-kernel` nor `portcullis-effects` (the PR acceptance's two
//! crates) can see the upstream checker — the kernel is dependency-free and
//! `portcullis-effects` does not depend on `portcullis`. So this guard runs
//! under `cargo test -p portcullis --test cross_layer_discharge_consistency`,
//! outside the two-crate acceptance set (reported).
//!
//! ## Scenario shape (isolating the two lifted obligations)
//!
//! We use `Operation::GitCommit` with a `Proposed` effect and no inputs so the
//! upstream `derive_obligations` yields exactly `[WithinDelegationCeiling,
//! InScopeWithTask]` (no `FsPathAllowed` — GitCommit has no action path; no
//! `VerifiedSinkCompatible` — Proposed; no `NoAdversarialAncestry` /
//! `InputsAuthorized` — no inputs, LowRisk request). The matched discharge term
//! is built to pass every OTHER discharge obligation (trusted+deterministic
//! artifact into the GitCommit sink, no source labels, zero cost) so that only
//! the two lifted obligations decide the verdict.

use portcullis::action_term::{
    preflight_action as upstream_preflight, ActionTerm as UpstreamTerm, PreflightContext,
    PreflightVerdict, TaskRef,
};
use portcullis::PermissionLattice;
use portcullis_core::discharge::{
    preflight_action as discharge_preflight, ActionTerm as DischargeTerm, VerifiedScope,
};
use portcullis_core::{
    AuthorityLevel, CapabilityLevel, ConfLevel, DerivationClass, Freshness, IFCLabel, IntegLevel,
    Operation, ProvenanceSet, SinkClass,
};

/// A trusted, deterministic artifact label — passes the discharge
/// IntegrityGate / DerivationClear checks at the GitCommit (verified) sink.
fn trusted_deterministic() -> IFCLabel {
    IFCLabel {
        confidentiality: ConfLevel::Internal,
        integrity: IntegLevel::Trusted,
        authority: AuthorityLevel::Directive,
        provenance: ProvenanceSet::SYSTEM,
        freshness: Freshness {
            observed_at: 1_000,
            ttl_secs: 0,
        },
        derivation: DerivationClass::Deterministic,
    }
}

/// Run the UPSTREAM checker for a GitCommit term with the given task scope and
/// policy ceiling. Returns `true` iff the aggregate verdict is `Pass` (i.e.
/// both lifted obligations are satisfied — they are the only ones derived).
fn upstream_all_satisfied(allowed_ops: &[Operation], git_commit_ceiling: CapabilityLevel) -> bool {
    let mut perms = PermissionLattice::permissive();
    // Set the ceiling for the operation under test (mutation sticks — it runs
    // after `normalize()`; the two lifted checks only read `capabilities` and
    // `paths`, so obligation normalization is irrelevant here).
    perms.capabilities.git_commit = git_commit_ceiling;
    let ctx = PreflightContext::new(&perms);

    let mut term = UpstreamTerm::from_operation(Operation::GitCommit, "commit message");
    term.task = Some(TaskRef::new(
        "task-1",
        "cross-layer scenario",
        allowed_ops.to_vec(),
        vec![],
    ));
    // Honest LowRisk request (matches from_operation's default and the matched
    // discharge term's `requested_capability` below).
    let result = upstream_preflight(&term, &ctx);
    result.verdict == PreflightVerdict::Pass
}

/// Run the DISCHARGE checker for the matched GitCommit term. Every non-lifted
/// obligation is arranged to pass, so `Allowed` iff both lifted obligations
/// (WithinDelegationCeiling, InScopeWithTask) hold.
fn discharge_allowed(allowed_ops: &[Operation], git_commit_ceiling: CapabilityLevel) -> bool {
    let term = DischargeTerm {
        operation: Operation::GitCommit,
        sink_class: SinkClass::GitCommit,
        source_labels: vec![],
        artifact_label: trusted_deterministic(),
        subject: "commit message".to_string(),
        estimated_cost_micro_usd: 0,
        capability_ceiling: Some(git_commit_ceiling),
        // Mirror the upstream term's honest LowRisk authority claim.
        requested_capability: Some(CapabilityLevel::LowRisk),
        verified_scope: Some(VerifiedScope {
            allowed_operations: allowed_ops.to_vec(),
            allowed_paths: vec![],
        }),
        // No inputs (matches the upstream scenario) → InputsAuthorized minted
        // vacuously. Plumbed `Some(vec![])`, never `None`, so this obligation
        // never decides the verdict — only the two lifted obligations do.
        content_addressed_inputs: Some(vec![]),
    };
    discharge_preflight(&term).is_allowed()
}

#[test]
fn upstream_and_discharge_agree_on_lifted_obligations() {
    // Corpus of matched scenarios over NON-EMPTY task scopes (the empty-scope
    // case is deliberately divergent — see the dedicated test below). Each entry
    // is (allowed_operations, git_commit_ceiling, expected_both_pass).
    let corpus: &[(&[Operation], CapabilityLevel, bool)] = &[
        // In-scope + within ceiling → both pass.
        (&[Operation::GitCommit], CapabilityLevel::Always, true),
        (&[Operation::GitCommit], CapabilityLevel::LowRisk, true),
        (
            &[Operation::GitCommit, Operation::ReadFiles],
            CapabilityLevel::LowRisk,
            true,
        ),
        // Ceiling forbids the op (Never < LowRisk request) → both fail.
        (&[Operation::GitCommit], CapabilityLevel::Never, false),
        // Op not in task scope → both fail.
        (&[Operation::ReadFiles], CapabilityLevel::Always, false),
        // Both dimensions bad → both fail.
        (&[Operation::ReadFiles], CapabilityLevel::Never, false),
    ];

    for (allowed_ops, ceiling, expected_both_pass) in corpus {
        let up = upstream_all_satisfied(allowed_ops, *ceiling);
        let dis = discharge_allowed(allowed_ops, *ceiling);
        assert_eq!(
            up, dis,
            "cross-layer divergence for ops={allowed_ops:?} ceiling={ceiling:?}: \
             upstream_all_satisfied={up} discharge_allowed={dis}"
        );
        assert_eq!(
            dis, *expected_both_pass,
            "unexpected verdict for ops={allowed_ops:?} ceiling={ceiling:?}"
        );
    }
}

/// Documented, intentional divergence: an EMPTY task scope.
///
/// Upstream `InScopeWithTask` treats an empty `allowed_operations` as
/// "no restriction" (allow-all) — the `!is_empty() &&` guard. The discharge
/// layer treats an empty `VerifiedScope.allowed_operations` as an allowlist that
/// authorizes NOTHING (fail-closed), because a `VerifiedScope` is a
/// capability-token scope, not a coarse task hint. This test pins that the
/// stricter discharge behavior is deliberate.
#[test]
fn empty_scope_is_intentionally_stricter_in_discharge() {
    let up = upstream_all_satisfied(&[], CapabilityLevel::Always);
    let dis = discharge_allowed(&[], CapabilityLevel::Always);
    assert!(up, "upstream treats empty allowed_operations as allow-all");
    assert!(
        !dis,
        "discharge treats an empty verified scope as fail-closed (deny)"
    );
}
