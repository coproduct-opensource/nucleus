/// **A bundle earned for one action does not authorise another.**
///
/// This is the confused deputy in its authorisation form. The effect
/// functions in `portcullis-effects` take the bundle as `_proof` — an
/// UNUSED type-level token — so before this the bundle proved only that
/// "a preflight ran somewhere", never that "a preflight ran for THIS
/// action". A bundle legitimately earned for a workspace write was
/// structurally usable to authorise a shell spawn.
///
/// The 2026 guidance on confused-deputy prevention is to bind the token to
/// the approved operation and scope — the macaroon "request-hash caveat"
/// pattern — so that authority cannot be exercised for an action the
/// principal never approved.
#[test]
fn a_bundle_does_not_authorise_a_different_action() {
    let term = ActionTerm {
        operation: Operation::WriteFiles,
        sink_class: SinkClass::WorkspaceWrite,
        source_labels: vec![],
        artifact_label: crate::IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            authority: AuthorityLevel::Directive,
            provenance: ProvenanceSet::SYSTEM,
            freshness: Freshness {
                observed_at: 1000,
                ttl_secs: 0,
            },
            derivation: DerivationClass::Deterministic,
        },
        subject: "scope-binding-test".to_string(),
        estimated_cost_micro_usd: 0,
        capability_ceiling: Some(crate::CapabilityLevel::LowRisk),
        requested_capability: Some(crate::CapabilityLevel::LowRisk),
        verified_scope: Some(VerifiedScope {
            allowed_operations: vec![Operation::WriteFiles],
            allowed_paths: vec![],
        }),
        content_addressed_inputs: Some(vec![]),
    };
    let bundle = match preflight_action(&term) {
        PreflightResult::Allowed(b) => b,
        other => panic!("expected Allowed, got {other:?}"),
    };

    // It authorises what it was earned for.
    assert!(
        bundle.authorizes(Operation::WriteFiles, SinkClass::WorkspaceWrite),
        "a bundle must authorise the action it was discharged for"
    );

    // It does NOT authorise a different operation at a different sink —
    // the escalation a confused deputy performs.
    assert!(
        !bundle.authorizes(Operation::RunBash, SinkClass::WorkspaceWrite),
        "a workspace-write bundle must not authorise a shell spawn"
    );
    assert!(
        !bundle.authorizes(Operation::WriteFiles, SinkClass::HTTPEgress),
        "a workspace-write bundle must not authorise http egress"
    );
}

use super::*;
use crate::{AuthorityLevel, ConfLevel, DerivationClass, Freshness, ProvenanceSet};

fn trusted_label() -> IFCLabel {
    IFCLabel {
        confidentiality: ConfLevel::Internal,
        integrity: IntegLevel::Trusted,
        authority: AuthorityLevel::Directive,
        provenance: ProvenanceSet::SYSTEM,
        freshness: Freshness {
            observed_at: 1000,
            ttl_secs: 0,
        },
        derivation: DerivationClass::Deterministic,
    }
}

fn adversarial_label() -> IFCLabel {
    IFCLabel {
        confidentiality: ConfLevel::Public,
        integrity: IntegLevel::Adversarial,
        authority: AuthorityLevel::NoAuthority,
        provenance: ProvenanceSet::WEB,
        freshness: Freshness {
            observed_at: 1000,
            ttl_secs: 0,
        },
        derivation: DerivationClass::OpaqueExternal,
    }
}

fn ai_derived_label() -> IFCLabel {
    IFCLabel {
        confidentiality: ConfLevel::Internal,
        integrity: IntegLevel::Trusted,
        authority: AuthorityLevel::Directive,
        provenance: ProvenanceSet::MODEL,
        freshness: Freshness {
            observed_at: 1000,
            ttl_secs: 0,
        },
        derivation: DerivationClass::AIDerived,
    }
}

fn human_promoted_label() -> IFCLabel {
    IFCLabel {
        derivation: DerivationClass::HumanPromoted,
        ..trusted_label()
    }
}

fn workspace_write_term() -> ActionTerm {
    ActionTerm {
        operation: Operation::WriteFiles,
        sink_class: SinkClass::WorkspaceWrite,
        source_labels: vec![],
        artifact_label: trusted_label(),
        subject: "spiffe://nucleus/agent/test".to_string(),
        estimated_cost_micro_usd: 0,
        // Happy-path inputs for the two widen-added obligations. The base
        // scope authorizes every operation the happy-path tests exercise;
        // denial tests override `operation`/labels to trip an *earlier*
        // check (integrity/path/derivation/ancestry/budget), which
        // short-circuits before the ceiling/scope checks.
        capability_ceiling: Some(CapabilityLevel::LowRisk),
        requested_capability: Some(CapabilityLevel::LowRisk),
        verified_scope: Some(VerifiedScope {
            allowed_operations: vec![
                Operation::WriteFiles,
                Operation::GitCommit,
                Operation::GitPush,
                Operation::CreatePr,
            ],
            allowed_paths: vec![],
        }),
        // Happy-path input for the widen 7 → 8 obligation (InputsAuthorized).
        // The channel is plumbed; denial tests that must trip InputsAuthorized
        // override this to `None`. Denial tests for *earlier* checks
        // short-circuit before check 8, so they inherit the happy-path value.
        content_addressed_inputs: Some(vec![]),
    }
}

// ── Happy path ──────────────────────────────────────────────────────────

#[test]
fn workspace_write_with_trusted_label_allowed() {
    let result = preflight_action(&workspace_write_term());
    assert!(result.is_allowed(), "workspace write should be allowed");
}

#[test]
fn git_commit_with_deterministic_label_allowed() {
    let term = ActionTerm {
        operation: Operation::GitCommit,
        sink_class: SinkClass::GitCommit,
        artifact_label: trusted_label(),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_allowed());
}

#[test]
fn git_push_with_human_promoted_label_allowed() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: human_promoted_label(),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_allowed());
}

#[test]
fn create_pr_with_deterministic_label_allowed() {
    let term = ActionTerm {
        operation: Operation::CreatePr,
        sink_class: SinkClass::PRCommentWrite,
        artifact_label: trusted_label(),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_allowed());
}

// ── IntegrityGate denials ───────────────────────────────────────────────

#[test]
fn git_push_with_adversarial_artifact_denied_integrity_gate() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: adversarial_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(
        result.is_denied(),
        "adversarial artifact at GitPush should be denied"
    );
    let reason = result.denial_reason().unwrap();
    assert!(
        reason.contains("IntegrityGate"),
        "denial should mention IntegrityGate, got: {reason}"
    );
}

#[test]
fn memory_persist_adversarial_artifact_denied_integrity_gate() {
    let term = ActionTerm {
        operation: Operation::WriteFiles,
        sink_class: SinkClass::MemoryPersist,
        artifact_label: adversarial_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(result.is_denied());
    assert!(result.denial_reason().unwrap().contains("IntegrityGate"));
}

// ── PathAllowed denials ─────────────────────────────────────────────────

#[test]
fn git_push_operation_to_workspace_sink_denied_path() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::WorkspaceWrite, // wrong sink for GitPush
        artifact_label: trusted_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(
        result.is_denied(),
        "GitPush to WorkspaceWrite should be denied"
    );
    let reason = result.denial_reason().unwrap();
    assert!(
        reason.contains("PathAllowed"),
        "denial should mention PathAllowed, got: {reason}"
    );
}

#[test]
fn run_bash_operation_to_git_push_sink_denied_path() {
    let term = ActionTerm {
        operation: Operation::RunBash,
        sink_class: SinkClass::GitPush, // wrong sink for RunBash
        artifact_label: trusted_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(result.is_denied());
    assert!(result.denial_reason().unwrap().contains("PathAllowed"));
}

// ── DerivationClear denials ─────────────────────────────────────────────

#[test]
fn ai_derived_artifact_at_git_push_denied_derivation() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: ai_derived_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(
        result.is_denied(),
        "AI-derived artifact at GitPush should be denied"
    );
    let reason = result.denial_reason().unwrap();
    assert!(
        reason.contains("DerivationClear"),
        "denial should mention DerivationClear, got: {reason}"
    );
}

#[test]
fn ai_derived_artifact_at_git_commit_denied_derivation() {
    let term = ActionTerm {
        operation: Operation::GitCommit,
        sink_class: SinkClass::GitCommit,
        artifact_label: ai_derived_label(),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_denied());
}

#[test]
fn ai_derived_artifact_at_workspace_write_allowed() {
    // WorkspaceWrite does NOT require verified derivation.
    let term = ActionTerm {
        operation: Operation::WriteFiles,
        sink_class: SinkClass::WorkspaceWrite,
        artifact_label: ai_derived_label(),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_allowed());
}

// ── NoAdversarialAncestry denials ───────────────────────────────────────

#[test]
fn adversarial_source_label_denied_ancestry() {
    let term = ActionTerm {
        operation: Operation::WriteFiles,
        sink_class: SinkClass::WorkspaceWrite,
        source_labels: vec![adversarial_label()],
        artifact_label: trusted_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(result.is_denied(), "adversarial source should be denied");
    let reason = result.denial_reason().unwrap();
    assert!(
        reason.contains("NoAdversarialAncestry"),
        "denial should mention NoAdversarialAncestry, got: {reason}"
    );
}

#[test]
fn mixed_sources_with_one_adversarial_denied() {
    let term = ActionTerm {
        operation: Operation::WriteFiles,
        sink_class: SinkClass::WorkspaceWrite,
        source_labels: vec![trusted_label(), adversarial_label()],
        artifact_label: trusted_label(),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_denied());
}

/// A term for a pure read on a session that has seen adversarial content:
/// the source labels carry `Adversarial` integrity and the artifact label is
/// their join, exactly as `run_gate::preflight_scoped` builds it on a tainted
/// session.
fn tainted_read_term(operation: Operation, sink_class: SinkClass) -> ActionTerm {
    ActionTerm {
        operation,
        sink_class,
        source_labels: vec![trusted_label(), adversarial_label()],
        artifact_label: trusted_label().join(adversarial_label()),
        verified_scope: Some(VerifiedScope {
            allowed_operations: vec![operation],
            allowed_paths: vec![],
        }),
        ..workspace_write_term()
    }
}

/// **A read cannot exfiltrate, so taint does not refuse it** (2026-09-27).
///
/// `NoAdversarialAncestry` is the non-interference clause: adversarial
/// content must not steer an effect. Before this, it ran for every pair,
/// so the first web page an agent fetched made every later file read
/// fail — an agent that read a hostile page could no longer look at its
/// own workspace, which is the opposite of what a defender wants it to do
/// next. A read at `AuditLogAppend` writes nothing outward; the taint is
/// still recorded when the bytes come back in (the ingest observe paths),
/// and every Acting pair that could carry those bytes out still pays #4.
///
/// RED-FIRST: on the unmodified kernel this fails with a
/// `NoAdversarialAncestry` denial for all three pairs.
#[test]
fn adversarial_ancestry_does_not_block_a_pure_read() {
    for op in [
        Operation::ReadFiles,
        Operation::GlobSearch,
        Operation::GrepSearch,
    ] {
        let result = preflight_action(&tainted_read_term(op, SinkClass::AuditLogAppend));
        assert!(
            result.is_allowed(),
            "{op:?} at AuditLogAppend on a tainted session must mint, got {result:?}"
        );
        assert_eq!(result.unwrap_bundle().kind(), ActionKind::PureRead);
    }
}

/// The operation decides, not the sink: `(WriteFiles, AuditLogAppend)` is
/// admissible and writes, so it still pays `NoAdversarialAncestry`. This
/// is the test a sink-keyed table would fail.
#[test]
fn adversarial_ancestry_still_blocks_a_write_to_the_audit_log() {
    let term = tainted_read_term(Operation::WriteFiles, SinkClass::AuditLogAppend);
    let result = preflight_action(&term);
    assert!(result.is_denied(), "got {result:?}");
    assert!(
        result
            .denial_reason()
            .unwrap()
            .contains("NoAdversarialAncestry"),
        "the denial must be #4, not an earlier gate: {result:?}"
    );
    // Non-vacuity: the identical term on a clean session mints, so the
    // denial above is #4 firing and not the pair being inadmissible.
    let clean = ActionTerm {
        source_labels: vec![trusted_label()],
        artifact_label: trusted_label(),
        ..term
    };
    assert!(preflight_action(&clean).is_allowed());
}

/// A read whose result is persisted is not a pure read. `(ReadFiles,
/// MemoryPersist)` is admissible (PathAllowed) and carries tainted bytes
/// into the next session, so it stays Acting and pays #4.
#[test]
fn adversarial_ancestry_still_blocks_a_read_persisted_to_memory() {
    for sink in [SinkClass::MemoryPersist, SinkClass::CacheWrite] {
        let term = ActionTerm {
            // Trusted artifact label so `MemoryPersist`'s Untrusted floor
            // (#1) passes and #4 is the gate under test.
            artifact_label: trusted_label(),
            ..tainted_read_term(Operation::ReadFiles, sink)
        };
        let result = preflight_action(&term);
        assert!(result.is_denied(), "{sink:?}: got {result:?}");
        assert!(
            result
                .denial_reason()
                .unwrap()
                .contains("NoAdversarialAncestry"),
            "{sink:?}: the denial must be #4: {result:?}"
        );
    }
}

// ── ActionKind: the pair decides, and only three pairs are pure reads ──

/// The pure-read pairs, written out once for the tests. The production
/// decider is `action_kind`; this list is its expectation, and
/// `pure_read_pairs_are_exactly_these` compares them over all 247 pairs.
/// In `Operation::ALL` order, which is the order the sweep finds them.
const PURE_READ_PAIRS: [(Operation, SinkClass); 4] = [
    (Operation::ReadFiles, SinkClass::AuditLogAppend),
    (Operation::GlobSearch, SinkClass::AuditLogAppend),
    (Operation::GrepSearch, SinkClass::AuditLogAppend),
    // Pod observe — list, status, logs (2026-09-27).
    (Operation::ManagePods, SinkClass::AuditLogAppend),
];

/// A clean term for `(op, sink)` that clears every obligation whenever the
/// pair is admissible — trusted, deterministic, in scope, zero cost.
fn clean_term(op: Operation, sink: SinkClass, subject: &str) -> ActionTerm {
    ActionTerm {
        operation: op,
        sink_class: sink,
        source_labels: vec![trusted_label()],
        artifact_label: trusted_label(),
        subject: subject.to_string(),
        verified_scope: Some(VerifiedScope {
            allowed_operations: vec![op],
            allowed_paths: vec![],
        }),
        ..workspace_write_term()
    }
}

#[test]
fn pure_read_pairs_are_exactly_these() {
    let mut pure = Vec::new();
    for op in Operation::ALL {
        for sink in SinkClass::ALL {
            if action_kind(op, sink) == ActionKind::PureRead {
                pure.push((op, sink));
            }
        }
    }
    assert_eq!(
        pure,
        PURE_READ_PAIRS.to_vec(),
        "the pure-read pairs drifted; a new one must be argued, not inherited"
    );
    // Every pure-read pair is admissible — a PureRead kind on a pair
    // PathAllowed refuses would be dead policy.
    for (op, sink) in PURE_READ_PAIRS {
        assert!(operation_allowed_for_sink(op, sink), "{op:?}/{sink:?}");
    }
}

/// **A pure-read bundle pays only for a pure read.** Over all 247 pairs:
/// every admissible pair mints a bundle whose `kind()` is `action_kind`
/// of that pair, and a bundle authorises its own pair and no other — so a
/// PureRead bundle cannot be presented to an Acting effect, whatever the
/// sink.
#[test]
fn a_pure_read_bundle_pays_only_for_pure_reads() {
    let mut minted = 0usize;
    let mut minted_pure = 0usize;
    for op in Operation::ALL {
        for sink in SinkClass::ALL {
            let kind = action_kind(op, sink);
            if kind == ActionKind::PureRead {
                assert!(PURE_READ_PAIRS.contains(&(op, sink)), "{op:?}/{sink:?}");
            }
            if !operation_allowed_for_sink(op, sink) {
                continue;
            }
            let bundle = match preflight_action(&clean_term(op, sink, "pair-sweep")) {
                PreflightResult::Allowed(b) => b,
                other => panic!("admissible {op:?}/{sink:?} must mint cleanly: {other:?}"),
            };
            minted += 1;
            assert_eq!(bundle.kind(), kind, "{op:?}/{sink:?}");
            if bundle.kind() == ActionKind::PureRead {
                minted_pure += 1;
                for other_op in Operation::ALL {
                    for other_sink in SinkClass::ALL {
                        if bundle.authorizes(other_op, other_sink) {
                            assert_eq!((other_op, other_sink), (op, sink));
                            assert_eq!(action_kind(other_op, other_sink), ActionKind::PureRead);
                        }
                    }
                }
            }
        }
    }
    // Non-vacuity: the sweep actually minted, and saw every pure read.
    assert!(minted > 20, "only {minted} admissible pairs minted");
    assert_eq!(minted_pure, PURE_READ_PAIRS.len());
}

/// The kind depends on the pair and nothing else on the term: the same
/// pair under a different subject, labels, or taint yields the same kind.
#[test]
fn kind_is_a_function_of_the_pair() {
    for (op, sink) in [
        (Operation::ReadFiles, SinkClass::AuditLogAppend),
        (Operation::WriteFiles, SinkClass::WorkspaceWrite),
    ] {
        let a = preflight_action(&clean_term(op, sink, "a")).unwrap_bundle();
        let b = preflight_action(&clean_term(op, sink, "some/other/subject")).unwrap_bundle();
        assert_eq!(a.kind(), b.kind());
        assert_eq!(a.kind(), action_kind(op, sink));
    }
    let tainted = preflight_action(&tainted_read_term(
        Operation::GrepSearch,
        SinkClass::AuditLogAppend,
    ))
    .unwrap_bundle();
    let clean = preflight_action(&clean_term(
        Operation::GrepSearch,
        SinkClass::AuditLogAppend,
        "x",
    ))
    .unwrap_bundle();
    assert_eq!(tainted.kind(), clean.kind());
}

/// Only #4 is waived. A pure read with no task scope, over the ceiling, or
/// with an un-plumbed inputs channel is still denied by that obligation.
#[test]
fn pure_read_still_needs_scope_ceiling_and_inputs() {
    let base = || tainted_read_term(Operation::ReadFiles, SinkClass::AuditLogAppend);
    let cases: [(&str, ActionTerm); 4] = [
        (
            "InScopeWithTask",
            ActionTerm {
                verified_scope: None,
                ..base()
            },
        ),
        (
            "InScopeWithTask",
            ActionTerm {
                verified_scope: Some(VerifiedScope {
                    allowed_operations: vec![Operation::WriteFiles],
                    allowed_paths: vec![],
                }),
                ..base()
            },
        ),
        (
            "WithinDelegationCeiling",
            ActionTerm {
                capability_ceiling: Some(CapabilityLevel::Never),
                requested_capability: Some(CapabilityLevel::LowRisk),
                ..base()
            },
        ),
        (
            "InputsAuthorized",
            ActionTerm {
                content_addressed_inputs: None,
                ..base()
            },
        ),
    ];
    for (obligation, term) in cases {
        let result = preflight_action(&term);
        assert!(result.is_denied(), "{obligation}: got {result:?}");
        assert!(
            result.denial_reason().unwrap().contains(obligation),
            "expected {obligation}, got {result:?}"
        );
    }
    // Non-vacuity: the base term itself mints.
    assert!(preflight_action(&base()).is_allowed());
}

#[test]
fn trusted_source_labels_allowed() {
    let term = ActionTerm {
        source_labels: vec![trusted_label(), trusted_label()],
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_allowed());
}

// ── BudgetNotExceeded denials ───────────────────────────────────────────

#[test]
fn non_zero_cost_without_budget_gate_denied() {
    let term = ActionTerm {
        estimated_cost_micro_usd: 1_000, // 0.001 USD
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(
        result.is_denied(),
        "non-zero cost without budget gate should be denied"
    );
    let reason = result.denial_reason().unwrap();
    assert!(
        reason.contains("BudgetNotExceeded"),
        "denial should mention BudgetNotExceeded, got: {reason}"
    );
}

#[test]
fn zero_cost_always_passes_budget() {
    let term = ActionTerm {
        estimated_cost_micro_usd: 0,
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_allowed());
}

// ── Sealing: DischargedBundle cannot be forged ──────────────────────────

#[test]
fn discharged_bundle_only_obtainable_via_preflight() {
    // This test validates the sealing contract: the only way to get a
    // DischargedBundle is through a successful preflight_action call.
    // The compile-fail aspect is verified by the doc-test on DischargedBundle.
    let bundle = preflight_action(&workspace_write_term()).unwrap_bundle();
    // We can inspect the bundle debug output, confirming fields are present.
    let debug_str = format!("{bundle:?}");
    assert!(debug_str.contains("DischargedBundle"));
    assert!(debug_str.contains("IntegrityGate"));
    assert!(debug_str.contains("DerivationClear"));
}

// ── PreflightResult helpers ─────────────────────────────────────────────

#[test]
fn preflight_result_is_denied_and_is_allowed_are_exclusive() {
    let allowed = preflight_action(&workspace_write_term());
    assert!(allowed.is_allowed());
    assert!(!allowed.is_denied());
    assert!(!allowed.requires_approval());

    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: adversarial_label(),
        ..workspace_write_term()
    };
    let denied = preflight_action(&term);
    assert!(!denied.is_allowed());
    assert!(denied.is_denied());
    assert!(!denied.requires_approval());
}

#[test]
fn denial_reason_present_on_denied_result() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: ai_derived_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(result.denial_reason().is_some());
    assert!(!result.denial_reason().unwrap().is_empty());
}

#[test]
fn denial_reason_none_on_allowed_result() {
    let result = preflight_action(&workspace_write_term());
    assert!(result.denial_reason().is_none());
}

// ── Obligation ordering: earlier checks take precedence ─────────────────

#[test]
fn integrity_gate_fires_before_derivation_check() {
    // Artifact is both adversarial AND AI-derived.
    // IntegrityGate (check 1) should fire before DerivationClear (check 3).
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: IFCLabel {
            integrity: IntegLevel::Adversarial,
            derivation: DerivationClass::AIDerived,
            ..trusted_label()
        },
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(result.is_denied());
    assert!(
        result.denial_reason().unwrap().contains("IntegrityGate"),
        "IntegrityGate should fire first"
    );
}

// ── Helper function unit tests ──────────────────────────────────────────

#[test]
fn git_push_sink_requires_verified_derivation() {
    assert!(sink_requires_verified_derivation(SinkClass::GitPush));
    assert!(sink_requires_verified_derivation(SinkClass::GitCommit));
    assert!(sink_requires_verified_derivation(SinkClass::PRCommentWrite));
}

#[test]
fn workspace_write_does_not_require_verified_derivation() {
    assert!(!sink_requires_verified_derivation(
        SinkClass::WorkspaceWrite
    ));
    assert!(!sink_requires_verified_derivation(SinkClass::BashExec));
    assert!(!sink_requires_verified_derivation(SinkClass::HTTPEgress));
}

#[test]
fn git_push_sink_requires_untrusted_min_integrity() {
    assert_eq!(
        sink_min_integrity(SinkClass::GitPush),
        IntegLevel::Untrusted
    );
    assert_eq!(
        sink_min_integrity(SinkClass::GitCommit),
        IntegLevel::Untrusted
    );
    assert_eq!(
        sink_min_integrity(SinkClass::PRCommentWrite),
        IntegLevel::Untrusted
    );
}

#[test]
fn workspace_write_accepts_adversarial_min_integrity() {
    assert_eq!(
        sink_min_integrity(SinkClass::WorkspaceWrite),
        IntegLevel::Adversarial
    );
}

#[test]
fn operation_sink_consistency_git_operations() {
    assert!(operation_allowed_for_sink(
        Operation::GitPush,
        SinkClass::GitPush
    ));
    assert!(!operation_allowed_for_sink(
        Operation::GitPush,
        SinkClass::WorkspaceWrite
    ));
    assert!(operation_allowed_for_sink(
        Operation::GitCommit,
        SinkClass::GitCommit
    ));
    assert!(!operation_allowed_for_sink(
        Operation::GitCommit,
        SinkClass::GitPush
    ));
    assert!(operation_allowed_for_sink(
        Operation::CreatePr,
        SinkClass::PRCommentWrite
    ));
}

// ── RepairHint tests (#1189) ────────────────────────────────────────────

#[test]
fn integrity_gate_hint_is_raise_integrity() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: adversarial_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    let hint = result.repair_hint().unwrap();
    assert!(matches!(
        hint,
        RepairHint::RaiseIntegrity {
            actual: IntegLevel::Adversarial,
            ..
        }
    ));
}

#[test]
fn path_allowed_hint_is_correct_pair() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::WorkspaceWrite,
        artifact_label: trusted_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    let hint = result.repair_hint().unwrap();
    assert!(matches!(
        hint,
        RepairHint::CorrectOperationSinkPair {
            operation: Operation::GitPush,
            declared_sink: SinkClass::WorkspaceWrite,
        }
    ));
}

#[test]
fn derivation_hint_is_promote_derivation() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: ai_derived_label(),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    let hint = result.repair_hint().unwrap();
    assert!(matches!(
        hint,
        RepairHint::PromoteDerivation {
            actual: DerivationClass::AIDerived,
            sink: SinkClass::GitPush,
        }
    ));
}

#[test]
fn adversarial_ancestry_hint_is_declassify() {
    let term = ActionTerm {
        source_labels: vec![adversarial_label()],
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    let hint = result.repair_hint().unwrap();
    assert!(matches!(hint, RepairHint::DeclassifyOrReplaceInput { .. }));
}

#[test]
fn budget_hint_is_wire_budget_gate() {
    let term = ActionTerm {
        estimated_cost_micro_usd: 5_000,
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    let hint = result.repair_hint().unwrap();
    assert!(matches!(
        hint,
        RepairHint::WireBudgetGate {
            cost_micro_usd: 5_000
        }
    ));
}

#[test]
fn allowed_result_has_no_hint() {
    let result = preflight_action(&workspace_write_term());
    assert!(result.repair_hint().is_none());
}

#[test]
fn repair_hint_display_is_human_readable() {
    let hint = RepairHint::RaiseIntegrity {
        actual: IntegLevel::Adversarial,
        required: IntegLevel::Untrusted,
        sink: SinkClass::GitPush,
    };
    let msg = hint.to_string();
    assert!(msg.contains("raise artifact integrity"));
    assert!(msg.contains("Adversarial"));
    assert!(msg.contains("Untrusted"));
}

// ── Repair rewriting system tests ───────────────────────────────────

#[test]
fn repair_budget_needs_approval_and_zeroes_cost() {
    let term = ActionTerm {
        estimated_cost_micro_usd: 5000,
        ..workspace_write_term()
    };
    let hint = RepairHint::WireBudgetGate {
        cost_micro_usd: 5000,
    };
    let repair = hint.try_repair(&term).unwrap();
    // Budget zeroing is policy-significant — requires human approval
    assert!(!repair.is_automatic());
    assert_eq!(repair.term().estimated_cost_micro_usd, 0);
    // The repaired term should pass preflight
    assert!(preflight_action(repair.term()).is_allowed());
}

#[test]
fn repair_adversarial_ancestry_needs_approval() {
    let term = ActionTerm {
        source_labels: vec![trusted_label(), adversarial_label()],
        ..workspace_write_term()
    };
    let hint = RepairHint::DeclassifyOrReplaceInput {
        subject: "test".to_string(),
    };
    let repair = hint.try_repair(&term).unwrap();
    // Declassifying adversarial ancestry is security-significant — no auto-laundering
    assert!(!repair.is_automatic());
    // Adversarial source removed, trusted remains
    assert_eq!(repair.term().source_labels.len(), 1);
    assert_eq!(
        repair.term().source_labels[0].integrity,
        IntegLevel::Trusted
    );
    // Repaired term should pass preflight
    assert!(preflight_action(repair.term()).is_allowed());
}

#[test]
fn repair_integrity_needs_approval() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: adversarial_label(),
        ..workspace_write_term()
    };
    let hint = RepairHint::RaiseIntegrity {
        actual: IntegLevel::Adversarial,
        required: IntegLevel::Untrusted,
        sink: SinkClass::GitPush,
    };
    let repair = hint.try_repair(&term).unwrap();
    assert!(!repair.is_automatic());
    // Repaired term has raised integrity
    assert_eq!(
        repair.term().artifact_label.integrity,
        IntegLevel::Untrusted
    );
}

#[test]
fn repair_derivation_needs_approval() {
    let term = ActionTerm {
        operation: Operation::GitPush,
        sink_class: SinkClass::GitPush,
        artifact_label: ai_derived_label(),
        ..workspace_write_term()
    };
    let hint = RepairHint::PromoteDerivation {
        actual: DerivationClass::AIDerived,
        sink: SinkClass::GitPush,
    };
    let repair = hint.try_repair(&term).unwrap();
    assert!(!repair.is_automatic());
    assert_eq!(
        repair.term().artifact_label.derivation,
        DerivationClass::HumanPromoted
    );
}

#[test]
fn repair_operation_sink_mismatch_returns_none() {
    let term = workspace_write_term();
    let hint = RepairHint::CorrectOperationSinkPair {
        operation: Operation::GitPush,
        declared_sink: SinkClass::WorkspaceWrite,
    };
    assert!(hint.try_repair(&term).is_none());
}

#[test]
fn full_deny_repair_retry_loop() {
    // End-to-end: deny → hint → repair (needs approval) → approved term passes
    let term = ActionTerm {
        estimated_cost_micro_usd: 1000,
        ..workspace_write_term()
    };
    // First attempt: denied (non-zero cost)
    let result = preflight_action(&term);
    assert!(result.is_denied());
    let hint = result.repair_hint().unwrap();
    // Repair: cost zeroed, but requires human approval
    let repair = hint.try_repair(&term).unwrap();
    assert!(!repair.is_automatic());
    // After approval, the repaired term passes preflight
    let retry = preflight_action(repair.term());
    assert!(retry.is_allowed());
}

// ── Widen 5 → 7: WithinDelegationCeiling + InScopeWithTask ──────────────
//
// These are the soundness guards for PR-B. The central property is the
// NO-VACUOUS-WITNESS rule: a term that is MISSING an input required by one
// of the two new obligations must be DENIED — a witness is never minted
// from absent evidence.

#[test]
fn happy_path_mints_full_eight_field_bundle() {
    // All inputs present + in-scope + within ceiling + inputs plumbed →
    // Allowed with a bundle whose Debug shows all eight obligation witnesses.
    let bundle = preflight_action(&workspace_write_term()).unwrap_bundle();
    let dbg = format!("{bundle:?}");
    for needle in [
        "IntegrityGate",
        "PathAllowed",
        "DerivationClear",
        "NoAdversarialAncestry",
        "BudgetNotExceeded",
        "WithinDelegationCeiling",
        "InScopeWithTask",
        "InputsAuthorized",
    ] {
        assert!(dbg.contains(needle), "bundle debug missing {needle}: {dbg}");
    }
}

// ── NO-VACUOUS-WITNESS: InputsAuthorized (widen 7 → 8) ─────────────────

#[test]
fn missing_content_addressed_inputs_denies_inputs_authorized() {
    // content_addressed_inputs: None (un-plumbed) → must DENY (never mint
    // InputsAuthorized from an absent inputs channel).
    let term = ActionTerm {
        content_addressed_inputs: None,
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(
        result.is_denied(),
        "absent content-addressed inputs channel must deny fail-closed"
    );
    assert!(
        result.denial_reason().unwrap().contains("InputsAuthorized"),
        "denial should name InputsAuthorized, got: {:?}",
        result.denial_reason()
    );
    assert!(matches!(
        result.repair_hint().unwrap(),
        RepairHint::ProvideContentAddressedInputs { .. }
    ));
}

#[test]
fn empty_inputs_vec_mints_inputs_authorized_vacuously() {
    // Some(vec![]) = an action with no inputs = vacuously authorized → Allowed.
    // Mirrors upstream `!inputs.any(empty_hash)` returning satisfied for zero
    // inputs. This is the deliberate empty-vec-vs-None asymmetry.
    let term = ActionTerm {
        content_addressed_inputs: Some(vec![]),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_allowed());
}

#[test]
fn present_content_hashes_mint_inputs_authorized() {
    // Some(non-empty) with real 32-byte digests → Allowed (presence attested).
    let term = ActionTerm {
        content_addressed_inputs: Some(vec![
            ContentHash::from_bytes([0x11; 32]),
            ContentHash::from_bytes([0x22; 32]),
        ]),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_allowed());
}

#[test]
fn scope_check_precedes_inputs_check() {
    // Both scope and inputs un-plumbed: scope (check 7) fires before inputs
    // (check 8), confirming ordering and short-circuit.
    let term = ActionTerm {
        verified_scope: None,
        content_addressed_inputs: None,
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(
        result.denial_reason().unwrap().contains("InScopeWithTask"),
        "scope (check 7) should fire before inputs (check 8)"
    );
}

#[test]
fn provide_inputs_hint_has_no_automatic_repair() {
    // The un-plumbed inputs state is a wiring defect, not a policy decision —
    // try_repair returns None (we cannot fabricate content hashes).
    let term = ActionTerm {
        content_addressed_inputs: None,
        ..workspace_write_term()
    };
    let hint = preflight_action(&term).repair_hint().unwrap().clone();
    assert!(matches!(
        hint,
        RepairHint::ProvideContentAddressedInputs { .. }
    ));
    assert!(hint.try_repair(&term).is_none());
}

// ── NO-VACUOUS-WITNESS: InScopeWithTask ────────────────────────────────

#[test]
fn missing_verified_scope_denies_in_scope_with_task() {
    // verified_scope: None → must DENY (never mint InScopeWithTask).
    let term = ActionTerm {
        verified_scope: None,
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(
        result.is_denied(),
        "absent verified scope must deny fail-closed"
    );
    assert!(
        result.denial_reason().unwrap().contains("InScopeWithTask"),
        "denial should name InScopeWithTask, got: {:?}",
        result.denial_reason()
    );
    assert!(matches!(
        result.repair_hint().unwrap(),
        RepairHint::OutOfTaskScope { .. }
    ));
}

#[test]
fn operation_outside_scope_denies_in_scope_with_task() {
    // scope present but does NOT authorize the operation → DENY.
    let term = ActionTerm {
        verified_scope: Some(VerifiedScope {
            allowed_operations: vec![Operation::ReadFiles], // not WriteFiles
            allowed_paths: vec![],
        }),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(result.is_denied());
    assert!(result.denial_reason().unwrap().contains("InScopeWithTask"));
}

#[test]
fn empty_scope_denies_in_scope_with_task_fail_closed() {
    // Empty allowed_operations = nothing authorized (TokenScope allowlist
    // semantics) → DENY. This is STRICTER than upstream's empty=allow-all
    // TaskRef guard, on purpose: a VerifiedScope is a capability-token scope.
    let term = ActionTerm {
        verified_scope: Some(VerifiedScope {
            allowed_operations: vec![],
            allowed_paths: vec![],
        }),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_denied());
}

// ── NO-VACUOUS-WITNESS: WithinDelegationCeiling ────────────────────────

#[test]
fn missing_capability_ceiling_denies_within_delegation_ceiling() {
    let term = ActionTerm {
        capability_ceiling: None,
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(
        result.is_denied(),
        "absent capability ceiling must deny fail-closed"
    );
    assert!(
        result
            .denial_reason()
            .unwrap()
            .contains("WithinDelegationCeiling")
    );
}

#[test]
fn missing_requested_capability_denies_within_delegation_ceiling() {
    let term = ActionTerm {
        requested_capability: None,
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(result.is_denied());
    assert!(
        result
            .denial_reason()
            .unwrap()
            .contains("WithinDelegationCeiling")
    );
}

#[test]
fn requested_above_ceiling_denies_within_delegation_ceiling() {
    // requested Always > ceiling LowRisk → DENY with ReduceCapabilityRequest.
    let term = ActionTerm {
        capability_ceiling: Some(CapabilityLevel::LowRisk),
        requested_capability: Some(CapabilityLevel::Always),
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(result.is_denied());
    assert!(matches!(
        result.repair_hint().unwrap(),
        RepairHint::ReduceCapabilityRequest {
            requested: CapabilityLevel::Always,
            ceiling: CapabilityLevel::LowRisk,
        }
    ));
}

#[test]
fn never_ceiling_denies_forbidden_operation() {
    // The meaningful lift: an operation the policy forbids (ceiling == Never)
    // is denied because requested LowRisk > Never. Not vacuous.
    let term = ActionTerm {
        capability_ceiling: Some(CapabilityLevel::Never),
        requested_capability: Some(CapabilityLevel::LowRisk),
        ..workspace_write_term()
    };
    assert!(preflight_action(&term).is_denied());
}

#[test]
fn ceiling_check_precedes_scope_check() {
    // Both new inputs bad: ceiling fires (check 6) before scope (check 7).
    let term = ActionTerm {
        capability_ceiling: None,
        verified_scope: None,
        ..workspace_write_term()
    };
    let result = preflight_action(&term);
    assert!(
        result
            .denial_reason()
            .unwrap()
            .contains("WithinDelegationCeiling"),
        "ceiling (check 6) should fire before scope (check 7)"
    );
}

// ── SECURITY_TODO #23: the unreachable-sink list cannot drift ───────────

/// Every `SinkClass` is either reachable from at least one `Operation`, or
/// is listed in `SINKS_WITH_NO_OPERATION` with a reason. The check runs in
/// BOTH directions, which is what makes it a gate rather than a comment:
///
///   * a sink that is unreachable and undocumented fails — this is what
///     silently happened to four sinks, under a doc claiming the pairing
///     gate was permissive by default;
///   * a sink that is documented as unreachable but has become reachable
///     also fails, so the list cannot rot into a lie the other way.
///
/// Same shape as `documented_inventory_equals_the_enum` in
/// `egress_channel.rs`: the enum and the prose are pinned to each other.
#[test]
fn every_sink_is_reachable_or_documented() {
    for sink in SinkClass::ALL {
        let reachable = Operation::ALL
            .iter()
            .any(|&op| operation_allowed_for_sink(op, sink));
        let documented = SINKS_WITH_NO_OPERATION.iter().any(|(s, _)| *s == sink);

        assert!(
            reachable != documented,
            "{sink:?}: reachable={reachable}, documented_unreachable={documented} — \
             a sink must be exactly one of the two. If a new Operation made it \
             reachable, drop it from SINKS_WITH_NO_OPERATION; if a new sink is \
             undischargeable, add it there with the reason."
        );
    }
}

/// Non-vacuity for the above: the four are genuinely unreachable today, and
/// at least one sink is genuinely reachable. Without this, an empty
/// `Operation::ALL` or an all-inclusive list would still satisfy the
/// exclusive-or.
#[test]
fn the_documented_sinks_are_the_unreachable_ones() {
    assert_eq!(SINKS_WITH_NO_OPERATION.len(), 4);
    for (sink, reason) in SINKS_WITH_NO_OPERATION {
        assert!(
            !Operation::ALL
                .iter()
                .any(|&op| operation_allowed_for_sink(op, sink)),
            "{sink:?} is documented unreachable ({reason}) but some Operation admits it"
        );
    }
    assert!(
        operation_allowed_for_sink(Operation::GitPush, SinkClass::GitPush),
        "a control pairing must be reachable, or the gate proves nothing"
    );
}

// ── AuthorityReducing: a tainted session can still stop its children ──

/// The authority-reducing pairs, written out once. `action_kind` is the
/// decider; `authority_reducing_pairs_are_exactly_these` compares them.
const AUTHORITY_REDUCING_PAIRS: [(Operation, SinkClass); 1] =
    [(Operation::ManagePods, SinkClass::CloudMutation)];

/// A pod term on a session that has read adversarial content: the source
/// labels carry `Adversarial` integrity AND the artifact label is their join,
/// so both obligation 1 (the sink floor) and obligation 4 would bite.
fn tainted_pod_term(sink_class: SinkClass) -> ActionTerm {
    ActionTerm {
        subject: "00000000-0000-0000-0000-00000000000b".to_string(),
        ..tainted_read_term(Operation::ManagePods, sink_class)
    }
}

/// **A tainted session can still cancel** (2026-09-27).
///
/// Teardown was `(ManagePods, CloudMutation)`, an Acting pair at a sink with
/// an `Untrusted` floor. So the first hostile page a parent agent read made it
/// unable to stop the children it had spawned — obligation 1 refused on the
/// artifact label, and obligation 4 on the source labels. The taint that
/// should make an agent more willing to stop things made stopping impossible.
/// Now the pair is `AuthorityReducing`: floor `Adversarial`, #4 not charged.
///
/// RED-FIRST: on the kernel before `AuthorityReducing` this is denied with an
/// `IntegrityGate` reason. A-19 probe: making `action_kind` return `Acting`
/// for this pair turns it red again.
#[test]
fn a_tainted_session_can_cancel() {
    let term = tainted_pod_term(SinkClass::CloudMutation);
    assert_eq!(term.artifact_label.integrity, IntegLevel::Adversarial);
    let result = preflight_action(&term);
    assert!(
        result.is_allowed(),
        "a tainted session must still be able to cancel: {result:?}"
    );
    let bundle = result.unwrap_bundle();
    assert_eq!(bundle.kind(), ActionKind::AuthorityReducing);
    assert!(bundle.authorizes(Operation::ManagePods, SinkClass::CloudMutation));
}

/// The same tainted session cannot CREATE a sub-pod: `(ManagePods,
/// AgentSpawn)` is Acting, so the `AgentSpawn` floor refuses it at #1 — and
/// with a trusted artifact label, #4 still refuses it on the source labels.
#[test]
fn a_tainted_session_cannot_create_a_sub_pod() {
    let term = tainted_pod_term(SinkClass::AgentSpawn);
    let result = preflight_action(&term);
    assert!(result.is_denied(), "got {result:?}");
    assert!(
        result.denial_reason().unwrap().contains("IntegrityGate"),
        "{result:?}"
    );
    let floor_cleared = ActionTerm {
        artifact_label: trusted_label(),
        ..tainted_pod_term(SinkClass::AgentSpawn)
    };
    let result = preflight_action(&floor_cleared);
    assert!(result.is_denied(), "got {result:?}");
    assert!(
        result
            .denial_reason()
            .unwrap()
            .contains("NoAdversarialAncestry"),
        "{result:?}"
    );
    // Non-vacuity: the pair itself is earnable on a clean session.
    let clean = clean_term(Operation::ManagePods, SinkClass::AgentSpawn, "x");
    assert!(preflight_action(&clean).is_allowed());
}

/// A teardown bundle authorises teardown and nothing else — in particular not
/// a spawn, the pair that shares its operation. The exemption is keyed on the
/// pair, and `authorizes` is pair equality, so it cannot leak to create.
#[test]
fn a_teardown_bundle_cannot_pay_for_a_spawn() {
    let bundle = preflight_action(&tainted_pod_term(SinkClass::CloudMutation)).unwrap_bundle();
    assert!(!bundle.authorizes(Operation::ManagePods, SinkClass::AgentSpawn));
    assert!(!bundle.authorizes(Operation::SpawnAgent, SinkClass::AgentSpawn));
    assert!(!bundle.authorizes(Operation::ManagePods, SinkClass::AuditLogAppend));
    let mut authorised = 0usize;
    for op in Operation::ALL {
        for sink in SinkClass::ALL {
            if bundle.authorizes(op, sink) {
                authorised += 1;
                assert_eq!((op, sink), AUTHORITY_REDUCING_PAIRS[0]);
            }
        }
    }
    assert_eq!(authorised, 1, "it must authorise its own pair");
}

/// Only #1's floor and #4 are waived. A cancel with no task scope, a scope
/// that does not name `ManagePods`, over the ceiling, over budget, or with an
/// un-plumbed inputs channel is still refused by that obligation.
#[test]
fn cancel_still_needs_task_scope() {
    let base = || tainted_pod_term(SinkClass::CloudMutation);
    let cases: [(&str, ActionTerm); 5] = [
        (
            "InScopeWithTask",
            ActionTerm {
                verified_scope: None,
                ..base()
            },
        ),
        (
            "InScopeWithTask",
            ActionTerm {
                verified_scope: Some(VerifiedScope {
                    allowed_operations: vec![Operation::ReadFiles],
                    allowed_paths: vec![],
                }),
                ..base()
            },
        ),
        (
            "WithinDelegationCeiling",
            ActionTerm {
                capability_ceiling: Some(CapabilityLevel::Never),
                requested_capability: Some(CapabilityLevel::LowRisk),
                ..base()
            },
        ),
        (
            "InputsAuthorized",
            ActionTerm {
                content_addressed_inputs: None,
                ..base()
            },
        ),
        (
            "BudgetNotExceeded",
            ActionTerm {
                estimated_cost_micro_usd: 1,
                ..base()
            },
        ),
    ];
    for (obligation, term) in cases {
        let result = preflight_action(&term);
        assert!(result.is_denied(), "{obligation}: got {result:?}");
        assert!(
            result.denial_reason().unwrap().contains(obligation),
            "expected {obligation}, got {result:?}"
        );
    }
    // Non-vacuity: the base term itself mints.
    assert!(preflight_action(&base()).is_allowed());
}

#[test]
fn authority_reducing_pairs_are_exactly_these() {
    let mut reducing = Vec::new();
    for op in Operation::ALL {
        for sink in SinkClass::ALL {
            if action_kind(op, sink) == ActionKind::AuthorityReducing {
                reducing.push((op, sink));
            }
        }
    }
    assert_eq!(
        reducing,
        AUTHORITY_REDUCING_PAIRS.to_vec(),
        "the authority-reducing pairs drifted; an exemption from the taint \
         obligations must be argued, not inherited"
    );
    for (op, sink) in AUTHORITY_REDUCING_PAIRS {
        assert!(operation_allowed_for_sink(op, sink), "{op:?}/{sink:?}");
        // Only this kind's floor moved: the sink's own floor is still the
        // publish floor, so an Acting pair at CloudMutation would pay it.
        assert_eq!(
            integrity_floor(ActionKind::AuthorityReducing, sink),
            IntegLevel::Adversarial
        );
        assert_eq!(
            integrity_floor(ActionKind::Acting, sink),
            IntegLevel::Untrusted
        );
    }
}

/// Pod observe is a pure read: a tainted session can still list its pods and
/// read their logs, and the bytes that come back are observed into the graph
/// by the node client, so every later Acting pair pays for them.
#[test]
fn a_tainted_session_can_observe_its_pods() {
    let result = preflight_action(&tainted_pod_term(SinkClass::AuditLogAppend));
    assert!(result.is_allowed(), "got {result:?}");
    assert_eq!(result.unwrap_bundle().kind(), ActionKind::PureRead);
}
