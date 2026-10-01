//! `(WriteFiles, MemoryPersist)` — the pair a memory write spends (2026-09-27).
//!
//! `/v1/memory/write` admits a record into the session's provenance memory,
//! which outlives the request and is read back into later sessions. It had no
//! discharge at all: `http_kernel_decide` ran, its token was bound to `_dt` and
//! dropped, and `memory_write_core` mutated the set. It could not have had one —
//! `PathAllowed` refused `(WriteFiles, MemoryPersist)`, so a handler that wanted
//! to spend a preflight before writing memory had no pair to earn.
//!
//! These live outside `discharge.rs` because they need nothing private: the term,
//! the preflight and the kind are all public, and that file is over its line
//! ceiling.

use nucleus_ifc_kernel::discharge::{ActionKind, ActionTerm, VerifiedScope, preflight_action};
use nucleus_ifc_kernel::{
    AuthorityLevel, CapabilityLevel, ConfLevel, DerivationClass, Freshness, IFCLabel, IntegLevel,
    Operation, ProvenanceSet, SinkClass,
};

fn trusted() -> IFCLabel {
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

fn adversarial() -> IFCLabel {
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

/// A memory-write term over `sources`, joined into `artifact`, in scope and
/// under the ceiling — so the only thing that can refuse it is the pair or the
/// labels.
fn memory_write(sources: Vec<IFCLabel>, artifact: IFCLabel) -> ActionTerm {
    ActionTerm {
        operation: Operation::WriteFiles,
        sink_class: SinkClass::MemoryPersist,
        source_labels: sources,
        artifact_label: artifact,
        subject: "memory://test".to_string(),
        estimated_cost_micro_usd: 0,
        capability_ceiling: Some(CapabilityLevel::LowRisk),
        requested_capability: Some(CapabilityLevel::LowRisk),
        verified_scope: Some(VerifiedScope {
            allowed_operations: vec![Operation::WriteFiles],
            allowed_paths: vec![],
        }),
        content_addressed_inputs: Some(vec![]),
    }
}

/// RED-FIRST: before `MemoryPersist` joined the `WriteFiles` arm of
/// `operation_allowed_for_sink` this is denied by `PathAllowed`.
#[test]
fn memory_write_pair_is_earnable_on_a_clean_session() {
    let result = preflight_action(&memory_write(vec![trusted()], trusted()));
    assert!(result.is_allowed(), "got {result:?}");
    // Acting, not a read: memory is a cross-session taint vector, so a memory
    // write pays `NoAdversarialAncestry` like any other write.
    assert_eq!(result.unwrap_bundle().kind(), ActionKind::Acting);
}

/// The other half: a tainted session cannot write memory. With the session's
/// own (adversarial) artifact label the `MemoryPersist` floor (`Untrusted`)
/// refuses it at #1; with a trusted artifact label over the same adversarial
/// sources, #4 still refuses it. Two independent gates, each pinned, so
/// removing either leaves the other visible.
#[test]
fn tainted_session_cannot_write_memory() {
    let sources = vec![trusted(), adversarial()];
    let floor = preflight_action(&memory_write(
        sources.clone(),
        trusted().join(adversarial()),
    ));
    assert!(floor.is_denied(), "got {floor:?}");
    assert!(
        floor.denial_reason().unwrap().contains("IntegrityGate"),
        "the Untrusted floor refuses first: {floor:?}"
    );

    let ancestry = preflight_action(&memory_write(sources, trusted()));
    assert!(ancestry.is_denied(), "got {ancestry:?}");
    assert!(
        ancestry
            .denial_reason()
            .unwrap()
            .contains("NoAdversarialAncestry"),
        "the ancestry clause refuses a laundered artifact label: {ancestry:?}"
    );
}
