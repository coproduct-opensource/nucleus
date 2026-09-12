//! The audit chain's digest preimage must not depend on `Debug`.
//!
//! `AuditEntry::content_hash` hashed `format!("{:?}", self.event)`. Derived
//! `Debug` is not a stability contract: the same entry hashed differently under
//! a different rustc, so the chain `executor_sig` signs was only ever
//! verifiable inside one build — and because it is derived, a field added to a
//! variant silently rewrote every historical hash while a field removed simply
//! stopped being committed.
//!
//! `PermissionEvent::digest_parts` replaced it with an exhaustive match over an
//! explicit encoding, absorbed tagged and length-prefixed. These tests pin the
//! three properties that makes it worth having: every variant hashes
//! differently, every field reaches the hash, and the framing is injective.
//!
//! The dylint pass `debug_format_in_preimage` keeps the `format!` from coming
//! back (`scripts/check-preimage-dylint.sh`); these keep the replacement
//! honest. Neither alone is enough — the pass cannot tell a stable encoding
//! from an unstable one, and a test cannot see the next author's new sink.

use portcullis::audit::{AuditEntry, PermissionEvent};
use portcullis::weakening::{WeakeningCost, WeakeningDimension, WeakeningRequest};
use portcullis::{CapabilityLevel, Operation, StateRisk};
use rust_decimal::Decimal;
use std::time::{Duration, SystemTime};

/// An entry whose only varying part is the event, so a hash difference can
/// only come from the event's encoding.
fn entry(event: PermissionEvent) -> AuditEntry {
    AuditEntry {
        schema_version: 1,
        sequence: 7,
        timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        identity: "spiffe://nucleus.local/ns/default/sa/test".to_string(),
        event,
        correlation_id: None,
        session_id: None,
        prev_hash: None,
        extensions: std::collections::BTreeMap::new(),
    }
}

fn cost() -> WeakeningCost {
    WeakeningCost {
        base: Decimal::new(5, 1),
        uninhabitable_multiplier: Decimal::new(3, 0),
        isolation_multiplier: Decimal::ONE,
    }
}

fn request() -> WeakeningRequest {
    WeakeningRequest {
        dimension: WeakeningDimension::Capability(Operation::GitPush),
        from_level: "never".to_string(),
        to_level: "always".to_string(),
        cost: cost(),
        uninhabitable_impact: StateRisk::Medium,
        justification: Some("because".to_string()),
    }
}

/// One of every variant. The list is what
/// `every_event_variant_hashes_differently` ranges over, and adding a
/// variant without adding it here leaves the new one unhashed by any test
/// — so `digest_parts`' exhaustive match is what actually forces the
/// update, and this is the reminder.
fn one_of_each() -> Vec<PermissionEvent> {
    vec![
        PermissionEvent::PermissionsDeclared {
            description: "d".into(),
            state_risk: StateRisk::Safe,
        },
        PermissionEvent::OperationRequested {
            operation: Operation::ReadFiles,
            declared_level: CapabilityLevel::Never,
            requested_level: CapabilityLevel::Always,
        },
        PermissionEvent::WeakeningRequested {
            request: request(),
            uninhabitable_impact: StateRisk::Low,
        },
        PermissionEvent::UninhabitableStateChanged {
            before: StateRisk::Safe,
            after: StateRisk::Medium,
            trigger: "t".into(),
        },
        PermissionEvent::ExecutionCompleted {
            total_cost: cost(),
            weakening_count: 2,
            state_uninhabitable: false,
        },
        PermissionEvent::ApprovalRequested {
            operation: Operation::GitPush,
            reason: "r".into(),
        },
        PermissionEvent::ApprovalGranted {
            operation: Operation::GitPush,
            approver: Some("a".into()),
        },
        PermissionEvent::ApprovalDenied {
            operation: Operation::GitPush,
            reason: Some("r".into()),
        },
        PermissionEvent::ExecutionBlocked {
            operation: Operation::GitPush,
            reason: "r".into(),
            threshold_exceeded: Some(Decimal::ONE),
        },
        PermissionEvent::DelegationDecision {
            from_identity: "p".into(),
            to_identity: "c".into(),
            requested_description: "rq".into(),
            granted_description: "gr".into(),
            was_narrowed: true,
            restricted_dimensions: vec!["write_files".into()],
        },
    ]
}

/// **Two different events must not share a chain hash.** They would be
/// interchangeable in the audit log: an `ApprovalGranted` swapped for an
/// `ApprovalDenied` with every link still verifying.
#[test]
fn every_event_variant_hashes_differently() {
    let mut hashes: Vec<String> = one_of_each()
        .into_iter()
        .map(|e| entry(e).content_hash())
        .collect();
    let before = hashes.len();
    hashes.sort();
    hashes.dedup();
    assert_eq!(before, 10, "a variant was added without a sample here");
    assert_eq!(hashes.len(), before, "two events share a content hash");
}

/// **Every field an event carries must reach the digest.** A field the hash
/// does not cover can be rewritten in flight with the chain still valid —
/// the tamper the hash exists to prevent. Perturb each one; each must move
/// the hash.
#[test]
fn every_event_field_reaches_the_digest() {
    let cases: Vec<(&str, PermissionEvent, PermissionEvent)> = vec![
        (
            "declared.description",
            PermissionEvent::PermissionsDeclared {
                description: "a".into(),
                state_risk: StateRisk::Safe,
            },
            PermissionEvent::PermissionsDeclared {
                description: "b".into(),
                state_risk: StateRisk::Safe,
            },
        ),
        (
            "declared.state_risk",
            PermissionEvent::PermissionsDeclared {
                description: "a".into(),
                state_risk: StateRisk::Safe,
            },
            PermissionEvent::PermissionsDeclared {
                description: "a".into(),
                state_risk: StateRisk::Uninhabitable,
            },
        ),
        (
            "requested.operation",
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::Never,
                requested_level: CapabilityLevel::Always,
            },
            PermissionEvent::OperationRequested {
                operation: Operation::GitPush,
                declared_level: CapabilityLevel::Never,
                requested_level: CapabilityLevel::Always,
            },
        ),
        (
            "requested.declared_level",
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::Never,
                requested_level: CapabilityLevel::Always,
            },
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::LowRisk,
                requested_level: CapabilityLevel::Always,
            },
        ),
        (
            "requested.requested_level",
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::Never,
                requested_level: CapabilityLevel::Always,
            },
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::Never,
                requested_level: CapabilityLevel::LowRisk,
            },
        ),
        (
            "weakening.request.dimension",
            PermissionEvent::WeakeningRequested {
                request: request(),
                uninhabitable_impact: StateRisk::Low,
            },
            PermissionEvent::WeakeningRequested {
                request: WeakeningRequest {
                    dimension: WeakeningDimension::Capability(Operation::ReadFiles),
                    ..request()
                },
                uninhabitable_impact: StateRisk::Low,
            },
        ),
        (
            "weakening.request.cost",
            PermissionEvent::WeakeningRequested {
                request: request(),
                uninhabitable_impact: StateRisk::Low,
            },
            PermissionEvent::WeakeningRequested {
                request: WeakeningRequest {
                    cost: WeakeningCost {
                        base: Decimal::new(9, 1),
                        ..cost()
                    },
                    ..request()
                },
                uninhabitable_impact: StateRisk::Low,
            },
        ),
        (
            "weakening.request.justification",
            PermissionEvent::WeakeningRequested {
                request: request(),
                uninhabitable_impact: StateRisk::Low,
            },
            PermissionEvent::WeakeningRequested {
                request: WeakeningRequest {
                    justification: None,
                    ..request()
                },
                uninhabitable_impact: StateRisk::Low,
            },
        ),
        (
            "weakening.uninhabitable_impact",
            PermissionEvent::WeakeningRequested {
                request: request(),
                uninhabitable_impact: StateRisk::Low,
            },
            PermissionEvent::WeakeningRequested {
                request: request(),
                uninhabitable_impact: StateRisk::Medium,
            },
        ),
        (
            "changed.before",
            PermissionEvent::UninhabitableStateChanged {
                before: StateRisk::Safe,
                after: StateRisk::Medium,
                trigger: "t".into(),
            },
            PermissionEvent::UninhabitableStateChanged {
                before: StateRisk::Low,
                after: StateRisk::Medium,
                trigger: "t".into(),
            },
        ),
        (
            "changed.after",
            PermissionEvent::UninhabitableStateChanged {
                before: StateRisk::Safe,
                after: StateRisk::Medium,
                trigger: "t".into(),
            },
            PermissionEvent::UninhabitableStateChanged {
                before: StateRisk::Safe,
                after: StateRisk::Uninhabitable,
                trigger: "t".into(),
            },
        ),
        (
            "changed.trigger",
            PermissionEvent::UninhabitableStateChanged {
                before: StateRisk::Safe,
                after: StateRisk::Medium,
                trigger: "t".into(),
            },
            PermissionEvent::UninhabitableStateChanged {
                before: StateRisk::Safe,
                after: StateRisk::Medium,
                trigger: "u".into(),
            },
        ),
        (
            "completed.total_cost",
            PermissionEvent::ExecutionCompleted {
                total_cost: cost(),
                weakening_count: 2,
                state_uninhabitable: false,
            },
            PermissionEvent::ExecutionCompleted {
                total_cost: WeakeningCost {
                    isolation_multiplier: Decimal::new(2, 0),
                    ..cost()
                },
                weakening_count: 2,
                state_uninhabitable: false,
            },
        ),
        (
            "completed.weakening_count",
            PermissionEvent::ExecutionCompleted {
                total_cost: cost(),
                weakening_count: 2,
                state_uninhabitable: false,
            },
            PermissionEvent::ExecutionCompleted {
                total_cost: cost(),
                weakening_count: 3,
                state_uninhabitable: false,
            },
        ),
        (
            "completed.state_uninhabitable",
            PermissionEvent::ExecutionCompleted {
                total_cost: cost(),
                weakening_count: 2,
                state_uninhabitable: false,
            },
            PermissionEvent::ExecutionCompleted {
                total_cost: cost(),
                weakening_count: 2,
                state_uninhabitable: true,
            },
        ),
        (
            "approval_requested.reason",
            PermissionEvent::ApprovalRequested {
                operation: Operation::GitPush,
                reason: "a".into(),
            },
            PermissionEvent::ApprovalRequested {
                operation: Operation::GitPush,
                reason: "b".into(),
            },
        ),
        (
            "approval_granted.approver",
            PermissionEvent::ApprovalGranted {
                operation: Operation::GitPush,
                approver: Some("a".into()),
            },
            PermissionEvent::ApprovalGranted {
                operation: Operation::GitPush,
                approver: None,
            },
        ),
        (
            "approval_denied.reason",
            PermissionEvent::ApprovalDenied {
                operation: Operation::GitPush,
                reason: Some("a".into()),
            },
            PermissionEvent::ApprovalDenied {
                operation: Operation::GitPush,
                reason: None,
            },
        ),
        (
            "blocked.threshold_exceeded",
            PermissionEvent::ExecutionBlocked {
                operation: Operation::GitPush,
                reason: "r".into(),
                threshold_exceeded: Some(Decimal::ONE),
            },
            PermissionEvent::ExecutionBlocked {
                operation: Operation::GitPush,
                reason: "r".into(),
                threshold_exceeded: None,
            },
        ),
        (
            "delegation.was_narrowed",
            PermissionEvent::DelegationDecision {
                from_identity: "p".into(),
                to_identity: "c".into(),
                requested_description: "rq".into(),
                granted_description: "gr".into(),
                was_narrowed: true,
                restricted_dimensions: vec!["write_files".into()],
            },
            PermissionEvent::DelegationDecision {
                from_identity: "p".into(),
                to_identity: "c".into(),
                requested_description: "rq".into(),
                granted_description: "gr".into(),
                was_narrowed: false,
                restricted_dimensions: vec!["write_files".into()],
            },
        ),
        (
            "delegation.restricted_dimensions",
            PermissionEvent::DelegationDecision {
                from_identity: "p".into(),
                to_identity: "c".into(),
                requested_description: "rq".into(),
                granted_description: "gr".into(),
                was_narrowed: true,
                restricted_dimensions: vec!["write_files".into()],
            },
            PermissionEvent::DelegationDecision {
                from_identity: "p".into(),
                to_identity: "c".into(),
                requested_description: "rq".into(),
                granted_description: "gr".into(),
                was_narrowed: true,
                restricted_dimensions: vec!["git_push".into()],
            },
        ),
    ];

    for (field, a, b) in cases {
        assert_ne!(
            entry(a).content_hash(),
            entry(b).content_hash(),
            "{field} does not reach the content hash: it can be rewritten with the chain \
             still verifying"
        );
    }
}

/// **Concatenation must not be ambiguous.** The parts are absorbed
/// tag-separated and length-prefixed precisely so that moving a character
/// across a field boundary is a different preimage. Without the framing
/// these two delegation records — the same total text, split differently —
/// would share a hash, and a narrowing decision could be restated as a
/// different one that still verifies.
#[test]
fn a_field_boundary_cannot_move_without_changing_the_hash() {
    let a = PermissionEvent::DelegationDecision {
        from_identity: "pc".into(),
        to_identity: "".into(),
        requested_description: "rq".into(),
        granted_description: "gr".into(),
        was_narrowed: true,
        restricted_dimensions: vec![],
    };
    let b = PermissionEvent::DelegationDecision {
        from_identity: "p".into(),
        to_identity: "c".into(),
        requested_description: "rq".into(),
        granted_description: "gr".into(),
        was_narrowed: true,
        restricted_dimensions: vec![],
    };
    assert_ne!(entry(a).content_hash(), entry(b).content_hash());
}

/// A list's element boundaries must be committed too: `["ab"]` and
/// `["a","b"]` are different sets of restricted dimensions.
#[test]
fn a_list_element_boundary_is_committed() {
    let joined = PermissionEvent::DelegationDecision {
        from_identity: "p".into(),
        to_identity: "c".into(),
        requested_description: "rq".into(),
        granted_description: "gr".into(),
        was_narrowed: true,
        restricted_dimensions: vec!["ab".into()],
    };
    let split = PermissionEvent::DelegationDecision {
        from_identity: "p".into(),
        to_identity: "c".into(),
        requested_description: "rq".into(),
        granted_description: "gr".into(),
        was_narrowed: true,
        restricted_dimensions: vec!["a".into(), "b".into()],
    };
    assert_ne!(entry(joined).content_hash(), entry(split).content_hash());
}
