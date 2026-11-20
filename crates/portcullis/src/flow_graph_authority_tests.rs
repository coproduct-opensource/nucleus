//! Authority from the control chain (#3459).
//!
//! The rule under test: an action's authority comes from the parents named as
//! CONTROL (a `UserPrompt`, or a `ModelPlan` rooted in one); every other label
//! dimension — and the stored label — from the full join over all parents.
//! `NoAuthority` and `Adversarial` data still cap authority exactly as before.
//!
//! The first test is the reason the rule exists: once a file read carries
//! `Informational` authority (#3431 step 2), read → write/run/commit must keep
//! working when a user prompt directed it. On `main` before this change the
//! same graph — every parent joined, authority included — denies all four with
//! `AuthorityEscalation`.

use super::*;
use portcullis_core::flow::{check_flow, FlowDenyReason};

const NOW: u64 = 1_000;

/// A file read labelled the way #3431 step 2 will label one: `FileRead`'s
/// intrinsic label with `Informational` authority. Built locally, through the
/// caller-labelled observe path, so this test does not depend on (or move) the
/// wasm-embedded intrinsic.
fn informational_file_read(g: &mut FlowGraph) -> NodeId {
    let mut label = intrinsic_label(NodeKind::FileRead, NOW);
    label.authority = AuthorityLevel::Informational;
    g.observe_with_label_and_content_hash(
        NodeKind::FileRead,
        label,
        &[],
        NOW,
        ContentHash::from_bytes([0x11; 32]),
    )
    .unwrap()
}

/// The workflows the rule must keep working: write, edit, run, commit.
const ACT_ON_A_READ: [Operation; 4] = [
    Operation::WriteFiles,
    Operation::EditFiles,
    Operation::RunBash,
    Operation::GitCommit,
];

/// Every operation whose sink (as `insert_action` classifies it) requires more
/// than `NoAuthority`.
fn privileged() -> impl Iterator<Item = Operation> {
    Operation::ALL
        .into_iter()
        .filter(|&op| default_sink_class(op).required_authority() > AuthorityLevel::NoAuthority)
}

#[test]
fn informational_file_read_does_not_block_acting_on_it_under_a_prompt() {
    for op in ACT_ON_A_READ {
        let mut g = FlowGraph::new();
        let user = g
            .insert_observation(NodeKind::UserPrompt, &[], NOW)
            .unwrap();
        let file = informational_file_read(&mut g);
        let d = g
            .insert_action(
                op,
                ActionParents {
                    control: &[user],
                    data: &[file],
                },
                NOW,
            )
            .unwrap();
        assert_eq!(
            d.verdict,
            FlowVerdict::Allow,
            "{op:?} after an informational read"
        );
        assert_eq!(
            d.authority,
            AuthorityLevel::Directive,
            "{op:?}: the prompt's authority"
        );
        // The stored label is still the full join: the file's authority is in it.
        assert_eq!(d.label.authority, AuthorityLevel::Informational, "{op:?}");
        assert_eq!(
            g.get(d.node_id).unwrap().label.authority,
            AuthorityLevel::Informational
        );
        // A receipt recomputed from stored state judges the same way.
        let receipt = g.build_receipt_for(d.node_id, NOW).unwrap();
        assert_eq!(
            receipt.verdict(),
            d.verdict,
            "{op:?}: receipt recomputation"
        );
    }
}

#[test]
fn a_file_or_web_content_named_as_control_confers_no_authority() {
    for op in ACT_ON_A_READ {
        let mut g = FlowGraph::new();
        let informational = informational_file_read(&mut g);
        // Today's FileRead intrinsic is Directive — still not an instruction.
        let directive_file = g.insert_observation(NodeKind::FileRead, &[], NOW).unwrap();
        let web = g
            .insert_observation(NodeKind::WebContent, &[], NOW)
            .unwrap();
        for control in [informational, directive_file, web] {
            let d = g
                .insert_action(
                    op,
                    ActionParents {
                        control: &[control],
                        data: &[],
                    },
                    NOW,
                )
                .unwrap();
            assert_eq!(
                d.verdict,
                FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation),
                "{op:?} with node {control} as the only control parent"
            );
            assert_eq!(d.authority, AuthorityLevel::NoAuthority);
        }
    }
}

#[test]
fn no_control_parent_has_no_authority() {
    let mut g = FlowGraph::new();
    let file = g.insert_observation(NodeKind::FileRead, &[], NOW).unwrap();
    let mut seen = 0;
    for op in privileged() {
        for data in [&[][..], &[file][..]] {
            let d = g
                .insert_action(op, ActionParents { control: &[], data }, NOW)
                .unwrap();
            assert_eq!(
                d.verdict,
                FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation),
                "{op:?} with no control parent (data {data:?}) must not default to authority"
            );
            seen += 1;
        }
    }
    assert!(seen >= 18, "the privileged set is not empty: {seen}");
    // A read needs no authority, so it still works without one.
    for op in [
        Operation::ReadFiles,
        Operation::GlobSearch,
        Operation::GrepSearch,
    ] {
        let d = g
            .insert_action(
                op,
                ActionParents {
                    control: &[],
                    data: &[],
                },
                NOW,
            )
            .unwrap();
        assert_eq!(d.verdict, FlowVerdict::Allow, "{op:?}");
    }
}

/// Adversarial data is judged exactly as before the split: the verdict equals
/// `check_flow` over the full-join label, authority included — today's rule —
/// for every operation, under a Directive control chain.
#[test]
fn adversarial_data_parent_denies_exactly_as_before() {
    for kind in [
        NodeKind::WebContent,
        NodeKind::McpToolResult,
        NodeKind::McpToolDescription,
        NodeKind::SponsoredOffer,
        NodeKind::PDFContent,
    ] {
        for op in Operation::ALL {
            let mut g = FlowGraph::new();
            let user = g
                .insert_observation(NodeKind::UserPrompt, &[], NOW)
                .unwrap();
            let bad = g.insert_observation(kind, &[], NOW).unwrap();
            let summary = g
                .insert_observation(NodeKind::Summarization, &[bad], NOW)
                .unwrap();
            for data in [bad, summary] {
                let d = g
                    .insert_action(
                        op,
                        ActionParents {
                            control: &[user],
                            data: &[data],
                        },
                        NOW,
                    )
                    .unwrap();
                let stored = *g.get(d.node_id).unwrap();
                assert_eq!(
                    d.verdict,
                    check_flow(&stored, NOW),
                    "{kind:?} → {op:?}: not judged as before the split"
                );
                if privileged().any(|p| p == op) {
                    assert!(
                        matches!(d.verdict, FlowVerdict::Deny(_)),
                        "{kind:?} → {op:?} must deny"
                    );
                }
            }
        }
    }
}

#[test]
fn no_authority_data_still_caps_a_prompted_action() {
    let mut g = FlowGraph::new();
    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], NOW)
        .unwrap();
    // Untrusted, not adversarial — but NoAuthority: it may not steer a write.
    let http = g
        .insert_observation(NodeKind::HTTPResponse, &[], NOW)
        .unwrap();
    let d = g
        .insert_action(
            Operation::WriteFiles,
            ActionParents {
                control: &[user],
                data: &[http],
            },
            NOW,
        )
        .unwrap();
    assert_eq!(
        d.verdict,
        FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
    );
}

#[test]
fn web_content_cannot_raise_authority() {
    let mut g = FlowGraph::new();
    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], NOW)
        .unwrap();
    let web = g
        .insert_observation(NodeKind::WebContent, &[], NOW)
        .unwrap();
    // Named alongside the prompt as a second instruction source, web content
    // lowers the meet; it never lifts it.
    let d = g
        .insert_action(
            Operation::WriteFiles,
            ActionParents {
                control: &[user, web],
                data: &[],
            },
            NOW,
        )
        .unwrap();
    assert_eq!(d.authority, AuthorityLevel::NoAuthority);
    assert_eq!(
        d.verdict,
        FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
    );
    // A plan derived from web content under the prompt confers nothing.
    let plan = g
        .insert_observation(NodeKind::ModelPlan, &[user, web], NOW)
        .unwrap();
    let d = g
        .insert_action(
            Operation::WriteFiles,
            ActionParents {
                control: &[plan],
                data: &[],
            },
            NOW,
        )
        .unwrap();
    assert_eq!(d.authority, AuthorityLevel::NoAuthority);
    assert!(matches!(d.verdict, FlowVerdict::Deny(_)));
}

#[test]
fn a_plan_confers_authority_only_when_rooted_in_a_prompt() {
    let mut g = FlowGraph::new();
    let user = g
        .insert_observation(NodeKind::UserPrompt, &[], NOW)
        .unwrap();
    let file = informational_file_read(&mut g);
    let rooted = g
        .insert_observation(NodeKind::ModelPlan, &[user, file], NOW)
        .unwrap();
    let nested = g
        .insert_observation(NodeKind::ModelPlan, &[rooted], NOW)
        .unwrap();
    let unrooted = g
        .insert_observation(NodeKind::ModelPlan, &[file], NOW)
        .unwrap();
    let parentless = g.insert_observation(NodeKind::ModelPlan, &[], NOW).unwrap();
    let write = |g: &mut FlowGraph, plan| {
        g.insert_action(
            Operation::WriteFiles,
            ActionParents {
                control: &[plan],
                data: &[],
            },
            NOW,
        )
        .unwrap()
    };
    for plan in [rooted, nested] {
        let d = write(&mut g, plan);
        assert_eq!(d.verdict, FlowVerdict::Allow, "plan {plan} is rooted");
        assert_eq!(d.authority, AuthorityLevel::Directive);
    }
    for plan in [unrooted, parentless] {
        let d = write(&mut g, plan);
        assert_eq!(
            d.verdict,
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation),
            "plan {plan} has no prompt in its control chain"
        );
    }
}
