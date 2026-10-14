//! Causal DAG integration tests (step 6 of bright-knitting-mitten), moved out
//! of `kernel_tests.rs` when #3459 named each action's control and data
//! parents and the file outgrew the line ratchet's default ceiling.

use super::*;
use crate::flow_graph::ActionParents;
use crate::PermissionLattice;

#[test]
fn dag_independent_branches_no_overtaint() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let user = kernel
        .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
        .unwrap();
    // Task A: web content (adversarial)
    let web_id = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();
    // Task B: local file (trusted) — NO dependency on web
    let file_id = kernel
        .observe(portcullis_core::flow::NodeKind::FileRead, &[])
        .unwrap();

    // Task B write depends ONLY on file — ALLOWED
    let (d, _) = kernel.decide_with_parents(
        Operation::WriteFiles,
        "/out.txt",
        ActionParents {
            control: &[user],
            data: &[file_id],
        },
    );
    assert!(
        d.verdict.is_allowed(),
        "File-only write should be allowed, got {:?}",
        d.verdict
    );
    assert!(d.flow_node_id.is_some());

    // Task A write depends on web — DENIED
    let (d, _) = kernel.decide_with_parents(
        Operation::WriteFiles,
        "/web.txt",
        ActionParents {
            control: &[user],
            data: &[web_id],
        },
    );
    assert!(
        d.verdict.is_denied(),
        "Web-tainted write should be denied, got {:?}",
        d.verdict
    );
    assert!(matches!(
        d.verdict,
        Verdict::Deny(DenyReason::FlowViolation { .. })
    ));
}

#[test]
fn dag_transitive_taint_propagation() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let user = kernel
        .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
        .unwrap();
    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();
    // Model plan derived from web content, rooted in the user's prompt
    let plan = kernel
        .observe(portcullis_core::flow::NodeKind::ModelPlan, &[user, web])
        .unwrap();

    // Write directed by the plan (transitively depends on web) — DENIED
    let (d, _) = kernel.decide_with_parents(
        Operation::WriteFiles,
        "/derived.txt",
        ActionParents {
            control: &[plan],
            data: &[],
        },
    );
    assert!(
        d.verdict.is_denied(),
        "Transitive web taint should propagate, got {:?}",
        d.verdict
    );
}

#[test]
fn dag_clean_chain_allowed() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let user = kernel
        .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
        .unwrap();
    let file = kernel
        .observe(portcullis_core::flow::NodeKind::FileRead, &[user])
        .unwrap();
    let plan = kernel
        .observe(portcullis_core::flow::NodeKind::ModelPlan, &[user, file])
        .unwrap();

    // Write directed by a clean chain: user → (file) → plan — ALLOWED
    let (d, token) = kernel.decide_with_parents(
        Operation::WriteFiles,
        "/clean.txt",
        ActionParents {
            control: &[plan],
            data: &[],
        },
    );
    assert!(d.verdict.is_allowed());
    assert!(token.is_some());
    assert!(d.flow_node_id.is_some());
}

#[test]
fn dag_denied_action_produces_receipt() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let user = kernel
        .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
        .unwrap();
    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();

    let (d, _) = kernel.decide_with_parents(
        Operation::CreatePr,
        "my-pr",
        ActionParents {
            control: &[user],
            data: &[web],
        },
    );
    assert!(d.verdict.is_denied());
    match &d.verdict {
        Verdict::Deny(DenyReason::FlowViolation { receipt, .. }) => {
            assert!(
                receipt.is_some(),
                "Denied DAG action should include receipt"
            );
            assert!(
                receipt.as_ref().unwrap().contains("BLOCKED"),
                "Receipt should contain BLOCKED"
            );
        }
        other => panic!("Expected FlowViolation, got {:?}", other),
    }
}

#[test]
fn dag_always_on_even_capability_only() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::capability_only(perms);
    // capability_only() still has a flow graph — decide_with_parents uses the DAG

    let (d, _) = kernel.decide_with_parents(
        Operation::ReadFiles,
        "/workspace/main.rs",
        ActionParents {
            control: &[],
            data: &[],
        },
    );
    assert!(d.verdict.is_allowed());
    assert!(
        d.flow_node_id.is_some(),
        "DAG always on → should have flow_node_id"
    );
}

#[test]
fn dag_capability_check_still_applies() {
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    let user = kernel
        .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
        .unwrap();

    // DAG says allow (clean parents), but capability lattice says never for GitPush
    let (d, _) = kernel.decide_with_parents(
        Operation::GitPush,
        "origin/main",
        ActionParents {
            control: &[user],
            data: &[],
        },
    );
    assert!(
        d.verdict.is_denied(),
        "Capability check should still apply even when DAG allows, got {:?}",
        d.verdict
    );
    assert!(matches!(
        d.verdict,
        Verdict::Deny(DenyReason::InsufficientCapability)
    ));
}

#[test]
fn dag_bypasses_flat_flow_label() {
    // Issue #365: when both flow systems are enabled, the DAG should
    // supersede the flat label — not double-deny.
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_control(); // flat label

    let user = kernel
        .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
        .unwrap();
    // Read web content — taints the flat session label
    let _web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();
    // Also taint the flat label via a regular decide()
    let (d, _) = kernel.decide(Operation::WebFetch, "https://example.com");
    assert!(d.verdict.is_allowed());

    // Now use the DAG with clean parents — should be allowed
    // even though the flat label is tainted
    let file = kernel
        .observe(portcullis_core::flow::NodeKind::FileRead, &[])
        .unwrap();
    let (d, _) = kernel.decide_with_parents(
        Operation::WriteFiles,
        "/clean.txt",
        ActionParents {
            control: &[user],
            data: &[file],
        },
    );
    assert!(
        d.verdict.is_allowed(),
        "DAG clean parents should override flat taint, got {:?}",
        d.verdict
    );
}

#[test]
fn dag_observe_works_on_capability_only() {
    // #753: flow graph is always present, even on capability_only kernels
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::capability_only(perms);
    let result = kernel.observe(portcullis_core::flow::NodeKind::FileRead, &[]);
    assert!(
        result.is_ok(),
        "observe() should succeed — DAG is always on"
    );
}

#[test]
fn dag_declassification_allows_validated_tool() {
    use portcullis_core::declassify::{DeclassificationRule, DeclassifyAction};
    use portcullis_core::IntegLevel;

    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);

    // Add declassification rule: search API output gets Adversarial → Untrusted
    kernel.add_declassification_rule(DeclassificationRule {
        action: DeclassifyAction::RaiseIntegrity {
            from: IntegLevel::Adversarial,
            to: IntegLevel::Untrusted,
        },
        justification: "Search API returns curated content".to_string(),
    });

    let user = kernel
        .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
        .unwrap();
    // Observe web content — normally Adversarial/NoAuthority
    let web = kernel
        .observe(portcullis_core::flow::NodeKind::WebContent, &[])
        .unwrap();

    // Without declassification, web content → write would be DENIED
    // (NoAuthority cannot steer privileged actions).
    // But the rule raised integrity from Adversarial → Untrusted.
    // Authority is still NoAuthority, so writes are still denied by
    // the authority check. This verifies declassification fires but
    // doesn't grant more than it should.
    let (d, _) = kernel.decide_with_parents(
        Operation::WriteFiles,
        "/out.txt",
        ActionParents {
            control: &[user],
            data: &[web],
        },
    );
    assert!(
        d.verdict.is_denied(),
        "Authority is still NoAuthority — write should be denied even with raised integrity"
    );
}

#[test]
fn dag_declassification_authority_upgrade_lifts_no_authority_cap() {
    // #3459: data caps authority only when NoAuthority (or adversarial). An HTTP
    // response is Untrusted/NoAuthority until a declassification raises it.
    use portcullis_core::declassify::{DeclassificationRule, DeclassifyAction};
    use portcullis_core::AuthorityLevel;

    let write_from_http = |kernel: &mut Kernel| {
        let user = kernel
            .observe(portcullis_core::flow::NodeKind::UserPrompt, &[])
            .unwrap();
        let http = kernel
            .observe(portcullis_core::flow::NodeKind::HTTPResponse, &[])
            .unwrap();
        kernel
            .decide_with_parents(
                Operation::WriteFiles,
                "/out.txt",
                ActionParents {
                    control: &[user],
                    data: &[http],
                },
            )
            .0
    };

    // Without the upgrade: NoAuthority data caps the user's authority.
    let mut strict = Kernel::new(PermissionLattice::safe_pr_fixer());
    let d = write_from_http(&mut strict);
    assert!(
        d.verdict.is_denied(),
        "NoAuthority data must cap a write even under the user's prompt, got {:?}",
        d.verdict
    );

    // With the upgrade (NoAuthority ≤ Informational → Suggestive): allowed.
    let mut kernel = Kernel::new(PermissionLattice::safe_pr_fixer());
    kernel.add_declassification_rule(DeclassificationRule {
        action: DeclassifyAction::RaiseAuthority {
            from: AuthorityLevel::Informational,
            to: AuthorityLevel::Suggestive,
        },
        justification: "Validated API output".to_string(),
    });
    let d = write_from_http(&mut kernel);
    assert!(
        d.verdict.is_allowed(),
        "Declassified HTTP response should allow write, got {:?}",
        d.verdict
    );
}
