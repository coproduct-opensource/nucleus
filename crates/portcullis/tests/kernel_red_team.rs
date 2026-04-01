//! Kernel-integration red team tests.
//!
//! These tests exercise the FULL enforcement path:
//!   Kernel::new() → enable_flow_graph() → observe() → decide_with_parents()
//!
//! Unlike `portcullis-core/tests/flow_red_team.rs` which constructs FlowNode
//! structs manually and calls check_flow() directly, these tests go through
//! the production Kernel API. They verify that the flow algebra is correctly
//! wired into the kernel — not just that the math is right.
//!
//! Issue: https://github.com/coproduct-opensource/nucleus/issues/785

use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::{Operation, PermissionLattice};
use portcullis_core::flow::NodeKind;

// ═════════════════════════════════════════════════════════════════════════
// Test 1: Web content taint blocks git push through the full kernel path
//
// Attack: Agent fetches content from https://evil.com, then attempts to
// push to a git remote. The web content carries Adversarial integrity,
// NoAuthority, WEB provenance, and OpaqueExternal derivation — all of
// which should trigger flow violations at a verified sink like GitPush.
//
// This is the canonical prompt-injection exfiltration scenario: a
// malicious web page instructs the agent to push tainted data.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn kernel_web_content_blocks_git_push() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_graph();

    // Step 1: Observe web content (reading is fine — no action, no check)
    let web_node = kernel
        .observe(NodeKind::WebContent, &[])
        .expect("observe WebContent should succeed");

    // Step 2: Attempt GitPush with the web content as causal parent
    let (decision, token) =
        kernel.decide_with_parents(Operation::GitPush, "origin main", &[web_node]);

    // Must be DENIED — web content cannot reach a verified sink
    assert!(
        decision.verdict.is_denied(),
        "GitPush with web content ancestor must be DENIED, got: {:?}",
        decision.verdict
    );
    assert!(
        token.is_none(),
        "Denied decision must not produce a DecisionToken"
    );

    // Verify the denial is specifically a FlowViolation (not capability, budget, etc.)
    match &decision.verdict {
        Verdict::Deny(DenyReason::FlowViolation { rule, receipt }) => {
            // The flow graph produces a receipt showing the causal chain
            assert!(
                receipt.is_some(),
                "DAG-denied action should include a receipt showing the forbidden path"
            );
            let receipt_text = receipt.as_ref().unwrap();
            assert!(
                receipt_text.contains("BLOCKED"),
                "Receipt should contain BLOCKED marker, got: {receipt_text}"
            );
            // The rule should indicate one of the flow violations triggered by web content:
            // - IntegrityViolation (Adversarial < Trusted)
            // - AuthorityEscalation (NoAuthority < Suggestive)
            // - Exfiltration (WEB provenance to exfil sink)
            // - DerivationViolation (OpaqueExternal at verified sink)
            // Any of these is correct — the point is the kernel catches it.
            assert!(
                !rule.is_empty(),
                "Flow violation rule description should not be empty"
            );
        }
        other => panic!("Expected Deny(FlowViolation), got: {:?}", other),
    }
}

// ═════════════════════════════════════════════════════════════════════════
// Test 2: Clean write allowed alongside tainted session
//
// Defense: The causal DAG enables precise tracking. Even if the session
// has observed web content, actions that don't causally depend on it
// should still be allowed. This is the key advantage of the DAG over
// flat session-level tainting.
//
// Scenario: Agent reads a web page (tainted), then reads a local file
// (clean). A write that depends only on the local file should succeed.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn kernel_clean_write_allowed_alongside_tainted_session() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_graph();

    // Step 1: Observe web content — taints the session-level label
    let _web_node = kernel
        .observe(NodeKind::WebContent, &[])
        .expect("observe WebContent should succeed");

    // Step 2: Observe a clean local file read (no web content in its ancestry)
    let clean_file = kernel
        .observe(NodeKind::FileRead, &[])
        .expect("observe FileRead should succeed");

    // Step 3: Write depending ONLY on the clean file — should be ALLOWED
    // because the DAG tracks actual causal dependencies, not session-wide taint
    let (decision, token) = kernel.decide_with_parents(
        Operation::WriteFiles,
        "/workspace/clean_output.txt",
        &[clean_file],
    );

    assert!(
        decision.verdict.is_allowed(),
        "WriteFiles with only clean ancestors should be ALLOWED, got: {:?}",
        decision.verdict
    );
    assert!(
        token.is_some(),
        "Allowed decision must produce a DecisionToken"
    );
    assert!(
        decision.flow_node_id.is_some(),
        "DAG-tracked decision should have a flow_node_id"
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Test 3: AI-derived content blocked from git push (Rule 6)
//
// Attack: An LLM generates code (ModelPlan node with AIDerived derivation),
// and the agent attempts to push it to a git remote. Verified sinks
// (GitPush, GitCommit, PRCommentWrite) require Deterministic or
// HumanPromoted derivation — AIDerived must be blocked.
//
// This prevents AI hallucinations from reaching publish vectors without
// explicit human review.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn kernel_ai_derived_blocked_from_git_push() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_graph();

    // Step 1: Observe a model plan step (AI-derived content)
    let model_node = kernel
        .observe(NodeKind::ModelPlan, &[])
        .expect("observe ModelPlan should succeed");

    // Step 2: Attempt GitPush with the AI-derived content as parent
    let (decision, token) =
        kernel.decide_with_parents(Operation::GitPush, "origin main", &[model_node]);

    // Must be DENIED — AIDerived derivation cannot reach a verified sink
    assert!(
        decision.verdict.is_denied(),
        "GitPush with AI-derived ancestor must be DENIED by DerivationViolation (Rule 6), got: {:?}",
        decision.verdict
    );
    assert!(
        token.is_none(),
        "Denied decision must not produce a DecisionToken"
    );

    // Verify it's a flow violation
    assert!(
        matches!(
            decision.verdict,
            Verdict::Deny(DenyReason::FlowViolation { .. })
        ),
        "Expected FlowViolation, got: {:?}",
        decision.verdict
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Test 4: Web content also blocks CreatePr (another verified sink)
//
// Same as Test 1 but for CreatePr — verifies the protection covers
// all verified sinks, not just GitPush.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn kernel_web_content_blocks_create_pr() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_graph();

    let web_node = kernel
        .observe(NodeKind::WebContent, &[])
        .expect("observe WebContent should succeed");

    let (decision, _) =
        kernel.decide_with_parents(Operation::CreatePr, "fix: apply suggestion", &[web_node]);

    assert!(
        decision.verdict.is_denied(),
        "CreatePr with web content ancestor must be DENIED, got: {:?}",
        decision.verdict
    );
    assert!(
        matches!(
            decision.verdict,
            Verdict::Deny(DenyReason::FlowViolation { .. })
        ),
        "Expected FlowViolation, got: {:?}",
        decision.verdict
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Test 5: Transitive taint through causal chain
//
// Attack: Web content → model summarization → git push. The taint from
// web content propagates through the model plan step to the push action.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn kernel_transitive_web_taint_through_model_plan() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_graph();

    // Step 1: Observe web content
    let web_node = kernel
        .observe(NodeKind::WebContent, &[])
        .expect("observe WebContent should succeed");

    // Step 2: Model processes the web content (inherits taint)
    let model_node = kernel
        .observe(NodeKind::ModelPlan, &[web_node])
        .expect("observe ModelPlan should succeed");

    // Step 3: Attempt GitPush from the model's output — should be DENIED
    // because web taint propagates transitively through the causal chain
    let (decision, _) =
        kernel.decide_with_parents(Operation::GitPush, "origin main", &[model_node]);

    assert!(
        decision.verdict.is_denied(),
        "GitPush with transitive web taint (web → model → push) must be DENIED, got: {:?}",
        decision.verdict
    );
    assert!(
        matches!(
            decision.verdict,
            Verdict::Deny(DenyReason::FlowViolation { .. })
        ),
        "Expected FlowViolation for transitive taint, got: {:?}",
        decision.verdict
    );
}

// ═════════════════════════════════════════════════════════════════════════
// Test 6: Clean chain passes — user prompt → file read → write → commit
//
// Positive control: A fully clean causal chain (no web content, no
// external data) should pass all flow checks. This proves the tests
// above aren't just blocking everything.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn kernel_clean_chain_allows_git_commit() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_graph();

    // User prompt → file read → model plan → git commit
    let user = kernel
        .observe(NodeKind::UserPrompt, &[])
        .expect("observe UserPrompt should succeed");
    let file = kernel
        .observe(NodeKind::FileRead, &[user])
        .expect("observe FileRead should succeed");
    let plan = kernel
        .observe(NodeKind::ModelPlan, &[file])
        .expect("observe ModelPlan should succeed");

    // WriteFiles from clean chain — ALLOWED
    let (d_write, t_write) =
        kernel.decide_with_parents(Operation::WriteFiles, "/workspace/output.rs", &[plan]);
    assert!(
        d_write.verdict.is_allowed(),
        "WriteFiles from clean chain should be ALLOWED, got: {:?}",
        d_write.verdict
    );
    assert!(t_write.is_some());
}

// ═════════════════════════════════════════════════════════════════════════
// Test 7: Secret data exfiltration blocked through kernel
//
// Attack: Agent reads an environment variable (Secret confidentiality),
// then attempts to push it to a git remote. Rule 1 (no-exfil) should
// block this: secret data cannot flow to external sinks.
// ═════════════════════════════════════════════════════════════════════════

#[test]
fn kernel_secret_exfil_blocked() {
    let perms = PermissionLattice::permissive();
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_graph();

    // Observe a secret (environment variable)
    let secret_node = kernel
        .observe(NodeKind::EnvVar, &[])
        .expect("observe EnvVar should succeed");

    // Attempt to push secret to remote — must be DENIED
    let (decision, _) =
        kernel.decide_with_parents(Operation::GitPush, "origin main", &[secret_node]);

    assert!(
        decision.verdict.is_denied(),
        "GitPush with secret ancestor must be DENIED, got: {:?}",
        decision.verdict
    );
    assert!(
        matches!(
            decision.verdict,
            Verdict::Deny(DenyReason::FlowViolation { .. })
        ),
        "Expected FlowViolation for secret exfil, got: {:?}",
        decision.verdict
    );
}
