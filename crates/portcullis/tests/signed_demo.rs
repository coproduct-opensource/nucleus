//! World-class demo: untrusted content inspected, blocked from privileged
//! action, with a **signed receipt** showing the forbidden causal chain.
//!
//! This is the moonshot requirement #16 — an agent reads a malicious
//! public GitHub issue, attempts to exfiltrate private repo data via PR
//! creation, and is blocked. The receipt is Ed25519-signed and verifiable.

use portcullis::kernel::Kernel;
// sign_receipt and verify_receipt are used by the kernel internally
// when set_signing_key() is configured — imported here for documentation.
use portcullis::{Operation, PermissionLattice};
use portcullis_core::flow::NodeKind;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

#[test]
fn invariant_exploit_blocked_with_signed_receipt() {
    // Generate signing key
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let signing_key = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public_key = signing_key.public_key().as_ref().to_vec();

    // Create kernel with flow graph and signing key
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    kernel.set_signing_key(std::sync::Arc::new(signing_key));

    // ── Simulate the Invariant exploit scenario ──
    //
    // 1. User opens a GitHub issue containing a malicious prompt
    //    (public content → Adversarial integrity, NoAuthority)
    let malicious_issue = kernel
        .observe(NodeKind::WebContent, &[])
        .expect("observe web content");

    // 2. Agent reads private repo data
    let private_data = kernel
        .observe(NodeKind::FileRead, &[])
        .expect("observe file read");

    // 3. Model builds a plan that depends on BOTH the malicious issue
    //    and the private data (this is where the attack happens —
    //    the model's plan is tainted by the malicious issue)
    let tainted_plan = kernel
        .observe(NodeKind::ModelPlan, &[malicious_issue, private_data])
        .expect("observe model plan");

    // 4. Agent attempts to create a PR that exfiltrates private data.
    //    The plan depends on the malicious issue → NoAuthority taint
    //    propagates → CreatePr requires Suggestive authority → BLOCKED.
    let (decision, _token) = kernel.decide_with_parents(
        Operation::CreatePr,
        "Create PR with private data",
        &[tainted_plan],
    );

    // ── Verify the verdict ──
    assert!(
        decision.verdict.is_denied(),
        "Expected DENIED, got {:?}",
        decision.verdict
    );

    // ── Verify the receipt is SIGNED ──
    match &decision.verdict {
        portcullis::kernel::Verdict::Deny(portcullis::kernel::DenyReason::FlowViolation {
            rule,
            receipt,
        }) => {
            // The rule that fired
            assert!(
                rule.contains("AuthorityEscalation"),
                "Expected AuthorityEscalation, got: {rule}"
            );

            // The receipt exists and shows the causal chain
            let receipt_text = receipt.as_ref().expect("receipt should exist");
            assert!(
                receipt_text.contains("BLOCKED"),
                "Receipt should say BLOCKED"
            );
            assert!(
                !receipt_text.contains("UNSIGNED"),
                "Receipt should be SIGNED, not unsigned"
            );

            // Print the receipt for visual verification
            println!("\n╔══════════════════════════════════════════════════════════════╗");
            println!("║  SIGNED FLOW RECEIPT — Invariant Exploit Blocked            ║");
            println!("╚══════════════════════════════════════════════════════════════╝");
            println!("{receipt_text}");
        }
        other => panic!("Expected FlowViolation, got {:?}", other),
    }

    // ── Meanwhile: clean-parented writes still work ──
    let clean_file = kernel
        .observe(NodeKind::FileRead, &[])
        .expect("observe clean file");
    let (clean_decision, _) =
        kernel.decide_with_parents(Operation::WriteFiles, "/workspace/fix.rs", &[clean_file]);
    assert!(
        clean_decision.verdict.is_allowed(),
        "Clean-parented write should be allowed"
    );

    println!("\n✓ Malicious issue → private data → PR: BLOCKED (signed receipt)");
    println!("✓ Clean file read → write: ALLOWED");
    println!("✓ Public key: {} bytes", public_key.len());
}
