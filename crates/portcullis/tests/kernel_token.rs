//! Kernel token verification tests (#783) — extracted from kernel.rs (#825).
//!
//! These tests verify that the kernel enforces Ed25519 signature
//! verification on declassification tokens when trusted keys are
//! configured, and falls back to unsigned for backward compatibility.

use portcullis::kernel::{DenyReason, Kernel};
use portcullis::token_sign;
use portcullis::{Operation, PermissionLattice};
use portcullis_core::declassify::{
    DeclassificationRule, DeclassificationToken, DeclassifyAction, TokenApplyResult,
};
use portcullis_core::flow::NodeKind;
use portcullis_core::IntegLevel;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn test_key() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn public_key_bytes(key: &Ed25519KeyPair) -> [u8; 32] {
    let pk = key.public_key().as_ref();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(pk);
    bytes
}

fn make_kernel_with_graph() -> Kernel {
    let perms = PermissionLattice::safe_pr_fixer();
    Kernel::new(perms)
}

fn make_token(node_id: u64) -> DeclassificationToken {
    DeclassificationToken::new(
        node_id,
        DeclassificationRule {
            action: DeclassifyAction::RaiseIntegrity {
                from: IntegLevel::Adversarial,
                to: IntegLevel::Untrusted,
            },
            justification: "Validated search results",
        },
        vec![Operation::WriteFiles],
        u64::MAX,
        "Curated API output".to_string(),
    )
}

#[test]
fn verified_token_applied_with_trusted_keys() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    // Observe web content to get a node
    let node_id = kernel.observe(NodeKind::WebContent, &[]).unwrap();

    // Sign a token targeting that node
    let mut token = make_token(node_id);
    token_sign::sign_token(&mut token, &key);
    assert!(token.is_signed());

    // Apply via kernel — should succeed
    let result = kernel.apply_declassification_token(&token);
    match result {
        Ok(TokenApplyResult::Applied {
            original_label,
            new_label,
        }) => {
            assert_eq!(
                original_label.integrity,
                IntegLevel::Adversarial,
                "original should be Adversarial"
            );
            assert_eq!(
                new_label.integrity,
                IntegLevel::Untrusted,
                "new should be Untrusted after declassification"
            );
        }
        other => panic!("expected Applied with label change, got {:?}", other),
    }
}

#[test]
fn unsigned_token_rejected_when_keys_set() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    let node_id = kernel.observe(NodeKind::WebContent, &[]).unwrap();

    // Create unsigned token (no signature)
    let token = make_token(node_id);
    assert!(!token.is_signed());

    // Apply via kernel — should be rejected
    let result = kernel.apply_declassification_token(&token);
    match result {
        Err(DenyReason::InvalidDeclassification { detail }) => {
            assert!(
                detail.contains("signature verification failed"),
                "expected signature failure detail, got: {detail}"
            );
        }
        other => panic!("expected InvalidDeclassification error, got {:?}", other),
    }
}

#[test]
fn wrong_key_token_rejected() {
    let sign_key = test_key();
    let wrong_key = test_key();
    let mut kernel = make_kernel_with_graph();
    // Set wrong key as trusted
    kernel.set_trusted_keys(vec![public_key_bytes(&wrong_key)]);

    let node_id = kernel.observe(NodeKind::WebContent, &[]).unwrap();

    // Sign with a different key
    let mut token = make_token(node_id);
    token_sign::sign_token(&mut token, &sign_key);

    let result = kernel.apply_declassification_token(&token);
    match result {
        Err(DenyReason::InvalidDeclassification { detail }) => {
            assert!(
                detail.contains("signature verification failed"),
                "expected signature failure detail, got: {detail}"
            );
        }
        other => panic!("expected InvalidDeclassification error, got {:?}", other),
    }
}

#[test]
fn no_keys_refuses_unsigned() {
    // Fail-closed (most-paranoid #3): with NO trusted keys configured there is no
    // authority to verify against, so declassification must be REFUSED — not
    // applied unsigned. (Previously this returned Ok(Applied); that fail-open
    // backward-compat path was removed.)
    let mut kernel = make_kernel_with_graph();

    let node_id = kernel.observe(NodeKind::WebContent, &[]).unwrap();

    let token = make_token(node_id);
    assert!(!token.is_signed());

    let result = kernel.apply_declassification_token(&token);
    match result {
        Err(DenyReason::InvalidDeclassification { detail }) => {
            assert!(
                detail.contains("no trusted public keys"),
                "expected no-keys refusal detail, got: {detail}"
            );
        }
        other => panic!(
            "expected InvalidDeclassification (fail-closed), got {:?}",
            other
        ),
    }
}

#[test]
fn key_rotation_accepts_old_key() {
    let old_key = test_key();
    let new_key = test_key();
    let mut kernel = make_kernel_with_graph();
    // Both old and new keys are trusted
    kernel.set_trusted_keys(vec![public_key_bytes(&new_key), public_key_bytes(&old_key)]);

    let node_id = kernel.observe(NodeKind::WebContent, &[]).unwrap();

    // Sign with old key
    let mut token = make_token(node_id);
    token_sign::sign_token(&mut token, &old_key);

    let result = kernel.apply_declassification_token(&token);
    assert!(
        matches!(result, Ok(TokenApplyResult::Applied { .. })),
        "old key should still be accepted during rotation, got {:?}",
        result
    );
}

#[test]
fn apply_token_for_nonexistent_node_returns_not_found() {
    // #753: flow graph is always present. Applying a token for a
    // nonexistent node returns NodeNotFound (not GraphNotEnabled).
    let key = test_key();
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    let mut token = make_token(42);
    token_sign::sign_token(&mut token, &key);

    let result = kernel.apply_declassification_token(&token);
    assert!(
        matches!(result, Ok(TokenApplyResult::NodeNotFound)),
        "expected NodeNotFound for nonexistent node, got {:?}",
        result
    );
}

// ── One-shot: exercising a token consumes it (HC-6 closure) ──────────────────
//
// The machine spec is capability-primitive's Spike/Declassify.lean: a release
// SPENDS its token (`one_shot`), a refused release does not
// (`no_release_after_spent` guards the ledger, not the refusals), and the
// counter-model `runReplayable` — the ledger that never advances — is exactly
// the shape these tests would catch if the kernel regressed to it.

#[test]
fn first_use_applies_then_identical_replay_is_denied() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    let node_id = kernel.observe(NodeKind::WebContent, &[]).unwrap();
    let mut token = make_token(node_id);
    token_sign::sign_token(&mut token, &key);

    // First use: the authority is exercised.
    match kernel.apply_declassification_token(&token) {
        Ok(TokenApplyResult::Applied { .. }) => {}
        other => panic!("first use must apply, got {other:?}"),
    }

    // Identical replay: refused with the dedicated verdict — BEFORE any graph
    // work, and not as a stringly "invalid": the signature still verifies; the
    // authority is simply spent.
    match kernel.apply_declassification_token(&token) {
        Err(DenyReason::DeclassificationReplayed { target_node }) => {
            assert_eq!(target_node, node_id.to_string());
        }
        other => panic!("replay must be denied as DeclassificationReplayed, got {other:?}"),
    }
}

#[test]
fn two_distinct_tokens_both_apply() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    // Two nodes, two independently signed tokens: one-shot is per-authorization
    // (per signature), not a global "declassified once already" latch.
    let n1 = kernel.observe(NodeKind::WebContent, &[]).unwrap();
    let n2 = kernel.observe(NodeKind::WebContent, &[]).unwrap();
    let mut t1 = make_token(n1);
    let mut t2 = make_token(n2);
    token_sign::sign_token(&mut t1, &key);
    token_sign::sign_token(&mut t2, &key);

    assert!(matches!(
        kernel.apply_declassification_token(&t1),
        Ok(TokenApplyResult::Applied { .. })
    ));
    assert!(matches!(
        kernel.apply_declassification_token(&t2),
        Ok(TokenApplyResult::Applied { .. })
    ));
}

#[test]
fn a_failed_application_does_not_burn_the_token() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    // Mint for a node that does not exist YET (ids are sequential), so the
    // first application fails without exercising any authority…
    let existing = kernel.observe(NodeKind::WebContent, &[]).unwrap();
    let future = existing + 1;
    let mut token = make_token(future);
    token_sign::sign_token(&mut token, &key);

    match kernel.apply_declassification_token(&token) {
        Ok(TokenApplyResult::NodeNotFound) => {}
        other => panic!("expected NodeNotFound for a not-yet-observed node, got {other:?}"),
    }

    // …then the obstacle clears, and the SAME token still works: a refusal is
    // not a spend. (If the kernel burnt on refusal, this would now be
    // DeclassificationReplayed — the over-eager-ledger defect.)
    let created = kernel.observe(NodeKind::WebContent, &[]).unwrap();
    assert_eq!(
        created, future,
        "observe() ids must be sequential for this test"
    );
    match kernel.apply_declassification_token(&token) {
        Ok(TokenApplyResult::Applied { .. }) => {}
        other => panic!("the un-exercised token must still apply, got {other:?}"),
    }

    // And now that it HAS been exercised, it is spent.
    assert!(matches!(
        kernel.apply_declassification_token(&token),
        Err(DenyReason::DeclassificationReplayed { .. })
    ));
}
