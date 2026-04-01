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
    let mut kernel = Kernel::new(perms);
    kernel.enable_flow_graph();
    kernel
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
fn backward_compat_no_keys_allows_unsigned() {
    // No trusted keys configured — unsigned tokens should work
    let mut kernel = make_kernel_with_graph();

    let node_id = kernel.observe(NodeKind::WebContent, &[]).unwrap();

    let token = make_token(node_id);
    assert!(!token.is_signed());

    // Apply without keys — backward compatible, should succeed
    let result = kernel.apply_declassification_token(&token);
    match result {
        Ok(TokenApplyResult::Applied { .. }) => {} // expected
        other => panic!("expected Applied (backward compat), got {:?}", other),
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
fn apply_token_without_flow_graph_returns_error() {
    let key = test_key();
    let perms = PermissionLattice::safe_pr_fixer();
    let mut kernel = Kernel::new(perms);
    // Do NOT enable flow graph
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    let mut token = make_token(42);
    token_sign::sign_token(&mut token, &key);

    let result = kernel.apply_declassification_token(&token);
    match result {
        Err(DenyReason::InvalidDeclassification { detail }) => {
            assert!(
                detail.contains("flow graph not enabled"),
                "expected flow graph error, got: {detail}"
            );
        }
        other => panic!(
            "expected InvalidDeclassification (flow graph), got {:?}",
            other
        ),
    }
}
