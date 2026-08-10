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
use portcullis_core::ContentHash;
use portcullis_core::IntegLevel;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

/// A fixed, non-zero recorded value identity (SHA-256 stand-in) that every
/// value-bound token in these tests commits to. Non-zero so a token bound to it
/// is `is_value_bound()`.
const VALUE_ID: [u8; 32] = [0x5Au8; 32];

/// A DIFFERENT value identity — a substituted value the governor did NOT
/// authorize. Used to prove a value-bound release is refused for it.
const OTHER_VALUE_ID: [u8; 32] = [0xA5u8; 32];

/// Observe a data-source node carrying [`VALUE_ID`] as its monitor-recorded
/// content hash, so a token committing to `VALUE_ID` value-binds to it.
fn observe_hashed(kernel: &mut Kernel, kind: NodeKind) -> u64 {
    kernel
        .observe_with_content_hash(kind, &[], ContentHash::from_bytes(VALUE_ID))
        .unwrap()
}

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
            justification: "Validated search results".to_string(),
        },
        vec![Operation::WriteFiles],
        u64::MAX,
        "Curated API output".to_string(),
    )
    // Value-bind every token to the recorded identity `observe_hashed` records,
    // so the Phase-3 gate admits them; the substitution/unbound/missing cases
    // are exercised explicitly below.
    .with_content_commitment(VALUE_ID)
}

#[test]
fn verified_token_applied_with_trusted_keys() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    // Observe web content to get a node
    let node_id = observe_hashed(&mut kernel, NodeKind::WebContent);

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

    let node_id = observe_hashed(&mut kernel, NodeKind::WebContent);

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

    let node_id = observe_hashed(&mut kernel, NodeKind::WebContent);

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

    let node_id = observe_hashed(&mut kernel, NodeKind::WebContent);

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

    let node_id = observe_hashed(&mut kernel, NodeKind::WebContent);

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

    let node_id = observe_hashed(&mut kernel, NodeKind::WebContent);
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
    let n1 = observe_hashed(&mut kernel, NodeKind::WebContent);
    let n2 = observe_hashed(&mut kernel, NodeKind::WebContent);
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
    let existing = observe_hashed(&mut kernel, NodeKind::WebContent);
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
    let created = observe_hashed(&mut kernel, NodeKind::WebContent);
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

#[test]
fn second_token_on_a_declassified_node_is_refused_and_not_burned() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    let node = observe_hashed(&mut kernel, NodeKind::WebContent);
    let mut first = make_token(node);
    token_sign::sign_token(&mut first, &key);
    assert!(matches!(
        kernel.apply_declassification_token(&first),
        Ok(TokenApplyResult::Applied { .. })
    ));

    // A DISTINCT token for the same node (different justification ⇒
    // different canonical bytes ⇒ different signature): refused, because a
    // node is declassified at most once.
    let mut second = make_token(node);
    second.justification = "a second, distinct authorization".to_string();
    token_sign::sign_token(&mut second, &key);
    assert!(matches!(
        kernel.apply_declassification_token(&second),
        Ok(TokenApplyResult::AlreadyDeclassified)
    ));

    // The refusal did not burn the second token: retrying yields the same
    // refusal, NOT DeclassificationReplayed. Only Applied spends.
    assert!(matches!(
        kernel.apply_declassification_token(&second),
        Ok(TokenApplyResult::AlreadyDeclassified)
    ));

    // And the first token's ledger entry is intact: its replay is still the
    // dedicated replay verdict.
    assert!(matches!(
        kernel.apply_declassification_token(&first),
        Err(DenyReason::DeclassificationReplayed { .. })
    ));
}

/// The governor wire contract: a signed token survives a JSON round-trip
/// byte-for-byte, so the signature the governor computed over `canonical_bytes`
/// still verifies after transport, and the token still applies live. This is
/// the property the `POST /v1/declassify` endpoint depends on — if serde
/// dropped or reordered a signed field, the endpoint would reject every real
/// token. Gated on `serde`, which the tool-proxy always builds with.
#[cfg(feature = "serde")]
#[test]
fn signed_token_survives_json_roundtrip_and_still_applies() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    let node = observe_hashed(&mut kernel, NodeKind::WebContent);
    let mut token = make_token(node);
    token_sign::sign_token(&mut token, &key);
    assert!(token.is_signed());

    // Round-trip through JSON (the endpoint's wire form).
    let json = serde_json::to_string(&token).expect("token serializes");
    let recovered: DeclassificationToken = serde_json::from_str(&json).expect("token deserializes");
    assert_eq!(recovered, token, "JSON round-trip must be identity");
    // The signature specifically survived (128-hex adapter).
    assert_eq!(recovered.signature, token.signature);

    // And the recovered token — the one a governor would POST — still applies:
    // its signature verifies against the trusted key over the same bytes.
    match kernel.apply_declassification_token(&recovered) {
        Ok(TokenApplyResult::Applied { .. }) => {}
        other => panic!("recovered token must apply, got {other:?}"),
    }
    // One-shot holds across the wire: the same recovered token is now spent.
    assert!(matches!(
        kernel.apply_declassification_token(&recovered),
        Err(DenyReason::DeclassificationReplayed { .. })
    ));
}

/// A token tampered with AFTER signing — the classic wire attack — is rejected:
/// deserialization succeeds (it is well-formed JSON) but the signature no
/// longer matches the mutated `allowed_sinks`, so the kernel refuses it. This
/// is what stops a workload from widening a governor's grant in transit.
#[cfg(feature = "serde")]
#[test]
fn tampering_with_a_signed_token_over_the_wire_is_rejected() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    let node = observe_hashed(&mut kernel, NodeKind::WebContent);
    let mut token = make_token(node); // signed for [WriteFiles]
    token_sign::sign_token(&mut token, &key);

    let json = serde_json::to_string(&token).unwrap();
    let mut tampered: DeclassificationToken = serde_json::from_str(&json).unwrap();
    // The adversary widens the grant to a privileged sink after signing.
    tampered.allowed_sinks.push(Operation::GitPush);

    match kernel.apply_declassification_token(&tampered) {
        Err(DenyReason::InvalidDeclassification { .. }) => {}
        other => panic!("tampered token must be rejected, got {other:?}"),
    }
}

// ── Value binding (Phase 3, C5): a signed release is bound to the SPECIFIC ──
// value the governor committed to. These are the C5-earning tests: a
// substituted value cannot ride a governor's signature, and every refusal is
// fail-closed and NON-BURNING.

/// The headline: a token committing to value V, applied to a node holding a
/// DIFFERENT value V', is DENIED with `ContentMismatch` — the substitution
/// attack. And the refusal does NOT burn the token (a retry yields the same
/// `ContentMismatch`, never `DeclassificationReplayed`).
#[test]
fn value_bound_token_denied_for_a_substituted_value() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    // The node holds OTHER_VALUE_ID; the token commits to VALUE_ID.
    let node = kernel
        .observe_with_content_hash(
            NodeKind::WebContent,
            &[],
            ContentHash::from_bytes(OTHER_VALUE_ID),
        )
        .unwrap();
    let mut token = make_token(node); // committed to VALUE_ID
    token_sign::sign_token(&mut token, &key);

    assert!(
        matches!(
            kernel.apply_declassification_token(&token),
            Ok(TokenApplyResult::ContentMismatch)
        ),
        "a substituted value must be refused with ContentMismatch"
    );
    // Non-burning: the SAME refusal repeats — a mismatch did not spend the token.
    assert!(
        matches!(
            kernel.apply_declassification_token(&token),
            Ok(TokenApplyResult::ContentMismatch)
        ),
        "a ContentMismatch must not burn the token (would be DeclassificationReplayed)"
    );
}

/// The matching value IS released: a token committing to V applied to a node
/// holding V applies (the gate is not deny-everything). This is the flip side
/// of the substitution denial and is what makes the denial non-vacuous.
#[test]
fn value_bound_token_applies_for_the_committed_value() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    let node = observe_hashed(&mut kernel, NodeKind::WebContent); // holds VALUE_ID
    let mut token = make_token(node); // committed to VALUE_ID
    token_sign::sign_token(&mut token, &key);

    assert!(
        matches!(
            kernel.apply_declassification_token(&token),
            Ok(TokenApplyResult::Applied { .. })
        ),
        "the committed value must be released"
    );
}

/// Fail-closed: an UNBOUND token (`content_commitment == [0u8; 32]`) is refused
/// even for a node that has a recorded value, and the refusal does not burn.
#[test]
fn unbound_token_is_denied() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    let node = observe_hashed(&mut kernel, NodeKind::WebContent);
    // Strip the value binding make_token added, then sign the unbound token.
    let mut token = make_token(node).with_content_commitment([0u8; 32]);
    assert!(
        !token.is_value_bound(),
        "test premise: token must be unbound"
    );
    token_sign::sign_token(&mut token, &key);

    assert!(
        matches!(
            kernel.apply_declassification_token(&token),
            Ok(TokenApplyResult::ContentMismatch)
        ),
        "an unbound token must be refused (fail-closed)"
    );
    // Still usable-shaped: a retry is the same refusal, not a replay.
    assert!(matches!(
        kernel.apply_declassification_token(&token),
        Ok(TokenApplyResult::ContentMismatch)
    ));
}

/// Fail-closed: a node with NO monitor-recorded content hash cannot host a
/// value-bound release — even a validly-signed, value-bound token is refused.
#[test]
fn missing_hash_node_is_denied() {
    let key = test_key();
    let mut kernel = make_kernel_with_graph();
    kernel.set_trusted_keys(vec![public_key_bytes(&key)]);

    // `observe` (not `observe_hashed`) records NO content hash.
    let node = kernel.observe(NodeKind::WebContent, &[]).unwrap();
    let mut token = make_token(node); // committed to VALUE_ID
    token_sign::sign_token(&mut token, &key);

    assert!(
        matches!(
            kernel.apply_declassification_token(&token),
            Ok(TokenApplyResult::ContentMismatch)
        ),
        "a node with no recorded value identity must refuse the release (fail-closed)"
    );
}
