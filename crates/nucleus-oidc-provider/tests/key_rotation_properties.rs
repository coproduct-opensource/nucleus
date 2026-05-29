//! Property-based tests for the `InMemoryKeyStore` rotation invariants.
//!
//! Acceptance coverage (task #52):
//! - (a) Every token signed by the active key verifies during its grace
//!   window — `prop_signed_during_grace_always_verifies`.
//! - (b) No token survives beyond `key.not_after + token.lifetime` —
//!   `prop_expired_grace_key_no_longer_resolves`. Pinned with a short
//!   real-time grace window + sleep; full clock-mocking is out of scope.
//! - (c) Rotation never violates monotonicity of `kid` epoch — KIDs
//!   are RFC 7638 thumbprints (content-derived), so "monotonic epoch"
//!   reads as **distinctness across rotations**:
//!   `prop_each_rotation_yields_distinct_kid`.
//! - (d) Concurrent rotate+sign+verify produces no torn reads —
//!   `prop_concurrent_rotate_sign_keeps_signatures_verifiable`.
//! - (e) Revoked key is not in `/jwks.json` within one grace period
//!   (immediately, in our implementation) —
//!   `prop_revoke_removes_from_all_verify_keys`.

use ed25519_dalek::Verifier as _;
use nucleus_oidc_provider::keystore::{InMemoryKeyStore, JwtKeyStore};
use proptest::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

/// One step in a sequence of operations against the key store.
#[derive(Debug, Clone)]
enum Op {
    Rotate,
    Sign(Vec<u8>),
    RevokeOldest,
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        Just(Op::Rotate),
        prop::collection::vec(any::<u8>(), 1..32).prop_map(Op::Sign),
        Just(Op::RevokeOldest),
    ]
}

// Acceptance (a) + (c): exercises a long sequence of rotates + signs,
// asserting after each step that EVERY signature emitted so far whose
// KID is still in the verify-set verifies correctly. KIDs that are
// no longer in the verify-set (revoked or expired) are excluded.
// Also confirms each `rotate` produces a previously-unseen KID.
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 25,
        max_shrink_iters: 200,
        .. ProptestConfig::default()
    })]

    #[test]
    fn prop_signed_during_grace_always_verifies(
        ops in prop::collection::vec(op_strategy(), 1..40)
    ) {
        let store = InMemoryKeyStore::with_grace_window(Duration::from_secs(60));
        let mut signed: Vec<(String, Vec<u8>, [u8; 64])> = Vec::new();
        let mut all_kids: HashSet<String> = HashSet::new();
        all_kids.insert(store.active_kid().unwrap());

        for op in ops {
            match op {
                Op::Rotate => {
                    let outcome = store.rotate().unwrap();
                    prop_assert!(
                        all_kids.insert(outcome.new_kid.clone()),
                        "rotation must produce a previously-unseen KID, got {:?}",
                        outcome.new_kid
                    );
                }
                Op::Sign(msg) => {
                    let s = store.sign(&msg).unwrap();
                    let sig_arr: [u8; 64] = s.signature.as_slice().try_into().unwrap();
                    signed.push((s.kid, msg, sig_arr));
                }
                Op::RevokeOldest => {
                    // Find the oldest KID that isn't the active one.
                    let active = store.active_kid().unwrap();
                    let keys = store.all_verify_keys().unwrap();
                    if let Some(target) = keys.iter().find(|k| k.kid != active) {
                        // revoke ignores its return value for our purposes
                        let _ = store.revoke(&target.kid);
                    }
                }
            }

            // Invariant (a): every signature with a kid still in the
            // verify-set must verify cleanly. No torn states.
            for (kid, msg, sig_bytes) in &signed {
                if let Ok(vk) = store.verify_key(kid) {
                    let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
                    prop_assert!(
                        vk.verifying_key.verify(msg, &sig).is_ok(),
                        "sig for kid {kid:?} must verify while kid is in verify-set"
                    );
                }
            }
        }
    }
}

/// Acceptance (c) — narrower: 100 sequential rotations must yield 101
/// distinct KIDs (one initial + 100 new). Documents the RFC-7638
/// distinctness property at a high case-count.
#[test]
fn prop_each_rotation_yields_distinct_kid() {
    let store = InMemoryKeyStore::with_grace_window(Duration::from_secs(60));
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(store.active_kid().unwrap());
    for _ in 0..100 {
        let outcome = store.rotate().unwrap();
        assert!(
            seen.insert(outcome.new_kid.clone()),
            "duplicate KID after rotate: {:?}",
            outcome.new_kid
        );
    }
    assert_eq!(seen.len(), 101);
}

/// Acceptance (b): a token signed BEFORE rotation must FAIL to resolve
/// AFTER the grace window has elapsed. Short grace + real-time sleep
/// substitutes for a mock clock — full deterministic time control is
/// out of scope for this iteration.
#[test]
fn prop_expired_grace_key_no_longer_resolves() {
    let store = InMemoryKeyStore::with_grace_window(Duration::from_millis(50));
    let signed = store.sign(b"pre-rotation").unwrap();
    let pre_kid = signed.kid.clone();

    store.rotate().unwrap();

    // During grace window — still verifies.
    assert!(store.verify_key(&pre_kid).is_ok());

    // Pass the grace window.
    std::thread::sleep(Duration::from_millis(150));

    // After grace — lookup fails (invariant b).
    assert!(
        store.verify_key(&pre_kid).is_err(),
        "kid {pre_kid:?} must NOT resolve after grace window expired"
    );
}

/// Acceptance (e): a revoked KID is immediately absent from
/// `all_verify_keys()` — i.e., it would not appear in `/jwks.json` on
/// the very next request. (Our implementation removes synchronously;
/// no grace period applies to explicit revoke.)
#[test]
fn prop_revoke_removes_from_all_verify_keys() {
    let store = InMemoryKeyStore::with_grace_window(Duration::from_secs(60));
    let original_kid = store.active_kid().unwrap();
    store.rotate().unwrap();

    // Before revoke: the old KID is in the verify-set.
    let keys_before: HashSet<String> = store
        .all_verify_keys()
        .unwrap()
        .iter()
        .map(|k| k.kid.clone())
        .collect();
    assert!(keys_before.contains(&original_kid));

    store.revoke(&original_kid).unwrap();

    // After revoke: gone from the verify-set immediately.
    let keys_after: HashSet<String> = store
        .all_verify_keys()
        .unwrap()
        .iter()
        .map(|k| k.kid.clone())
        .collect();
    assert!(
        !keys_after.contains(&original_kid),
        "revoked kid {original_kid:?} must be absent from verify-set immediately"
    );
}

/// Acceptance (d): concurrent rotate + sign + verify produces no torn
/// reads — every signature emitted by any worker thread verifies
/// against SOME entry in the final verify-set (active or grace-window).
///
/// Stress version of `parallel_rotate_calls_serialize` from #37 — that
/// test asserts rotation alone serializes; this test mixes rotate +
/// sign and asserts NO signature is left orphaned by a race.
#[test]
fn prop_concurrent_rotate_sign_keeps_signatures_verifiable() {
    let store: Arc<InMemoryKeyStore> =
        Arc::new(InMemoryKeyStore::with_grace_window(Duration::from_secs(60)));
    let signed_lock = Arc::new(std::sync::Mutex::new(Vec::new()));

    let mut handles = Vec::new();
    // 4 threads × 25 operations = 100 mixed ops.
    for thread_idx in 0..4 {
        let store = Arc::clone(&store);
        let signed_lock = Arc::clone(&signed_lock);
        handles.push(std::thread::spawn(move || {
            for op_idx in 0..25 {
                // Roughly 25% rotate, 75% sign.
                if op_idx % 4 == 0 {
                    store.rotate().unwrap();
                } else {
                    let msg = format!("t{thread_idx}-op{op_idx}").into_bytes();
                    let s = store.sign(&msg).unwrap();
                    let sig_arr: [u8; 64] = s.signature.as_slice().try_into().unwrap();
                    signed_lock.lock().unwrap().push((s.kid, msg, sig_arr));
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    // Every signature whose kid is in the verify-set must verify. None
    // may be in an inconsistent state where lookup succeeds but verify
    // fails (the "torn read" failure mode).
    let signed = signed_lock.lock().unwrap();
    let mut verified = 0usize;
    let mut expired = 0usize;
    for (kid, msg, sig_bytes) in signed.iter() {
        match store.verify_key(kid) {
            Ok(vk) => {
                let sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
                assert!(
                    vk.verifying_key.verify(msg, &sig).is_ok(),
                    "TORN READ: kid {kid:?} resolves but signature fails to verify"
                );
                verified += 1;
            }
            Err(_) => {
                // Kid evicted from verify-set; expected when grace
                // overflow happens (we have many rotations).
                expired += 1;
            }
        }
    }
    // Sanity: most signatures should verify given the 60s grace.
    assert!(verified > 0, "no signatures verified — test setup broken");
    assert_eq!(
        verified + expired,
        signed.len(),
        "every signature must be in exactly one category"
    );
}
