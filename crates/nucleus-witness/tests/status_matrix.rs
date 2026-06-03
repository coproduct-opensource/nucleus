//! Merge-gate tests for the C2SP `tlog-witness` status matrix.
//!
//! These are the security-load-bearing NEGATIVE tests: a witness mints
//! cosignatures with its private key, so every rejection path must be
//! exercised. Plus a real 2-of-2 quorum integration test that drives two
//! in-process witnesses through the actual HTTP handler and feeds their
//! cosignatures to the Sigsum policy evaluator.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ct_merkle::mem_backed_tree::MemoryBackedTree;
use nucleus_lineage::{
    ed25519_key_id, format_checkpoint_body, format_signature_line, Ed25519Witness, Policy,
    SIG_TYPE_ED25519,
};
use nucleus_witness::cosign::verify_cosign_line;
use nucleus_witness::store::CosignedPosition;
use nucleus_witness::{
    app::build_app, decide, Decision, InMemoryStore, TrustedLogKey, WitnessKey, WitnessState,
};
use sha2::Sha256;
use tower::ServiceExt; // for oneshot

const ORIGIN: &str = "nucleus.example/log";
const LOG_KEY_NAME: &str = "nucleus.example/log";
const NOW: u64 = 1_700_000_000;

// ── Test helpers ────────────────────────────────────────────────────

/// A ct-merkle tree over deterministic leaves; lets us compute real
/// RFC 6962 roots and consistency proofs.
fn tree_of(n: u64) -> MemoryBackedTree<Sha256, Vec<u8>> {
    let mut t = MemoryBackedTree::<Sha256, Vec<u8>>::new();
    for i in 0..n {
        t.push(vec![i as u8; 32]);
    }
    t
}

fn root_bytes(t: &MemoryBackedTree<Sha256, Vec<u8>>) -> [u8; 32] {
    let r = t.root();
    let mut out = [0u8; 32];
    out.copy_from_slice(r.as_bytes().as_slice());
    out
}

/// Real consistency proof from `old`→current (`old < current`).
fn consistency_proof(t: &MemoryBackedTree<Sha256, Vec<u8>>, old: u64) -> Vec<[u8; 32]> {
    let cur = t.len();
    let proof = t.prove_consistency((cur - old) as usize);
    proof
        .as_bytes()
        .chunks_exact(32)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            a
        })
        .collect()
}

/// Build a well-formed add-checkpoint body signed by `log_key`.
fn build_body(
    log_key: &Ed25519Witness,
    key_name: &str,
    origin: &str,
    size: u64,
    root: &[u8; 32],
    old_size: u64,
    proof: &[[u8; 32]],
) -> Vec<u8> {
    let cp_body = format_checkpoint_body(origin, size, root).unwrap();
    let sig = log_key.sign_message(cp_body.as_bytes());
    let key_id = ed25519_key_id(key_name, SIG_TYPE_ED25519, &log_key.verifying_key_bytes());
    let sig_line = format_signature_line(key_name, &key_id, &sig).unwrap();

    let mut body = Vec::new();
    body.extend_from_slice(format!("old {old_size}\n").as_bytes());
    for h in proof {
        body.extend_from_slice(B64.encode(h).as_bytes());
        body.push(b'\n');
    }
    body.push(b'\n');
    body.extend_from_slice(cp_body.as_bytes());
    body.push(b'\n');
    body.extend_from_slice(sig_line.as_bytes());
    body.push(b'\n');
    body
}

/// A witness state trusting ORIGIN signed by `log_key` under
/// LOG_KEY_NAME, with an optional starting last-cosigned position.
fn state_with(
    log_key: &Ed25519Witness,
    witness_seed: u8,
    last: Option<CosignedPosition>,
) -> WitnessState {
    let store = InMemoryStore::new();
    store.add_origin(
        ORIGIN,
        vec![TrustedLogKey {
            key_name: LOG_KEY_NAME.to_string(),
            pubkey: log_key.verifying_key_bytes(),
        }],
        last,
    );
    WitnessState {
        store: Arc::new(store),
        witness_key: Arc::new(WitnessKey::from_seed(
            [witness_seed; 32],
            "nucleus.witness/test",
        )),
    }
}

// ════════════════════════════════════════════════════════════════════
//  NEGATIVE TEST 1 — forged/invalid cosignature → 403.
//  A signature line whose key name+ID match a trusted key but whose
//  signature fails to verify.
// ════════════════════════════════════════════════════════════════════
#[test]
fn neg1_forged_signature_matching_trusted_key_is_403() {
    let log_key = Ed25519Witness::from_seed([1u8; 32]);
    let state = state_with(&log_key, 2, None);

    let t = tree_of(5);
    let root = root_bytes(&t);
    // Build a body, then CORRUPT the signature bytes while keeping the
    // key_name + key_id intact (so it matches the trusted key by
    // name+ID but fails crypto verification).
    let cp_body = format_checkpoint_body(ORIGIN, 5, &root).unwrap();
    let mut sig = log_key.sign_message(cp_body.as_bytes());
    sig[0] ^= 0xFF; // flip a byte → signature no longer verifies
    let key_id = ed25519_key_id(
        LOG_KEY_NAME,
        SIG_TYPE_ED25519,
        &log_key.verifying_key_bytes(),
    );
    let sig_line = format_signature_line(LOG_KEY_NAME, &key_id, &sig).unwrap();
    let mut body = Vec::new();
    body.extend_from_slice(b"old 0\n\n");
    body.extend_from_slice(cp_body.as_bytes());
    body.push(b'\n');
    body.extend_from_slice(sig_line.as_bytes());
    body.push(b'\n');

    let d = decide(&state, &body, NOW);
    assert_eq!(d.status(), StatusCode::FORBIDDEN, "got {d:?}");
    assert!(matches!(d, Decision::Forbidden(_)));
}

// ════════════════════════════════════════════════════════════════════
//  NEGATIVE TEST 2a — unknown origin → 404.
//  NEGATIVE TEST 2b — origin known but no trusted-key signature → 403.
// ════════════════════════════════════════════════════════════════════
#[test]
fn neg2a_unknown_origin_is_404() {
    let log_key = Ed25519Witness::from_seed([1u8; 32]);
    // State trusts ORIGIN, but we submit a checkpoint for a DIFFERENT
    // origin.
    let state = state_with(&log_key, 2, None);
    let t = tree_of(3);
    let root = root_bytes(&t);
    let body = build_body(&log_key, "other/log", "other/log", 3, &root, 0, &[]);

    let d = decide(&state, &body, NOW);
    assert_eq!(d.status(), StatusCode::NOT_FOUND, "got {d:?}");
}

#[test]
fn neg2b_no_trusted_key_signature_is_403() {
    let trusted_log = Ed25519Witness::from_seed([1u8; 32]);
    let state = state_with(&trusted_log, 2, None);

    // Sign the checkpoint with a DIFFERENT (untrusted) key, but the
    // origin IS trusted. No trusted-key signature present → 403.
    let attacker = Ed25519Witness::from_seed([99u8; 32]);
    let t = tree_of(4);
    let root = root_bytes(&t);
    // Use a key_name that doesn't match the trusted key's name.
    let body = build_body(&attacker, "attacker/key", ORIGIN, 4, &root, 0, &[]);

    let d = decide(&state, &body, NOW);
    assert_eq!(d.status(), StatusCode::FORBIDDEN, "got {d:?}");
}

// ════════════════════════════════════════════════════════════════════
//  NEGATIVE TEST 3a — old size > checkpoint size → 400.
//  NEGATIVE TEST 3b — old size ≠ witness's last-cosigned size → 409.
// ════════════════════════════════════════════════════════════════════
#[test]
fn neg3a_old_size_greater_than_checkpoint_size_is_400() {
    let log_key = Ed25519Witness::from_seed([1u8; 32]);
    // Trust origin with last-cosigned size 10 so old=10 passes the 409
    // gate but old(10) > size(5) trips the 400 gate.
    let t10 = tree_of(10);
    let last = Some(CosignedPosition {
        size: 10,
        root: root_bytes(&t10),
    });
    let state = state_with(&log_key, 2, last);

    let t5 = tree_of(5);
    let root = root_bytes(&t5);
    let body = build_body(&log_key, LOG_KEY_NAME, ORIGIN, 5, &root, 10, &[]);

    let d = decide(&state, &body, NOW);
    assert_eq!(d.status(), StatusCode::BAD_REQUEST, "got {d:?}");
    assert!(matches!(d, Decision::BadRequest(_)));
}

#[test]
fn neg3b_old_size_mismatch_is_409() {
    let log_key = Ed25519Witness::from_seed([1u8; 32]);
    // Witness last cosigned size 3.
    let t3 = tree_of(3);
    let last = Some(CosignedPosition {
        size: 3,
        root: root_bytes(&t3),
    });
    let state = state_with(&log_key, 2, last);

    // Producer claims old=2 (≠ witness's 3) → 409 rollback/conflict.
    let t8 = tree_of(8);
    let root = root_bytes(&t8);
    let proof = consistency_proof(&t8, 2);
    let body = build_body(&log_key, LOG_KEY_NAME, ORIGIN, 8, &root, 2, &proof);

    let d = decide(&state, &body, NOW);
    assert_eq!(d.status(), StatusCode::CONFLICT, "got {d:?}");
    assert!(matches!(
        d,
        Decision::Conflict {
            last_cosigned_size: 3
        }
    ));
}

// ════════════════════════════════════════════════════════════════════
//  NEGATIVE TEST 4a — consistency proof doesn't verify → 422.
//  NEGATIVE TEST 4b — old size == checkpoint size but different root → 409.
// ════════════════════════════════════════════════════════════════════
#[test]
fn neg4a_bad_consistency_proof_is_422() {
    let log_key = Ed25519Witness::from_seed([1u8; 32]);
    // Witness last cosigned size 3 with the REAL root at size 3.
    let t3 = tree_of(3);
    let last = Some(CosignedPosition {
        size: 3,
        root: root_bytes(&t3),
    });
    let state = state_with(&log_key, 2, last);

    // Real new tree at size 8, but send a GARBAGE consistency proof.
    let t8 = tree_of(8);
    let root = root_bytes(&t8);
    let real_proof = consistency_proof(&t8, 3);
    // Corrupt one proof hash so old→new no longer verifies.
    let mut bad_proof = real_proof.clone();
    assert!(!bad_proof.is_empty(), "proof should be non-empty for 3→8");
    bad_proof[0][0] ^= 0xFF;
    let body = build_body(&log_key, LOG_KEY_NAME, ORIGIN, 8, &root, 3, &bad_proof);

    let d = decide(&state, &body, NOW);
    assert_eq!(d.status(), StatusCode::UNPROCESSABLE_ENTITY, "got {d:?}");
    assert!(matches!(d, Decision::Unprocessable(_)));
}

#[test]
fn neg4b_same_size_different_root_is_409() {
    let log_key = Ed25519Witness::from_seed([1u8; 32]);
    // Witness last cosigned size 5 with the REAL root.
    let t5 = tree_of(5);
    let last = Some(CosignedPosition {
        size: 5,
        root: root_bytes(&t5),
    });
    let state = state_with(&log_key, 2, last);

    // Producer re-presents size 5 (old==size==5) but with a DIFFERENT
    // root → split-view conflict → 409.
    let different_root = [0xABu8; 32];
    let body = build_body(&log_key, LOG_KEY_NAME, ORIGIN, 5, &different_root, 5, &[]);

    let d = decide(&state, &body, NOW);
    assert_eq!(d.status(), StatusCode::CONFLICT, "got {d:?}");
    assert!(matches!(
        d,
        Decision::Conflict {
            last_cosigned_size: 5
        }
    ));
}

// ════════════════════════════════════════════════════════════════════
//  POSITIVE control: a valid first submission cosigns (200) and the
//  cosignature line verifies; a valid extension with a real proof also
//  cosigns and advances state.
// ════════════════════════════════════════════════════════════════════
#[test]
fn positive_first_submission_then_extension_cosign_200() {
    let log_key = Ed25519Witness::from_seed([1u8; 32]);
    let state = state_with(&log_key, 2, None);
    let witness_pubkey = state.witness_key.verifying_key_bytes();

    // First submission: old 0, no proof.
    let t3 = tree_of(3);
    let root3 = root_bytes(&t3);
    let body = build_body(&log_key, LOG_KEY_NAME, ORIGIN, 3, &root3, 0, &[]);
    let d = decide(&state, &body, NOW);
    assert_eq!(d.status(), StatusCode::OK, "first submission: got {d:?}");
    let cosig_line = match d {
        Decision::Ok { cosignature_lines } => cosignature_lines[0].clone(),
        other => panic!("expected Ok, got {other:?}"),
    };
    // The cosignature must verify against the witness pubkey over the
    // checkpoint note body.
    let note_body = format_checkpoint_body(ORIGIN, 3, &root3).unwrap();
    let (ts, name) =
        verify_cosign_line(&cosig_line, note_body.as_bytes(), &witness_pubkey).unwrap();
    assert_eq!(ts, NOW);
    assert_eq!(name, "nucleus.witness/test");

    // Extension: old 3 → size 8 with a REAL consistency proof.
    let t8 = tree_of(8);
    let root8 = root_bytes(&t8);
    let proof = consistency_proof(&t8, 3);
    let body2 = build_body(&log_key, LOG_KEY_NAME, ORIGIN, 8, &root8, 3, &proof);
    let d2 = decide(&state, &body2, NOW + 1);
    assert_eq!(d2.status(), StatusCode::OK, "extension: got {d2:?}");

    // State advanced to size 8.
    let rec = state.store.get(ORIGIN).unwrap();
    assert_eq!(rec.last_cosigned.unwrap().size, 8);
}

// ════════════════════════════════════════════════════════════════════
//  Full HTTP path smoke test through the axum router (200).
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn http_add_checkpoint_returns_200_and_cosig_line() {
    let log_key = Ed25519Witness::from_seed([1u8; 32]);
    let state = state_with(&log_key, 2, None);
    let app = build_app(state);

    let t = tree_of(4);
    let root = root_bytes(&t);
    let body = build_body(&log_key, LOG_KEY_NAME, ORIGIN, 4, &root, 0, &[]);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/add-checkpoint")
                .header("content-type", "text/plain")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.starts_with('\u{2014}'), "cosig line: {text:?}");
}

// ════════════════════════════════════════════════════════════════════
//  REAL 2-of-2 QUORUM INTEGRATION TEST.
//  Two in-process witnesses each cosign the SAME real checkpoint via the
//  actual HTTP handler; the Sigsum policy evaluator (k=2 of 2) accepts.
// ════════════════════════════════════════════════════════════════════
#[tokio::test]
async fn two_of_two_quorum_real_cosignatures_satisfy_policy() {
    let log_key = Ed25519Witness::from_seed([1u8; 32]);

    // Two independent witnesses (distinct seeds = distinct keys =
    // distinct failure domains in the deployment model).
    let w_a_seed = 0x0Au8;
    let w_b_seed = 0x0Bu8;
    let wk_a = WitnessKey::from_seed([w_a_seed; 32], "nucleus.witness/a");
    let wk_b = WitnessKey::from_seed([w_b_seed; 32], "nucleus.witness/b");
    let pk_a = wk_a.verifying_key_bytes();
    let pk_b = wk_b.verifying_key_bytes();

    // Build two witness servers, each trusting the same origin+log key.
    let make_state = |seed: u8, name: &str| {
        let store = InMemoryStore::new();
        store.add_origin(
            ORIGIN,
            vec![TrustedLogKey {
                key_name: LOG_KEY_NAME.to_string(),
                pubkey: log_key.verifying_key_bytes(),
            }],
            None,
        );
        WitnessState {
            store: Arc::new(store),
            witness_key: Arc::new(WitnessKey::from_seed([seed; 32], name.to_string())),
        }
    };
    let state_a = make_state(w_a_seed, "nucleus.witness/a");
    let state_b = make_state(w_b_seed, "nucleus.witness/b");

    // The SAME real checkpoint at size 6.
    let t = tree_of(6);
    let root = root_bytes(&t);
    let note_body = format_checkpoint_body(ORIGIN, 6, &root).unwrap();
    let body = build_body(&log_key, LOG_KEY_NAME, ORIGIN, 6, &root, 0, &[]);

    // Drive each witness through the real HTTP handler.
    async fn cosign_via_http(state: WitnessState, body: Vec<u8>) -> String {
        let app = build_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/add-checkpoint")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec())
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string()
    }

    let line_a = cosign_via_http(state_a, body.clone()).await;
    let line_b = cosign_via_http(state_b, body.clone()).await;

    // Verify each cosignature cryptographically against its witness key,
    // then build the SET OF VALID witness names for the policy.
    let (_, name_a) = verify_cosign_line(&line_a, note_body.as_bytes(), &pk_a).unwrap();
    let (_, name_b) = verify_cosign_line(&line_b, note_body.as_bytes(), &pk_b).unwrap();
    let valid: HashSet<String> = [name_a.clone(), name_b.clone()].into_iter().collect();
    assert_eq!(valid.len(), 2, "two distinct witnesses");

    // Sigsum policy: k=2 of {a, b}.
    let policy_text = format!(
        "witness {wn_a} {pk_a_hex}\nwitness {wn_b} {pk_b_hex}\ngroup g 2 {wn_a} {wn_b}\nquorum g\n",
        wn_a = "nucleus.witness/a",
        wn_b = "nucleus.witness/b",
        pk_a_hex = hex::encode(pk_a),
        pk_b_hex = hex::encode(pk_b),
    );
    let policy = Policy::parse(&policy_text).unwrap();

    // Both cosignatures present → k=2 satisfied.
    assert!(
        policy.is_satisfied(&valid),
        "2-of-2 quorum must be satisfied by both real cosignatures"
    );

    // Negative control: only witness A → below k=2 → NOT satisfied.
    let only_a: HashSet<String> = [name_a].into_iter().collect();
    assert!(
        !policy.is_satisfied(&only_a),
        "1-of-2 must NOT satisfy a k=2 quorum"
    );
}
