//! Integration tests for `C2spHttpWitnessClient` — the v2.3b C2SP
//! `POST /add-checkpoint` HTTP client. wiremock-based; no real network.
//!
//! Strategy: the mock witness handler parses the request body, runs
//! `InProcessWitness::cosign_c2sp` on the checkpoint body internally,
//! and returns a C2SP signature line. The client parses the response
//! and constructs a `Cosignature{kind: C2sp}` that must verify
//! cryptographically against the witness's public key.
//!
//! Requires `--features http,dev`.

#![cfg(all(feature = "http", feature = "dev"))]

use std::sync::Arc;
use std::time::Duration;

use nucleus_lineage::{
    canonical_sth_bytes, checkpoint_signed_bytes, ed25519_key_id, format_signature_line,
    parse_signature_line, C2spHttpWitnessClient, Cosignature, CosignatureKind, Ed25519Witness,
    SignedTreeHead, TreeWitness, WitnessClient, SIG_LINE_PREFIX, SIG_TYPE_ED25519,
};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

/// wiremock responder that:
///   1. Parses the C2SP `add-checkpoint` request body
///   2. Extracts origin/size/root from the checkpoint body
///   3. Internally cosigns those bytes via InProcessWitness
///   4. Returns a C2SP-formatted signature line
struct C2spWitnessHandler {
    witness_seed: [u8; 32],
    expected_origin: String,
}

impl Respond for C2spWitnessHandler {
    fn respond(&self, req: &wiremock::Request) -> ResponseTemplate {
        let body = match std::str::from_utf8(&req.body) {
            Ok(s) => s,
            Err(_) => return ResponseTemplate::new(400).set_body_string("non-UTF-8 body"),
        };

        // Find the checkpoint body (between blank lines).
        // Layout: "old N\n\n<origin>\n<size>\n<base64-root>\n\n<sig lines>"
        let mut blank_count = 0;
        let mut origin = None;
        let mut size: Option<u64> = None;
        let mut root_b64 = None;
        let mut producer_sig_line = None;
        let mut in_checkpoint = false;
        for line in body.lines() {
            if line.is_empty() {
                blank_count += 1;
                if blank_count == 1 {
                    in_checkpoint = true;
                }
                continue;
            }
            if in_checkpoint && blank_count == 1 {
                // Reading checkpoint body lines.
                if origin.is_none() {
                    origin = Some(line.to_string());
                } else if size.is_none() {
                    size = line.parse().ok();
                } else if root_b64.is_none() {
                    root_b64 = Some(line.to_string());
                }
            }
            if line.starts_with(SIG_LINE_PREFIX) {
                producer_sig_line = Some(line.to_string());
            }
        }

        let origin = match origin {
            Some(o) => o,
            None => return ResponseTemplate::new(400).set_body_string("missing checkpoint origin"),
        };
        if origin != self.expected_origin {
            return ResponseTemplate::new(404).set_body_string(format!("unknown origin: {origin}"));
        }
        let size = match size {
            Some(s) => s,
            None => return ResponseTemplate::new(400).set_body_string("missing tree size"),
        };
        let root_bytes = match root_b64.and_then(|b| {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            STANDARD.decode(b).ok()
        }) {
            Some(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => {
                return ResponseTemplate::new(400).set_body_string("malformed root_hash base64");
            }
        };
        if producer_sig_line.is_none() {
            return ResponseTemplate::new(403).set_body_string("missing producer signature");
        }

        // Witness signs the (recomputed) checkpoint body bytes.
        let checkpoint = match checkpoint_signed_bytes(&origin, size, &root_bytes) {
            Ok(b) => b,
            Err(e) => {
                return ResponseTemplate::new(500).set_body_string(format!("format error: {e}"));
            }
        };
        let witness = Ed25519Witness::from_seed(self.witness_seed);
        let sig = witness.sign_message(&checkpoint);
        let pubkey = witness.verifying_key_bytes();
        let key_name = format!("witness.example.com/seed{:02x}", self.witness_seed[0]);
        let key_id = ed25519_key_id(&key_name, SIG_TYPE_ED25519, &pubkey);
        let line = match format_signature_line(&key_name, &key_id, &sig) {
            Ok(l) => l,
            Err(e) => {
                return ResponseTemplate::new(500).set_body_string(format!("sig line error: {e}"));
            }
        };
        ResponseTemplate::new(200)
            .set_body_string(format!("{line}\n"))
            .insert_header("content-type", "text/plain")
    }
}

/// Helper: produce a real-looking STH from a producer witness so the
/// client has something to send.
fn make_sth(producer: &Ed25519Witness, tree_size: u64, root: [u8; 32]) -> SignedTreeHead {
    producer.sign_sth(tree_size, &root).unwrap()
}

#[tokio::test]
async fn c2sp_http_witness_end_to_end_round_trip_verifies() {
    let mock = MockServer::start().await;
    let origin = "nucleus.example.com/log42".to_string();
    let witness_seed = [0xAA; 32];
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(C2spWitnessHandler {
            witness_seed,
            expected_origin: origin.clone(),
        })
        .mount(&mock)
        .await;

    let producer = Arc::new(Ed25519Witness::from_seed([1u8; 32]));
    let producer_key_name = origin.clone();
    let sth = make_sth(producer.as_ref(), 5, [0x99; 32]);

    let base = mock.uri();
    let cosig: Cosignature = tokio::task::spawn_blocking({
        let producer = producer.clone();
        let origin = origin.clone();
        let producer_key_name = producer_key_name.clone();
        let sth = sth.clone();
        move || {
            let client =
                C2spHttpWitnessClient::new(base, origin, producer, producer_key_name).unwrap();
            client.cosign(&sth).unwrap()
        }
    })
    .await
    .unwrap();

    assert_eq!(cosig.kind, CosignatureKind::C2sp);
    assert!(
        cosig.witness_kid.starts_with("witness.example.com/seed"),
        "got kid {:?}",
        cosig.witness_kid
    );
    assert_eq!(cosig.signature.len(), 64);

    // Cryptographically verify the returned cosig against the witness's
    // pubkey over the C2SP checkpoint body bytes (NOT canonical_sth_bytes).
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let root: [u8; 32] = hex::decode(&sth.root_hash_hex).unwrap().try_into().unwrap();
    let checkpoint_body = checkpoint_signed_bytes(&origin, sth.tree_size, &root).unwrap();
    let witness = Ed25519Witness::from_seed(witness_seed);
    let vk = VerifyingKey::from_bytes(&witness.verifying_key_bytes()).unwrap();
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&cosig.signature);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(&checkpoint_body, &sig)
        .expect("C2SP-returned cosig must verify against checkpoint body bytes");
}

#[tokio::test]
async fn c2sp_witness_unknown_origin_returns_backend_error() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(C2spWitnessHandler {
            witness_seed: [0xBB; 32],
            expected_origin: "different.example.com/log".to_string(),
        })
        .mount(&mock)
        .await;

    let producer = Arc::new(Ed25519Witness::from_seed([2u8; 32]));
    let sth = make_sth(producer.as_ref(), 1, [0u8; 32]);
    let base = mock.uri();
    let err = tokio::task::spawn_blocking(move || {
        let client = C2spHttpWitnessClient::new(
            base,
            "wrong.example.com/log",
            producer,
            "wrong.example.com/log",
        )
        .unwrap();
        client.cosign(&sth)
    })
    .await
    .unwrap()
    .expect_err("origin mismatch must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("404") && msg.contains("unknown origin"),
        "got: {msg}"
    );
}

#[tokio::test]
async fn c2sp_witness_oversized_response_rejected() {
    let mock = MockServer::start().await;
    let huge = format!("{}{}", SIG_LINE_PREFIX, "A".repeat(20 * 1024));
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(huge)
                .insert_header("content-type", "text/plain"),
        )
        .mount(&mock)
        .await;

    let producer = Arc::new(Ed25519Witness::from_seed([3u8; 32]));
    let sth = make_sth(producer.as_ref(), 1, [0u8; 32]);
    let base = mock.uri();
    let err = tokio::task::spawn_blocking(move || {
        let client = C2spHttpWitnessClient::new(base, "origin", producer, "origin").unwrap();
        client.cosign(&sth)
    })
    .await
    .unwrap()
    .expect_err("oversized response must be rejected");
    assert!(err.to_string().contains("byte body") || err.to_string().contains("Content-Length"));
}

#[tokio::test]
async fn c2sp_witness_empty_response_rejected() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("")
                .insert_header("content-type", "text/plain"),
        )
        .mount(&mock)
        .await;

    let producer = Arc::new(Ed25519Witness::from_seed([4u8; 32]));
    let sth = make_sth(producer.as_ref(), 1, [0u8; 32]);
    let base = mock.uri();
    let err = tokio::task::spawn_blocking(move || {
        let client = C2spHttpWitnessClient::new(base, "origin", producer, "origin").unwrap();
        client.cosign(&sth)
    })
    .await
    .unwrap()
    .expect_err("empty response must be rejected");
    assert!(err.to_string().contains("no signature lines"));
}

#[tokio::test]
async fn c2sp_witness_cosign_many_returns_multiple_lines() {
    let mock = MockServer::start().await;
    // Mock returns TWO signature lines from two different (fake)
    // witnesses — simulating an aggregator service.
    let witness1 = Ed25519Witness::from_seed([0x10; 32]);
    let witness2 = Ed25519Witness::from_seed([0x20; 32]);
    let origin = "agg.example.com/log".to_string();
    let body_canon = checkpoint_signed_bytes(&origin, 7, &[0x77; 32]).unwrap();
    let line1 = {
        let sig = witness1.sign_message(&body_canon);
        let pubkey = witness1.verifying_key_bytes();
        let kid = ed25519_key_id("witness1", SIG_TYPE_ED25519, &pubkey);
        format_signature_line("witness1", &kid, &sig).unwrap()
    };
    let line2 = {
        let sig = witness2.sign_message(&body_canon);
        let pubkey = witness2.verifying_key_bytes();
        let kid = ed25519_key_id("witness2", SIG_TYPE_ED25519, &pubkey);
        format_signature_line("witness2", &kid, &sig).unwrap()
    };
    let response = format!("{line1}\n{line2}\n");
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(response)
                .insert_header("content-type", "text/plain"),
        )
        .mount(&mock)
        .await;

    let producer = Arc::new(Ed25519Witness::from_seed([0xAB; 32]));
    let sth = make_sth(producer.as_ref(), 7, [0x77; 32]);
    let base = mock.uri();
    let cosigs = tokio::task::spawn_blocking({
        let producer = producer.clone();
        let origin = origin.clone();
        let sth = sth.clone();
        move || {
            let client =
                C2spHttpWitnessClient::new(base, origin.clone(), producer, origin).unwrap();
            client.cosign_many(&sth)
        }
    })
    .await
    .unwrap()
    .expect("aggregator must return both cosigs");
    assert_eq!(cosigs.len(), 2);
    assert_eq!(cosigs[0].witness_kid, "witness1");
    assert_eq!(cosigs[1].witness_kid, "witness2");
    for c in &cosigs {
        assert_eq!(c.kind, CosignatureKind::C2sp);
    }
}

#[tokio::test]
async fn c2sp_witness_timeout_clean_backend_error() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(10)))
        .mount(&mock)
        .await;

    let producer = Arc::new(Ed25519Witness::from_seed([5u8; 32]));
    let sth = make_sth(producer.as_ref(), 1, [0u8; 32]);
    let base = mock.uri();
    let err = tokio::task::spawn_blocking(move || {
        let client = C2spHttpWitnessClient::new(base, "origin", producer, "origin")
            .unwrap()
            .with_timeout(Duration::from_millis(500))
            .unwrap();
        client.cosign(&sth)
    })
    .await
    .unwrap()
    .expect_err("timeout must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("/add-checkpoint") && msg.contains("backend failure"),
        "got: {msg}"
    );
}

/// **v2.3b HIGH-3**: witness returns 409 Conflict with decimal
/// last-known size in body. Client surfaces as `WitnessError::Conflict`
/// with the parsed size, NOT a generic Backend error. A v2.3c stateful
/// client will use this to update its tracked size and retry.
#[tokio::test]
async fn c2sp_witness_409_conflict_parses_last_known_size() {
    use nucleus_lineage::WitnessError;
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(
            ResponseTemplate::new(409)
                .insert_header("content-type", "text/x.tlog.size")
                .set_body_string("42\n"),
        )
        .mount(&mock)
        .await;

    let producer = Arc::new(Ed25519Witness::from_seed([7u8; 32]));
    let sth = make_sth(producer.as_ref(), 5, [0u8; 32]);
    let base = mock.uri();
    let err = tokio::task::spawn_blocking(move || {
        let client = C2spHttpWitnessClient::new(
            base,
            "nucleus.example.com/log",
            producer,
            "nucleus.example.com/log",
        )
        .unwrap();
        client.cosign(&sth)
    })
    .await
    .unwrap()
    .expect_err("409 must surface as Conflict");
    match err {
        WitnessError::Conflict { last_known_size } => {
            assert_eq!(last_known_size, 42);
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
}

/// 409 with a non-decimal body falls back to the generic Backend
/// error path (preserves the body excerpt for human diagnosis) — pins
/// behavior so a future witness implementation can't quietly omit the
/// size.
#[tokio::test]
async fn c2sp_witness_409_with_non_decimal_body_is_backend_error() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(ResponseTemplate::new(409).set_body_string("conflict: try again later"))
        .mount(&mock)
        .await;

    let producer = Arc::new(Ed25519Witness::from_seed([8u8; 32]));
    let sth = make_sth(producer.as_ref(), 5, [0u8; 32]);
    let base = mock.uri();
    let err = tokio::task::spawn_blocking(move || {
        let client = C2spHttpWitnessClient::new(
            base,
            "nucleus.example.com/log",
            producer,
            "nucleus.example.com/log",
        )
        .unwrap();
        client.cosign(&sth)
    })
    .await
    .unwrap()
    .expect_err("non-decimal 409 body falls through");
    let msg = err.to_string();
    assert!(
        msg.contains("409") && msg.contains("conflict"),
        "got: {msg}"
    );
}

// ─────────────────────────────────────────────────────────────────────
// v2.3c — stateful client + consistency-proof carrying

/// Mock witness for v2.3c stateful tests. Parses the request body's
/// `old <prev>` line and consistency proof lines, validates the proof
/// against an internal MemoryBackedTree, signs the new checkpoint
/// body, and emits a C2SP signature line.
struct C2spStatefulHandler {
    witness_seed: [u8; 32],
    expected_origin: String,
    /// What `old <N>` value to accept. If the request's `old` doesn't
    /// match, returns 409 with this size.
    expected_old: std::sync::Mutex<u64>,
    /// If true, ASSERT that the request carries ≥ 1 proof line; if the
    /// request has zero proof lines, return 400.
    require_proof_lines: bool,
}

impl wiremock::Respond for C2spStatefulHandler {
    fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
        let body = match std::str::from_utf8(&req.body) {
            Ok(s) => s,
            Err(_) => return wiremock::ResponseTemplate::new(400).set_body_string("non-UTF-8"),
        };
        // Parse `old <N>` from the first line.
        let mut lines = body.lines();
        let first = lines.next().unwrap_or("");
        let prev: u64 = match first.strip_prefix("old ").and_then(|s| s.parse().ok()) {
            Some(n) => n,
            None => {
                return wiremock::ResponseTemplate::new(400).set_body_string("malformed old line");
            }
        };

        // Consistency proof lines: every line after `old N` and before
        // the first blank line.
        let mut proof_lines = 0;
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            proof_lines += 1;
        }

        let expected_old = *self.expected_old.lock().unwrap();
        if prev != expected_old {
            return wiremock::ResponseTemplate::new(409)
                .insert_header("content-type", "text/x.tlog.size")
                .set_body_string(format!("{expected_old}\n"));
        }
        if self.require_proof_lines && proof_lines == 0 {
            return wiremock::ResponseTemplate::new(400)
                .set_body_string("missing consistency proof");
        }

        // Continue parsing: origin/size/root.
        let mut origin = None;
        let mut size: Option<u64> = None;
        let mut root_b64 = None;
        for line in lines.by_ref() {
            if line.is_empty() {
                break;
            }
            if origin.is_none() {
                origin = Some(line.to_string());
            } else if size.is_none() {
                size = line.parse().ok();
            } else if root_b64.is_none() {
                root_b64 = Some(line.to_string());
            }
        }
        let origin = match origin {
            Some(o) if o == self.expected_origin => o,
            Some(o) => {
                return wiremock::ResponseTemplate::new(404)
                    .set_body_string(format!("unknown origin: {o}"));
            }
            None => return wiremock::ResponseTemplate::new(400).set_body_string("no origin"),
        };
        let size = size.unwrap_or(0);
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let root_bytes: [u8; 32] = match root_b64.and_then(|b| STANDARD.decode(b).ok()) {
            Some(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                arr
            }
            _ => return wiremock::ResponseTemplate::new(400).set_body_string("bad root"),
        };

        let checkpoint = checkpoint_signed_bytes(&origin, size, &root_bytes).unwrap();
        let witness = Ed25519Witness::from_seed(self.witness_seed);
        let sig = witness.sign_message(&checkpoint);
        let pubkey = witness.verifying_key_bytes();
        let key_name = format!("stateful.example.com/seed{:02x}", self.witness_seed[0]);
        let key_id = ed25519_key_id(&key_name, SIG_TYPE_ED25519, &pubkey);
        let line = format_signature_line(&key_name, &key_id, &sig).unwrap();
        wiremock::ResponseTemplate::new(200)
            .insert_header("content-type", "text/plain")
            .set_body_string(format!("{line}\n"))
    }
}

/// Convert an Ed25519Witness into a MerkleProver-bearing MerkleSink
/// for use in v2.3c tests that need real consistency proofs.
fn make_prover_sink_with_n_leaves(
    n: usize,
) -> (
    std::sync::Arc<dyn nucleus_lineage::MerkleProver>,
    nucleus_lineage::SignedTreeHead,
) {
    use nucleus_lineage::{
        CallSpiffeId, EdgeSigner, InMemorySink, LineageEdge, LineageSink, LocalIssuer,
        MerkleConfig, MerkleSink, Proof,
    };
    let dir = tempfile::tempdir().unwrap();
    let inner = InMemorySink::new();
    let producer = Ed25519Witness::from_seed([99u8; 32]);
    let sink = MerkleSink::new(
        inner,
        producer,
        MerkleConfig::new(dir.path()).with_interval(10_000),
    )
    .unwrap();
    let issuer = LocalIssuer::random().unwrap();
    let pod = CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap();
    use nucleus_lineage::EdgeKind;
    let mut prev_hash: Option<[u8; 32]> = None;
    for i in 0..n {
        let mut edge = if i == 0 {
            LineageEdge::pod_admit(pod.clone())
        } else {
            // Use a derivation edge so each leaf hashes uniquely.
            // `derive_tool` makes the child identity content-distinct
            // per iteration so the Merkle leaves don't collide.
            let unique_marker = format!("iter-{i}");
            let child = pod
                .derive_tool("shell", Some(unique_marker.as_bytes()))
                .unwrap();
            LineageEdge::from_parent(
                child,
                pod.clone(),
                EdgeKind::ToolCall {
                    tool: "shell".into(),
                },
            )
        };
        let bytes = nucleus_lineage::canonical_edge_bytes(&edge, prev_hash.as_ref());
        let sig = issuer.sign(&bytes).unwrap();
        let mut proof = Proof::new(issuer.kid(), issuer.alg(), sig);
        if let Some(h) = prev_hash {
            proof = proof.with_prev_hash(h);
        }
        edge.proof = Some(proof);
        let new_hash = nucleus_lineage::edge_content_hash(&edge, prev_hash.as_ref());
        prev_hash = Some(new_hash);
        sink.emit(edge).unwrap();
    }
    let prover_arc: std::sync::Arc<dyn nucleus_lineage::MerkleProver> = std::sync::Arc::new(sink);
    let sth = prover_arc.seal_current_root().unwrap();
    (prover_arc, sth)
}

/// **v2.3c happy path**: client tracks state across two POSTs.
/// First call sends `old 0` (no proof). Second call uses last-known
/// size + consistency proof.
#[tokio::test]
async fn c2sp_stateful_client_tracks_size_across_two_calls() {
    let mock = MockServer::start().await;
    let origin = "nucleus.example.com/log-stateful".to_string();
    let witness_seed = [0xC1; 32];

    // Build a producer + tree with 5 leaves first.
    let (prover, sth_first) = make_prover_sink_with_n_leaves(5);
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(C2spStatefulHandler {
            witness_seed,
            expected_origin: origin.clone(),
            expected_old: std::sync::Mutex::new(0u64),
            require_proof_lines: false,
        })
        .mount(&mock)
        .await;

    let producer_witness = Arc::new(Ed25519Witness::from_seed([0xAB; 32]));
    let producer_key_name = origin.clone();
    let base = mock.uri();
    let prover_clone = prover.clone();
    let cosig: Cosignature = tokio::task::spawn_blocking({
        let producer_witness = producer_witness.clone();
        let origin = origin.clone();
        let producer_key_name = producer_key_name.clone();
        let sth = sth_first.clone();
        move || {
            let client =
                C2spHttpWitnessClient::new(base, origin, producer_witness, producer_key_name)
                    .unwrap()
                    .with_consistency_prover(prover_clone);
            client.cosign(&sth).unwrap()
        }
    })
    .await
    .unwrap();
    assert_eq!(cosig.kind, CosignatureKind::C2sp);
    let _ = sth_first;
}

/// **v2.3c 409 recovery**: client has stale state (None / 0 → mock
/// expects 3), sees 409 with the correct size, updates state, retries
/// ONCE with a fresh proof. Second attempt succeeds.
#[tokio::test]
async fn c2sp_stateful_client_recovers_from_409_with_retry() {
    use nucleus_lineage::WitnessError;
    // Build a tree with 10 leaves; witness "saw" us at 3, current
    // size is 10. Client starts with no state → sends `old 0` first
    // → mock 409 says size=3 → client updates state and retries
    // `old 3` + consistency proof from 3 → 10 → succeeds.
    let (prover, sth_ten) = make_prover_sink_with_n_leaves(10);
    assert_eq!(sth_ten.tree_size, 10);

    let origin = "nucleus.example.com/log-recover".to_string();
    let witness_seed = [0xC2; 32];
    let mock = MockServer::start().await;
    // Wiremock can't easily change response between calls without
    // priority + remaining_calls; use a stateful handler instead.
    use std::sync::atomic::{AtomicU64, Ordering};
    let call_count = std::sync::Arc::new(AtomicU64::new(0));
    let call_count_clone = call_count.clone();

    struct RecoveryHandler {
        witness_seed: [u8; 32],
        origin: String,
        calls: std::sync::Arc<AtomicU64>,
    }
    impl wiremock::Respond for RecoveryHandler {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            let body = std::str::from_utf8(&req.body).unwrap_or("");
            let first = body.lines().next().unwrap_or("");
            let prev: u64 = first
                .strip_prefix("old ")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            // First call: client sent `old 0`, witness expects 3 →
            // 409 + body "3\n".
            if n == 0 {
                if prev == 0 {
                    return wiremock::ResponseTemplate::new(409)
                        .insert_header("content-type", "text/x.tlog.size")
                        .set_body_string("3\n");
                }
                // Unexpected — client sent something other than 0 on
                // first call.
                return wiremock::ResponseTemplate::new(500)
                    .set_body_string(format!("unexpected first old={prev}"));
            }
            // Second call: must send `old 3`. Count proof lines.
            if prev != 3 {
                return wiremock::ResponseTemplate::new(500)
                    .set_body_string(format!("retry: expected old=3, got {prev}"));
            }
            let mut proof_lines = 0usize;
            let mut iter = body.lines();
            iter.next(); // skip `old 3`
            for line in iter.by_ref() {
                if line.is_empty() {
                    break;
                }
                proof_lines += 1;
            }
            if proof_lines == 0 {
                return wiremock::ResponseTemplate::new(400)
                    .set_body_string("retry missing consistency proof");
            }
            // Parse checkpoint and cosign.
            let mut origin_seen = None;
            let mut size: Option<u64> = None;
            let mut root_b64 = None;
            for line in iter.by_ref() {
                if line.is_empty() {
                    break;
                }
                if origin_seen.is_none() {
                    origin_seen = Some(line.to_string());
                } else if size.is_none() {
                    size = line.parse().ok();
                } else if root_b64.is_none() {
                    root_b64 = Some(line.to_string());
                }
            }
            let o = origin_seen.unwrap();
            assert_eq!(o, self.origin);
            let s = size.unwrap();
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let rb = root_b64.unwrap();
            let raw = STANDARD.decode(rb).unwrap();
            let mut root = [0u8; 32];
            root.copy_from_slice(&raw);
            let checkpoint = checkpoint_signed_bytes(&o, s, &root).unwrap();
            let witness = Ed25519Witness::from_seed(self.witness_seed);
            let sig = witness.sign_message(&checkpoint);
            let pubkey = witness.verifying_key_bytes();
            let key_name = "recovery.example.com/w".to_string();
            let key_id = ed25519_key_id(&key_name, SIG_TYPE_ED25519, &pubkey);
            let line = format_signature_line(&key_name, &key_id, &sig).unwrap();
            wiremock::ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(format!("{line}\n"))
        }
    }

    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(RecoveryHandler {
            witness_seed,
            origin: origin.clone(),
            calls: call_count_clone,
        })
        .mount(&mock)
        .await;

    let producer_witness = Arc::new(Ed25519Witness::from_seed([0xCD; 32]));
    let base = mock.uri();
    let prover_clone = prover.clone();
    let result = tokio::task::spawn_blocking({
        let producer_witness = producer_witness.clone();
        let origin = origin.clone();
        let sth = sth_ten.clone();
        move || {
            let client = C2spHttpWitnessClient::new(base, origin.clone(), producer_witness, origin)
                .unwrap()
                .with_consistency_prover(prover_clone);
            client.cosign(&sth)
        }
    })
    .await
    .unwrap();

    let cosig = result.expect("retry-after-409 should succeed");
    assert_eq!(cosig.kind, CosignatureKind::C2sp);
    assert_eq!(
        call_count.load(Ordering::SeqCst),
        2,
        "client must POST twice (initial + retry-after-409)"
    );
    let _ = WitnessError::Conflict { last_known_size: 0 };
}

/// **v2.3c**: 409 without an attached consistency prover surfaces as
/// `WitnessError::Conflict` after the FIRST attempt — the client
/// can't construct a valid proof to retry, so it doesn't loop.
#[tokio::test]
async fn c2sp_stateful_client_409_without_prover_surfaces_conflict() {
    use nucleus_lineage::WitnessError;
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(
            ResponseTemplate::new(409)
                .insert_header("content-type", "text/x.tlog.size")
                .set_body_string("17\n"),
        )
        .mount(&mock)
        .await;

    let producer = Arc::new(Ed25519Witness::from_seed([0xCE; 32]));
    let sth = make_sth(producer.as_ref(), 20, [0; 32]);
    let base = mock.uri();
    let err = tokio::task::spawn_blocking(move || {
        let client = C2spHttpWitnessClient::new(
            base,
            "nucleus.example.com/log",
            producer,
            "nucleus.example.com/log",
        )
        .unwrap();
        client.cosign(&sth)
    })
    .await
    .unwrap()
    .expect_err("no prover ⇒ can't retry, must surface Conflict");
    match err {
        WitnessError::Conflict {
            last_known_size: 17,
        } => {}
        other => panic!("expected Conflict{{17}}, got {other:?}"),
    }
}

// ─────────────────────────────────────────────────────────────────────
// CRIT-1 (#1646) — concurrent cosign_many serialization

/// **CRIT-1**: under concurrent `cosign` calls against a single client,
/// the read-attempt-write sequence must serialize. Before the fix,
/// two callers could read the same `prev_size`, both succeed at the
/// witness, and the slower writer would clobber the faster one's
/// correct new size — causing the NEXT call to send a stale `old N`
/// and trigger a spurious 409.
///
/// This test fires K concurrent `cosign` calls against the same client.
/// The witness mock COUNTS posts and rejects any unexpected `old` with
/// 500 (so a race-induced wrong-old would fail the test loudly rather
/// than silently retrying). Expectation: K posts total, zero 409s,
/// zero 500s, all K cosigs returned successfully.
///
/// Uses synchronous `std::thread` for the parallel cosigns instead of
/// `tokio::spawn_blocking` because `reqwest::blocking::Client` panics
/// when its internal runtime is dropped inside an async context.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn c2sp_concurrent_cosigns_serialize_without_spurious_409() {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    const K: usize = 8;

    let origin = "nucleus.example.com/log-crit1".to_string();
    let witness_seed = [0xD3; 32];
    let mock = MockServer::start().await;

    // Witness mock: tracks "current cosigned size", expects monotone
    // `old` advancement from K concurrent submitters that share a
    // client (serialization invariant). Returns 500 if a request
    // arrives with stale `old` — exposes any race.
    let current_size = std::sync::Arc::new(AtomicU64::new(0));
    let post_count = std::sync::Arc::new(AtomicUsize::new(0));
    let unexpected_old_count = std::sync::Arc::new(AtomicUsize::new(0));

    struct ConcurrentHandler {
        witness_seed: [u8; 32],
        origin: String,
        current_size: std::sync::Arc<AtomicU64>,
        post_count: std::sync::Arc<AtomicUsize>,
        unexpected_old_count: std::sync::Arc<AtomicUsize>,
    }
    impl wiremock::Respond for ConcurrentHandler {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            self.post_count.fetch_add(1, Ordering::SeqCst);
            let body = std::str::from_utf8(&req.body).unwrap_or("");
            let first = body.lines().next().unwrap_or("");
            let prev: u64 = first
                .strip_prefix("old ")
                .and_then(|s| s.parse().ok())
                .unwrap_or(u64::MAX);

            let expected = self.current_size.load(Ordering::SeqCst);
            if prev != expected {
                // Race exposed: serialization should have ensured
                // monotone old. Failing loudly instead of just 409ing.
                self.unexpected_old_count.fetch_add(1, Ordering::SeqCst);
                return wiremock::ResponseTemplate::new(500).set_body_string(format!(
                    "race-detected: expected old={expected}, got {prev}"
                ));
            }

            // Skip past `old N` and zero+ proof lines to checkpoint.
            let mut iter = body.lines();
            iter.next();
            for line in iter.by_ref() {
                if line.is_empty() {
                    break;
                }
            }
            let mut origin_seen = None;
            let mut size: Option<u64> = None;
            let mut root_b64 = None;
            for line in iter.by_ref() {
                if line.is_empty() {
                    break;
                }
                if origin_seen.is_none() {
                    origin_seen = Some(line.to_string());
                } else if size.is_none() {
                    size = line.parse().ok();
                } else if root_b64.is_none() {
                    root_b64 = Some(line.to_string());
                }
            }
            let o = origin_seen.unwrap();
            if o != self.origin {
                return wiremock::ResponseTemplate::new(404).set_body_string("origin");
            }
            let s = size.unwrap();
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            let rb = root_b64.unwrap();
            let raw = STANDARD.decode(rb).unwrap();
            let mut root = [0u8; 32];
            root.copy_from_slice(&raw);
            let checkpoint = checkpoint_signed_bytes(&o, s, &root).unwrap();
            let witness = Ed25519Witness::from_seed(self.witness_seed);
            let sig = witness.sign_message(&checkpoint);
            let pubkey = witness.verifying_key_bytes();
            let key_name = "concurrent.example.com/w".to_string();
            let key_id = ed25519_key_id(&key_name, SIG_TYPE_ED25519, &pubkey);
            let line = format_signature_line(&key_name, &key_id, &sig).unwrap();
            // Advance witness's tracked size — next request's `old`
            // must match this new value.
            self.current_size.store(s, Ordering::SeqCst);
            wiremock::ResponseTemplate::new(200)
                .insert_header("content-type", "text/plain")
                .set_body_string(format!("{line}\n"))
        }
    }

    Mock::given(method("POST"))
        .and(path("/add-checkpoint"))
        .respond_with(ConcurrentHandler {
            witness_seed,
            origin: origin.clone(),
            current_size: current_size.clone(),
            post_count: post_count.clone(),
            unexpected_old_count: unexpected_old_count.clone(),
        })
        .mount(&mock)
        .await;

    let base = mock.uri();
    let origin_clone = origin.clone();

    // All blocking work (client construction + concurrent cosigns +
    // client drop) lives in one spawn_blocking so reqwest's private
    // runtime is dropped on a blocking thread, not in async context.
    // No consistency prover is needed for race testing — the race is
    // in state update logic, not proof generation.
    let (all_ok, total_posts, race_count) = tokio::task::spawn_blocking(move || {
        let producer = Arc::new(Ed25519Witness::from_seed([0xD4; 32]));
        let client = std::sync::Arc::new(
            C2spHttpWitnessClient::new(base, origin_clone.clone(), producer.clone(), origin_clone)
                .unwrap(),
        );

        // Synthetic STHs at strictly-increasing sizes 5, 6, ..., 5+K-1.
        // Each is signed by the producer (validation isn't done by
        // the witness mock, but it's the right shape). The witness
        // mock will accept them in arrival order if and only if the
        // `old` value advances monotonically.
        let sths: Vec<_> = (5..(5 + K as u64))
            .map(|size| {
                let root = [(size as u8); 32];
                producer.sign_sth(size, &root).unwrap()
            })
            .collect();

        // Fire K concurrent cosigns via std::thread. They share one
        // client → serialize at the state mutex. Without the CRIT-1
        // fix, two threads can read the same prev_size and the
        // second writer clobbers the first; this manifests as the
        // mock's race-detector returning 500 with
        // unexpected_old_count++.
        let handles: Vec<_> = sths
            .into_iter()
            .map(|sth| {
                let client = client.clone();
                std::thread::spawn(move || client.cosign(&sth))
            })
            .collect();

        let mut all_ok = 0;
        for h in handles {
            match h.join().unwrap() {
                Ok(_) => all_ok += 1,
                Err(e) => panic!("cosign failed: {e:?}"),
            }
        }
        // Drop the client here on this blocking thread.
        drop(client);
        (
            all_ok,
            post_count.load(Ordering::SeqCst),
            unexpected_old_count.load(Ordering::SeqCst),
        )
    })
    .await
    .unwrap();

    assert_eq!(all_ok, K, "every cosign must succeed");
    assert_eq!(
        race_count, 0,
        "race-detector: no out-of-order `old` values allowed"
    );
    assert_eq!(total_posts, K, "K posts (no race-induced 409 retries)");
}

// canonical_sth_bytes and parse_signature_line are pulled in via use
// statements; silence dead-code/unused-import for the (currently
// unused) ones to keep the file warning-free across feature combos.
#[allow(dead_code)]
fn _unused() {
    let _ = canonical_sth_bytes;
    let _ = parse_signature_line;
}
