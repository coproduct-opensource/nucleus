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
        let line = format_signature_line(&key_name, &key_id, &sig);
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
        format_signature_line("witness1", &kid, &sig)
    };
    let line2 = {
        let sig = witness2.sign_message(&body_canon);
        let pubkey = witness2.verifying_key_bytes();
        let kid = ed25519_key_id("witness2", SIG_TYPE_ED25519, &pubkey);
        format_signature_line("witness2", &kid, &sig)
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

// canonical_sth_bytes and parse_signature_line are pulled in via use
// statements; silence dead-code/unused-import for the (currently
// unused) ones to keep the file warning-free across feature combos.
#[allow(dead_code)]
fn _unused() {
    let _ = canonical_sth_bytes;
    let _ = parse_signature_line;
}
