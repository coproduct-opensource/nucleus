//! Emit REAL signed bundles + matching trust anchors for the in-browser
//! verifier demo (`sdks/verifier-js/demo.html`). No fake data: every edge is
//! Ed25519-signed and hash-chained, the Merkle anchor is witness-cosigned, and
//! this binary asserts the bundles verify (and that a one-byte tamper is
//! rejected) before writing them — so the committed fixtures are exactly what
//! the demo claims.
//!
//! Usage: `cargo run -p nucleus-envelope --example emit_demo_bundle -- <out_dir>`
//! (defaults to `sdks/verifier-js/demo-fixtures`).

use std::path::{Path, PathBuf};

use nucleus_envelope::{verify_bundle, Bundle, BundleBuilder, TrustAnchor};
use nucleus_lineage::{
    edge_content_hash, CallSpiffeId, Ed25519Witness, EdgeKind, EdgeSigner, Jwks, LineageEdge,
    LineageSink, LocalIssuer, MerkleConfig, MerkleSink, Proof,
};

fn pod() -> CallSpiffeId {
    CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
}

/// Sign `edge` with `issuer`, chaining against `prev` (mirrors the e2e test).
fn signed_edge(
    issuer: &LocalIssuer,
    mut edge: LineageEdge,
    prev: Option<&[u8; 32]>,
) -> LineageEdge {
    let bytes = nucleus_lineage::canonical_edge_bytes(&edge, prev);
    let sig = issuer.sign(&bytes).unwrap();
    let mut proof = Proof::new(issuer.kid(), issuer.alg(), sig);
    if let Some(h) = prev {
        proof = proof.with_prev_hash(*h);
    }
    edge.proof = Some(proof);
    edge
}

/// Emit a fully-signed 3-edge session: pod_admit -> ToolCall(Read) -> ArtifactProduced.
fn populate_session(sink: &dyn LineageSink, issuer: &LocalIssuer) {
    let p = pod();

    let e1 = signed_edge(issuer, LineageEdge::pod_admit(p.clone()), None);
    let h1 = edge_content_hash(&e1, None);
    sink.emit(e1).unwrap();

    let tool = p.derive_tool("Read", Some(b"input bytes")).unwrap();
    let e2 = signed_edge(
        issuer,
        LineageEdge::from_parent(
            tool.clone(),
            p,
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ),
        Some(&h1),
    );
    let h2 = edge_content_hash(&e2, Some(&h1));
    sink.emit(e2).unwrap();

    let leaf = tool.derive_artifact(b"summarized output").unwrap();
    let e3 = signed_edge(
        issuer,
        LineageEdge::from_parent(leaf, tool, EdgeKind::ArtifactProduced),
        Some(&h2),
    );
    sink.emit(e3).unwrap();
}

/// Flip one hex nibble in the serialized bundle and assert it no longer
/// verifies — the demo's core claim, checked at generation time.
fn assert_tamper_rejected(bundle_json: &str, anchor: &TrustAnchor) {
    // Find a long hex run (a signature / hash) and flip its first nibble.
    let bytes = bundle_json.as_bytes();
    let mut run_start = None;
    let mut run_len = 0usize;
    let mut flip_at = None;
    for (i, &b) in bytes.iter().enumerate() {
        let is_hex = b.is_ascii_hexdigit();
        if is_hex {
            if run_start.is_none() {
                run_start = Some(i);
                run_len = 1;
            } else {
                run_len += 1;
            }
            if run_len >= 40 {
                flip_at = run_start;
                break;
            }
        } else {
            run_start = None;
            run_len = 0;
        }
    }
    let flip_at = flip_at.expect("bundle JSON must contain a long hex signature/hash run");
    let mut tampered: Vec<u8> = bundle_json.bytes().collect();
    // 'a' <-> 'b' is always a real change for a hex nibble.
    tampered[flip_at] = if tampered[flip_at] == b'a' {
        b'b'
    } else {
        b'a'
    };
    let tampered = String::from_utf8(tampered).unwrap();
    let parsed: Result<Bundle, _> = serde_json::from_str(&tampered);
    match parsed {
        Ok(b) => assert!(
            verify_bundle(&b, anchor).is_err(),
            "TAMPERED bundle MUST be rejected — demo claim would be false otherwise"
        ),
        Err(_) => { /* tamper broke JSON shape; that is also a rejection */ }
    }
}

fn write(out: &Path, name: &str, contents: &str) {
    let path = out.join(name);
    std::fs::write(&path, contents).unwrap_or_else(|e| panic!("write {path:?}: {e}"));
    println!("  wrote {} ({} bytes)", path.display(), contents.len());
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("sdks/verifier-js/demo-fixtures"));
    std::fs::create_dir_all(&out).unwrap();

    // ---- Fixture A: basic signed bundle (chain + JWKS only). ----
    {
        let issuer = LocalIssuer::random().unwrap();
        let sink = nucleus_lineage::InMemorySink::new();
        populate_session(&sink, &issuer);
        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({
                "stats": {"input_bytes": 11, "output_bytes": 17},
                "summary": "summarized output"
            }))
            .sink(&sink)
            .jwks(jwks)
            .require_signed()
            .build()
            .expect("basic bundle must build");

        let anchor = TrustAnchor::from_jwks(serde_json::from_value(issuer.publish_jwks()).unwrap());
        let report = verify_bundle(&bundle, &anchor).expect("basic bundle must verify");
        assert_eq!(report.edge_count, 3);
        let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();
        assert_tamper_rejected(&bundle_json, &anchor);

        let anchor_json = serde_json::to_string_pretty(&serde_json::json!({
            "trust_jwks": issuer.publish_jwks(),
            "allow_empty": false,
            "cosignature_threshold": 0
        }))
        .unwrap();
        write(&out, "bundle.basic.json", &bundle_json);
        write(&out, "trust-anchor.basic.json", &anchor_json);
    }

    // ---- Fixture B: Merkle bundle witness-cosigned (the lead demo). ----
    {
        let dir = std::env::temp_dir().join("nucleus-demo-merkle");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let inner = nucleus_lineage::InMemorySink::new();
        let witness = Ed25519Witness::from_seed([42u8; 32]);
        let witness_pub = witness.verifying_key_bytes();
        let cfg = MerkleConfig::new(&dir).with_interval(1000);
        let sink = MerkleSink::new(inner, witness, cfg).unwrap();

        let issuer = LocalIssuer::random().unwrap();
        populate_session(&sink, &issuer);
        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        let bundle = BundleBuilder::new(pod())
            .payload(serde_json::json!({"demo": "agent execution lineage", "v2": true}))
            .sink(&sink)
            .jwks(jwks)
            .require_signed()
            .with_merkle_prover(&sink)
            .build()
            .expect("cosigned bundle must build");
        assert!(bundle.envelope.merkle_anchor.is_some());

        let witness_hex = hex::encode(witness_pub);
        let anchor = TrustAnchor::from_jwks(serde_json::from_value(issuer.publish_jwks()).unwrap())
            .with_witness_pubkey(witness_pub);
        let report = verify_bundle(&bundle, &anchor).expect("cosigned bundle must verify");
        assert!(report.merkle_verified, "merkle_verified must hold");

        let bundle_json = serde_json::to_string_pretty(&bundle).unwrap();
        assert_tamper_rejected(&bundle_json, &anchor);

        let anchor_json = serde_json::to_string_pretty(&serde_json::json!({
            "trust_jwks": issuer.publish_jwks(),
            "trust_witness_pubkey_hex": witness_hex,
            "allow_empty": false,
            "cosignature_threshold": 0
        }))
        .unwrap();
        write(&out, "bundle.json", &bundle_json);
        write(&out, "trust-anchor.json", &anchor_json);
        let _ = std::fs::remove_dir_all(&dir);
    }

    println!("OK — real fixtures emitted and self-verified (incl. tamper-rejection).");
}
