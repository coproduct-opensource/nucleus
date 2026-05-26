//! End-to-end: emit signed edges into a sink, build a bundle, serialize,
//! deserialize, verify standalone. This is the round-trip the v1 plan
//! calls out — proves the envelope is portable and self-validating.

use nucleus_envelope::{verify_bundle, BundleBuilder, VerifyBundleError};
use nucleus_lineage::{
    edge_content_hash, CallSpiffeId, EdgeKind, EdgeSigner, InMemorySink, LineageEdge, LineageSink,
    LocalIssuer, Proof,
};

fn pod() -> CallSpiffeId {
    CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
}

/// Sign `edge` with `issuer`, chaining against `prev`.
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

/// Emit a fully-signed 3-edge session: pod_admit → ToolCall → ArtifactProduced.
fn populate_session(sink: &InMemorySink, issuer: &LocalIssuer) {
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

#[test]
fn end_to_end_signed_bundle_verifies_after_json_round_trip() {
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    populate_session(&sink, &issuer);

    let jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();

    let bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({
            "stats": {"input_bytes": 11, "output_bytes": 17},
            "summary": "summarized output"
        }))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .unwrap();

    assert_eq!(bundle.envelope.edges.len(), 3);

    // Wire round-trip — proves the envelope serializes without losing any
    // verification material.
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: nucleus_envelope::Bundle = serde_json::from_str(&json).unwrap();

    let report = verify_bundle(&restored).expect("signed bundle must verify after round-trip");
    assert_eq!(report.edge_count, 3);
    assert_eq!(report.distinct_issuers, 1);
    assert_eq!(report.checkpoint_count, 0);
}

#[test]
fn tampered_payload_does_not_invalidate_envelope_chain() {
    // The envelope binds the *lineage*, not the payload bytes. Payload
    // integrity is the caller's responsibility (downstream wrapper, e.g. a
    // detached COSE signature over the whole Bundle — that's a v2 surface).
    // This test pins the boundary so a future change that DOES bind the
    // payload to the envelope is explicit.
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    populate_session(&sink, &issuer);
    let jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let mut bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({"summary": "original"}))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .unwrap();

    bundle.payload = serde_json::json!({"summary": "tampered"});
    verify_bundle(&bundle).expect("payload tamper does not break envelope (v1 boundary)");
}

#[test]
fn tampered_edge_breaks_chain_verification() {
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    populate_session(&sink, &issuer);
    let jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let mut bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({}))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .unwrap();

    // Tamper: rewrite the middle edge's `attrs` map (which is NOT part of
    // canonical bytes) leaves the chain intact; rewrite the `child` (which
    // IS in canonical bytes) breaks the signature.
    let new_pod = CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap();
    let attacker_child = new_pod.derive_tool("Bash", Some(b"different")).unwrap();
    bundle.envelope.edges[1].child = attacker_child;

    let err = verify_bundle(&bundle).expect_err("tampered edge must fail chain verification");
    assert!(matches!(err, VerifyBundleError::Chain { index: 1, .. }));
}

#[test]
fn reordered_edges_break_chain_verification() {
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    populate_session(&sink, &issuer);
    let jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let mut bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({}))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .unwrap();

    bundle.envelope.edges.swap(1, 2);

    let err = verify_bundle(&bundle).expect_err("reordering must fail chain verification");
    assert!(matches!(err, VerifyBundleError::Chain { .. }));
}

#[test]
fn empty_session_via_allow_empty_still_verifies() {
    let sink = InMemorySink::new();
    let bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({"stats": {}, "summary": ""}))
        .sink(&sink)
        .jwks(serde_json::from_value(serde_json::json!({"keys": []})).unwrap())
        .allow_empty()
        .build()
        .unwrap();

    let report = verify_bundle(&bundle).expect("empty envelope is structurally valid");
    assert_eq!(report.edge_count, 0);
}
