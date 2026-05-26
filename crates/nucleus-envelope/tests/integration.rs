//! End-to-end: emit signed edges into a sink, build a bundle, serialize,
//! deserialize, verify standalone against an out-of-band trust anchor.
//! Plus falsification tests (tampered edge, reorder, attacker-controlled
//! JWKS) that pin the v1 security boundary.

use nucleus_envelope::{verify_bundle, BundleBuilder, TrustAnchor, VerifyBundleError};
use nucleus_lineage::{
    edge_content_hash, CallSpiffeId, EdgeKind, EdgeSigner, InMemorySink, Jwks, LineageEdge,
    LineageSink, LocalIssuer, Proof,
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

fn trusted_anchor(issuer: &LocalIssuer) -> TrustAnchor {
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    TrustAnchor::from_jwks(jwks)
}

#[test]
fn end_to_end_signed_bundle_verifies_after_json_round_trip() {
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    populate_session(&sink, &issuer);

    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();

    let bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({
            "stats": {"input_bytes": 11, "output_bytes": 17},
            "summary": "summarized output"
        }))
        .sink(&sink)
        .jwks(jwks)
        .require_signed() // catch unsigned edges at build time
        .build()
        .unwrap();

    assert_eq!(bundle.envelope.edges.len(), 3);

    // Wire round-trip — proves the envelope serializes without losing any
    // verification material.
    let json = serde_json::to_string(&bundle).unwrap();
    let restored: nucleus_envelope::Bundle = serde_json::from_str(&json).unwrap();

    let report = verify_bundle(&restored, &trusted_anchor(&issuer))
        .expect("signed bundle must verify against trusted JWKS after round-trip");
    assert_eq!(report.edge_count, 3);
    assert_eq!(report.kids.len(), 1);
    assert_eq!(report.checkpoint_count, 0);
    assert_eq!(report.trust_domain, "prod.example.com");
    assert!(!report.head_edge_hash_hex.is_empty());
    assert!(!report.trust_mode_self_check_only);
}

/// **v1 documented limitation:** the envelope binds the *lineage*, not the
/// payload bytes. A v2 wrapper (detached COSE signature over the whole
/// Bundle) is the planned tightening. This test pins the boundary so a
/// future change that DOES bind the payload is explicit, not accidental.
#[test]
fn v1_envelope_does_not_bind_payload_documented_limitation() {
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    populate_session(&sink, &issuer);
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let mut bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({"summary": "original"}))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .unwrap();

    bundle.payload = serde_json::json!({"summary": "tampered"});
    verify_bundle(&bundle, &trusted_anchor(&issuer))
        .expect("v1: payload tamper does not break envelope chain (documented)");
}

#[test]
fn tampered_edge_breaks_chain_verification() {
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    populate_session(&sink, &issuer);
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let mut bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({}))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .unwrap();

    let new_pod = CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap();
    let attacker_child = new_pod.derive_tool("Bash", Some(b"different")).unwrap();
    bundle.envelope.edges[1].child = attacker_child;

    let err = verify_bundle(&bundle, &trusted_anchor(&issuer))
        .expect_err("tampered edge must fail chain verification");
    assert!(matches!(err, VerifyBundleError::Chain { index: 1, .. }));
}

#[test]
fn reordered_edges_break_chain_verification() {
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    populate_session(&sink, &issuer);
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let mut bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({}))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .unwrap();

    bundle.envelope.edges.swap(1, 2);

    // Reordering makes the new edges[1] a non-pod-admit at position 0?
    // No — the swap is between 1 and 2; head is still pod_admit. The
    // chain break is what we expect.
    let err = verify_bundle(&bundle, &trusted_anchor(&issuer))
        .expect_err("reordering must fail chain verification");
    assert!(matches!(err, VerifyBundleError::Chain { .. }));
}

#[test]
fn empty_envelope_rejected_unless_anchor_opts_in() {
    let sink = InMemorySink::new();
    let bundle = BundleBuilder::new(pod())
        .payload(serde_json::json!({}))
        .sink(&sink)
        .jwks(Jwks { keys: vec![] })
        .allow_empty()
        .build()
        .unwrap();

    let strict = TrustAnchor::from_jwks(Jwks { keys: vec![] });
    let err = verify_bundle(&bundle, &strict).expect_err("empty envelopes authenticate nothing");
    assert!(matches!(err, VerifyBundleError::EmptyEnvelope));

    let permissive = TrustAnchor::from_jwks(Jwks { keys: vec![] }).allow_empty();
    let report = verify_bundle(&bundle, &permissive).expect("opt-in empty bundle accepted");
    assert_eq!(report.edge_count, 0);
}

/// **The CRIT-1 falsification test.** An attacker who controls the bundle
/// can put their own JWKS inside it. Without an out-of-band trust anchor,
/// every signature passes against the attacker's keys — that's the whole
/// reason `verify_bundle` requires a `TrustAnchor`.
///
/// Self-check mode validates against the embedded JWKS *and* flags the
/// report so downstream code knows it's integrity-against-itself, not
/// provenance. Out-of-band mode validates against the verifier's JWKS and
/// rejects the attacker's forgery.
#[test]
fn attacker_jwks_passes_self_check_but_fails_against_real_anchor() {
    let attacker = LocalIssuer::random().unwrap();
    let real_issuer = LocalIssuer::random().unwrap();

    // Build an entirely attacker-signed bundle with the attacker's JWKS
    // embedded. From the bundle's perspective, every signature is fine.
    let sink = InMemorySink::new();
    populate_session(&sink, &attacker);
    let attacker_jwks: Jwks = serde_json::from_value(attacker.publish_jwks()).unwrap();
    let forgery = BundleBuilder::new(pod())
        .payload(serde_json::json!({"summary": "I am the legitimate producer"}))
        .sink(&sink)
        .jwks(attacker_jwks)
        .build()
        .unwrap();

    // 1) Self-check mode — explicit opt-in to "internally consistent" only.
    //    The forgery passes because it's internally consistent. Report
    //    flags this clearly.
    let self_check_report = verify_bundle(&forgery, &TrustAnchor::self_check_only())
        .expect("self-check validates internal consistency");
    assert!(
        self_check_report.trust_mode_self_check_only,
        "report MUST flag self-check mode so downstream refuses to treat as provenance"
    );

    // 2) Real out-of-band anchor — the real issuer's JWKS. Forgery's
    //    `kid` is unknown to the real JWKS.
    let real_jwks: Jwks = serde_json::from_value(real_issuer.publish_jwks()).unwrap();
    let err = verify_bundle(&forgery, &TrustAnchor::from_jwks(real_jwks))
        .expect_err("forgery must fail against the real issuer's JWKS");
    assert!(
        matches!(err, VerifyBundleError::Chain { .. }),
        "expected chain failure (UnknownKid inside), got {err:?}"
    );
}

#[test]
fn require_signed_catches_unsigned_edges_at_build_time() {
    // Mix signed + unsigned edges, then build with require_signed.
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    let p = pod();

    let e1 = signed_edge(&issuer, LineageEdge::pod_admit(p.clone()), None);
    sink.emit(e1).unwrap();

    // Unsigned edge mixed in.
    let unsigned_tool = LineageEdge::from_parent(
        p.derive_tool("Read", Some(b"x")).unwrap(),
        p,
        EdgeKind::ToolCall {
            tool: "Read".to_string(),
        },
    );
    sink.emit(unsigned_tool).unwrap();

    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let err = BundleBuilder::new(pod())
        .payload(serde_json::json!({}))
        .sink(&sink)
        .jwks(jwks)
        .require_signed()
        .build()
        .expect_err("mixed signed/unsigned must error at build time");
    assert!(
        matches!(
            err,
            nucleus_envelope::BundleError::UnsignedEdge { index: 1 }
        ),
        "expected UnsignedEdge at index 1, got {err:?}"
    );
}
