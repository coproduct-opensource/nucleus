//! Adversarial case builders. Each fn returns `(Bundle, TrustAnchor)`
//! such that `verify_bundle(&bundle, &anchor)` MUST return Err.

use nucleus_envelope::{Bundle, BundleBuilder, TrustAnchor};
use nucleus_lineage::{
    CallSpiffeId, EdgeKind, InMemorySink, Jwks, LineageEdge, LineageSink, LocalIssuer,
};

use crate::fixture;

/// C01 — Tampered edge child SPIFFE id.
///
/// Take a known-good bundle, rewrite one edge's `child` to point at
/// a different SPIFFE id. The per-edge proof was signed over the
/// original child URI so the signature no longer verifies against
/// the canonical bytes.
pub fn c01_tampered_edge_child() -> (Bundle, TrustAnchor) {
    let mut bundle = fixture::known_good_bundle();
    let attacker_pod =
        CallSpiffeId::pod("attacker.example.com", "evil", "different").expect("attacker pod");
    let attacker_child = attacker_pod
        .derive_tool("Drain", Some(b"siphon"))
        .expect("derive_tool");
    bundle.envelope.edges[1].child = attacker_child;
    (bundle, fixture::fixture_anchor())
}

/// C02 — Swapped edge signatures.
///
/// Two edges, each signed over its own canonical bytes. Swapping
/// the `proof.signature` fields means neither edge's signature
/// covers its own bytes — both must fail verification.
pub fn c02_swapped_edge_signatures() -> (Bundle, TrustAnchor) {
    let mut bundle = fixture::known_good_bundle();
    // Both edges have proofs; swap their `sig` fields. Neither
    // resulting signature covers its own canonical bytes.
    let p0_sig = bundle.envelope.edges[0]
        .proof
        .as_ref()
        .map(|p| p.sig.clone())
        .expect("edge 0 must be signed");
    let p1_sig = bundle.envelope.edges[1]
        .proof
        .as_ref()
        .map(|p| p.sig.clone())
        .expect("edge 1 must be signed");
    if let Some(p) = bundle.envelope.edges[0].proof.as_mut() {
        p.sig = p1_sig;
    }
    if let Some(p) = bundle.envelope.edges[1].proof.as_mut() {
        p.sig = p0_sig;
    }
    (bundle, fixture::fixture_anchor())
}

/// C03 — Truncated envelope.
///
/// Drop the last edge from a valid envelope. The verifier's chain
/// walk computes the same chain-head hash whether or not the final
/// edge is present, but the head as observed by the producer
/// differs — the resulting `head_edge_hash_hex` no longer matches
/// what an out-of-band consumer would have anchored.
///
/// In v1 this also leaves the bundle with at least one signed
/// edge, so verification of remaining edges succeeds; the
/// "rejection" comes from envelope-binding mechanisms (when
/// PayloadBinding is required) or from a downstream consumer
/// comparing chain-head against an external attestation.
///
/// Without a payload binding the envelope still verifies as a
/// fragmentary truth — which is itself a real risk, hence the
/// trust anchor explicitly demands a binding to expose this.
pub fn c03_truncated_envelope() -> (Bundle, TrustAnchor) {
    let mut bundle = fixture::known_good_bundle();
    bundle.envelope.edges.pop();
    // Without a payload binding requirement v1 accepts truncated
    // envelopes (real-world risk documented in audit MED-2). The
    // anchor here demands the binding which closes the case.
    let anchor = fixture::fixture_anchor().require_payload_binding();
    (bundle, anchor)
}

/// C04 — Empty envelope under strict allow-empty=false.
///
/// A bundle with zero lineage edges is a vacuous provenance claim;
/// the default trust anchor rejects it. Use the explicit
/// `allow_empty()` opt-in only for sentinel cases.
pub fn c04_empty_envelope_strict() -> (Bundle, TrustAnchor) {
    let issuer = fixture::known_good_issuer();
    let sink = InMemorySink::new(); // empty — no emit()
    let _ = &issuer;
    let bundle = BundleBuilder::new(fixture::fixture_pod())
        .payload(serde_json::json!({"summary": "empty"}))
        .sink(&sink)
        .jwks(fixture::known_good_issuer_jwks())
        .allow_empty() // builder allows empty…
        .build()
        .expect("empty bundle constructs in allow-empty mode");
    // …but the strict anchor does NOT, so verify_bundle rejects.
    (bundle, fixture::fixture_anchor())
}

/// C05 — Attacker JWKS embedded in the bundle.
///
/// Forger generates their own keys, builds a bundle whose
/// envelope.jwks lists the attacker key, and signs every edge with
/// the attacker key. Self-check verification would pass; out-of-band
/// verification against the producer's real JWKS must fail because
/// the trust anchor doesn't know the attacker's `kid`.
pub fn c05_attacker_jwks() -> (Bundle, TrustAnchor) {
    // Build a bundle entirely with an attacker-controlled issuer.
    let attacker = LocalIssuer::random().expect("attacker issuer constructs");
    let attacker_jwks: Jwks =
        serde_json::from_value(attacker.publish_jwks()).expect("attacker jwks parse");
    let attacker_pod =
        CallSpiffeId::pod("attacker.example.com", "evil", "subject").expect("attacker pod");

    let sink = InMemorySink::new();
    let e0 = fixture::signed_edge(
        &attacker,
        LineageEdge::pod_admit(attacker_pod.clone()),
        None,
    );
    let h0 = nucleus_lineage::edge_content_hash(&e0, None);
    sink.emit(e0).unwrap();
    let e1 = fixture::signed_edge(
        &attacker,
        LineageEdge::from_parent(
            attacker_pod
                .derive_tool("Read", Some(b"x"))
                .expect("derive_tool"),
            attacker_pod.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ),
        Some(&h0),
    );
    sink.emit(e1).unwrap();

    let bundle = BundleBuilder::new(attacker_pod)
        .payload(serde_json::json!({"summary": "from attacker"}))
        .sink(&sink)
        .jwks(attacker_jwks) // <-- bundle embeds attacker JWKS
        .build()
        .expect("attacker bundle constructs cleanly");

    // Defender's trust anchor uses the REAL fixture JWKS. Anchor
    // has no knowledge of the attacker kid, so verify rejects.
    (bundle, fixture::fixture_anchor())
}

/// C06 — Unknown kid in edge proof.
///
/// Rewrite one edge's `proof.kid` to a value that doesn't appear
/// in the bundle's JWKS. Verifier can't resolve the key, so it
/// can't even attempt signature verification — rejection at
/// chain-walk time.
pub fn c06_unknown_kid() -> (Bundle, TrustAnchor) {
    let mut bundle = fixture::known_good_bundle();
    if let Some(proof) = bundle.envelope.edges[1].proof.as_mut() {
        proof.kid = "kid-does-not-exist".to_string();
    }
    (bundle, fixture::fixture_anchor())
}

/// C07 — Edge parent points outside the session root.
///
/// Cross-session contamination: an edge claims a parent that
/// belongs to a different pod. Verifier MUST reject — this is the
/// shared-sink protection (envelopes only contain edges descending
/// from their declared session_root).
pub fn c07_foreign_parent() -> (Bundle, TrustAnchor) {
    let mut bundle = fixture::known_good_bundle();
    let foreign_pod = CallSpiffeId::pod("other.example.com", "agents", "other-sa")
        .expect("foreign pod constructs");
    // edges[1].parents is a Vec<CallSpiffeId>; rewrite to a foreign id.
    if let Some(first) = bundle.envelope.edges[1].parents.first_mut() {
        *first = foreign_pod;
    }
    (bundle, fixture::fixture_anchor())
}

/// C08 — Session root is not a pod id.
///
/// Bundle's `session_root` is a `/call/...`-suffixed call id rather
/// than a pod id. The verifier requires the session root to be a
/// pod (parent of all per-call ids); a call-id session root is
/// rejected as structurally malformed.
pub fn c08_session_root_not_pod() -> (Bundle, TrustAnchor) {
    let mut bundle = fixture::known_good_bundle();
    let pod = fixture::fixture_pod();
    // Derive a per-call id from the pod and swap it in as the root.
    let call_id = pod
        .derive_tool("Read", Some(b"some-input"))
        .expect("derive call id");
    bundle.envelope.session_root = call_id;
    (bundle, fixture::fixture_anchor())
}
