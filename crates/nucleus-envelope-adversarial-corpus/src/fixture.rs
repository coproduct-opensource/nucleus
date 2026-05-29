//! Shared fixtures used to build adversarial cases.

use nucleus_envelope::{Bundle, BundleBuilder, TrustAnchor};
use nucleus_lineage::{
    canonical_edge_bytes, CallSpiffeId, EdgeKind, EdgeSigner, InMemorySink, Jwks, LineageEdge,
    LineageSink, LocalIssuer, Proof,
};

/// Deterministic issuer secret seed.
const FIXTURE_ISSUER_SEED: [u8; 32] = [0x42; 32];

pub fn known_good_issuer() -> LocalIssuer {
    use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
    let mut bytes = [0u8; SECRET_KEY_LENGTH];
    bytes.copy_from_slice(&FIXTURE_ISSUER_SEED);
    let sk = SigningKey::from_bytes(&bytes);
    let issuer_url = "https://control.fixture.local".to_string();
    let lifetime = std::time::Duration::from_secs(3600);
    LocalIssuer::from_signing_key(sk, issuer_url, lifetime)
        .expect("fixture issuer must construct cleanly")
}

pub fn known_good_issuer_jwks() -> Jwks {
    serde_json::from_value(known_good_issuer().publish_jwks())
        .expect("fixture issuer's JWKS must round-trip into Jwks")
}

pub fn fixture_pod() -> CallSpiffeId {
    CallSpiffeId::pod("fixture.nucleus.local", "agents", "summarizer")
        .expect("fixture pod id must construct")
}

/// Sign `edge` with `issuer`, chaining against `prev`.
pub fn signed_edge(
    issuer: &LocalIssuer,
    mut edge: LineageEdge,
    prev: Option<&[u8; 32]>,
) -> LineageEdge {
    let bytes = canonical_edge_bytes(&edge, prev);
    let sig = issuer.sign(&bytes).expect("issuer signs canonical bytes");
    let mut proof = Proof::new(issuer.kid(), issuer.alg(), sig);
    if let Some(h) = prev {
        proof = proof.with_prev_hash(*h);
    }
    edge.proof = Some(proof);
    edge
}

/// Populate a fresh sink with a 3-edge signed session.
pub fn populated_sink(issuer: &LocalIssuer) -> InMemorySink {
    let sink = InMemorySink::new();
    let pod = fixture_pod();

    let e0 = signed_edge(issuer, LineageEdge::pod_admit(pod.clone()), None);
    let h0 = nucleus_lineage::edge_content_hash(&e0, None);
    sink.emit(e0).expect("emit pod_admit");

    let e1 = signed_edge(
        issuer,
        LineageEdge::from_parent(
            pod.derive_tool("Read", Some(b"input-A"))
                .expect("derive_tool Read"),
            pod.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ),
        Some(&h0),
    );
    let h1 = nucleus_lineage::edge_content_hash(&e1, Some(&h0));
    sink.emit(e1).expect("emit edge 1");

    let e2 = signed_edge(
        issuer,
        LineageEdge::from_parent(
            pod.derive_tool("Write", Some(b"output-A"))
                .expect("derive_tool Write"),
            pod.clone(),
            EdgeKind::ToolCall {
                tool: "Write".to_string(),
            },
        ),
        Some(&h1),
    );
    sink.emit(e2).expect("emit edge 2");
    sink
}

pub fn known_good_bundle() -> Bundle {
    let issuer = known_good_issuer();
    let sink = populated_sink(&issuer);
    let jwks = known_good_issuer_jwks();
    BundleBuilder::new(fixture_pod())
        .payload(serde_json::json!({"summary": "ok"}))
        .sink(&sink)
        .jwks(jwks)
        .build()
        .expect("known_good_bundle must build cleanly")
}

pub fn fixture_anchor() -> TrustAnchor {
    TrustAnchor::from_jwks(known_good_issuer_jwks())
}
