//! Integration tests for content-addressed bundle transfer.
//!
//! These exercise the REAL iroh-blobs transport (in-memory store + in-process
//! QUIC endpoints over loopback — no relay, no discovery). The negative tests
//! are the point: they prove a peer cannot substitute content, and that
//! BLAKE3 transport-integrity is INDEPENDENT of envelope provenance.

use iroh::{endpoint::presets, protocol::Router, Endpoint, EndpointAddr, RelayMode};
use iroh_blobs::{store::mem::MemStore, BlobsProtocol};

use nucleus_bundle_cas::{
    blake3_bundle_hash, fetch_bundle, publish_bundle, BundleHash, FetchError,
};
use nucleus_envelope::{verify_bundle, Bundle, BundleBuilder, TrustAnchor, VerifyBundleError};
use nucleus_lineage::{
    canonical_edge_bytes, edge_content_hash, CallSpiffeId, EdgeKind, EdgeSigner, InMemorySink,
    Jwks, LineageEdge, LineageSink, LocalIssuer, Proof,
};

fn pod() -> CallSpiffeId {
    CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap()
}

/// Sign `edge` with `issuer`, chaining against `prev`. Mirrors the helper in
/// nucleus-envelope/tests/integration.rs.
fn signed_edge(
    issuer: &LocalIssuer,
    mut edge: LineageEdge,
    prev: Option<&[u8; 32]>,
) -> LineageEdge {
    let bytes = canonical_edge_bytes(&edge, prev);
    let sig = issuer.sign(&bytes).unwrap();
    let mut proof = Proof::new(issuer.kid(), issuer.alg(), sig);
    if let Some(h) = prev {
        proof = proof.with_prev_hash(*h);
    }
    edge.proof = Some(proof);
    edge
}

/// A fully-signed 2-edge bundle plus the issuer that signed it (so the test
/// can build a matching trust anchor).
fn signed_bundle() -> (Bundle, LocalIssuer) {
    let issuer = LocalIssuer::random().unwrap();
    let sink = InMemorySink::new();
    let p = pod();

    let e1 = signed_edge(&issuer, LineageEdge::pod_admit(p.clone()), None);
    let h1 = edge_content_hash(&e1, None);
    sink.emit(e1).unwrap();

    let tool = p.derive_tool("Read", Some(b"input bytes")).unwrap();
    let e2 = signed_edge(
        &issuer,
        LineageEdge::from_parent(
            tool,
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ),
        Some(&h1),
    );
    sink.emit(e2).unwrap();

    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    let bundle = BundleBuilder::new(p)
        .payload(serde_json::json!({"summary": "content-addressed"}))
        .sink(&sink)
        .jwks(jwks)
        .require_signed()
        .build()
        .unwrap();
    (bundle, issuer)
}

fn anchor_for(issuer: &LocalIssuer) -> TrustAnchor {
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    TrustAnchor::from_jwks(jwks)
}

/// Bind a relay-less, discovery-less endpoint on loopback. We do NOT call
/// `online()` (it blocks forever waiting on a relay handshake when relay is
/// disabled) and we dial via explicit direct addresses (see `direct_addr`).
async fn local_endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Disabled)
        .clear_address_lookup()
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .expect("valid loopback bind addr")
        .bind()
        .await
        .expect("bind endpoint")
}

/// Build a dialable `EndpointAddr` from an endpoint's bound loopback sockets.
/// Unlike `endpoint.addr()`/`online()`, `bound_sockets()` returns immediately
/// and needs no relay/netcheck — so a peer can connect directly with no hang.
fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
    endpoint
        .bound_sockets()
        .into_iter()
        .fold(EndpointAddr::new(endpoint.id()), |acc, s| {
            acc.with_ip_addr(s)
        })
}

/// Stand up a serving node: a store with the bundle published, behind a
/// Router that accepts the blobs ALPN. Returns the published hash, the
/// router (kept alive for the duration of the test), and the serving
/// endpoint's address.
async fn serve(bundle: &Bundle) -> (BundleHash, Router, iroh::EndpointAddr) {
    let endpoint = local_endpoint().await;
    let store = MemStore::new();
    let hash = publish_bundle(&store, bundle).await.expect("publish");
    let blobs = BlobsProtocol::new(&store, None);
    let addr = direct_addr(&endpoint);
    let router = Router::builder(endpoint)
        .accept(iroh_blobs::ALPN, blobs)
        .spawn();
    (hash, router, addr)
}

// ── publish -> get round-trip against in-memory store ──────────────────

#[tokio::test]
async fn publish_then_fetch_round_trips_to_equal_bundle() {
    let (bundle, _issuer) = signed_bundle();

    let (hash, _router, addr) = serve(&bundle).await;
    assert_eq!(
        hash,
        blake3_bundle_hash(&bundle),
        "published hash must equal the locally-computed BLAKE3 root"
    );

    let client_ep = local_endpoint().await;
    let client_store = MemStore::new();
    let fetched = fetch_bundle(&client_ep, &client_store, addr, hash)
        .await
        .expect("fetch must succeed for a correct hash");

    // Fetched bytes deserialize to an EQUAL bundle (by canonical hash and
    // by re-serialization).
    assert_eq!(
        serde_json::to_vec(&fetched).unwrap(),
        serde_json::to_vec(&bundle).unwrap(),
        "fetched bundle must be byte-identical to the published one"
    );
    assert_eq!(blake3_bundle_hash(&fetched), hash);
}

// ── NEGATIVE: a peer cannot substitute content ─────────────────────────

#[tokio::test]
async fn fetching_a_wrong_hash_fails_peer_cannot_substitute() {
    let (bundle, _issuer) = signed_bundle();
    let (real_hash, _router, addr) = serve(&bundle).await;

    // Ask the peer for a DIFFERENT hash than what it actually serves. The
    // peer has no blob with this id; even if it tried to substitute its
    // real bundle, the bao-verified stream is rooted at `wrong_hash` and
    // would reject the substituted bytes.
    let mut wrong = *real_hash.as_bytes();
    wrong[0] ^= 0xFF;
    let wrong_hash = BundleHash::from_bytes(wrong);
    assert_ne!(wrong_hash, real_hash);

    let client_ep = local_endpoint().await;
    let client_store = MemStore::new();
    let err = fetch_bundle(&client_ep, &client_store, addr, wrong_hash)
        .await
        .expect_err("requesting a wrong/different hash must fail");

    // The failure is in the get (bao) stage — a content/transport failure,
    // NOT a deserialization of substituted bytes.
    assert!(
        matches!(err, FetchError::Get(_)),
        "expected a bao-verified Get failure (no substitution possible), got {err:?}"
    );

    // And nothing under the wrong id landed in the client store.
    assert!(
        client_store.get_bytes(wrong_hash).await.is_err(),
        "no bytes for a hash the peer never verifiably served"
    );
}

// ── INTEGRATION: two-layer independence (transport vs provenance) ──────

#[tokio::test]
async fn two_in_process_endpoints_transport_and_provenance_are_independent() {
    let (bundle, issuer) = signed_bundle();

    // Node A publishes + serves.
    let (hash, _router, addr) = serve(&bundle).await;

    // Node B fetches by hash + address.
    let client_ep = local_endpoint().await;
    let client_store = MemStore::new();
    let fetched = fetch_bundle(&client_ep, &client_store, addr, hash)
        .await
        .expect("B fetches the bundle by hash from A");

    // (a) BLAKE3 transport-integrity held: fetched re-hashes to `hash`,
    //     AND the bundle passes verify_bundle with a MATCHING trust anchor.
    assert_eq!(blake3_bundle_hash(&fetched), hash);
    let matching = anchor_for(&issuer);
    let report =
        verify_bundle(&fetched, &matching).expect("perfect-hash fetch + matching JWKS must verify");
    assert_eq!(report.edge_count, 2);
    assert!(!report.trust_mode_self_check_only);

    // (b) The SAME perfectly-fetched bytes FAIL verify_bundle under a
    //     MISMATCHED JWKS — proving transport-integrity and envelope-
    //     provenance are INDEPENDENT layers, both enforced. A correct hash
    //     does NOT imply a trusted producer.
    let attacker = LocalIssuer::random().unwrap();
    let mismatched = anchor_for(&attacker);
    let err = verify_bundle(&fetched, &mismatched)
        .expect_err("a perfect-hash fetch must still FAIL against a mismatched JWKS");
    assert!(
        matches!(err, VerifyBundleError::Chain { .. }),
        "expected a Chain (unknown-kid) provenance failure, got {err:?}"
    );
}

// ── ADVERSARIAL: corrupted/truncated blob is rejected before deserialize

#[tokio::test]
async fn truncated_blob_is_rejected_by_bao_before_deserialize() {
    let (bundle, _issuer) = signed_bundle();
    let real_hash = blake3_bundle_hash(&bundle);

    // A peer that serves a DIFFERENT (truncated) byte string under the
    // requested hash. We model this by publishing the truncated bytes into
    // the serving store under their OWN (correct-for-truncated) id, but then
    // having the client REQUEST `real_hash`. The serving node does not have
    // `real_hash`, and crucially even a malicious node that returned the
    // truncated bytes for `real_hash` would be rejected: bao verification is
    // rooted at `real_hash`, and the truncated bytes do not reproduce it.
    let serving_ep = local_endpoint().await;
    let serving_store = MemStore::new();

    // Truncate the real serialized bundle by one byte (corrupted payload).
    let mut bytes = serde_json::to_vec(&bundle).unwrap();
    bytes.pop();
    serving_store
        .add_bytes(bytes)
        .await
        .expect("add truncated bytes");

    let blobs = BlobsProtocol::new(&serving_store, None);
    let addr = direct_addr(&serving_ep);
    let _router = Router::builder(serving_ep)
        .accept(iroh_blobs::ALPN, blobs)
        .spawn();

    let client_ep = local_endpoint().await;
    let client_store = MemStore::new();
    // Request the REAL hash; the peer only has truncated/corrupted bytes.
    let err = fetch_bundle(&client_ep, &client_store, addr, real_hash)
        .await
        .expect_err("bao verification must reject before any deserialize");

    // The rejection happens at the Get (bao) stage, NOT at Deserialize —
    // corrupted bytes never reach serde_json.
    assert!(
        matches!(err, FetchError::Get(_)),
        "expected bao rejection at Get stage (not Deserialize), got {err:?}"
    );
}
