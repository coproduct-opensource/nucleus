//! The verify-before-you-act handshake, end to end.
//!
//! HEADLINE: an agent signs a card advertising its bundle-issuer's JWKS;
//! the recipient verifies the card against an out-of-band P-256 key,
//! derives a TrustAnchor, and `verify_bundle` SUCCEEDS for a real Bundle
//! from that issuer.
//!
//! THE NEGATIVE TEST (the point): if the bundle is from a DIFFERENT issuer
//! than the card advertises, the card still verifies (it is validly
//! signed) BUT the recipient REFUSES TO ACT — `verify_bundle` against the
//! card-derived anchor FAILS.
//!
//! Requires `--features sign` for the card-signing helper.
#![cfg(feature = "sign")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use nucleus_agent_card::{sign_card, trust_anchor_from_card, verify_card, AgentCard};
use nucleus_envelope::{verify_bundle, Bundle, BundleBuilder};
use nucleus_identity::JsonWebKey;
use nucleus_lineage::{
    edge_content_hash, CallSpiffeId, EdgeKind, EdgeSigner, InMemorySink, Jwks, LineageEdge,
    LineageSink, LocalIssuer, Proof,
};

/// Generate a P-256 keypair: (PKCS#8 DER, matching public JWK).
fn p256_keypair() -> (Vec<u8>, JsonWebKey) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let der = pkcs8.as_ref().to_vec();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng).unwrap();
    let pk = kp.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pk[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pk[33..65]);
    (der, JsonWebKey::ec_p256(x, y))
}

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

/// Build a real, fully-signed 3-edge Bundle from `issuer`.
fn build_bundle(issuer: &LocalIssuer) -> Bundle {
    let sink = InMemorySink::new();
    let p = pod();

    let e1 = signed_edge(issuer, LineageEdge::pod_admit(p.clone()), None);
    let h1 = edge_content_hash(&e1, None);
    sink.emit(e1).unwrap();

    let tool = p.derive_tool("Read", Some(b"input bytes")).unwrap();
    let e2 = signed_edge(
        issuer,
        LineageEdge::from_parent(
            tool.clone(),
            p.clone(),
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

    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    BundleBuilder::new(pod())
        .payload(serde_json::json!({"summary": "summarized output"}))
        .sink(&sink)
        .jwks(jwks)
        .require_signed()
        .build()
        .unwrap()
}

/// A card advertising `issuer`'s `publish_jwks()` as its trust anchor.
fn card_for(issuer: &LocalIssuer) -> AgentCard {
    let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
    AgentCard {
        spiffe_id: "spiffe://prod.example.com/ns/agents/sa/summarizer".to_string(),
        did: "did:web:summarizer.prod.example.com".to_string(),
        security_schemes: serde_json::json!({}),
        supported_envelope_schema_versions: vec!["1".to_string(), "2".to_string()],
        jwks_uri: Some("https://summarizer.prod.example.com/.well-known/jwks.json".to_string()),
        trust_jwks: jwks,
    }
}

#[test]
fn headline_card_anchored_bundle_verifies() {
    // Out-of-band card-signing key (resolved by the recipient via DID/JWKS).
    let (card_der, card_pub) = p256_keypair();

    // The agent's bundle-signing issuer (Ed25519 lineage).
    let issuer = LocalIssuer::random().unwrap();

    // 1) Agent signs a card advertising issuer's JWKS.
    let card = card_for(&issuer);
    let signed = sign_card(card, &card_der).unwrap();

    // 2) Recipient verifies the card against the OUT-OF-BAND key.
    let verified = verify_card(&signed, &card_pub).expect("card must verify");

    // 3) Derive the TrustAnchor and verify a REAL bundle from that issuer.
    let anchor = trust_anchor_from_card(&verified);
    let bundle = build_bundle(&issuer);
    let report = verify_bundle(&bundle, &anchor)
        .expect("bundle from the card's advertised issuer MUST verify");
    assert_eq!(report.edge_count, 3);
    assert_eq!(report.trust_domain, "prod.example.com");
    assert!(!report.trust_mode_self_check_only);
}

#[test]
fn negative_mismatched_issuer_bundle_is_refused() {
    // Out-of-band card-signing key.
    let (card_der, card_pub) = p256_keypair();

    // Issuer A: the issuer the card HONESTLY advertises.
    let issuer_a = LocalIssuer::random().unwrap();
    // Issuer B: a DIFFERENT issuer that actually produced the bundle.
    let issuer_b = LocalIssuer::random().unwrap();

    // The card advertises issuer A's JWKS and is validly signed.
    let card = card_for(&issuer_a);
    let signed = sign_card(card, &card_der).unwrap();

    // The card STILL VERIFIES — it is genuinely signed by the resolved key.
    let verified =
        verify_card(&signed, &card_pub).expect("validly-signed card must verify regardless");

    // But the bundle is from issuer B, not the advertised issuer A.
    let anchor = trust_anchor_from_card(&verified);
    let bundle_from_b = build_bundle(&issuer_b);

    // THE POINT: the recipient REFUSES TO ACT. verify_bundle FAILS because
    // the bundle's edges are signed by B's kid, which is not in the card's
    // advertised (A's) JWKS.
    let err = verify_bundle(&bundle_from_b, &anchor).expect_err(
        "bundle NOT from the card's advertised issuer MUST be refused (verify_bundle fails)",
    );
    assert!(
        matches!(err, nucleus_envelope::VerifyBundleError::Chain { .. }),
        "expected a Chain verification failure (UnknownKid inside), got {err:?}"
    );
}
