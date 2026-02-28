//! End-to-end integration tests for the SPIFFE-DID identity pipeline.
//!
//! Tests the complete flow from SVID creation through DPoP verification:
//!
//! ```text
//! CSR → CA sign → WorkloadCertificate
//!   → extract_svid_material → build_did_document → build_binding
//!     → serialize → InMemoryDidResolver → resolve → verify_binding
//!       → DpopProofBuilder → DpopVerifier
//! ```
//!
//! This proves that all identity modules compose correctly end-to-end.

use std::time::Duration;

use nucleus_identity::ca::CaClient;
use nucleus_identity::did::ServiceEndpoint;
use nucleus_identity::did_resolver::{CachingDidResolver, DidResolver, InMemoryDidResolver};
use nucleus_identity::dpop::{DpopProofBuilder, DpopVerifier};
use nucleus_identity::webfinger::{parse_webfinger_resource, WebFingerResponse};
use nucleus_identity::{
    build_binding, build_did_document, extract_svid_material, verify_binding, CsrOptions, Identity,
    SelfSignedCa,
};
use ring::signature::KeyPair;

/// Generate a fresh P-256 app signing key (PKCS#8 DER + JWK).
fn make_app_key() -> (Vec<u8>, nucleus_identity::did::JsonWebKey) {
    use base64::Engine;
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &rng,
    )
    .unwrap();

    let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap();

    let pub_bytes = key_pair.public_key().as_ref();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);

    (
        pkcs8.as_ref().to_vec(),
        nucleus_identity::did::JsonWebKey::ec_p256(&x, &y),
    )
}

// ============================================================================
// SECTION 1: FULL PIPELINE - CSR to DPoP
// ============================================================================

/// The grand integration test: exercises every module in sequence.
#[tokio::test]
async fn full_pipeline_csr_to_dpop() {
    // ── Step 1: Create a SPIFFE identity and sign a certificate ──────
    let identity = Identity::new("example.com", "production", "api-gateway");
    let ca = SelfSignedCa::new("example.com").unwrap();

    let cert_sign = CsrOptions::new(identity.to_spiffe_uri())
        .generate()
        .unwrap();
    let cert = ca
        .sign_csr(
            cert_sign.csr(),
            cert_sign.private_key(),
            &identity,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

    // ── Step 2: Extract SVID material for DID document ───────────────
    let svid_material = extract_svid_material(&cert).unwrap();
    assert!(!svid_material.fingerprint.is_empty());
    assert!(svid_material.fingerprint.starts_with("SHA256:"));
    assert!(!svid_material.chain_base64url.is_empty());

    // ── Step 3: Build a DID document ─────────────────────────────────
    let did = identity.to_did_web();
    let (app_key_der, app_key_jwk) = make_app_key();

    let did_doc = build_did_document(
        &did,
        &app_key_jwk,
        &svid_material,
        vec![ServiceEndpoint {
            id: format!("{did}#api"),
            service_type: "RestApi".into(),
            service_endpoint: "https://api-gateway.example.com/v1".into(),
            description: Some("Primary API endpoint".into()),
        }],
    );

    assert_eq!(did_doc.id, did);
    assert_eq!(did_doc.verification_method.len(), 2); // app key + SVID key
    assert!(did_doc.service.is_some());
    assert_eq!(did_doc.service.as_ref().unwrap().len(), 1);

    // Verify the DID document is valid W3C JSON
    let did_json = serde_json::to_string_pretty(&did_doc).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&did_json).unwrap();
    assert_eq!(parsed["@context"][0], "https://www.w3.org/ns/did/v1");

    // ── Step 4: Build a SPIFFE-DID binding proof ─────────────────────
    let spiffe_id = identity.to_spiffe_uri();
    let svid_key_der = cert_sign.private_key_der().unwrap();

    let binding = build_binding(
        &did,
        &spiffe_id,
        &svid_material,
        &svid_key_der,
        &app_key_der,
        &format!("{did}#app-signing-key-1"),
    )
    .unwrap();

    assert_eq!(binding.did, did);
    assert_eq!(binding.spiffe_id, spiffe_id);
    assert!(!binding.binding_proof.signature_over_did_by_svid.is_empty());
    assert!(!binding.binding_proof.signature_over_svid_by_did.is_empty());

    // ── Step 5: Serialize and deserialize (simulates network) ────────
    let binding_json = serde_json::to_string_pretty(&binding).unwrap();
    let binding_roundtrip: nucleus_identity::SpiffeDidBinding =
        serde_json::from_str(&binding_json).unwrap();
    assert_eq!(binding_roundtrip.did, binding.did);

    let did_doc_json = serde_json::to_string_pretty(&did_doc).unwrap();
    let did_doc_roundtrip: nucleus_identity::DidDocument =
        serde_json::from_str(&did_doc_json).unwrap();
    assert_eq!(did_doc_roundtrip.id, did_doc.id);

    // ── Step 6: Resolve via InMemoryDidResolver ──────────────────────
    let mut resolver = InMemoryDidResolver::new();
    resolver.insert(did_doc_roundtrip.clone());
    resolver.insert_binding(binding_roundtrip.clone());

    let (resolved_doc, resolved_binding) = resolver.resolve_with_binding(&did).await.unwrap();
    assert_eq!(resolved_doc.id, did);
    assert!(resolved_binding.is_some());

    // ── Step 7: Verify the binding ───────────────────────────────────
    let trust_bundle = ca.trust_bundle();
    let verification = verify_binding(&binding_roundtrip, &did_doc_roundtrip, Some(trust_bundle));
    assert!(
        verification.is_fully_verified(),
        "binding should be fully verified, got: {verification:?}"
    );
    assert_eq!(verification.did().unwrap(), &did);
    assert_eq!(verification.spiffe_id().unwrap(), &spiffe_id);

    // ── Step 8: Create and verify a DPoP proof ───────────────────────
    let proof = DpopProofBuilder::new("POST", "https://api-gateway.example.com/v1/orders")
        .with_spiffe_id(&spiffe_id)
        .with_access_token("at_live_order_12345")
        .build(&svid_key_der)
        .unwrap();

    let verifier = DpopVerifier::new();
    let claims = verifier
        .verify_with_token(
            &proof,
            &svid_material.public_key_jwk,
            "POST",
            "https://api-gateway.example.com/v1/orders",
            "at_live_order_12345",
        )
        .unwrap();

    assert_eq!(claims.htm, "POST");
    assert_eq!(claims.htu, "https://api-gateway.example.com/v1/orders");
    assert_eq!(claims.spiffe_id.as_deref(), Some(spiffe_id.as_str()));
    assert!(claims.ath.is_some());
}

// ============================================================================
// SECTION 2: WEBFINGER + RESOLVER INTEGRATION
// ============================================================================

#[tokio::test]
async fn webfinger_to_resolver_flow() {
    // ── Step 1: Parse a WebFinger resource query ─────────────────────
    let resource = parse_webfinger_resource("spiffe://example.com/ns/apps/sa/my-app").unwrap();
    assert_eq!(resource.as_str(), "spiffe://example.com/ns/apps/sa/my-app");

    // ── Step 2: Create a WebFinger response ──────────────────────────
    let did = "did:web:my-app.example.com";
    let webfinger = WebFingerResponse::for_spiffe_did(resource.as_str(), did);

    assert_eq!(webfinger.subject, "spiffe://example.com/ns/apps/sa/my-app");
    let did_url = webfinger.did_document_url().unwrap();
    assert_eq!(did_url, "https://my-app.example.com/.well-known/did.json");

    // ── Step 3: Resolve the DID from the WebFinger response ──────────
    let mut resolver = InMemoryDidResolver::new();
    let doc = nucleus_identity::DidDocument::new(did);
    resolver.insert(doc);

    let resolved = resolver.resolve(did).await.unwrap();
    assert_eq!(resolved.id, did);
}

// ============================================================================
// SECTION 3: CACHING RESOLVER
// ============================================================================

#[tokio::test]
async fn caching_resolver_end_to_end() {
    let identity = Identity::new("cache-test.dev", "default", "svc");
    let ca = SelfSignedCa::new("cache-test.dev").unwrap();
    let cert_sign = CsrOptions::new(identity.to_spiffe_uri())
        .generate()
        .unwrap();
    let cert = ca
        .sign_csr(
            cert_sign.csr(),
            cert_sign.private_key(),
            &identity,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

    let svid_material = extract_svid_material(&cert).unwrap();
    let did = identity.to_did_web();
    let (_, app_key_jwk) = make_app_key();

    let did_doc = build_did_document(&did, &app_key_jwk, &svid_material, vec![]);

    // Set up caching resolver
    let mut inner = InMemoryDidResolver::new();
    inner.insert(did_doc.clone());

    let caching = CachingDidResolver::new(inner, std::time::Duration::from_secs(300));

    // First resolve populates cache
    let doc1 = caching.resolve(&did).await.unwrap();
    assert_eq!(doc1.id, did);
    assert_eq!(doc1.verification_method.len(), 2);

    // Second resolve hits cache (same result)
    let doc2 = caching.resolve(&did).await.unwrap();
    assert_eq!(doc2, doc1);

    // Invalidate and re-resolve
    caching.invalidate(&did).await;
    let doc3 = caching.resolve(&did).await.unwrap();
    assert_eq!(doc3.id, did);
}

// ============================================================================
// SECTION 4: CROSS-APP DPOP DELEGATION
// ============================================================================

/// Simulates App A delegating to App B using DPoP.
#[tokio::test]
async fn cross_app_dpop_delegation() {
    // ── App A: Create identity and DPoP proof ────────────────────────
    let app_a = Identity::new("example.com", "payments", "checkout");
    let ca = SelfSignedCa::new("example.com").unwrap();

    let cert_sign_a = CsrOptions::new(app_a.to_spiffe_uri()).generate().unwrap();
    let cert_a = ca
        .sign_csr(
            cert_sign_a.csr(),
            cert_sign_a.private_key(),
            &app_a,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
    let svid_a = extract_svid_material(&cert_a).unwrap();

    let access_token = "at_delegation_abc123";
    let key_a_der = cert_sign_a.private_key_der().unwrap();

    let proof = DpopProofBuilder::new("POST", "https://orders.example.com/api/charge")
        .with_spiffe_id(&app_a.to_spiffe_uri())
        .with_access_token(access_token)
        .build(&key_a_der)
        .unwrap();

    // ── App B: Verify the DPoP proof ─────────────────────────────────
    // App B knows App A's public key (e.g., from resolving its DID document)
    let verifier = DpopVerifier::new();
    let claims = verifier
        .verify_with_token(
            &proof,
            &svid_a.public_key_jwk,
            "POST",
            "https://orders.example.com/api/charge",
            access_token,
        )
        .unwrap();

    // App B confirms:
    // 1. The proof is signed by App A's SVID key
    assert_eq!(claims.htm, "POST");
    // 2. The SPIFFE ID identifies the workload
    assert_eq!(
        claims.spiffe_id.as_deref(),
        Some(app_a.to_spiffe_uri().as_str())
    );
    // 3. The access token is bound
    assert!(claims.ath.is_some());

    // ── App B: Reject replayed proof with wrong method ───────────────
    let result = verifier.verify_with_token(
        &proof,
        &svid_a.public_key_jwk,
        "GET", // wrong method
        "https://orders.example.com/api/charge",
        access_token,
    );
    assert!(result.is_err());

    // ── App B: Reject proof from different workload ──────────────────
    let app_c = Identity::new("example.com", "shipping", "tracker");
    let cert_sign_c = CsrOptions::new(app_c.to_spiffe_uri()).generate().unwrap();
    let cert_c = ca
        .sign_csr(
            cert_sign_c.csr(),
            cert_sign_c.private_key(),
            &app_c,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();
    let svid_c = extract_svid_material(&cert_c).unwrap();

    let result = verifier.verify_with_token(
        &proof,
        &svid_c.public_key_jwk, // App C's key, not App A's
        "POST",
        "https://orders.example.com/api/charge",
        access_token,
    );
    assert!(result.is_err());
}

// ============================================================================
// SECTION 5: IDENTITY ↔ DID ROUNDTRIP
// ============================================================================

#[test]
fn identity_to_did_and_back() {
    let identity = Identity::new("prod.example.com", "backend", "user-service");

    // Identity → did:web
    let did = identity.to_did_web();
    assert!(did.starts_with("did:web:"));

    // did:web → URL
    let url = nucleus_identity::did_web_to_url(&did).unwrap();
    assert!(url.starts_with("https://"));
    assert!(url.ends_with("/did.json"));

    // did:web → Identity (requires namespace)
    let roundtrip = Identity::from_did_web(&did, "backend").unwrap();
    assert_eq!(roundtrip.trust_domain(), identity.trust_domain());
    assert_eq!(roundtrip.service_account(), identity.service_account());

    // Identity → SPIFFE URI → WebFinger resource
    let spiffe_uri = identity.to_spiffe_uri();
    let resource = parse_webfinger_resource(&spiffe_uri).unwrap();
    assert_eq!(resource.as_str(), spiffe_uri);

    // WebFinger response links to the correct DID URL
    let webfinger = WebFingerResponse::try_for_spiffe_did(&spiffe_uri, &did).unwrap();
    assert_eq!(webfinger.did_document_url().unwrap(), url);
}

// ============================================================================
// SECTION 6: PARTIAL VERIFICATION (no trust bundle)
// ============================================================================

#[tokio::test]
async fn partial_verification_without_trust_bundle() {
    let identity = Identity::new("partial.dev", "ns", "app");
    let ca = SelfSignedCa::new("partial.dev").unwrap();

    let cert_sign = CsrOptions::new(identity.to_spiffe_uri())
        .generate()
        .unwrap();
    let cert = ca
        .sign_csr(
            cert_sign.csr(),
            cert_sign.private_key(),
            &identity,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

    let svid_material = extract_svid_material(&cert).unwrap();
    let did = identity.to_did_web();
    let (app_key_der, app_key_jwk) = make_app_key();

    let did_doc = build_did_document(&did, &app_key_jwk, &svid_material, vec![]);
    let svid_key_der = cert_sign.private_key_der().unwrap();
    let binding = build_binding(
        &did,
        &identity.to_spiffe_uri(),
        &svid_material,
        &svid_key_der,
        &app_key_der,
        &format!("{did}#app-signing-key-1"),
    )
    .unwrap();

    // Verify WITHOUT trust bundle → PartiallyVerified
    let verification = verify_binding(&binding, &did_doc, None);
    assert!(
        verification.is_verified(),
        "should be at least partially verified"
    );
    assert!(
        !verification.is_fully_verified(),
        "should NOT be fully verified without trust bundle"
    );

    // Verify WITH trust bundle → FullyVerified
    let trust_bundle = ca.trust_bundle();
    let verification = verify_binding(&binding, &did_doc, Some(trust_bundle));
    assert!(
        verification.is_fully_verified(),
        "should be fully verified with trust bundle: {verification:?}"
    );
}

// ============================================================================
// SECTION 7: CROSS-TRUST-DOMAIN REJECTION
// ============================================================================

#[tokio::test]
async fn cross_trust_domain_binding_rejected() {
    // Create two CAs for different trust domains
    let ca_a = SelfSignedCa::new("domain-a.com").unwrap();
    let ca_b = SelfSignedCa::new("domain-b.com").unwrap();

    // App signed by CA A
    let app = Identity::new("domain-a.com", "ns", "app");
    let cert_sign = CsrOptions::new(app.to_spiffe_uri()).generate().unwrap();
    let cert = ca_a
        .sign_csr(
            cert_sign.csr(),
            cert_sign.private_key(),
            &app,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

    let svid_material = extract_svid_material(&cert).unwrap();
    let did = app.to_did_web();
    let (app_key_der, app_key_jwk) = make_app_key();

    let did_doc = build_did_document(&did, &app_key_jwk, &svid_material, vec![]);
    let svid_key_der = cert_sign.private_key_der().unwrap();
    let binding = build_binding(
        &did,
        &app.to_spiffe_uri(),
        &svid_material,
        &svid_key_der,
        &app_key_der,
        &format!("{did}#app-signing-key-1"),
    )
    .unwrap();

    // Verify with CA B's trust bundle → should NOT be fully verified
    let trust_bundle_b = ca_b.trust_bundle();
    let verification = verify_binding(&binding, &did_doc, Some(trust_bundle_b));
    assert!(
        !verification.is_fully_verified(),
        "should reject binding verified against wrong trust domain"
    );
}
