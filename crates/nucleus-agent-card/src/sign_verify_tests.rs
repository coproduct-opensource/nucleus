//! Sign↔verify round-trip + negative tests. Gated on `feature = "sign"`
//! because they exercise [`crate::sign::sign_card`]; verification itself
//! is always available.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use crate::card::{
    AgentCapabilities, AgentCard, AgentInterface, NucleusClaims, A2A_PROTOCOL_VERSION,
};
use crate::jcs::canonicalize;
use crate::jwk::JsonWebKey;
use crate::sign::sign_card;
use crate::verify::verify_card;

/// Generate a fresh P-256 keypair: returns (PKCS#8 DER, matching public JWK).
fn p256_keypair() -> (Vec<u8>, JsonWebKey) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let der = pkcs8.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng).unwrap();

    // public_key() is the uncompressed EC point: 0x04 || x[32] || y[32].
    let pk = key_pair.public_key().as_ref();
    assert_eq!(pk.len(), 65, "uncompressed P-256 point");
    assert_eq!(pk[0], 0x04);
    let x = URL_SAFE_NO_PAD.encode(&pk[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pk[33..65]);
    (der, JsonWebKey::ec_p256(x, y))
}

/// A real, well-formed Ed25519 JWKS produced by an in-process issuer
/// (the `dev` feature is active during test builds via the dev-dependency).
fn good_jwks() -> nucleus_lineage::Jwks {
    let issuer = nucleus_lineage::LocalIssuer::random().unwrap();
    serde_json::from_value(issuer.publish_jwks()).unwrap()
}

fn claims_with(jwks: nucleus_lineage::Jwks) -> NucleusClaims {
    NucleusClaims {
        spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
        did: "did:web:coder.prod.example.com".to_string(),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks: jwks,
        runtime_guarantees: None,
    }
}

fn base_card() -> AgentCard {
    AgentCard {
        name: "Coder Agent".to_string(),
        description: "sign/verify round-trip tests".to_string(),
        supported_interfaces: vec![AgentInterface {
            url: "https://coder.prod.example.com/a2a/v1".to_string(),
            protocol_binding: "JSONRPC".to_string(),
            tenant: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }],
        provider: None,
        version: "1.0.0".to_string(),
        documentation_url: None,
        capabilities: AgentCapabilities::default(),
        security_schemes: Default::default(),
        security_requirements: vec![],
        default_input_modes: vec!["application/json".to_string()],
        default_output_modes: vec!["application/json".to_string()],
        skills: vec![],
        signatures: vec![],
        icon_url: None,
    }
}

fn sample_card() -> AgentCard {
    base_card()
        .with_nucleus_claims(&claims_with(good_jwks()))
        .unwrap()
}

#[test]
fn sign_then_verify_happy_path() {
    let (der, pub_jwk) = p256_keypair();
    let signed = sign_card(sample_card(), &der, "card-key-1").unwrap();
    let verified = verify_card(&signed, &pub_jwk).expect("freshly-signed card must verify");
    assert_eq!(verified.claims.did, "did:web:coder.prod.example.com");
    assert_eq!(verified.advertised_jwks().keys.len(), 1);
}

#[test]
fn protected_header_carries_alg_typ_kid_per_8_4_2() {
    // §8.4.2: the protected header MUST include alg, typ (SHOULD "JOSE")
    // and kid.
    let (der, _pub_jwk) = p256_keypair();
    let signed = sign_card(sample_card(), &der, "card-key-1").unwrap();
    let protected = URL_SAFE_NO_PAD
        .decode(&signed.signatures[0].protected)
        .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&protected).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "JOSE");
    assert_eq!(header["kid"], "card-key-1");
}

#[test]
fn sign_and_verify_canonicalize_identically() {
    // The signature is over JCS(card minus signatures); the verifier
    // reconstructs the same bytes FROM THE SIGNED CARD — the §8.4.1
    // signature-exclusion rule is what makes these equal.
    let (der, pub_jwk) = p256_keypair();
    let card = sample_card();
    let jcs_at_sign = canonicalize(&card).unwrap();
    let signed = sign_card(card, &der, "card-key-1").unwrap();
    let jcs_at_verify = canonicalize(&signed).unwrap();
    assert_eq!(
        jcs_at_sign, jcs_at_verify,
        "sign and verify must JCS identically"
    );
    verify_card(&signed, &pub_jwk).unwrap();
}

#[test]
fn second_signature_keeps_the_first_valid() {
    // §8.4.3: multiple signatures MAY be present (key rotation). Because
    // the canonical payload excludes ALL signatures, appending a second
    // one must not invalidate the first — which is the one verify_card
    // checks.
    let (der_a, pub_a) = p256_keypair();
    let (der_b, _pub_b) = p256_keypair();
    let signed_once = sign_card(sample_card(), &der_a, "key-a").unwrap();
    let signed_twice = sign_card(signed_once, &der_b, "key-b").unwrap();
    assert_eq!(signed_twice.signatures.len(), 2);
    verify_card(&signed_twice, &pub_a).expect("first signature still verifies");
}

#[test]
fn flipping_one_byte_of_card_body_fails_verification() {
    let (der, pub_jwk) = p256_keypair();
    let mut signed = sign_card(sample_card(), &der, "card-key-1").unwrap();
    // Mutate the card AFTER signing — the detached signature was over the
    // original JCS, so the reconstructed payload no longer matches.
    signed.name = "Imposter Agent".to_string();
    let err = verify_card(&signed, &pub_jwk).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}

#[test]
fn tampering_the_nucleus_claims_fails_verification() {
    // The claims travel inside capabilities.extensions — part of the
    // signed content, so identity swaps are caught.
    let (der, pub_jwk) = p256_keypair();
    let mut signed = sign_card(sample_card(), &der, "card-key-1").unwrap();
    let mut claims = signed.nucleus_claims().unwrap().unwrap();
    claims.did = "did:web:attacker.example.com".to_string();
    signed = signed.with_nucleus_claims(&claims).unwrap();
    let err = verify_card(&signed, &pub_jwk).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}

#[test]
fn card_signed_by_key_a_fails_under_key_b() {
    // Proves the out-of-band resolved key is load-bearing: a perfectly
    // valid signature by A is worthless when verified against B's key.
    let (der_a, _pub_a) = p256_keypair();
    let (_der_b, pub_b) = p256_keypair();
    let signed = sign_card(sample_card(), &der_a, "card-key-1").unwrap();
    let err = verify_card(&signed, &pub_b).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}

#[test]
fn card_without_nucleus_extension_is_rejected() {
    // A validly signed plain A2A card with no nucleus claims cannot anchor
    // anything — verify_card refuses it.
    let (der, pub_jwk) = p256_keypair();
    let signed = sign_card(base_card(), &der, "card-key-1").unwrap();
    let err = verify_card(&signed, &pub_jwk).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}

#[test]
fn empty_trust_jwks_is_rejected() {
    let (der, pub_jwk) = p256_keypair();
    let card = base_card()
        .with_nucleus_claims(&claims_with(nucleus_lineage::Jwks { keys: vec![] }))
        .unwrap();
    let signed = sign_card(card, &der, "card-key-1").unwrap();
    let err = verify_card(&signed, &pub_jwk).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}

#[test]
fn malformed_trust_jwks_is_rejected() {
    let (der, pub_jwk) = p256_keypair();
    // A key with an undecodable `x` is malformed — can't become a
    // verifying key, so it can't anchor any bundle.
    let bad = nucleus_lineage::Jwks {
        keys: vec![nucleus_lineage::Jwk {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            kid: "broken".to_string(),
            x: Some("!!! not base64url !!!".to_string()),
            alg: Some("EdDSA".to_string()),
            use_: Some("sig".to_string()),
            not_before: None,
            not_after: None,
        }],
    };
    let card = base_card().with_nucleus_claims(&claims_with(bad)).unwrap();
    let signed = sign_card(card, &der, "card-key-1").unwrap();
    let err = verify_card(&signed, &pub_jwk).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}

fn sample_profile() -> crate::RuntimeGuaranteeProfile {
    crate::RuntimeGuaranteeProfile {
        profile_version: "1.0".to_string(),
        tracked_sources: vec!["web_content".to_string(), "secret".to_string()],
        enforcement_rules: vec![crate::EnforcementRule {
            name: "no_adversarial_to_outbound".to_string(),
            description:
                "deny outbound actions whose ancestry includes adversarial-integrity content"
                    .to_string(),
        }],
        attestation_reference: None,
    }
}

#[test]
fn sign_and_verify_with_runtime_guarantees_roundtrip() {
    let (der, pub_jwk) = p256_keypair();
    let mut claims = claims_with(good_jwks());
    claims.runtime_guarantees = Some(sample_profile());
    let card = base_card().with_nucleus_claims(&claims).unwrap();
    let signed = sign_card(card, &der, "card-key-1").unwrap();
    let verified = verify_card(&signed, &pub_jwk).expect("card with profile must verify");
    let prof = verified
        .claims
        .runtime_guarantees
        .as_ref()
        .expect("profile present");
    assert_eq!(prof.enforcement_rules[0].name, "no_adversarial_to_outbound");
}

#[test]
fn tampering_runtime_guarantees_breaks_signature() {
    let (der, pub_jwk) = p256_keypair();
    let mut claims = claims_with(good_jwks());
    claims.runtime_guarantees = Some(sample_profile());
    let card = base_card().with_nucleus_claims(&claims).unwrap();
    let mut signed = sign_card(card, &der, "card-key-1").unwrap();
    // Flip a declared rule name AFTER signing → JCS changes → signature
    // must fail. Mutate the raw extension params in place.
    let ext = signed
        .capabilities
        .extensions
        .iter_mut()
        .find(|e| e.uri == crate::NUCLEUS_EXTENSION_URI)
        .unwrap();
    ext.params.as_mut().unwrap()["runtimeGuarantees"]["enforcementRules"][0]["name"] =
        serde_json::json!("allow_everything");
    assert!(
        verify_card(&signed, &pub_jwk).is_err(),
        "a tampered runtime-guarantee profile must fail verification"
    );
}

/// Regenerates `sdks/verifier-js/test/fixtures/agent-card.json`.
///
/// Run manually after any wire-shape change:
///
/// ```bash
/// cargo test -p nucleus-agent-card --features sign \
///   print_verifier_js_fixture -- --ignored --nocapture
/// ```
///
/// and paste the JSON between the BEGIN/END markers into the fixture.
#[test]
#[ignore = "fixture generator — run with --ignored --nocapture to regenerate"]
fn print_verifier_js_fixture() {
    let (der, pub_jwk) = p256_keypair();
    let (_other_der, wrong_jwk) = p256_keypair();

    let mut claims = claims_with(nucleus_lineage::Jwks {
        keys: vec![nucleus_lineage::Jwk {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            kid: "issuer-k1".to_string(),
            x: Some("6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw".to_string()),
            alg: Some("EdDSA".to_string()),
            use_: Some("sig".to_string()),
            not_before: None,
            not_after: None,
        }],
    });
    claims.runtime_guarantees = Some(crate::RuntimeGuaranteeProfile {
        profile_version: "1.0".to_string(),
        tracked_sources: vec!["web_content".to_string(), "secret".to_string()],
        enforcement_rules: vec![crate::EnforcementRule {
            name: "no_adversarial_to_outbound".to_string(),
            description: "deny outbound actions tainted by adversarial content".to_string(),
        }],
        attestation_reference: None,
    });
    let card = base_card().with_nucleus_claims(&claims).unwrap();
    let signed = sign_card(card, &der, "card-key-1").unwrap();
    verify_card(&signed, &pub_jwk).expect("fixture card must verify before shipping");

    let fixture = serde_json::json!({
        "_generated_by": "nucleus-agent-card print_verifier_js_fixture (sign_card with an ephemeral ring P-256 key — a TEST key; resolved_jwk is the matching public key a recipient would resolve out-of-band; wrong_jwk is a second, unrelated P-256 key). A2A v1.0 card shape.",
        "resolved_jwk": pub_jwk,
        "signed_card": signed,
        "wrong_jwk": wrong_jwk,
    });
    println!("BEGIN-FIXTURE");
    println!("{}", serde_json::to_string_pretty(&fixture).unwrap());
    println!("END-FIXTURE");
}
