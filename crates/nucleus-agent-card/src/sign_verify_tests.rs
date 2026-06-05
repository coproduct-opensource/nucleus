//! Sign↔verify round-trip + negative tests. Gated on `feature = "sign"`
//! because they exercise [`crate::sign::sign_card`]; verification itself
//! is always available.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use nucleus_identity::JsonWebKey;

use crate::card::AgentCard;
use crate::jcs::canonicalize;
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

fn sample_card() -> AgentCard {
    AgentCard {
        spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
        did: "did:web:coder.prod.example.com".to_string(),
        security_schemes: serde_json::json!({"bearer": {"type": "http"}}),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks: good_jwks(),
    }
}

#[test]
fn sign_then_verify_happy_path() {
    let (der, pub_jwk) = p256_keypair();
    let signed = sign_card(sample_card(), &der).unwrap();
    let verified = verify_card(&signed, &pub_jwk).expect("freshly-signed card must verify");
    assert_eq!(verified.card.did, "did:web:coder.prod.example.com");
    assert_eq!(verified.advertised_jwks().keys.len(), 1);
}

#[test]
fn sign_and_verify_canonicalize_identically() {
    // The signature is over JCS(card); the verifier reconstructs JCS(card).
    // Confirm both sides agree on the exact bytes — the contract that makes
    // the detached JWS verifiable at all.
    let (der, pub_jwk) = p256_keypair();
    let card = sample_card();
    let jcs_at_sign = canonicalize(&card).unwrap();
    let signed = sign_card(card, &der).unwrap();
    let jcs_at_verify = canonicalize(&signed.card).unwrap();
    assert_eq!(
        jcs_at_sign, jcs_at_verify,
        "sign and verify must JCS identically"
    );
    verify_card(&signed, &pub_jwk).unwrap();
}

#[test]
fn flipping_one_byte_of_card_body_fails_verification() {
    let (der, pub_jwk) = p256_keypair();
    let mut signed = sign_card(sample_card(), &der).unwrap();
    // Mutate the card AFTER signing — the detached signature was over the
    // original JCS, so the reconstructed payload no longer matches.
    signed.card.did = "did:web:attacker.example.com".to_string();
    let err = verify_card(&signed, &pub_jwk).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}

#[test]
fn card_signed_by_key_a_fails_under_key_b() {
    // Proves the out-of-band resolved key is load-bearing: a perfectly
    // valid signature by A is worthless when verified against B's key.
    let (der_a, _pub_a) = p256_keypair();
    let (_der_b, pub_b) = p256_keypair();
    let signed = sign_card(sample_card(), &der_a).unwrap();
    let err = verify_card(&signed, &pub_b).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}

#[test]
fn empty_trust_jwks_is_rejected() {
    let (der, pub_jwk) = p256_keypair();
    let mut card = sample_card();
    card.trust_jwks = nucleus_lineage::Jwks { keys: vec![] };
    let signed = sign_card(card, &der).unwrap();
    let err = verify_card(&signed, &pub_jwk).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}

#[test]
fn malformed_trust_jwks_is_rejected() {
    let (der, pub_jwk) = p256_keypair();
    let mut card = sample_card();
    // A key with an undecodable `x` is malformed — can't become a
    // verifying key, so it can't anchor any bundle.
    card.trust_jwks = nucleus_lineage::Jwks {
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
    let signed = sign_card(card, &der).unwrap();
    let err = verify_card(&signed, &pub_jwk).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");
}
