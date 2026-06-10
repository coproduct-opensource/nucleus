//! End-to-end: a REAL signed card goes through [`crate::verify_card`], is
//! lifted into `Projection::Capability`, travels inside a signed
//! [`nucleus_receipt::Receipt`], and narrows back to matching claims —
//! plus the tamper test on the signed envelope.
//!
//! Gated on `sign` (to produce a genuinely signed card) AND `envelope`
//! (the lift/narrow seam under test).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use crate::card::{AgentCard, EnforcementRule, RuntimeGuaranteeProfile};
use crate::envelope::{card_claims_from_projection, to_capability_projection, CardClaims};
use crate::jwk::JsonWebKey;
use crate::sign::sign_card;
use crate::verify::verify_card;
use nucleus_receipt::{Projection, Receipt, ReceiptError, Session};

/// Generate a fresh P-256 keypair: returns (PKCS#8 DER, matching public JWK).
fn p256_keypair() -> (Vec<u8>, JsonWebKey) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let der = pkcs8.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng).unwrap();
    let pk = key_pair.public_key().as_ref();
    assert_eq!(pk.len(), 65, "uncompressed P-256 point");
    assert_eq!(pk[0], 0x04);
    let x = URL_SAFE_NO_PAD.encode(&pk[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pk[33..65]);
    (der, JsonWebKey::ec_p256(x, y))
}

fn sample_card() -> AgentCard {
    let issuer = nucleus_lineage::LocalIssuer::random().unwrap();
    AgentCard {
        spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
        did: "did:web:coder.prod.example.com".to_string(),
        security_schemes: serde_json::json!({"bearer": {"type": "http"}}),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks: serde_json::from_value(issuer.publish_jwks()).unwrap(),
        runtime_guarantees: Some(RuntimeGuaranteeProfile {
            profile_version: "1.0".to_string(),
            tracked_sources: vec!["web_content".to_string(), "secret".to_string()],
            enforcement_rules: vec![EnforcementRule {
                name: "no_adversarial_to_outbound".to_string(),
                description:
                    "deny outbound actions whose ancestry includes adversarial-integrity content"
                        .to_string(),
            }],
            attestation_reference: None,
        }),
    }
}

fn session() -> Session {
    Session {
        session_id: "spiffe://prod.example.com/ns/agents/sa/coder".into(),
        issuer_kid: "test-kid".into(),
        issued_at_micros: 1_717_000_000_000_000,
        parent_chain: vec![],
    }
}

/// The full discovery→receipt path: sign a card, verify it (the only way to
/// obtain the `VerifiedCard` witness), lift it, sign the envelope, verify the
/// envelope, narrow — and the claims match what the card declared.
#[test]
fn verified_card_travels_inside_a_signed_receipt_end_to_end() {
    // Discovery time: a real signed card, verified against the out-of-band key.
    let (der, pub_jwk) = p256_keypair();
    let signed_card = sign_card(sample_card(), &der).unwrap();
    let verified = verify_card(&signed_card, &pub_jwk).expect("freshly-signed card verifies");
    let expected = CardClaims::from(&verified);

    // Receipt time: the verified claims ride along inside the signed envelope.
    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let vk: [u8; 32] = sk.verifying_key().to_bytes();
    let receipt = Receipt::sign(session(), vec![to_capability_projection(&verified)], &sk);

    // The envelope signature binds the issuer to the carried claims.
    receipt
        .verify(&vk)
        .expect("freshly signed envelope verifies");

    // Narrow back to typed claims — they match the verified card exactly.
    let back =
        card_claims_from_projection(&receipt.projections[0]).expect("capability narrows back");
    assert_eq!(back, expected);
    assert_eq!(
        back.spiffe_id,
        "spiffe://prod.example.com/ns/agents/sa/coder"
    );
    assert_eq!(back.did, "did:web:coder.prod.example.com");
    assert_eq!(
        back.runtime_guarantees.as_ref().unwrap().enforcement_rules[0].name,
        "no_adversarial_to_outbound"
    );
    // The advertised kids are exactly the card's trust_jwks kids.
    let kids: Vec<String> = verified
        .advertised_jwks()
        .keys
        .iter()
        .map(|k| k.kid.clone())
        .collect();
    assert_eq!(back.advertised_jwks_kids, kids);
}

/// Tampering with a declared guarantee INSIDE the signed envelope is caught
/// by the receipt's signature check (`RootHashMismatch`) — the discovery-time
/// guarantee cannot be quietly rewritten in transit.
#[test]
fn tampered_guarantee_inside_signed_envelope_fails_root_hash() {
    let (der, pub_jwk) = p256_keypair();
    let signed_card = sign_card(sample_card(), &der).unwrap();
    let verified = verify_card(&signed_card, &pub_jwk).unwrap();

    let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let vk: [u8; 32] = sk.verifying_key().to_bytes();
    let mut receipt = Receipt::sign(session(), vec![to_capability_projection(&verified)], &sk);

    // Rewrite the declared enforcement rule inside the signed body.
    let Projection::Capability(body) = &mut receipt.projections[0] else {
        panic!("envelope holds a capability projection");
    };
    body["card"]["runtime_guarantees"]["enforcement_rules"][0]["name"] =
        serde_json::json!("allow_everything");

    // The envelope check fails FIRST: the re-canonicalized bytes no longer
    // match the signed root hash.
    assert!(matches!(
        receipt.verify(&vk),
        Err(ReceiptError::RootHashMismatch { .. })
    ));
}
