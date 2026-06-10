//! A2A v1.0 §8.4 conformance suite — pins this crate's signing surface to
//! the SPEC's own worked examples and MUSTs, not merely to itself.
//!
//! Spec ground truth: docs/specification.md @ a2aproject/A2A v1.0.1
//! (normative data shapes: specification/a2a.proto, package lf.a2a.v1).
//! Gated on `feature = "sign"` like the round-trip suite — the negative
//! cases hand-craft signatures.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use crate::card::{
    AgentCapabilities, AgentCard, AgentCardSignature, AgentInterface, NucleusClaims,
    A2A_PROTOCOL_VERSION,
};
use crate::jcs::canonicalize;
use crate::jwk::JsonWebKey;
use crate::sign::sign_card;
use crate::verify::verify_card;

fn p256_keypair() -> (Vec<u8>, JsonWebKey) {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let der = pkcs8.as_ref().to_vec();
    let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng).unwrap();
    let pk = key_pair.public_key().as_ref();
    let x = URL_SAFE_NO_PAD.encode(&pk[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pk[33..65]);
    (der, JsonWebKey::ec_p256(x, y))
}

/// A FIXED (non-random) advertised JWKS so canonical bytes can be golden
/// -pinned. The verify path only requires it to be well-formed Ed25519.
fn fixed_jwks() -> nucleus_lineage::Jwks {
    serde_json::from_value(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "kid": "conformance-k1",
            // 32 zero bytes, base64url — a valid point encoding for
            // parsing purposes (never used to verify anything here).
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        }]
    }))
    .unwrap()
}

fn fixed_claims() -> NucleusClaims {
    NucleusClaims {
        spiffe_id: "spiffe://conformance.example.com/ns/agents/sa/golden".to_string(),
        did: "did:web:golden.conformance.example.com".to_string(),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks: fixed_jwks(),
        runtime_guarantees: None,
    }
}

/// The §8.4.1 worked example's card fragment, completed into a full card
/// (the spec fragment omits fields that are REQUIRED on the wire).
fn spec_example_card() -> AgentCard {
    AgentCard {
        name: "Example Agent".to_string(),
        description: "".to_string(),
        supported_interfaces: vec![AgentInterface {
            url: "https://agent.example.com/a2a/v1".to_string(),
            protocol_binding: "JSONRPC".to_string(),
            tenant: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }],
        provider: None,
        version: "1.0.0".to_string(),
        documentation_url: None,
        capabilities: AgentCapabilities {
            // Explicitly set to their defaults — §8.4.1 says explicitly-set
            // optionals MUST be included.
            streaming: Some(false),
            push_notifications: Some(false),
            extensions: vec![],
            extended_agent_card: None,
        },
        security_schemes: serde_json::Map::new(),
        security_requirements: vec![],
        default_input_modes: vec!["application/json".to_string()],
        default_output_modes: vec!["application/json".to_string()],
        skills: vec![],
        signatures: vec![],
        icon_url: None,
    }
}

/// §8.4.1 worked example, decision by decision. The spec's expected output
/// for the fragment is
/// `{"capabilities":{"pushNotifications":false,"streaming":false},"description":"","name":"Example Agent","skills":[]}`
/// — we assert each of its decisions on the completed card's canonical
/// bytes.
#[test]
fn spec_8_4_1_worked_example_decisions_hold() {
    let canon = String::from_utf8(canonicalize(&spec_example_card()).unwrap()).unwrap();

    // Explicitly-set optional defaults are INCLUDED; empty repeated
    // `extensions` is OMITTED; keys are lexicographic — this exact
    // substring is the spec's own expected capabilities object.
    assert!(
        canon.contains(r#""capabilities":{"pushNotifications":false,"streaming":false}"#),
        "{canon}"
    );
    // REQUIRED empty string is INCLUDED.
    assert!(canon.contains(r#""description":"""#), "{canon}");
    // REQUIRED empty array is INCLUDED.
    assert!(canon.contains(r#""skills":[]"#), "{canon}");
    // Unset optionals are absent entirely.
    for absent in ["extendedAgentCard", "extensions", "provider", "iconUrl"] {
        assert!(!canon.contains(absent), "{absent} must be omitted: {canon}");
    }
    // RFC 8785 lexicographic top-level ordering.
    let order = [
        "capabilities",
        "defaultInputModes",
        "defaultOutputModes",
        "description",
        "name",
    ];
    let idx: Vec<usize> = order
        .iter()
        .map(|k| canon.find(&format!("\"{k}\"")).unwrap())
        .collect();
    assert!(idx.windows(2).all(|w| w[0] < w[1]), "{canon}");
}

/// GOLDEN PIN: the exact canonical bytes of a fully deterministic card
/// (fixed claims, fixed JWKS). Any change to field naming, presence rules,
/// extension layout, or JCS behavior breaks this byte string — that is the
/// point. Regenerate ONLY for a deliberate, spec-cited wire change.
#[test]
fn golden_canonical_bytes_are_pinned() {
    let card = spec_example_card()
        .with_nucleus_claims(&fixed_claims())
        .unwrap();
    let canon = String::from_utf8(canonicalize(&card).unwrap()).unwrap();
    let expected = concat!(
        r#"{"capabilities":{"extensions":[{"description":"nucleus verify-before-you-act claims: SPIFFE/DID identity, trust JWKS, envelope schema versions, runtime-guarantee profile","params":{"did":"did:web:golden.conformance.example.com","spiffeId":"spiffe://conformance.example.com/ns/agents/sa/golden","supportedEnvelopeSchemaVersions":["1"],"trustJwks":{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"conformance-k1","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}},"uri":"https://coproduct.one/a2a/ext/runtime-guarantees/v1"}],"pushNotifications":false,"streaming":false},"#,
        r#""defaultInputModes":["application/json"],"defaultOutputModes":["application/json"],"description":"","name":"Example Agent","#,
        r#""skills":[],"supportedInterfaces":[{"protocolBinding":"JSONRPC","protocolVersion":"1.0","url":"https://agent.example.com/a2a/v1"}],"version":"1.0.0"}"#
    );
    assert_eq!(canon, expected);
}

/// §8.4.2: the protected header is exactly `{alg, typ, kid}` with the
/// spec-required values — the same parameter set as the spec's own
/// example header.
#[test]
fn protected_header_is_spec_shaped() {
    let (der, _) = p256_keypair();
    let signed = sign_card(
        spec_example_card()
            .with_nucleus_claims(&fixed_claims())
            .unwrap(),
        &der,
        "key-1",
    )
    .unwrap();
    let header_bytes = URL_SAFE_NO_PAD
        .decode(&signed.signatures[0].protected)
        .unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "JOSE");
    assert_eq!(header["kid"], "key-1");
    assert_eq!(header.as_object().unwrap().len(), 3, "{header}");
}

/// §8.4.1 rule 1 exists so cards can be RECONSTRUCTED: a signed card that
/// travels through serde (wire JSON -> struct) must still verify,
/// including explicit-default presence.
#[test]
fn reconstruction_round_trip_preserves_signature() {
    let (der, jwk) = p256_keypair();
    let signed = sign_card(
        spec_example_card()
            .with_nucleus_claims(&fixed_claims())
            .unwrap(),
        &der,
        "key-1",
    )
    .unwrap();
    let wire = serde_json::to_string(&signed).unwrap();
    let reconstructed: AgentCard = serde_json::from_str(&wire).unwrap();
    verify_card(&reconstructed, &jwk).expect("reconstructed card verifies");
}

/// Presence is SIGNATURE-BOUND: a card signed with `streaming` unset must
/// not verify after someone "helpfully" materializes the default.
#[test]
fn explicit_default_materialization_breaks_the_signature() {
    let (der, jwk) = p256_keypair();
    let mut card = spec_example_card()
        .with_nucleus_claims(&fixed_claims())
        .unwrap();
    card.capabilities.streaming = None;
    let mut signed = sign_card(card, &der, "key-1").unwrap();
    verify_card(&signed, &jwk).expect("baseline verifies");
    signed.capabilities.streaming = Some(false);
    assert!(verify_card(&signed, &jwk).is_err());
}

/// §8.4.1 rule 3 + §8.4.3 co-signing: `signatures` never enters the signed
/// content, so (a) canonical bytes are identical before/after signing and
/// (b) appending a second signature keeps the first valid.
#[test]
fn signatures_are_excluded_and_append_only() {
    let (der1, jwk1) = p256_keypair();
    let (der2, _) = p256_keypair();
    let card = spec_example_card()
        .with_nucleus_claims(&fixed_claims())
        .unwrap();
    let before = canonicalize(&card).unwrap();
    let signed_once = sign_card(card, &der1, "key-1").unwrap();
    assert_eq!(before, canonicalize(&signed_once).unwrap());
    let signed_twice = sign_card(signed_once, &der2, "key-2").unwrap();
    assert_eq!(before, canonicalize(&signed_twice).unwrap());
    // verify_card checks the FIRST signature — still key-1's.
    verify_card(&signed_twice, &jwk1).expect("first signature survives co-signing");
}

/// §8.4.2: a protected header missing `kid` (or carrying an empty one) is
/// nonconformant and must be rejected — even when the signature itself
/// would cryptographically verify.
#[test]
fn missing_or_empty_kid_is_rejected() {
    let (der, jwk) = p256_keypair();
    let card = spec_example_card()
        .with_nucleus_claims(&fixed_claims())
        .unwrap();
    let jcs = canonicalize(&card).unwrap();

    for header in [
        r#"{"alg":"ES256","typ":"JOSE"}"#,
        r#"{"alg":"ES256","typ":"JOSE","kid":""}"#,
    ] {
        let compact =
            nucleus_identity::did_crypto::jws_sign_es256_with_protected_header(header, &jcs, &der)
                .unwrap();
        let parts: Vec<&str> = compact.splitn(3, '.').collect();
        let mut bad = card.clone();
        bad.signatures = vec![AgentCardSignature {
            protected: parts[0].to_string(),
            signature: parts[2].to_string(),
            header: None,
        }];
        let err = verify_card(&bad, &jwk).unwrap_err();
        assert!(format!("{err}").contains("kid"), "{err}");
    }
}

/// Tampering with ANY field after signing — including inside the nucleus
/// extension params — must fail verification.
#[test]
fn any_post_signing_tamper_is_rejected() {
    let (der, jwk) = p256_keypair();
    let signed = sign_card(
        spec_example_card()
            .with_nucleus_claims(&fixed_claims())
            .unwrap(),
        &der,
        "key-1",
    )
    .unwrap();

    let mut t1 = signed.clone();
    t1.name = "Renamed Agent".to_string();
    assert!(verify_card(&t1, &jwk).is_err());

    let mut t2 = signed.clone();
    t2.capabilities.extensions[0]
        .params
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .insert("spiffeId".to_string(), "spiffe://evil/sa/mallory".into());
    assert!(verify_card(&t2, &jwk).is_err());

    let mut t3 = signed;
    t3.supported_interfaces[0].url = "https://evil.example.com/a2a/v1".to_string();
    assert!(verify_card(&t3, &jwk).is_err());
}
