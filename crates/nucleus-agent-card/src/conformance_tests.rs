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

use std::collections::BTreeMap;

use crate::card::{
    AgentCapabilities, AgentCard, AgentCardSignature, AgentInterface, ApiKeySecurityScheme,
    AuthorizationCodeOAuthFlow, ClientCredentialsOAuthFlow, DeviceCodeOAuthFlow,
    HttpAuthSecurityScheme, ImplicitOAuthFlow, MutualTlsSecurityScheme, NucleusClaims,
    OAuth2SecurityScheme, OAuthFlows, OpenIdConnectSecurityScheme, PasswordOAuthFlow,
    SecurityScheme, A2A_PROTOCOL_VERSION,
};
use crate::jcs::{canonicalize, canonicalize_received};
use crate::jwk::JsonWebKey;
use crate::sign::sign_card;
use crate::verify::{verify_card, verify_card_json, verify_card_signature};

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
        security_schemes: Default::default(),
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

/// A fully deterministic `securitySchemes` map covering all five
/// `SecurityScheme` oneof variants AND all five `OAuthFlows` oneof
/// variants (one oauth2 scheme per flow).
fn populated_security_schemes() -> BTreeMap<String, SecurityScheme> {
    let entries = [
        (
            "api-key",
            SecurityScheme::ApiKey(ApiKeySecurityScheme {
                description: String::new(),
                location: "header".to_string(),
                name: "X-Api-Key".to_string(),
            }),
        ),
        (
            "bearer",
            SecurityScheme::HttpAuth(HttpAuthSecurityScheme {
                description: String::new(),
                scheme: "Bearer".to_string(),
                bearer_format: "JWT".to_string(),
            }),
        ),
        (
            "mtls",
            SecurityScheme::MutualTls(MutualTlsSecurityScheme::default()),
        ),
        (
            "oauth-ac",
            SecurityScheme::OAuth2(OAuth2SecurityScheme {
                description: String::new(),
                flows: OAuthFlows::AuthorizationCode(AuthorizationCodeOAuthFlow {
                    authorization_url: "https://auth.example.com/authorize".to_string(),
                    token_url: "https://auth.example.com/token".to_string(),
                    refresh_url: String::new(),
                    scopes: BTreeMap::from([("read".to_string(), "Read access".to_string())]),
                    pkce_required: true,
                }),
                oauth2_metadata_url:
                    "https://auth.example.com/.well-known/oauth-authorization-server".to_string(),
            }),
        ),
        (
            "oauth-cc",
            SecurityScheme::OAuth2(OAuth2SecurityScheme {
                description: String::new(),
                flows: OAuthFlows::ClientCredentials(ClientCredentialsOAuthFlow {
                    token_url: "https://auth.example.com/token".to_string(),
                    refresh_url: String::new(),
                    scopes: BTreeMap::new(),
                }),
                oauth2_metadata_url: String::new(),
            }),
        ),
        (
            "oauth-dc",
            SecurityScheme::OAuth2(OAuth2SecurityScheme {
                description: String::new(),
                flows: OAuthFlows::DeviceCode(DeviceCodeOAuthFlow {
                    device_authorization_url: "https://auth.example.com/device".to_string(),
                    token_url: "https://auth.example.com/token".to_string(),
                    refresh_url: String::new(),
                    scopes: BTreeMap::new(),
                }),
                oauth2_metadata_url: String::new(),
            }),
        ),
        (
            "oauth-implicit",
            SecurityScheme::OAuth2(OAuth2SecurityScheme {
                description: String::new(),
                flows: OAuthFlows::Implicit(ImplicitOAuthFlow {
                    authorization_url: "https://auth.example.com/authorize".to_string(),
                    ..Default::default()
                }),
                oauth2_metadata_url: String::new(),
            }),
        ),
        (
            "oauth-password",
            SecurityScheme::OAuth2(OAuth2SecurityScheme {
                description: String::new(),
                flows: OAuthFlows::Password(PasswordOAuthFlow {
                    token_url: "https://auth.example.com/token".to_string(),
                    ..Default::default()
                }),
                oauth2_metadata_url: String::new(),
            }),
        ),
        (
            "oidc",
            SecurityScheme::OpenIdConnect(OpenIdConnectSecurityScheme {
                description: String::new(),
                open_id_connect_url:
                    "https://accounts.example.com/.well-known/openid-configuration".to_string(),
            }),
        ),
    ];
    entries
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
}

/// GOLDEN PIN, populated `securitySchemes`: the exact canonical bytes the
/// typed model signs for every scheme variant and every OAuth flow
/// variant. The oneof wrapper objects (`{"mtlsSecurityScheme":{}}`, …) are
/// the ProtoJSON encoding the normative `a2a.proto` prescribes — the same
/// shape as the spec's §8.5 sample card entry
/// `{"google":{"openIdConnectSecurityScheme":{...}}}`. Presence decisions
/// pinned here: REQUIRED `scopes` stays on the wire even when empty;
/// optional empty strings (`refreshUrl`, `description`,
/// `oauth2MetadataUrl`) and default `pkceRequired:false` are omitted.
#[test]
fn golden_canonical_bytes_with_populated_security_schemes_are_pinned() {
    let mut card = spec_example_card()
        .with_nucleus_claims(&fixed_claims())
        .unwrap();
    card.security_schemes = populated_security_schemes();
    let canon = String::from_utf8(canonicalize(&card).unwrap()).unwrap();
    let expected = concat!(
        r#"{"capabilities":{"extensions":[{"description":"nucleus verify-before-you-act claims: SPIFFE/DID identity, trust JWKS, envelope schema versions, runtime-guarantee profile","params":{"did":"did:web:golden.conformance.example.com","spiffeId":"spiffe://conformance.example.com/ns/agents/sa/golden","supportedEnvelopeSchemaVersions":["1"],"trustJwks":{"keys":[{"alg":"EdDSA","crv":"Ed25519","kid":"conformance-k1","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}},"uri":"https://coproduct.one/a2a/ext/runtime-guarantees/v1"}],"pushNotifications":false,"streaming":false},"#,
        r#""defaultInputModes":["application/json"],"defaultOutputModes":["application/json"],"description":"","name":"Example Agent","#,
        r#""securitySchemes":{"#,
        r#""api-key":{"apiKeySecurityScheme":{"location":"header","name":"X-Api-Key"}},"#,
        r#""bearer":{"httpAuthSecurityScheme":{"bearerFormat":"JWT","scheme":"Bearer"}},"#,
        r#""mtls":{"mtlsSecurityScheme":{}},"#,
        r#""oauth-ac":{"oauth2SecurityScheme":{"flows":{"authorizationCode":{"authorizationUrl":"https://auth.example.com/authorize","pkceRequired":true,"scopes":{"read":"Read access"},"tokenUrl":"https://auth.example.com/token"}},"oauth2MetadataUrl":"https://auth.example.com/.well-known/oauth-authorization-server"}},"#,
        r#""oauth-cc":{"oauth2SecurityScheme":{"flows":{"clientCredentials":{"scopes":{},"tokenUrl":"https://auth.example.com/token"}}}},"#,
        r#""oauth-dc":{"oauth2SecurityScheme":{"flows":{"deviceCode":{"deviceAuthorizationUrl":"https://auth.example.com/device","scopes":{},"tokenUrl":"https://auth.example.com/token"}}}},"#,
        r#""oauth-implicit":{"oauth2SecurityScheme":{"flows":{"implicit":{"authorizationUrl":"https://auth.example.com/authorize"}}}},"#,
        r#""oauth-password":{"oauth2SecurityScheme":{"flows":{"password":{"tokenUrl":"https://auth.example.com/token"}}}},"#,
        r#""oidc":{"openIdConnectSecurityScheme":{"openIdConnectUrl":"https://accounts.example.com/.well-known/openid-configuration"}}},"#,
        r#""skills":[],"supportedInterfaces":[{"protocolBinding":"JSONRPC","protocolVersion":"1.0","url":"https://agent.example.com/a2a/v1"}],"version":"1.0.0"}"#
    );
    assert_eq!(canon, expected);
}

/// The schemes are inside the signed content: a card signed with a
/// populated map verifies after a wire round-trip, and ANY post-signing
/// mutation of a scheme — even just requiring PKCE — breaks the signature.
#[test]
fn security_schemes_are_signature_covered() {
    let (der, jwk) = p256_keypair();
    let mut card = spec_example_card()
        .with_nucleus_claims(&fixed_claims())
        .unwrap();
    card.security_schemes = populated_security_schemes();
    let signed = sign_card(card, &der, "key-1").unwrap();

    let wire = serde_json::to_string(&signed).unwrap();
    let reconstructed: AgentCard = serde_json::from_str(&wire).unwrap();
    verify_card(&reconstructed, &jwk).expect("populated card verifies after round-trip");

    let mut tampered = reconstructed;
    let Some(SecurityScheme::OAuth2(scheme)) = tampered.security_schemes.get_mut("oauth-ac") else {
        panic!("oauth-ac entry present");
    };
    let OAuthFlows::AuthorizationCode(flow) = &mut scheme.flows else {
        panic!("authorization-code flow present");
    };
    flow.pkce_required = false;
    assert!(verify_card(&tampered, &jwk).is_err());
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
    // verify_card checks EVERY signature against the caller's key (§8.4.3
    // allows multiple for rotation) — key-1's, at index 0, still verifies.
    verify_card(&signed_twice, &jwk1).expect("first signature survives co-signing");
}

/// §8.4.3 "Multiple signatures MAY be present to support key rotation":
/// a card co-signed old-key-then-new-key must verify for a holder of
/// EITHER key. The new-key holder's valid signature sits at index 1 — a
/// verifier that only ever checked `signatures[0]` would wrongly reject it.
#[test]
fn rotation_co_signed_card_verifies_under_either_key() {
    let (der_old, jwk_old) = p256_keypair();
    let (der_new, jwk_new) = p256_keypair();
    let card = spec_example_card()
        .with_nucleus_claims(&fixed_claims())
        .unwrap();
    let co_signed = sign_card(
        sign_card(card, &der_old, "key-old").unwrap(),
        &der_new,
        "key-new",
    )
    .unwrap();
    assert_eq!(co_signed.signatures.len(), 2);
    verify_card(&co_signed, &jwk_old).expect("old-key holder verifies (signature at index 0)");
    verify_card(&co_signed, &jwk_new).expect("new-key holder verifies (signature at index 1)");
}

/// A failing entry at index 0 must not mask a valid signature at index 1 —
/// and when NO entry verifies, the card is still rejected. Iteration is
/// bounded by the array and the key is always the caller's resolved one
/// (no card-controlled key selection).
#[test]
fn valid_signature_at_index_1_verifies() {
    let (der, jwk) = p256_keypair();
    let signed = sign_card(
        spec_example_card()
            .with_nucleus_claims(&fixed_claims())
            .unwrap(),
        &der,
        "key-1",
    )
    .unwrap();

    // Prepend a structurally-plausible but cryptographically-garbage entry.
    let mut shuffled = signed.clone();
    shuffled.signatures.insert(
        0,
        AgentCardSignature {
            protected: signed.signatures[0].protected.clone(),
            signature: "bm90LWEtcmVhbC1zaWc".to_string(),
            header: None,
        },
    );
    verify_card(&shuffled, &jwk).expect("the valid entry at index 1 must be found");

    // Under an unrelated key, neither entry verifies — still rejected.
    let (_other_der, other_jwk) = p256_keypair();
    assert!(verify_card(&shuffled, &other_jwk).is_err());
}

/// §8.4.3 steps 3–6 operate on "the received Agent Card": a signed card
/// whose received document carries an attacker-INJECTED unknown member
/// must NOT verify through the received-document path — the signature
/// does not cover what was received.
#[test]
fn injected_unknown_member_is_rejected_on_the_received_document() {
    let (der, jwk) = p256_keypair();
    let signed = sign_card(
        spec_example_card()
            .with_nucleus_claims(&fixed_claims())
            .unwrap(),
        &der,
        "key-1",
    )
    .unwrap();

    // Baseline: the untampered received document verifies.
    let genuine = serde_json::to_string(&signed).unwrap();
    verify_card_json(&genuine, &jwk).expect("untampered received document verifies");

    // Inject a member the signature never covered.
    let mut doc = serde_json::to_value(&signed).unwrap();
    doc.as_object_mut().unwrap().insert(
        "injectedByAttacker".to_string(),
        serde_json::json!("not covered by the signature"),
    );
    let tampered = serde_json::to_string(&doc).unwrap();
    let err = verify_card_json(&tampered, &jwk).unwrap_err();
    assert!(matches!(err, crate::Error::Verify(_)), "got {err:?}");

    // Contrast (and the reason the JSON path exists): re-typing the
    // tampered document DROPS the unknown member, so the struct path can
    // only attest to the fields it models and would accept it. A caller
    // holding the raw received document must therefore verify through
    // verify_card_json, never through parse-then-verify_card.
    let retyped: AgentCard = serde_json::from_str(&tampered).unwrap();
    verify_card(&retyped, &jwk)
        .expect("the struct path attests the modeled fields only — by construction");
}

/// Forward-compat per the crate's own documentation: a card legitimately
/// signed by a NEWER implementation over a member this version does not
/// model must still verify through the received-document path (the §8.4.1
/// canonical payload includes every received member; an older verifier
/// re-serializing its typed struct would wrongly drop it and fail).
#[test]
fn unmodeled_member_signed_by_a_newer_producer_verifies_via_the_json_path() {
    let (der, jwk) = p256_keypair();

    // The "newer producer": this version's card plus an unmodeled member,
    // assembled as a raw document.
    let card = spec_example_card()
        .with_nucleus_claims(&fixed_claims())
        .unwrap();
    let mut doc = serde_json::to_value(&card).unwrap();
    doc.as_object_mut().unwrap().insert(
        "futureField".to_string(),
        serde_json::json!({"introducedIn": "a later A2A revision"}),
    );

    // Sign the received-document canonical bytes with the SAME JWS
    // primitive sign_card uses (detached ES256 over §8.4.1 JCS).
    let canonical = canonicalize_received(&doc).unwrap();
    let compact = nucleus_identity::did_crypto::jws_sign_es256_with_protected_header(
        r#"{"alg":"ES256","typ":"JOSE","kid":"future-key-1"}"#,
        &canonical,
        &der,
    )
    .unwrap();
    let parts: Vec<&str> = compact.splitn(3, '.').collect();
    doc.as_object_mut().unwrap().insert(
        "signatures".to_string(),
        serde_json::json!([{"protected": parts[0], "signature": parts[2]}]),
    );

    let raw = serde_json::to_string(&doc).unwrap();
    let verified =
        verify_card_json(&raw, &jwk).expect("unmodeled member must not break verification");
    assert_eq!(
        verified.claims.did,
        "did:web:golden.conformance.example.com"
    );

    // The typed struct path can never verify this card: re-serialization
    // drops `futureField`, so the reconstructed payload differs from the
    // one signed — the exact fail-closed defect the JSON path fixes.
    let retyped: AgentCard = serde_json::from_str(&raw).unwrap();
    assert!(verify_card(&retyped, &jwk).is_err());
}

/// The §8.4.3 signature layer and the nucleus claims policy are separate:
/// a validly signed PLAIN A2A card (no nucleus extension, as any
/// non-nucleus implementation would publish) passes pure signature
/// verification, and is then rejected by `verify_card` with an error that
/// names the policy — never a signature failure.
#[test]
fn plain_a2a_card_passes_signature_verification_and_fails_only_policy() {
    let (der, jwk) = p256_keypair();
    let plain = sign_card(spec_example_card(), &der, "key-1").unwrap();

    // Layer 1 (§8.4.3) accepts it — struct and received-document paths.
    verify_card_signature(&plain, &jwk).expect("\u{a7}8.4.3 accepts a signed plain card");
    crate::verify::verify_card_signature_json(&serde_json::to_value(&plain).unwrap(), &jwk)
        .expect("received-document path agrees");

    // Layer 2 (nucleus policy) rejects it, saying it is policy.
    let err = verify_card(&plain, &jwk).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("nucleus claims policy"), "{msg}");
    assert!(msg.contains("not a signature failure"), "{msg}");
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
