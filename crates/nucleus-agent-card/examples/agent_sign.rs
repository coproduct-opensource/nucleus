//! `agent-sign` — sign an A2A v1.0 Agent Card whose nucleus extension
//! declares an IFC runtime-guarantee profile, then verify it (incl.
//! tamper-detection of the profile).
//!
//! Run with:
//!
//! ```bash
//! just agent-sign
//! # or: cargo run -p nucleus-agent-card --example agent_sign --features sign
//! ```
//!
//! This uses an **ephemeral** P-256 key for self-containment. In production the
//! key is obtained keyless via OIDC→SPIFFE (`nucleus-github-oidc` /
//! `nucleus-fly-oidc`); the signing + verification are identical. The profile is
//! ATTESTATION, not enforcement — see `RuntimeGuaranteeProfile`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

use nucleus_agent_card::{
    sign_card, verify_card, AgentCapabilities, AgentCard, AgentInterface, EnforcementRule,
    JsonWebKey, NucleusClaims, RuntimeGuaranteeProfile, A2A_PROTOCOL_VERSION,
    NUCLEUS_EXTENSION_URI,
};
use nucleus_lineage::{Jwks, LocalIssuer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Ephemeral P-256 signer (production: OIDC-keyless → SPIFFE).
    let rng = SystemRandom::new();
    let pkcs8 =
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).expect("keygen");
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
        .expect("load key");
    let pk = kp.public_key().as_ref();
    let resolved_key = JsonWebKey::ec_p256(
        URL_SAFE_NO_PAD.encode(&pk[1..33]),
        URL_SAFE_NO_PAD.encode(&pk[33..65]),
    );

    // The agent's A2A v1.0 card. Nucleus claims (identity, trust JWKS, and
    // the IFC guarantee the agent declares it enforces at runtime) travel
    // in the registered extension NUCLEUS_EXTENSION_URI.
    let trust_jwks: Jwks = serde_json::from_value(LocalIssuer::random()?.publish_jwks())?;
    let base_card = AgentCard {
        name: "Summarizer Agent".to_string(),
        description: "Summarizes documents and emits provenance receipts.".to_string(),
        supported_interfaces: vec![AgentInterface {
            url: "https://summarizer.prod.example.com/a2a/v1".to_string(),
            protocol_binding: "JSONRPC".to_string(),
            tenant: None,
            protocol_version: A2A_PROTOCOL_VERSION.to_string(),
        }],
        provider: None,
        version: "1.0.0".to_string(),
        documentation_url: None,
        capabilities: AgentCapabilities::default(),
        security_schemes: serde_json::Map::new(),
        security_requirements: vec![],
        default_input_modes: vec!["application/json".to_string()],
        default_output_modes: vec!["application/json".to_string()],
        skills: vec![],
        signatures: vec![],
        icon_url: None,
    };
    let card = base_card.with_nucleus_claims(&NucleusClaims {
        spiffe_id: "spiffe://prod.example.com/ns/agents/sa/summarizer".to_string(),
        did: "did:web:summarizer.prod.example.com".to_string(),
        supported_envelope_schema_versions: vec!["1".to_string()],
        jwks_uri: None,
        trust_jwks,
        runtime_guarantees: Some(RuntimeGuaranteeProfile {
            profile_version: "1.0".to_string(),
            tracked_sources: vec![
                "user_prompt".to_string(),
                "web_content".to_string(),
                "secret".to_string(),
            ],
            enforcement_rules: vec![
                EnforcementRule {
                    name: "no_adversarial_to_outbound".to_string(),
                    description: "deny outbound actions whose ancestry includes \
                                  adversarial-integrity content (web/tool)"
                        .to_string(),
                },
                EnforcementRule {
                    name: "no_secret_to_public_sink".to_string(),
                    description: "deny secret-confidentiality data flowing to a public sink"
                        .to_string(),
                },
            ],
            // Advisory: point at an external policy (e.g. an MS ACS policy id).
            attestation_reference: None,
        }),
    })?;

    // Sign → verify. The §8.4.2 protected header carries alg/typ/kid.
    let signed = sign_card(card, pkcs8.as_ref(), "card-key-1")?;
    println!(
        "signed agent card:\n{}",
        serde_json::to_string_pretty(&signed)?
    );

    let verified = verify_card(&signed, &resolved_key)?;
    let profile = verified
        .claims
        .runtime_guarantees
        .as_ref()
        .expect("the verified card carries its IFC profile");
    println!("\nverified ✓  — IFC profile is authentic + untampered:");
    println!("  spiffe_id        = {}", verified.claims.spiffe_id);
    println!("  tracked_sources  = {:?}", profile.tracked_sources);
    for rule in &profile.enforcement_rules {
        println!("  rule             = {} — {}", rule.name, rule.description);
    }

    // Tamper-detection: flip a declared rule (inside the signed extension
    // params) after signing → verify must fail.
    let mut tampered = signed;
    let ext = tampered
        .capabilities
        .extensions
        .iter_mut()
        .find(|e| e.uri == NUCLEUS_EXTENSION_URI)
        .expect("nucleus extension present");
    ext.params.as_mut().unwrap()["runtimeGuarantees"]["enforcementRules"][0]["name"] =
        serde_json::json!("allow_everything");
    match verify_card(&tampered, &resolved_key) {
        Err(_) => println!("\ntamper check ✓  — flipping a declared rule breaks the signature"),
        Ok(_) => panic!("BUG: a tampered profile must not verify"),
    }

    println!(
        "\nNote: a verified profile is ATTESTATION, not enforcement — the client \
         verifies the declaration + receipts; the host enforces (coverage-limited)."
    );
    Ok(())
}
