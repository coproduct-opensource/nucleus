//! `agent-sign` — sign an Agent Card that declares an IFC runtime-guarantee
//! profile, then verify it (incl. tamper-detection of the profile).
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
    sign_card, verify_card, AgentCard, EnforcementRule, RuntimeGuaranteeProfile,
};
use nucleus_identity::JsonWebKey;
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

    // The agent's card, declaring the IFC guarantee it enforces at runtime.
    let trust_jwks: Jwks = serde_json::from_value(LocalIssuer::random()?.publish_jwks())?;
    let card = AgentCard {
        spiffe_id: "spiffe://prod.example.com/ns/agents/sa/summarizer".to_string(),
        did: "did:web:summarizer.prod.example.com".to_string(),
        security_schemes: serde_json::json!({}),
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
    };

    // Sign → verify.
    let signed = sign_card(card, pkcs8.as_ref())?;
    println!(
        "signed agent card:\n{}",
        serde_json::to_string_pretty(&signed)?
    );

    let verified = verify_card(&signed, &resolved_key)?;
    let profile = verified
        .card
        .runtime_guarantees
        .as_ref()
        .expect("the verified card carries its IFC profile");
    println!("\nverified ✓  — IFC profile is authentic + untampered:");
    println!("  spiffe_id        = {}", verified.card.spiffe_id);
    println!("  tracked_sources  = {:?}", profile.tracked_sources);
    for rule in &profile.enforcement_rules {
        println!("  rule             = {} — {}", rule.name, rule.description);
    }

    // Tamper-detection: flip a declared rule after signing → verify must fail.
    let mut tampered = signed;
    tampered
        .card
        .runtime_guarantees
        .as_mut()
        .unwrap()
        .enforcement_rules[0]
        .name = "allow_everything".to_string();
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
