//! Agent Card types — an A2A-style identity document plus its detached
//! RFC 7515 JWS-JSON signatures.
//!
//! These are pure data; signing lives in [`crate::sign`] (feature-gated)
//! and verification in [`crate::verify`] (always available).
//!
//! # Forward-compat
//!
//! None of these structs use `deny_unknown_fields`. A newer producer may
//! add fields this verifier doesn't know about; unknown fields are
//! ignored on parse so an older verifier still works against a newer
//! card. The canonicalization in [`crate::jcs`] covers exactly the
//! fields defined here — what we sign is what we know.

use serde::{Deserialize, Serialize};

/// The self-describing identity document an agent publishes (typically at
/// `/.well-known/agent-card.json`).
///
/// The card advertises WHO the agent is (`spiffe_id`, `did`), how to talk
/// to it (`security_schemes`, `supported_envelope_schema_versions`), and —
/// critically for the verify-before-you-act flow — the JWKS the agent
/// claims its provenance bundles are signed under (`trust_jwks`).
///
/// **The advertised `trust_jwks` is a CLAIM, not an anchor.** It only
/// becomes load-bearing once the card itself has been verified against an
/// out-of-band-resolved key (see [`crate::verify::verify_card`]) AND the
/// recipient refuses to act on any bundle that doesn't verify against it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// SPIFFE identity of the agent (e.g. `spiffe://prod.example.com/ns/agents/sa/coder`).
    pub spiffe_id: String,

    /// Decentralized identifier for the agent (e.g. `did:web:coder.prod.example.com`).
    pub did: String,

    /// A2A-style security schemes describing how callers authenticate to
    /// the agent. Opaque JSON — this crate does not interpret it.
    pub security_schemes: serde_json::Value,

    /// Envelope/bundle schema versions this agent can produce or consume.
    pub supported_envelope_schema_versions: Vec<String>,

    /// Optional URI where the agent's JWKS is published out-of-band. A
    /// recipient MAY resolve this to obtain the verification key for the
    /// card; it is NOT trusted material on its own.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,

    /// The JWKS the agent advertises as authoritative for its provenance
    /// bundles. Becomes a [`nucleus_envelope::TrustAnchor`] only after the
    /// card is verified.
    pub trust_jwks: nucleus_lineage::Jwks,

    /// Optional declared runtime information-flow-control guarantee profile.
    /// Covered by the card's JCS signature, so a verifier knows the declaration
    /// is authentic and untampered. **Attestation, not enforcement** — see
    /// [`RuntimeGuaranteeProfile`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_guarantees: Option<RuntimeGuaranteeProfile>,
}

/// A declared runtime information-flow-control (IFC) guarantee profile, carried
/// inside a signed [`AgentCard`].
///
/// # What a verified profile proves — and does not
///
/// Because the profile is part of the card's JCS-canonical bytes, the card
/// signature makes it **authentic and tamper-evident**: a counterparty can
/// confirm *the agent issued this exact declaration*. It does **NOT** prove the
/// declared rules are enforced, sound, or sufficient — attestation is not
/// enforcement. The agent's `nucleus-envelope` receipts are the behavioural
/// evidence that the declared rules were actually evaluated at runtime; a
/// verifier checks them post-hoc, client-side. Enforcement remains host-side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeGuaranteeProfile {
    /// Profile schema version (e.g. `"1.0"`), versioned independently of the card.
    pub profile_version: String,

    /// Data-flow source kinds the agent declares it labels/tracks — the
    /// lethal-trifecta surface (e.g. `"web_content"`, `"secret"`, `"file_read"`).
    /// Tokens match `nucleus-verify-commerce`'s `DeclaredInput` serde names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tracked_sources: Vec<String>,

    /// Named IFC enforcement rules the agent declares it applies at runtime.
    pub enforcement_rules: Vec<EnforcementRule>,

    /// Advisory pointer to external policy evidence (e.g. a Microsoft Agent
    /// Control Specification policy id, or a Sigstore bundle URL). Advisory
    /// only — a verifier with no out-of-band knowledge cannot confirm it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_reference: Option<String>,
}

/// One named IFC enforcement rule a [`RuntimeGuaranteeProfile`] declares.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnforcementRule {
    /// Stable rule identifier (e.g. `"no_adversarial_to_outbound"`).
    pub name: String,
    /// Human-readable description of what the rule denies.
    pub description: String,
}

/// One detached RFC 7515 JWS-JSON signature over the JCS-canonicalized
/// [`AgentCard`].
///
/// "Detached" means the JWS payload segment is dropped on the wire: the
/// recipient reconstructs it by canonicalizing the `card` itself. This is
/// what binds the signature to the exact card content without duplicating
/// the bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentCardSignature {
    /// Base64url-encoded protected JWS header (e.g. `{"alg":"ES256"}`).
    pub protected: String,

    /// Base64url-encoded signature over `protected || "." || base64url(JCS(card))`.
    pub signature: String,

    /// Optional unprotected JWS header (RFC 7515 §7.2.1). Not covered by
    /// the signature; carry hints like `kid` here at the producer's risk.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
}

/// An [`AgentCard`] plus one or more detached signatures.
///
/// The verifier uses the FIRST signature (see [`crate::verify::verify_card`]).
/// Multiple signatures are permitted for key-rotation / co-signing but the
/// trust decision is made against the caller's out-of-band-resolved key,
/// not against any `kid` the card or signature claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAgentCard {
    /// The identity document.
    pub card: AgentCard,

    /// Detached JWS-JSON signatures over the JCS of `card`.
    pub signatures: Vec<AgentCardSignature>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_card() -> AgentCard {
        AgentCard {
            spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
            did: "did:web:coder.prod.example.com".to_string(),
            security_schemes: serde_json::json!({
                "bearer": {"type": "http", "scheme": "bearer"}
            }),
            supported_envelope_schema_versions: vec!["1".to_string(), "2".to_string()],
            jwks_uri: Some("https://coder.prod.example.com/.well-known/jwks.json".to_string()),
            trust_jwks: nucleus_lineage::Jwks {
                keys: vec![nucleus_lineage::Jwk {
                    kty: "OKP".to_string(),
                    crv: Some("Ed25519".to_string()),
                    kid: "k1".to_string(),
                    x: Some("AAAA_AAAAAA-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
                    alg: Some("EdDSA".to_string()),
                    use_: Some("sig".to_string()),
                    not_before: None,
                    not_after: None,
                }],
            },
            runtime_guarantees: None,
        }
    }

    #[test]
    fn agent_card_serde_round_trip() {
        let card = sample_card();
        let json = serde_json::to_string(&card).unwrap();
        let back: AgentCard = serde_json::from_str(&json).unwrap();
        // Jwks has no PartialEq, so compare via canonical JSON value.
        assert_eq!(
            serde_json::to_value(&card).unwrap(),
            serde_json::to_value(&back).unwrap()
        );
    }

    #[test]
    fn signed_agent_card_serde_round_trip() {
        let signed = SignedAgentCard {
            card: sample_card(),
            signatures: vec![AgentCardSignature {
                protected: "eyJhbGciOiJFUzI1NiJ9".to_string(),
                signature: "c2lnbmF0dXJl".to_string(),
                header: Some(serde_json::json!({"kid": "k1"})),
            }],
        };
        let json = serde_json::to_string(&signed).unwrap();
        let back: SignedAgentCard = serde_json::from_str(&json).unwrap();
        assert_eq!(
            serde_json::to_value(&signed).unwrap(),
            serde_json::to_value(&back).unwrap()
        );
    }

    #[test]
    fn unknown_fields_are_ignored_forward_compat() {
        // A newer producer adds a field this verifier doesn't model.
        let json = serde_json::json!({
            "spiffe_id": "spiffe://prod.example.com/ns/agents/sa/coder",
            "did": "did:web:coder.prod.example.com",
            "security_schemes": {},
            "supported_envelope_schema_versions": ["1"],
            "trust_jwks": {"keys": []},
            "future_field_we_dont_know": {"nested": true}
        });
        let card: AgentCard = serde_json::from_value(json).unwrap();
        assert_eq!(card.did, "did:web:coder.prod.example.com");
    }
}
