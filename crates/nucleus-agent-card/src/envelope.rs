//! Lift a [`VerifiedCard`]'s claims into `nucleus-receipt`'s signed colimit
//! envelope (feature `envelope`, off by default).
//!
//! An agent's card is its *discovery-time* capability claim: who it is
//! (`spiffe_id`, `did`), what it speaks
//! (`supported_envelope_schema_versions`), which keys it claims sign its
//! provenance (`trust_jwks` kids), and — the load-bearing part — its declared
//! [`RuntimeGuaranteeProfile`](crate::RuntimeGuaranteeProfile). On the A2A
//! v1.0 card those claims travel as the
//! [`NucleusClaims`](crate::NucleusClaims) extension; here the verified
//! subset is lifted into the receipt envelope. Putting those
//! claims into [`Projection::Capability`] means the guarantees a counterparty
//! checked at discovery time ride along, signed, inside every
//! [`Receipt`](nucleus_receipt::Receipt) the agent later emits — the receipt's
//! Ed25519/BLAKE3 envelope makes the carried claims tamper-evident end to end.
//!
//! ## Verify before you project (type-enforced)
//!
//! [`to_capability_projection`] takes a [`VerifiedCard`] — the output of
//! [`verify_card`](crate::verify_card) — and deliberately NOT a raw signed
//! [`AgentCard`](crate::AgentCard). A raw signed card is an
//! unverified blob: lifting it would let an agent embed claims nobody ever
//! checked against an out-of-band key. Requiring the `VerifiedCard` witness
//! makes "this card verified" a precondition the type system discharges —
//! you cannot project a card you did not verify.
//!
//! ## The asymmetry is the point
//!
//! Narrowing goes to [`CardClaims`], a plain data struct — NOT back to a
//! [`VerifiedCard`]. Reconstructing a `VerifiedCard` from a projection body
//! would forge the verification witness: the projection carries what a
//! verified card *claimed*, not the proof that anyone verified it. The
//! enclosing [`Receipt`](nucleus_receipt::Receipt) signature proves the
//! *issuer* vouched for these claims at signing time; a consumer who needs
//! the card-level guarantee re-verifies the card itself.
//!
//! ## Wire shape (stable)
//!
//! The `Projection::Capability` body produced by [`to_capability_projection`]
//! is:
//!
//! ```json
//! { "kind": "agent-card", "card": { "spiffe_id": "...", ... } }
//! ```
//!
//! - outer `"kind"` is always [`CAPABILITY_AGENT_CARD_KIND`] (`"agent-card"`)
//!   — the discriminant *within* the capability projection, so other
//!   capability bodies (e.g. Portcullis lattice points) can coexist under the
//!   same projection kind;
//! - `"card"` is the [`CardClaims`] JSON — the lifted subset of the verified
//!   card's fields.

use serde::{Deserialize, Serialize};

use crate::card::RuntimeGuaranteeProfile;
use crate::verify::VerifiedCard;

pub use nucleus_receipt::Projection;

/// The `"kind"` discriminant inside a `Projection::Capability` body that
/// marks it as carrying agent-card claims. Stable wire constant.
pub const CAPABILITY_AGENT_CARD_KIND: &str = "agent-card";

/// The claims lifted out of a [`VerifiedCard`] — what travels inside the
/// signed receipt.
///
/// This is deliberately a plain deserializable struct, not a
/// [`VerifiedCard`]: deserializing claims off the wire must never mint a
/// verification witness (see the module docs on the asymmetry).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CardClaims {
    /// SPIFFE identity the verified card declared.
    pub spiffe_id: String,

    /// Decentralized identifier the verified card declared.
    pub did: String,

    /// Envelope/bundle schema versions the agent declared it speaks.
    pub supported_envelope_schema_versions: Vec<String>,

    /// The declared runtime IFC guarantee profile, if any — the discovery-time
    /// guarantee that now rides along with every receipt. Attestation, not
    /// enforcement (see [`RuntimeGuaranteeProfile`]). Serializes in the
    /// profile's A2A camelCase wire form (`profileVersion`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_guarantees: Option<RuntimeGuaranteeProfile>,

    /// `kid`s of the JWKS the card advertised as authoritative for its
    /// provenance bundles. Kids only — the keys themselves stay out-of-band,
    /// so a projection consumer can correlate but never treat the projection
    /// as key material.
    pub advertised_jwks_kids: Vec<String>,
}

impl From<&VerifiedCard> for CardClaims {
    fn from(verified: &VerifiedCard) -> Self {
        CardClaims {
            spiffe_id: verified.claims.spiffe_id.clone(),
            did: verified.claims.did.clone(),
            supported_envelope_schema_versions: verified
                .claims
                .supported_envelope_schema_versions
                .clone(),
            runtime_guarantees: verified.claims.runtime_guarantees.clone(),
            advertised_jwks_kids: verified
                .advertised_jwks()
                .keys
                .iter()
                .map(|k| k.kid.clone())
                .collect(),
        }
    }
}

/// Why a [`Projection`] could not be narrowed to [`CardClaims`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum NarrowError {
    /// The projection is not `Projection::Capability` at all.
    #[error("projection kind is `{found}`, expected `capability`")]
    NotCapability {
        /// The wire discriminant of the projection that was supplied.
        found: &'static str,
    },
    /// The capability body's `kind` is not `"agent-card"` (or is missing) —
    /// some other capability record travels under this projection.
    #[error("capability body kind is `{found}`, expected `agent-card`")]
    NotAgentCard {
        /// The inner `kind` found, or `<missing>`.
        found: String,
    },
    /// The body claimed to be an agent card but its `card` field is absent
    /// or does not deserialize as [`CardClaims`].
    #[error("agent-card capability body is malformed: {0}")]
    MalformedBody(String),
}

/// Lift a [`VerifiedCard`]'s claims into the [`Projection::Capability`] body
/// they travel as inside a signed [`Receipt`](nucleus_receipt::Receipt).
/// See the module docs for the stable inner shape.
///
/// Only a [`VerifiedCard`] can be lifted — verify-before-you-project is
/// enforced by the type system, not by convention (see the module docs).
pub fn to_capability_projection(verified: &VerifiedCard) -> Projection {
    Projection::Capability(serde_json::json!({
        "kind": CAPABILITY_AGENT_CARD_KIND,
        "card": CardClaims::from(verified),
    }))
}

/// Narrow a [`Projection`] back to the typed [`CardClaims`].
///
/// Rejects, with distinct errors: non-`Capability` projections
/// ([`NarrowError::NotCapability`]), capability bodies that are not agent
/// cards ([`NarrowError::NotAgentCard`]), and agent-card bodies whose `card`
/// is missing or malformed ([`NarrowError::MalformedBody`]).
///
/// Narrowing does NOT verify anything — and it cannot return a
/// [`VerifiedCard`], because that would forge the verification witness. Call
/// [`Receipt::verify`](nucleus_receipt::Receipt::verify) on the envelope
/// *before* narrowing to establish the issuer vouched for these claims; if
/// you need the card-level guarantee itself, re-verify the card with
/// [`verify_card`](crate::verify_card) against an out-of-band key.
pub fn card_claims_from_projection(projection: &Projection) -> Result<CardClaims, NarrowError> {
    let Projection::Capability(body) = projection else {
        return Err(NarrowError::NotCapability {
            found: projection.kind(),
        });
    };
    match body.get("kind").and_then(serde_json::Value::as_str) {
        Some(CAPABILITY_AGENT_CARD_KIND) => {}
        Some(other) => {
            return Err(NarrowError::NotAgentCard {
                found: other.to_string(),
            })
        }
        None => {
            return Err(NarrowError::NotAgentCard {
                found: "<missing>".to_string(),
            })
        }
    }
    let card = body
        .get("card")
        .ok_or_else(|| NarrowError::MalformedBody("missing `card` field".to_string()))?;
    serde_json::from_value(card.clone()).map_err(|e| NarrowError::MalformedBody(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::{
        AgentCapabilities, AgentCard, AgentInterface, EnforcementRule, NucleusClaims,
        A2A_PROTOCOL_VERSION,
    };

    fn sample_profile() -> RuntimeGuaranteeProfile {
        RuntimeGuaranteeProfile {
            profile_version: "1.0".to_string(),
            tracked_sources: vec!["web_content".to_string(), "secret".to_string()],
            enforcement_rules: vec![EnforcementRule {
                name: "no_adversarial_to_outbound".to_string(),
                description:
                    "deny outbound actions whose ancestry includes adversarial-integrity content"
                        .to_string(),
            }],
            attestation_reference: None,
        }
    }

    fn sample_claims() -> NucleusClaims {
        NucleusClaims {
            spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
            did: "did:web:coder.prod.example.com".to_string(),
            supported_envelope_schema_versions: vec!["1".to_string(), "2".to_string()],
            jwks_uri: None,
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
            runtime_guarantees: Some(sample_profile()),
        }
    }

    fn sample_card() -> AgentCard {
        AgentCard {
            name: "Coder Agent".to_string(),
            description: "lift/narrow tests".to_string(),
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
            security_schemes: serde_json::Map::new(),
            security_requirements: vec![],
            default_input_modes: vec!["application/json".to_string()],
            default_output_modes: vec!["application/json".to_string()],
            skills: vec![],
            signatures: vec![],
            icon_url: None,
        }
        .with_nucleus_claims(&sample_claims())
        .unwrap()
    }

    /// In-crate test shortcut: `VerifiedCard`'s fields are public within
    /// the crate's API, but the END-TO-END test (sign_verify path, feature
    /// `sign`) is the one that goes through `verify_card` for real.
    fn verified() -> VerifiedCard {
        VerifiedCard {
            card: sample_card(),
            claims: sample_claims(),
        }
    }

    /// The round-trip law: narrow ∘ lift = id on the lifted claims.
    #[test]
    fn lift_then_narrow_is_identity_on_claims() {
        let v = verified();
        let expected = CardClaims::from(&v);
        let p = to_capability_projection(&v);
        assert_eq!(p.kind(), "capability");
        let back = card_claims_from_projection(&p).expect("lifted projection narrows back");
        assert_eq!(back, expected);
        // Spot-check the load-bearing fields explicitly.
        assert_eq!(
            back.spiffe_id,
            "spiffe://prod.example.com/ns/agents/sa/coder"
        );
        assert_eq!(back.advertised_jwks_kids, vec!["k1".to_string()]);
        assert_eq!(
            back.runtime_guarantees.unwrap().enforcement_rules[0].name,
            "no_adversarial_to_outbound"
        );
    }

    #[test]
    fn capability_body_shape_is_stable() {
        // Wire pin: {"kind": "agent-card", "card": {...}} — downstream
        // consumers dispatch on the inner kind, so drift fails here.
        let Projection::Capability(body) = to_capability_projection(&verified()) else {
            panic!("lift must produce a capability projection");
        };
        assert_eq!(body["kind"], CAPABILITY_AGENT_CARD_KIND);
        assert_eq!(body["card"]["did"], "did:web:coder.prod.example.com");
        assert_eq!(body["card"]["advertised_jwks_kids"][0], "k1");
    }

    #[test]
    fn absent_profile_is_omitted_from_the_wire() {
        let mut v = verified();
        v.claims.runtime_guarantees = None;
        let Projection::Capability(body) = to_capability_projection(&v) else {
            panic!("lift must produce a capability projection");
        };
        assert!(
            body["card"].get("runtime_guarantees").is_none(),
            "a None profile must be omitted from the claims JSON"
        );
        let back = card_claims_from_projection(&to_capability_projection(&v)).unwrap();
        assert!(back.runtime_guarantees.is_none());
    }

    #[test]
    fn narrowing_rejects_non_capability_projection() {
        let p = Projection::Identity(serde_json::json!({"sub": "spiffe://test/agent"}));
        assert_eq!(
            card_claims_from_projection(&p),
            Err(NarrowError::NotCapability { found: "identity" })
        );
    }

    #[test]
    fn narrowing_rejects_other_capability_bodies() {
        // A different capability record under the same projection kind.
        let p = Projection::Capability(serde_json::json!({
            "kind": "portcullis-lattice-point",
            "card": {"anything": true},
        }));
        assert_eq!(
            card_claims_from_projection(&p),
            Err(NarrowError::NotAgentCard {
                found: "portcullis-lattice-point".into()
            })
        );
        // Missing inner kind entirely.
        let p = Projection::Capability(serde_json::json!({"card": {}}));
        assert_eq!(
            card_claims_from_projection(&p),
            Err(NarrowError::NotAgentCard {
                found: "<missing>".into()
            })
        );
    }

    #[test]
    fn narrowing_rejects_malformed_agent_card_bodies() {
        // `card` field absent.
        let p = Projection::Capability(serde_json::json!({"kind": "agent-card"}));
        assert!(matches!(
            card_claims_from_projection(&p),
            Err(NarrowError::MalformedBody(_))
        ));
        // `card` present but not CardClaims.
        let p = Projection::Capability(serde_json::json!({
            "kind": "agent-card",
            "card": {"spiffe_id": 42},
        }));
        assert!(matches!(
            card_claims_from_projection(&p),
            Err(NarrowError::MalformedBody(_))
        ));
    }
}
