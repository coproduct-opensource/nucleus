//! [`AgentCardVerifier`] — verify a signed A2A v1.0 Agent Card.

use async_trait::async_trait;
use nucleus_agent_card::{verify_card, AgentCard, JsonWebKey};

use crate::{CallerClaims, CallerVerifier, CommerceError, VerifiedCaller};

/// A [`CallerVerifier`] that treats the caller's credential as a JSON
/// signed [`AgentCard`] (A2A v1.0: the JWS signatures ride in the card's
/// own `signatures` field) and verifies it against an
/// **out-of-band-resolved** key.
///
/// The one rule that makes this safe (inherited from
/// [`nucleus_agent_card::verify_card`]): the verification key comes ONLY from
/// `resolved_key`, configured here by the seller out-of-band (DID resolution, a
/// pinned JWKS, an operator file). It is never read from the card. A card
/// verified against an attacker-supplied key is "verified garbage".
///
/// On success the verified caller's identity is the `spiffe_id` from the
/// card's nucleus extension claims — the verified truth, not the
/// caller-asserted [`CallerClaims::agent_id`].
pub struct AgentCardVerifier {
    resolved_key: JsonWebKey,
}

impl AgentCardVerifier {
    /// Construct with the out-of-band-resolved verification key.
    pub fn new(resolved_key: JsonWebKey) -> Self {
        Self { resolved_key }
    }
}

#[async_trait]
impl CallerVerifier for AgentCardVerifier {
    async fn verify(&self, claims: &CallerClaims) -> Result<VerifiedCaller, CommerceError> {
        let signed: AgentCard = serde_json::from_str(&claims.credential)
            .map_err(|e| CommerceError::Unverified(format!("malformed signed agent card: {e}")))?;

        let verified = verify_card(&signed, &self.resolved_key)
            .map_err(|e| CommerceError::Unverified(format!("agent card did not verify: {e}")))?;

        Ok(VerifiedCaller {
            spiffe_id: verified.claims.spiffe_id.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use nucleus_agent_card::{
        sign_card, AgentCapabilities, AgentInterface, NucleusClaims, A2A_PROTOCOL_VERSION,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    /// Fresh P-256 keypair: (PKCS#8 DER, matching public JWK).
    fn p256_keypair() -> (Vec<u8>, JsonWebKey) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let der = pkcs8.as_ref().to_vec();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng).unwrap();
        let pk = kp.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&pk[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pk[33..65]);
        (der, JsonWebKey::ec_p256(x, y))
    }

    fn sample_card() -> AgentCard {
        let jwks: nucleus_lineage::Jwks = serde_json::from_value(
            nucleus_lineage::LocalIssuer::random()
                .unwrap()
                .publish_jwks(),
        )
        .unwrap();
        AgentCard {
            name: "Buyer Agent".to_string(),
            description: "card-verifier tests".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: "https://buyer.prod.example.com/a2a/v1".to_string(),
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
        .with_nucleus_claims(&NucleusClaims {
            spiffe_id: "spiffe://prod.example.com/ns/agents/sa/buyer".to_string(),
            did: "did:web:buyer.prod.example.com".to_string(),
            supported_envelope_schema_versions: vec!["1".to_string()],
            jwks_uri: None,
            trust_jwks: jwks,
            runtime_guarantees: None,
        })
        .unwrap()
    }

    fn claims_for(signed: &AgentCard) -> CallerClaims {
        CallerClaims {
            agent_id: signed.nucleus_claims().unwrap().unwrap().did,
            credential: serde_json::to_string(signed).unwrap(),
        }
    }

    #[tokio::test]
    async fn verifies_a_genuinely_signed_card_to_its_spiffe_id() {
        let (der, pub_jwk) = p256_keypair();
        let signed = sign_card(sample_card(), &der, "card-key-1").unwrap();
        let verifier = AgentCardVerifier::new(pub_jwk);

        let caller = verifier.verify(&claims_for(&signed)).await.unwrap();
        assert_eq!(
            caller.spiffe_id,
            "spiffe://prod.example.com/ns/agents/sa/buyer"
        );
    }

    #[tokio::test]
    async fn rejects_a_card_verified_against_the_wrong_key() {
        let (der, _pub_jwk) = p256_keypair();
        let (_other_der, attacker_view_key) = p256_keypair(); // unrelated key
        let signed = sign_card(sample_card(), &der, "card-key-1").unwrap();
        // Resolve to a key that did NOT sign the card → must reject.
        let verifier = AgentCardVerifier::new(attacker_view_key);

        let err = verifier.verify(&claims_for(&signed)).await.unwrap_err();
        assert!(matches!(err, CommerceError::Unverified(_)));
    }

    #[tokio::test]
    async fn rejects_malformed_credential() {
        let (_der, pub_jwk) = p256_keypair();
        let verifier = AgentCardVerifier::new(pub_jwk);
        let claims = CallerClaims {
            agent_id: "x".into(),
            credential: "not a signed card".into(),
        };
        assert!(matches!(
            verifier.verify(&claims).await.unwrap_err(),
            CommerceError::Unverified(_)
        ));
    }
}
