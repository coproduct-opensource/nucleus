//! [`IdentityFetcher`] — pluggable issuer for JWT-SVIDs scoped to a
//! [`CallSpiffeId`].
//!
//! Two impls are expected to coexist in the codebase:
//!
//! - [`LocalIssuer`] (this crate) — in-process Ed25519 signer for tests,
//!   demos, and CI. No network, no SPIRE Agent. Verifying keys are exposed
//!   so a relying party in the same process can validate SVIDs.
//!
//! - A `SpiffeWorkloadApi` impl in `nucleus-identity` — connects to a real
//!   SPIRE Agent socket and fetches the JWT-SVID for the requested audience.
//!
//! Both implementations satisfy the same contract: given a `CallSpiffeId`
//! and an audience, return a JWT whose `sub` claim is the SPIFFE ID and
//! whose `aud` is the requested audience. Lifetimes are issuer-controlled.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::id::CallSpiffeId;

/// Errors a JWT-SVID issuer may surface.
#[derive(Debug, Error)]
pub enum IssuerError {
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("system clock before unix epoch")]
    Clock,
    #[error("key encoding error: {0}")]
    Pkcs8(String),
}

/// Standard JWT-SVID claims, plus a short-form `nucleus_kind` for routing.
///
/// Wire-compatible with what a SPIRE-issued JWT-SVID would carry: the
/// non-standard claims live alongside the SPIFFE-required `sub`, `aud`,
/// `iss`, `iat`, `exp`, `jti`. Relying parties that only inspect standard
/// claims will round-trip unchanged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SvidClaims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    /// Optional: a kind hint set by the issuer (e.g. "tool_call", "llm_call").
    /// Useful for routing/audit but not part of the SPIFFE JWT-SVID spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nucleus_kind: Option<String>,
}

/// Pluggable JWT-SVID issuer.
///
/// Implementations must be safe to call concurrently (`&self`).
pub trait IdentityFetcher: Send + Sync {
    /// Mint a JWT-SVID with the given subject SPIFFE ID and audience. The
    /// returned string is a compact JWS (three base64url segments separated
    /// by `.`).
    fn fetch_jwt_svid(
        &self,
        subject: &CallSpiffeId,
        audience: &str,
    ) -> Result<String, IssuerError>;

    /// Optional kind hint; defaults to `None`. Issuers may attach this to
    /// the `nucleus_kind` claim.
    fn fetch_jwt_svid_with_kind(
        &self,
        subject: &CallSpiffeId,
        audience: &str,
        _kind: Option<&str>,
    ) -> Result<String, IssuerError> {
        self.fetch_jwt_svid(subject, audience)
    }
}

// ────────────────────────────────────────────────────────────────────────
// LocalIssuer

/// In-process JWT-SVID issuer for tests and demos.
///
/// Holds an Ed25519 keypair generated at construction. SVIDs are signed
/// EdDSA. The issuer URL string defaults to `nucleus-local://demo` and the
/// SVID lifetime defaults to 5 minutes (matching SPIRE Agent's default).
///
/// In a process that needs to verify the SVIDs (e.g., the demo's mock LLM
/// endpoint), call [`Self::decoding_key`] to get a [`DecodingKey`] and pass
/// it to `jsonwebtoken::decode`. [`Self::public_key_pem`] returns the
/// verifying key in PEM form for sharing across processes.
pub struct LocalIssuer {
    signing_key: SigningKey,
    encoding_key: EncodingKey,
    verifying_key: VerifyingKey,
    issuer: String,
    lifetime: Duration,
    key_id: String,
}

impl LocalIssuer {
    /// Construct with a fresh random Ed25519 keypair.
    pub fn random() -> Result<Self, IssuerError> {
        Self::random_with(
            "nucleus-local://demo".to_string(),
            Duration::from_secs(300),
        )
    }

    /// Construct with a fresh random keypair and explicit issuer/lifetime.
    pub fn random_with(issuer: String, lifetime: Duration) -> Result<Self, IssuerError> {
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self::from_signing_key(signing_key, issuer, lifetime)
    }

    /// Construct around a caller-provided signing key. Useful for tests
    /// that want deterministic SVIDs.
    pub fn from_signing_key(
        signing_key: SigningKey,
        issuer: String,
        lifetime: Duration,
    ) -> Result<Self, IssuerError> {
        let pkcs8 = signing_key
            .to_pkcs8_der()
            .map_err(|e| IssuerError::Pkcs8(e.to_string()))?;
        let encoding_key = EncodingKey::from_ed_der(pkcs8.as_bytes());
        let verifying_key = signing_key.verifying_key();
        // Stable kid: short hash of the public key bytes.
        let mut h = Sha256::new();
        h.update(verifying_key.as_bytes());
        let kid_bytes = h.finalize();
        let key_id = URL_SAFE_NO_PAD.encode(&kid_bytes[..12]);
        Ok(Self {
            signing_key,
            encoding_key,
            verifying_key,
            issuer,
            lifetime,
            key_id,
        })
    }

    /// The issuer URL ("iss" claim) used by this issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// JWK key id used in JWT headers and JWKS publication.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Verifying key for in-process JWT validation.
    pub fn decoding_key(&self) -> DecodingKey {
        DecodingKey::from_ed_der(self.verifying_key.as_bytes())
    }

    /// Raw verifying key bytes (32 bytes Ed25519 public key) for sharing
    /// with external verifiers that already speak Ed25519.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Raw signing key (useful for tests that want to construct another
    /// issuer with the same identity).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }
}

impl IdentityFetcher for LocalIssuer {
    fn fetch_jwt_svid(
        &self,
        subject: &CallSpiffeId,
        audience: &str,
    ) -> Result<String, IssuerError> {
        self.fetch_jwt_svid_with_kind(subject, audience, None)
    }

    fn fetch_jwt_svid_with_kind(
        &self,
        subject: &CallSpiffeId,
        audience: &str,
        kind: Option<&str>,
    ) -> Result<String, IssuerError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| IssuerError::Clock)?
            .as_secs();
        let claims = SvidClaims {
            sub: subject.to_string(),
            aud: audience.to_string(),
            iss: self.issuer.clone(),
            iat: now,
            exp: now + self.lifetime.as_secs(),
            jti: Uuid::new_v4().to_string(),
            nucleus_kind: kind.map(|s| s.to_string()),
        };
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.key_id.clone());
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, Validation};

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    #[test]
    fn local_issuer_mints_jwt_with_correct_claims() {
        let issuer = LocalIssuer::random().unwrap();
        let p = pod();
        let token = issuer
            .fetch_jwt_svid(&p, "https://api.anthropic.com")
            .unwrap();
        // Three base64 segments separated by `.`.
        assert_eq!(token.matches('.').count(), 2);

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["https://api.anthropic.com"]);
        validation.set_issuer(&[issuer.issuer()]);
        let decoded = decode::<SvidClaims>(&token, &issuer.decoding_key(), &validation).unwrap();

        assert_eq!(decoded.claims.sub, p.to_string());
        assert_eq!(decoded.claims.aud, "https://api.anthropic.com");
        assert_eq!(decoded.claims.iss, issuer.issuer());
        assert!(decoded.claims.exp > decoded.claims.iat);
        assert!(!decoded.claims.jti.is_empty());
    }

    #[test]
    fn jwt_signature_verifies_only_with_matching_key() {
        let issuer_a = LocalIssuer::random().unwrap();
        let issuer_b = LocalIssuer::random().unwrap();
        let token = issuer_a.fetch_jwt_svid(&pod(), "aud").unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["aud"]);
        validation.set_issuer(&[issuer_a.issuer()]);
        // Wrong key → InvalidSignature.
        let result = decode::<SvidClaims>(&token, &issuer_b.decoding_key(), &validation);
        assert!(result.is_err(), "wrong-key verification must fail");
    }

    #[test]
    fn nucleus_kind_round_trips() {
        let issuer = LocalIssuer::random().unwrap();
        let token = issuer
            .fetch_jwt_svid_with_kind(&pod(), "aud", Some("llm_call"))
            .unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_audience(&["aud"]);
        validation.set_issuer(&[issuer.issuer()]);
        let decoded = decode::<SvidClaims>(&token, &issuer.decoding_key(), &validation).unwrap();
        assert_eq!(decoded.claims.nucleus_kind.as_deref(), Some("llm_call"));
    }

    #[test]
    fn key_id_is_stable_across_calls() {
        let issuer = LocalIssuer::random().unwrap();
        let kid = issuer.key_id().to_string();
        let token1 = issuer.fetch_jwt_svid(&pod(), "aud").unwrap();
        let token2 = issuer.fetch_jwt_svid(&pod(), "aud").unwrap();
        for token in [&token1, &token2] {
            let header = jsonwebtoken::decode_header(token).unwrap();
            assert_eq!(header.kid.as_deref(), Some(kid.as_str()));
        }
    }

    #[test]
    fn verifying_key_bytes_match_signing_key() {
        let bytes: [u8; 32] = [3; 32];
        let sk = SigningKey::from_bytes(&bytes);
        let issuer =
            LocalIssuer::from_signing_key(sk.clone(), "iss".into(), Duration::from_secs(60))
                .unwrap();
        assert_eq!(
            issuer.verifying_key_bytes(),
            sk.verifying_key().to_bytes()
        );
    }

    #[test]
    fn deterministic_signing_key_yields_stable_key_id() {
        // Same signing-key bytes → same kid.
        let bytes: [u8; 32] = [7; 32];
        let sk1 = SigningKey::from_bytes(&bytes);
        let sk2 = SigningKey::from_bytes(&bytes);
        let i1 =
            LocalIssuer::from_signing_key(sk1, "iss".to_string(), Duration::from_secs(60)).unwrap();
        let i2 =
            LocalIssuer::from_signing_key(sk2, "iss".to_string(), Duration::from_secs(60)).unwrap();
        assert_eq!(i1.key_id(), i2.key_id());
    }
}
