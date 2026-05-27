//! [`LocalIssuer`] — in-process Ed25519 JWT-SVID issuer for tests and demos.
//!
//! **NOT FOR PRODUCTION USE.** This module is gated behind the `dev` cargo
//! feature (`nucleus-lineage = { features = ["dev"] }`) so production
//! binaries cannot link or re-export it. Constructing an instance also logs
//! a one-time `tracing::warn!` so any accidental use is immediately visible
//! in logs.
//!
//! For production: write a `SpiffeWorkloadApi` impl of [`IdentityFetcher`]
//! that connects to a real SPIRE Agent socket, and provide it to the
//! runtime instead. No such impl ships in this repo today.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::id::CallSpiffeId;
use crate::issuer::{EdgeSigner, IdentityFetcher, IssuerError, SvidClaims};

/// One-time guard so we only `tracing::warn!` once per process about
/// LocalIssuer being demo-only.
static WARNED: AtomicBool = AtomicBool::new(false);

fn warn_once() {
    if WARNED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        tracing::warn!(
            target: "nucleus_lineage::local_issuer",
            "LocalIssuer is a DEMO-ONLY in-process Ed25519 issuer. \
             Do not use in production. Wire a SPIRE-Workload-API-backed \
             IdentityFetcher impl instead."
        );
    }
}

/// In-process JWT-SVID issuer for tests and demos.
///
/// Holds an Ed25519 keypair generated at construction. SVIDs are signed
/// EdDSA. The issuer URL string defaults to `nucleus-local://demo` and the
/// SVID lifetime defaults to 5 minutes (matching SPIRE Agent's default).
///
/// In a process that needs to verify the SVIDs (e.g., the demo's mock LLM
/// endpoint), call [`Self::decoding_key`] for an in-process verifier.
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
        Self::random_with("nucleus-local://demo".to_string(), Duration::from_secs(300))
    }

    /// Construct with a fresh random keypair and explicit issuer/lifetime.
    pub fn random_with(issuer: String, lifetime: Duration) -> Result<Self, IssuerError> {
        let mut csprng = rand::rng();
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
        warn_once();
        let pkcs8 = signing_key
            .to_pkcs8_der()
            .map_err(|e| IssuerError::KeyEncoding(e.to_string()))?;
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

    /// JWK key id used in JWT headers and (future) JWKS publication.
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

    /// Publish a single-key JWKS (JSON Web Key Set) suitable for serializing
    /// to disk or to an HTTPS endpoint. The verifier (in any process) loads
    /// this, looks up the key by `kid`, and verifies signatures against it.
    ///
    /// The format follows RFC 7517 + RFC 8037 (Ed25519 OKP):
    ///
    /// ```text
    /// {
    ///   "keys": [
    ///     { "kty": "OKP", "crv": "Ed25519", "kid": "<kid>", "x": "<base64url>", "alg": "EdDSA", "use": "sig" }
    ///   ]
    /// }
    /// ```
    pub fn publish_jwks(&self) -> serde_json::Value {
        let x = URL_SAFE_NO_PAD.encode(self.verifying_key.as_bytes());
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": self.key_id,
                "x": x,
                "alg": "EdDSA",
                "use": "sig",
            }]
        })
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
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| IssuerError::Backend(e.to_string()))?;
        Ok(token)
    }
}

impl EdgeSigner for LocalIssuer {
    fn alg(&self) -> &str {
        "EdDSA"
    }

    fn kid(&self) -> &str {
        &self.key_id
    }

    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, IssuerError> {
        let sig = self.signing_key.sign(canonical_bytes);
        Ok(sig.to_bytes().to_vec())
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
        assert_eq!(issuer.verifying_key_bytes(), sk.verifying_key().to_bytes());
    }

    #[test]
    fn deterministic_signing_key_yields_stable_key_id() {
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
