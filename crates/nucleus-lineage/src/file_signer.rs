//! Production Ed25519 edge signer backed by a PKCS#8 private key (most-paranoid #6).
//!
//! Unlike the dev-only `LocalIssuer` (which generates a random key in-process,
//! warns on every construction, and is gated behind the `insecure-local-issuer`
//! feature), `Pkcs8FileSigner` loads a *caller-supplied* long-lived key from a
//! file or env var. It is always compiled (no insecure feature) and is the
//! signer a production control-plane / tool-proxy installs so that real-run
//! lineage edges are signed by an operator-controlled key, verifiable by the
//! stateless verifier via [`Pkcs8FileSigner::publish_jwks`].
//!
//! Decode-only: it never generates keys, so it pulls no CSPRNG.

#![forbid(unsafe_code)]

use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::issuer::{EdgeSigner, IssuerError, SigningProvider};

/// An Ed25519 edge signer constructed from an externally-managed PKCS#8 key.
pub struct Pkcs8FileSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    /// Stable JWKS key id: `base64url(sha256(pubkey)[..12])` — identical scheme
    /// to `LocalIssuer`, so verifiers resolve either signer the same way.
    kid: String,
}

impl Pkcs8FileSigner {
    /// Build from PKCS#8 DER bytes.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, IssuerError> {
        let signing_key = SigningKey::from_pkcs8_der(der)
            .map_err(|e| IssuerError::KeyEncoding(format!("pkcs8 der decode: {e}")))?;
        Ok(Self::from_signing_key(signing_key))
    }

    /// Build from a PKCS#8 PEM string (a standard `PRIVATE KEY` PEM block).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, IssuerError> {
        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| IssuerError::KeyEncoding(format!("pkcs8 pem decode: {e}")))?;
        Ok(Self::from_signing_key(signing_key))
    }

    /// Build from a PKCS#8 PEM file on disk.
    pub fn from_pkcs8_pem_file(path: &Path) -> Result<Self, IssuerError> {
        let pem = std::fs::read_to_string(path).map_err(|e| {
            IssuerError::KeyEncoding(format!("reading key {}: {e}", path.display()))
        })?;
        Self::from_pkcs8_pem(&pem)
    }

    /// Build from a base64-encoded PKCS#8 DER value in an environment variable.
    pub fn from_env(var: &str) -> Result<Self, IssuerError> {
        let b64 = std::env::var(var)
            .map_err(|_| IssuerError::KeyEncoding(format!("env var {var} not set")))?;
        let der = URL_SAFE_NO_PAD
            .decode(b64.trim())
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(b64.trim()))
            .map_err(|e| IssuerError::KeyEncoding(format!("base64 decode of {var}: {e}")))?;
        Self::from_pkcs8_der(&der)
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let mut h = Sha256::new();
        h.update(verifying_key.as_bytes());
        let kid = URL_SAFE_NO_PAD.encode(&h.finalize()[..12]);
        Self {
            signing_key,
            verifying_key,
            kid,
        }
    }

    /// Raw 32-byte Ed25519 verifying key (for sharing with external verifiers).
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl EdgeSigner for Pkcs8FileSigner {
    fn alg(&self) -> &str {
        "EdDSA"
    }

    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign(&self, canonical_bytes: &[u8]) -> Result<Vec<u8>, IssuerError> {
        Ok(self.signing_key.sign(canonical_bytes).to_bytes().to_vec())
    }
}

impl SigningProvider for Pkcs8FileSigner {
    fn publish_jwks(&self) -> serde_json::Value {
        let x = URL_SAFE_NO_PAD.encode(self.verifying_key.as_bytes());
        serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": self.kid,
                "x": x,
                "alg": "EdDSA",
                "use": "sig",
            }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::EncodePrivateKey;

    // A deterministic test key (NOT random — decode-only crate has no CSPRNG).
    fn test_der() -> Vec<u8> {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        sk.to_pkcs8_der().unwrap().as_bytes().to_vec()
    }

    #[test]
    fn from_der_signs_and_kid_matches_jwks() {
        let signer = Pkcs8FileSigner::from_pkcs8_der(&test_der()).unwrap();
        let sig = signer.sign(b"hello").unwrap();
        assert_eq!(sig.len(), 64);
        assert_eq!(signer.alg(), "EdDSA");
        let jwks = signer.publish_jwks();
        assert_eq!(jwks["keys"][0]["kid"], signer.kid());
        assert_eq!(jwks["keys"][0]["crv"], "Ed25519");
    }

    #[test]
    fn signature_verifies_against_published_key() {
        use ed25519_dalek::Verifier;
        let signer = Pkcs8FileSigner::from_pkcs8_der(&test_der()).unwrap();
        let msg = b"canonical edge bytes";
        let sig_bytes = signer.sign(msg).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        let vk = VerifyingKey::from_bytes(&signer.verifying_key_bytes()).unwrap();
        assert!(vk.verify(msg, &sig).is_ok());
    }

    #[test]
    fn pem_roundtrip() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let pem = sk.to_pkcs8_pem(Default::default()).unwrap();
        let signer = Pkcs8FileSigner::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(signer.sign(b"x").unwrap().len(), 64);
    }

    #[test]
    fn malformed_der_fails() {
        assert!(Pkcs8FileSigner::from_pkcs8_der(b"not a key").is_err());
    }

    #[test]
    fn deterministic_kid() {
        let a = Pkcs8FileSigner::from_pkcs8_der(&test_der()).unwrap();
        let b = Pkcs8FileSigner::from_pkcs8_der(&test_der()).unwrap();
        assert_eq!(a.kid(), b.kid());
    }
}
