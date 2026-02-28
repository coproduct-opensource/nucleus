//! OAuth2 DPoP (Demonstrating Proof-of-Possession) tokens bound to SPIFFE SVIDs.
//!
//! Implements [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) DPoP proofs
//! using ES256 (P-256 ECDSA) signing, with SPIFFE identity binding. DPoP
//! prevents token theft by cryptographically binding access tokens to the
//! key material of the workload's SVID.
//!
//! # Security Model
//!
//! ```text
//! App A (sender)                          App B (verifier)
//! ┌────────────────────┐                  ┌────────────────────┐
//! │ SVID private key   │                  │ SVID public key    │
//! │ + SPIFFE ID        │                  │ (from DID document │
//! │                    │   DPoP proof +   │  or direct trust)  │
//! │ Creates DPoP proof ├─── access token ─►                    │
//! │ binding token to   │                  │ Verifies:          │
//! │ HTTP method + URL  │                  │  1. JWS signature  │
//! │                    │                  │  2. htm/htu match  │
//! └────────────────────┘                  │  3. Token binding  │
//!                                         │  4. Freshness      │
//!                                         └────────────────────┘
//! ```
//!
//! # Example
//!
//! ```
//! use nucleus_identity::dpop::{DpopProofBuilder, DpopVerifier};
//! use nucleus_identity::did::JsonWebKey;
//! use ring::signature::KeyPair;
//! use base64::Engine;
//!
//! // Generate a test key pair
//! let rng = ring::rand::SystemRandom::new();
//! let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
//!     &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
//!     &rng,
//! ).unwrap();
//!
//! // Extract public key as JWK
//! let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
//!     &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
//!     pkcs8.as_ref(),
//!     &rng,
//! ).unwrap();
//! let pub_bytes = key_pair.public_key().as_ref();
//! let x = base64::engine::general_purpose::URL_SAFE_NO_PAD
//!     .encode(&pub_bytes[1..33]);
//! let y = base64::engine::general_purpose::URL_SAFE_NO_PAD
//!     .encode(&pub_bytes[33..65]);
//! let jwk = JsonWebKey::ec_p256(&x, &y);
//!
//! // Create a DPoP proof
//! let proof = DpopProofBuilder::new("POST", "https://api.example.com/data")
//!     .with_spiffe_id("spiffe://example.com/ns/apps/sa/my-app")
//!     .build(pkcs8.as_ref())
//!     .unwrap();
//!
//! // Verify it
//! let verifier = DpopVerifier::new();
//! let claims = verifier.verify(&proof, &jwk, "POST", "https://api.example.com/data").unwrap();
//! assert_eq!(claims.htm, "POST");
//! ```

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::did::JsonWebKey;
use crate::{Error, Result};

/// Default maximum clock skew allowed when verifying DPoP proofs (60 seconds).
const DEFAULT_MAX_CLOCK_SKEW_SECS: i64 = 60;

/// Default maximum age of a DPoP proof before it's considered stale (5 minutes).
const DEFAULT_MAX_AGE_SECS: i64 = 300;

// ═══════════════════════════════════════════════════════════════════════════
// DPOP HEADER
// ═══════════════════════════════════════════════════════════════════════════

/// The JWS header of a DPoP proof per RFC 9449 §4.2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DpopHeader {
    /// Always `"dpop+jwt"`.
    pub typ: String,

    /// Signing algorithm — always `"ES256"` for P-256 ECDSA.
    pub alg: String,

    /// The public key corresponding to the signing key, as a JWK.
    pub jwk: JsonWebKey,
}

// ═══════════════════════════════════════════════════════════════════════════
// DPOP CLAIMS
// ═══════════════════════════════════════════════════════════════════════════

/// The JWT claims payload of a DPoP proof per RFC 9449 §4.2.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DpopClaims {
    /// Unique token identifier (prevents replay).
    pub jti: String,

    /// The HTTP method of the request (e.g., `"POST"`).
    pub htm: String,

    /// The HTTP target URI of the request (without query/fragment).
    pub htu: String,

    /// Issued-at timestamp (Unix epoch seconds).
    pub iat: i64,

    /// Optional: SHA-256 hash of the access token being bound (base64url).
    /// Present when binding a DPoP proof to a specific access token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ath: Option<String>,

    /// SPIFFE extension: the SPIFFE ID of the workload creating the proof.
    /// This binds the DPoP proof to a specific workload identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// DPOP PROOF BUILDER
// ═══════════════════════════════════════════════════════════════════════════

/// Builder for creating DPoP proofs bound to SVID key material.
///
/// Creates JWS compact serializations (ES256) with the required DPoP
/// header (`typ: "dpop+jwt"`, `jwk`) and claims (`jti`, `htm`, `htu`, `iat`).
pub struct DpopProofBuilder {
    htm: String,
    htu: String,
    access_token: Option<String>,
    spiffe_id: Option<String>,
}

impl DpopProofBuilder {
    /// Create a new DPoP proof builder for the given HTTP method and URL.
    pub fn new(htm: &str, htu: &str) -> Self {
        Self {
            htm: htm.to_string(),
            htu: htu.to_string(),
            access_token: None,
            spiffe_id: None,
        }
    }

    /// Bind this DPoP proof to a specific access token.
    ///
    /// The access token's SHA-256 hash will be included as the `ath` claim,
    /// preventing the proof from being used with a different token.
    pub fn with_access_token(mut self, token: &str) -> Self {
        self.access_token = Some(token.to_string());
        self
    }

    /// Include the SPIFFE ID of the workload in the proof.
    ///
    /// This is a SPIFFE-specific extension that binds the DPoP proof
    /// to a specific workload identity, enabling the verifier to confirm
    /// both possession and identity.
    pub fn with_spiffe_id(mut self, spiffe_id: &str) -> Self {
        self.spiffe_id = Some(spiffe_id.to_string());
        self
    }

    /// Build the DPoP proof JWS using the given PKCS#8-encoded private key.
    ///
    /// Returns a compact JWS string (`header.payload.signature`) suitable
    /// for use in the `DPoP` HTTP header.
    ///
    /// # Errors
    ///
    /// Returns an error if key parsing or signing fails.
    pub fn build(self, private_key_pkcs8_der: &[u8]) -> Result<String> {
        let rng = SystemRandom::new();

        // Parse the key pair to extract the public key for the header
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            private_key_pkcs8_der,
            &rng,
        )
        .map_err(|e| Error::Internal(format!("failed to parse PKCS#8 key: {e}")))?;

        // Extract public key as JWK
        let pub_bytes = key_pair.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
        let jwk = JsonWebKey::ec_p256(&x, &y);

        // Build the header
        let header = DpopHeader {
            typ: "dpop+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk,
        };

        // Compute access token hash if provided
        let ath = self.access_token.map(|token| {
            let hash = Sha256::digest(token.as_bytes());
            URL_SAFE_NO_PAD.encode(hash)
        });

        // Generate unique token ID
        let jti = generate_jti();

        // Build the claims
        let claims = DpopClaims {
            jti,
            htm: self.htm,
            htu: self.htu,
            iat: Utc::now().timestamp(),
            ath,
            spiffe_id: self.spiffe_id,
        };

        // Encode header and payload
        let header_json = serde_json::to_string(&header)
            .map_err(|e| Error::Internal(format!("failed to serialize DPoP header: {e}")))?;
        let claims_json = serde_json::to_string(&claims)
            .map_err(|e| Error::Internal(format!("failed to serialize DPoP claims: {e}")))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

        // Sign header.payload
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = key_pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|e| Error::Internal(format!("DPoP signing failed: {e}")))?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DPOP VERIFIER
// ═══════════════════════════════════════════════════════════════════════════

/// Verifier for DPoP proofs.
///
/// Validates the JWS signature, checks the header and claims structure,
/// and enforces freshness constraints.
pub struct DpopVerifier {
    max_clock_skew: chrono::Duration,
    max_age: chrono::Duration,
}

impl DpopVerifier {
    /// Create a new verifier with default settings (60s skew, 5min max age).
    pub fn new() -> Self {
        Self {
            max_clock_skew: chrono::Duration::seconds(DEFAULT_MAX_CLOCK_SKEW_SECS),
            max_age: chrono::Duration::seconds(DEFAULT_MAX_AGE_SECS),
        }
    }

    /// Set the maximum allowed clock skew.
    pub fn with_max_clock_skew(mut self, skew: chrono::Duration) -> Self {
        self.max_clock_skew = skew;
        self
    }

    /// Set the maximum age of a DPoP proof.
    pub fn with_max_age(mut self, age: chrono::Duration) -> Self {
        self.max_age = age;
        self
    }

    /// Verify a DPoP proof against expected parameters.
    ///
    /// Checks:
    /// 1. JWS structure and `dpop+jwt` type header
    /// 2. ES256 signature against the embedded JWK
    /// 3. `htm` matches the expected HTTP method
    /// 4. `htu` matches the expected HTTP URI
    /// 5. `iat` is within acceptable time window
    ///
    /// Optionally also verifies the JWK matches an expected public key.
    ///
    /// # Arguments
    ///
    /// * `proof` — The DPoP JWS compact serialization
    /// * `expected_key` — The expected public key (from DID document or SVID)
    /// * `expected_htm` — The HTTP method of the request being authenticated
    /// * `expected_htu` — The HTTP URI of the request being authenticated
    ///
    /// # Errors
    ///
    /// Returns an error if any verification step fails.
    pub fn verify(
        &self,
        proof: &str,
        expected_key: &JsonWebKey,
        expected_htm: &str,
        expected_htu: &str,
    ) -> Result<DpopClaims> {
        // Split the JWS
        let parts: Vec<&str> = proof.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(Error::VerificationFailed(
                "DPoP proof must have 3 dot-separated parts".into(),
            ));
        }

        let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        // Decode and validate header
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| Error::VerificationFailed(format!("invalid header encoding: {e}")))?;
        let header: DpopHeader = serde_json::from_slice(&header_bytes)
            .map_err(|e| Error::VerificationFailed(format!("invalid DPoP header: {e}")))?;

        // Verify header fields
        if header.typ != "dpop+jwt" {
            return Err(Error::VerificationFailed(format!(
                "expected typ \"dpop+jwt\", got \"{}\"",
                header.typ
            )));
        }
        if header.alg != "ES256" {
            return Err(Error::VerificationFailed(format!(
                "expected alg \"ES256\", got \"{}\"",
                header.alg
            )));
        }

        // Verify the embedded JWK matches the expected key (both x and y must match)
        if header.jwk.x != expected_key.x || header.jwk.y != expected_key.y {
            return Err(Error::VerificationFailed(
                "DPoP proof JWK does not match expected key".into(),
            ));
        }

        // Verify the signature using the embedded JWK
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| Error::VerificationFailed(format!("invalid signature encoding: {e}")))?;

        // Reconstruct the uncompressed EC point from the JWK
        let x_bytes = URL_SAFE_NO_PAD
            .decode(&header.jwk.x)
            .map_err(|e| Error::VerificationFailed(format!("invalid JWK x: {e}")))?;
        let y_str = header
            .jwk
            .y
            .as_deref()
            .ok_or_else(|| Error::VerificationFailed("DPoP JWK missing y coordinate".into()))?;
        let y_bytes = URL_SAFE_NO_PAD
            .decode(y_str)
            .map_err(|e| Error::VerificationFailed(format!("invalid JWK y: {e}")))?;

        let mut pub_key_bytes = Vec::with_capacity(65);
        pub_key_bytes.push(0x04); // uncompressed point
        pub_key_bytes.extend_from_slice(&x_bytes);
        pub_key_bytes.extend_from_slice(&y_bytes);

        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_FIXED,
            &pub_key_bytes,
        );

        public_key
            .verify(signing_input.as_bytes(), &sig_bytes)
            .map_err(|_| Error::VerificationFailed("DPoP signature verification failed".into()))?;

        // Decode and validate claims
        let claims_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| Error::VerificationFailed(format!("invalid payload encoding: {e}")))?;
        let claims: DpopClaims = serde_json::from_slice(&claims_bytes)
            .map_err(|e| Error::VerificationFailed(format!("invalid DPoP claims: {e}")))?;

        // Verify HTTP method
        if claims.htm != expected_htm {
            return Err(Error::VerificationFailed(format!(
                "htm mismatch: expected \"{expected_htm}\", got \"{}\"",
                claims.htm
            )));
        }

        // Verify HTTP URI
        if claims.htu != expected_htu {
            return Err(Error::VerificationFailed(format!(
                "htu mismatch: expected \"{expected_htu}\", got \"{}\"",
                claims.htu
            )));
        }

        // Verify freshness
        let now = Utc::now();
        let issued_at = DateTime::from_timestamp(claims.iat, 0).ok_or_else(|| {
            Error::VerificationFailed(format!("invalid iat timestamp: {}", claims.iat))
        })?;

        // Not issued in the future (with clock skew tolerance)
        if issued_at > now + self.max_clock_skew {
            return Err(Error::VerificationFailed(
                "DPoP proof issued in the future".into(),
            ));
        }

        // Not too old
        if now - issued_at > self.max_age {
            return Err(Error::VerificationFailed("DPoP proof expired".into()));
        }

        Ok(claims)
    }

    /// Verify a DPoP proof and also check the access token binding.
    ///
    /// In addition to standard verification, confirms that the `ath` claim
    /// matches the SHA-256 hash of the provided access token.
    pub fn verify_with_token(
        &self,
        proof: &str,
        expected_key: &JsonWebKey,
        expected_htm: &str,
        expected_htu: &str,
        access_token: &str,
    ) -> Result<DpopClaims> {
        let claims = self.verify(proof, expected_key, expected_htm, expected_htu)?;

        // Verify access token binding
        let expected_ath = URL_SAFE_NO_PAD.encode(Sha256::digest(access_token.as_bytes()));

        match &claims.ath {
            Some(ath) if ath == &expected_ath => Ok(claims),
            Some(ath) => Err(Error::VerificationFailed(format!(
                "access token hash mismatch: expected {expected_ath}, got {ath}"
            ))),
            None => Err(Error::VerificationFailed(
                "DPoP proof missing ath claim for token binding".into(),
            )),
        }
    }
}

impl Default for DpopVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a unique JTI (JWT ID) for replay prevention.
///
/// Uses 16 random bytes encoded as base64url (22 characters).
fn generate_jti() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 16];
    ring::rand::SecureRandom::fill(&rng, &mut bytes).expect("system random should not fail");
    URL_SAFE_NO_PAD.encode(bytes)
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    use ring::signature::KeyPair;

    /// Generate a fresh P-256 PKCS#8 key pair for testing.
    fn make_test_key() -> (Vec<u8>, JsonWebKey) {
        let rng = SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .unwrap();

        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
            &rng,
        )
        .unwrap();

        let pub_bytes = key_pair.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);

        (pkcs8.as_ref().to_vec(), JsonWebKey::ec_p256(&x, &y))
    }

    #[test]
    fn dpop_proof_roundtrip() {
        let (key, jwk) = make_test_key();
        let proof = DpopProofBuilder::new("POST", "https://api.example.com/data")
            .build(&key)
            .unwrap();

        let verifier = DpopVerifier::new();
        let claims = verifier
            .verify(&proof, &jwk, "POST", "https://api.example.com/data")
            .unwrap();

        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.htu, "https://api.example.com/data");
        assert!(!claims.jti.is_empty());
        assert!(claims.ath.is_none());
        assert!(claims.spiffe_id.is_none());
    }

    #[test]
    fn dpop_proof_with_spiffe_id() {
        let (key, jwk) = make_test_key();
        let proof = DpopProofBuilder::new("GET", "https://api.example.com/status")
            .with_spiffe_id("spiffe://example.com/ns/apps/sa/my-app")
            .build(&key)
            .unwrap();

        let verifier = DpopVerifier::new();
        let claims = verifier
            .verify(&proof, &jwk, "GET", "https://api.example.com/status")
            .unwrap();

        assert_eq!(
            claims.spiffe_id.as_deref(),
            Some("spiffe://example.com/ns/apps/sa/my-app")
        );
    }

    #[test]
    fn dpop_proof_with_access_token_binding() {
        let (key, jwk) = make_test_key();
        let access_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test";

        let proof = DpopProofBuilder::new("POST", "https://api.example.com/data")
            .with_access_token(access_token)
            .build(&key)
            .unwrap();

        let verifier = DpopVerifier::new();
        let claims = verifier
            .verify_with_token(
                &proof,
                &jwk,
                "POST",
                "https://api.example.com/data",
                access_token,
            )
            .unwrap();

        assert!(claims.ath.is_some());
    }

    #[test]
    fn dpop_rejects_wrong_access_token() {
        let (key, jwk) = make_test_key();
        let proof = DpopProofBuilder::new("POST", "https://api.example.com/data")
            .with_access_token("correct-token")
            .build(&key)
            .unwrap();

        let verifier = DpopVerifier::new();
        let result = verifier.verify_with_token(
            &proof,
            &jwk,
            "POST",
            "https://api.example.com/data",
            "wrong-token",
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("access token hash mismatch"));
    }

    #[test]
    fn dpop_rejects_missing_token_binding() {
        let (key, jwk) = make_test_key();
        // Build without access token
        let proof = DpopProofBuilder::new("POST", "https://api.example.com/data")
            .build(&key)
            .unwrap();

        let verifier = DpopVerifier::new();
        let result = verifier.verify_with_token(
            &proof,
            &jwk,
            "POST",
            "https://api.example.com/data",
            "some-token",
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("missing ath claim"));
    }

    #[test]
    fn dpop_rejects_wrong_http_method() {
        let (key, jwk) = make_test_key();
        let proof = DpopProofBuilder::new("POST", "https://api.example.com/data")
            .build(&key)
            .unwrap();

        let verifier = DpopVerifier::new();
        let result = verifier.verify(&proof, &jwk, "GET", "https://api.example.com/data");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("htm mismatch"));
    }

    #[test]
    fn dpop_rejects_wrong_url() {
        let (key, jwk) = make_test_key();
        let proof = DpopProofBuilder::new("POST", "https://api.example.com/data")
            .build(&key)
            .unwrap();

        let verifier = DpopVerifier::new();
        let result = verifier.verify(&proof, &jwk, "POST", "https://evil.com/data");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("htu mismatch"));
    }

    #[test]
    fn dpop_rejects_wrong_key() {
        let (key, _) = make_test_key();
        let (_, wrong_jwk) = make_test_key();

        let proof = DpopProofBuilder::new("POST", "https://api.example.com/data")
            .build(&key)
            .unwrap();

        let verifier = DpopVerifier::new();
        let result = verifier.verify(&proof, &wrong_jwk, "POST", "https://api.example.com/data");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("does not match expected key"));
    }

    #[test]
    fn dpop_rejects_tampered_payload() {
        let (key, jwk) = make_test_key();
        let proof = DpopProofBuilder::new("POST", "https://api.example.com/data")
            .build(&key)
            .unwrap();

        // Tamper with the payload
        let parts: Vec<&str> = proof.splitn(3, '.').collect();
        let tampered = format!("{}.{}.{}", parts[0], "dGFtcGVyZWQ", parts[2]);

        let verifier = DpopVerifier::new();
        let result = verifier.verify(&tampered, &jwk, "POST", "https://api.example.com/data");
        assert!(result.is_err());
    }

    #[test]
    fn dpop_header_is_dpop_jwt() {
        let (key, _) = make_test_key();
        let proof = DpopProofBuilder::new("GET", "https://example.com")
            .build(&key)
            .unwrap();

        // Decode the header
        let header_b64 = proof.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: DpopHeader = serde_json::from_slice(&header_bytes).unwrap();

        assert_eq!(header.typ, "dpop+jwt");
        assert_eq!(header.alg, "ES256");
        assert_eq!(header.jwk.kty, "EC");
        assert_eq!(header.jwk.crv, "P-256");
    }

    #[test]
    fn dpop_unique_jti_per_proof() {
        let (key, _) = make_test_key();

        let proof1 = DpopProofBuilder::new("GET", "https://example.com")
            .build(&key)
            .unwrap();
        let proof2 = DpopProofBuilder::new("GET", "https://example.com")
            .build(&key)
            .unwrap();

        // Extract JTIs
        let jti1 = extract_jti(&proof1);
        let jti2 = extract_jti(&proof2);
        assert_ne!(jti1, jti2);
    }

    #[test]
    fn dpop_rejects_malformed_jws() {
        let (_, jwk) = make_test_key();
        let verifier = DpopVerifier::new();

        // Two parts (missing signature)
        assert!(verifier
            .verify("only.two", &jwk, "GET", "https://x.com")
            .is_err());

        // Empty string
        assert!(verifier.verify("", &jwk, "GET", "https://x.com").is_err());
    }

    #[test]
    fn dpop_full_spiffe_flow() {
        // Simulates the full SPIFFE-DPoP flow:
        // 1. Workload creates a DPoP proof with its SVID key + SPIFFE ID
        // 2. Binds it to an access token
        // 3. Verifier checks everything
        let (svid_key, svid_jwk) = make_test_key();
        let spiffe_id = "spiffe://prod.example.com/ns/payments/sa/payment-service";
        let access_token = "at_live_abc123xyz789";

        let proof = DpopProofBuilder::new("POST", "https://orders.example.com/api/charge")
            .with_spiffe_id(spiffe_id)
            .with_access_token(access_token)
            .build(&svid_key)
            .unwrap();

        let verifier = DpopVerifier::new();
        let claims = verifier
            .verify_with_token(
                &proof,
                &svid_jwk,
                "POST",
                "https://orders.example.com/api/charge",
                access_token,
            )
            .unwrap();

        // All three bindings are verified:
        // 1. Proof is signed by the SVID key (cryptographic possession)
        assert_eq!(claims.htm, "POST");
        assert_eq!(claims.htu, "https://orders.example.com/api/charge");
        // 2. SPIFFE ID is present (workload identity)
        assert_eq!(claims.spiffe_id.as_deref(), Some(spiffe_id));
        // 3. Access token is bound (user consent)
        assert!(claims.ath.is_some());
    }

    #[test]
    fn dpop_claims_serde_roundtrip() {
        let claims = DpopClaims {
            jti: "test-jti-123".into(),
            htm: "POST".into(),
            htu: "https://example.com/api".into(),
            iat: 1700000000,
            ath: Some("token-hash".into()),
            spiffe_id: Some("spiffe://example.com/ns/apps/sa/app".into()),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let parsed: DpopClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, claims);
    }

    #[test]
    fn dpop_claims_skips_optional_fields() {
        let claims = DpopClaims {
            jti: "test".into(),
            htm: "GET".into(),
            htu: "https://example.com".into(),
            iat: 1700000000,
            ath: None,
            spiffe_id: None,
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("ath"));
        assert!(!json.contains("spiffe_id"));
    }

    /// Helper to extract JTI from a DPoP proof JWS.
    fn extract_jti(proof: &str) -> String {
        let payload_b64 = proof.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let claims: DpopClaims = serde_json::from_slice(&payload_bytes).unwrap();
        claims.jti
    }
}
