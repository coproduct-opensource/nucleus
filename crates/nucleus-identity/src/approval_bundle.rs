//! Signed preflight approval bundles for operation authorization.
//!
//! An approval bundle is a JWS-signed artifact that authorizes a specific
//! set of operations for a particular manifest (PodSpec). Unlike runtime
//! approval tokens, bundles are created *before* execution and can be
//! verified without the approver being present.
//!
//! # Security Properties
//!
//! - **Non-replayable**: Each bundle has a unique `jti` (16 random bytes).
//!   The verifier caller is responsible for JTI deduplication.
//! - **Manifest-bound**: The bundle's `manifest_hash` must match the
//!   SHA-256 of the serialized PodSpec being executed.
//! - **Time-bounded**: Bundles have an expiration time (`exp`).
//! - **SPIFFE-bound**: The approver's SPIFFE ID is embedded as `iss`.
//! - **Composable**: A bundle's JWS bytes can populate
//!   `SpiffeTraceLink.attestation` for escalation chain integration.
//!
//! # Example
//!
//! ```
//! use nucleus_identity::approval_bundle::{
//!     ApprovalBundleBuilder, ApprovalBundleVerifier, compute_manifest_hash,
//! };
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
//! let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
//!     &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
//!     pkcs8.as_ref(),
//!     &rng,
//! ).unwrap();
//! let pub_bytes = key_pair.public_key().as_ref();
//! let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
//! let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
//! let jwk = JsonWebKey::ec_p256(&x, &y);
//!
//! // Create a manifest hash
//! let manifest_hash = compute_manifest_hash(b"apiVersion: nucleus/v1\nkind: Pod");
//!
//! // Build an approval bundle
//! let jws = ApprovalBundleBuilder::new("spiffe://nucleus.local/human/alice")
//!     .approve_operation("write_files")
//!     .approve_operation("run_bash")
//!     .manifest_hash(&manifest_hash)
//!     .ttl_seconds(3600)
//!     .build(pkcs8.as_ref())
//!     .unwrap();
//!
//! // Verify it
//! let verifier = ApprovalBundleVerifier::new();
//! let claims = verifier.verify(&jws, &jwk, &manifest_hash).unwrap();
//! assert_eq!(claims.iss, "spiffe://nucleus.local/human/alice");
//! assert!(claims.approved_operations.contains("write_files"));
//! ```

use std::collections::BTreeSet;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::did::JsonWebKey;
use crate::{Error, Result};

/// Default maximum clock skew allowed when verifying bundles (60 seconds).
const DEFAULT_MAX_CLOCK_SKEW_SECS: i64 = 60;

// ═══════════════════════════════════════════════════════════════════════════
// HEADER
// ═══════════════════════════════════════════════════════════════════════════

/// JWS header for an approval bundle.
///
/// Uses `typ: "approval+jwt"` to distinguish from DPoP proofs (`dpop+jwt`),
/// preventing cross-protocol attacks where one token type is confused for another.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalBundleHeader {
    /// Always `"approval+jwt"`.
    pub typ: String,

    /// Signing algorithm — always `"ES256"` for P-256 ECDSA.
    pub alg: String,

    /// The approver's public key as a JWK.
    pub jwk: JsonWebKey,
}

// ═══════════════════════════════════════════════════════════════════════════
// CLAIMS
// ═══════════════════════════════════════════════════════════════════════════

/// Claims payload for an approval bundle.
///
/// Operations are represented as strings matching `lattice_guard::Operation`'s
/// serde representation (snake_case). This avoids a dependency from
/// `nucleus-identity` on `lattice-guard`; the consumer (e.g., tool-proxy)
/// maps strings back to concrete `Operation` variants.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalBundleClaims {
    /// Unique bundle identifier (prevents replay).
    /// Generated from 16 random bytes, base64url-encoded.
    pub jti: String,

    /// Issuer: the SPIFFE ID of the approver.
    pub iss: String,

    /// Issued-at timestamp (Unix epoch seconds).
    pub iat: i64,

    /// Expiration timestamp (Unix epoch seconds).
    pub exp: i64,

    /// SHA-256 hash of the serialized PodSpec manifest (hex-encoded).
    /// The verifier checks this against the actual PodSpec being executed.
    pub manifest_hash: String,

    /// Approved operations (strings matching `lattice_guard::Operation` serde names).
    /// e.g., `{"write_files", "run_bash", "git_push"}`
    pub approved_operations: BTreeSet<String>,

    /// Optional: maximum number of times this approval can be consumed.
    /// `None` means unlimited within the TTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,

    /// Optional: drand round at time of approval for temporal anchoring.
    /// When present, the verifier can confirm the bundle was created
    /// at a verifiable point in cryptographic time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drand_round: Option<u64>,

    /// Optional: SHA-256 hex of the VM launch attestation's combined hash.
    /// When present, binds this approval to a specific VM configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_hash: Option<String>,

    /// Optional: human-readable reason for the approval.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// BUILDER
// ═══════════════════════════════════════════════════════════════════════════

/// Builder for creating signed approval bundles.
///
/// Collects approval parameters and signs the claims with the approver's
/// PKCS#8-encoded private key, producing a JWS compact serialization.
pub struct ApprovalBundleBuilder {
    approver_spiffe_id: String,
    operations: BTreeSet<String>,
    manifest_hash: String,
    ttl_seconds: u64,
    max_uses: Option<u32>,
    drand_round: Option<u64>,
    attestation_hash: Option<String>,
    reason: Option<String>,
}

impl ApprovalBundleBuilder {
    /// Create a new builder for the given approver SPIFFE ID.
    pub fn new(approver_spiffe_id: impl Into<String>) -> Self {
        Self {
            approver_spiffe_id: approver_spiffe_id.into(),
            operations: BTreeSet::new(),
            manifest_hash: String::new(),
            ttl_seconds: 3600,
            max_uses: None,
            drand_round: None,
            attestation_hash: None,
            reason: None,
        }
    }

    /// Add a single operation to the approved set.
    pub fn approve_operation(mut self, operation: impl Into<String>) -> Self {
        self.operations.insert(operation.into());
        self
    }

    /// Add multiple operations to the approved set.
    pub fn approve_operations<S: AsRef<str>>(mut self, operations: &[S]) -> Self {
        for op in operations {
            self.operations.insert(op.as_ref().to_string());
        }
        self
    }

    /// Set the manifest hash (SHA-256 hex of the serialized PodSpec).
    pub fn manifest_hash(mut self, hash: impl Into<String>) -> Self {
        self.manifest_hash = hash.into();
        self
    }

    /// Set the TTL in seconds (default: 3600).
    pub fn ttl_seconds(mut self, ttl: u64) -> Self {
        self.ttl_seconds = ttl;
        self
    }

    /// Set the maximum number of times this approval can be used.
    pub fn max_uses(mut self, n: u32) -> Self {
        self.max_uses = Some(n);
        self
    }

    /// Anchor the bundle to a drand round for cryptographic timestamping.
    pub fn drand_round(mut self, round: u64) -> Self {
        self.drand_round = Some(round);
        self
    }

    /// Bind the bundle to a specific VM attestation hash.
    pub fn attestation_hash(mut self, hash: impl Into<String>) -> Self {
        self.attestation_hash = Some(hash.into());
        self
    }

    /// Set a human-readable reason for the approval.
    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    /// Build and sign the approval bundle.
    ///
    /// Returns a JWS compact serialization string (`header.payload.signature`).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `manifest_hash` was not set
    /// - No operations were approved
    /// - The private key is invalid
    /// - Signing fails
    pub fn build(self, private_key_pkcs8_der: &[u8]) -> Result<String> {
        if self.manifest_hash.is_empty() {
            return Err(Error::Internal(
                "manifest_hash is required for approval bundle".to_string(),
            ));
        }
        if self.operations.is_empty() {
            return Err(Error::Internal(
                "at least one operation must be approved".to_string(),
            ));
        }

        let rng = SystemRandom::new();

        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            private_key_pkcs8_der,
            &rng,
        )
        .map_err(|e| Error::Internal(format!("failed to parse PKCS#8 key: {e}")))?;

        // Extract public key as JWK for the header
        let pub_bytes = key_pair.public_key().as_ref();
        let x = URL_SAFE_NO_PAD.encode(&pub_bytes[1..33]);
        let y = URL_SAFE_NO_PAD.encode(&pub_bytes[33..65]);
        let jwk = JsonWebKey::ec_p256(&x, &y);

        let header = ApprovalBundleHeader {
            typ: "approval+jwt".to_string(),
            alg: "ES256".to_string(),
            jwk,
        };

        let now = Utc::now().timestamp();
        let claims = ApprovalBundleClaims {
            jti: generate_jti(),
            iss: self.approver_spiffe_id,
            iat: now,
            exp: now + self.ttl_seconds as i64,
            manifest_hash: self.manifest_hash,
            approved_operations: self.operations,
            max_uses: self.max_uses,
            drand_round: self.drand_round,
            attestation_hash: self.attestation_hash,
            reason: self.reason,
        };

        let header_json = serde_json::to_string(&header)
            .map_err(|e| Error::Internal(format!("failed to serialize header: {e}")))?;
        let claims_json = serde_json::to_string(&claims)
            .map_err(|e| Error::Internal(format!("failed to serialize claims: {e}")))?;

        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_b64 = URL_SAFE_NO_PAD.encode(claims_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = key_pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|e| Error::Internal(format!("approval bundle signing failed: {e}")))?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

        Ok(format!("{signing_input}.{sig_b64}"))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// VERIFIER
// ═══════════════════════════════════════════════════════════════════════════

/// Verifier for signed approval bundles.
///
/// Validates:
/// 1. JWS structure and `"approval+jwt"` type header
/// 2. ES256 signature against the embedded JWK
/// 3. Embedded JWK matches expected public key
/// 4. Bundle has not expired
/// 5. Bundle was not issued in the future (with clock skew tolerance)
/// 6. Manifest hash matches the expected value
///
/// JTI deduplication (replay prevention) is the caller's responsibility;
/// the verifier validates structure and crypto only.
pub struct ApprovalBundleVerifier {
    max_clock_skew_secs: i64,
}

impl ApprovalBundleVerifier {
    /// Create a new verifier with default settings (60s clock skew tolerance).
    pub fn new() -> Self {
        Self {
            max_clock_skew_secs: DEFAULT_MAX_CLOCK_SKEW_SECS,
        }
    }

    /// Set the maximum allowed clock skew in seconds.
    pub fn with_max_clock_skew(mut self, skew_secs: i64) -> Self {
        self.max_clock_skew_secs = skew_secs;
        self
    }

    /// Verify an approval bundle's signature, expiry, and manifest binding.
    ///
    /// # Arguments
    ///
    /// * `jws` — The JWS compact serialization of the approval bundle
    /// * `expected_key` — The approver's public key (from DID document or SVID)
    /// * `expected_manifest_hash` — SHA-256 hex of the PodSpec being executed
    ///
    /// # Returns
    ///
    /// The verified `ApprovalBundleClaims` on success.
    pub fn verify(
        &self,
        jws: &str,
        expected_key: &JsonWebKey,
        expected_manifest_hash: &str,
    ) -> Result<ApprovalBundleClaims> {
        // Split JWS into parts
        let parts: Vec<&str> = jws.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(Error::VerificationFailed(
                "approval bundle must have 3 dot-separated parts".into(),
            ));
        }

        let (header_b64, payload_b64, sig_b64) = (parts[0], parts[1], parts[2]);

        // Decode and validate header
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| Error::VerificationFailed(format!("invalid header encoding: {e}")))?;
        let header: ApprovalBundleHeader = serde_json::from_slice(&header_bytes).map_err(|e| {
            Error::VerificationFailed(format!("invalid approval bundle header: {e}"))
        })?;

        // Verify header type
        if header.typ != "approval+jwt" {
            return Err(Error::VerificationFailed(format!(
                "expected typ \"approval+jwt\", got \"{}\"",
                header.typ
            )));
        }
        if header.alg != "ES256" {
            return Err(Error::VerificationFailed(format!(
                "expected alg \"ES256\", got \"{}\"",
                header.alg
            )));
        }

        // Verify embedded JWK matches expected key
        if header.jwk.x != expected_key.x || header.jwk.y != expected_key.y {
            return Err(Error::VerificationFailed(
                "approval bundle JWK does not match expected approver key".into(),
            ));
        }

        // Verify signature
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64)
            .map_err(|e| Error::VerificationFailed(format!("invalid signature encoding: {e}")))?;

        let x_bytes = URL_SAFE_NO_PAD
            .decode(&header.jwk.x)
            .map_err(|e| Error::VerificationFailed(format!("invalid JWK x: {e}")))?;
        let y_str = header.jwk.y.as_deref().ok_or_else(|| {
            Error::VerificationFailed("approval bundle JWK missing y coordinate".into())
        })?;
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
            .map_err(|_| {
                Error::VerificationFailed("approval bundle signature verification failed".into())
            })?;

        // Decode claims
        let claims_bytes = URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| Error::VerificationFailed(format!("invalid payload encoding: {e}")))?;
        let claims: ApprovalBundleClaims = serde_json::from_slice(&claims_bytes).map_err(|e| {
            Error::VerificationFailed(format!("invalid approval bundle claims: {e}"))
        })?;

        // Verify time bounds
        let now = Utc::now().timestamp();

        if claims.iat > now + self.max_clock_skew_secs {
            return Err(Error::VerificationFailed(
                "approval bundle issued in the future".into(),
            ));
        }

        if claims.exp <= now - self.max_clock_skew_secs {
            return Err(Error::VerificationFailed(
                "approval bundle has expired".into(),
            ));
        }

        // Verify manifest hash
        if claims.manifest_hash != expected_manifest_hash {
            return Err(Error::VerificationFailed(format!(
                "manifest hash mismatch: bundle={}, expected={}",
                claims.manifest_hash, expected_manifest_hash
            )));
        }

        Ok(claims)
    }

    /// Verify an approval bundle and check that a specific operation is approved.
    pub fn verify_operation(
        &self,
        jws: &str,
        expected_key: &JsonWebKey,
        expected_manifest_hash: &str,
        operation: &str,
    ) -> Result<ApprovalBundleClaims> {
        let claims = self.verify(jws, expected_key, expected_manifest_hash)?;

        if !claims.approved_operations.contains(operation) {
            return Err(Error::VerificationFailed(format!(
                "operation \"{operation}\" not in approved set: {:?}",
                claims.approved_operations
            )));
        }

        Ok(claims)
    }
}

impl Default for ApprovalBundleVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/// Compute the SHA-256 manifest hash of serialized PodSpec bytes.
///
/// The caller is responsible for serializing the PodSpec to a canonical form
/// (e.g., deterministic JSON via `serde_json::to_vec`). The returned hex
/// string is suitable for use as the `manifest_hash` in approval claims.
pub fn compute_manifest_hash(pod_spec_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(pod_spec_bytes))
}

/// Convert a JWS approval bundle string to bytes suitable for
/// `SpiffeTraceLink.attestation`.
///
/// This bridges approval bundles and the escalation trace chain:
/// each trace link's `attestation` field can contain the JWS bytes
/// of the approval bundle that authorized the delegation.
pub fn bundle_to_attestation_bytes(jws: &str) -> Vec<u8> {
    jws.as_bytes().to_vec()
}

/// Extract a JWS approval bundle string from `SpiffeTraceLink.attestation` bytes.
///
/// Returns `None` if the bytes are not valid UTF-8 or don't have JWS structure.
pub fn attestation_bytes_to_bundle(attestation: &[u8]) -> Option<&str> {
    let s = std::str::from_utf8(attestation).ok()?;
    if s.splitn(4, '.').count() == 3 {
        Some(s)
    } else {
        None
    }
}

/// Generate a unique JTI (JWT ID) for replay prevention.
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

    /// Helper to extract JTI from a JWS compact serialization.
    fn extract_jti(jws: &str) -> String {
        let payload_b64 = jws.split('.').nth(1).unwrap();
        let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).unwrap();
        let claims: ApprovalBundleClaims = serde_json::from_slice(&payload_bytes).unwrap();
        claims.jti
    }

    #[test]
    fn approval_bundle_roundtrip() {
        let (key, jwk) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"test pod spec YAML");

        let jws = ApprovalBundleBuilder::new("spiffe://nucleus.local/human/alice")
            .approve_operation("write_files")
            .approve_operation("run_bash")
            .manifest_hash(&manifest_hash)
            .ttl_seconds(3600)
            .build(&key)
            .unwrap();

        let verifier = ApprovalBundleVerifier::new();
        let claims = verifier.verify(&jws, &jwk, &manifest_hash).unwrap();

        assert_eq!(claims.iss, "spiffe://nucleus.local/human/alice");
        assert!(claims.approved_operations.contains("write_files"));
        assert!(claims.approved_operations.contains("run_bash"));
        assert_eq!(claims.approved_operations.len(), 2);
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn approval_bundle_rejects_wrong_key() {
        let (key, _) = make_test_key();
        let (_, wrong_jwk) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"spec");

        let jws = ApprovalBundleBuilder::new("spiffe://test/approver")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .build(&key)
            .unwrap();

        let verifier = ApprovalBundleVerifier::new();
        let result = verifier.verify(&jws, &wrong_jwk, &manifest_hash);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not match"));
    }

    #[test]
    fn approval_bundle_rejects_wrong_manifest() {
        let (key, jwk) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"correct spec");

        let jws = ApprovalBundleBuilder::new("spiffe://test/approver")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .build(&key)
            .unwrap();

        let wrong_hash = compute_manifest_hash(b"different spec");
        let verifier = ApprovalBundleVerifier::new();
        let result = verifier.verify(&jws, &jwk, &wrong_hash);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("manifest hash mismatch"));
    }

    #[test]
    fn approval_bundle_rejects_expired() {
        let (key, jwk) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"spec");

        let jws = ApprovalBundleBuilder::new("spiffe://test/approver")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .ttl_seconds(0)
            .build(&key)
            .unwrap();

        // Verify with zero clock skew so TTL=0 is immediately expired
        let verifier = ApprovalBundleVerifier::new().with_max_clock_skew(0);
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let result = verifier.verify(&jws, &jwk, &manifest_hash);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn approval_bundle_rejects_tampered_payload() {
        let (key, jwk) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"spec");

        let jws = ApprovalBundleBuilder::new("spiffe://test/approver")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .build(&key)
            .unwrap();

        let parts: Vec<&str> = jws.splitn(3, '.').collect();
        let tampered = format!("{}.{}.{}", parts[0], "dGFtcGVyZWQ", parts[2]);

        let verifier = ApprovalBundleVerifier::new();
        let result = verifier.verify(&tampered, &jwk, &manifest_hash);
        assert!(result.is_err());
    }

    #[test]
    fn approval_bundle_rejects_malformed_jws() {
        let (_, jwk) = make_test_key();
        let verifier = ApprovalBundleVerifier::new();

        assert!(verifier.verify("only.two", &jwk, "hash").is_err());
        assert!(verifier.verify("", &jwk, "hash").is_err());
    }

    #[test]
    fn approval_bundle_requires_manifest_hash() {
        let (key, _) = make_test_key();

        let result = ApprovalBundleBuilder::new("spiffe://test/approver")
            .approve_operation("read_files")
            .build(&key);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("manifest_hash"));
    }

    #[test]
    fn approval_bundle_requires_operations() {
        let (key, _) = make_test_key();

        let result = ApprovalBundleBuilder::new("spiffe://test/approver")
            .manifest_hash("abc123")
            .build(&key);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least one operation"));
    }

    #[test]
    fn approval_bundle_unique_jti() {
        let (key, _) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"spec");

        let jws1 = ApprovalBundleBuilder::new("spiffe://test/a")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .build(&key)
            .unwrap();

        let jws2 = ApprovalBundleBuilder::new("spiffe://test/a")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .build(&key)
            .unwrap();

        assert_ne!(extract_jti(&jws1), extract_jti(&jws2));
    }

    #[test]
    fn approval_bundle_with_optional_fields() {
        let (key, jwk) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"spec");
        let att_hash = hex::encode(Sha256::digest(b"combined hash"));

        let jws = ApprovalBundleBuilder::new("spiffe://test/approver")
            .approve_operation("write_files")
            .manifest_hash(&manifest_hash)
            .drand_round(54321)
            .attestation_hash(&att_hash)
            .max_uses(5)
            .reason("emergency fix")
            .build(&key)
            .unwrap();

        let verifier = ApprovalBundleVerifier::new();
        let claims = verifier.verify(&jws, &jwk, &manifest_hash).unwrap();
        assert_eq!(claims.drand_round, Some(54321));
        assert_eq!(claims.attestation_hash.as_deref(), Some(att_hash.as_str()));
        assert_eq!(claims.max_uses, Some(5));
        assert_eq!(claims.reason.as_deref(), Some("emergency fix"));
    }

    #[test]
    fn approval_bundle_verify_operation() {
        let (key, jwk) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"spec");

        let jws = ApprovalBundleBuilder::new("spiffe://test/approver")
            .approve_operation("write_files")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .build(&key)
            .unwrap();

        let verifier = ApprovalBundleVerifier::new();

        // Approved operation succeeds
        verifier
            .verify_operation(&jws, &jwk, &manifest_hash, "write_files")
            .unwrap();

        // Unapproved operation fails
        let result = verifier.verify_operation(&jws, &jwk, &manifest_hash, "git_push");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("not in approved set"));
    }

    #[test]
    fn approval_bundle_attestation_roundtrip() {
        let (key, jwk) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"spec");

        let jws = ApprovalBundleBuilder::new("spiffe://test/approver")
            .approve_operation("write_files")
            .manifest_hash(&manifest_hash)
            .build(&key)
            .unwrap();

        let attestation = bundle_to_attestation_bytes(&jws);
        let recovered = attestation_bytes_to_bundle(&attestation).unwrap();

        let verifier = ApprovalBundleVerifier::new();
        let claims = verifier.verify(recovered, &jwk, &manifest_hash).unwrap();
        assert!(claims.approved_operations.contains("write_files"));
    }

    #[test]
    fn approval_bundle_header_is_approval_jwt() {
        let (key, _) = make_test_key();
        let manifest_hash = compute_manifest_hash(b"spec");

        let jws = ApprovalBundleBuilder::new("spiffe://test/approver")
            .approve_operation("read_files")
            .manifest_hash(&manifest_hash)
            .build(&key)
            .unwrap();

        let header_b64 = jws.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header: ApprovalBundleHeader = serde_json::from_slice(&header_bytes).unwrap();

        assert_eq!(header.typ, "approval+jwt");
        assert_eq!(header.alg, "ES256");
        assert_eq!(header.jwk.kty, "EC");
        assert_eq!(header.jwk.crv, "P-256");
    }

    #[test]
    fn approval_bundle_claims_serde_roundtrip() {
        let mut ops = BTreeSet::new();
        ops.insert("write_files".to_string());
        ops.insert("run_bash".to_string());

        let claims = ApprovalBundleClaims {
            jti: "test-jti".into(),
            iss: "spiffe://test/approver".into(),
            iat: 1_700_000_000,
            exp: 1_700_003_600,
            manifest_hash: "abcdef1234567890".into(),
            approved_operations: ops,
            max_uses: Some(5),
            drand_round: Some(12345),
            attestation_hash: None,
            reason: Some("emergency fix".into()),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let parsed: ApprovalBundleClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, claims);
    }

    #[test]
    fn approval_bundle_claims_skips_optional_fields() {
        let mut ops = BTreeSet::new();
        ops.insert("read_files".to_string());

        let claims = ApprovalBundleClaims {
            jti: "test".into(),
            iss: "spiffe://test/x".into(),
            iat: 1_700_000_000,
            exp: 1_700_003_600,
            manifest_hash: "hash".into(),
            approved_operations: ops,
            max_uses: None,
            drand_round: None,
            attestation_hash: None,
            reason: None,
        };

        let json = serde_json::to_string(&claims).unwrap();
        assert!(!json.contains("max_uses"));
        assert!(!json.contains("drand_round"));
        assert!(!json.contains("attestation_hash"));
        assert!(!json.contains("reason"));
    }

    #[test]
    fn attestation_bytes_rejects_non_jws() {
        assert!(attestation_bytes_to_bundle(b"not a jws").is_none());
        assert!(attestation_bytes_to_bundle(b"only.two").is_none());
        assert!(attestation_bytes_to_bundle(b"too.many.dots.here").is_none());
        assert!(attestation_bytes_to_bundle(&[0xFF, 0xFE]).is_none()); // invalid UTF-8
    }

    #[test]
    fn compute_manifest_hash_deterministic() {
        let h1 = compute_manifest_hash(b"pod spec data");
        let h2 = compute_manifest_hash(b"pod spec data");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }
}
