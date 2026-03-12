//! Attenuation tokens — compact, presentable delegation credentials.
//!
//! An [`AttenuationToken`] is a compact binary encoding of a
//! [`LatticeCertificate`] suitable for wire transport between processes.
//! It bundles the certificate with its root public key, allowing
//! the recipient to verify the delegation chain and create a
//! [`Kernel`] session from the verified permissions.
//!
//! # Lifecycle
//!
//! ```text
//! mint() ──► delegate() ──► AttenuationToken::seal() ──► wire ──► verify() ──► Kernel
//! ```
//!
//! 1. **Mint**: Root authority creates a [`LatticeCertificate`] with root permissions.
//! 2. **Delegate**: Each hop attenuates via `certificate.delegate()`.
//! 3. **Seal**: The holder packages the certificate into an [`AttenuationToken`].
//! 4. **Transport**: The token is sent as compact bytes (base64 over wire).
//! 5. **Verify**: The recipient calls [`AttenuationToken::verify`] to get
//!    [`VerifiedPermissions`], which can only be produced by cryptographic
//!    verification.
//! 6. **Enforce**: The recipient creates a [`Kernel`] from the verified
//!    permissions, binding the session to the delegation chain.
//!
//! # Security Properties
//!
//! - **Compact**: Binary encoding is smaller than JSON for wire transport.
//! - **Self-contained**: The token carries the root public key, so verification
//!   requires only the token itself and trust in the root key.
//! - **Unforgeable**: Ed25519 signatures prevent fabrication.
//! - **Auditable**: The [`SessionProvenance`] recorded in the kernel links
//!   every decision back to the delegation chain.
//!
//! # Example
//!
//! ```rust
//! use portcullis::token::AttenuationToken;
//! use portcullis::certificate::LatticeCertificate;
//! use portcullis::PermissionLattice;
//! use ring::signature::KeyPair;
//! use chrono::{Utc, Duration};
//!
//! let rng = ring::rand::SystemRandom::new();
//! let root_pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
//! let root_key = ring::signature::Ed25519KeyPair::from_pkcs8(root_pkcs8.as_ref()).unwrap();
//! let root_pub = root_key.public_key().as_ref().to_vec();
//! let not_after = Utc::now() + Duration::hours(8);
//!
//! // Mint and delegate
//! let (cert, holder_key) = LatticeCertificate::mint(
//!     PermissionLattice::permissive(),
//!     "spiffe://nucleus.local/human/alice".into(),
//!     not_after,
//!     &root_key,
//!     &rng,
//! );
//! let (cert, _) = cert.delegate(
//!     &PermissionLattice::restrictive(),
//!     "spiffe://nucleus.local/agent/coder".into(),
//!     not_after,
//!     &holder_key,
//!     &rng,
//! ).unwrap();
//!
//! // Seal into a compact token
//! let token = AttenuationToken::seal(cert, root_pub.clone());
//!
//! // Transport as bytes
//! let wire_bytes = token.to_bytes().unwrap();
//!
//! // Recipient verifies and creates kernel
//! let restored = AttenuationToken::from_bytes(&wire_bytes).unwrap();
//! let verified = restored.verify(Utc::now(), 10).unwrap();
//! assert_eq!(verified.chain_depth, 1);
//! ```

use chrono::{DateTime, Utc};

#[cfg(feature = "serde")]
use base64::Engine;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::certificate::{
    verify_certificate, CertificateError, LatticeCertificate, VerifiedPermissions,
    DEFAULT_MAX_CHAIN_DEPTH,
};

/// A compact, self-contained attenuation token for wire transport.
///
/// Bundles a [`LatticeCertificate`] with its root public key, enabling
/// offline verification by any recipient who trusts the root authority.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AttenuationToken {
    /// The delegation certificate chain.
    certificate: LatticeCertificate,
    /// Ed25519 public key of the root authority (32 bytes).
    root_public_key: Vec<u8>,
    /// Token format version for forward compatibility.
    version: u8,
}

/// Errors during token operations.
#[derive(Debug, Clone)]
pub enum TokenError {
    /// Certificate verification failed.
    VerificationFailed(CertificateError),
    /// Token deserialization failed.
    DeserializationFailed(String),
    /// Token serialization failed.
    SerializationFailed(String),
    /// Root public key length is invalid (must be 32 bytes for Ed25519).
    InvalidRootKeyLength {
        /// Actual length.
        actual: usize,
    },
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VerificationFailed(e) => write!(f, "token verification failed: {}", e),
            Self::DeserializationFailed(e) => write!(f, "token deserialization failed: {}", e),
            Self::SerializationFailed(e) => write!(f, "token serialization failed: {}", e),
            Self::InvalidRootKeyLength { actual } => {
                write!(
                    f,
                    "invalid root key length: expected 32 bytes, got {}",
                    actual
                )
            }
        }
    }
}

impl std::error::Error for TokenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::VerificationFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl From<CertificateError> for TokenError {
    fn from(e: CertificateError) -> Self {
        Self::VerificationFailed(e)
    }
}

/// Current token format version.
const TOKEN_VERSION: u8 = 1;

impl AttenuationToken {
    /// Seal a certificate and root public key into an attenuation token.
    ///
    /// # Panics
    ///
    /// Panics if `root_public_key` is not 32 bytes (Ed25519 public key size).
    pub fn seal(certificate: LatticeCertificate, root_public_key: Vec<u8>) -> Self {
        assert_eq!(
            root_public_key.len(),
            32,
            "Ed25519 public key must be 32 bytes"
        );
        Self {
            certificate,
            root_public_key,
            version: TOKEN_VERSION,
        }
    }

    /// Try to seal a certificate with validation.
    ///
    /// Returns an error if the root public key length is invalid.
    pub fn try_seal(
        certificate: LatticeCertificate,
        root_public_key: Vec<u8>,
    ) -> Result<Self, TokenError> {
        if root_public_key.len() != 32 {
            return Err(TokenError::InvalidRootKeyLength {
                actual: root_public_key.len(),
            });
        }
        Ok(Self {
            certificate,
            root_public_key,
            version: TOKEN_VERSION,
        })
    }

    /// Verify the token's certificate chain and return sealed [`VerifiedPermissions`].
    ///
    /// This performs full cryptographic verification:
    /// 1. Chain depth check
    /// 2. Ed25519 signature verification at each hop
    /// 3. SHA-256 hash chain integrity
    /// 4. Monotone attenuation (permissions only decrease)
    /// 5. Time expiry checks
    /// 6. Proof-of-possession
    pub fn verify(
        &self,
        now: DateTime<Utc>,
        max_chain_depth: usize,
    ) -> Result<VerifiedPermissions, TokenError> {
        verify_certificate(
            &self.certificate,
            &self.root_public_key,
            now,
            max_chain_depth,
        )
        .map_err(TokenError::VerificationFailed)
    }

    /// Verify with default max chain depth.
    pub fn verify_default(&self, now: DateTime<Utc>) -> Result<VerifiedPermissions, TokenError> {
        self.verify(now, DEFAULT_MAX_CHAIN_DEPTH)
    }

    /// Get the certificate fingerprint (SHA-256).
    pub fn fingerprint(&self) -> [u8; 32] {
        self.certificate.fingerprint()
    }

    /// Get the root public key.
    pub fn root_public_key(&self) -> &[u8] {
        &self.root_public_key
    }

    /// Get a reference to the inner certificate.
    pub fn certificate(&self) -> &LatticeCertificate {
        &self.certificate
    }

    /// Get the chain depth.
    pub fn chain_depth(&self) -> usize {
        self.certificate.chain_depth()
    }

    /// Get the root identity.
    pub fn root_identity(&self) -> &str {
        self.certificate.root_identity()
    }

    /// Get the leaf identity.
    pub fn leaf_identity(&self) -> &str {
        self.certificate.leaf_identity()
    }

    /// Get the token format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Serialize to compact bytes (JSON + optional future binary format).
    #[cfg(feature = "serde")]
    pub fn to_bytes(&self) -> Result<Vec<u8>, TokenError> {
        serde_json::to_vec(self).map_err(|e| TokenError::SerializationFailed(e.to_string()))
    }

    /// Deserialize from bytes.
    #[cfg(feature = "serde")]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TokenError> {
        serde_json::from_slice(bytes).map_err(|e| TokenError::DeserializationFailed(e.to_string()))
    }

    /// Encode to a base64 string for text-based transport (HTTP headers, env vars).
    #[cfg(feature = "serde")]
    pub fn to_base64(&self) -> Result<String, TokenError> {
        let bytes = self.to_bytes()?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
    }

    /// Decode from a base64 string.
    #[cfg(feature = "serde")]
    pub fn from_base64(encoded: &str) -> Result<Self, TokenError> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e: base64::DecodeError| TokenError::DeserializationFailed(e.to_string()))?;
        Self::from_bytes(&bytes)
    }
}

/// Provenance information linking a kernel session to its delegation chain.
///
/// This is recorded when a [`Kernel`] is created from a verified certificate,
/// providing an auditable link from every decision back to the root authority.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SessionProvenance {
    /// SHA-256 fingerprint of the certificate that authorized this session.
    pub certificate_fingerprint: [u8; 32],
    /// Identity of the root authority (e.g., SPIFFE ID).
    pub root_identity: String,
    /// Identity of the session holder (leaf of the delegation chain).
    pub leaf_identity: String,
    /// Number of delegation hops from root to leaf.
    pub chain_depth: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PermissionLattice;
    use chrono::Duration;
    use ring::rand::SecureRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn test_rng() -> ring::rand::SystemRandom {
        ring::rand::SystemRandom::new()
    }

    fn generate_key(rng: &dyn SecureRandom) -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn mint_and_delegate(
        rng: &ring::rand::SystemRandom,
    ) -> (LatticeCertificate, Vec<u8>, Ed25519KeyPair) {
        let root_key = generate_key(rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            rng,
        );

        let (cert, delegatee_key) = cert
            .delegate(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent/coder-042".into(),
                not_after,
                &holder_key,
                rng,
            )
            .unwrap();

        (cert, root_pub, delegatee_key)
    }

    #[test]
    fn test_seal_and_verify() {
        let rng = test_rng();
        let (cert, root_pub, _) = mint_and_delegate(&rng);

        let token = AttenuationToken::seal(cert, root_pub);
        let verified = token.verify(Utc::now(), 10).unwrap();

        assert_eq!(verified.chain_depth, 1);
        assert_eq!(verified.root_identity, "spiffe://test/human/alice");
        assert_eq!(verified.leaf_identity, "spiffe://test/agent/coder-042");
    }

    #[test]
    fn test_try_seal_validates_key_length() {
        let rng = test_rng();
        let (cert, _, _) = mint_and_delegate(&rng);

        // Wrong length
        let result = AttenuationToken::try_seal(cert.clone(), vec![0u8; 16]);
        assert!(matches!(
            result,
            Err(TokenError::InvalidRootKeyLength { actual: 16 })
        ));

        // Correct length
        let result = AttenuationToken::try_seal(cert, vec![0u8; 32]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_wrong_root_key_fails_verification() {
        let rng = test_rng();
        let (cert, _, _) = mint_and_delegate(&rng);
        let wrong_key = generate_key(&rng);
        let wrong_pub = wrong_key.public_key().as_ref().to_vec();

        let token = AttenuationToken::seal(cert, wrong_pub);
        let result = token.verify(Utc::now(), 10);

        assert!(matches!(
            result,
            Err(TokenError::VerificationFailed(
                CertificateError::InvalidSignature { .. }
            ))
        ));
    }

    #[test]
    fn test_fingerprint_stable() {
        let rng = test_rng();
        let (cert, root_pub, _) = mint_and_delegate(&rng);

        let token = AttenuationToken::seal(cert, root_pub);
        let fp1 = token.fingerprint();
        let fp2 = token.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_accessors() {
        let rng = test_rng();
        let (cert, root_pub, _) = mint_and_delegate(&rng);

        let token = AttenuationToken::seal(cert, root_pub.clone());
        assert_eq!(token.chain_depth(), 1);
        assert_eq!(token.root_identity(), "spiffe://test/human/alice");
        assert_eq!(token.leaf_identity(), "spiffe://test/agent/coder-042");
        assert_eq!(token.root_public_key(), root_pub.as_slice());
        assert_eq!(token.version(), TOKEN_VERSION);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_bytes_roundtrip() {
        let rng = test_rng();
        let (cert, root_pub, _) = mint_and_delegate(&rng);

        let token = AttenuationToken::seal(cert, root_pub);
        let bytes = token.to_bytes().unwrap();
        let restored = AttenuationToken::from_bytes(&bytes).unwrap();

        let verified = restored.verify(Utc::now(), 10).unwrap();
        assert_eq!(verified.chain_depth, 1);
        assert_eq!(verified.root_identity, "spiffe://test/human/alice");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_base64_roundtrip() {
        let rng = test_rng();
        let (cert, root_pub, _) = mint_and_delegate(&rng);

        let token = AttenuationToken::seal(cert, root_pub);
        let encoded = token.to_base64().unwrap();
        let restored = AttenuationToken::from_base64(&encoded).unwrap();

        let verified = restored.verify(Utc::now(), 10).unwrap();
        assert_eq!(verified.chain_depth, 1);
    }

    #[test]
    fn test_provenance_from_verified() {
        let rng = test_rng();
        let (cert, root_pub, _) = mint_and_delegate(&rng);
        let fingerprint = cert.fingerprint();

        let token = AttenuationToken::seal(cert, root_pub);
        let verified = token.verify(Utc::now(), 10).unwrap();

        let provenance = SessionProvenance {
            certificate_fingerprint: fingerprint,
            root_identity: verified.root_identity.clone(),
            leaf_identity: verified.leaf_identity.clone(),
            chain_depth: verified.chain_depth,
        };

        assert_eq!(provenance.root_identity, "spiffe://test/human/alice");
        assert_eq!(provenance.leaf_identity, "spiffe://test/agent/coder-042");
        assert_eq!(provenance.chain_depth, 1);
    }

    #[test]
    fn test_expired_token_rejected() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();

        // Expired 1 hour ago
        let not_after = Utc::now() - Duration::hours(1);
        let (cert, _) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/root".into(),
            not_after,
            &root_key,
            &rng,
        );

        let token = AttenuationToken::seal(cert, root_pub);
        let result = token.verify(Utc::now(), 10);
        assert!(matches!(
            result,
            Err(TokenError::VerificationFailed(
                CertificateError::Expired { .. }
            ))
        ));
    }

    #[test]
    fn test_multi_hop_token() {
        let rng = test_rng();
        let root_key = generate_key(&rng);
        let root_pub = root_key.public_key().as_ref().to_vec();
        let not_after = Utc::now() + Duration::hours(8);

        let (cert, holder_key) = LatticeCertificate::mint(
            PermissionLattice::permissive(),
            "spiffe://test/human/alice".into(),
            not_after,
            &root_key,
            &rng,
        );

        // Alice → Orchestrator
        let (cert, orch_key) = cert
            .delegate(
                &PermissionLattice::permissive(),
                "spiffe://test/agent/orch".into(),
                not_after,
                &holder_key,
                &rng,
            )
            .unwrap();

        // Orchestrator → Coder
        let (cert, coder_key) = cert
            .delegate(
                &PermissionLattice::restrictive(),
                "spiffe://test/agent/coder".into(),
                not_after,
                &orch_key,
                &rng,
            )
            .unwrap();

        // Coder → TestRunner
        let (cert, _) = cert
            .delegate(
                &PermissionLattice::read_only(),
                "spiffe://test/agent/test".into(),
                not_after,
                &coder_key,
                &rng,
            )
            .unwrap();

        let root_perms = cert.authority().root_permissions.clone();
        let token = AttenuationToken::seal(cert, root_pub);
        let verified = token.verify(Utc::now(), 10).unwrap();

        assert_eq!(verified.chain_depth, 3);
        assert_eq!(verified.root_identity, "spiffe://test/human/alice");
        assert_eq!(verified.leaf_identity, "spiffe://test/agent/test");

        // Effective perms are ≤ root (monotone attenuation)
        assert!(verified.effective.leq(&root_perms));
    }
}
