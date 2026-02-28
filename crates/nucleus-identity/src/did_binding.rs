//! SPIFFE-DID binding proof types.
//!
//! This module defines the cryptographic binding between a SPIFFE workload
//! identity (X.509 SVID) and a did:web identity. The binding is bidirectional:
//!
//! - The SVID private key signs the DID string (proves the workload claims this DID)
//! - The DID signing key signs the SPIFFE ID string (proves the DID claims this workload)
//!
//! The binding document is served at `/.well-known/spiffe-did-binding.json`
//! alongside the DID document at `/.well-known/did.json`.
//!
//! # Verification Levels
//!
//! ```text
//! FullyVerified      — Both cross-signatures valid AND SVID chain verified
//!                      against SPIFFE trust bundle (requires same trust domain
//!                      or SPIFFE Federation)
//!
//! PartiallyVerified  — DID-side signature valid, but no SPIFFE trust bundle
//!                      available. Trust based on DNS/TLS + DID self-signature.
//!
//! Failed             — Signature verification or chain validation failed.
//! ```
//!
//! # Example
//!
//! ```
//! use nucleus_identity::did_binding::{SpiffeDidBinding, BindingProof};
//! use chrono::Utc;
//!
//! let binding = SpiffeDidBinding {
//!     did: "did:web:music-app.groundtruth.dev".into(),
//!     spiffe_id: "spiffe://groundtruth.dev/ns/apps/sa/music-app".into(),
//!     binding_proof: BindingProof {
//!         proof_type: "SpiffeDidBinding".into(),
//!         created: Utc::now(),
//!         expires: Utc::now() + chrono::Duration::hours(1),
//!         svid_fingerprint: "SHA256:xK3d8jF...".into(),
//!         did_key_id: "did:web:music-app.groundtruth.dev#app-signing-key-1".into(),
//!         attestation_chain: vec!["<base64url leaf cert>".into()],
//!         signature_over_did_by_svid: "<JWS>".into(),
//!         signature_over_svid_by_did: "<JWS>".into(),
//!     },
//! };
//!
//! assert_eq!(binding.did, "did:web:music-app.groundtruth.dev");
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════════════
// BINDING DOCUMENT
// ═══════════════════════════════════════════════════════════════════════════

/// The binding proof document served at `/.well-known/spiffe-did-binding.json`.
///
/// Proves bidirectional ownership: the SPIFFE workload claims the DID,
/// and the DID controller claims the SPIFFE identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpiffeDidBinding {
    /// The `did:web` identifier.
    pub did: String,

    /// The SPIFFE ID (e.g., `"spiffe://groundtruth.dev/ns/apps/sa/music-app"`).
    pub spiffe_id: String,

    /// The cryptographic binding proof.
    pub binding_proof: BindingProof,
}

impl SpiffeDidBinding {
    /// Check whether this binding has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.binding_proof.expires
    }

    /// Check whether this binding expires within the given duration.
    pub fn expires_within(&self, duration: chrono::Duration) -> bool {
        Utc::now() + duration > self.binding_proof.expires
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// BINDING PROOF
// ═══════════════════════════════════════════════════════════════════════════

/// Cryptographic proof binding SPIFFE and DID identities.
///
/// Contains two cross-signatures:
/// - `signature_over_did_by_svid`: SVID private key signs the DID string
/// - `signature_over_svid_by_did`: DID signing key signs the SPIFFE ID string
///
/// And the SVID certificate chain for verifiers who have the SPIFFE trust bundle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BindingProof {
    /// Proof type identifier (always `"SpiffeDidBinding"`).
    #[serde(rename = "type")]
    pub proof_type: String,

    /// When this binding was created.
    pub created: DateTime<Utc>,

    /// When this binding expires (should be <= SVID expiry).
    pub expires: DateTime<Utc>,

    /// SHA-256 fingerprint of the current SVID leaf certificate.
    pub svid_fingerprint: String,

    /// The DID verification method key ID used for the DID-side signature.
    pub did_key_id: String,

    /// X.509 certificate chain from the SVID (base64url-encoded DER).
    /// Leaf first, intermediates follow, root last.
    pub attestation_chain: Vec<String>,

    /// JWS: SVID private key signs the DID identifier string.
    /// Proves the SPIFFE workload claims this DID.
    pub signature_over_did_by_svid: String,

    /// JWS: DID signing key signs the SPIFFE ID string.
    /// Proves the DID controller claims this SPIFFE identity.
    pub signature_over_svid_by_did: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// VERIFICATION RESULT
// ═══════════════════════════════════════════════════════════════════════════

/// Result of verifying a SPIFFE-DID binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingVerification {
    /// Both cross-signatures valid and SVID chain rooted in trust bundle.
    FullyVerified {
        did: String,
        spiffe_id: String,
        svid_expiry: DateTime<Utc>,
    },

    /// DID-side signature valid, but no SPIFFE trust bundle available.
    /// Trust is based on DNS/TLS + DID self-signature only.
    PartiallyVerified {
        did: String,
        spiffe_id: String,
        reason: String,
    },

    /// Verification failed.
    Failed { reason: String },
}

impl BindingVerification {
    /// Whether the verification succeeded (fully or partially).
    pub fn is_verified(&self) -> bool {
        !matches!(self, Self::Failed { .. })
    }

    /// Whether the verification is fully verified (SPIFFE chain validated).
    pub fn is_fully_verified(&self) -> bool {
        matches!(self, Self::FullyVerified { .. })
    }

    /// Extract the DID if verification succeeded.
    pub fn did(&self) -> Option<&str> {
        match self {
            Self::FullyVerified { did, .. } | Self::PartiallyVerified { did, .. } => Some(did),
            Self::Failed { .. } => None,
        }
    }

    /// Extract the SPIFFE ID if verification succeeded.
    pub fn spiffe_id(&self) -> Option<&str> {
        match self {
            Self::FullyVerified { spiffe_id, .. } | Self::PartiallyVerified { spiffe_id, .. } => {
                Some(spiffe_id)
            }
            Self::Failed { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_binding() -> SpiffeDidBinding {
        SpiffeDidBinding {
            did: "did:web:music-app.groundtruth.dev".into(),
            spiffe_id: "spiffe://groundtruth.dev/ns/apps/sa/music-app".into(),
            binding_proof: BindingProof {
                proof_type: "SpiffeDidBinding".into(),
                created: Utc::now(),
                expires: Utc::now() + chrono::Duration::hours(1),
                svid_fingerprint: "SHA256:xK3d8jFaBcDeFgHiJkLmNoPqRsT".into(),
                did_key_id: "did:web:music-app.groundtruth.dev#app-signing-key-1".into(),
                attestation_chain: vec![
                    "MIIB_base64url_leaf_cert".into(),
                    "MIIC_base64url_intermediate".into(),
                ],
                signature_over_did_by_svid: "eyJhbGciOiJFUzI1NiJ9.svid_sig".into(),
                signature_over_svid_by_did: "eyJhbGciOiJFUzI1NiJ9.did_sig".into(),
            },
        }
    }

    #[test]
    fn binding_serde_roundtrip() {
        let binding = sample_binding();
        let json = serde_json::to_string_pretty(&binding).unwrap();
        let parsed: SpiffeDidBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.did, binding.did);
        assert_eq!(parsed.spiffe_id, binding.spiffe_id);
        assert_eq!(
            parsed.binding_proof.svid_fingerprint,
            binding.binding_proof.svid_fingerprint
        );
        assert_eq!(
            parsed.binding_proof.attestation_chain.len(),
            binding.binding_proof.attestation_chain.len()
        );
    }

    #[test]
    fn binding_json_field_names() {
        let binding = sample_binding();
        let json = serde_json::to_string(&binding).unwrap();
        assert!(json.contains("\"type\""));
        assert!(json.contains("\"SpiffeDidBinding\""));
        assert!(json.contains("\"svid_fingerprint\""));
        assert!(json.contains("\"attestation_chain\""));
        assert!(json.contains("\"signature_over_did_by_svid\""));
        assert!(json.contains("\"signature_over_svid_by_did\""));
    }

    #[test]
    fn binding_not_expired() {
        let binding = sample_binding();
        assert!(!binding.is_expired());
    }

    #[test]
    fn binding_expired() {
        let mut binding = sample_binding();
        binding.binding_proof.expires = Utc::now() - chrono::Duration::hours(1);
        assert!(binding.is_expired());
    }

    #[test]
    fn binding_expires_within() {
        let binding = sample_binding();
        // Expires in 1 hour — should be true for 2-hour window
        assert!(binding.expires_within(chrono::Duration::hours(2)));
        // Should be false for 30-minute window
        assert!(!binding.expires_within(chrono::Duration::minutes(30)));
    }

    #[test]
    fn verification_fully_verified() {
        let v = BindingVerification::FullyVerified {
            did: "did:web:app.dev".into(),
            spiffe_id: "spiffe://dev/ns/x/sa/app".into(),
            svid_expiry: Utc::now() + chrono::Duration::hours(1),
        };
        assert!(v.is_verified());
        assert!(v.is_fully_verified());
        assert_eq!(v.did(), Some("did:web:app.dev"));
        assert_eq!(v.spiffe_id(), Some("spiffe://dev/ns/x/sa/app"));
    }

    #[test]
    fn verification_partially_verified() {
        let v = BindingVerification::PartiallyVerified {
            did: "did:web:app.dev".into(),
            spiffe_id: "spiffe://dev/ns/x/sa/app".into(),
            reason: "no trust bundle".into(),
        };
        assert!(v.is_verified());
        assert!(!v.is_fully_verified());
        assert_eq!(v.did(), Some("did:web:app.dev"));
    }

    #[test]
    fn verification_failed() {
        let v = BindingVerification::Failed {
            reason: "signature invalid".into(),
        };
        assert!(!v.is_verified());
        assert!(!v.is_fully_verified());
        assert_eq!(v.did(), None);
        assert_eq!(v.spiffe_id(), None);
    }
}
