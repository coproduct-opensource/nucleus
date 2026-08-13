//! Attestation verification for tool proxy requests.
//!
//! This module provides verification of SPIFFE certificates with embedded
//! launch attestation, ensuring that requests come from workloads running
//! in attested VM environments.
//!
//! # Attestation Flow
//!
//! 1. Client presents X.509 certificate with SPIFFE identity and attestation extension
//! 2. Tool proxy extracts attestation from custom OID (1.3.6.1.4.1.57212.1.1)
//! 3. Attestation hashes are compared against configured allowed values
//! 4. Request proceeds only if attestation matches requirements
//!
//! # Configuration
//!
//! Attestation requirements can be configured via:
//! - `--require-attestation`: Enable attestation verification
//! - `--allowed-kernel-hashes`: Comma-separated list of allowed kernel SHA-256 hashes
//! - `--allowed-rootfs-hashes`: Comma-separated list of allowed rootfs SHA-256 hashes
//!
//! If no allowed hashes are specified but attestation is required, any valid
//! attestation is accepted (useful for logging without enforcement).

use nucleus_identity::{AssuranceLevel, LaunchAttestation};
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// OID for Nucleus Launch Attestation extension: 1.3.6.1.4.1.57212.1.1
/// This OID is encoded in DER as: 06 0a 2b 06 01 04 01 83 be 5c 01 01
#[allow(dead_code)]
const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 57212, 1, 1];

/// Configuration for attestation verification.
#[derive(Clone, Debug, Default)]
pub struct AttestationConfig {
    /// Whether attestation is required for all requests.
    pub require_attestation: bool,
    /// Set of allowed kernel hashes (SHA-256, hex-encoded).
    /// Empty means any kernel hash is allowed.
    pub allowed_kernel_hashes: HashSet<String>,
    /// Set of allowed rootfs hashes (SHA-256, hex-encoded).
    /// Empty means any rootfs hash is allowed.
    pub allowed_rootfs_hashes: HashSet<String>,
    /// Set of allowed config hashes (SHA-256, hex-encoded).
    /// Empty means any config hash is allowed.
    pub allowed_config_hashes: HashSet<String>,
    /// Minimum normalized assurance level a request's SVID must carry (North Star
    /// C9). `L0Bearer` (the default) imposes no floor. A floor above `L0Bearer`
    /// makes attestation effectively required and refuses any SVID whose verified
    /// assurance is below it — fail-closed on absent/invalid evidence. Note a
    /// `L2Device`+ floor refuses every SVID until the EK-manufacturer root lands
    /// (residency alone is `L1Software`).
    pub min_assurance: AssuranceLevel,
}

impl AttestationConfig {
    /// Creates a new attestation config with attestation required.
    pub fn required() -> Self {
        Self {
            require_attestation: true,
            ..Default::default()
        }
    }

    /// Adds allowed kernel hashes from a comma-separated string.
    pub fn with_kernel_hashes(mut self, hashes: &str) -> Self {
        for hash in hashes.split(',') {
            let hash = hash.trim().to_lowercase();
            if !hash.is_empty() {
                self.allowed_kernel_hashes.insert(hash);
            }
        }
        self
    }

    /// Adds allowed rootfs hashes from a comma-separated string.
    pub fn with_rootfs_hashes(mut self, hashes: &str) -> Self {
        for hash in hashes.split(',') {
            let hash = hash.trim().to_lowercase();
            if !hash.is_empty() {
                self.allowed_rootfs_hashes.insert(hash);
            }
        }
        self
    }

    /// Adds allowed config hashes from a comma-separated string.
    pub fn with_config_hashes(mut self, hashes: &str) -> Self {
        for hash in hashes.split(',') {
            let hash = hash.trim().to_lowercase();
            if !hash.is_empty() {
                self.allowed_config_hashes.insert(hash);
            }
        }
        self
    }

    /// Sets the minimum assurance floor. A floor above `L0Bearer` also makes
    /// attestation required (a floor cannot be checked without a client cert).
    pub fn with_min_assurance(mut self, level: AssuranceLevel) -> Self {
        self.min_assurance = level;
        if level > AssuranceLevel::L0Bearer {
            self.require_attestation = true;
        }
        self
    }

    /// Checks if attestation verification is effectively enforcing.
    #[allow(dead_code)]
    pub fn is_enforcing(&self) -> bool {
        self.require_attestation
    }
}

/// Result of attestation verification.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AttestationResult {
    /// Whether attestation was present in the certificate.
    pub attestation_present: bool,
    /// The extracted attestation, if present.
    pub attestation: Option<AttestationInfo>,
    /// Whether the attestation matches requirements.
    pub matches_requirements: bool,
    /// Reason for rejection, if any.
    pub rejection_reason: Option<String>,
}

/// Extracted attestation information.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AttestationInfo {
    /// Kernel hash as hex string.
    pub kernel_hash: String,
    /// Rootfs hash as hex string.
    pub rootfs_hash: String,
    /// Config hash as hex string.
    pub config_hash: String,
    /// Timestamp when attestation was computed.
    pub timestamp: String,
}

impl From<&LaunchAttestation> for AttestationInfo {
    fn from(att: &LaunchAttestation) -> Self {
        Self {
            kernel_hash: hex::encode(att.kernel_hash()),
            rootfs_hash: hex::encode(att.rootfs_hash()),
            config_hash: hex::encode(att.config_hash()),
            timestamp: att.timestamp().to_rfc3339(),
        }
    }
}

/// Attestation verifier for tool proxy.
#[derive(Clone)]
pub struct AttestationVerifier {
    config: Arc<AttestationConfig>,
}

impl AttestationVerifier {
    /// Creates a new attestation verifier with the given config.
    pub fn new(config: AttestationConfig) -> Self {
        if config.require_attestation {
            let kernel_count = if config.allowed_kernel_hashes.is_empty() {
                "any".to_string()
            } else {
                config.allowed_kernel_hashes.len().to_string()
            };
            let rootfs_count = if config.allowed_rootfs_hashes.is_empty() {
                "any".to_string()
            } else {
                config.allowed_rootfs_hashes.len().to_string()
            };
            let config_count = if config.allowed_config_hashes.is_empty() {
                "any".to_string()
            } else {
                config.allowed_config_hashes.len().to_string()
            };
            info!(
                "attestation verification enabled: kernel_hashes={}, rootfs_hashes={}, config_hashes={}",
                kernel_count, rootfs_count, config_count,
            );
        }
        Self {
            config: Arc::new(config),
        }
    }

    /// Verifies attestation from a DER-encoded X.509 certificate.
    ///
    /// This extracts the attestation extension (if present) and validates
    /// it against the configured requirements.
    #[allow(dead_code)]
    pub fn verify_certificate(&self, cert_der: &[u8]) -> AttestationResult {
        // Try to extract attestation from certificate
        let attestation = match extract_attestation_from_cert(cert_der) {
            Ok(Some(att)) => att,
            Ok(None) => {
                if self.config.require_attestation {
                    return AttestationResult {
                        attestation_present: false,
                        attestation: None,
                        matches_requirements: false,
                        rejection_reason: Some("attestation required but not present".to_string()),
                    };
                }
                return AttestationResult {
                    attestation_present: false,
                    attestation: None,
                    matches_requirements: true,
                    rejection_reason: None,
                };
            }
            Err(e) => {
                warn!("failed to parse attestation extension: {}", e);
                return AttestationResult {
                    attestation_present: false,
                    attestation: None,
                    matches_requirements: !self.config.require_attestation,
                    rejection_reason: if self.config.require_attestation {
                        Some(format!("attestation parse error: {}", e))
                    } else {
                        None
                    },
                };
            }
        };

        let info = AttestationInfo::from(&attestation);
        debug!(
            "attestation present: kernel={}, rootfs={}, config={}",
            &info.kernel_hash[..16],
            &info.rootfs_hash[..16],
            &info.config_hash[..16]
        );

        // Validate against requirements
        let (matches, reason) = self.validate_attestation(&info);

        AttestationResult {
            attestation_present: true,
            attestation: Some(info),
            matches_requirements: matches,
            rejection_reason: reason,
        }
    }

    /// Verifies attestation from an attestation header value (base64-encoded DER).
    ///
    /// This is an alternative path when attestation is passed via HTTP header
    /// rather than embedded in a certificate.
    pub fn verify_header(&self, attestation_header: &str) -> AttestationResult {
        // Decode base64
        let der = match base64_decode(attestation_header) {
            Ok(der) => der,
            Err(e) => {
                return AttestationResult {
                    attestation_present: false,
                    attestation: None,
                    matches_requirements: !self.config.require_attestation,
                    rejection_reason: if self.config.require_attestation {
                        Some(format!("invalid attestation header encoding: {}", e))
                    } else {
                        None
                    },
                };
            }
        };

        // Parse attestation DER
        let attestation = match LaunchAttestation::from_der(&der) {
            Ok(att) => att,
            Err(e) => {
                return AttestationResult {
                    attestation_present: false,
                    attestation: None,
                    matches_requirements: !self.config.require_attestation,
                    rejection_reason: if self.config.require_attestation {
                        Some(format!("invalid attestation DER: {}", e))
                    } else {
                        None
                    },
                };
            }
        };

        let info = AttestationInfo::from(&attestation);
        debug!(
            "attestation from header: kernel={}, rootfs={}, config={}",
            &info.kernel_hash[..16],
            &info.rootfs_hash[..16],
            &info.config_hash[..16]
        );

        let (matches, reason) = self.validate_attestation(&info);

        AttestationResult {
            attestation_present: true,
            attestation: Some(info),
            matches_requirements: matches,
            rejection_reason: reason,
        }
    }

    /// Validates attestation info against configured requirements.
    fn validate_attestation(&self, info: &AttestationInfo) -> (bool, Option<String>) {
        // Check kernel hash if restrictions are configured
        if !self.config.allowed_kernel_hashes.is_empty()
            && !self
                .config
                .allowed_kernel_hashes
                .contains(&info.kernel_hash)
        {
            return (
                false,
                Some(format!(
                    "kernel hash {} not in allowed list",
                    &info.kernel_hash[..16]
                )),
            );
        }

        // Check rootfs hash if restrictions are configured
        if !self.config.allowed_rootfs_hashes.is_empty()
            && !self
                .config
                .allowed_rootfs_hashes
                .contains(&info.rootfs_hash)
        {
            return (
                false,
                Some(format!(
                    "rootfs hash {} not in allowed list",
                    &info.rootfs_hash[..16]
                )),
            );
        }

        // Check config hash if restrictions are configured
        if !self.config.allowed_config_hashes.is_empty()
            && !self
                .config
                .allowed_config_hashes
                .contains(&info.config_hash)
        {
            return (
                false,
                Some(format!(
                    "config hash {} not in allowed list",
                    &info.config_hash[..16]
                )),
            );
        }

        (true, None)
    }

    /// Returns whether attestation is required.
    pub fn is_required(&self) -> bool {
        self.config.require_attestation
    }

    /// Enforces the assurance floor (North Star C9) for a request whose launch
    /// attestation already passed.
    ///
    /// The launch attestation establishes at most `L1Software`; TPM residency
    /// evidence carried by the client certificate can raise the effective level,
    /// and a present-but-invalid or replayed proof makes this err (fail-closed).
    /// Returns `Err(reason)` when the SVID's verified assurance is below the floor.
    /// A no-op (`Ok`) when the floor is `L0Bearer`.
    pub fn enforce_floor(
        &self,
        client_cert_der: Option<&[u8]>,
        attestation_result: &AttestationResult,
    ) -> Result<(), String> {
        let min = self.config.min_assurance;
        if min <= AssuranceLevel::L0Bearer {
            return Ok(());
        }
        let cert_der = client_cert_der
            .ok_or_else(|| "assurance floor requires an mTLS client certificate".to_string())?;
        let launch_verified =
            attestation_result.attestation_present && attestation_result.matches_requirements;
        let level = nucleus_identity::tpm_devid::effective_assurance(cert_der, launch_verified)
            .map_err(|e| format!("residency evidence invalid: {e}"))?;
        if level < min {
            return Err(format!("assurance {level:?} below required floor {min:?}"));
        }
        Ok(())
    }
}

/// Extracts attestation from a DER-encoded X.509 certificate.
#[allow(dead_code)]
fn extract_attestation_from_cert(cert_der: &[u8]) -> Result<Option<LaunchAttestation>, String> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("failed to parse certificate: {}", e))?;

    // Construct our attestation OID for comparison
    // OID: 1.3.6.1.4.1.57212.1.1
    let attestation_oid =
        oid_registry::Oid::from(ATTESTATION_OID).expect("invalid attestation OID");

    // Look for our custom attestation extension
    for ext in cert.extensions() {
        if ext.oid == attestation_oid {
            // Found attestation extension, parse the DER content
            let attestation = LaunchAttestation::from_der(ext.value)
                .map_err(|e| format!("failed to parse attestation DER: {}", e))?;
            return Ok(Some(attestation));
        }
    }

    Ok(None)
}

/// Decode standard base64 to bytes.
pub(crate) fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD
        .decode(input)
        .map_err(|e| format!("base64 decode error: {e}"))
}

/// Encode bytes to standard base64.
#[cfg(test)]
pub(crate) fn base64_encode(input: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_config_default() {
        let config = AttestationConfig::default();
        assert!(!config.require_attestation);
        assert!(config.allowed_kernel_hashes.is_empty());
        assert!(config.allowed_rootfs_hashes.is_empty());
        // No floor by default — existing deployments are unaffected.
        assert_eq!(config.min_assurance, AssuranceLevel::L0Bearer);
    }

    #[test]
    fn enforce_floor_admits_refuses_and_fails_closed() {
        // Any DER works here: with no residency extension the effective assurance is
        // exactly the launch base, so this exercises the floor RESULT mapping without
        // TPM fixtures. (A garbage DER simply parses to "no residency" → base level.)
        let dummy_cert = [0x30u8, 0x00];
        let launch_ok = AttestationResult {
            attestation_present: true,
            attestation: None,
            matches_requirements: true, // launch verified → base L1Software
            rejection_reason: None,
        };
        let bearer = AttestationResult {
            attestation_present: false,
            attestation: None,
            matches_requirements: false, // no launch → base L0Bearer
            rejection_reason: None,
        };

        // No floor → always Ok, even without a client cert.
        let v0 = AttestationVerifier::new(AttestationConfig::default());
        assert!(v0.enforce_floor(None, &bearer).is_ok());

        // L1 floor: a launch-verified SVID is admitted; a bare bearer is refused.
        let v1 = AttestationVerifier::new(
            AttestationConfig::default().with_min_assurance(AssuranceLevel::L1Software),
        );
        assert!(v1.enforce_floor(Some(&dummy_cert), &launch_ok).is_ok());
        assert!(v1.enforce_floor(Some(&dummy_cert), &bearer).is_err());
        // A floor with no client certificate fails closed.
        assert!(v1.enforce_floor(None, &launch_ok).is_err());

        // L2 floor refuses even a launch-verified SVID: residency-only tops out at
        // L1Software until the EK-manufacturer root lands (never over-admits L2).
        let v2 = AttestationVerifier::new(
            AttestationConfig::default().with_min_assurance(AssuranceLevel::L2Device),
        );
        assert!(v2.enforce_floor(Some(&dummy_cert), &launch_ok).is_err());
    }

    #[test]
    fn test_min_assurance_floor_implies_required() {
        // A floor above L0 makes attestation required (can't check a floor without
        // a client cert); an L0 floor leaves require_attestation untouched.
        let floored = AttestationConfig::default().with_min_assurance(AssuranceLevel::L2Device);
        assert_eq!(floored.min_assurance, AssuranceLevel::L2Device);
        assert!(floored.require_attestation);

        let no_floor = AttestationConfig::default().with_min_assurance(AssuranceLevel::L0Bearer);
        assert_eq!(no_floor.min_assurance, AssuranceLevel::L0Bearer);
        assert!(!no_floor.require_attestation);
    }

    #[test]
    fn test_attestation_config_with_hashes() {
        let config = AttestationConfig::required()
            .with_kernel_hashes("abc123,def456")
            .with_rootfs_hashes("111222");

        assert!(config.require_attestation);
        assert_eq!(config.allowed_kernel_hashes.len(), 2);
        assert!(config.allowed_kernel_hashes.contains("abc123"));
        assert!(config.allowed_kernel_hashes.contains("def456"));
        assert_eq!(config.allowed_rootfs_hashes.len(), 1);
        assert!(config.allowed_rootfs_hashes.contains("111222"));
    }

    #[test]
    fn test_verifier_no_attestation_not_required() {
        let config = AttestationConfig::default();
        let verifier = AttestationVerifier::new(config);

        // Empty cert (will fail to parse but attestation not required)
        let result = verifier.verify_certificate(&[]);
        assert!(!result.attestation_present);
        assert!(result.matches_requirements);
    }

    #[test]
    fn test_verifier_no_attestation_required() {
        let config = AttestationConfig::required();
        let verifier = AttestationVerifier::new(config);

        // Empty cert (will fail to parse and attestation is required)
        let result = verifier.verify_certificate(&[]);
        assert!(!result.attestation_present);
        assert!(!result.matches_requirements);
        assert!(result.rejection_reason.is_some());
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"hello world attestation data";
        let encoded = base64_encode(original);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_attestation_info_from_launch_attestation() {
        let attestation = LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], [0xcc; 32]);

        let info = AttestationInfo::from(&attestation);
        assert_eq!(info.kernel_hash, "aa".repeat(32));
        assert_eq!(info.rootfs_hash, "bb".repeat(32));
        assert_eq!(info.config_hash, "cc".repeat(32));
    }

    #[test]
    fn test_validate_attestation_any_allowed() {
        let config = AttestationConfig::required();
        let verifier = AttestationVerifier::new(config);

        let info = AttestationInfo {
            kernel_hash: "aa".repeat(32),
            rootfs_hash: "bb".repeat(32),
            config_hash: "cc".repeat(32),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let (matches, reason) = verifier.validate_attestation(&info);
        assert!(matches);
        assert!(reason.is_none());
    }

    #[test]
    fn test_validate_attestation_kernel_hash_mismatch() {
        let config = AttestationConfig::required().with_kernel_hashes(&"dd".repeat(32));
        let verifier = AttestationVerifier::new(config);

        let info = AttestationInfo {
            kernel_hash: "aa".repeat(32),
            rootfs_hash: "bb".repeat(32),
            config_hash: "cc".repeat(32),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let (matches, reason) = verifier.validate_attestation(&info);
        assert!(!matches);
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("kernel hash"));
    }

    #[test]
    fn test_validate_attestation_kernel_hash_match() {
        let kernel_hash = "aa".repeat(32);
        let config = AttestationConfig::required().with_kernel_hashes(&kernel_hash);
        let verifier = AttestationVerifier::new(config);

        let info = AttestationInfo {
            kernel_hash: kernel_hash.clone(),
            rootfs_hash: "bb".repeat(32),
            config_hash: "cc".repeat(32),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let (matches, reason) = verifier.validate_attestation(&info);
        assert!(matches);
        assert!(reason.is_none());
    }

    #[test]
    fn test_verify_header_valid_attestation() {
        let attestation = LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x33; 32]);
        let der = attestation.to_der();
        let encoded = base64_encode(&der);

        let config = AttestationConfig::required();
        let verifier = AttestationVerifier::new(config);

        let result = verifier.verify_header(&encoded);
        assert!(result.attestation_present);
        assert!(result.matches_requirements);
        assert!(result.attestation.is_some());

        let info = result.attestation.unwrap();
        assert_eq!(info.kernel_hash, "11".repeat(32));
        assert_eq!(info.rootfs_hash, "22".repeat(32));
        assert_eq!(info.config_hash, "33".repeat(32));
    }
}
