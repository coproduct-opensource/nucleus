//! Launch attestation for Firecracker VM integrity verification.
//!
//! This module provides attestation primitives that cryptographically bind
//! SPIFFE identities to specific VM configurations. Attestation proves:
//!
//! - **Kernel integrity**: SHA-256 hash of the kernel image
//! - **Rootfs integrity**: SHA-256 hash of the root filesystem
//! - **Configuration integrity**: SHA-256 hash of PodSpec + lattice-guard policy
//!
//! # TCG DICE Compliance
//!
//! The attestation encoding follows the TCG DICE Attestation Architecture,
//! using proper ASN.1 DER encoding with OIDs from the TCG namespace.
//!
//! OID hierarchy:
//! - `2.23.133` - TCG root
//! - `2.23.133.5.4` - tcg-dice
//! - `2.23.133.5.4.1` - DiceTcbInfo
//!
//! See: [DICE Attestation Architecture v1.2](https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-v1.2_pub.pdf)
//!
//! # How It Works
//!
//! 1. Before launching a Firecracker VM, the host computes hashes of all components
//! 2. The attestation is embedded in the SPIFFE certificate as an X.509 extension
//! 3. Verifiers can require specific attestation hashes for sensitive operations
//!
//! # Example
//!
//! ```ignore
//! use nucleus_identity::LaunchAttestation;
//! use std::path::Path;
//!
//! let attestation = LaunchAttestation::compute(
//!     Path::new("/var/lib/nucleus/vmlinux"),
//!     Path::new("/var/lib/nucleus/rootfs.ext4"),
//!     &pod_spec_bytes,
//! ).await?;
//!
//! // Embed in certificate via CaClient::sign_attested_csr()
//! ```

use crate::{Error, Result};
use chrono::{DateTime, Utc};
use ring::digest::{digest, SHA256};
use std::path::Path;

/// SHA-256 hash (32 bytes).
pub type Hash256 = [u8; 32];

/// OID for SHA-256: 2.16.840.1.101.3.4.2.1 (NIST)
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// OID for Nucleus Launch Attestation (private enterprise arc).
///
/// **TODO(production):** Register a Private Enterprise Number (PEN) with IANA:
/// <https://www.iana.org/assignments/enterprise-numbers/>
///
/// Current value uses 1.3.6.1.4.1.57212.1.1 which is an unregistered placeholder.
/// 57212 is not officially assigned and may conflict with other software.
/// For production, obtain an official PEN and update this OID.
///
/// Format follows TCG DICE DiceTcbInfo-like structure.
const OID_NUCLEUS_ATTESTATION: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xde, 0x7c, // 1.3.6.1.4.1.57212 (unregistered)
    0x01, 0x01, // .1.1 (attestation.launch)
];

/// OID components for Nucleus Launch Attestation as u64 array.
///
/// Used by certificate generation (rcgen) which accepts OID components.
/// Exported for use by CA implementations.
///
/// Arc: 1.3.6.1.4.1.57212.1.1
pub const OID_NUCLEUS_ATTESTATION_COMPONENTS: &[u64] = &[1, 3, 6, 1, 4, 1, 57212, 1, 1];

/// Launch attestation containing integrity measurements of VM components.
///
/// This structure captures the cryptographic identity of a Firecracker VM's
/// configuration at launch time, enabling verification that the VM is running
/// expected code and configuration.
///
/// # ASN.1 Structure
///
/// ```text
/// NucleusLaunchAttestation ::= SEQUENCE {
///     version     INTEGER DEFAULT 1,
///     kernel      FWID,
///     rootfs      FWID,
///     config      FWID,
///     timestamp   GeneralizedTime
/// }
///
/// FWID ::= SEQUENCE {
///     hashAlg     OBJECT IDENTIFIER,  -- SHA-256
///     digest      OCTET STRING
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchAttestation {
    /// SHA-256 hash of the kernel image.
    kernel_hash: Hash256,
    /// SHA-256 hash of the root filesystem.
    rootfs_hash: Hash256,
    /// SHA-256 hash of the configuration (PodSpec + policy).
    config_hash: Hash256,
    /// When this attestation was computed.
    timestamp: DateTime<Utc>,
}

impl LaunchAttestation {
    /// Computes launch attestation by hashing VM components.
    ///
    /// # Arguments
    ///
    /// * `kernel` - Path to the kernel image (vmlinux)
    /// * `rootfs` - Path to the root filesystem (ext4, squashfs, etc.)
    /// * `config` - Serialized configuration (PodSpec + policy)
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel or rootfs files cannot be read.
    pub async fn compute(kernel: &Path, rootfs: &Path, config: &[u8]) -> Result<Self> {
        let kernel_hash = hash_file(kernel).await?;
        let rootfs_hash = hash_file(rootfs).await?;
        let config_hash = hash_bytes(config);

        Ok(Self {
            kernel_hash,
            rootfs_hash,
            config_hash,
            timestamp: Utc::now(),
        })
    }

    /// Creates an attestation from pre-computed hashes.
    ///
    /// Useful for testing or when hashes are provided externally.
    pub fn from_hashes(kernel_hash: Hash256, rootfs_hash: Hash256, config_hash: Hash256) -> Self {
        Self {
            kernel_hash,
            rootfs_hash,
            config_hash,
            timestamp: Utc::now(),
        }
    }

    /// Returns the kernel hash.
    pub fn kernel_hash(&self) -> &Hash256 {
        &self.kernel_hash
    }

    /// Returns the rootfs hash.
    pub fn rootfs_hash(&self) -> &Hash256 {
        &self.rootfs_hash
    }

    /// Returns the config hash.
    pub fn config_hash(&self) -> &Hash256 {
        &self.config_hash
    }

    /// Returns when this attestation was computed.
    pub fn timestamp(&self) -> DateTime<Utc> {
        self.timestamp
    }

    /// Computes a combined hash of all attestation components.
    ///
    /// This single hash can be used for compact verification.
    /// Format: SHA256(kernel_hash || rootfs_hash || config_hash)
    pub fn combined_hash(&self) -> Hash256 {
        let mut combined = Vec::with_capacity(96);
        combined.extend_from_slice(&self.kernel_hash);
        combined.extend_from_slice(&self.rootfs_hash);
        combined.extend_from_slice(&self.config_hash);
        hash_bytes(&combined)
    }

    /// Returns the X.509 extension OID for this attestation type.
    pub fn extension_oid() -> &'static [u8] {
        OID_NUCLEUS_ATTESTATION
    }

    /// Serializes attestation to ASN.1 DER-encoded bytes for X.509 extension.
    ///
    /// Structure follows TCG DICE conventions with proper ASN.1 encoding:
    /// ```text
    /// SEQUENCE {
    ///     INTEGER 1,                    -- version
    ///     SEQUENCE { OID, OCTET STRING }, -- kernel FWID
    ///     SEQUENCE { OID, OCTET STRING }, -- rootfs FWID
    ///     SEQUENCE { OID, OCTET STRING }, -- config FWID
    ///     GeneralizedTime               -- timestamp
    /// }
    /// ```
    pub fn to_der(&self) -> Vec<u8> {
        let mut content = Vec::new();

        // Version: INTEGER 1
        content.extend_from_slice(&encode_integer(1));

        // kernel FWID
        content.extend_from_slice(&encode_fwid(&self.kernel_hash));

        // rootfs FWID
        content.extend_from_slice(&encode_fwid(&self.rootfs_hash));

        // config FWID
        content.extend_from_slice(&encode_fwid(&self.config_hash));

        // timestamp: GeneralizedTime
        content.extend_from_slice(&encode_generalized_time(&self.timestamp));

        // Wrap in outer SEQUENCE
        encode_sequence(&content)
    }

    /// Parses attestation from ASN.1 DER-encoded bytes.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let mut pos = 0;

        // Outer SEQUENCE
        let (_, seq_content) = decode_sequence(der, &mut pos)?;
        let mut inner_pos = 0;

        // Version: INTEGER
        let version = decode_integer(&seq_content, &mut inner_pos)?;
        if version != 1 {
            return Err(Error::Certificate(format!(
                "unsupported attestation version: {}",
                version
            )));
        }

        // kernel FWID
        let kernel_hash = decode_fwid(&seq_content, &mut inner_pos)?;

        // rootfs FWID
        let rootfs_hash = decode_fwid(&seq_content, &mut inner_pos)?;

        // config FWID
        let config_hash = decode_fwid(&seq_content, &mut inner_pos)?;

        // timestamp: GeneralizedTime
        let timestamp = decode_generalized_time(&seq_content, &mut inner_pos)?;

        Ok(Self {
            kernel_hash,
            rootfs_hash,
            config_hash,
            timestamp,
        })
    }

    /// Returns a hex-encoded string representation for logging.
    pub fn to_hex_summary(&self) -> String {
        format!(
            "kernel={} rootfs={} config={}",
            hex_short(&self.kernel_hash),
            hex_short(&self.rootfs_hash),
            hex_short(&self.config_hash),
        )
    }
}

/// Requirements for attestation verification.
///
/// Verifiers can specify which hashes are acceptable for a given operation.
#[derive(Debug, Clone, Default)]
pub struct AttestationRequirements {
    /// Allowed kernel hashes (empty = any kernel).
    pub allowed_kernel_hashes: Vec<Hash256>,
    /// Allowed rootfs hashes (empty = any rootfs).
    pub allowed_rootfs_hashes: Vec<Hash256>,
    /// Allowed config hashes (empty = any config).
    pub allowed_config_hashes: Vec<Hash256>,
}

impl AttestationRequirements {
    /// Creates requirements that accept any attestation.
    pub fn any() -> Self {
        Self::default()
    }

    /// Creates requirements that require specific kernel, rootfs, and config.
    pub fn exact(kernel: Hash256, rootfs: Hash256, config: Hash256) -> Self {
        Self {
            allowed_kernel_hashes: vec![kernel],
            allowed_rootfs_hashes: vec![rootfs],
            allowed_config_hashes: vec![config],
        }
    }

    /// Adds an allowed kernel hash.
    pub fn allow_kernel(mut self, hash: Hash256) -> Self {
        self.allowed_kernel_hashes.push(hash);
        self
    }

    /// Adds an allowed rootfs hash.
    pub fn allow_rootfs(mut self, hash: Hash256) -> Self {
        self.allowed_rootfs_hashes.push(hash);
        self
    }

    /// Adds an allowed config hash.
    pub fn allow_config(mut self, hash: Hash256) -> Self {
        self.allowed_config_hashes.push(hash);
        self
    }

    /// Checks if an attestation meets these requirements.
    ///
    /// Empty allowed lists mean any value is acceptable.
    pub fn verify(&self, attestation: &LaunchAttestation) -> Result<()> {
        // Check kernel hash
        if !self.allowed_kernel_hashes.is_empty()
            && !self
                .allowed_kernel_hashes
                .contains(&attestation.kernel_hash)
        {
            return Err(Error::VerificationFailed(format!(
                "kernel hash {} not in allowed list",
                hex_short(&attestation.kernel_hash)
            )));
        }

        // Check rootfs hash
        if !self.allowed_rootfs_hashes.is_empty()
            && !self
                .allowed_rootfs_hashes
                .contains(&attestation.rootfs_hash)
        {
            return Err(Error::VerificationFailed(format!(
                "rootfs hash {} not in allowed list",
                hex_short(&attestation.rootfs_hash)
            )));
        }

        // Check config hash
        if !self.allowed_config_hashes.is_empty()
            && !self
                .allowed_config_hashes
                .contains(&attestation.config_hash)
        {
            return Err(Error::VerificationFailed(format!(
                "config hash {} not in allowed list",
                hex_short(&attestation.config_hash)
            )));
        }

        Ok(())
    }
}

// ============================================================================
// ASN.1 DER Encoding Helpers (X.690)
// ============================================================================

/// ASN.1 tag for SEQUENCE.
const TAG_SEQUENCE: u8 = 0x30;
/// ASN.1 tag for INTEGER.
const TAG_INTEGER: u8 = 0x02;
/// ASN.1 tag for OCTET STRING.
const TAG_OCTET_STRING: u8 = 0x04;
/// ASN.1 tag for OID.
const TAG_OID: u8 = 0x06;
/// ASN.1 tag for GeneralizedTime.
const TAG_GENERALIZED_TIME: u8 = 0x18;

/// Encodes length in DER format.
fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        // Short form
        vec![len as u8]
    } else if len < 256 {
        // Long form, 1 byte
        vec![0x81, len as u8]
    } else {
        // Long form, 2 bytes
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// Encodes a DER SEQUENCE.
fn encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut result = vec![TAG_SEQUENCE];
    result.extend_from_slice(&encode_length(content.len()));
    result.extend_from_slice(content);
    result
}

/// Encodes a DER INTEGER.
fn encode_integer(value: i64) -> Vec<u8> {
    // For small positive integers
    if (0..128).contains(&value) {
        vec![TAG_INTEGER, 0x01, value as u8]
    } else {
        // Handle larger values (simplified for version=1)
        let bytes = value.to_be_bytes();
        let mut start = 0;
        while start < 7 && bytes[start] == 0 {
            start += 1;
        }
        // Add leading zero if high bit is set (to keep positive)
        let needs_padding = bytes[start] & 0x80 != 0;
        let mut result = vec![TAG_INTEGER];
        let len = 8 - start + if needs_padding { 1 } else { 0 };
        result.push(len as u8);
        if needs_padding {
            result.push(0x00);
        }
        result.extend_from_slice(&bytes[start..]);
        result
    }
}

/// Encodes a DER OCTET STRING.
fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![TAG_OCTET_STRING];
    result.extend_from_slice(&encode_length(data.len()));
    result.extend_from_slice(data);
    result
}

/// Encodes a DER OID.
fn encode_oid(oid: &[u8]) -> Vec<u8> {
    let mut result = vec![TAG_OID];
    result.extend_from_slice(&encode_length(oid.len()));
    result.extend_from_slice(oid);
    result
}

/// Encodes an FWID (hashAlg OID + digest OCTET STRING) as SEQUENCE.
fn encode_fwid(digest: &Hash256) -> Vec<u8> {
    let mut content = encode_oid(OID_SHA256);
    content.extend_from_slice(&encode_octet_string(digest));
    encode_sequence(&content)
}

/// Encodes a GeneralizedTime.
fn encode_generalized_time(dt: &DateTime<Utc>) -> Vec<u8> {
    // Format: YYYYMMDDHHMMSSZ
    let time_str = dt.format("%Y%m%d%H%M%SZ").to_string();
    let mut result = vec![TAG_GENERALIZED_TIME];
    result.extend_from_slice(&encode_length(time_str.len()));
    result.extend_from_slice(time_str.as_bytes());
    result
}

// ============================================================================
// ASN.1 DER Decoding Helpers
// ============================================================================

/// Decodes DER length at position, returns (length, bytes_consumed).
fn decode_length(data: &[u8], pos: &mut usize) -> Result<usize> {
    if *pos >= data.len() {
        return Err(Error::Certificate("unexpected end of DER data".to_string()));
    }

    let first = data[*pos];
    *pos += 1;

    if first < 128 {
        // Short form
        Ok(first as usize)
    } else {
        // Long form
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 {
            return Err(Error::Certificate(
                "invalid DER length encoding".to_string(),
            ));
        }
        if *pos + num_bytes > data.len() {
            return Err(Error::Certificate("truncated DER length".to_string()));
        }
        let mut len = 0usize;
        for _ in 0..num_bytes {
            len = (len << 8) | (data[*pos] as usize);
            *pos += 1;
        }
        Ok(len)
    }
}

/// Decodes a DER SEQUENCE, returns content slice.
fn decode_sequence(data: &[u8], pos: &mut usize) -> Result<(u8, Vec<u8>)> {
    if *pos >= data.len() {
        return Err(Error::Certificate("unexpected end of DER data".to_string()));
    }

    let tag = data[*pos];
    if tag != TAG_SEQUENCE {
        return Err(Error::Certificate(format!(
            "expected SEQUENCE tag 0x30, got 0x{:02x}",
            tag
        )));
    }
    *pos += 1;

    let len = decode_length(data, pos)?;
    if *pos + len > data.len() {
        return Err(Error::Certificate("truncated SEQUENCE content".to_string()));
    }

    let content = data[*pos..*pos + len].to_vec();
    *pos += len;
    Ok((tag, content))
}

/// Decodes a DER INTEGER.
fn decode_integer(data: &[u8], pos: &mut usize) -> Result<i64> {
    if *pos >= data.len() || data[*pos] != TAG_INTEGER {
        return Err(Error::Certificate("expected INTEGER tag".to_string()));
    }
    *pos += 1;

    let len = decode_length(data, pos)?;
    if len == 0 || *pos + len > data.len() {
        return Err(Error::Certificate("invalid INTEGER".to_string()));
    }

    // Reject integers that are too large to fit in i64 (max 8 bytes)
    if len > 8 {
        return Err(Error::Certificate("INTEGER too large".to_string()));
    }

    let mut value: i64 = 0;
    let is_negative = data[*pos] & 0x80 != 0;
    for i in 0..len {
        value = (value << 8) | (data[*pos + i] as i64);
    }
    if is_negative {
        // Sign extend for negative numbers
        let sign_bits = 64 - (len * 8);
        value = (value << sign_bits) >> sign_bits;
    }
    *pos += len;
    Ok(value)
}

/// Decodes an FWID SEQUENCE, extracts the digest.
fn decode_fwid(data: &[u8], pos: &mut usize) -> Result<Hash256> {
    let (_, fwid_content) = decode_sequence(data, pos)?;
    let mut inner_pos = 0;

    // Skip OID (we assume SHA-256)
    if inner_pos >= fwid_content.len() || fwid_content[inner_pos] != TAG_OID {
        return Err(Error::Certificate("expected OID in FWID".to_string()));
    }
    inner_pos += 1;
    let oid_len = decode_length(&fwid_content, &mut inner_pos)?;
    inner_pos += oid_len;

    // Decode OCTET STRING
    if inner_pos >= fwid_content.len() || fwid_content[inner_pos] != TAG_OCTET_STRING {
        return Err(Error::Certificate(
            "expected OCTET STRING in FWID".to_string(),
        ));
    }
    inner_pos += 1;
    let digest_len = decode_length(&fwid_content, &mut inner_pos)?;

    if digest_len != 32 {
        return Err(Error::Certificate(format!(
            "expected 32-byte digest, got {}",
            digest_len
        )));
    }
    if inner_pos + 32 > fwid_content.len() {
        return Err(Error::Certificate("truncated FWID digest".to_string()));
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&fwid_content[inner_pos..inner_pos + 32]);
    Ok(hash)
}

/// Decodes a GeneralizedTime.
fn decode_generalized_time(data: &[u8], pos: &mut usize) -> Result<DateTime<Utc>> {
    if *pos >= data.len() || data[*pos] != TAG_GENERALIZED_TIME {
        return Err(Error::Certificate(
            "expected GeneralizedTime tag".to_string(),
        ));
    }
    *pos += 1;

    let len = decode_length(data, pos)?;
    if *pos + len > data.len() {
        return Err(Error::Certificate("truncated GeneralizedTime".to_string()));
    }

    let time_str = std::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|_| Error::Certificate("invalid GeneralizedTime encoding".to_string()))?;
    *pos += len;

    // Parse YYYYMMDDHHMMSSZ format
    use chrono::NaiveDateTime;
    let naive = NaiveDateTime::parse_from_str(time_str, "%Y%m%d%H%M%SZ")
        .map_err(|e| Error::Certificate(format!("invalid GeneralizedTime: {}", e)))?;

    Ok(naive.and_utc())
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Computes SHA-256 hash of a file.
async fn hash_file(path: &Path) -> Result<Hash256> {
    let contents = tokio::fs::read(path).await.map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read {}: {}", path.display(), e),
        ))
    })?;
    Ok(hash_bytes(&contents))
}

/// Computes SHA-256 hash of bytes.
fn hash_bytes(data: &[u8]) -> Hash256 {
    let digest = digest(&SHA256, data);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(digest.as_ref());
    hash
}

/// Returns first 8 hex characters of a hash for logging.
fn hex_short(hash: &Hash256) -> String {
    hash.iter().take(4).map(|b| format!("{:02x}", b)).collect()
}

/// Parses a hex string into a hash.
pub fn parse_hash(hex: &str) -> Option<Hash256> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }

    let mut hash = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hex_str = std::str::from_utf8(chunk).ok()?;
        hash[i] = u8::from_str_radix(hex_str, 16).ok()?;
    }

    Some(hash)
}

/// Formats a hash as a hex string.
pub fn format_hash(hash: &Hash256) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_attestation_compute() {
        // Create temp files
        let mut kernel = NamedTempFile::new().unwrap();
        kernel.write_all(b"fake kernel image").unwrap();

        let mut rootfs = NamedTempFile::new().unwrap();
        rootfs.write_all(b"fake rootfs image").unwrap();

        let config = b"pod spec yaml content";

        let attestation = LaunchAttestation::compute(kernel.path(), rootfs.path(), config)
            .await
            .expect("should compute attestation");

        // Verify hashes are non-zero
        assert_ne!(attestation.kernel_hash, [0u8; 32]);
        assert_ne!(attestation.rootfs_hash, [0u8; 32]);
        assert_ne!(attestation.config_hash, [0u8; 32]);

        // Verify config hash is deterministic
        let expected_config_hash = hash_bytes(config);
        assert_eq!(attestation.config_hash, expected_config_hash);
    }

    #[test]
    fn test_attestation_der_roundtrip() {
        let attestation = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);

        let der = attestation.to_der();

        // DER should start with SEQUENCE tag
        assert_eq!(der[0], TAG_SEQUENCE, "should start with SEQUENCE tag");

        // Parse it back
        let parsed = LaunchAttestation::from_der(&der).expect("should parse");
        assert_eq!(parsed.kernel_hash, attestation.kernel_hash);
        assert_eq!(parsed.rootfs_hash, attestation.rootfs_hash);
        assert_eq!(parsed.config_hash, attestation.config_hash);

        // Timestamps may differ slightly due to truncation, but should be close
        let diff = (parsed.timestamp - attestation.timestamp)
            .num_seconds()
            .abs();
        assert!(diff <= 1, "timestamps should match within 1 second");
    }

    #[test]
    fn test_attestation_der_structure() {
        let attestation = LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], [0xcc; 32]);

        let der = attestation.to_der();

        // Verify it's a valid SEQUENCE
        assert_eq!(der[0], 0x30, "outer tag should be SEQUENCE");

        // The DER should contain:
        // - 1 SEQUENCE wrapper
        // - 1 INTEGER (version)
        // - 3 FWID SEQUENCES (each containing OID + OCTET STRING)
        // - 1 GeneralizedTime

        // Parse to verify structure
        let mut pos = 0;
        let (_, content) = decode_sequence(&der, &mut pos).expect("should parse outer SEQUENCE");

        let mut inner_pos = 0;

        // Version INTEGER
        let version = decode_integer(&content, &mut inner_pos).expect("should parse version");
        assert_eq!(version, 1);

        // Three FWIDs
        let kernel = decode_fwid(&content, &mut inner_pos).expect("should parse kernel FWID");
        assert_eq!(kernel, [0xaa; 32]);

        let rootfs = decode_fwid(&content, &mut inner_pos).expect("should parse rootfs FWID");
        assert_eq!(rootfs, [0xbb; 32]);

        let config = decode_fwid(&content, &mut inner_pos).expect("should parse config FWID");
        assert_eq!(config, [0xcc; 32]);

        // GeneralizedTime
        let _timestamp =
            decode_generalized_time(&content, &mut inner_pos).expect("should parse timestamp");
    }

    #[test]
    fn test_attestation_combined_hash() {
        let attestation = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);

        let combined = attestation.combined_hash();
        assert_ne!(combined, [0u8; 32]);

        // Same inputs should produce same combined hash
        let attestation2 = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);
        assert_eq!(attestation.combined_hash(), attestation2.combined_hash());

        // Different inputs should produce different combined hash
        let attestation3 = LaunchAttestation::from_hashes(
            [1u8; 32], [2u8; 32], [4u8; 32], // Different config
        );
        assert_ne!(attestation.combined_hash(), attestation3.combined_hash());
    }

    #[test]
    fn test_requirements_verify_empty() {
        let req = AttestationRequirements::any();
        let attestation = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);

        // Empty requirements should accept anything
        req.verify(&attestation).expect("should accept any");
    }

    #[test]
    fn test_requirements_verify_exact_match() {
        let req = AttestationRequirements::exact([1u8; 32], [2u8; 32], [3u8; 32]);
        let attestation = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);

        req.verify(&attestation).expect("should accept exact match");
    }

    #[test]
    fn test_requirements_verify_kernel_mismatch() {
        let req = AttestationRequirements::any().allow_kernel([1u8; 32]);
        let attestation = LaunchAttestation::from_hashes([99u8; 32], [2u8; 32], [3u8; 32]);

        let result = req.verify(&attestation);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("kernel hash"));
    }

    #[test]
    fn test_requirements_verify_multiple_allowed() {
        let req = AttestationRequirements::any()
            .allow_kernel([1u8; 32])
            .allow_kernel([2u8; 32]); // Allow two kernels

        let attestation1 = LaunchAttestation::from_hashes([1u8; 32], [0u8; 32], [0u8; 32]);
        let attestation2 = LaunchAttestation::from_hashes([2u8; 32], [0u8; 32], [0u8; 32]);
        let attestation3 = LaunchAttestation::from_hashes([3u8; 32], [0u8; 32], [0u8; 32]);

        req.verify(&attestation1).expect("should accept kernel 1");
        req.verify(&attestation2).expect("should accept kernel 2");
        assert!(req.verify(&attestation3).is_err());
    }

    #[test]
    fn test_parse_hash() {
        let hash = [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
            0x23, 0x45, 0x67, 0x89,
        ];

        let hex = format_hash(&hash);
        assert_eq!(hex.len(), 64);

        let parsed = parse_hash(&hex).expect("should parse");
        assert_eq!(parsed, hash);
    }

    #[test]
    fn test_hex_summary() {
        let attestation = LaunchAttestation::from_hashes(
            [
                0xab, 0xcd, 0xef, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ],
        );

        let summary = attestation.to_hex_summary();
        assert!(summary.contains("abcdef01"));
        assert!(summary.contains("12345678"));
        assert!(summary.contains("deadbeef"));
    }

    #[test]
    fn test_extension_oid() {
        let oid = LaunchAttestation::extension_oid();
        // Should be a valid OID encoding
        assert!(!oid.is_empty());
        // First byte encodes first two OID components
        assert_eq!(oid[0], 0x2b); // 1.3 encoded as 1*40+3 = 43 = 0x2b
    }

    #[test]
    fn test_encode_decode_length() {
        // Short form
        let short = encode_length(50);
        assert_eq!(short, vec![50]);

        // Long form 1 byte
        let medium = encode_length(200);
        assert_eq!(medium, vec![0x81, 200]);

        // Long form 2 bytes
        let long = encode_length(500);
        assert_eq!(long, vec![0x82, 0x01, 0xf4]);

        // Decode them back
        let mut pos = 0;
        assert_eq!(decode_length(&short, &mut pos).unwrap(), 50);

        pos = 0;
        assert_eq!(decode_length(&medium, &mut pos).unwrap(), 200);

        pos = 0;
        assert_eq!(decode_length(&long, &mut pos).unwrap(), 500);
    }
}
