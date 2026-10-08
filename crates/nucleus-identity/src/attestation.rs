//! Launch attestation for Firecracker VM integrity verification.
//!
//! This module provides attestation primitives that bind SPIFFE identities to the
//! measurements the *node* computed for a VM's components. Each attestation carries:
//!
//! - **Kernel measurement**: SHA-256 hash of the kernel image
//! - **Rootfs measurement**: SHA-256 hash of the root filesystem
//! - **Configuration measurement**: SHA-256 hash of PodSpec + portcullis policy
//!
//! # Trust boundary — NOT hardware-rooted
//!
//! These are **first-party, software** measurements: the node hashes what it
//! launched and signs the result with its own CA key. There is **no hardware root**
//! — no TPM / SEV-SNP / TDX quote, no UDS-in-ROM DICE identity binding the signing
//! key to silicon. A compromised node can sign any measurement, so the guarantee is
//! conditional: *IF you trust the node's key, THEN the pod ran an artifact with
//! these measurements.* Do not label this "hardware attestation" or "DICE measured
//! boot."
//!
//! # DICE-format-compatible encoding
//!
//! The DER encoding borrows the TCG DICE `DiceTcbInfo` *format* (FWID hash
//! entries) so off-the-shelf ASN.1 tooling can parse it — it is not a hardware DICE
//! layer. See: [DICE Attestation Architecture v1.2](https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-v1.2_pub.pdf)
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

use crate::{Error, Result, oid};
use chrono::{DateTime, Utc};
use ring::digest::{Context, SHA256, digest};
use std::path::Path;

/// SHA-256 hash (32 bytes).
pub type Hash256 = [u8; 32];

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
        oid::OID_NUCLEUS_ATTESTATION_BYTES
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
    let mut content = encode_oid(oid::OID_SHA256_BYTES);
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
        value = (value << 8) | i64::from(data[*pos + i]);
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

/// Measures the SHA-256 digest of an on-disk artifact (e.g. a guest rootfs)
/// using the SAME hashing the launch attestation uses. A posture claim verified
/// against this value is therefore comparing against exactly the digest
/// [`LaunchAttestation::rootfs_hash`] reports for the same file — the registry
/// digest, the attestation digest, and the posture-admission digest are one
/// function's output, so they cannot drift apart. Returns the raw 32-byte hash;
/// callers hex-encode for comparison against operator-supplied digests.
pub async fn measure_artifact(path: &Path) -> Result<Hash256> {
    hash_file(path).await
}

/// Computes SHA-256 hash of a file, a chunk at a time.
///
/// Streamed rather than read whole, because what this measures are microVM images. A 1 GiB
/// rootfs through `tokio::fs::read` is a 1 GiB allocation on the launch path — and on a pod that
/// carries a posture claim it happened TWICE, once for the posture gate and once for the launch
/// attestation, neither knowing the other had just read the same file. The digest is identical
/// either way; only the peak differs.
async fn hash_file(path: &Path) -> Result<Hash256> {
    use tokio::io::AsyncReadExt as _;

    let io = |e: std::io::Error| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read {}: {}", path.display(), e),
        ))
    };
    let mut file = tokio::fs::File::open(path).await.map_err(io)?;
    let mut ctx = Context::new(&SHA256);
    // A mebibyte: big enough that the read syscalls disappear against the hashing, small enough
    // that the buffer is not itself the allocation this exists to avoid.
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).await.map_err(io)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(ctx.finish().as_ref());
    Ok(hash)
}

/// Computes SHA-256 hash of bytes.
pub fn hash_bytes(data: &[u8]) -> Hash256 {
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

// ═══════════════════════════════════════════════════════════════════════════
// PERMISSION FINGERPRINT EXTRACTION (SPIFFE Identity Fusion, Layer 2)
// ═══════════════════════════════════════════════════════════════════════════

/// Extract a permission fingerprint from an X.509 certificate extension.
///
/// Looks for OID `1.3.6.1.4.1.57212.1.2` (Nucleus Permission Fingerprint)
/// in the certificate's extensions and parses the DER-encoded SHA-256 fingerprint.
///
/// Returns `None` if the extension is not present or cannot be parsed.
pub fn extract_permission_fingerprint(cert_der: &[u8]) -> Option<[u8; 32]> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    for ext in cert.extensions() {
        // Compare raw OID bytes against our known permission fingerprint OID
        if ext.oid.as_bytes() == crate::oid::OID_NUCLEUS_PERMISSION_FINGERPRINT_BYTES {
            return parse_permission_fingerprint_der(ext.value);
        }
    }
    None
}

/// Parse the DER content of a permission fingerprint extension.
///
/// Expected format: `SEQUENCE { INTEGER(version=1), OCTET STRING(32 bytes) }`
fn parse_permission_fingerprint_der(der: &[u8]) -> Option<[u8; 32]> {
    let mut pos = 0;

    // SEQUENCE tag
    if pos >= der.len() || der[pos] != 0x30 {
        return None;
    }
    pos += 1;
    let seq_len = der[pos] as usize;
    pos += 1;
    if pos + seq_len > der.len() {
        return None;
    }

    // INTEGER tag (version)
    if pos >= der.len() || der[pos] != 0x02 {
        return None;
    }
    pos += 1;
    let int_len = der[pos] as usize;
    pos += 1;
    // Skip version bytes
    pos += int_len;

    // OCTET STRING tag (fingerprint)
    if pos >= der.len() || der[pos] != 0x04 {
        return None;
    }
    pos += 1;
    let oct_len = der[pos] as usize;
    pos += 1;
    if oct_len != 32 || pos + 32 > der.len() {
        return None;
    }

    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&der[pos..pos + 32]);
    Some(fingerprint)
}

// ═══════════════════════════════════════════════════════════════════════════
// LAUNCH ATTESTATION EXTRACTION + RELYING-PARTY VERIFICATION (North Star C9)
// ═══════════════════════════════════════════════════════════════════════════

/// Extract a launch attestation from an X.509 certificate (DER).
///
/// Looks for OID `1.3.6.1.4.1.57212.1.1` (Nucleus Launch Attestation) among the
/// certificate's extensions and parses the embedded [`LaunchAttestation`].
///
/// Returns `None` if the extension is absent or cannot be parsed.
pub fn extract_launch_attestation(cert_der: &[u8]) -> Option<LaunchAttestation> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    for ext in cert.extensions() {
        if ext.oid.as_bytes() == crate::oid::OID_NUCLEUS_ATTESTATION_BYTES {
            return LaunchAttestation::from_der(ext.value).ok();
        }
    }
    None
}

/// Extract the mediator-key binding from an X.509 certificate extension.
///
/// Looks for OID `1.3.6.1.4.1.57212.1.4` (Nucleus mediator-key binding) and
/// returns the embedded `SHA-256(mediator Ed25519 public key)`. This is the value
/// a relying party places in [`VerifiedAttestation::subject_key_sha256`] so
/// `verify_attested_receipt` can require the receipt to be signed by exactly this
/// key. The wire shape is identical to the permission fingerprint (a
/// version-tagged 32-byte octet string), so the same DER parser reads it.
///
/// Returns `None` if the extension is absent or cannot be parsed.
pub fn extract_mediation_key_binding(cert_der: &[u8]) -> Option<[u8; 32]> {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;
    for ext in cert.extensions() {
        if ext.oid.as_bytes() == crate::oid::OID_NUCLEUS_MEDIATION_KEY_BINDING_BYTES {
            return parse_permission_fingerprint_der(ext.value);
        }
    }
    None
}

/// A launch claim on a leaf that chains to a trusted CA.
///
/// # The defect this type exists to make unwritable
///
/// `verify_attested_svid` used to read the launch extension (OID
/// 1.3.6.1.4.1.57212.1.1) off the leaf and never ask who signed the leaf. A
/// self-signed certificate carrying that OID, made in a few lines of `rcgen` by
/// anyone, passed `nucleus verify-attestation`. The tool-proxy had fixed the same
/// defect for itself on 2026-09-29 with a private `VerifiedLaunch`, so a weak
/// public check and a strong private one decided the same fact (ADR 0007 G-1).
/// [`issued_launch`] is now the one decider, and both call it.
///
/// The fields are private and [`VerifiedLaunch::verify`] is the only constructor
/// (C-1, C-2). Both halves are required, in this order: a launch claim on a
/// certificate the trusted CA did not sign is a forgery, not a weaker form of
/// the real thing.
#[derive(Debug)]
pub struct VerifiedLaunch {
    spiffe_id: String,
    launch: LaunchAttestation,
}

impl VerifiedLaunch {
    /// Verify `leaf_der` against `trust_bundle`, then read its launch claim.
    ///
    /// # Errors
    ///
    /// The leaf does not chain to the bundle, names no SPIFFE ID, or carries no
    /// parseable launch attestation.
    pub fn verify(leaf_der: &[u8], trust_bundle: &crate::TrustBundle) -> Result<Self> {
        match issued_launch(leaf_der, trust_bundle)? {
            IssuedLaunch::Measured(launch) => {
                let spiffe_id = crate::spiffe_uri_from_svid(leaf_der).map_err(|e| {
                    Error::VerificationFailed(format!("verified leaf has no SPIFFE ID: {e}"))
                })?;
                Ok(Self { spiffe_id, launch })
            }
            IssuedLaunch::Unmeasured(tier) => Err(Error::VerificationFailed(unmeasured(tier))),
            IssuedLaunch::Unstated => Err(Error::VerificationFailed(
                "verified leaf carries no parseable launch attestation".to_string(),
            )),
        }
    }

    /// The workload identity the verified leaf names.
    pub fn spiffe_id(&self) -> &str {
        &self.spiffe_id
    }

    /// The launch measurement the verified leaf carries.
    pub fn launch(&self) -> &LaunchAttestation {
        &self.launch
    }
}

/// The one decider: the leaf chains to a root in `trust_bundle`, and then its
/// launch claim, if it carries one. The issuer is checked first and always, so
/// "carries no attestation" is said only of a leaf a trusted CA signed.
fn issued_launch(leaf_der: &[u8], trust_bundle: &crate::TrustBundle) -> Result<IssuedLaunch> {
    let leaf = crate::certificate::Certificate::from_der(leaf_der.to_vec());
    crate::verify_svid_chain(&leaf, trust_bundle).map_err(|e| {
        Error::VerificationFailed(format!("leaf is not issued by a trusted CA: {e}"))
    })?;
    match (
        extract_launch_attestation(leaf_der),
        extract_unmeasured_launch(leaf_der)?,
    ) {
        (Some(launch), None) => Ok(IssuedLaunch::Measured(launch)),
        (None, Some(tier)) => Ok(IssuedLaunch::Unmeasured(tier)),
        (None, None) => Ok(IssuedLaunch::Unstated),
        // Two answers to one question is not a launch claim of either kind.
        (Some(_), Some(tier)) => Err(Error::VerificationFailed(format!(
            "leaf claims both a measured launch and an unmeasured `{}` launch",
            tier.as_str()
        ))),
    }
}

/// What a leaf a trusted CA signed says about the launch it identifies.
enum IssuedLaunch {
    /// The node's measurement of the kernel, rootfs and config it launched.
    Measured(LaunchAttestation),
    /// The tier that launched it cannot measure a launch, and the leaf says so.
    Unmeasured(UnmeasuredTier),
    /// Neither: an identity that is not a pod launch (a node, a client).
    Unstated,
}

fn unmeasured(tier: UnmeasuredTier) -> String {
    format!(
        "the launch is unmeasured: the `{}` tier cannot measure what it launches, and a \
         measured launch is required",
        tier.as_str()
    )
}

/// A tier that launches workloads without measuring them, named in the leaf
/// (OID `.1.6`) so the absence of a measurement is stated, never inferred from a
/// missing extension.
///
/// No `Default` (ADR 0007 B-1); every match over it is exhaustive (E-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnmeasuredTier {
    /// A container runtime.
    Container,
    /// A process on the node, no VM (`local-driver`).
    Local,
    /// Apple Virtualization.framework.
    AppleVz,
    /// The host tier: `nucleus run --local`, `nucleus shell`.
    Host,
}

impl UnmeasuredTier {
    /// Every tier, for tests and censuses.
    pub const ALL: [UnmeasuredTier; 4] = [Self::Container, Self::Local, Self::AppleVz, Self::Host];

    /// The name the extension carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Container => "container",
            Self::Local => "local",
            Self::AppleVz => "apple-vz",
            Self::Host => "host",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == name)
    }

    /// The extension value: the DER `UTF8String` of [`Self::as_str`].
    ///
    /// # Errors
    ///
    /// A name too long for a short-form DER length (none of today's).
    pub fn extension_value(self) -> Result<Vec<u8>> {
        let name = self.as_str().as_bytes();
        let len = u8::try_from(name.len())
            .ok()
            .filter(|l| *l < 0x80)
            .ok_or_else(|| Error::Internal(format!("tier name `{}` is too long", self.as_str())))?;
        let mut der = vec![0x0c, len];
        der.extend_from_slice(name);
        Ok(der)
    }
}

/// The unmeasured-launch tier a leaf names, if it carries the extension.
///
/// # Errors
///
/// The extension is present but its value is not one known tier: a statement
/// nobody can read is refused, never read as absent (ADR 0007 A-2).
pub fn extract_unmeasured_launch(cert_der: &[u8]) -> Result<Option<UnmeasuredTier>> {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let Ok((_, cert)) = X509Certificate::from_der(cert_der) else {
        return Ok(None);
    };
    let Some(ext) = cert
        .extensions()
        .iter()
        .find(|e| e.oid.as_bytes() == crate::oid::OID_NUCLEUS_UNMEASURED_LAUNCH_BYTES)
    else {
        return Ok(None);
    };
    let tier = match ext.value {
        [0x0c, len, name @ ..] if usize::from(*len) == name.len() => std::str::from_utf8(name)
            .ok()
            .and_then(UnmeasuredTier::parse),
        _ => None,
    };
    tier.map(Some).ok_or_else(|| {
        Error::VerificationFailed("leaf carries an unreadable unmeasured-launch extension".into())
    })
}

/// Relying-party verification of an attested SVID served over `FETCH_SVID`.
///
/// This is the *outside* verifier for the North Star C9 leg: given the PEM cert
/// chain a pod serves, the trust bundle of the node that issued it, and the
/// measurements an operator expects, decide whether to trust the pod. Three teeth:
///
/// * **issuer** — the leaf must chain to `trust_bundle`. A leaf no trusted CA
///   signed is an `Err` whatever it carries, even when no attestation is required.
/// * **fail-closed on absent** — with `require_attestation` set, a served leaf that
///   carries no launch-attestation extension is an `Err`, NOT a vacuous pass.
///   (`AttestationRequirements::any().verify` would accept anything; this refuses a
///   cert that carries no measurement at all.) With `require_attestation` cleared,
///   an absent extension yields `Ok(None)`.
/// * **drift** — a present measurement outside `requirements` is an `Err`.
///
/// # Trust boundary (read this)
///
/// The measurement is the *node's own* SHA-256 of the kernel+rootfs it launched,
/// signed by the node's CA key. There is **no hardware root**: no TPM / SEV-SNP /
/// TDX quote, no UDS-in-ROM DICE identity binding the signing key to silicon. The
/// guarantee is therefore strictly conditional — *IF you trust this node's key,
/// THEN the pod was launched from an artifact with these measurements.* A
/// compromised node can sign any measurement. This is first-party **software**
/// launch attestation, not hardware attestation (ADR 0016 S3 roots it in the TPM).
///
/// # Errors
///
/// Any tooth above, or a chain that does not parse as PEM.
pub fn verify_attested_svid(
    chain_pem: &str,
    trust_bundle: &crate::TrustBundle,
    requirements: &AttestationRequirements,
    require_attestation: bool,
) -> Result<Option<LaunchAttestation>> {
    let leaf = pem::parse(chain_pem)
        .map_err(|e| Error::VerificationFailed(format!("cert PEM parse failed: {e}")))?;
    match issued_launch(leaf.contents(), trust_bundle)? {
        IssuedLaunch::Measured(att) => {
            requirements.verify(&att)?;
            Ok(Some(att))
        }
        IssuedLaunch::Unmeasured(tier) if require_attestation => {
            Err(Error::VerificationFailed(unmeasured(tier)))
        }
        IssuedLaunch::Unstated if require_attestation => Err(Error::VerificationFailed(
            "served SVID carries no launch-attestation extension (fail-closed)".to_string(),
        )),
        IssuedLaunch::Unmeasured(_) | IssuedLaunch::Unstated => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Streaming must not change the answer, including across chunk boundaries.
    ///
    /// `hash_file` reads a mebibyte at a time. A digest that were computed per chunk instead of
    /// over the concatenation would agree with the one-shot answer for every file smaller than
    /// the buffer and disagree for every file larger than it — which is to say it would pass a
    /// careless test and mismeasure every real rootfs.
    #[tokio::test]
    async fn streaming_a_file_hashes_it_exactly_as_reading_it_whole_does() {
        for len in [
            0usize,
            1,
            4096,
            (1 << 20) - 1, // one byte short of the buffer
            1 << 20,       // exactly the buffer
            (1 << 20) + 1, // one byte over: the first file that needs a second read
            (3 << 20) + 7, // several reads, last one partial
        ] {
            // Deterministic, non-repeating: a buffer bug that dropped or reordered a chunk
            // could hide behind uniform bytes.
            // `i % 251` is 0..=250, so the cast is lossless by construction; 251 is prime, which
            // is what makes the pattern non-repeating across the buffer boundary above.
            #[allow(clippy::cast_possible_truncation)]
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut f = NamedTempFile::new().unwrap();
            f.write_all(&bytes).unwrap();
            f.flush().unwrap();

            assert_eq!(
                hash_file(f.path()).await.unwrap(),
                hash_bytes(&bytes),
                "streamed and one-shot digests differ at {len} bytes"
            );
        }
    }

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

/// The issuer tooth (ADR 0016 S2). A real attested SVID, and a self-signed leaf
/// carrying the SAME launch extension bytes (OID `.1.1`) lifted off it: the
/// first verifies against its node's bundle and the forgery is refused, as is
/// the real one against a bundle that is not its issuer's.
#[cfg(test)]
mod issuer_tests {
    use super::*;
    use crate::{CaClient, CsrOptions, Identity, SelfSignedCa};
    use std::time::Duration;
    use x509_parser::prelude::{FromDer, X509Certificate};

    async fn attested(ca: &SelfSignedCa) -> (String, Identity, LaunchAttestation) {
        let identity = Identity::for_pod("test.local", "pod-1");
        let cs = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let att = LaunchAttestation::from_hashes([7u8; 32], [8u8; 32], [9u8; 32]);
        let cert = ca
            .sign_attested_csr(
                cs.csr(),
                cs.private_key(),
                &identity,
                Duration::from_secs(3600),
                &att,
            )
            .await
            .unwrap();
        (cert.chain_pem(), identity, att)
    }

    /// A self-signed leaf naming the same SPIFFE ID and carrying the launch
    /// extension's exact bytes, lifted from `real_pem`.
    fn forged_from(real_pem: &str, identity: &Identity) -> String {
        let real = pem::parse(real_pem).unwrap();
        let (_, parsed) = X509Certificate::from_der(real.contents()).unwrap();
        let ext = parsed
            .extensions()
            .iter()
            .find(|e| e.oid.as_bytes() == crate::oid::OID_NUCLEUS_ATTESTATION_BYTES)
            .expect("the real leaf carries the launch extension");
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.subject_alt_names = vec![rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(identity.to_spiffe_uri()).unwrap(),
        )];
        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            crate::oid::OID_NUCLEUS_ATTESTATION_TUPLE,
            ext.value.to_vec(),
        )];
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    #[tokio::test]
    async fn a_self_signed_leaf_carrying_the_launch_extension_is_refused() {
        let ca = SelfSignedCa::new("test.local").unwrap();
        let (real, identity, att) = attested(&ca).await;
        let exact = AttestationRequirements::exact(
            *att.kernel_hash(),
            *att.rootfs_hash(),
            *att.config_hash(),
        );

        // Non-vacuous: the node-issued leaf verifies against its issuer.
        let ok = verify_attested_svid(&real, ca.trust_bundle(), &exact, true)
            .expect("the node-issued leaf verifies");
        exact
            .verify(&ok.expect("a launch"))
            .expect("the measurement it carries");

        let forged = forged_from(&real, &identity);
        // The forgery really carries the claim: reading the extension alone accepts it.
        let leaf = pem::parse(&forged).unwrap();
        let lifted = extract_launch_attestation(leaf.contents()).expect("the forgery carries it");
        exact
            .verify(&lifted)
            .expect("the very measurement the node signed");

        for require in [true, false] {
            let err = verify_attested_svid(&forged, ca.trust_bundle(), &exact, require)
                .expect_err("a self-signed leaf is not issued by the node's CA");
            assert!(
                err.to_string().contains("not issued by a trusted CA"),
                "{err}"
            );
        }
        assert!(VerifiedLaunch::verify(leaf.contents(), ca.trust_bundle()).is_err());

        // The real leaf against a bundle that is not its issuer's.
        let stranger = SelfSignedCa::new("test.local").unwrap();
        assert!(verify_attested_svid(&real, stranger.trust_bundle(), &exact, true).is_err());
    }

    #[tokio::test]
    async fn verified_launch_names_the_spiffe_id_and_measurement() {
        let ca = SelfSignedCa::new("test.local").unwrap();
        let (real, identity, att) = attested(&ca).await;
        let leaf = pem::parse(&real).unwrap();
        let v = VerifiedLaunch::verify(leaf.contents(), ca.trust_bundle()).unwrap();
        AttestationRequirements::exact(*att.kernel_hash(), *att.rootfs_hash(), *att.config_hash())
            .verify(v.launch())
            .expect("the measurement it carries");
        assert_eq!(v.spiffe_id(), identity.to_spiffe_uri());
    }
}
