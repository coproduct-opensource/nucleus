//! Centralized OID definitions for Nucleus identity extensions.
//!
//! This module manages Object Identifiers (OIDs) used in X.509 certificates
//! and cryptographic extensions. OIDs are represented in two formats:
//!
//! - **DER encoding**: Binary format for protocol transmission (used in certificates)
//! - **Component form**: Numeric array form (used in certificate generation)
//!
//! # Production Registration
//!
//! Nucleus currently uses a placeholder Private Enterprise Number (PEN):
//! - **Current arc**: `1.3.6.1.4.1.57212.1.1` (unregistered)
//! - **Status**: Development/testing only
//!
//! **For production deployment:**
//! 1. Register a Private Enterprise Number with IANA at:
//!    <https://www.iana.org/assignments/enterprise-numbers/>
//! 2. Replace the `57212` component with your assigned PEN
//! 3. Update `ATTESTATION_OID_COMPONENTS` and `ATTESTATION_OID_DER` below
//! 4. Run tests to ensure compatibility
//!
//! Example after registration:
//! ```ignore
//! // After obtaining PEN 12345 from IANA:
//! const ATTESTATION_OID_COMPONENTS: &[u64] = &[1, 3, 6, 1, 4, 1, 12345, 1, 1];
//! ```

/// OID for SHA-256 hash algorithm (NIST standard).
///
/// - **OID**: `2.16.840.1.101.3.4.2.1`
/// - **Reference**: FIPS 180-4
/// - **DER encoding**: `0x60 0x86 0x48 0x01 0x65 0x03 0x04 0x02 0x01`
pub const SHA256_OID_DER: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

/// OID for Nucleus Launch Attestation (custom private enterprise OID).
///
/// - **OID**: `1.3.6.1.4.1.57212.1.1`
/// - **Status**: Unregistered placeholder for development
/// - **Arc components**: `iso.org.dod.internet.private.enterprise.57212.attestation.launch`
///
/// This OID identifies attestation extensions containing VM integrity measurements
/// following TCG DICE conventions. The numeric components form is used for certificate
/// generation libraries that expect component arrays.
///
/// **⚠️ WARNING**: This OID is not officially registered with IANA and may conflict
/// with other software. For production, obtain an official PEN and update both
/// constants below.
pub const ATTESTATION_OID_COMPONENTS: &[u64] = &[1, 3, 6, 1, 4, 1, 57212, 1, 1];

/// OID for Nucleus Launch Attestation in DER-encoded form.
///
/// This is the binary representation of `ATTESTATION_OID_COMPONENTS` suitable for
/// embedding in ASN.1 structures and X.509 extensions.
///
/// **Encoding breakdown**:
/// - `0x2b` = 1.3 (encoded as 1*40+3 = 43)
/// - `0x06 0x01 0x04 0x01` = 6.1.4.1 (single-byte VLQ per component)
/// - `0x83 0xbe 0x7c` = 57212 (three-byte VLQ: 57212 = 3×128² + 62×128 + 124)
/// - `0x01 0x01` = 1.1 (attestation.launch subarcs)
pub const ATTESTATION_OID_DER: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbe, 0x7c, // 1.3.6.1.4.1.57212
    0x01, 0x01, // .1.1 (attestation.launch)
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a single OID component in VLQ (base-128) form.
    ///
    /// VLQ encoding rules:
    /// 1. Split the value into 7-bit groups.
    /// 2. Write groups most-significant first.
    /// 3. Set the high bit (0x80) on every byte except the last.
    fn vlq_encode(value: u64) -> Vec<u8> {
        if value == 0 {
            return vec![0x00];
        }
        let mut bytes = Vec::new();
        let mut v = value;
        while v > 0 {
            bytes.push((v & 0x7F) as u8);
            v >>= 7;
        }
        bytes.reverse();
        let last = bytes.len() - 1;
        for b in &mut bytes[..last] {
            *b |= 0x80;
        }
        bytes
    }

    /// Encodes a full OID component array into DER bytes (without tag/length wrapper).
    ///
    /// The first two arc values are combined as `first*40 + second`.
    fn encode_oid_components(components: &[u64]) -> Vec<u8> {
        assert!(components.len() >= 2, "OID must have at least 2 arcs");
        let mut bytes = Vec::new();
        // First two components combined
        let first_byte = components[0] * 40 + components[1];
        bytes.extend_from_slice(&vlq_encode(first_byte));
        for &c in &components[2..] {
            bytes.extend_from_slice(&vlq_encode(c));
        }
        bytes
    }

    #[test]
    fn test_oid_constants_exist() {
        assert!(!SHA256_OID_DER.is_empty());
        assert!(!ATTESTATION_OID_COMPONENTS.is_empty());
        assert!(!ATTESTATION_OID_DER.is_empty());
    }

    #[test]
    fn test_attestation_oid_der_starts_with_arc() {
        // First byte encodes 1.3 as 1*40+3 = 43 = 0x2b
        assert_eq!(ATTESTATION_OID_DER[0], 0x2b, "OID should start with 1.3 arc (0x2b)");
    }

    #[test]
    fn test_sha256_oid_der_nist_compliance() {
        // SHA-256 OID (2.16.840.1.101.3.4.2.1) starts with 2.16 = 2*40+16 = 96 = 0x60
        assert_eq!(SHA256_OID_DER[0], 0x60, "SHA-256 OID should start with 0x60 (arc 2.16)");
        // 840 encodes as two VLQ bytes: 0x86 0x48
        assert_eq!(SHA256_OID_DER[1], 0x86, "second byte of SHA-256 OID should be 0x86");
        assert_eq!(SHA256_OID_DER[2], 0x48, "third byte of SHA-256 OID should be 0x48");
        // Total length for 2.16.840.1.101.3.4.2.1 is 9 bytes
        assert_eq!(SHA256_OID_DER.len(), 9, "SHA-256 OID DER should be 9 bytes");
    }

    /// Verifies ATTESTATION_OID_DER is the exact DER encoding of ATTESTATION_OID_COMPONENTS.
    ///
    /// This is the key consistency test: both constants must encode the same OID.
    #[test]
    fn test_attestation_oid_der_matches_components() {
        let computed = encode_oid_components(ATTESTATION_OID_COMPONENTS);
        assert_eq!(
            ATTESTATION_OID_DER,
            computed.as_slice(),
            "ATTESTATION_OID_DER must be the DER encoding of ATTESTATION_OID_COMPONENTS.\n\
             Expected (from components): {:02x?}\n\
             Got (constant):             {:02x?}",
            computed,
            ATTESTATION_OID_DER,
        );
    }

    #[test]
    fn test_attestation_oid_components_values() {
        // 1.3.6.1.4.1.57212.1.1
        assert_eq!(ATTESTATION_OID_COMPONENTS, &[1, 3, 6, 1, 4, 1, 57212, 1, 1]);
    }

    #[test]
    fn test_vlq_encode_57212() {
        // Verify the VLQ encoding of the PEN (57212) used in the attestation OID.
        // 57212 = 3×128² + 62×128 + 124  →  [0x83, 0xBE, 0x7C]
        let encoded = vlq_encode(57212);
        assert_eq!(encoded, vec![0x83, 0xbe, 0x7c]);
    }

    #[test]
    fn test_vlq_encode_known_values() {
        assert_eq!(vlq_encode(0), vec![0x00]);
        assert_eq!(vlq_encode(1), vec![0x01]);
        assert_eq!(vlq_encode(127), vec![0x7f]);
        assert_eq!(vlq_encode(128), vec![0x81, 0x00]);
        assert_eq!(vlq_encode(840), vec![0x86, 0x48]); // from SHA-256 OID
    }
}
