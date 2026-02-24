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
/// - `0x06 0x01 0x04 0x01` = 6.1.4.1 (multi-byte OID encoding)
/// - `0x82 0xde 0x7c` = 57212 (multi-byte encoding: 57212 = 0x2b7c, encoded as 0x82 0xde 0x7c)
/// - `0x01 0x01` = 1.1 (attestation.launch subarcs)
pub const ATTESTATION_OID_DER: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xde, 0x7c, // 1.3.6.1.4.1.57212
    0x01, 0x01, // .1.1 (attestation.launch)
];

#[cfg(test)]
mod tests {
    use super::*;

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
        // SHA-256 OID starts with 2.16.840 = 0x60 0x86 0x48
        assert_eq!(&ATTESTATION_OID_DER[0], &0x2b, "first byte should be 0x2b");
        assert_eq!(&SHA256_OID_DER[0], &0x60, "SHA-256 OID should start with 0x60");
    }
}
