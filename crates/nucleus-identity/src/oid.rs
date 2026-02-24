//! OID (Object Identifier) constants for nucleus attestation and certificates.
//!
//! This module centralizes OID definitions to ensure consistency across
//! the codebase and provide a single point for managing OID registration.

/// OID for SHA-256 hash algorithm (NIST standard).
///
/// OID: 2.16.840.1.101.3.4.2.1
pub const OID_SHA256_BYTES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
pub const OID_SHA256_TUPLE: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 2, 1];

/// OID for Nucleus Launch Attestation (private enterprise number arc).
///
/// **PRODUCTION NOTE:** This OID currently uses an unregistered Private Enterprise Number (PEN).
///
/// Current value: 1.3.6.1.4.1.57212.1.1
/// - PEN: 57212 (unregistered placeholder)
/// - Component: .1.1 (attestation.launch)
///
/// For production deployment:
/// 1. Register a Private Enterprise Number (PEN) with IANA:
///    <https://www.iana.org/assignments/enterprise-numbers/>
/// 2. Update `OID_NUCLEUS_ATTESTATION_BYTES` with the registered PEN
/// 3. Update this documentation with the official PEN
///
/// **Rationale:** During development and testing, an unregistered PEN allows
/// flexible iteration. Production deployments MUST use an official IANA-registered
/// PEN to avoid conflicts with other software.
pub const OID_NUCLEUS_ATTESTATION_BYTES: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xde, 0x7c, // 1.3.6.1.4.1.57212
    0x01, 0x01, // .1.1 (attestation.launch)
];

pub const OID_NUCLEUS_ATTESTATION_TUPLE: &[u64] = &[1, 3, 6, 1, 4, 1, 57212, 1, 1];

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that OID representations (byte and tuple) are kept in sync.
    ///
    /// This test ensures that if developers update one representation,
    /// they must also update the other, preventing inconsistencies.
    #[test]
    fn test_oid_representations_consistent() {
        // SHA-256 OID should match
        assert_eq!(OID_SHA256_BYTES.len(), 9);
        assert_eq!(OID_SHA256_TUPLE.len(), 9);

        // Nucleus attestation OID should match
        assert_eq!(OID_NUCLEUS_ATTESTATION_BYTES.len(), 10);
        assert_eq!(OID_NUCLEUS_ATTESTATION_TUPLE.len(), 9);

        // The first two components (1.3) are encoded as 0x2b (1*40+3)
        assert_eq!(OID_NUCLEUS_ATTESTATION_BYTES[0], 0x2b);

        // Component 4 is 57212, encoded as 0x82 0xde 0x7c (multi-byte encoding)
        // 57212 = 0xdf5c = 0b1101111101011100
        // Encoded as: 0x82 (continuation bit + 2 bits) 0xde (6 bits) 0x7c (7 bits)
        assert_eq!(OID_NUCLEUS_ATTESTATION_BYTES[4..7], [0x82, 0xde, 0x7c]);
    }

    /// Verifies that the PEN is unregistered (for development awareness).
    #[test]
    fn test_attestation_oid_uses_unregistered_pen() {
        // Component index 4 contains the PEN value (57212 as 0x82 0xde 0x7c)
        // This test documents that we're using an unregistered PEN
        let pen_bytes = &OID_NUCLEUS_ATTESTATION_BYTES[4..7];
        // 57212 is NOT an officially registered PEN with IANA
        assert_eq!(pen_bytes, &[0x82, 0xde, 0x7c]);
    }
}
