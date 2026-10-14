//! Ed25519 trust roots, checked with `verify_strict` only (audit finding M-3).

use ed25519_dalek::{Signature, VerifyingKey};

use crate::roots::SigRefusal;

/// The SPKI DER prefix of an Ed25519 public key (RFC 8410): SEQUENCE, AlgorithmIdentifier
/// `1.3.101.112`, BIT STRING of 33 bytes with no unused bits. The key follows as 32 bytes.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// An Ed25519 key from SPKI DER, or `None` if the DER is not exactly one, or the key is a
/// small-order point.
pub(crate) fn key_from_spki(der: &[u8]) -> Option<VerifyingKey> {
    let raw = der.strip_prefix(SPKI_PREFIX.as_slice())?;
    let raw: [u8; 32] = raw.try_into().ok()?;
    let key = VerifyingKey::from_bytes(&raw).ok()?;
    (!key.is_weak()).then_some(key)
}

/// Check a 64-byte Ed25519 signature over `message`, strictly.
pub(crate) fn check(key: &VerifyingKey, message: &[u8], raw: &[u8]) -> Result<(), SigRefusal> {
    let raw: [u8; 64] = raw.try_into().map_err(|_| SigRefusal::Encoding)?;
    let signature = Signature::from_bytes(&raw);
    key.verify_strict(message, &signature)
        .map_err(|_| SigRefusal::DoesNotVerify)
}
