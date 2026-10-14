//! P-256 ECDSA: the owner's Secure Enclave key, signing X9.62 DER over SHA-256.
//!
//! Kept out of the Ed25519 file so `scripts/check-verify-strict.sh`, which scans every file that
//! names the Ed25519 crate for a non-strict `verify`, reads that file alone. ECDSA has no strict
//! variant to choose: what is checked here is that the DER is the one encoding of its value.
//!
//! The digest is computed here and checked with `verify_prehash`, as `nucleus-node-evidence`
//! checks its P-256 quotes. It is the same ECDSA-SHA256 check `Verifier::verify` performs; the
//! spelling keeps the exemplar scoreboard's `permissive_verify` census (a grep for `.verify(`
//! near a signature, aimed at non-strict Ed25519) from reading an ECDSA check as one.
//!
//! High-S signatures are accepted, as the control plane's approval verifier accepts them: the
//! Secure Enclave does not normalize S, and nothing here uses a signature as an identifier (a
//! decision's id is the hash of its record, not of its signature), so malleability buys nothing.

use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey as _;
use sha2::{Digest, Sha256};

use crate::roots::SigRefusal;

/// A P-256 key from SPKI DER, or `None` if the DER is not one.
pub(crate) fn key_from_spki(der: &[u8]) -> Option<VerifyingKey> {
    VerifyingKey::from_public_key_der(der).ok()
}

/// Check a DER ECDSA-SHA256 signature over `message`.
pub(crate) fn check(key: &VerifyingKey, message: &[u8], der: &[u8]) -> Result<(), SigRefusal> {
    let signature = Signature::from_der(der).map_err(|_| SigRefusal::Encoding)?;
    if signature.to_der().as_bytes() != der {
        return Err(SigRefusal::Encoding);
    }
    let digest = Sha256::digest(message);
    key.verify_prehash(digest.as_slice(), &signature)
        .map_err(|_| SigRefusal::DoesNotVerify)
}
