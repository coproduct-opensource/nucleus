//! Authenticated-identity binding for the durable credit ledger.
//!
//! The stateful credit endpoints persist standing keyed by `identity`. Left
//! self-asserted, anyone could accrue under any id and claim another agent's
//! receipts (the documented interim gap). To close it, `POST
//! /v1/credit/{agent_id}/accrue` REQUIRES a detached Ed25519 signature over the
//! EXACT request body bytes, and **the signer's own public key IS the
//! identity**: the canonical ledger key is `hex(vk)`, derived from the verified
//! key — never from a caller-chosen path string. An attacker can mint keys but
//! cannot accrue under an identity it does not control, because it cannot forge
//! that identity's signature over the body.
//!
//! ## Honesty boundary (do NOT overclaim)
//!
//! This is a **detached Ed25519 signature** — the same primitive the
//! C2SP-aligned `/v1/witness/peer-sth` endpoint already ships (see
//! [`crate::witness`]) — NOT a literal RFC-7515 JWS. There is no EdDSA-JWS
//! verifier anywhere in the tree, and closing this gap adds **no new
//! dependency**: it reuses the `ed25519-dalek` already pulled in for STH
//! signing. We verify over the transmitted bytes directly, so no JSON
//! canonicalization (JCS) is required — the signature covers exactly what the
//! handler parses.
//!
//! There is no nonce/timestamp/expiry, so a captured signature stays valid
//! forever; this is replay-SAFE-by-idempotence (a replayed envelope can only
//! re-assert the signer's own already-counted receipts — the per-identity
//! `receipt_hash` dedup in [`nucleus_creditworthiness::store`] makes it a
//! no-op), not replay-PREVENTED. Signature freshness (a signed `issued_at` /
//! nonce) is a future extension and out of scope for closing the identity gap.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::error::VerifyApiError;

/// Request header carrying the agent's Ed25519 public key: lowercase hex of the
/// 32-byte verifying key (64 hex chars). This key — once its signature
/// verifies — IS the agent's identity.
pub const PUBKEY_HEADER: &str = "x-nucleus-agent-pubkey";

/// Request header carrying the detached signature: STANDARD base64 of the
/// 64-byte Ed25519 signature over the exact request body bytes.
pub const SIGNATURE_HEADER: &str = "x-nucleus-signature";

/// Verify a detached Ed25519 signature `sig_b64` (STANDARD base64 of 64 bytes)
/// over `msg`, made by the key `pubkey_hex` (64 hex chars of the 32-byte key).
///
/// Returns the parsed [`VerifyingKey`] on success so the caller derives the
/// canonical identity from the SAME key the signature was checked against (no
/// TOCTOU between "what we verified" and "what we key the ledger by").
///
/// Every failure mode — malformed / short / long pubkey hex, a non-point key,
/// malformed / wrong-length signature, or a signature that does not verify over
/// `msg` — collapses to [`VerifyApiError::Unauthorized`]. Fail closed: this
/// function never returns a key it did not just verify a signature for. Mirrors
/// the witness federation accept-mechanic ([`crate::witness`]): hex-decode the
/// key to `[u8; 32]` (the "must be 32 bytes" check), base64-decode the sig to
/// `[u8; 64]`, then `vk.verify(msg, &sig)`.
pub fn verify_detached_ed25519(
    pubkey_hex: &str,
    sig_b64: &str,
    msg: &[u8],
) -> Result<VerifyingKey, VerifyApiError> {
    // Parse the verifying key (mirrors witness.rs "must be 32 bytes").
    let key_bytes = hex::decode(pubkey_hex.trim())
        .map_err(|_| VerifyApiError::Unauthorized("agent pubkey is not valid hex".into()))?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyApiError::Unauthorized("agent pubkey must be 32 bytes".into()))?;
    let vk = VerifyingKey::from_bytes(&key_array).map_err(|_| {
        VerifyApiError::Unauthorized("agent pubkey is not a valid Ed25519 point".into())
    })?;

    // Parse the detached signature (STANDARD base64 of 64 bytes).
    let sig_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, sig_b64.trim())
            .map_err(|_| VerifyApiError::Unauthorized("signature is not valid base64".into()))?;
    let sig_array: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| VerifyApiError::Unauthorized("signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_array);

    // The integrity check: the signature must verify over the EXACT bytes the
    // handler will parse. A single flipped body byte fails here.
    vk.verify_strict(msg, &signature).map_err(|_| {
        VerifyApiError::Unauthorized("signature did not verify over the request body".into())
    })?;
    Ok(vk)
}

/// The canonical, dependency-free ledger identity for a verifying key: lowercase
/// hex of its 32 raw bytes. Matches the `peer_pubkey_hex` convention
/// [`crate::witness`] uses (lowercased on store/lookup). This DERIVED value —
/// never a caller-supplied path string — is the store key.
pub fn canonical_id(vk: &VerifyingKey) -> String {
    hex::encode(vk.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn sign(sk: &SigningKey, msg: &[u8]) -> (String, String) {
        let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());
        let sig_b64 = base64::engine::general_purpose::STANDARD.encode(sk.sign(msg).to_bytes());
        (pubkey_hex, sig_b64)
    }

    #[test]
    fn round_trips_a_real_signature() {
        let sk = key(1);
        let msg = br#"{"receipts":[],"max_defection_gain_micro":1000000}"#;
        let (pk, sig) = sign(&sk, msg);
        let vk = verify_detached_ed25519(&pk, &sig, msg).expect("valid signature must verify");
        // The returned key is exactly the signer's key.
        assert_eq!(vk.to_bytes(), sk.verifying_key().to_bytes());
    }

    #[test]
    fn rejects_a_single_flipped_body_byte() {
        let sk = key(2);
        let msg = b"the exact bytes that were signed";
        let (pk, sig) = sign(&sk, msg);
        let mut tampered = msg.to_vec();
        tampered[0] ^= 0x01;
        assert!(matches!(
            verify_detached_ed25519(&pk, &sig, &tampered),
            Err(VerifyApiError::Unauthorized(_))
        ));
    }

    #[test]
    fn rejects_a_single_flipped_signature_byte() {
        let sk = key(3);
        let msg = b"body";
        let (pk, sig) = sign(&sk, msg);
        let mut raw = base64::engine::general_purpose::STANDARD
            .decode(&sig)
            .unwrap();
        raw[0] ^= 0x01;
        let bad_sig = base64::engine::general_purpose::STANDARD.encode(&raw);
        assert!(matches!(
            verify_detached_ed25519(&pk, &bad_sig, msg),
            Err(VerifyApiError::Unauthorized(_))
        ));
    }

    #[test]
    fn rejects_a_signature_by_a_different_key() {
        let signer = key(4);
        let attacker = key(5);
        let msg = b"body";
        let (_, sig) = sign(&signer, msg);
        // Present the attacker's pubkey with the signer's signature.
        let attacker_pk = hex::encode(attacker.verifying_key().to_bytes());
        assert!(matches!(
            verify_detached_ed25519(&attacker_pk, &sig, msg),
            Err(VerifyApiError::Unauthorized(_))
        ));
    }

    /// M-2 strong-binding regression (site: `verify_detached_ed25519`,
    /// the `vk.verify_strict` call). The Ed25519 identity/neutral key
    /// (`[1, 0, ..., 0]`) with the identity-triple signature
    /// (R = identity encoding, s = 0) satisfies the cofactored
    /// verification equation for EVERY message, so non-strict `verify()`
    /// ACCEPTS it — a key-substitution forgery. `verify_strict()` rejects
    /// small-order keys. If line 86 is reverted to `vk.verify(...)`,
    /// assertion (ii) below fails.
    #[test]
    fn small_order_key_is_rejected_by_verify_strict() {
        // (i) No regression: an honest detached signature still verifies.
        let sk = key(7);
        let msg = b"the exact bytes that were signed";
        let (pk, sig) = sign(&sk, msg);
        verify_detached_ed25519(&pk, &sig, msg)
            .expect("honest signature must still verify through verify_strict");

        // (ii) Strong binding: identity key + identity-triple signature.
        let mut id = [0u8; 32];
        id[0] = 1; // identity/neutral point encoding, a small-order key
        let identity_pk_hex = hex::encode(id);
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&id); // R = identity, s = 0
        let identity_sig_b64 = base64::engine::general_purpose::STANDARD.encode(sig_bytes);
        assert!(
            matches!(
                verify_detached_ed25519(&identity_pk_hex, &identity_sig_b64, b"any body"),
                Err(VerifyApiError::Unauthorized(_))
            ),
            "small-order identity key must be REJECTED by verify_strict; \
             a revert to non-strict verify() would ACCEPT this forgery"
        );
    }

    #[test]
    fn rejects_malformed_pubkey() {
        let sk = key(6);
        let msg = b"body";
        let (_, sig) = sign(&sk, msg);
        // Non-hex.
        assert!(matches!(
            verify_detached_ed25519("not-hex!!", &sig, msg),
            Err(VerifyApiError::Unauthorized(_))
        ));
        // Wrong length (valid hex, 31 bytes).
        let short = hex::encode([0u8; 31]);
        assert!(matches!(
            verify_detached_ed25519(&short, &sig, msg),
            Err(VerifyApiError::Unauthorized(_))
        ));
    }

    #[test]
    fn rejects_malformed_signature() {
        let sk = key(7);
        let msg = b"body";
        let pk = hex::encode(sk.verifying_key().to_bytes());
        // Not base64.
        assert!(matches!(
            verify_detached_ed25519(&pk, "@@@not base64@@@", msg),
            Err(VerifyApiError::Unauthorized(_))
        ));
        // Valid base64 but wrong length (63 bytes).
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 63]);
        assert!(matches!(
            verify_detached_ed25519(&pk, &short, msg),
            Err(VerifyApiError::Unauthorized(_))
        ));
    }

    #[test]
    fn canonical_id_is_lowercase_64_char_hex() {
        let sk = key(8);
        let id = canonical_id(&sk.verifying_key());
        assert_eq!(id.len(), 64);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(id, id.to_lowercase());
        // It is exactly hex of the raw verifying-key bytes.
        assert_eq!(id, hex::encode(sk.verifying_key().to_bytes()));
    }
}
