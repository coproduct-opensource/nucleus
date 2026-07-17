//! Witness cosignature minting per [c2sp.org/tlog-cosignature].
//!
//! A cosignature/v1 line is:
//!
//! ```text
//! — <witness-name> base64(keyID(4) || timestamp(8, big-endian) || ed25519_sig(64))
//! ```
//!
//! The signed message is:
//!
//! ```text
//! cosignature/v1\n
//! time <unix>\n
//! <full checkpoint note body, including its final newline>
//! ```
//!
//! `keyID = SHA-256(name || 0x0A || 0x04 || pubkey)[:4]` — exactly
//! [`nucleus_lineage::ed25519_key_id`] with the cosignature sig-type
//! byte ([`nucleus_lineage::SIG_TYPE_COSIGNATURE`]). We REUSE that key-ID
//! computation and the lineage Ed25519 signing primitive; the only
//! net-new logic is the cosignature/v1 message framing + the
//! `keyID||timestamp||sig` payload layout.
//!
//! [c2sp.org/tlog-cosignature]: https://c2sp.org/tlog-cosignature

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nucleus_lineage::{ed25519_key_id, SIG_LINE_PREFIX, SIG_TYPE_COSIGNATURE};

/// A witness signing identity: an Ed25519 key plus its C2SP name.
pub struct WitnessKey {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    name: String,
}

impl WitnessKey {
    /// Construct from a 32-byte Ed25519 seed and a C2SP witness name.
    pub fn from_seed(seed: [u8; 32], name: impl Into<String>) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            name: name.into(),
        }
    }

    /// The witness's C2SP name (the `key_name` in cosignature lines).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The 32-byte Ed25519 verifying key — publish out-of-band so
    /// verifiers can place this witness in a Sigsum policy.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// The 4-byte C2SP key ID under the cosignature sig-type byte
    /// (`SHA-256(name || 0x0A || 0x04 || pubkey)[:4]`).
    pub fn key_id(&self) -> [u8; 4] {
        ed25519_key_id(
            &self.name,
            SIG_TYPE_COSIGNATURE,
            &self.verifying_key.to_bytes(),
        )
    }

    /// Build the exact cosignature/v1 signed message for a checkpoint
    /// note body at `timestamp` (unix seconds).
    ///
    /// `note_body` MUST be the whole checkpoint note body INCLUDING its
    /// final newline and EXCLUDING any signature lines — i.e.
    /// [`crate::parse::Checkpoint::body_bytes`].
    pub fn cosignature_message(timestamp: u64, note_body: &[u8]) -> Vec<u8> {
        let mut msg = Vec::with_capacity(note_body.len() + 32);
        msg.extend_from_slice(b"cosignature/v1\n");
        msg.extend_from_slice(format!("time {timestamp}\n").as_bytes());
        msg.extend_from_slice(note_body);
        msg
    }

    /// Mint a cosignature/v1 line over `note_body` at `timestamp`.
    ///
    /// `timestamp` is unix seconds and MUST be non-zero (the spec
    /// requires a real time). Returns the full `— <name> <base64>` line
    /// (no trailing newline).
    pub fn cosign_line(&self, note_body: &[u8], timestamp: u64) -> String {
        debug_assert!(timestamp != 0, "cosignature timestamp must be non-zero");
        let msg = Self::cosignature_message(timestamp, note_body);
        let sig: Signature = self.signing_key.sign(&msg);
        let key_id = self.key_id();
        // Payload: keyID(4) || timestamp(8, big-endian) || sig(64).
        let mut payload = Vec::with_capacity(4 + 8 + 64);
        payload.extend_from_slice(&key_id);
        payload.extend_from_slice(&timestamp.to_be_bytes());
        payload.extend_from_slice(&sig.to_bytes());
        format!("{SIG_LINE_PREFIX}{} {}", self.name, B64.encode(&payload))
    }
}

/// Verify a cosignature/v1 line minted by a witness with `pubkey`.
/// Returns the recovered `(timestamp, key_name)` on success. Used by the
/// 2-of-2 integration test and any policy-side verification.
///
/// This is the inverse of [`WitnessKey::cosign_line`]: it re-derives the
/// signed message from `note_body` + the embedded timestamp and checks
/// the Ed25519 signature.
pub fn verify_cosign_line(
    line: &str,
    note_body: &[u8],
    pubkey: &[u8; 32],
) -> Result<(u64, String), CosignVerifyError> {
    let parsed = nucleus_lineage::parse_signature_line(line)
        .map_err(|e| CosignVerifyError::Malformed(e.to_string()))?;
    // payload after the 4-byte key_id is timestamp(8) || sig(64).
    if parsed.signature.len() != 8 + 64 {
        return Err(CosignVerifyError::BadPayloadLen {
            got: parsed.signature.len(),
        });
    }
    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&parsed.signature[..8]);
    let timestamp = u64::from_be_bytes(ts_bytes);
    if timestamp == 0 {
        return Err(CosignVerifyError::ZeroTimestamp);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&parsed.signature[8..]);
    let signature = Signature::from_bytes(&sig_bytes);
    let vk = VerifyingKey::from_bytes(pubkey).map_err(|_| CosignVerifyError::BadKey)?;
    let msg = WitnessKey::cosignature_message(timestamp, note_body);
    vk.verify_strict(&msg, &signature)
        .map_err(|_| CosignVerifyError::SignatureInvalid)?;
    Ok((timestamp, parsed.key_name))
}

/// Errors from [`verify_cosign_line`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CosignVerifyError {
    #[error("cosignature line malformed: {0}")]
    Malformed(String),
    #[error("cosignature payload after key_id is {got} bytes; expected 72 (8 ts + 64 sig)")]
    BadPayloadLen { got: usize },
    #[error("cosignature timestamp is zero")]
    ZeroTimestamp,
    #[error("witness public key is not a valid Ed25519 key")]
    BadKey,
    #[error("cosignature signature did not verify")]
    SignatureInvalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosign_round_trip_verifies() {
        let wk = WitnessKey::from_seed([7u8; 32], "nucleus.witness/a");
        let note_body = b"nucleus.example/log\n5\ncm9vdA==\n";
        let line = wk.cosign_line(note_body, 1_700_000_000);
        let (ts, name) = verify_cosign_line(&line, note_body, &wk.verifying_key_bytes()).unwrap();
        assert_eq!(ts, 1_700_000_000);
        assert_eq!(name, "nucleus.witness/a");
    }

    #[test]
    fn cosign_line_has_em_dash_and_name() {
        let wk = WitnessKey::from_seed([8u8; 32], "nucleus.witness/b");
        let line = wk.cosign_line(b"body\n", 1234);
        assert!(line.starts_with("\u{2014} nucleus.witness/b "));
    }

    #[test]
    fn verify_rejects_wrong_note_body() {
        let wk = WitnessKey::from_seed([9u8; 32], "w");
        let line = wk.cosign_line(b"original\n", 1234);
        let err = verify_cosign_line(&line, b"tampered\n", &wk.verifying_key_bytes()).unwrap_err();
        assert_eq!(err, CosignVerifyError::SignatureInvalid);
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let wk = WitnessKey::from_seed([10u8; 32], "w");
        let other = WitnessKey::from_seed([11u8; 32], "w");
        let line = wk.cosign_line(b"body\n", 1234);
        let err = verify_cosign_line(&line, b"body\n", &other.verifying_key_bytes()).unwrap_err();
        assert_eq!(err, CosignVerifyError::SignatureInvalid);
    }

    /// M-2 strong-binding regression (site: `verify_cosign_line`, the
    /// `vk.verify_strict` call). Crafts a cosignature line whose payload
    /// carries the identity-triple signature (R = identity encoding,
    /// s = 0) and verifies it against the Ed25519 identity/neutral key
    /// (`[1, 0, ..., 0]`). That triple satisfies the cofactored
    /// verification equation for EVERY message, so non-strict `verify()`
    /// ACCEPTS it — a key-substitution forgery — while `verify_strict()`
    /// rejects small-order keys. If line 134 is reverted to
    /// `vk.verify(...)`, assertion (ii) below fails.
    #[test]
    fn small_order_key_is_rejected_by_verify_strict() {
        // (i) No regression: an honest cosignature still verifies.
        let wk = WitnessKey::from_seed([42u8; 32], "nucleus.witness/honest");
        let note_body = b"nucleus.example/log\n5\ncm9vdA==\n";
        let honest_line = wk.cosign_line(note_body, 1_700_000_000);
        verify_cosign_line(&honest_line, note_body, &wk.verifying_key_bytes())
            .expect("honest cosignature must still verify through verify_strict");

        // (ii) Strong binding: craft a line embedding the identity-triple
        // signature. `verify_cosign_line` uses the passed pubkey (not the
        // key_id), so the 4 key_id bytes are arbitrary. Payload layout is
        // keyID(4) || timestamp(8, big-endian) || sig(64).
        let mut id = [0u8; 32];
        id[0] = 1; // identity/neutral point encoding, a small-order key
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&id); // R = identity, s = 0
        let timestamp: u64 = 1_700_000_000;
        let mut payload = Vec::with_capacity(4 + 8 + 64);
        payload.extend_from_slice(&[0u8; 4]); // arbitrary key_id
        payload.extend_from_slice(&timestamp.to_be_bytes());
        payload.extend_from_slice(&sig_bytes);
        let forged_line = format!(
            "{SIG_LINE_PREFIX}nucleus.witness/honest {}",
            B64.encode(&payload)
        );
        assert_eq!(
            verify_cosign_line(&forged_line, note_body, &id).unwrap_err(),
            CosignVerifyError::SignatureInvalid,
            "small-order identity key must be REJECTED by verify_strict; \
             a revert to non-strict verify() would ACCEPT this forgery"
        );
    }

    #[test]
    fn key_id_uses_cosignature_sig_type() {
        let wk = WitnessKey::from_seed([12u8; 32], "name");
        let expected = ed25519_key_id("name", SIG_TYPE_COSIGNATURE, &wk.verifying_key_bytes());
        assert_eq!(wk.key_id(), expected);
    }

    #[test]
    fn message_framing_is_exact() {
        let msg = WitnessKey::cosignature_message(1679315147, b"origin\n5\nroot\n");
        assert_eq!(
            msg,
            b"cosignature/v1\ntime 1679315147\norigin\n5\nroot\n".to_vec()
        );
    }
}
