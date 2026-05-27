//! Signed Tree Heads (STHs) for the Merkle-chained lineage log.
//!
//! A [`SignedTreeHead`] is the transparency-log primitive that lets an
//! auditor verify the lineage sink hasn't been tampered with: it carries
//! `(tree_size, timestamp, root_hash)` signed by a [`TreeWitness`]. The
//! signed bytes follow a fixed canonical encoding so the same STH validates
//! across processes regardless of JSON formatting.
//!
//! Layout broadly mirrors the `SignedTreeHeadDataV2` structure from
//! RFC 9162 §4.10 (Certificate Transparency v2.0); we keep it minimal so
//! a future external witness (e.g., a Sigstore-Rekor-style tile log) can
//! adopt the same payload.
//!
//! # Witness model
//!
//! Witnessing is abstracted behind the [`TreeWitness`] trait so we can
//! swap implementations without touching the sink:
//!
//! - [`Ed25519Witness`] — in-process Ed25519, suitable for single-node
//!   deployments and tests. The key material lives in the same process
//!   that emits the lineage; binds tampering only against attackers who
//!   don't have the key.
//! - *(future)* a `RekorWitness` that ships STHs to an external Sigstore
//!   Rekor v2 tile log. Drop-in: implements the same trait.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Errors surfaced by [`TreeWitness::sign_sth`] and [`SignedTreeHead::verify`].
#[derive(Debug, Error)]
pub enum WitnessError {
    /// The witness's signing backend failed (e.g., KMS unreachable).
    #[error("witness backend failure: {0}")]
    Backend(String),
    /// The signature did not match the canonical STH bytes.
    #[error("signature did not verify for kid {0}")]
    InvalidSignature(String),
    /// The witness's verifying key id did not match this STH's kid.
    #[error("kid mismatch: STH says {sth_kid}, witness offers {witness_kid}")]
    KidMismatch {
        sth_kid: String,
        witness_kid: String,
    },
    /// The system clock returned an error.
    #[error("system clock failure")]
    Clock,
    /// The witness's verifying key bytes were not a valid Ed25519 public key.
    #[error("invalid verifying key")]
    InvalidVerifyingKey,
}

/// A signed checkpoint of the lineage Merkle tree.
///
/// `tree_size` is the leaf count at the moment of signing; `root_hash` is
/// the RFC 6962 Merkle Tree Hash over those leaves; `timestamp_ms` is the
/// witness's wall-clock reading at signing time (POSIX milliseconds, no
/// monotonicity guarantee across witnesses). `witness_sig` is the raw
/// Ed25519 signature over [`canonical_sth_bytes`].
///
/// Wire format is forward-compatible serde JSON — never remove or rename
/// fields; new fields must be `#[serde(default)]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Number of leaves committed at sign time.
    pub tree_size: u64,
    /// Wall-clock timestamp in Unix milliseconds at sign time.
    pub timestamp_ms: u64,
    /// RFC 6962 Merkle Tree Hash root, hex-encoded (lowercase, no `0x`).
    pub root_hash_hex: String,
    /// Witness key id (matches [`TreeWitness::kid`]).
    pub witness_kid: String,
    /// Ed25519 signature over [`canonical_sth_bytes`], base64-encoded.
    #[serde(with = "base64_bytes")]
    pub witness_sig: Vec<u8>,
}

impl SignedTreeHead {
    /// Verify this STH's signature against a [`TreeWitness`] (which can
    /// supply the verifying key for the matching kid).
    pub fn verify(&self, witness: &dyn TreeWitness) -> Result<(), WitnessError> {
        if witness.kid() != self.witness_kid {
            return Err(WitnessError::KidMismatch {
                sth_kid: self.witness_kid.clone(),
                witness_kid: witness.kid().to_string(),
            });
        }
        let root = hex_decode_32(&self.root_hash_hex)
            .ok_or_else(|| WitnessError::Backend("malformed root_hash_hex".into()))?;
        let canonical = canonical_sth_bytes(self.tree_size, self.timestamp_ms, &root);
        witness.verify_canonical(&canonical, &self.witness_sig)
    }
}

/// Canonical bytes that a [`TreeWitness`] signs to produce an STH.
///
/// Encoding (matches the spirit of RFC 9162 §4.10's STH-over-tls-bytes;
/// we use big-endian fixed-width integers for clock-stable parsing):
///
/// 1. 8 bytes — `tree_size` (big-endian u64)
/// 2. 8 bytes — `timestamp_ms` (big-endian u64)
/// 3. 32 bytes — `root_hash` (raw Merkle Tree Hash bytes)
///
/// Total: 48 bytes. No domain separator: the signature scope is "this is
/// a nucleus-lineage STH" and is established out-of-band by the verifier
/// knowing which kid maps to which log.
pub fn canonical_sth_bytes(tree_size: u64, timestamp_ms: u64, root_hash: &[u8; 32]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out[..8].copy_from_slice(&tree_size.to_be_bytes());
    out[8..16].copy_from_slice(&timestamp_ms.to_be_bytes());
    out[16..].copy_from_slice(root_hash);
    out
}

/// A backend that can sign STHs.
///
/// Implementations:
///
/// - [`Ed25519Witness`] for in-process signing.
/// - *(future)* a Rekor / external-tlog witness — the trait's signing
///   primitive is "give me canonical bytes, give back a signature" so
///   it doesn't constrain the backend to local key material.
pub trait TreeWitness: Send + Sync {
    /// Stable identifier for this witness's key (appears in
    /// [`SignedTreeHead::witness_kid`]).
    fn kid(&self) -> &str;

    /// Produce a [`SignedTreeHead`] for the given (tree_size, root_hash).
    /// Implementations stamp `timestamp_ms` with their own clock reading.
    fn sign_sth(
        &self,
        tree_size: u64,
        root_hash: &[u8; 32],
    ) -> Result<SignedTreeHead, WitnessError>;

    /// Verify a signature over canonical STH bytes against this witness's
    /// verifying key. Used by [`SignedTreeHead::verify`].
    fn verify_canonical(&self, canonical: &[u8], sig: &[u8]) -> Result<(), WitnessError>;
}

/// In-process Ed25519 witness. Wraps an [`ed25519_dalek::SigningKey`]
/// directly; the key id is the URL-safe base64 of the SHA-256 of the
/// public-key bytes, truncated to 12 chars (matches the LocalIssuer's
/// kid convention so a deployment can reuse the same key for both
/// SVID and STH signing if desired).
pub struct Ed25519Witness {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    kid: String,
}

impl Ed25519Witness {
    /// Wrap a caller-provided signing key. The kid is derived
    /// deterministically from the public key.
    pub fn new(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let kid = derive_kid(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            kid,
        }
    }

    /// Construct from a 32-byte Ed25519 secret-key seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self::new(SigningKey::from_bytes(&seed))
    }

    /// Construct a verify-only witness from a 32-byte public key. Cannot
    /// sign — `sign_sth` returns [`WitnessError::Backend`]. Useful for
    /// auditors that hold only the public material.
    pub fn verify_only(verifying_key_bytes: [u8; 32]) -> Result<VerifyOnlyWitness, WitnessError> {
        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
            .map_err(|_| WitnessError::InvalidVerifyingKey)?;
        let kid = derive_kid(&verifying_key);
        Ok(VerifyOnlyWitness { verifying_key, kid })
    }

    /// The Ed25519 verifying key bytes (32 bytes). Publish to whoever
    /// will verify STHs offline.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl TreeWitness for Ed25519Witness {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign_sth(
        &self,
        tree_size: u64,
        root_hash: &[u8; 32],
    ) -> Result<SignedTreeHead, WitnessError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WitnessError::Clock)?
            .as_millis() as u64;
        let canonical = canonical_sth_bytes(tree_size, ts, root_hash);
        let sig = self.signing_key.sign(&canonical);
        Ok(SignedTreeHead {
            tree_size,
            timestamp_ms: ts,
            root_hash_hex: hex::encode(root_hash),
            witness_kid: self.kid.clone(),
            witness_sig: sig.to_bytes().to_vec(),
        })
    }

    fn verify_canonical(&self, canonical: &[u8], sig: &[u8]) -> Result<(), WitnessError> {
        let sig_arr: [u8; 64] = sig
            .try_into()
            .map_err(|_| WitnessError::InvalidSignature(self.kid.clone()))?;
        let signature = Signature::from_bytes(&sig_arr);
        self.verifying_key
            .verify(canonical, &signature)
            .map_err(|_| WitnessError::InvalidSignature(self.kid.clone()))
    }
}

/// A verify-only witness. Holds a public key but cannot sign; used by
/// auditors who validate STHs they did not produce.
pub struct VerifyOnlyWitness {
    verifying_key: VerifyingKey,
    kid: String,
}

impl VerifyOnlyWitness {
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl TreeWitness for VerifyOnlyWitness {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign_sth(&self, _: u64, _: &[u8; 32]) -> Result<SignedTreeHead, WitnessError> {
        Err(WitnessError::Backend(
            "VerifyOnlyWitness cannot sign — verify-only".into(),
        ))
    }

    fn verify_canonical(&self, canonical: &[u8], sig: &[u8]) -> Result<(), WitnessError> {
        let sig_arr: [u8; 64] = sig
            .try_into()
            .map_err(|_| WitnessError::InvalidSignature(self.kid.clone()))?;
        let signature = Signature::from_bytes(&sig_arr);
        self.verifying_key
            .verify(canonical, &signature)
            .map_err(|_| WitnessError::InvalidSignature(self.kid.clone()))
    }
}

fn derive_kid(verifying_key: &VerifyingKey) -> String {
    let mut h = Sha256::new();
    h.update(verifying_key.as_bytes());
    let digest = h.finalize();
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(&digest[..12])
}

fn hex_decode_32(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_witness() -> Ed25519Witness {
        // Deterministic seed for test determinism.
        Ed25519Witness::from_seed([7u8; 32])
    }

    #[test]
    fn canonical_bytes_are_48_and_stable() {
        let bytes = canonical_sth_bytes(5, 1_700_000_000_000, &[0xAB; 32]);
        assert_eq!(bytes.len(), 48);
        // Determinism
        let bytes2 = canonical_sth_bytes(5, 1_700_000_000_000, &[0xAB; 32]);
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn canonical_bytes_change_with_any_field() {
        let base = canonical_sth_bytes(5, 1000, &[1; 32]);
        assert_ne!(base, canonical_sth_bytes(6, 1000, &[1; 32]));
        assert_ne!(base, canonical_sth_bytes(5, 1001, &[1; 32]));
        assert_ne!(base, canonical_sth_bytes(5, 1000, &[2; 32]));
    }

    #[test]
    fn ed25519_witness_signs_and_self_verifies() {
        let w = fixed_witness();
        let sth = w.sign_sth(42, &[0x11; 32]).unwrap();
        assert_eq!(sth.tree_size, 42);
        assert_eq!(sth.witness_kid, w.kid());
        sth.verify(&w).unwrap();
    }

    #[test]
    fn sth_roundtrips_through_json() {
        let w = fixed_witness();
        let sth = w.sign_sth(3, &[0x42; 32]).unwrap();
        let json = serde_json::to_string(&sth).unwrap();
        let back: SignedTreeHead = serde_json::from_str(&json).unwrap();
        assert_eq!(sth, back);
    }

    #[test]
    fn sth_rejects_tampered_root_hash() {
        let w = fixed_witness();
        let mut sth = w.sign_sth(3, &[0xAA; 32]).unwrap();
        // Flip one nibble in the hex
        sth.root_hash_hex.replace_range(0..1, "0");
        assert!(matches!(
            sth.verify(&w),
            Err(WitnessError::InvalidSignature(_))
        ));
    }

    #[test]
    fn sth_rejects_tampered_tree_size() {
        let w = fixed_witness();
        let mut sth = w.sign_sth(3, &[0xAA; 32]).unwrap();
        sth.tree_size = 999;
        assert!(matches!(
            sth.verify(&w),
            Err(WitnessError::InvalidSignature(_))
        ));
    }

    #[test]
    fn verify_only_witness_validates_third_party_signatures() {
        let signer = fixed_witness();
        let sth = signer.sign_sth(10, &[0x33; 32]).unwrap();

        // An auditor who only has the verifying key can still validate.
        let auditor = Ed25519Witness::verify_only(signer.verifying_key_bytes()).unwrap();
        assert_eq!(auditor.kid(), signer.kid());
        sth.verify(&auditor).unwrap();
    }

    #[test]
    fn verify_only_witness_cannot_sign() {
        let signer = fixed_witness();
        let auditor = Ed25519Witness::verify_only(signer.verifying_key_bytes()).unwrap();
        assert!(matches!(
            auditor.sign_sth(1, &[0u8; 32]),
            Err(WitnessError::Backend(_))
        ));
    }

    #[test]
    fn kid_mismatch_is_distinguished_from_invalid_signature() {
        let signer = fixed_witness();
        let sth = signer.sign_sth(1, &[0u8; 32]).unwrap();

        // A different signer with a different kid
        let other = Ed25519Witness::from_seed([9u8; 32]);
        let err = sth.verify(&other).unwrap_err();
        assert!(matches!(err, WitnessError::KidMismatch { .. }));
    }
}
