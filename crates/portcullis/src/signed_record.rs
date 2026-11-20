//! The signing scheme the tool-proxy's two record logs share (#3293, #3309).
//!
//! The tool-proxy keeps two hash-chained logs: its audit log
//! (`nucleus_spec::tool_proxy_audit::AuditRecord`) and the Article 12 decision
//! log ([`crate::art12_record::Art12Record`]). Both are signed by the same
//! Ed25519 key, the proxy's `AuditSigner`, and both carry the same two
//! fields that say how a record was signed: `sig_alg` and `signer`.
//!
//! Everything about those two fields lives here, once (ADR 0007 G-1): the
//! algorithm tag, the rule that tells a signed record from a legacy MAC'd one,
//! the length-prefixed encoding both signed preimages are built from, and the
//! chain hash over a signed record. It is in `portcullis` rather than in
//! `nucleus-spec` because `Art12Record` is declared here and `nucleus-spec`
//! depends on `portcullis`, not the reverse; `nucleus_spec::tool_proxy_audit`
//! re-exports it, so the audit log reads it under the name it always had.
//!
//! # The two forms
//!
//! - **Signed** (`sig_alg: "ed25519"`, `signer`): Ed25519 by the key `signer`
//!   names. The name is inside the signed bytes and so inside the chain hash.
//! - **Legacy** (neither field): a shared-secret MAC from a tool-proxy older
//!   than the log's signing change. It can be checked only against the secret
//!   it was keyed with, and an empty secret is not a key.
//!
//! A record carrying one of the two fields without the other is neither form.
//! It is refused ([`FormError`]), never read as legacy: reading it as legacy
//! would let a forger strip the algorithm and fall back to the keyless MAC.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How a record's `signature` was made. Absent on a legacy record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigAlg {
    /// Ed25519 by the key `signer` names, over the record's signed preimage.
    Ed25519,
}

/// Which of the two forms a record is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordForm<'a> {
    /// A shared-secret MAC from a tool-proxy older than the log's signing change.
    LegacyMac,
    /// Ed25519 by `signer` (hex public key).
    Signed {
        /// The signer's Ed25519 public key, hex-encoded.
        signer: &'a str,
    },
}

/// A record that is neither form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormError {
    /// `sig_alg` is present and `signer` is not: nothing names the key.
    SignerMissing,
    /// `signer` is present and `sig_alg` is not: reading it as legacy would let
    /// a forger strip the algorithm and fall back to the keyless MAC.
    AlgMissing,
}

impl std::fmt::Display for FormError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SignerMissing => "the record names a signature algorithm but no signer",
            Self::AlgMissing => {
                "the record names a signer but no signature algorithm; it is not a legacy record"
            }
        })
    }
}

impl std::error::Error for FormError {}

/// The form a record's `sig_alg` and `signer` put it in. The one decider for
/// both logs.
///
/// # Errors
/// [`FormError`] when exactly one of the two is present.
pub fn form(sig_alg: Option<SigAlg>, signer: Option<&str>) -> Result<RecordForm<'_>, FormError> {
    match (sig_alg, signer) {
        (None, None) => Ok(RecordForm::LegacyMac),
        (Some(SigAlg::Ed25519), Some(signer)) => Ok(RecordForm::Signed { signer }),
        (Some(SigAlg::Ed25519), None) => Err(FormError::SignerMissing),
        (None, Some(_)) => Err(FormError::AlgMissing),
    }
}

/// The chain hash of a signed record: SHA-256 over its signed preimage
/// followed by the signature, so the next record's `prev_hash` commits to both.
#[must_use]
pub fn signed_chain_hash(mut signed_preimage: Vec<u8>, signature: &str) -> String {
    absorb(&mut signed_preimage, "signature", signature.as_bytes());
    hex::encode(Sha256::digest(&signed_preimage))
}

/// Append one tagged, length-prefixed field. No two distinct sequences of
/// fields share an encoding, so a `|` in a value can never move a boundary
/// (the legacy `|`-joined preimages have that defect).
pub fn absorb(out: &mut Vec<u8>, tag: &str, bytes: &[u8]) {
    out.extend_from_slice(tag.as_bytes());
    out.push(0);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// [`absorb`] for an optional field: an absent value and an empty one are
/// different preimages.
pub fn absorb_opt(out: &mut Vec<u8>, tag: &str, bytes: Option<&[u8]>) {
    match bytes {
        Some(b) => {
            out.push(1);
            absorb(out, tag, b);
        }
        None => {
            out.push(0);
            absorb(out, tag, &[]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_a_signed_record_is_neither_form() {
        assert_eq!(form(None, None), Ok(RecordForm::LegacyMac));
        assert_eq!(
            form(Some(SigAlg::Ed25519), Some("ab")),
            Ok(RecordForm::Signed { signer: "ab" })
        );
        assert_eq!(
            form(Some(SigAlg::Ed25519), None),
            Err(FormError::SignerMissing)
        );
        assert_eq!(form(None, Some("ab")), Err(FormError::AlgMissing));
    }

    #[test]
    fn absent_and_empty_are_different_preimages() {
        let (mut a, mut b) = (Vec::new(), Vec::new());
        absorb_opt(&mut a, "t", None);
        absorb_opt(&mut b, "t", Some(b""));
        assert_ne!(a, b);
    }

    #[test]
    fn the_signature_is_inside_the_chain_hash() {
        assert_ne!(
            signed_chain_hash(b"x".to_vec(), "00"),
            signed_chain_hash(b"x".to_vec(), "01")
        );
    }
}
