//! The tool-proxy's audit record, declared once (#3293).
//!
//! `nucleus-tool-proxy` writes these records and `nucleus-audit verify` reads
//! them back. Both use this module's preimage, so the writer and the verifier
//! cannot disagree about what a record commits to (ADR 0007 G-1). Before this
//! module, each side spelled the preimage out on its own. A drand round the
//! writer signed and the verifier omitted already cost one release a verifier
//! that refused every anchored log.
//!
//! # Why a signature, not a MAC
//!
//! A record used to carry `HMAC(audit secret, preimage)`. The audit secret
//! defaulted to the proxy's auth secret, and on the transports that carry no
//! shared secret (vsock on Firecracker, the peer-verified Unix socket that is
//! the container default since #3290) that secret is EMPTY. `HMAC(∅, …)` is
//! computable by anyone, so the "signature" proved nothing about who wrote a
//! record. It was a checksum presented as an authenticator.
//!
//! A record is now signed with Ed25519 by a key the tool-proxy generates at
//! startup and holds only in its own memory ([`SigAlg::Ed25519`]). The record
//! names the public half (`signer`), and that name is inside the signed bytes
//! and therefore inside the chain hash. The node signs the chain's tail hash
//! into the pod receipt (`audit_tail_hash`), so the receipt pins every signer
//! the chain names. A verifier pins a signer through the receipt's tail hash,
//! or directly by the key the proxy printed on its console at boot.
//!
//! # The two forms
//!
//! [`RecordForm`] tells them apart, and the verifier must handle both:
//!
//! - **Signed** (`sig_alg: "ed25519"`, `signer`): the form every record takes
//!   from this change on.
//! - **Legacy** (neither field): a shared-secret MAC, written by a tool-proxy
//!   older than this change. It can be checked only against the secret it was
//!   keyed with. An empty secret is not a key, so the verifier refuses rather
//!   than "verify" against one.
//!
//! A record carrying one of the two fields without the other is neither form.
//! It is refused ([`FormError`]), never read as legacy.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The domain tag at the head of every signed record's preimage, so a
/// signature over an audit record is never a valid signature over anything
/// else that key might sign.
pub const SIGNED_DOMAIN: &str = "nucleus-tool-proxy-audit/2";

/// How a record's `signature` was made. Absent on a legacy record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigAlg {
    /// Ed25519 by the key `signer` names, over [`AuditRecord::signed_bytes`].
    Ed25519,
}

/// What a caller asks the audit log to record. The chain fields (`prev_hash`,
/// `hash`, `signature`, `signer`) are not in it: only the log can fill them,
/// so a caller cannot hand it a record that claims to be signed.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    pub timestamp_unix: u64,
    pub actor: Option<String>,
    pub event: String,
    pub subject: String,
    pub result: String,
    /// SPIFFE identity of the authenticated requester, when there is one.
    pub spiffe_id: Option<String>,
    /// Policy rule that authorized the operation, when there is one.
    pub policy_rule: Option<String>,
}

/// One line of the tool-proxy's audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub timestamp_unix: u64,
    pub actor: Option<String>,
    pub event: String,
    pub subject: String,
    pub result: String,
    pub prev_hash: String,
    pub hash: String,
    pub signature: String,
    /// Drand round the writer anchored this record to. Inside the signed bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drand_round: Option<u64>,
    /// Inside the signed bytes of a signed record; outside a legacy one's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
    /// Inside the signed bytes of a signed record; outside a legacy one's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rule: Option<String>,
    /// Absent on a legacy record. See [`RecordForm`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_alg: Option<SigAlg>,
    /// The signer's Ed25519 public key, 64 hex characters. Absent on a legacy record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// Which of the two forms a record is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordForm<'a> {
    /// A shared-secret MAC from a tool-proxy older than #3293.
    LegacyMac,
    /// Ed25519 by `signer` (hex public key).
    Signed { signer: &'a str },
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

impl AuditEvent {
    /// The record this event becomes when `signer` (hex public key) signs it
    /// after `prev_hash`. Unsigned: [`AuditRecord::with_signature`] seals it.
    pub fn unsigned(
        self,
        prev_hash: String,
        drand_round: Option<u64>,
        signer: String,
    ) -> AuditRecord {
        let AuditEvent {
            timestamp_unix,
            actor,
            event,
            subject,
            result,
            spiffe_id,
            policy_rule,
        } = self;
        AuditRecord {
            timestamp_unix,
            actor,
            event,
            subject,
            result,
            prev_hash,
            hash: String::new(),
            signature: String::new(),
            drand_round,
            spiffe_id,
            policy_rule,
            sig_alg: Some(SigAlg::Ed25519),
            signer: Some(signer),
        }
    }
}

impl AuditRecord {
    /// Which form this record is in.
    ///
    /// # Errors
    /// [`FormError`] when exactly one of `sig_alg` and `signer` is present.
    pub fn form(&self) -> Result<RecordForm<'_>, FormError> {
        match (self.sig_alg, self.signer.as_deref()) {
            (None, None) => Ok(RecordForm::LegacyMac),
            (Some(SigAlg::Ed25519), Some(signer)) => Ok(RecordForm::Signed { signer }),
            (Some(SigAlg::Ed25519), None) => Err(FormError::SignerMissing),
            (None, Some(_)) => Err(FormError::AlgMissing),
        }
    }

    /// The bytes `signature` covers, for this record's form.
    ///
    /// # Errors
    /// [`FormError`] when the record is neither form.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, FormError> {
        match self.form()? {
            RecordForm::LegacyMac => Ok(self.legacy_message().into_bytes()),
            RecordForm::Signed { .. } => Ok(self.signed_preimage()),
        }
    }

    /// The chain hash this record must carry, given its `signature`. The next
    /// record names it as its `prev_hash`.
    ///
    /// # Errors
    /// [`FormError`] when the record is neither form.
    pub fn chain_hash(&self) -> Result<String, FormError> {
        match self.form()? {
            RecordForm::LegacyMac => Ok(hex::encode(Sha256::digest(
                format!("{}|{}", self.legacy_message(), self.signature).as_bytes(),
            ))),
            RecordForm::Signed { .. } => {
                let mut bytes = self.signed_preimage();
                absorb(&mut bytes, "signature", self.signature.as_bytes());
                Ok(hex::encode(Sha256::digest(&bytes)))
            }
        }
    }

    /// Set the signature and the chain hash it implies.
    ///
    /// # Errors
    /// [`FormError`] when the record is neither form.
    pub fn with_signature(mut self, signature: String) -> Result<Self, FormError> {
        self.signature = signature;
        self.hash = self.chain_hash()?;
        Ok(self)
    }

    /// The legacy preimage, `ts|actor|event|subject|result|prev[|drand:r]`.
    /// Kept byte for byte, so a log written before #3293 can still be checked
    /// against the secret it was keyed with.
    fn legacy_message(&self) -> String {
        let drand_part = self
            .drand_round
            .map(|r| format!("|drand:{r}"))
            .unwrap_or_default();
        format!(
            "{}|{}|{}|{}|{}|{}{}",
            self.timestamp_unix,
            self.actor.as_deref().unwrap_or_default(),
            self.event,
            self.subject,
            self.result,
            self.prev_hash,
            drand_part
        )
    }

    /// The signed preimage. Every field is tag-separated and length-prefixed,
    /// so no two distinct records share a preimage by concatenation (the legacy
    /// `|`-joined form has that defect: a `|` in `subject` moves a boundary).
    ///
    /// EXHAUSTIVELY DESTRUCTURED (ADR 0007 E-1): a field added to the record
    /// is a compile error here until someone decides whether it is signed.
    fn signed_preimage(&self) -> Vec<u8> {
        let AuditRecord {
            timestamp_unix,
            actor,
            event,
            subject,
            result,
            prev_hash,
            hash: _,
            signature: _,
            drand_round,
            spiffe_id,
            policy_rule,
            sig_alg: _,
            signer,
        } = self;
        let mut out = Vec::new();
        absorb(&mut out, "domain", SIGNED_DOMAIN.as_bytes());
        absorb_opt(&mut out, "signer", signer.as_deref().map(str::as_bytes));
        absorb(&mut out, "timestamp_unix", &timestamp_unix.to_be_bytes());
        absorb_opt(&mut out, "actor", actor.as_deref().map(str::as_bytes));
        absorb(&mut out, "event", event.as_bytes());
        absorb(&mut out, "subject", subject.as_bytes());
        absorb(&mut out, "result", result.as_bytes());
        absorb(&mut out, "prev_hash", prev_hash.as_bytes());
        let round = drand_round.map(u64::to_be_bytes);
        absorb_opt(
            &mut out,
            "drand_round",
            round.as_ref().map(<[u8; 8]>::as_slice),
        );
        absorb_opt(
            &mut out,
            "spiffe_id",
            spiffe_id.as_deref().map(str::as_bytes),
        );
        absorb_opt(
            &mut out,
            "policy_rule",
            policy_rule.as_deref().map(str::as_bytes),
        );
        out
    }
}

fn absorb(out: &mut Vec<u8>, tag: &str, bytes: &[u8]) {
    out.extend_from_slice(tag.as_bytes());
    out.push(0);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// An absent value and an empty one are different preimages.
fn absorb_opt(out: &mut Vec<u8>, tag: &str, bytes: Option<&[u8]>) {
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

    fn event(subject: &str) -> AuditEvent {
        AuditEvent {
            timestamp_unix: 7,
            actor: Some("n".into()),
            event: "boot".into(),
            subject: subject.into(),
            result: "ok".into(),
            spiffe_id: None,
            policy_rule: None,
        }
    }

    #[test]
    fn a_record_round_trips_and_keeps_its_hash() {
        let rec = event("s")
            .unsigned(String::new(), Some(3), "ab".repeat(32))
            .with_signature("cd".repeat(64))
            .expect("signed form");
        let line = serde_json::to_string(&rec).expect("serialize");
        let back: AuditRecord = serde_json::from_str(&line).expect("parse");
        assert_eq!(back, rec);
        assert_eq!(back.chain_hash().expect("form"), rec.hash);
    }

    #[test]
    fn the_signer_is_inside_the_signed_bytes_and_the_hash() {
        let a = event("s").unsigned(String::new(), None, "ab".repeat(32));
        let b = event("s").unsigned(String::new(), None, "cd".repeat(32));
        assert_ne!(a.signed_bytes(), b.signed_bytes());
        let (a, b) = (
            a.with_signature("00".into()).expect("form"),
            b.with_signature("00".into()).expect("form"),
        );
        assert_ne!(a.hash, b.hash);
    }

    #[test]
    fn a_pipe_in_a_field_cannot_move_a_boundary_in_the_signed_form() {
        let mut a = event("x|y").unsigned(String::new(), None, "ab".repeat(32));
        let mut b = event("x").unsigned(String::new(), None, "ab".repeat(32));
        a.result = "ok".into();
        b.result = "y|ok".into();
        assert_ne!(a.signed_bytes(), b.signed_bytes());
    }

    #[test]
    fn half_a_signed_record_is_neither_form() {
        let mut rec = event("s").unsigned(String::new(), None, "ab".repeat(32));
        rec.sig_alg = None;
        assert_eq!(rec.form(), Err(FormError::AlgMissing));
        let mut rec = event("s").unsigned(String::new(), None, "ab".repeat(32));
        rec.signer = None;
        assert_eq!(rec.form(), Err(FormError::SignerMissing));
    }

    #[test]
    fn an_unknown_field_or_algorithm_is_refused() {
        let rec = event("s")
            .unsigned(String::new(), None, "ab".repeat(32))
            .with_signature("00".into())
            .expect("form");
        let mut v = serde_json::to_value(&rec).expect("value");
        v["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<AuditRecord>(v).is_err());
        let mut v = serde_json::to_value(&rec).expect("value");
        v["sig_alg"] = serde_json::json!("hmac-sha256");
        assert!(serde_json::from_value::<AuditRecord>(v).is_err());
    }
}
