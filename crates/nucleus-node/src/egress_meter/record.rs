//! The signed record a pod's egress exhaustion owes (#2905).
//!
//! FM-3: no effect without a receipt, and a pod losing its egress is an effect. The record used
//! to be a plain `lifecycle.log` append: anything with write access to the pod directory could
//! add one, remove one, or rewrite its counts, and a reader could not tell. It is now signed by
//! the node's root key — the key that signs the pod's receipt — under its own domain tag
//! ([`SignedRecord::EgressExhaustion`]), so a reader holding the node's pinned root key can check
//! that the node wrote it and that nothing in it moved.
//!
//! The record IS the lifecycle entry, with the same five fields every lifecycle entry carries
//! plus what the signature needs. One record of the fact, not a log line and a receipt that can
//! disagree (ADR 0007 G-1).

use serde::{Deserialize, Serialize};

use crate::pod_authority::{EgressRecordSigner, SignedRecord};

/// The version of [`EgressRecord::preimage`]. Absorbed into it, so a change to the preimage is a
/// new version rather than a reinterpretation of signed records.
pub const EGRESS_RECORD_VERSION: u32 = 1;

/// Append one tag-separated, length-prefixed part of a signed record's preimage, so no two
/// distinct records share a preimage by concatenation. The one encoding every egress record
/// uses (ADR 0007 G-1).
pub(super) fn absorb(out: &mut Vec<u8>, tag: &str, bytes: &[u8]) {
    out.extend_from_slice(tag.as_bytes());
    out.push(0);
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// One signed egress-exhaustion record, as it is written to the pod's `lifecycle.log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRecord {
    pub timestamp_unix: u64,
    /// Always `nucleus-node`: the host wrote it.
    pub actor: String,
    /// `egress_budget_exhausted`, `egress_rate_exceeded`, … — which refusal latched.
    pub event: String,
    /// `pod:<id>`.
    pub subject: String,
    /// The refusal, with its counts.
    pub result: String,
    /// The exhausted dimension (`egress.max_bytes`, …), named for a person to act on.
    pub dimension: String,
    pub version: u32,
    /// The node's signature over [`Self::preimage`], and the key that made it.
    pub signature: String,
    pub signer_pubkey: String,
}

impl EgressRecord {
    /// A record of `refusal` for `pod_id`, signed by `signer`.
    pub(crate) fn signed(
        signer: &EgressRecordSigner,
        timestamp_unix: u64,
        event: &str,
        pod_id: &str,
        refusal: &portcullis::EgressRefusal,
    ) -> Self {
        let mut record = Self {
            timestamp_unix,
            actor: "nucleus-node".to_string(),
            event: event.to_string(),
            subject: format!("pod:{pod_id}"),
            result: refusal.to_string(),
            dimension: refusal.dimension().to_string(),
            version: EGRESS_RECORD_VERSION,
            signature: String::new(),
            signer_pubkey: String::new(),
        };
        let (signature, signer_pubkey) = signer.sign(&record.preimage());
        record.signature = signature;
        record.signer_pubkey = signer_pubkey;
        record
    }

    /// The bytes the node signs.
    ///
    /// Exhaustively destructured, so a field added here is an E0027 until someone says whether
    /// the signature covers it (ADR 0007 E-1). Each part is tag-separated and length-prefixed, so
    /// no two distinct records share a preimage by concatenation. `signature` and
    /// `signer_pubkey` are not in it: a signature cannot cover itself.
    pub fn preimage(&self) -> Vec<u8> {
        let Self {
            timestamp_unix,
            actor,
            event,
            subject,
            result,
            dimension,
            version,
            signature: _,
            signer_pubkey: _,
        } = self;
        let mut out = Vec::new();
        absorb(&mut out, "version", &version.to_be_bytes());
        absorb(&mut out, "timestamp_unix", &timestamp_unix.to_be_bytes());
        absorb(&mut out, "actor", actor.as_bytes());
        absorb(&mut out, "event", event.as_bytes());
        absorb(&mut out, "subject", subject.as_bytes());
        absorb(&mut out, "result", result.as_bytes());
        absorb(&mut out, "dimension", dimension.as_bytes());
        out
    }

    /// Whether `node_pubkey_hex` — the node's root key, pinned by the reader, never the
    /// record's own `signer_pubkey` taken on its word — signed this record.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn verifies_under(&self, node_pubkey_hex: &str) -> bool {
        self.signer_pubkey == node_pubkey_hex
            && crate::pod_authority::verify_record(
                SignedRecord::EgressExhaustion,
                node_pubkey_hex,
                &self.preimage(),
                &self.signature,
            )
    }
}
