//! The signed record a pod's link check owes when it cuts egress (#2905).
//!
//! The bypass detector (`egress_link::bypass`) cuts a pod's egress in two cases: the kernel
//! counted more leaving the pod's link than the ledger admitted, or the counters could not be
//! read at all. Both are effects, so both leave a record (FM-3), signed by the node's root key
//! like the exhaustion record — but in their own signature space
//! ([`SignedRecord::EgressLink`]), so a link record never verifies as an exhaustion record, a
//! pod receipt, or a certificate body.

use serde::{Deserialize, Serialize};

use super::record::absorb;
use crate::pod_authority::{EgressRecordSigner, SignedRecord};

/// The version of [`LinkRecord::preimage`]. Absorbed into it.
pub const LINK_RECORD_VERSION: u32 = 1;

/// The event a record names: which of the two cuts it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkCut {
    /// The kernel counted more than the ledger admitted.
    Bypass,
    /// The counters could not be read or compared. Not "no bypass".
    CouldNotCheck,
}

impl LinkCut {
    const fn event(self) -> &'static str {
        match self {
            Self::Bypass => "egress_link_bypass",
            Self::CouldNotCheck => "egress_link_unchecked",
        }
    }
}

/// One signed link record, as written to the pod's `lifecycle.log`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkRecord {
    pub timestamp_unix: u64,
    /// Always `nucleus-node`: the host wrote it.
    pub actor: String,
    /// `egress_link_bypass` or `egress_link_unchecked`.
    pub event: String,
    /// `pod:<id>`.
    pub subject: String,
    /// What was found, with the counts or the reason the counters could not be read.
    pub result: String,
    /// Always `egress.link`.
    pub dimension: String,
    pub version: u32,
    /// The node's signature over [`Self::preimage`], and the key that made it.
    pub signature: String,
    pub signer_pubkey: String,
}

impl LinkRecord {
    /// A record of `cut` for `pod_id`, saying `result`, signed by `signer`.
    pub(crate) fn signed(
        signer: &EgressRecordSigner,
        timestamp_unix: u64,
        cut: LinkCut,
        pod_id: &str,
        result: String,
    ) -> Self {
        let mut record = Self {
            timestamp_unix,
            actor: "nucleus-node".to_string(),
            event: cut.event().to_string(),
            subject: format!("pod:{pod_id}"),
            result,
            dimension: "egress.link".to_string(),
            version: LINK_RECORD_VERSION,
            signature: String::new(),
            signer_pubkey: String::new(),
        };
        let (signature, signer_pubkey) = signer.sign_link(&record.preimage());
        record.signature = signature;
        record.signer_pubkey = signer_pubkey;
        record
    }

    /// The bytes the node signs. Exhaustively destructured (ADR 0007 E-1); `signature` and
    /// `signer_pubkey` are not in it.
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

    /// Whether `node_pubkey_hex` — the node's root key as the reader pinned it — signed this
    /// record in the link space.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn verifies_under(&self, node_pubkey_hex: &str) -> bool {
        self.signer_pubkey == node_pubkey_hex
            && crate::pod_authority::verify_record(
                SignedRecord::EgressLink,
                node_pubkey_hex,
                &self.preimage(),
                &self.signature,
            )
    }
}
