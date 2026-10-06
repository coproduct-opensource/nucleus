//! The evidence document a node publishes: EAT-shaped JSON claims
//! (RFC 9711) carrying a TPM quote, the logs that explain it, the key binding
//! the quote signs, and the anchor the node claims for its AK.
//!
//! Every field is the node's *claim*. Nothing here is trusted until
//! [`crate::appraise`] has checked it against the quote signature, the
//! replayed logs, and the relying party's own inputs.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::anchor::AkAnchorClaim;
use crate::binding::{Freshness, KeyBinding};
use crate::crypto::sha256;
use crate::ima::ImaLogFormat;

/// The evidence profile (EAT `eat_profile`).
pub const EVIDENCE_PROFILE: &str = "nucleus-node-evidence/v1";

/// The TPM quote and what it was taken over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TpmQuote {
    /// The AK as a `TPM2B_PUBLIC`, base64.
    pub ak_public: String,
    /// The signed `TPMS_ATTEST`, base64.
    pub attest: String,
    /// The `TPMT_SIGNATURE` over it, base64.
    pub signature: String,
    /// The SHA-256 bank PCR values the quote covers, hex, by index. Their
    /// hash must equal the quote's `pcrDigest`.
    pub pcrs: BTreeMap<u8, String>,
}

impl TpmQuote {
    /// Encode raw quote parts: a `TPM2B_PUBLIC`, a `TPMS_ATTEST`, a
    /// `TPMT_SIGNATURE`, and the SHA-256 PCR values the quote covers.
    pub fn from_parts(
        ak_public: &[u8],
        attest: &[u8],
        signature: &[u8],
        pcrs: &BTreeMap<u8, [u8; 32]>,
    ) -> Self {
        Self {
            ak_public: b64(ak_public),
            attest: b64(attest),
            signature: b64(signature),
            pcrs: pcrs.iter().map(|(k, v)| (*k, hex::encode(v))).collect(),
        }
    }
}

fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// A log the node either attached or says why it did not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootLog {
    /// The TCG crypto-agile event log, base64.
    Attached(String),
    /// Not attached, and why.
    Absent(String),
}

impl BootLog {
    /// Attach a log's raw bytes.
    pub fn attach(bytes: &[u8]) -> Self {
        Self::Attached(b64(bytes))
    }
}

/// The IMA log, or why it is absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImaLog {
    /// The binary measurement list, base64, in `format`.
    Attached {
        /// The binary layout.
        format: ImaLogFormat,
        /// The log bytes, base64.
        log: String,
    },
    /// Not attached, and why.
    Absent(String),
}

impl ImaLog {
    /// Attach a log's raw bytes in `format`.
    pub fn attach(format: ImaLogFormat, bytes: &[u8]) -> Self {
        Self::Attached {
            format,
            log: b64(bytes),
        }
    }
}

/// The node's evidence document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeEvidence {
    /// Must equal [`EVIDENCE_PROFILE`].
    pub eat_profile: String,
    /// The keys this evidence speaks for.
    pub binding: KeyBinding,
    /// How it claims to be fresh.
    pub freshness: Freshness,
    /// The quote.
    pub tpm: TpmQuote,
    /// The boot event log.
    pub boot_event_log: BootLog,
    /// The IMA log.
    pub ima_log: ImaLog,
    /// The anchor claimed for the AK.
    pub ak_anchor: AkAnchorClaim,
}

/// The digest a receipt binds: SHA-256 of the evidence document's exact
/// bytes, as published. Recompute it with any SHA-256 tool.
pub fn evidence_digest(document: &[u8]) -> [u8; 32] {
    sha256(document)
}
