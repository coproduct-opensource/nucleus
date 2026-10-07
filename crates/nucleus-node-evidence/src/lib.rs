//! # nucleus-node-evidence
//!
//! Third-party-verifiable evidence of **what booted** on the node whose key
//! signs receipts, and a pure-Rust verifier for it. ADR 0011 records the
//! design; this is the summary.
//!
//! ## Roles (RFC 9334, RATS)
//!
//! * **Attester** — the node. It asks its TPM for a quote whose qualifying
//!   data commits to the node's executor key ([`binding`]), and publishes a
//!   [`NodeEvidence`] document: the quote, the TCG boot event log, a narrow
//!   IMA log, the AK, and the anchor it claims for the AK.
//! * **Verifier** — [`appraise`], here, and the audit CLI built on it. It
//!   shares no code with the node's decision path.
//! * **Relying party** — whoever checks a receipt. It supplies everything
//!   appraisal compares against: the executor key from the receipt, the
//!   freshness requirement, the reference manifest, and its own trust roots
//!   or operator pins. The evidence supplies none of those.
//!
//! ## Results
//!
//! [`Tier`] is one of four, the AR4SI / EAR tiers: `Attested` (affirming),
//! `Contested` (contraindicated), `Expired` (warning), `Unattested` (none).
//! Evidence that is not evidence — a bad signature, a log that does not
//! replay, a quote bound to another key — is a [`Refusal`], kept apart from
//! the tiers. Every result names its [`AkAnchor`], and the anchor is never
//! reported stronger than the relying party's inputs establish.
//!
//! ## Federation key custody
//!
//! [`key_attestation`] checks that a node's federation (JWKS) key is
//! TPM-resident and usable only in the boot state the quote measured: the AK
//! certifies it (`TPM2_Certify`), and its `authPolicy` is `PolicyPCR` over
//! the quoted boot PCRs. ADR 0012.
//!
//! ## What this does not do
//!
//! * It measures the **host** boot and the node's own files. What runs inside
//!   a guest VM is not measured by the host TPM.
//! * IMA records a load, not that the loaded file is still what runs.
//! * An `OperatorFetched` anchor is the operator vouching for the AK, not a
//!   signed artifact; it is labelled as such and is the weakest anchor.
//! * Epoch freshness trusts the node's own clock for `iat`, signed by the
//!   TPM through the qualifying data but not measured by it.

#![deny(missing_docs)]
// The verifier parses hostile bytes; a panic on crafted evidence is a denial of
// service against every relying party. The shipped build may not panic.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

pub mod anchor;
pub mod appraise;
#[cfg(feature = "attester")]
pub mod attester;
pub mod binding;
mod crypto;
pub mod eventlog;
pub mod evidence;
pub mod ima;
pub mod key_attestation;
pub mod reference;
pub mod relying_party;
pub mod tpm;
#[cfg(feature = "attester")]
pub mod tpm_key;
mod wire;

#[cfg(test)]
mod appraise_tests;
#[cfg(test)]
mod key_attestation_tests;

pub use anchor::{AkAnchor, AkAnchorClaim, AnchorPolicy, OperatorPin, UnanchoredReason};
pub use appraise::{
    Appraisal, AppraisalPolicy, Divergence, FreshnessExpectation, FreshnessVerdict, Refusal,
    StaleReason, Tier, UnattestedReason, appraise,
};
pub use binding::{ExecutorKey, Federation, Freshness, KeyBinding, Nonce, qualifying_data};
pub use crypto::HashAlg;
pub use evidence::{BootLog, EVIDENCE_PROFILE, ImaLog, NodeEvidence, TpmQuote, evidence_digest};
pub use ima::{ImaEntry, ImaLogFormat};
pub use key_attestation::{
    AttestedKey, BOOT_POLICY_PCRS, CustodyStatement, FederationKeyAttestation,
    KEY_ATTESTATION_PROFILE, KeyRefusal, KeyResidency, TpmCustodyStatement,
    appraise_federation_keys,
};
pub use reference::{
    CmdlineRule, DigestSet, Expect, ImaReference, ImaScope, REFERENCE_PROFILE, ReferenceManifest,
    ReferenceValues,
};
pub use relying_party::{InputError, RelyingParty, Report, report};

/// A binary structure that did not parse.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Malformed {
    /// Fewer bytes than the structure needs.
    #[error("{structure}: truncated at offset {offset} (needed {needed} more bytes)")]
    Truncated {
        /// The structure.
        structure: &'static str,
        /// Where.
        offset: usize,
        /// How many bytes the read needed.
        needed: usize,
    },
    /// Bytes left after the structure ended.
    #[error("{structure}: {count} trailing bytes")]
    TrailingBytes {
        /// The structure.
        structure: &'static str,
        /// How many.
        count: usize,
    },
    /// A field holds a value the structure does not allow.
    #[error("{structure}: {reason}")]
    Field {
        /// The structure.
        structure: &'static str,
        /// What is wrong.
        reason: String,
    },
}
