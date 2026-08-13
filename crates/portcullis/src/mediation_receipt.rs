//! Mediation receipt — a portable, verifiable proof of one agent↔tool crossing.
//!
//! The agent↔tool seam is where nucleus's whole thesis lives: an agent's request
//! becomes a tool action only through a kernel decision at the sole `VerdictSink`.
//! A [`MediationReceipt`] makes ONE such crossing third-party-verifiable end to
//! end. The mediator (the tool-proxy) signs, with its own key, a receipt binding:
//!
//!   * **who mediated** — the mediator's SPIFFE id;
//!   * **what it decided** — the operation, subject, and verdict;
//!   * **the record** — the SHA-256 hash of the [`Art12Record`] that recorded the
//!     decision (the content-address that ties this receipt to the audit log).
//!
//! # What this brick establishes, and what the relying party must still check
//!
//! [`MediationReceipt::verify`] establishes only that the receipt is the
//! **mediator-key-holder's own word** about a decision. On its own that is the
//! mediator vouching for itself. The full seam proof is a composition the relying
//! party completes against machinery that already exists:
//!
//!   1. this receipt's signature verifies under the mediator's key *(here)*;
//!   2. that key's SVID is **attested** (C9 EK/DevID) — the mediator is the
//!      genuine, hardware-rooted nucleus mediator, not an impostor — AND the
//!      receipt's self-claimed `signer_assurance` / `signer_backend` **equal** that
//!      independently-verified attestation (so an inflated self-claim is rejected,
//!      never believed on the signer's own word);
//!   3. the `art12_record_hash` is **included in the witnessed lineage** (the
//!      Article 12 signed-tree-head / witness federation) — the crossing was
//!      recorded and the record cannot have been rewritten.
//!
//! Together: *an attested mediator authorized this action, and it is recorded in
//! a tamper-evident, witnessed log.* This module is (1) plus the binding object;
//! (2) and (3) are the attestation and lineage verifiers, unchanged.

// Needs `crypto` (ed25519 signing) AND `serde` (the receipt derives Serialize/
// Deserialize and binds an `Art12Record`). Gating on `crypto` alone breaks the
// single-feature build (`cargo hack --each-feature --features crypto`), where
// serde is absent.
#![cfg(all(feature = "crypto", feature = "serde"))]

use crate::art12_record::Art12Record;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Schema version — a new version gets a new number (a verifier rejects a version
/// it does not know rather than guessing a layout).
pub const MEDIATION_RECEIPT_SCHEMA_VERSION: u32 = 1;

/// Domain separator folded into every preimage, so a mediation-receipt signature
/// can never be confused with a signature over any other nucleus structure.
const PREIMAGE_DOMAIN: &str = "nucleus-mediation-receipt-v1";

/// A signed, portable proof that an attested mediator authorized one tool crossing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediationReceipt {
    /// Layout version; a verifier rejects a version it does not know.
    pub schema_version: u32,
    /// SPIFFE id of the MEDIATOR (the tool-proxy) that reached the verdict.
    pub mediator_spiffe_id: String,
    /// The session this crossing belongs to.
    pub session_id: String,
    /// The kernel-decision sequence within the session.
    pub decision_seq: u64,
    /// The operation's canonical name (also bound to the record via the hash).
    pub operation: String,
    /// What the operation was requested against (path / command / URL …).
    pub subject: String,
    /// `allow` | `requires_approval` | `deny` | `error`.
    pub verdict: String,
    /// SHA-256 hash of the [`Art12Record`] that recorded this decision.
    pub art12_record_hash: String,
    /// The mediator's **self-claimed** normalized assurance level (0..=3, the
    /// `AssuranceLevel` ordinal) for the key it signed with.
    ///
    /// This is the signer's own word and is **not self-authenticating**: a valid
    /// signature over `signer_assurance = 2` proves only that the key-holder
    /// *wrote* `2`, not that its key is genuinely device-rooted. A relying party
    /// MUST treat it as unverified metadata until it is cross-checked against an
    /// independently-verified attestation of the mediator's SVID (the tool-proxy's
    /// `verify_attested`, which admits the claim only if it *equals* the derived
    /// [`nucleus_identity::assurance::VerifiedAttestation`]). Carrying the claim in
    /// the signed preimage is what lets that cross-check detect an inflated claim;
    /// it does not by itself establish the level.
    pub signer_assurance: u8,
    /// The mediator's **self-claimed** attestation backend id (e.g.
    /// `"self-measured"`, `"tpm-devid-residency"`, `"apple-sep"`). Same trust
    /// caveat as [`Self::signer_assurance`]: believed only when it equals the
    /// backend of the independently-verified attestation.
    pub signer_backend: String,
    /// Ed25519 signature over [`MediationReceipt::preimage`], hex-encoded.
    pub signature: String,
}

/// Why a mediation receipt was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediationReceiptError {
    /// The receipt uses a schema version this verifier does not know.
    UnknownSchema(u32),
    /// The signature field is not valid hex or not 64 bytes.
    BadSignatureEncoding,
    /// The mediator signature does not verify over the receipt's preimage.
    SignatureInvalid,
}

impl std::fmt::Display for MediationReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchema(v) => write!(f, "unknown mediation-receipt schema version {v}"),
            Self::BadSignatureEncoding => write!(f, "signature is not valid hex or not 64 bytes"),
            Self::SignatureInvalid => {
                write!(f, "mediator signature does not verify over the receipt")
            }
        }
    }
}

impl std::error::Error for MediationReceiptError {}

impl MediationReceipt {
    /// The canonical preimage: a `|`-joined, field-ordered rendering reconstructed
    /// **from the receipt's own fields** — never re-serialized JSON, so a verifier
    /// is not checking its own serializer (the same discipline as `Art12Record`).
    /// Excludes the signature.
    #[must_use]
    pub fn preimage(&self) -> Vec<u8> {
        format!(
            "{PREIMAGE_DOMAIN}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.schema_version,
            self.mediator_spiffe_id,
            self.session_id,
            self.decision_seq,
            self.operation,
            self.subject,
            self.verdict,
            self.art12_record_hash,
            self.signer_assurance,
            self.signer_backend,
        )
        .into_bytes()
    }

    /// Issue a receipt: the mediator vouches, over its OWN identity, for the
    /// verdict in `record`, binding that record's content hash. The verdict fields
    /// are taken from `record` so the receipt cannot describe a decision other
    /// than the one recorded.
    ///
    /// `signer_assurance` / `signer_backend` are the mediator's **self-claimed**
    /// attestation level and backend for its signing key (see the field docs): they
    /// are signed so a relying party's cross-check can detect an inflated claim, but
    /// they are not proof on their own.
    #[must_use]
    pub fn issue(
        record: &Art12Record,
        mediator_spiffe_id: &str,
        signer_assurance: u8,
        signer_backend: &str,
        key: &SigningKey,
    ) -> Self {
        let mut receipt = Self {
            schema_version: MEDIATION_RECEIPT_SCHEMA_VERSION,
            mediator_spiffe_id: mediator_spiffe_id.to_string(),
            session_id: record.session_id.clone(),
            decision_seq: record.decision_sequence.unwrap_or(record.seq),
            operation: record.operation.clone(),
            subject: record.subject.clone(),
            verdict: record.verdict.clone(),
            art12_record_hash: record.hash.clone(),
            signer_assurance,
            signer_backend: signer_backend.to_string(),
            signature: String::new(),
        };
        receipt.signature = hex::encode(key.sign(&receipt.preimage()).to_bytes());
        receipt
    }

    /// Verify the mediator's signature (strict). Establishes ONLY that this receipt
    /// is the holder of `mediator_pubkey`'s word — the relying party must still
    /// check that key's SVID is attested and that `art12_record_hash` is in the
    /// witnessed lineage (see the module docs).
    pub fn verify(&self, mediator_pubkey: &VerifyingKey) -> Result<(), MediationReceiptError> {
        if self.schema_version != MEDIATION_RECEIPT_SCHEMA_VERSION {
            return Err(MediationReceiptError::UnknownSchema(self.schema_version));
        }
        let raw = hex::decode(&self.signature)
            .map_err(|_| MediationReceiptError::BadSignatureEncoding)?;
        let bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| MediationReceiptError::BadSignatureEncoding)?;
        // `verify_strict`, never `verify`: it rejects the small-order / malleable
        // signatures the plain path accepts (enforced repo-wide by
        // check-verify-strict.sh).
        mediator_pubkey
            .verify_strict(&self.preimage(), &Signature::from_bytes(&bytes))
            .map_err(|_| MediationReceiptError::SignatureInvalid)
    }

    /// True iff this receipt genuinely describes `record`: the content hash AND the
    /// verdict fields match. This is what ties a signature-verified receipt to a
    /// record the relying party has independently proven is in the witnessed
    /// lineage — so the receipt cannot borrow another decision's inclusion proof.
    #[must_use]
    pub fn binds_record(&self, record: &Art12Record) -> bool {
        self.art12_record_hash == record.hash
            && self.operation == record.operation
            && self.subject == record.subject
            && self.verdict == record.verdict
            && self.session_id == record.session_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::art12_record::Actor;

    fn record(op: &str) -> Art12Record {
        Art12Record {
            schema_version: 1,
            seq: 4,
            timestamp_unix: 1_700_000_000,
            session_id: "sess-1".into(),
            transport: "http".into(),
            actor: Actor {
                kind: "authenticated".into(),
                spiffe_id: Some("spiffe://demo/ns/default/sa/agent".into()),
            },
            operation: op.into(),
            subject: "/etc/passwd".into(),
            verdict: "deny".into(),
            gate_class: "hard".into(),
            deny_reason: None,
            policy_checksum: "abc".into(),
            policy_rule: None,
            dlc_admission: "admitted".into(),
            lockdown_active: false,
            decision_sequence: Some(9),
            extensions: Default::default(),
            prev_hash: "00".into(),
            hash: format!("hash-of-{op}"),
            signature: "hmac".into(),
        }
    }

    fn keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn issue_then_verify_round_trips() {
        let (sk, vk) = keypair();
        let r = record("read_file");
        let receipt = MediationReceipt::issue(
            &r,
            "spiffe://demo/ns/default/sa/proxy",
            1,
            "self-measured",
            &sk,
        );
        assert!(receipt.verify(&vk).is_ok());
        assert_eq!(receipt.signer_assurance, 1);
        assert_eq!(receipt.signer_backend, "self-measured");
        assert!(
            receipt.binds_record(&r),
            "the receipt must bind its source record"
        );
    }

    #[test]
    fn a_tampered_field_fails_verification() {
        let (sk, vk) = keypair();
        let mut receipt = MediationReceipt::issue(
            &record("read_file"),
            "spiffe://demo/proxy",
            1,
            "self-measured",
            &sk,
        );
        receipt.operation = "run_bash".into(); // forge the operation, keep the signature
        assert_eq!(
            receipt.verify(&vk),
            Err(MediationReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn a_swapped_record_hash_fails_verification() {
        let (sk, vk) = keypair();
        let mut receipt = MediationReceipt::issue(
            &record("read_file"),
            "spiffe://demo/proxy",
            1,
            "self-measured",
            &sk,
        );
        receipt.art12_record_hash = "hash-of-something-else".into();
        assert_eq!(
            receipt.verify(&vk),
            Err(MediationReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn a_different_mediator_key_does_not_verify() {
        let (sk, _vk) = keypair();
        let receipt = MediationReceipt::issue(
            &record("read_file"),
            "spiffe://demo/proxy",
            1,
            "self-measured",
            &sk,
        );
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert_eq!(
            receipt.verify(&other),
            Err(MediationReceiptError::SignatureInvalid)
        );
    }

    /// A receipt binds exactly the record it was issued over — it cannot be
    /// pointed at a different record to borrow that record's lineage inclusion.
    #[test]
    fn binds_only_its_own_record() {
        let (sk, _vk) = keypair();
        let r = record("read_file");
        let receipt = MediationReceipt::issue(&r, "spiffe://demo/proxy", 1, "self-measured", &sk);
        assert!(receipt.binds_record(&r));
        assert!(!receipt.binds_record(&record("run_bash")));
    }

    /// The self-claimed assurance/backend are in the signed preimage, so an
    /// attacker cannot inflate `L1 → L2` (or swap the backend) on a captured
    /// receipt without breaking the signature. (The *semantic* cross-check that the
    /// claim equals an independently-verified attestation lives in the tool-proxy;
    /// this guards the cryptographic half — the claim is bound, not free-floating.)
    #[test]
    fn a_forged_signer_assurance_or_backend_fails_verification() {
        let (sk, vk) = keypair();
        let mut inflated = MediationReceipt::issue(
            &record("read_file"),
            "spiffe://demo/proxy",
            1,
            "self-measured",
            &sk,
        );
        inflated.signer_assurance = 2; // claim L2Device on an L1 signature
        assert_eq!(
            inflated.verify(&vk),
            Err(MediationReceiptError::SignatureInvalid)
        );

        let mut swapped = MediationReceipt::issue(
            &record("read_file"),
            "spiffe://demo/proxy",
            1,
            "self-measured",
            &sk,
        );
        swapped.signer_backend = "apple-sep".into(); // claim a hardware backend
        assert_eq!(
            swapped.verify(&vk),
            Err(MediationReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn a_future_schema_is_rejected_not_guessed() {
        let (sk, vk) = keypair();
        let mut receipt = MediationReceipt::issue(
            &record("read_file"),
            "spiffe://demo/proxy",
            1,
            "self-measured",
            &sk,
        );
        receipt.schema_version = 999;
        assert_eq!(
            receipt.verify(&vk),
            Err(MediationReceiptError::UnknownSchema(999))
        );
    }
}
