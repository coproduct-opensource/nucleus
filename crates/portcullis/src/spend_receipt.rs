//! Spend receipt — the mediator's signed statement that one charge was made
//! against a pod's delegated budget.
//!
//! # Why the host needs this
//!
//! A pod's budget is allocated by the node when the pod is admitted and returned
//! to the parent's ledger when the pod exits. Between those two moments the only
//! place a charge happens is INSIDE the guest — the tool-proxy's own ledger
//! debits the Clarke pivot when an authority round is won — and the node cannot
//! see it. So the node had one honest option at release: fold the WHOLE
//! allocation into the parent's consumption, as if every dollar were spent
//! (#2541). Correct, and wasteful: a pod that spent nothing costs its parent
//! everything.
//!
//! A [`SpendReceipt`] is the guest's account of one charge, signed with the
//! per-pod mediation key the node minted and served once before any workload
//! existed (`FETCH_MEDIATION_KEY`). The node verifies each receipt against its
//! OWN record of that key (`mediator-pubkey.hex`), keeps the verified ones in a
//! host-side log the pod cannot retract, and at release folds
//! `min(allocation, Σ verified)` — never more than was delegated, and never
//! less than what was signed for.
//!
//! # What a verified receipt establishes, and what it does not
//!
//! Signature verification proves the receipt is the **mediation-key-holder's
//! word**. That key lives in the tool-proxy, not the workload, so a workload
//! cannot mint one — the same trust granularity as [`crate::mediation_receipt`],
//! and stated there. It does not prove the charge was *warranted*; that is what
//! the clearing receipt named in [`SpendReceipt::basis`] is for, and a relying
//! party recomputes it with `nucleus-recompute`.
//!
//! # Completeness requires a signed terminal statement
//!
//! Charges are numbered from 1. A gap detects a missing interior charge, but
//! a contiguous prefix cannot detect a lost tail. Only a signed `Final` record
//! committing to the next sequence and accumulated total establishes completion.
//! The issuer must stop charging before sealing. Missing, duplicate, misplaced,
//! or inconsistent terminal evidence never earns a refund.

// Needs `crypto` (ed25519) AND `serde` (the receipt is shipped as JSON), the
// same gating as `mediation_receipt` and for the same reason.
#![cfg(all(feature = "crypto", feature = "serde"))]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Schema version — a verifier rejects a version it does not know.
pub const SPEND_RECEIPT_SCHEMA_VERSION: u32 = 2;

/// Domain separator folded into every preimage, so a spend-receipt signature
/// can never be confused with a mediation receipt's or any other nucleus
/// structure's.
const PREIMAGE_DOMAIN: &str = "nucleus-spend-receipt-v2";

/// A charge or the mediator's irrevocable end-of-log statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpendKind {
    /// One debit against the delegated budget.
    Charge,
    /// No more charges can occur. `seq` follows the last charge and
    /// `amount_micro` commits to the sum of all preceding charges.
    Final,
}

/// One signed charge against a pod's delegated budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendReceipt {
    /// Layout version.
    pub schema_version: u32,
    /// The statement this signature attests to.
    pub kind: SpendKind,
    /// SPIFFE id of the mediator (the tool-proxy) that made the charge.
    pub mediator_spiffe_id: String,
    /// The pod whose budget was charged. The host checks this against the pod
    /// the vsock connection is bound to, so a receipt cannot be filed under
    /// another pod.
    pub pod_id: String,
    /// 1-based, contiguous per pod. See the module docs.
    pub seq: u64,
    /// The charge, micro-USD.
    pub amount_micro: u64,
    /// What the charge was for — e.g. `authority-round:<clearing receipt content
    /// hash>`. Opaque here; bound by the signature so it cannot be re-attributed.
    pub basis: String,
    /// Hex-encoded Ed25519 signature over [`SpendReceipt::preimage`].
    pub signature: String,
}

/// Why a spend receipt did not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendReceiptError {
    /// A schema version this verifier does not know.
    UnknownSchema(u32),
    /// The signature is not 64 hex-encoded bytes.
    BadSignatureEncoding,
    /// The signature does not verify over the receipt's preimage.
    SignatureInvalid,
}

impl std::fmt::Display for SpendReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchema(v) => write!(f, "unknown spend-receipt schema version {v}"),
            Self::BadSignatureEncoding => write!(f, "signature is not valid hex or not 64 bytes"),
            Self::SignatureInvalid => {
                write!(f, "mediator signature does not verify over the receipt")
            }
        }
    }
}

impl std::error::Error for SpendReceiptError {}

impl SpendReceipt {
    /// The canonical preimage, reconstructed from the receipt's own fields —
    /// never re-serialized JSON, so a verifier is not checking its own
    /// serializer. Excludes the signature.
    #[must_use]
    pub fn preimage(&self) -> Vec<u8> {
        let mut out = PREIMAGE_DOMAIN.as_bytes().to_vec();
        out.extend_from_slice(&self.schema_version.to_be_bytes());
        out.push(match self.kind {
            SpendKind::Charge => 0,
            SpendKind::Final => 1,
        });
        // Length framing prevents a separator inside an identity or basis
        // from moving bytes into the adjacent signed field.
        for value in [&self.mediator_spiffe_id, &self.pod_id, &self.basis] {
            out.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.amount_micro.to_be_bytes());
        out
    }

    /// Issue a receipt for one charge. `seq` is the caller's monotonic counter;
    /// a caller that reuses or skips one has made the pod's whole spend log
    /// unreadable at the host (see the module docs), which is the point.
    #[must_use]
    pub fn issue(
        mediator_spiffe_id: &str,
        pod_id: &str,
        seq: u64,
        amount_micro: u64,
        basis: &str,
        key: &SigningKey,
    ) -> Self {
        let mut receipt = Self {
            schema_version: SPEND_RECEIPT_SCHEMA_VERSION,
            kind: SpendKind::Charge,
            mediator_spiffe_id: mediator_spiffe_id.to_string(),
            pod_id: pod_id.to_string(),
            seq,
            amount_micro,
            basis: basis.to_string(),
            signature: String::new(),
        };
        receipt.signature = hex::encode(key.sign(&receipt.preimage()).to_bytes());
        receipt
    }

    /// Seal a stopped accounting session. The caller must prevent all later
    /// charges before signing: this is evidence about the complete log, not a
    /// checkpoint. `next_seq` is one after the last charge, or 1 for no charges.
    #[must_use]
    pub fn seal(
        mediator: &str,
        pod: &str,
        next_seq: u64,
        total_micro: u64,
        key: &SigningKey,
    ) -> Self {
        let mut receipt = Self::issue(mediator, pod, next_seq, total_micro, "", key);
        receipt.kind = SpendKind::Final;
        receipt.signature = hex::encode(key.sign(&receipt.preimage()).to_bytes());
        receipt
    }

    /// Verify the mediator's signature (strict). Establishes ONLY that this
    /// receipt is the holder of `mediator_pubkey`'s word about a charge.
    ///
    /// Named `verify_strict`, not `verify`, so the guarantee travels to every
    /// call site: the body rejects the small-order and malleable signatures
    /// `VerifyingKey::verify` accepts, and a reader of the CALLER should not
    /// have to open this file to learn that. It also keeps the exemplar
    /// scoreboard's `permissive_verify` census honest — that metric reads call
    /// sites, and a strict verifier spelled `verify` reads there as a
    /// permissive one.
    pub fn verify_strict(&self, mediator_pubkey: &VerifyingKey) -> Result<(), SpendReceiptError> {
        if self.schema_version != SPEND_RECEIPT_SCHEMA_VERSION {
            return Err(SpendReceiptError::UnknownSchema(self.schema_version));
        }
        let raw =
            hex::decode(&self.signature).map_err(|_| SpendReceiptError::BadSignatureEncoding)?;
        let bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| SpendReceiptError::BadSignatureEncoding)?;
        // `verify_strict`, never `verify`: it rejects the small-order / malleable
        // signatures the plain path accepts.
        mediator_pubkey
            .verify_strict(&self.preimage(), &Signature::from_bytes(&bytes))
            .map_err(|_| SpendReceiptError::SignatureInvalid)
    }
}

/// Fold a pod's receipts into the amount the host may count as spent.
///
/// Absence, an unsealed prefix, and gaps all mean the host could not see
/// every charge (ADR 0007 A-1). None may be reported as a spend of zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedSpend {
    /// The pod shipped nothing the host could verify.
    NoReceipts,
    /// A contiguous prefix without a signed end-of-log statement.
    Unsealed,
    /// Every charge from `seq = 1` to `count` is present, followed by a
    /// verified terminal record at `count + 1` committing to their total.
    Complete {
        /// Σ `amount_micro`, saturating.
        total_micro: u64,
        /// How many receipts were folded.
        count: u64,
    },
    /// Verified receipts exist but their sequence is not `1..=n`: a charge is
    /// missing or duplicated, and the total cannot be trusted.
    Gapped {
        /// The first sequence number expected and not found, or found twice.
        at_seq: u64,
    },
}

impl VerifiedSpend {
    /// Fold receipts that have ALREADY been verified. Order-independent.
    ///
    /// The caller verifies (it holds the key); this function only asks whether
    /// the verified set is complete. An unverified receipt must not be passed
    /// here — it is the caller's job to drop it, and dropping it is what
    /// produces the gap this function reports.
    #[must_use]
    pub fn fold<'a>(verified: impl IntoIterator<Item = &'a SpendReceipt>) -> Self {
        let mut receipts: Vec<&SpendReceipt> = verified.into_iter().collect();
        if receipts.is_empty() {
            return Self::NoReceipts;
        }
        receipts.sort_unstable_by_key(|r| r.seq);
        let mut expected: u64 = 1;
        let mut total: u64 = 0;
        let mut sealed = false;
        for receipt in receipts {
            if sealed || receipt.seq != expected {
                return Self::Gapped { at_seq: expected };
            }
            match receipt.kind {
                SpendKind::Charge => {
                    total = total.saturating_add(receipt.amount_micro);
                    expected = expected.saturating_add(1);
                }
                SpendKind::Final => {
                    if receipt.amount_micro != total || !receipt.basis.is_empty() {
                        return Self::Gapped { at_seq: expected };
                    }
                    sealed = true;
                }
            }
        }
        if !sealed {
            return Self::Unsealed;
        }
        Self::Complete {
            total_micro: total,
            count: expected.saturating_sub(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn receipt(seq: u64, amount: u64, k: &SigningKey) -> SpendReceipt {
        SpendReceipt::issue(
            "spiffe://t/mediator",
            "pod-1",
            seq,
            amount,
            "authority-round:abc",
            k,
        )
    }

    #[test]
    fn issued_receipt_verifies_under_its_key() {
        let k = key(7);
        let r = receipt(1, 250_000, &k);
        assert_eq!(r.verify_strict(&k.verifying_key()), Ok(()));
    }

    #[test]
    fn a_changed_amount_fails_verification() {
        let k = key(7);
        let mut r = receipt(1, 250_000, &k);
        r.amount_micro = 1;
        assert_eq!(
            r.verify_strict(&k.verifying_key()),
            Err(SpendReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn a_reattributed_pod_fails_verification() {
        let k = key(7);
        let mut r = receipt(1, 250_000, &k);
        r.pod_id = "pod-2".into();
        assert_eq!(
            r.verify_strict(&k.verifying_key()),
            Err(SpendReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn another_key_does_not_verify() {
        let r = receipt(1, 250_000, &key(7));
        assert_eq!(
            r.verify_strict(&key(8).verifying_key()),
            Err(SpendReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn unknown_schema_is_refused_before_the_signature_is_looked_at() {
        let k = key(7);
        let mut r = receipt(1, 250_000, &k);
        r.schema_version = SPEND_RECEIPT_SCHEMA_VERSION + 1;
        assert_eq!(
            r.verify_strict(&k.verifying_key()),
            Err(SpendReceiptError::UnknownSchema(
                SPEND_RECEIPT_SCHEMA_VERSION + 1
            ))
        );
    }

    #[test]
    fn a_mediation_receipt_signature_cannot_be_reused_here() {
        // Same key, same bytes as fields, but the domain separator differs, so a
        // signature lifted from any other structure fails.
        let k = key(7);
        let mut r = receipt(1, 250_000, &k);
        let other_domain = format!(
            "nucleus-mediation-receipt-v1|{}",
            String::from_utf8_lossy(&r.preimage())
        );
        r.signature = hex::encode(k.sign(other_domain.as_bytes()).to_bytes());
        assert_eq!(
            r.verify_strict(&k.verifying_key()),
            Err(SpendReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn json_roundtrip_preserves_the_signature() {
        let k = key(7);
        let r = receipt(3, 42, &k);
        let json = serde_json::to_string(&r).unwrap();
        let back: SpendReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.verify_strict(&k.verifying_key()), Ok(()));
    }

    #[test]
    fn signed_fields_cannot_be_repartitioned_at_a_separator() {
        let k = key(1);
        let first = SpendReceipt::issue("a|b", "c", 1, 10, "basis", &k);
        let mut second = first.clone();
        second.mediator_spiffe_id = "a".into();
        second.pod_id = "b|c".into();
        assert_ne!(first.preimage(), second.preimage());
        assert_eq!(
            second.verify_strict(&k.verifying_key()),
            Err(SpendReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn a_charge_cannot_be_relabelled_as_a_terminal_statement() {
        let k = key(1);
        let mut r = receipt(1, 0, &k);
        r.kind = SpendKind::Final;
        assert_eq!(
            r.verify_strict(&k.verifying_key()),
            Err(SpendReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn only_a_terminal_statement_proves_a_contiguous_log_complete() {
        let k = key(1);
        let first = receipt(1, 10, &k);
        let last = receipt(2, 20, &k);
        let seal = SpendReceipt::seal("spiffe://t/mediator", "pod-1", 3, 30, &k);
        assert_eq!(seal.verify_strict(&k.verifying_key()), Ok(()));
        assert_eq!(VerifiedSpend::fold([&first]), VerifiedSpend::Unsealed);
        assert_eq!(
            VerifiedSpend::fold([&first, &last]),
            VerifiedSpend::Unsealed
        );
        assert_eq!(
            VerifiedSpend::fold([&first, &seal]),
            VerifiedSpend::Gapped { at_seq: 2 }
        );
        assert_eq!(
            VerifiedSpend::fold([&seal, &last, &first]),
            VerifiedSpend::Complete {
                count: 2,
                total_micro: 30
            }
        );
        let wrong_total = SpendReceipt::seal("spiffe://t/mediator", "pod-1", 3, 29, &k);
        assert_eq!(
            VerifiedSpend::fold([&first, &last, &wrong_total]),
            VerifiedSpend::Gapped { at_seq: 3 }
        );
        assert_eq!(
            VerifiedSpend::fold([&first, &last, &seal, &seal]),
            VerifiedSpend::Gapped { at_seq: 3 }
        );
        let later = receipt(4, 1, &k);
        assert_eq!(
            VerifiedSpend::fold([&first, &last, &seal, &later]),
            VerifiedSpend::Gapped { at_seq: 3 }
        );
    }

    #[test]
    fn a_zero_spend_requires_an_explicit_terminal_record() {
        let k = key(1);
        let seal = SpendReceipt::seal("spiffe://t/mediator", "pod-1", 1, 0, &k);
        assert_eq!(
            VerifiedSpend::fold([&seal]),
            VerifiedSpend::Complete {
                count: 0,
                total_micro: 0
            }
        );
    }

    // ── fold ─────────────────────────────────────────────────────────────

    #[test]
    fn no_receipts_is_not_zero_spend() {
        assert_eq!(
            VerifiedSpend::fold(std::iter::empty()),
            VerifiedSpend::NoReceipts
        );
    }

    #[test]
    fn a_complete_sequence_sums_regardless_of_order() {
        let k = key(1);
        let rs = [
            receipt(3, 5, &k),
            receipt(1, 10, &k),
            receipt(2, 20, &k),
            SpendReceipt::seal("spiffe://t/mediator", "pod-1", 4, 35, &k),
        ];
        assert_eq!(
            VerifiedSpend::fold(rs.iter()),
            VerifiedSpend::Complete {
                total_micro: 35,
                count: 3
            }
        );
    }

    #[test]
    fn a_missing_receipt_is_a_gap_not_a_smaller_total() {
        let k = key(1);
        let rs = [receipt(1, 10, &k), receipt(3, 5, &k)];
        assert_eq!(
            VerifiedSpend::fold(rs.iter()),
            VerifiedSpend::Gapped { at_seq: 2 }
        );
    }

    #[test]
    fn a_sequence_not_starting_at_one_is_a_gap() {
        let k = key(1);
        let rs = [receipt(2, 10, &k)];
        assert_eq!(
            VerifiedSpend::fold(rs.iter()),
            VerifiedSpend::Gapped { at_seq: 1 }
        );
    }

    #[test]
    fn a_duplicated_receipt_is_a_gap_not_a_double_charge() {
        let k = key(1);
        let rs = [receipt(1, 10, &k), receipt(1, 10, &k)];
        assert_eq!(
            VerifiedSpend::fold(rs.iter()),
            VerifiedSpend::Gapped { at_seq: 2 }
        );
    }

    #[test]
    fn the_total_saturates_rather_than_wrapping() {
        let k = key(1);
        let rs = [
            receipt(1, u64::MAX, &k),
            receipt(2, 1, &k),
            SpendReceipt::seal("spiffe://t/mediator", "pod-1", 3, u64::MAX, &k),
        ];
        assert_eq!(
            VerifiedSpend::fold(rs.iter()),
            VerifiedSpend::Complete {
                total_micro: u64::MAX,
                count: 2
            }
        );
    }
}
