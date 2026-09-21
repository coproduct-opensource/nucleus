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
//! # Sequence numbers are the completeness claim
//!
//! `seq` starts at 1 and increments by one per receipt the mediator issues. A
//! host that holds receipts 1, 2 and 4 knows one is missing, and a missing
//! receipt is a charge it cannot see. The fold treats a gap as "could not
//! look" and charges the full allocation — so suppressing a receipt costs the
//! pod more than shipping it, which is the incentive the design needs.

// Needs `crypto` (ed25519) AND `serde` (the receipt is shipped as JSON), the
// same gating as `mediation_receipt` and for the same reason.
#![cfg(all(feature = "crypto", feature = "serde"))]

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Schema version — a verifier rejects a version it does not know.
pub const SPEND_RECEIPT_SCHEMA_VERSION: u32 = 1;

/// Domain separator folded into every preimage, so a spend-receipt signature
/// can never be confused with a mediation receipt's or any other nucleus
/// structure's.
const PREIMAGE_DOMAIN: &str = "nucleus-spend-receipt-v1";

/// One signed charge against a pod's delegated budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpendReceipt {
    /// Layout version.
    pub schema_version: u32,
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
        format!(
            "{PREIMAGE_DOMAIN}|{}|{}|{}|{}|{}|{}",
            self.schema_version,
            self.mediator_spiffe_id,
            self.pod_id,
            self.seq,
            self.amount_micro,
            self.basis,
        )
        .into_bytes()
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

    /// Verify the mediator's signature (strict). Establishes ONLY that this
    /// receipt is the holder of `mediator_pubkey`'s word about a charge.
    pub fn verify(&self, mediator_pubkey: &VerifyingKey) -> Result<(), SpendReceiptError> {
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
/// Three-valued on purpose (ADR 0007 A-1): "no receipts" and "receipts with a
/// gap" are both cases where the host could not see every charge, and neither
/// may be reported as a spend of zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedSpend {
    /// The pod shipped nothing the host could verify.
    NoReceipts,
    /// Every receipt from `seq = 1` to `count` is present and verified.
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
        let mut seqs: Vec<(u64, u64)> = verified
            .into_iter()
            .map(|r| (r.seq, r.amount_micro))
            .collect();
        if seqs.is_empty() {
            return Self::NoReceipts;
        }
        seqs.sort_unstable_by_key(|(s, _)| *s);
        let mut expected: u64 = 1;
        let mut total: u64 = 0;
        for (seq, amount) in seqs {
            if seq != expected {
                return Self::Gapped { at_seq: expected };
            }
            total = total.saturating_add(amount);
            expected = expected.saturating_add(1);
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
        assert_eq!(r.verify(&k.verifying_key()), Ok(()));
    }

    #[test]
    fn a_changed_amount_fails_verification() {
        let k = key(7);
        let mut r = receipt(1, 250_000, &k);
        r.amount_micro = 1;
        assert_eq!(
            r.verify(&k.verifying_key()),
            Err(SpendReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn a_reattributed_pod_fails_verification() {
        let k = key(7);
        let mut r = receipt(1, 250_000, &k);
        r.pod_id = "pod-2".into();
        assert_eq!(
            r.verify(&k.verifying_key()),
            Err(SpendReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn another_key_does_not_verify() {
        let r = receipt(1, 250_000, &key(7));
        assert_eq!(
            r.verify(&key(8).verifying_key()),
            Err(SpendReceiptError::SignatureInvalid)
        );
    }

    #[test]
    fn unknown_schema_is_refused_before_the_signature_is_looked_at() {
        let k = key(7);
        let mut r = receipt(1, 250_000, &k);
        r.schema_version = 2;
        assert_eq!(
            r.verify(&k.verifying_key()),
            Err(SpendReceiptError::UnknownSchema(2))
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
            r.verify(&k.verifying_key()),
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
        assert_eq!(back.verify(&k.verifying_key()), Ok(()));
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
        let rs = [receipt(3, 5, &k), receipt(1, 10, &k), receipt(2, 20, &k)];
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
        let rs = [receipt(1, u64::MAX, &k), receipt(2, 1, &k)];
        assert_eq!(
            VerifiedSpend::fold(rs.iter()),
            VerifiedSpend::Complete {
                total_micro: u64::MAX,
                count: 2
            }
        );
    }
}
