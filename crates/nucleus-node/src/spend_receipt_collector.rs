//! Host-side collection and verification of `SpendReceipt`s streamed from pods
//! over vsock (`SHIP_SPEND`), and the fold the node applies at release.
//!
//! # Why this is separate from the mediation-receipt collector
//!
//! [`crate::mediation_receipt_collector`] stores opaque lines and leaves
//! verification to `nucleus-audit`, because nothing on the node DECIDES on a
//! mediation receipt. A spend receipt is different: the node decides, at
//! `release_child`, how much of a pod's allocation to fold into its parent's
//! consumption (#2541). A decision taken on an unverified number is the guest
//! deciding its own bill, so every receipt is verified here — against the
//! node's OWN record of the key it minted for this pod (`mediator-pubkey.hex`),
//! never a key the guest supplies — and the log holds only what verified.
//!
//! # One decider
//!
//! [`check`] is the single function that says whether a line is a valid spend
//! receipt for a pod. The vsock handler calls it to accept or refuse a shipped
//! line; [`verified_spend`] calls it again over the stored log at release. Two
//! call sites, one rule (ADR 0007 G-1).
//!
//! # What the fold refuses to guess
//!
//! `portcullis::spend_receipt::VerifiedSpend` is three-valued. `NoReceipts` and
//! `Gapped` are both "the host could not see every charge", and `release_child`
//! folds the FULL allocation for either. Only `Complete` — receipts `1..=n`, all
//! verified — is a spend the node will count as less than everything.

use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use portcullis::spend_receipt::{SpendReceipt, SpendReceiptError, VerifiedSpend};

/// The verified-spend log inside a pod's node-side directory. Same directory
/// and same host-privacy argument as `collected-receipts.jsonl`.
#[must_use]
pub fn spend_log_path(pod_dir: &Path) -> PathBuf {
    pod_dir.join("spend-receipts.jsonl")
}

/// Why a shipped line was not accepted as this pod's spend receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendRejection {
    /// Not a `SpendReceipt` JSON document.
    Malformed,
    /// The receipt names a pod other than the one this connection is bound to.
    WrongPod,
    /// The node holds no `mediator-pubkey.hex` for this pod: it minted no
    /// mediation key, so nothing could have signed a receipt it would trust.
    NoAnchor,
    /// The anchor file exists and is not a 32-byte hex Ed25519 public key.
    AnchorUnreadable,
    /// The signature does not verify under the anchored key.
    Signature(SpendReceiptError),
}

impl std::fmt::Display for SpendRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => f.write_str("spend receipt body is not a SpendReceipt"),
            Self::WrongPod => f.write_str("spend receipt names another pod"),
            Self::NoAnchor => f.write_str("no mediator key was minted for this pod"),
            Self::AnchorUnreadable => f.write_str("mediator key anchor is unreadable"),
            Self::Signature(e) => write!(f, "spend receipt rejected: {e}"),
        }
    }
}

/// The public key the node minted for this pod's mediator, from its own anchor.
fn anchor_key(pod_dir: &Path) -> Result<VerifyingKey, SpendRejection> {
    let hex_text = std::fs::read_to_string(pod_dir.join("mediator-pubkey.hex"))
        .map_err(|_| SpendRejection::NoAnchor)?;
    let raw = hex::decode(hex_text.trim()).map_err(|_| SpendRejection::AnchorUnreadable)?;
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| SpendRejection::AnchorUnreadable)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| SpendRejection::AnchorUnreadable)
}

/// Whether `line` is a spend receipt for `pod_id`, signed by the key the node
/// minted for that pod. The one decider (see the module docs).
///
/// Order matters for the walk model's predictions: a body that is not a
/// receipt is `Malformed` before any key is consulted, so the refusal a guest
/// sees for garbage does not depend on host state.
pub fn check(pod_dir: &Path, pod_id: &str, line: &str) -> Result<SpendReceipt, SpendRejection> {
    let receipt: SpendReceipt =
        serde_json::from_str(line).map_err(|_| SpendRejection::Malformed)?;
    if receipt.pod_id != pod_id {
        return Err(SpendRejection::WrongPod);
    }
    let key = anchor_key(pod_dir)?;
    receipt.verify(&key).map_err(SpendRejection::Signature)?;
    Ok(receipt)
}

/// Append one CHECKED receipt line to the pod's spend log, synced before the
/// caller acks the pod (the same durability contract as mediation receipts).
///
/// # Errors
/// If the append fails — the caller must NOT ack the pod on error.
pub async fn append_spend(
    pod_dir: &Path,
    line: &str,
) -> Result<nucleus_jsonl::Durable, std::io::Error> {
    nucleus_jsonl::append_line_synced_async(spend_log_path(pod_dir), line.to_owned()).await
}

/// Fold the pod's stored receipts into what the node may count as spent.
///
/// Every line is re-checked: the log is host-private, but re-verifying costs a
/// few signatures per pod exit and removes "the file was valid when written"
/// from the trust argument. A line that fails is dropped with a warning; the
/// gap it leaves is what [`VerifiedSpend::Gapped`] reports.
#[must_use]
pub fn verified_spend(pod_dir: &Path, pod_id: &str) -> VerifiedSpend {
    let Ok(text) = std::fs::read_to_string(spend_log_path(pod_dir)) else {
        return VerifiedSpend::NoReceipts;
    };
    let mut verified = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match check(pod_dir, pod_id, line) {
            Ok(r) => verified.push(r),
            Err(e) => tracing::warn!(
                pod = pod_id,
                line = n.saturating_add(1),
                error = %e,
                "a stored spend receipt did not re-verify; it is dropped from the fold"
            ),
        }
    }
    VerifiedSpend::fold(verified.iter())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const POD: &str = "0f7b3a2e-1111-4222-8333-444455556666";

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn anchor(dir: &Path, k: &SigningKey) {
        std::fs::write(
            dir.join("mediator-pubkey.hex"),
            format!("{}\n", hex::encode(k.verifying_key().to_bytes())),
        )
        .unwrap();
    }

    fn line(seq: u64, amount: u64, k: &SigningKey) -> String {
        serde_json::to_string(&SpendReceipt::issue(
            "spiffe://t/mediator",
            POD,
            seq,
            amount,
            "authority-round:abc",
            k,
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn two_shipped_receipts_fold_to_their_sum() {
        let dir = tempfile::tempdir().unwrap();
        let k = key(3);
        anchor(dir.path(), &k);
        for (seq, amt) in [(1, 300_000), (2, 200_000)] {
            let l = line(seq, amt, &k);
            check(dir.path(), POD, &l).expect("a valid receipt is accepted");
            let kept = append_spend(dir.path(), &l).await.unwrap();
            assert!(kept.proves(&spend_log_path(dir.path()), &l));
        }
        assert_eq!(
            verified_spend(dir.path(), POD),
            VerifiedSpend::Complete {
                total_micro: 500_000,
                count: 2
            }
        );
    }

    #[test]
    fn no_log_is_no_receipts() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(verified_spend(dir.path(), POD), VerifiedSpend::NoReceipts);
    }

    #[test]
    fn a_receipt_under_another_key_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        anchor(dir.path(), &key(3));
        let forged = line(1, 1, &key(4));
        assert_eq!(
            check(dir.path(), POD, &forged),
            Err(SpendRejection::Signature(
                SpendReceiptError::SignatureInvalid
            ))
        );
    }

    #[test]
    fn a_receipt_for_another_pod_is_refused_before_the_key_is_read() {
        let dir = tempfile::tempdir().unwrap();
        // No anchor on purpose: WrongPod must win over NoAnchor.
        let l = line(1, 1, &key(3));
        assert_eq!(
            check(dir.path(), "other-pod", &l),
            Err(SpendRejection::WrongPod)
        );
    }

    #[test]
    fn garbage_is_malformed_regardless_of_host_state() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            check(dir.path(), POD, r#"{"receipt":"walk"}"#),
            Err(SpendRejection::Malformed)
        );
    }

    #[test]
    fn a_pod_the_node_minted_no_key_for_can_ship_nothing_it_trusts() {
        let dir = tempfile::tempdir().unwrap();
        let l = line(1, 1, &key(3));
        assert_eq!(check(dir.path(), POD, &l), Err(SpendRejection::NoAnchor));
    }

    /// A forged line that somehow reached the log is dropped at fold time, and
    /// the sequence it occupied becomes a gap — the fold does not quietly sum
    /// the rest.
    #[tokio::test]
    async fn a_forged_line_in_the_log_becomes_a_gap_not_a_discount() {
        let dir = tempfile::tempdir().unwrap();
        let k = key(3);
        anchor(dir.path(), &k);
        // The middle line is forged (another key). Each append still proves it
        // reached the log: storage is not verification, and the fold is where
        // the forgery is caught.
        for l in [line(1, 100, &k), line(2, 100, &key(9)), line(3, 100, &k)] {
            let kept = append_spend(dir.path(), &l).await.unwrap();
            assert!(kept.proves(&spend_log_path(dir.path()), &l));
        }
        assert_eq!(
            verified_spend(dir.path(), POD),
            VerifiedSpend::Gapped { at_seq: 2 }
        );
    }
}
