//! Host-side collection of the `ClearingReceipt`s a pod's auctions produced,
//! and the binding that makes a spend receipt's claim checkable.
//!
//! # Why the host needs these, and why a hash was not enough
//!
//! A `SpendReceipt` says "I charged 2 000 000 µUSD, on the basis of
//! `authority-round:<hash>`". The hash names the clearing receipt that
//! justifies the amount — the bids, the proposals, the winners, the payments.
//! That receipt lived in the guest's `/run/nucleus/authority.jsonl`, on a
//! tmpfs, and died with the microVM. So the node held **a reference to
//! evidence nobody kept**: it could verify that the pod's mediator signed the
//! amount, and nothing at all about whether the amount was the one the
//! mechanism actually cleared.
//!
//! The pod now ships the clearing receipt over the same vsock channel
//! (`SHIP_CLEARING`), and this is where it lands.
//!
//! # Verification here is RECOMPUTATION, not a signature
//!
//! A spend receipt is checked against a key, because it is somebody's word.
//! A clearing receipt is not anybody's word: it carries its declared inputs,
//! so `nucleus_recompute::verify_receipt` re-derives the outputs with the
//! proven kernel and says [`RecomputeOutcome::Match`] or names the field that
//! diverged. That is strictly stronger than a signature — a signed wrong
//! clearing still fails here — which is why this collector does not care who
//! signed it.
//!
//! Two things are checked before a receipt is stored:
//!
//! 1. it recomputes, and
//! 2. its content hash is the one the sender claims, so the log is keyed by a
//!    name the spend receipt's `basis` can actually resolve.
//!
//! # The binding, and why it is load-bearing
//!
//! [`resolve_spend_basis`] is what makes the corpus matter rather than
//! decorate: a spend receipt whose `basis` names a clearing receipt the host
//! does not hold — or holds and cannot recompute — is **not credited**.
//! `PodAuthority::release_child` folds the full allocation in that case, the
//! same as for a missing receipt. Evidence that changes no decision is not
//! evidence, so the discount is conditional on the evidence being here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use nucleus_recompute::{ClearingReceipt, RecomputeOutcome, content_hash_hex, verify_receipt};

/// The prefix a `SpendReceipt::basis` uses to name the round that justifies it.
/// Written by `nucleus-tool-proxy`'s exchange; read here.
pub const AUTHORITY_ROUND_BASIS: &str = "authority-round:";

/// The collected-clearings log inside a pod's node-side directory. Same
/// directory and same host-privacy argument as the other per-pod records.
#[must_use]
pub fn clearing_log_path(pod_dir: &Path) -> PathBuf {
    pod_dir.join("clearing-receipts.jsonl")
}

/// Why a shipped clearing receipt was not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearingRejection {
    /// Not a `ClearingReceipt` JSON document.
    Malformed,
    /// The receipt does not recompute: a claimed output diverges from what the
    /// proven kernel derives from the declared inputs. The field is named.
    Mismatch(String),
    /// The receipt's declared inputs are not even well-formed enough to run.
    Invalid(String),
}

impl std::fmt::Display for ClearingRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => f.write_str("clearing receipt body is not a ClearingReceipt"),
            Self::Mismatch(field) => write!(f, "clearing receipt does not recompute: {field}"),
            Self::Invalid(why) => write!(f, "clearing receipt inputs are unusable: {why}"),
        }
    }
}

/// Whether `line` is a clearing receipt that recomputes. Returns its content
/// hash, which is the name a spend receipt's `basis` resolves against.
///
/// The one decider of "is this a usable clearing receipt", called by the vsock
/// handler on arrival and again by [`verified_clearings`] over the stored log
/// (ADR 0007 G-1).
pub fn check(line: &str) -> Result<(ClearingReceipt, String), ClearingRejection> {
    let receipt: ClearingReceipt =
        serde_json::from_str(line).map_err(|_| ClearingRejection::Malformed)?;
    match verify_receipt(&receipt) {
        RecomputeOutcome::Match => {
            let hash = content_hash_hex(&receipt);
            Ok((receipt, hash))
        }
        RecomputeOutcome::Mismatch { field, .. } => {
            Err(ClearingRejection::Mismatch(field.to_string()))
        }
        RecomputeOutcome::Invalid(why) => Err(ClearingRejection::Invalid(why)),
    }
}

/// Append one CHECKED clearing receipt, synced before the caller acks the pod.
///
/// # Errors
/// If the append fails — the caller must NOT ack the pod on error.
pub async fn append_clearing(
    pod_dir: &Path,
    line: &str,
) -> Result<nucleus_jsonl::Durable, std::io::Error> {
    nucleus_jsonl::append_line_synced_async(clearing_log_path(pod_dir), line.to_owned()).await
}

/// Every clearing receipt the host holds for this pod that still recomputes,
/// keyed by content hash.
///
/// Re-checked rather than trusted: the log is host-private, but re-deriving
/// costs one kernel run per receipt at pod exit and removes "it was valid when
/// written" from the trust argument. A line that no longer recomputes is
/// dropped with a warning, and the basis that named it then fails to resolve.
#[must_use]
pub fn verified_clearings(pod_dir: &Path) -> BTreeMap<String, ClearingReceipt> {
    let mut out = BTreeMap::new();
    let Ok(text) = std::fs::read_to_string(clearing_log_path(pod_dir)) else {
        return out;
    };
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        match check(line) {
            Ok((receipt, hash)) => {
                out.insert(hash, receipt);
            }
            Err(e) => tracing::warn!(
                line = n.saturating_add(1),
                error = %e,
                "a stored clearing receipt did not re-verify; the spend receipt \
                 naming it will not resolve"
            ),
        }
    }
    out
}

/// Whether a spend receipt's `basis` names a clearing receipt this host holds
/// and can recompute.
///
/// `None` for a basis this collector does not understand, so a future basis
/// kind cannot silently read as unresolved: the caller decides what an unknown
/// basis means, and today `release_child` treats it as "could not look".
#[must_use]
pub fn resolve_spend_basis(
    clearings: &BTreeMap<String, ClearingReceipt>,
    basis: &str,
) -> Option<bool> {
    let hash = basis.strip_prefix(AUTHORITY_ROUND_BASIS)?;
    Some(clearings.contains_key(hash))
}

/// What the node may credit a pod as having SPENT, or `None` for "could not
/// look".
///
/// This is the whole evidence chain in one place, and it is deliberately not in
/// `pod_authority.rs`: that file decides authority, and
/// `docs/econ-layer-boundary.md` keeps economics out of it. The authority side
/// receives a number and clamps it to the allocation; everything that reads a
/// receipt happens here.
///
/// `Some(total)` requires ALL of:
///
/// * the spend receipts verify under the key the node minted for this pod, and
/// * their sequence is exactly `1..=n`, so none is missing, and
/// * every receipt's `basis` names a clearing receipt this host holds and can
///   RECOMPUTE.
///
/// Any gap gives `None`, and `release_child` then folds the full allocation.
/// That is what makes the corpus load-bearing: a pod that wants the discount
/// has to ship the evidence, and the evidence has to survive recomputation.
#[must_use]
pub fn creditable_spend(pod_dir: &Path, pod_id: &str) -> Option<rust_decimal::Decimal> {
    use portcullis::spend_receipt::VerifiedSpend;

    let spends = crate::spend_receipt_collector::verified_spend_receipts(pod_dir, pod_id);
    match VerifiedSpend::fold(spends.iter()) {
        VerifiedSpend::Complete { total_micro, count } => {
            let clearings = verified_clearings(pod_dir);
            for s in &spends {
                match resolve_spend_basis(&clearings, &s.basis) {
                    Some(true) => {}
                    Some(false) => {
                        tracing::warn!(
                            pod = pod_id,
                            seq = s.seq,
                            basis = %s.basis,
                            "a spend receipt names a clearing receipt this host does not \
                             hold or cannot recompute; the pod is charged its full \
                             allocation"
                        );
                        return None;
                    }
                    None => {
                        tracing::warn!(
                            pod = pod_id,
                            seq = s.seq,
                            basis = %s.basis,
                            "a spend receipt carries a basis kind this node cannot resolve; \
                             treated as unlooked-at, not as satisfied"
                        );
                        return None;
                    }
                }
            }
            tracing::info!(
                pod = pod_id,
                receipts = count,
                clearings = clearings.len(),
                "every spend receipt resolves to a clearing receipt that recomputes"
            );
            Some(rust_decimal::Decimal::from_i128_with_scale(
                i128::from(total_micro),
                6,
            ))
        }
        VerifiedSpend::NoReceipts => None,
        VerifiedSpend::Gapped { at_seq } => {
            tracing::warn!(
                pod = pod_id,
                missing_seq = at_seq,
                "spend receipts have a gap; the pod is charged its full allocation"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// A real cleared round, issued by the proven kernel so it recomputes.
    fn a_real_clearing() -> ClearingReceipt {
        let bids = vec![
            nucleus_recompute::IntegerBid {
                bidder: "alice".into(),
                proposal_id: "authority-slot/network_egress".into(),
                effective_value_micro_usd: 3_000_000,
            },
            nucleus_recompute::IntegerBid {
                bidder: "bob".into(),
                proposal_id: "authority-slot/network_egress".into(),
                effective_value_micro_usd: 2_000_000,
            },
        ];
        let proposals = vec![nucleus_recompute::IntegerProposal {
            id: "authority-slot/network_egress".into(),
            cost_micro_usd: 1,
        }];
        nucleus_recompute::issue_vcg(bids, proposals, 1).expect("the kernel clears this")
    }

    #[tokio::test]
    async fn a_clearing_that_recomputes_is_stored_and_resolves_its_spend() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = a_real_clearing();
        let line = serde_json::to_string(&receipt).unwrap();
        let (_, hash) = check(&line).expect("it recomputes");
        let kept = append_clearing(dir.path(), &line).await.unwrap();
        assert!(kept.proves(&clearing_log_path(dir.path()), &line));

        let clearings = verified_clearings(dir.path());
        assert_eq!(clearings.len(), 1);
        assert_eq!(
            resolve_spend_basis(&clearings, &format!("{AUTHORITY_ROUND_BASIS}{hash}")),
            Some(true),
            "the basis the proxy writes must resolve"
        );
        assert_eq!(
            resolve_spend_basis(&clearings, &format!("{AUTHORITY_ROUND_BASIS}deadbeef")),
            Some(false),
            "a hash the host does not hold must NOT resolve"
        );
        assert_eq!(
            resolve_spend_basis(&clearings, "some-future-basis:x"),
            None,
            "an unknown basis kind is not silently 'unresolved'"
        );
    }

    /// The point of recomputing rather than checking a signature: a receipt
    /// whose claimed payment was edited is refused even though it is
    /// well-formed JSON that no key ever vouched for.
    #[tokio::test]
    async fn a_tampered_payment_is_refused_on_arrival_and_at_the_fold() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = a_real_clearing();
        let mut json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&receipt).unwrap()).unwrap();
        // Reach into the claim and overstate what the winner paid.
        let payments = json
            .pointer_mut("/clearing/winners/0/vcg_payment_micro_usd")
            .expect("the claim has a winner payment");
        *payments = serde_json::json!(9_999_999u64);
        let tampered = serde_json::to_string(&json).unwrap();

        match check(&tampered) {
            Err(ClearingRejection::Mismatch(field)) => {
                assert!(!field.is_empty(), "the refusal must name the field");
            }
            other => panic!("a tampered payment must be refused, got {other:?}"),
        }

        // Even if it reaches the log, the fold drops it and the basis it would
        // have satisfied no longer resolves.
        let kept = append_clearing(dir.path(), &tampered).await.unwrap();
        assert!(kept.proves(&clearing_log_path(dir.path()), &tampered));
        assert!(
            verified_clearings(dir.path()).is_empty(),
            "a stored receipt that does not recompute must not be counted"
        );
    }

    /// THE BINDING, end to end: a spend receipt is credited only when the host
    /// holds a clearing receipt that recomputes for its basis. This is the test
    /// that moved out of `pod_authority.rs` when the evidence chain did.
    #[tokio::test]
    async fn a_spend_is_credited_only_when_its_basis_is_here_and_recomputes() {
        use ed25519_dalek::SigningKey;
        use portcullis::spend_receipt::SpendReceipt;

        const POD: &str = "3f2a1b0c-1111-4222-8333-444455556666";
        let key = SigningKey::from_bytes(&[23u8; 32]);
        let dir = tempfile::tempdir().unwrap();
        // The node's own anchor for this pod's mediator key.
        std::fs::write(
            dir.path().join("mediator-pubkey.hex"),
            format!("{}\n", hex::encode(key.verifying_key().to_bytes())),
        )
        .unwrap();

        let clearing = a_real_clearing();
        let clearing_line = serde_json::to_string(&clearing).unwrap();
        let (_, hash) = check(&clearing_line).expect("it recomputes");
        let spend = SpendReceipt::issue(
            "spiffe://t/mediator",
            POD,
            1,
            2_000_000,
            &format!("{AUTHORITY_ROUND_BASIS}{hash}"),
            &key,
        );
        let spend_line = serde_json::to_string(&spend).unwrap();
        let kept = crate::spend_receipt_collector::append_spend(dir.path(), &spend_line)
            .await
            .unwrap();
        assert!(kept.proves(
            &crate::spend_receipt_collector::spend_log_path(dir.path()),
            &spend_line
        ));

        // Spend present, evidence absent: NOT credited. This is the state the
        // node was in before the pod shipped clearing receipts at all — it held
        // a hash pointing at nothing.
        assert_eq!(
            creditable_spend(dir.path(), POD),
            None,
            "a basis the host cannot resolve must not be credited"
        );

        // Evidence arrives: credited, and at the amount the receipt signed.
        let kept = append_clearing(dir.path(), &clearing_line).await.unwrap();
        assert!(kept.proves(&clearing_log_path(dir.path()), &clearing_line));
        assert_eq!(
            creditable_spend(dir.path(), POD),
            Some(rust_decimal::Decimal::from_i128_with_scale(2_000_000, 6)),
            "with the clearing receipt here, the signed amount is credited"
        );

        // A second spend naming a round nobody shipped poisons the credit
        // rather than being skipped: the host cannot see every charge, so it
        // credits none of them.
        let orphan = SpendReceipt::issue(
            "spiffe://t/mediator",
            POD,
            2,
            500_000,
            &format!("{AUTHORITY_ROUND_BASIS}deadbeef"),
            &key,
        );
        let orphan_line = serde_json::to_string(&orphan).unwrap();
        let kept = crate::spend_receipt_collector::append_spend(dir.path(), &orphan_line)
            .await
            .unwrap();
        assert!(kept.proves(
            &crate::spend_receipt_collector::spend_log_path(dir.path()),
            &orphan_line
        ));
        assert_eq!(
            creditable_spend(dir.path(), POD),
            None,
            "one unresolvable basis must not leave the rest silently credited"
        );
    }

    #[test]
    fn garbage_is_malformed() {
        assert_eq!(
            check("{\"not\":\"a receipt\"}"),
            Err(ClearingRejection::Malformed)
        );
    }
}
