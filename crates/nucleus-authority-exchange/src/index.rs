//! The price of authority, as a recomputable aggregate over receipts.
//!
//! # What an index is here, and what it is not
//!
//! Every orchestrator allocates scarce slots by self-reported urgency, and
//! self-reported urgency is inflated by whoever reports it. Under a truthful
//! mechanism the bid *is* the value, so the sequence of clearing prices is
//! something no heuristic allocator can produce: what egress, exec, approval
//! are actually worth per slot, to whom, at what contention. That series is
//! the information asymmetry the exchange creates, and this module is the
//! shape in which it can be published.
//!
//! Published without trust, because of two rules:
//!
//! 1. **The index is a pure function of a receipt set.** Same receipts, same
//!    index, in any order. Anyone holding the receipts re-derives every number.
//! 2. **A receipt that does not recompute is refused, not skipped.** An index
//!    over unverified receipts is a heuristic wearing a mechanism's name. And
//!    it is refused loudly — `IndexError`, naming the receipt — rather than
//!    dropped, because a dropped receipt is a tampered receipt nobody hears
//!    about.
//!
//! Receipts are deduplicated by content hash first. Every participant in a
//! round holds the *same* receipt, so a naive fold would count one clearing
//! once per bidder who witnessed it — the same defect the credit file guards
//! against, and it is invisible when it happens because a multiplied count
//! looks exactly like a larger one.
//!
//! # Where the dimension comes from
//!
//! The receipt's declared proposal id, via [`crate::slot_good`]. That
//! field is under the receipt's content hash, so a reader recovers *what was
//! sold* from the signed bytes and from nothing else.

use std::collections::{BTreeMap, BTreeSet};

use nucleus_econ_types::MicroUsd;
use nucleus_recompute::{ClearingReceipt, RecomputeOutcome, content_hash_hex, verify_receipt};
use serde::{Deserialize, Serialize};

use crate::clearing::slot_good;
use crate::good::ScarceGood;

/// Why a receipt set could not be indexed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IndexError {
    /// A receipt did not recompute. Refused, not skipped: the index is only
    /// over clearings a stranger can re-derive.
    #[error("receipt {hash} does not recompute: {outcome:?}")]
    ReceiptDoesNotRecompute {
        /// Its content hash.
        hash: String,
        /// What the verifier said.
        outcome: RecomputeOutcome,
    },
    /// Not a VCG receipt — a settlement or commons split is not a clearing
    /// price.
    #[error("receipt {hash} is not a VCG clearing")]
    NotAClearing {
        /// Its content hash.
        hash: String,
    },
    /// The proposal is not one this crate issues, so the good is unknown.
    #[error("receipt {hash} proposal {proposal:?} names no known dimension")]
    UnknownGood {
        /// Its content hash.
        hash: String,
        /// The declared proposal id.
        proposal: String,
    },
    /// Winners paid different prices. Outside the uniform-price regime the
    /// index is stated for; see `ClearError::NonUniformPrice`.
    #[error("receipt {hash} charged winners non-uniform prices")]
    NonUniformPrice {
        /// Its content hash.
        hash: String,
    },
}

/// Order statistics over the contested clearing prices of one dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceStats {
    /// Median.
    pub p50: MicroUsd,
    /// 90th percentile.
    pub p90: MicroUsd,
    /// The highest price paid.
    pub max: MicroUsd,
}

/// One dimension's slice of the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionIndex {
    /// Rounds cleared.
    pub rounds: u64,
    /// Rounds where demand exceeded supply — the only ones with a price.
    pub contested: u64,
    /// Bids submitted across all rounds.
    pub bidders: u64,
    /// Price statistics over the contested rounds. Absent exactly when
    /// `contested == 0`: nothing was priced, so there is no distribution to
    /// summarise, and inventing one from uncontested zeros would report a
    /// price of nothing as a price.
    pub price: Option<PriceStats>,
}

/// A recomputable index over a set of clearing receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceIndex {
    /// Per dimension, keyed by its label so the index serialises without a
    /// map over an enum.
    pub dimensions: BTreeMap<String, DimensionIndex>,
    /// Distinct receipts the index was computed over, after deduplication.
    pub receipts: u64,
}

/// The `p`-th percentile of a sorted slice as an order statistic
/// (`⌈p·k/100⌉ − 1`), `0` for an empty slice.
fn percentile(sorted: &[u64], p: usize) -> u64 {
    let k = sorted.len();
    if k == 0 {
        return 0;
    }
    let idx = k
        .saturating_mul(p)
        .saturating_add(99)
        .checked_div(100)
        .unwrap_or(1)
        .saturating_sub(1)
        .min(k.saturating_sub(1));
    sorted.get(idx).copied().unwrap_or(0)
}

impl PriceIndex {
    /// Build the index. Order-independent; refuses any receipt that does not
    /// recompute.
    ///
    /// # Errors
    ///
    /// [`IndexError`], naming the receipt, on the first one that cannot be
    /// indexed.
    pub fn from_receipts(receipts: &[ClearingReceipt]) -> Result<Self, IndexError> {
        // Dedup by content hash, and iterate in hash order so the result does
        // not depend on the order the receipts arrived in.
        let mut by_hash: BTreeMap<String, &ClearingReceipt> = BTreeMap::new();
        for r in receipts {
            by_hash.entry(content_hash_hex(r)).or_insert(r);
        }

        let mut rounds: BTreeMap<ScarceGood, Vec<u64>> = BTreeMap::new();
        let mut contested: BTreeMap<ScarceGood, u64> = BTreeMap::new();
        let mut bidders: BTreeMap<ScarceGood, u64> = BTreeMap::new();

        for (hash, receipt) in &by_hash {
            let outcome = verify_receipt(receipt);
            if outcome != RecomputeOutcome::Match {
                return Err(IndexError::ReceiptDoesNotRecompute {
                    hash: hash.clone(),
                    outcome,
                });
            }
            let ClearingReceipt::Vcg(claim) = receipt else {
                return Err(IndexError::NotAClearing { hash: hash.clone() });
            };
            let proposal = claim
                .proposals
                .first()
                .map(|p| p.id.clone())
                .unwrap_or_default();
            let Some(dimension) = slot_good(&proposal) else {
                return Err(IndexError::UnknownGood {
                    hash: hash.clone(),
                    proposal,
                });
            };
            let price = claim
                .clearing
                .winners
                .first()
                .map_or(0, |w| w.vcg_payment_micro_usd);
            if claim
                .clearing
                .winners
                .iter()
                .any(|w| w.vcg_payment_micro_usd != price)
            {
                return Err(IndexError::NonUniformPrice { hash: hash.clone() });
            }

            let n_bids = u64::try_from(claim.bids.len()).unwrap_or(u64::MAX);
            let entry = bidders.entry(dimension.clone()).or_insert(0);
            *entry = entry.saturating_add(n_bids);
            // The Clarke pivot is zero exactly when nobody was displaced, so
            // price > 0 is the contested test — read from the receipt, not
            // from a flag someone set.
            if price > 0 {
                rounds.entry(dimension.clone()).or_default().push(price);
                let c = contested.entry(dimension).or_insert(0);
                *c = c.saturating_add(1);
            } else {
                rounds.entry(dimension).or_default();
            }
        }

        // Rounds per dimension, contested or not.
        let mut round_counts: BTreeMap<ScarceGood, u64> = BTreeMap::new();
        for (hash, receipt) in &by_hash {
            let _ = hash;
            if let ClearingReceipt::Vcg(claim) = receipt
                && let Some(d) = claim.proposals.first().and_then(|p| slot_good(&p.id))
            {
                let c = round_counts.entry(d).or_insert(0);
                *c = c.saturating_add(1);
            }
        }

        let dims: BTreeSet<ScarceGood> = rounds.keys().cloned().collect();
        let mut dimensions = BTreeMap::new();
        for d in dims {
            let mut prices = rounds.remove(&d).unwrap_or_default();
            prices.sort_unstable();
            let n_contested = contested.get(&d).copied().unwrap_or(0);
            let price = if prices.is_empty() {
                None
            } else {
                Some(PriceStats {
                    p50: MicroUsd::new(percentile(&prices, 50)),
                    p90: MicroUsd::new(percentile(&prices, 90)),
                    max: MicroUsd::new(prices.last().copied().unwrap_or(0)),
                })
            };
            dimensions.insert(
                d.label().to_string(),
                DimensionIndex {
                    rounds: round_counts.get(&d).copied().unwrap_or(0),
                    contested: n_contested,
                    bidders: bidders.get(&d).copied().unwrap_or(0),
                    price,
                },
            );
        }

        Ok(PriceIndex {
            dimensions,
            receipts: u64::try_from(by_hash.len()).unwrap_or(u64::MAX),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clearing::{Clearing, VcgClearing};
    use crate::round::Round;
    use crate::test_support::bid;
    use nucleus_econ_types::AuctionId;
    use nucleus_permission_market::PermissionDimension;

    const EGRESS: PermissionDimension = PermissionDimension::NetworkEgress;
    const EXEC: PermissionDimension = PermissionDimension::CommandExec;

    fn cleared(dim: PermissionDimension, id: &str, values: &[u64]) -> ClearingReceipt {
        let mut r = Round::open(AuctionId::new(id), dim.into());
        for (i, v) in values.iter().enumerate() {
            r.submit(bid(&format!("{id}-{i}"), *v, dim))
                .expect("admitted");
        }
        VcgClearing
            .clear(&r)
            .expect("clears")
            .receipt()
            .expect("receipt")
            .clone()
    }

    #[test]
    fn the_index_is_a_pure_function_of_the_receipt_set_in_any_order() {
        let a = cleared(EGRESS, "a", &[100, 70]);
        let b = cleared(EGRESS, "b", &[50, 20, 10]);
        let c = cleared(EXEC, "c", &[9, 3]);
        let fwd = PriceIndex::from_receipts(&[a.clone(), b.clone(), c.clone()]).unwrap();
        let rev = PriceIndex::from_receipts(&[c, b, a]).unwrap();
        assert_eq!(fwd, rev);
    }

    /// Every participant holds the same receipt. Three copies of one clearing
    /// are one clearing.
    #[test]
    fn duplicate_receipts_are_one_round() {
        let a = cleared(EGRESS, "a", &[100, 70]);
        let idx = PriceIndex::from_receipts(&[a.clone(), a.clone(), a]).unwrap();
        assert_eq!(idx.receipts, 1);
        assert_eq!(idx.dimensions["network_egress"].rounds, 1);
    }

    #[test]
    fn dimensions_are_kept_apart_and_priced_from_their_own_receipts() {
        let idx = PriceIndex::from_receipts(&[
            cleared(EGRESS, "a", &[100, 70]),
            cleared(EGRESS, "b", &[50, 20]),
            cleared(EXEC, "c", &[9, 3]),
        ])
        .unwrap();
        let egress = &idx.dimensions["network_egress"];
        assert_eq!(egress.rounds, 2);
        assert_eq!(egress.contested, 2);
        assert_eq!(egress.bidders, 4);
        let p = egress.price.expect("priced");
        assert_eq!(p.max, MicroUsd::new(70));
        assert_eq!(p.p50, MicroUsd::new(20));
        let exec = &idx.dimensions["command_exec"];
        assert_eq!(exec.price.expect("priced").max, MicroUsd::new(3));
    }

    /// An uncontested round is a round, but not a price. `None` here is the
    /// absence of a distribution, and it is explained by `contested == 0`.
    #[test]
    fn uncontested_rounds_count_but_do_not_price() {
        let idx = PriceIndex::from_receipts(&[cleared(EGRESS, "lone", &[100])]).unwrap();
        let d = &idx.dimensions["network_egress"];
        assert_eq!(d.rounds, 1);
        assert_eq!(d.contested, 0);
        assert!(d.price.is_none());
    }

    /// A-19: a tampered receipt is refused by hash, not silently dropped.
    #[test]
    fn a_tampered_receipt_is_refused_by_name() {
        let mut bad = cleared(EGRESS, "a", &[100, 70]);
        let expected_hash = content_hash_hex(&bad);
        let ClearingReceipt::Vcg(ref mut claim) = bad else {
            panic!("vcg");
        };
        claim.clearing.winners[0].vcg_payment_micro_usd = 1;
        let tampered_hash = content_hash_hex(&bad);
        assert_ne!(expected_hash, tampered_hash, "tampering moves the hash");
        let err = PriceIndex::from_receipts(&[bad]).expect_err("must refuse");
        assert!(
            matches!(err, IndexError::ReceiptDoesNotRecompute { ref hash, .. } if *hash == tampered_hash),
            "{err:?}"
        );
    }

    /// A receipt whose proposal names no dimension cannot be attributed, and
    /// an index that guessed would be a heuristic.
    #[test]
    fn a_receipt_for_an_unknown_good_is_refused() {
        let mut r = cleared(EGRESS, "a", &[100, 70]);
        let ClearingReceipt::Vcg(ref mut claim) = r else {
            panic!("vcg");
        };
        for p in &mut claim.proposals {
            p.id = "something-else".into();
        }
        for b in &mut claim.bids {
            b.proposal_id = "something-else".into();
        }
        // Re-issue so it recomputes under the new (unknown) proposal name.
        let reissued = nucleus_recompute::issue_vcg(
            claim.bids.clone(),
            claim.proposals.clone(),
            claim.budget_micro_usd,
        )
        .unwrap();
        let err = PriceIndex::from_receipts(&[reissued]).expect_err("unknown good");
        assert!(matches!(err, IndexError::UnknownGood { .. }), "{err:?}");
    }

    #[test]
    fn percentiles_are_order_statistics() {
        let s = [10u64, 20, 30, 40, 50];
        assert_eq!(percentile(&s, 50), 30);
        assert_eq!(percentile(&s, 90), 50);
        assert_eq!(percentile(&[], 50), 0);
        assert_eq!(percentile(&[7], 50), 7);
    }
}
