//! `nucleus-recompute` — the money-path-runs-the-proven-function check (gap G4).
//!
//! A [`ClearingReceipt`] bundles a cleared outcome's **declared inputs** with its
//! **claimed outputs**. [`verify_receipt`] re-derives the outputs from the inputs
//! using the *proven* kernels in `nucleus-econ-kernels` (`classify` /
//! `seller_gross` / `refund` — pinned to `SettlementDecision.lean`;
//! `route_to_commons` — pinned to `Commons.lean`'s `routed_conserves`; `run_vcg` —
//! truthful/IR-proven) and compares them field-by-field to what was claimed.
//!
//! This is the centerpiece of "verify, don't trust": a relying party who never saw
//! the auction can take a receipt and confirm — by *recomputing* — that the
//! settlement split, the externality→commons routing, and the VCG payments are
//! exactly what the proven functions produce on the declared inputs. A MISPRICE
//! (claimed ≠ recompute), a skimmed commons split, or a fabricated VCG payment all
//! surface as a [`Mismatch`](RecomputeOutcome::Mismatch).
//!
//! ## Binding to lineage
//!
//! The receipt is generic content: [`content_hash_hex`] is `sha256` over the
//! domain-tagged canonical bytes, which is exactly what a `nucleus-lineage`
//! edge's `content_hash_hex` commits to. So an edge claiming a clearing is bound
//! to a receipt with **no lineage schema change** — the recompute reads the
//! content the edge already points at. (Wiring the bundle walker to call this is a
//! follow-up; this crate is the self-contained, tested recompute core.)
//!
//! ## What this does NOT prove
//!
//! Recompute checks the *arithmetic* is the proven function of the *declared*
//! inputs. It says nothing about whether those inputs are themselves truthful
//! (that `delivered_bps` reflects real delivery — the PoTE seam — or that the bid
//! set is complete — the on-chain `CommitSet` closure handles that). See
//! `docs/PROOFS.md`.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use nucleus_econ_kernels::{
    classify, refund, route_to_commons, run_vcg, seller_gross, Clearing, CommonsAllocation,
    CommonsShare, IntegerBid, IntegerProposal, Verdict,
};

/// Domain separator for the canonical receipt bytes (versioned).
const RECEIPT_DOMAIN: &[u8] = b"nucleus-recompute/clearing-receipt/v1\0";

/// A settlement claim: the cleared price + delivery score, and the claimed split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementClaim {
    /// Declared input: the cleared price, micro-USD.
    pub price_micro: u64,
    /// Declared input: the delivery score, basis points.
    pub delivered_bps: u64,
    /// Claimed output: the verdict.
    pub verdict: Verdict,
    /// Claimed output: the seller's gross payout.
    pub seller_gross: u64,
    /// Claimed output: the bidder's refund.
    pub refund: u64,
}

/// A commons-routing claim: the Pigouvian pool + shares, and the claimed split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonsClaim {
    /// Declared input: the pool to route, micro-USD.
    pub pool_micro: u64,
    /// Declared input: the destination shares (bps must sum to 10_000).
    pub shares: Vec<CommonsShare>,
    /// Claimed output: the per-destination allocations.
    pub allocations: Vec<CommonsAllocation>,
}

/// A VCG-clearing claim: the bids/proposals/budget, and the claimed clearing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcgClaim {
    /// Declared input: the submitted bids.
    pub bids: Vec<IntegerBid>,
    /// Declared input: the proposals being bid on.
    pub proposals: Vec<IntegerProposal>,
    /// Declared input: the budget ceiling, micro-USD.
    pub budget_micro_usd: u64,
    /// Claimed output: winners + Clarke-pivot payments + totals.
    pub clearing: Clearing,
}

/// A receipt for one cleared outcome: declared inputs + claimed outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClearingReceipt {
    /// A settlement split.
    Settlement(SettlementClaim),
    /// An externality→commons routing.
    Commons(CommonsClaim),
    /// A VCG clearing.
    Vcg(VcgClaim),
}

/// The result of recomputing a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecomputeOutcome {
    /// Every claimed output matches the proven kernel's recomputation.
    Match,
    /// A claimed output diverges from the recomputed value.
    Mismatch {
        /// Which field diverged (e.g. `"seller_gross"`, `"allocations"`).
        field: &'static str,
        /// What the receipt claimed.
        claimed: String,
        /// What the proven kernel actually produces.
        recomputed: String,
    },
    /// The declared inputs were rejected by the kernel (e.g. commons shares don't
    /// sum to 10_000, or VCG input validation failed) — the receipt is not
    /// well-formed, so its claim cannot stand.
    Invalid(String),
}

impl RecomputeOutcome {
    /// `true` only for [`RecomputeOutcome::Match`].
    pub fn is_match(&self) -> bool {
        matches!(self, RecomputeOutcome::Match)
    }
}

fn mismatch<A: std::fmt::Debug, B: std::fmt::Debug>(
    field: &'static str,
    claimed: A,
    recomputed: B,
) -> RecomputeOutcome {
    RecomputeOutcome::Mismatch {
        field,
        claimed: format!("{claimed:?}"),
        recomputed: format!("{recomputed:?}"),
    }
}

/// Re-derive a receipt's claimed outputs from its declared inputs via the proven
/// kernels and compare. [`RecomputeOutcome::Match`] iff every claimed number is
/// exactly what the proven function produces.
pub fn verify_receipt(receipt: &ClearingReceipt) -> RecomputeOutcome {
    match receipt {
        ClearingReceipt::Settlement(c) => {
            let v = classify(c.delivered_bps);
            if v != c.verdict {
                return mismatch("verdict", c.verdict, v);
            }
            let g = seller_gross(c.price_micro, c.delivered_bps);
            if g != c.seller_gross {
                return mismatch("seller_gross", c.seller_gross, g);
            }
            let r = refund(c.price_micro, c.delivered_bps);
            if r != c.refund {
                return mismatch("refund", c.refund, r);
            }
            RecomputeOutcome::Match
        }
        ClearingReceipt::Commons(c) => match route_to_commons(c.pool_micro, &c.shares) {
            Ok(allocs) => {
                if allocs != c.allocations {
                    mismatch("allocations", &c.allocations, &allocs)
                } else {
                    RecomputeOutcome::Match
                }
            }
            Err(e) => RecomputeOutcome::Invalid(e.to_string()),
        },
        ClearingReceipt::Vcg(c) => match run_vcg(&c.bids, &c.proposals, c.budget_micro_usd) {
            Ok(clearing) => {
                if clearing != c.clearing {
                    mismatch("clearing", &c.clearing, &clearing)
                } else {
                    RecomputeOutcome::Match
                }
            }
            Err(e) => RecomputeOutcome::Invalid(format!("{e:?}")),
        },
    }
}

/// Canonical, domain-tagged bytes for a receipt. Deterministic: the receipt types
/// contain no maps, so serde's field/element order is stable. This is what a
/// lineage edge's `content_hash_hex` commits to.
pub fn canonical_bytes(receipt: &ClearingReceipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECEIPT_DOMAIN.len() + 256);
    out.extend_from_slice(RECEIPT_DOMAIN);
    // Infallible for these concrete, map-free types.
    serde_json::to_writer(&mut out, receipt).expect("receipt serialization is infallible");
    out
}

/// `sha256` over [`canonical_bytes`], hex-encoded — the value a `nucleus-lineage`
/// edge's `content_hash_hex` carries for a clearing receipt. A relying party
/// checks both that the edge points at this hash AND that [`verify_receipt`]
/// returns [`Match`](RecomputeOutcome::Match).
pub fn content_hash_hex(receipt: &ClearingReceipt) -> String {
    let mut h = Sha256::new();
    h.update(canonical_bytes(receipt));
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shares() -> Vec<CommonsShare> {
        vec![
            CommonsShare {
                destination: "carbon".into(),
                bps: 6_000,
            },
            CommonsShare {
                destination: "affected".into(),
                bps: 2_500,
            },
            CommonsShare {
                destination: "verifier".into(),
                bps: 1_500,
            },
        ]
    }

    // ── Settlement ────────────────────────────────────────────────────────────

    fn honest_settlement(price: u64, bps: u64) -> ClearingReceipt {
        ClearingReceipt::Settlement(SettlementClaim {
            price_micro: price,
            delivered_bps: bps,
            verdict: classify(bps),
            seller_gross: seller_gross(price, bps),
            refund: refund(price, bps),
        })
    }

    #[test]
    fn honest_settlement_matches() {
        assert!(verify_receipt(&honest_settlement(1_000_000, 2_500)).is_match());
        assert!(verify_receipt(&honest_settlement(7_654_321, 5_000)).is_match());
        assert!(verify_receipt(&honest_settlement(1, 10_000)).is_match());
    }

    #[test]
    fn misprice_seller_gross_is_caught() {
        let mut r = honest_settlement(1_000_000, 2_500);
        if let ClearingReceipt::Settlement(ref mut c) = r {
            c.seller_gross += 1; // skim 1 micro-USD
        }
        match verify_receipt(&r) {
            RecomputeOutcome::Mismatch { field, .. } => assert_eq!(field, "seller_gross"),
            other => panic!("expected seller_gross mismatch, got {other:?}"),
        }
    }

    #[test]
    fn wrong_verdict_is_caught() {
        let mut r = honest_settlement(1_000_000, 10_000); // Release
        if let ClearingReceipt::Settlement(ref mut c) = r {
            c.verdict = Verdict::Partial; // lie about the verdict
        }
        match verify_receipt(&r) {
            RecomputeOutcome::Mismatch { field, .. } => assert_eq!(field, "verdict"),
            other => panic!("expected verdict mismatch, got {other:?}"),
        }
    }

    #[test]
    fn broken_conservation_refund_is_caught() {
        let mut r = honest_settlement(1_000_000, 2_500);
        if let ClearingReceipt::Settlement(ref mut c) = r {
            c.refund -= 1; // pocket 1 micro-USD: seller_gross + refund != price
        }
        match verify_receipt(&r) {
            RecomputeOutcome::Mismatch { field, .. } => assert_eq!(field, "refund"),
            other => panic!("expected refund mismatch, got {other:?}"),
        }
    }

    // ── Commons ─────────────────────────────────────────────────────────────

    fn honest_commons(pool: u64) -> ClearingReceipt {
        let allocations = route_to_commons(pool, &shares()).unwrap();
        ClearingReceipt::Commons(CommonsClaim {
            pool_micro: pool,
            shares: shares(),
            allocations,
        })
    }

    #[test]
    fn honest_commons_matches() {
        assert!(verify_receipt(&honest_commons(1_000_000)).is_match());
        assert!(verify_receipt(&honest_commons(7)).is_match());
    }

    #[test]
    fn skimmed_commons_allocation_is_caught() {
        let mut r = honest_commons(1_000_000);
        if let ClearingReceipt::Commons(ref mut c) = r {
            c.allocations[0].amount_micro -= 100; // skim from the first destination
        }
        match verify_receipt(&r) {
            RecomputeOutcome::Mismatch { field, .. } => assert_eq!(field, "allocations"),
            other => panic!("expected allocations mismatch, got {other:?}"),
        }
    }

    #[test]
    fn commons_shares_not_summing_is_invalid() {
        let bad = ClearingReceipt::Commons(CommonsClaim {
            pool_micro: 1_000_000,
            shares: vec![CommonsShare {
                destination: "only".into(),
                bps: 9_999,
            }],
            allocations: vec![CommonsAllocation {
                destination: "only".into(),
                amount_micro: 1_000_000,
            }],
        });
        assert!(matches!(verify_receipt(&bad), RecomputeOutcome::Invalid(_)));
    }

    // ── VCG ───────────────────────────────────────────────────────────────────

    fn vcg_inputs() -> (Vec<IntegerBid>, Vec<IntegerProposal>, u64) {
        let bids = vec![
            IntegerBid {
                bidder: "alice".into(),
                proposal_id: "high".into(),
                effective_value_micro_usd: 70_000_000,
            },
            IntegerBid {
                bidder: "bob".into(),
                proposal_id: "low".into(),
                effective_value_micro_usd: 65_000_000,
            },
        ];
        let proposals = vec![
            IntegerProposal {
                id: "high".into(),
                cost_micro_usd: 60_000_000,
            },
            IntegerProposal {
                id: "low".into(),
                cost_micro_usd: 60_000_000,
            },
        ];
        (bids, proposals, 100_000_000)
    }

    fn honest_vcg() -> ClearingReceipt {
        let (bids, proposals, budget) = vcg_inputs();
        let clearing = run_vcg(&bids, &proposals, budget).unwrap();
        ClearingReceipt::Vcg(VcgClaim {
            bids,
            proposals,
            budget_micro_usd: budget,
            clearing,
        })
    }

    #[test]
    fn honest_vcg_matches() {
        assert!(verify_receipt(&honest_vcg()).is_match());
    }

    #[test]
    fn fabricated_vcg_payment_is_caught() {
        let mut r = honest_vcg();
        if let ClearingReceipt::Vcg(ref mut c) = r {
            // Understate the winner's VCG payment (pocket the difference).
            c.clearing.winners[0].vcg_payment_micro_usd = 0;
            c.clearing.total_payments_micro_usd = 0;
        }
        match verify_receipt(&r) {
            RecomputeOutcome::Mismatch { field, .. } => assert_eq!(field, "clearing"),
            other => panic!("expected clearing mismatch, got {other:?}"),
        }
    }

    // ── Content-hash binding ───────────────────────────────────────────────────

    #[test]
    fn content_hash_is_deterministic_and_tamper_evident() {
        let r = honest_settlement(1_000_000, 2_500);
        let h1 = content_hash_hex(&r);
        let h2 = content_hash_hex(&r.clone());
        assert_eq!(h1, h2, "canonical hash must be deterministic");
        assert_eq!(h1.len(), 64);

        // A different receipt → different hash (so an edge's content_hash_hex
        // cannot point at one receipt while a different one is recomputed).
        let other = honest_settlement(1_000_000, 2_501);
        assert_ne!(h1, content_hash_hex(&other));
    }

    #[test]
    fn receipt_round_trips_through_json() {
        for r in [
            honest_settlement(1_000_000, 2_500),
            honest_commons(7),
            honest_vcg(),
        ] {
            let bytes = serde_json::to_vec(&r).unwrap();
            let back: ClearingReceipt = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(r, back);
            assert!(verify_receipt(&back).is_match());
        }
    }
}
