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
    CommonsError, CommonsShare, IntegerBid, IntegerProposal, VcgError, Verdict,
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

// ─────────────────────────────────────────────────────────────────────────────
// Producer side — "the money-path runs the proven function".
//
// `verify_receipt` is the VERIFIER (re-derive + compare). These `issue_*` fns are
// the dual PRODUCER: run the SAME proven kernels on the declared inputs and emit a
// receipt carrying both the inputs and the recomputable outputs. Honest by
// construction, and — crucially — verifiable offline by anyone via `verify_receipt`
// with zero trust in the issuer. Shipping these closes the e2e loop: there is now a
// production path that emits recompute-verifiable receipts, not just a verifier of
// hypothetical ones.
// ─────────────────────────────────────────────────────────────────────────────

/// Issue a settlement receipt by running the proven settlement kernels
/// (`classify` / `seller_gross` / `refund`) on the declared inputs. Total — the
/// settlement kernels accept any `(price, bps)`.
pub fn issue_settlement(price_micro: u64, delivered_bps: u64) -> ClearingReceipt {
    ClearingReceipt::Settlement(SettlementClaim {
        price_micro,
        delivered_bps,
        verdict: classify(delivered_bps),
        seller_gross: seller_gross(price_micro, delivered_bps),
        refund: refund(price_micro, delivered_bps),
    })
}

/// Issue a commons-routing receipt by running the proven `route_to_commons` kernel
/// (`Commons.lean`'s `routed_conserves`). Errors if the shares are ill-formed
/// (bps must sum to 10_000) — a malformed input cannot produce a standing receipt.
pub fn issue_commons(
    pool_micro: u64,
    shares: Vec<CommonsShare>,
) -> Result<ClearingReceipt, CommonsError> {
    let allocations = route_to_commons(pool_micro, &shares)?;
    Ok(ClearingReceipt::Commons(CommonsClaim {
        pool_micro,
        shares,
        allocations,
    }))
}

/// Issue a VCG-clearing receipt by running the proven `run_vcg` kernel
/// (truthful / individually-rational). Errors if VCG input validation fails.
pub fn issue_vcg(
    bids: Vec<IntegerBid>,
    proposals: Vec<IntegerProposal>,
    budget_micro_usd: u64,
) -> Result<ClearingReceipt, VcgError> {
    let clearing = run_vcg(&bids, &proposals, budget_micro_usd)?;
    Ok(ClearingReceipt::Vcg(VcgClaim {
        bids,
        proposals,
        budget_micro_usd,
        clearing,
    }))
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

/// Lift/narrow between [`ClearingReceipt`] and `nucleus-receipt`'s signed
/// colimit envelope (feature `envelope`, off by default).
///
/// A [`ClearingReceipt`] on its own is *unsigned*: its verification is pure
/// recomputation, so it says "these numbers re-derive" but not "who emitted
/// them". `nucleus-receipt`'s [`Receipt`](nucleus_receipt::Receipt) is the
/// Ed25519/BLAKE3 envelope that says who — and its
/// [`Projection::Economic`](nucleus_receipt::Projection::Economic) variant
/// was designed to carry exactly this body. This module wires the two, so a
/// clearing travels as one signed object carrying BOTH guarantees:
///
/// 1. **Signature** — [`Receipt::verify`](nucleus_receipt::Receipt::verify)
///    proves the issuer emitted these bytes (any tamper fails here first);
/// 2. **Recompute** — [`clearing_from_projection`] narrows the body back to a
///    typed [`ClearingReceipt`], and [`verify_receipt`](crate::verify_receipt)
///    re-derives every cleared number from the proven kernels.
///
/// ## Wire shape (stable)
///
/// The `Projection::Economic` body produced by [`to_economic_projection`] is:
///
/// ```json
/// { "kind": "clearing", "receipt": { "kind": "settlement", ... } }
/// ```
///
/// - outer `"kind"` is always [`ECONOMIC_CLEARING_KIND`] (`"clearing"`) — the
///   discriminant *within* the economic projection, so other economic bodies
///   (e.g. bid+match records) can coexist under the same projection kind;
/// - `"receipt"` is the internally-tagged [`ClearingReceipt`] JSON
///   (`"kind": "settlement" | "commons" | "vcg"`), unchanged from this
///   crate's existing wire format — [`content_hash_hex`](crate::content_hash_hex)
///   of the narrowed value therefore still matches any lineage edge that
///   committed to the bare receipt.
#[cfg(feature = "envelope")]
pub mod envelope {
    use crate::ClearingReceipt;

    pub use nucleus_receipt::Projection;

    /// The `"kind"` discriminant inside a `Projection::Economic` body that
    /// marks it as a clearing receipt. Stable wire constant.
    pub const ECONOMIC_CLEARING_KIND: &str = "clearing";

    /// Why a [`Projection`] could not be narrowed to a [`ClearingReceipt`].
    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum NarrowError {
        /// The projection is not `Projection::Economic` at all.
        #[error("projection kind is `{found}`, expected `economic`")]
        NotEconomic {
            /// The wire discriminant of the projection that was supplied.
            found: &'static str,
        },
        /// The economic body's `kind` is not `"clearing"` (or is missing) —
        /// some other economic record travels under this projection.
        #[error("economic body kind is `{found}`, expected `clearing`")]
        NotClearing {
            /// The inner `kind` found, or `<missing>`.
            found: String,
        },
        /// The body claimed to be a clearing but its `receipt` field is
        /// absent or does not deserialize as a [`ClearingReceipt`].
        #[error("economic clearing body is malformed: {0}")]
        MalformedBody(String),
    }

    /// Lift a [`ClearingReceipt`] into the [`Projection::Economic`] body it
    /// travels as inside a signed [`Receipt`](nucleus_receipt::Receipt).
    /// See the module docs for the stable inner shape.
    pub fn to_economic_projection(receipt: &ClearingReceipt) -> Projection {
        Projection::Economic(serde_json::json!({
            "kind": ECONOMIC_CLEARING_KIND,
            "receipt": receipt,
        }))
    }

    /// Narrow a [`Projection`] back to the typed [`ClearingReceipt`].
    ///
    /// Rejects, with distinct errors: non-`Economic` projections
    /// ([`NarrowError::NotEconomic`]), economic bodies that are not clearings
    /// ([`NarrowError::NotClearing`]), and clearing bodies whose `receipt`
    /// is missing or malformed ([`NarrowError::MalformedBody`]).
    ///
    /// Narrowing does NOT verify anything: call
    /// [`Receipt::verify`](nucleus_receipt::Receipt::verify) on the envelope
    /// *before* narrowing, and [`verify_receipt`](crate::verify_receipt) on
    /// the narrowed value after.
    pub fn clearing_from_projection(
        projection: &Projection,
    ) -> Result<ClearingReceipt, NarrowError> {
        let Projection::Economic(body) = projection else {
            return Err(NarrowError::NotEconomic {
                found: projection.kind(),
            });
        };
        match body.get("kind").and_then(serde_json::Value::as_str) {
            Some(ECONOMIC_CLEARING_KIND) => {}
            Some(other) => {
                return Err(NarrowError::NotClearing {
                    found: other.to_string(),
                })
            }
            None => {
                return Err(NarrowError::NotClearing {
                    found: "<missing>".to_string(),
                })
            }
        }
        let receipt = body
            .get("receipt")
            .ok_or_else(|| NarrowError::MalformedBody("missing `receipt` field".to_string()))?;
        serde_json::from_value(receipt.clone())
            .map_err(|e| NarrowError::MalformedBody(e.to_string()))
    }

    /// The end-to-end verifier verdict: BOTH guarantees in one value.
    #[derive(Debug, PartialEq, Eq)]
    pub enum SignedClearingVerdict {
        /// The Ed25519 signature did not verify (tampered bytes or wrong key) —
        /// checked FIRST, before any recompute.
        BadSignature,
        /// Signature verified, but the projection is not a narrowable clearing.
        Malformed(NarrowError),
        /// Signature verified + narrowed; the recompute outcome. Fully verified
        /// iff this is [`RecomputeOutcome::Match`](crate::RecomputeOutcome::Match).
        Recomputed(crate::RecomputeOutcome),
    }

    impl SignedClearingVerdict {
        /// `true` iff the signature verified AND every cleared number re-derives
        /// from the proven kernels — the only "fully verified" state.
        pub fn is_verified(&self) -> bool {
            matches!(
                self,
                SignedClearingVerdict::Recomputed(crate::RecomputeOutcome::Match)
            )
        }
    }

    /// The public end-to-end verifier: take a signed receipt envelope and a
    /// verifying key, and (1) check the Ed25519 signature over the canonical bytes
    /// (who emitted it), then (2) narrow to the typed [`ClearingReceipt`] and
    /// RECOMPUTE every cleared number via the proven kernels (the numbers re-derive).
    /// One call, both guarantees — this is what a relying party who never saw the
    /// auction runs to trust a receipt without trusting its issuer.
    pub fn verify_signed_clearing(
        signed: &nucleus_receipt::Receipt,
        verifying_key_bytes: &[u8; 32],
    ) -> SignedClearingVerdict {
        if signed.verify(verifying_key_bytes).is_err() {
            return SignedClearingVerdict::BadSignature;
        }
        // A clearing travels in the first (economic) projection.
        match signed.projections.first() {
            Some(p) => match clearing_from_projection(p) {
                Ok(receipt) => SignedClearingVerdict::Recomputed(crate::verify_receipt(&receipt)),
                Err(e) => SignedClearingVerdict::Malformed(e),
            },
            None => SignedClearingVerdict::Malformed(NarrowError::NotEconomic { found: "none" }),
        }
    }
}

// The headline e2e enforcement: a real producer issues a signed clearing, a
// relying party verifies signature + recompute in one call, and BOTH a
// post-signing byte tamper (caught by the signature) and a dishonest-issuer
// forged output under a VALID signature (caught by recompute) are rejected. This
// is the test that makes "the recompute layer is shipped e2e" a mechanical claim.
#[cfg(all(test, feature = "envelope"))]
mod e2e_enforcement_tests {
    use super::*;
    use crate::envelope::{to_economic_projection, verify_signed_clearing, SignedClearingVerdict};
    use nucleus_econ_kernels::CommonsShare;
    use nucleus_receipt::{Projection, Receipt, Session};

    fn session() -> Session {
        Session {
            session_id: "spiffe://test/clearing-issuer".into(),
            issuer_kid: "test-kid".into(),
            issued_at_micros: 1_717_000_000_000_000,
            parent_chain: vec![],
        }
    }

    fn shares() -> Vec<CommonsShare> {
        vec![
            CommonsShare {
                destination: "commons://carbon".into(),
                bps: 6000,
            },
            CommonsShare {
                destination: "commons://research".into(),
                bps: 4000,
            },
        ]
    }

    /// The full money path, for every receipt variant: issue via the proven
    /// kernels → sign → a relying party verifies signature + recompute in ONE call
    /// and it is fully verified.
    #[test]
    fn issued_clearings_verify_end_to_end() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let vk: [u8; 32] = sk.verifying_key().to_bytes();

        let receipts = [
            issue_settlement(1_000_000, 9_500),
            issue_commons(1_000_000, shares()).expect("well-formed shares"),
            issue_vcg(vcg_bids(), vcg_proposals(), 5_000_000).expect("valid vcg inputs"),
        ];
        for r in receipts {
            let signed = Receipt::sign(session(), vec![to_economic_projection(&r)], &sk);
            assert!(
                verify_signed_clearing(&signed, &vk).is_verified(),
                "issued receipt must verify (sig + recompute) e2e: {r:?}"
            );
        }
    }

    /// A post-signing byte tamper is caught by the SIGNATURE, before recompute.
    #[test]
    fn post_sign_tamper_is_rejected_by_signature() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let vk: [u8; 32] = sk.verifying_key().to_bytes();

        let r = issue_settlement(1_000_000, 9_500);
        let mut signed = Receipt::sign(session(), vec![to_economic_projection(&r)], &sk);
        let Projection::Economic(body) = &mut signed.projections[0] else {
            panic!("economic projection");
        };
        let claimed = body["receipt"]["seller_gross"].as_u64().unwrap();
        body["receipt"]["seller_gross"] = serde_json::json!(claimed + 1);

        assert_eq!(
            verify_signed_clearing(&signed, &vk),
            SignedClearingVerdict::BadSignature,
            "a post-signing tamper must fail the signature check"
        );
    }

    /// THE MOAT: a dishonest issuer forges an output (wrong seller_gross) and signs
    /// it with their OWN valid key — the signature verifies, but RECOMPUTE catches
    /// the lie. This is what a signature-only verifier cannot do.
    #[test]
    fn forged_output_under_valid_signature_is_caught_by_recompute() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let vk: [u8; 32] = sk.verifying_key().to_bytes();

        // Honest receipt, then forge a single cleared number.
        let mut claim = match issue_settlement(1_000_000, 9_500) {
            ClearingReceipt::Settlement(c) => c,
            _ => unreachable!(),
        };
        claim.seller_gross += 1; // the lie
        let forged = ClearingReceipt::Settlement(claim);

        // The attacker signs their own forged bytes — signature is VALID.
        let signed = Receipt::sign(session(), vec![to_economic_projection(&forged)], &sk);

        match verify_signed_clearing(&signed, &vk) {
            SignedClearingVerdict::Recomputed(RecomputeOutcome::Mismatch { field, .. }) => {
                assert_eq!(
                    field, "seller_gross",
                    "recompute must name the forged field"
                );
            }
            other => panic!("recompute must catch the forged output, got {other:?}"),
        }
    }

    fn vcg_bids() -> Vec<IntegerBid> {
        vec![
            IntegerBid {
                bidder: "spiffe://a".into(),
                proposal_id: "p1".into(),
                effective_value_micro_usd: 3_000_000,
            },
            IntegerBid {
                bidder: "spiffe://b".into(),
                proposal_id: "p1".into(),
                effective_value_micro_usd: 2_000_000,
            },
        ]
    }

    fn vcg_proposals() -> Vec<IntegerProposal> {
        vec![IntegerProposal {
            id: "p1".into(),
            cost_micro_usd: 1_000_000,
        }]
    }
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

    // ── Signed Economic projection (feature `envelope`) ───────────────────────

    #[cfg(feature = "envelope")]
    mod envelope_tests {
        use super::*;
        use crate::envelope::{
            clearing_from_projection, to_economic_projection, NarrowError, ECONOMIC_CLEARING_KIND,
        };
        use nucleus_receipt::{Projection, Receipt, ReceiptError, Session};

        fn session() -> Session {
            Session {
                session_id: "spiffe://test/clearing-agent".into(),
                issuer_kid: "test-kid".into(),
                issued_at_micros: 1_717_000_000_000_000,
                parent_chain: vec![],
            }
        }

        /// The round-trip law: narrow ∘ lift = id, for every receipt variant.
        #[test]
        fn lift_then_narrow_is_identity() {
            for r in [
                honest_settlement(1_000_000, 2_500),
                honest_commons(7),
                honest_vcg(),
            ] {
                let p = to_economic_projection(&r);
                assert_eq!(p.kind(), "economic");
                let back = clearing_from_projection(&p).expect("lifted projection narrows back");
                assert_eq!(back, r);
            }
        }

        #[test]
        fn economic_body_shape_is_stable() {
            // Wire pin: {"kind": "clearing", "receipt": {...}} — downstream
            // consumers dispatch on the inner kind, so drift fails here.
            let Projection::Economic(body) = to_economic_projection(&honest_settlement(10, 2_500))
            else {
                panic!("lift must produce an economic projection");
            };
            assert_eq!(body["kind"], ECONOMIC_CLEARING_KIND);
            assert_eq!(body["receipt"]["kind"], "settlement");
        }

        #[test]
        fn narrowing_rejects_non_economic_projection() {
            let p = Projection::Identity(serde_json::json!({"sub": "spiffe://test/agent"}));
            assert_eq!(
                clearing_from_projection(&p),
                Err(NarrowError::NotEconomic { found: "identity" })
            );
        }

        #[test]
        fn narrowing_rejects_other_economic_bodies() {
            // A different economic record under the same projection kind.
            let p = Projection::Economic(serde_json::json!({
                "kind": "bid_match",
                "receipt": {"anything": true},
            }));
            assert_eq!(
                clearing_from_projection(&p),
                Err(NarrowError::NotClearing {
                    found: "bid_match".into()
                })
            );
            // Missing inner kind entirely.
            let p = Projection::Economic(serde_json::json!({"receipt": {}}));
            assert_eq!(
                clearing_from_projection(&p),
                Err(NarrowError::NotClearing {
                    found: "<missing>".into()
                })
            );
        }

        #[test]
        fn narrowing_rejects_malformed_clearing_bodies() {
            // `receipt` field absent.
            let p = Projection::Economic(serde_json::json!({"kind": "clearing"}));
            assert!(matches!(
                clearing_from_projection(&p),
                Err(NarrowError::MalformedBody(_))
            ));
            // `receipt` present but not a ClearingReceipt.
            let p = Projection::Economic(serde_json::json!({
                "kind": "clearing",
                "receipt": {"kind": "settlement", "price_micro": "not-a-number"},
            }));
            assert!(matches!(
                clearing_from_projection(&p),
                Err(NarrowError::MalformedBody(_))
            ));
        }

        /// The full both-guarantees path: lift → sign → verify (signature:
        /// who emitted it) → narrow → recompute (the numbers re-derive).
        #[test]
        fn signed_envelope_carries_both_guarantees_end_to_end() {
            let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let vk: [u8; 32] = sk.verifying_key().to_bytes();

            for r in [
                honest_settlement(1_000_000, 2_500),
                honest_commons(1_000_000),
                honest_vcg(),
            ] {
                let signed = Receipt::sign(session(), vec![to_economic_projection(&r)], &sk);

                // Guarantee 1: the signature binds the issuer to these bytes.
                signed
                    .verify(&vk)
                    .expect("freshly signed envelope verifies");

                // Narrow the projection back to the typed receipt…
                let back = clearing_from_projection(&signed.projections[0])
                    .expect("signed economic projection narrows back");
                assert_eq!(back, r);

                // Guarantee 2: every cleared number re-derives from the
                // proven kernels on the narrowed value.
                assert!(verify_receipt(&back).is_match());
            }
        }

        /// Tampering with one cleared number inside the signed envelope is
        /// caught by the SIGNATURE check — before recompute is even consulted.
        #[test]
        fn tampered_cleared_number_fails_signature_before_recompute() {
            let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
            let vk: [u8; 32] = sk.verifying_key().to_bytes();

            let mut signed = Receipt::sign(
                session(),
                vec![to_economic_projection(&honest_settlement(1_000_000, 2_500))],
                &sk,
            );

            // Skim 1 micro-USD off the seller's gross inside the signed body.
            let Projection::Economic(body) = &mut signed.projections[0] else {
                panic!("envelope holds an economic projection");
            };
            let claimed = body["receipt"]["seller_gross"].as_u64().unwrap();
            body["receipt"]["seller_gross"] = serde_json::json!(claimed + 1);

            // The envelope check fails FIRST — no recompute needed: the
            // re-canonicalized bytes no longer match the signed root hash.
            assert!(matches!(
                signed.verify(&vk),
                Err(ReceiptError::RootHashMismatch { .. })
            ));

            // (And even if a consumer skipped the signature, the recompute
            // layer independently catches the skim on the narrowed value.)
            let back = clearing_from_projection(&signed.projections[0]).unwrap();
            assert!(matches!(
                verify_receipt(&back),
                RecomputeOutcome::Mismatch {
                    field: "seller_gross",
                    ..
                }
            ));
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IFC egress-gate verdict recompute (verify_ifc_flow)
//
// The gateway's IFC egress gate rejects an egress-allowlisted tool call when the
// chain's effective integrity is adversarial, and CO-COMMITS the decision into a
// signature-covered slot: the edge's `VerifierAttestation.ifc_gated_effective_
// integrity` (present iff the hop was egress-gated AND allowed). `verify_ifc_flow`
// lets any third party re-derive that verdict OFFLINE from the receipt — using
// the SAME `egress_blocked_by_integrity` predicate the gateway used (single
// source = the trustless guarantee), never re-querying the tool registry.
//
// HONEST SCOPE: this checks consistency-with-the-SIGNED-stamp, not the *truth* of
// the stamp (the effective-integrity value originates upstream; grounding it is a
// separate rung — have the runner sign it). It does NOT claim "a denial happened"
// — a denied egress produces no edge, so absence is not evidence. The property is
// only over present, signed, egress-gated hops.
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of recomputing one hop's IFC egress-gate verdict from its signed
/// `ifc_gated_effective_integrity` co-commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfcFlowOutcome {
    /// Not an egress-gate hop (the co-commit field was absent).
    NotGated,
    /// The signed co-commit is consistent with the allow-rule: an egress was
    /// permitted under an effective integrity the rule allows.
    Allow,
    /// The signed co-commit is SELF-INCONSISTENT: it records an *allowed* egress
    /// under an effective integrity the gate would have *denied* (adversarial or
    /// an unrecognized, fail-closed token). Such a signed edge cannot have been
    /// honestly produced — the gateway would have rejected before signing.
    Inconsistent {
        /// The effective integrity the co-commit claims the gate evaluated.
        effective_integrity: String,
    },
}

impl IfcFlowOutcome {
    /// `true` unless the co-commit is self-inconsistent. `NotGated` and `Allow`
    /// are both acceptable (a non-egress hop is vacuously fine).
    pub fn is_consistent(&self) -> bool {
        !matches!(self, IfcFlowOutcome::Inconsistent { .. })
    }
}

/// Re-derive a hop's IFC egress-gate verdict from its signed co-commit
/// (`VerifierAttestation.ifc_gated_effective_integrity`), using the single
/// source-of-truth predicate [`nucleus_ifc::egress_blocked_by_integrity`].
///
/// Plain-data (wasm-pure) core: takes the stamped value, never a `LineageEdge`
/// (`nucleus-lineage` is not wasm-pure). A `&LineageEdge` adapter belongs behind
/// an optional feature.
pub fn verify_ifc_flow(gated_effective_integrity: Option<&str>) -> IfcFlowOutcome {
    match gated_effective_integrity {
        None => IfcFlowOutcome::NotGated,
        Some(i) if !nucleus_ifc::egress_blocked_by_integrity(i) => IfcFlowOutcome::Allow,
        Some(i) => IfcFlowOutcome::Inconsistent {
            effective_integrity: i.to_string(),
        },
    }
}

/// Cross-check a hop's gate **output** against the **input** the runner signed
/// upstream: the child edge's `ifc_gated_effective_integrity` (the value the
/// gateway co-committed it gated on) must equal the parent edge's signed
/// `ifc_effective_integrity` (the running integrity the runner attested). A
/// mismatch means the gate evaluated a *different* value than was signed upstream
/// — e.g. someone fed the gate a downgraded label — so the hop is rejected even
/// if it is internally allow-consistent.
///
/// This binds gate-input(runner-signed) to gate-output(gateway-signed) across the
/// hop. It still does NOT ground either value's *truth* (a compromised runner can
/// sign a consistent-but-false pair) — that is the separate Level-2 rung.
///
/// `child_gated == None` ⇒ [`IfcFlowOutcome::NotGated`] (not an egress hop, the
/// cross-check is vacuous). Otherwise the egress hop must both be allow-consistent
/// (via [`verify_ifc_flow`]) AND match the parent's signed integrity.
pub fn verify_ifc_flow_consistent(
    child_gated: Option<&str>,
    parent_effective: Option<&str>,
) -> IfcFlowOutcome {
    match child_gated {
        None => IfcFlowOutcome::NotGated,
        Some(g) => {
            // First: the gated value must itself satisfy the allow-rule.
            match verify_ifc_flow(Some(g)) {
                IfcFlowOutcome::Allow => {
                    // Then: it must equal what the runner signed upstream.
                    if parent_effective == Some(g) {
                        IfcFlowOutcome::Allow
                    } else {
                        IfcFlowOutcome::Inconsistent {
                            effective_integrity: g.to_string(),
                        }
                    }
                }
                other => other, // already Inconsistent (adversarial / unknown)
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Whole-trace IFC conformance (verify_ifc_trace) — the RUNTIME WITNESS of the
// multi-hop unwinding theorem (D1, UnwindingNoninterference / the extracted
// integrity leg `irun_antitone`). The per-hop / per-pair checks above bind one
// edge; this binds the WHOLE chain: a real receipt trace must obey the property
// the theorem proves — effective integrity is MONOTONE-NON-INCREASING in trust
// along the chain, so taint introduced upstream can NEVER be laundered into an
// allowed egress downstream.
//
// HONEST SCOPE: validates a *present, signed* chain is internally consistent with
// the unwinding guarantee (tamper-evident: a chain whose trust *rises* could not
// have been honestly folded). It does NOT prove the labels are true, nor that the
// chain is complete (absence ≠ denial) — those are the same Level-2 residuals the
// single-hop checks carry. The theorem is over the model; this is the receipt-side
// round-trip that catches any run diverging from it.
// ─────────────────────────────────────────────────────────────────────────────

/// One hop of a signed IFC receipt chain: the running `ifc_effective_integrity`
/// the runner attested, and (if it was an egress hop) the
/// `ifc_gated_effective_integrity` the gateway co-committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfcHop {
    /// The running effective integrity the runner signed at this hop, if present.
    pub effective_integrity: Option<String>,
    /// The integrity the egress gate co-committed it evaluated, if this was an
    /// egress hop.
    pub gated_effective_integrity: Option<String>,
}

/// Outcome of recomputing a whole IFC receipt chain against the unwinding guarantee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceOutcome {
    /// Every hop is allow-consistent, pairwise-bound, and the chain's trust is
    /// monotone-non-increasing (no laundering). `hops` = number checked.
    Consistent {
        /// Number of hops validated.
        hops: usize,
    },
    /// A hop violated consistency. `hop_index` is the 0-based offending hop.
    Inconsistent {
        /// The offending hop's index.
        hop_index: usize,
        /// Why it was rejected.
        reason: String,
    },
}

impl TraceOutcome {
    /// `true` iff the whole chain conforms.
    pub fn is_consistent(&self) -> bool {
        matches!(self, TraceOutcome::Consistent { .. })
    }
}

/// Trust rank for the integrity order: `trusted (2) > untrusted (1) >
/// {adversarial, secret, unknown} (0, fail-closed)`. The join (taint) only ever
/// LOWERS this — the unwinding theorem's `irun_antitone`. An unrecognized token
/// folds to the bottom (fail-closed), matching `egress_blocked_by_integrity`.
fn integrity_rank(i: &str) -> u8 {
    match i {
        "trusted" => 2,
        "untrusted" => 1,
        _ => 0,
    }
}

/// Recompute a whole IFC receipt chain against the multi-hop unwinding guarantee.
///
/// Two checks, end to end: (1) each egress hop is allow-consistent and bound to
/// its predecessor's signed integrity ([`verify_ifc_flow_consistent`]); (2) the
/// chain's effective integrity is MONOTONE-NON-INCREASING in trust — a hop whose
/// running integrity is *more* trusted than its predecessor's is laundering
/// (the fold can only lower trust), so it is rejected. This is the receipt-side
/// round-trip of the unwinding theorem: any real run that diverges from the proven
/// monotone-fold property is caught here.
pub fn verify_ifc_trace(hops: &[IfcHop]) -> TraceOutcome {
    let mut prev_effective: Option<String> = None;
    for (idx, hop) in hops.iter().enumerate() {
        // (1) Per-hop egress allow-consistency + binding to the predecessor.
        let pair = verify_ifc_flow_consistent(
            hop.gated_effective_integrity.as_deref(),
            prev_effective.as_deref(),
        );
        if let IfcFlowOutcome::Inconsistent {
            effective_integrity,
        } = pair
        {
            return TraceOutcome::Inconsistent {
                hop_index: idx,
                reason: format!(
                    "egress hop inconsistent at effective integrity {effective_integrity:?}"
                ),
            };
        }
        // (2) Whole-chain monotonicity: trust may only ratchet DOWN (no laundering).
        if let (Some(prev), Some(cur)) = (
            prev_effective.as_deref(),
            hop.effective_integrity.as_deref(),
        ) {
            if integrity_rank(cur) > integrity_rank(prev) {
                return TraceOutcome::Inconsistent {
                    hop_index: idx,
                    reason: format!(
                        "trust rose along the chain ({prev:?} -> {cur:?}): the IFC fold can only \
                         lower integrity (unwinding theorem), so this is laundering"
                    ),
                };
            }
        }
        if hop.effective_integrity.is_some() {
            prev_effective = hop.effective_integrity.clone();
        }
    }
    TraceOutcome::Consistent { hops: hops.len() }
}

#[cfg(test)]
mod ifc_trace_tests {
    use super::*;

    fn hop(eff: &str, gated: Option<&str>) -> IfcHop {
        IfcHop {
            effective_integrity: Some(eff.to_string()),
            gated_effective_integrity: gated.map(str::to_string),
        }
    }

    #[test]
    fn clean_descending_chain_is_consistent() {
        // trusted -> untrusted: trust ratchets down; the egress hop gated on the
        // parent's signed integrity ("trusted", allowed) and bound to it.
        let chain = [hop("trusted", None), hop("untrusted", Some("trusted"))];
        assert!(verify_ifc_trace(&chain).is_consistent());
    }

    #[test]
    fn laundering_chain_is_rejected() {
        // adversarial taint enters, then trust "rises" to trusted with no egress —
        // impossible under the monotone fold. Isolates the no-laundering check.
        let chain = [hop("adversarial", None), hop("trusted", None)];
        match verify_ifc_trace(&chain) {
            TraceOutcome::Inconsistent { hop_index, reason } => {
                assert_eq!(hop_index, 1);
                assert!(
                    reason.contains("trust rose"),
                    "expected laundering reason, got: {reason}"
                );
            }
            other => panic!("expected laundering rejection, got {other:?}"),
        }
    }

    #[test]
    fn adversarial_egress_is_rejected() {
        // An egress hop co-committing an *allowed* egress under adversarial integrity
        // is self-inconsistent (the gate would have denied before signing).
        let chain = [hop("adversarial", Some("adversarial"))];
        assert!(!verify_ifc_trace(&chain).is_consistent());
    }

    #[test]
    fn empty_chain_is_vacuously_consistent() {
        assert_eq!(verify_ifc_trace(&[]), TraceOutcome::Consistent { hops: 0 });
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Budget node verdict recompute (verify_budget_*)
//
// The gateway enforces budget as a caveat ceiling + a running accumulator: a hop
// is permitted iff its charge fits the effective remaining (the `after_spend`
// deflationary invariant, Aeneas-extracted + `afterSpend_extracted_deflationary`).
// These fns re-derive that verdict OFFLINE from the SIGNED VA figures
// (`budget_charged` / `budget_effective_remaining` / `budget_spent_so_far`).
//
// HONEST SCOPE: checks the spend ledger is internally consistent + tamper-evident
// (a signed edge whose charge exceeds the remaining it claims to have evaluated is
// self-inconsistent). Does NOT check the charge is FAIR / the work happened (PoTE)
// nor that every hop is present (completeness). NOTE: this is NOT greedy_pack —
// that theorem models a closed-list auction allocation, the wrong model for an
// open-ended sequential gate.
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of recomputing a budget permit / flow check from signed figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetFlowOutcome {
    /// Not a budget-grounded hop (the relevant figures were absent).
    NotGrounded,
    /// The signed figures satisfy the permit / accumulator rule.
    Ok,
    /// Self-inconsistent: a charge exceeds the effective remaining the gate
    /// claimed to evaluate, or the chain spend-accumulator equation is violated.
    Inconsistent { reason: String },
}

impl BudgetFlowOutcome {
    /// `true` unless the figures are self-inconsistent. `NotGrounded` and `Ok`
    /// are both acceptable (an ungrounded hop is vacuously fine).
    pub fn is_consistent(&self) -> bool {
        !matches!(self, BudgetFlowOutcome::Inconsistent { .. })
    }
}

/// Re-derive the per-hop budget permit verdict: the signed charge must not exceed
/// the signed effective-remaining the gate evaluated (the `after_spend`
/// deflationary invariant). Plain-data wasm-pure (micro-USD decimal strings).
pub fn verify_budget_permit(
    effective_remaining_micro_usd: Option<&str>,
    charged_micro_usd: Option<&str>,
) -> BudgetFlowOutcome {
    match (effective_remaining_micro_usd, charged_micro_usd) {
        (None, None) => BudgetFlowOutcome::NotGrounded,
        (Some(rem), Some(chg)) => match (rem.parse::<u128>(), chg.parse::<u128>()) {
            (Ok(rem), Ok(chg)) if chg <= rem => BudgetFlowOutcome::Ok,
            (Ok(rem), Ok(chg)) => BudgetFlowOutcome::Inconsistent {
                reason: format!("charge {chg} exceeds effective remaining {rem}"),
            },
            _ => BudgetFlowOutcome::Inconsistent {
                reason: format!("unparseable budget figures rem={rem:?} chg={chg:?}"),
            },
        },
        _ => BudgetFlowOutcome::Inconsistent {
            reason: "partial budget grounding (charge xor remaining present)".to_string(),
        },
    }
}

/// Cross-check the chain spend accumulator across a parent→child hop:
/// `child_spent == parent_spent + parent_charged` and monotone-nondecreasing.
/// Mirrors [`verify_ifc_flow_consistent`].
pub fn verify_budget_flow_consistent(
    parent_spent_micro_usd: Option<&str>,
    parent_charged_micro_usd: Option<&str>,
    child_spent_micro_usd: Option<&str>,
) -> BudgetFlowOutcome {
    match (
        parent_spent_micro_usd,
        parent_charged_micro_usd,
        child_spent_micro_usd,
    ) {
        (None, None, None) => BudgetFlowOutcome::NotGrounded,
        (Some(ps), Some(pc), Some(cs)) => {
            match (ps.parse::<u128>(), pc.parse::<u128>(), cs.parse::<u128>()) {
                (Ok(ps), Ok(pc), Ok(cs)) => {
                    if cs < ps {
                        return BudgetFlowOutcome::Inconsistent {
                            reason: format!("spent went backwards: child {cs} < parent {ps}"),
                        };
                    }
                    match ps.checked_add(pc) {
                        Some(expected) if expected == cs => BudgetFlowOutcome::Ok,
                        Some(expected) => BudgetFlowOutcome::Inconsistent {
                            reason: format!(
                                "accumulator mismatch: child {cs} != parent_spent {ps} + parent_charged {pc} = {expected}"
                            ),
                        },
                        None => BudgetFlowOutcome::Inconsistent {
                            reason: "spend overflow".to_string(),
                        },
                    }
                }
                _ => BudgetFlowOutcome::Inconsistent {
                    reason: "unparseable spend figures".to_string(),
                },
            }
        }
        _ => BudgetFlowOutcome::Inconsistent {
            reason: "partial spend grounding".to_string(),
        },
    }
}

/// Outcome of re-deriving an `AttestationMode` tag against the signer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationModeOutcome {
    /// No mode tag present — the edge makes no Mediated/Attested claim.
    NotGrounded,
    /// The tag is consistent with the signer and the grounding requirement.
    Ok,
    /// A `Mediated` tag whose `handler_id` does not match the signer, OR an
    /// `Attested` tag presented where a grounded (observed) claim is required,
    /// OR an unrecognized mode kind.
    Rejected { reason: String },
}

/// Re-derive the `AttestationMode` verdict OFFLINE (plain-data, wasm-pure — does
/// NOT depend on `nucleus-lineage`). The lineage `AttestationMode` is decomposed
/// to plain data: `mode_kind` is `"mediated"` / `"attested"` / absent, and
/// `mode_id` is the handler_id / attestor_id.
///
/// The honesty invariant: `Mediated { handler_id }` is valid ONLY when
/// `handler_id == verifier_binary_hash` (the edge's signer) — so a tool cannot
/// self-assert `Mediated` (its signer hash is the tool, not the sealed handler).
/// `Attested` (relabeled trust) is REJECTED wherever `grounding_required`, so it
/// can never masquerade as a kernel-observed atom.
pub fn verify_attestation_mode(
    mode_kind: Option<&str>,
    mode_id: Option<&str>,
    verifier_binary_hash: Option<&str>,
    grounding_required: bool,
) -> AttestationModeOutcome {
    match mode_kind {
        None => AttestationModeOutcome::NotGrounded,
        Some("mediated") => match (mode_id, verifier_binary_hash) {
            (Some(handler_id), Some(signer)) if handler_id == signer => AttestationModeOutcome::Ok,
            (handler_id, signer) => AttestationModeOutcome::Rejected {
                reason: format!("forged Mediated: handler_id {handler_id:?} != signer {signer:?}"),
            },
        },
        Some("attested") if grounding_required => AttestationModeOutcome::Rejected {
            reason: "Attested claim presented where a Mediated (observed) claim is required"
                .to_string(),
        },
        Some("attested") => AttestationModeOutcome::Ok,
        Some(other) => AttestationModeOutcome::Rejected {
            reason: format!("unrecognized attestation mode kind {other:?}"),
        },
    }
}

#[cfg(test)]
mod attestation_mode_tests {
    use super::*;

    #[test]
    fn mediated_matching_signer_is_ok() {
        // A sealed handler signed the edge; its handler_id IS the signer hash.
        assert_eq!(
            verify_attestation_mode(
                Some("mediated"),
                Some("portcullis-effects@0.1.0"),
                Some("portcullis-effects@0.1.0"),
                true,
            ),
            AttestationModeOutcome::Ok,
        );
    }

    #[test]
    fn mediated_forged_by_tool_is_rejected() {
        // A tool stamps `Mediated{RealEffects::read}` into an edge IT signs.
        // Its signer hash is the tool, not the handler → forgery caught.
        assert!(matches!(
            verify_attestation_mode(
                Some("mediated"),
                Some("RealEffects::read"),
                Some("evil-tool@0.1"),
                true,
            ),
            AttestationModeOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn attested_where_grounding_required_is_rejected() {
        // Relabeled trust can never masquerade as an observed atom.
        assert!(matches!(
            verify_attestation_mode(Some("attested"), Some("web-fetch"), Some("signer"), true),
            AttestationModeOutcome::Rejected { .. }
        ));
    }

    #[test]
    fn attested_where_grounding_not_required_is_ok() {
        assert_eq!(
            verify_attestation_mode(Some("attested"), Some("web-fetch"), Some("signer"), false),
            AttestationModeOutcome::Ok,
        );
    }

    #[test]
    fn absent_mode_is_not_grounded() {
        assert_eq!(
            verify_attestation_mode(None, None, Some("signer"), true),
            AttestationModeOutcome::NotGrounded,
        );
    }
}

#[cfg(test)]
mod budget_flow_tests {
    use super::*;

    #[test]
    fn permit_ungrounded_is_not_grounded() {
        assert_eq!(
            verify_budget_permit(None, None),
            BudgetFlowOutcome::NotGrounded
        );
    }

    #[test]
    fn permit_charge_within_remaining_is_ok() {
        // anti-vacuity: a legitimate charge is accepted, not rejected.
        assert_eq!(
            verify_budget_permit(Some("1000"), Some("100")),
            BudgetFlowOutcome::Ok
        );
        assert_eq!(
            verify_budget_permit(Some("100"), Some("100")),
            BudgetFlowOutcome::Ok
        );
    }

    #[test]
    fn permit_charge_over_remaining_is_inconsistent() {
        assert!(!verify_budget_permit(Some("100"), Some("101")).is_consistent());
        assert!(!verify_budget_permit(Some("abc"), Some("1")).is_consistent());
        assert!(!verify_budget_permit(None, Some("1")).is_consistent());
    }

    #[test]
    fn flow_accumulator_consistent() {
        // parent spent 50, charged 100 => child spent 150.
        assert_eq!(
            verify_budget_flow_consistent(Some("50"), Some("100"), Some("150")),
            BudgetFlowOutcome::Ok
        );
    }

    #[test]
    fn flow_accumulator_mismatch_and_backwards_rejected() {
        // wrong sum: 50 + 100 != 140
        assert!(
            !verify_budget_flow_consistent(Some("50"), Some("100"), Some("140")).is_consistent()
        );
        // backwards: child < parent
        assert!(!verify_budget_flow_consistent(Some("50"), Some("0"), Some("40")).is_consistent());
        assert_eq!(
            verify_budget_flow_consistent(None, None, None),
            BudgetFlowOutcome::NotGrounded
        );
    }
}

#[cfg(test)]
mod ifc_flow_tests {
    use super::*;

    #[test]
    fn non_egress_hop_is_not_gated() {
        assert_eq!(verify_ifc_flow(None), IfcFlowOutcome::NotGated);
        assert!(verify_ifc_flow(None).is_consistent());
    }

    #[test]
    fn allowed_clean_egress_is_consistent() {
        // anti-vacuity: the verifier must ACCEPT legitimate allowed egress, not
        // reject everything.
        assert_eq!(verify_ifc_flow(Some("trusted")), IfcFlowOutcome::Allow);
        assert_eq!(verify_ifc_flow(Some("untrusted")), IfcFlowOutcome::Allow);
    }

    #[test]
    fn allowed_adversarial_egress_is_inconsistent() {
        // A signed edge claiming an allowed egress under adversarial integrity is
        // self-inconsistent — the gateway would have denied before signing.
        match verify_ifc_flow(Some("adversarial")) {
            IfcFlowOutcome::Inconsistent {
                effective_integrity,
            } => {
                assert_eq!(effective_integrity, "adversarial");
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
        assert!(!verify_ifc_flow(Some("adversarial")).is_consistent());
    }

    #[test]
    fn unrecognized_token_is_inconsistent_fail_closed() {
        assert!(!verify_ifc_flow(Some("garbage_token")).is_consistent());
        assert!(!verify_ifc_flow(Some("")).is_consistent());
    }

    #[test]
    fn matches_the_single_source_predicate() {
        // verify_ifc_flow's Allow/Inconsistent split is EXACTLY the gateway's
        // predicate — proving producer and verifier share one rule.
        for tok in ["trusted", "untrusted", "adversarial", "secret", "weird"] {
            let blocked = nucleus_ifc::egress_blocked_by_integrity(tok);
            let consistent = verify_ifc_flow(Some(tok)).is_consistent();
            assert_eq!(consistent, !blocked, "drift for token {tok:?}");
        }
    }

    // ── cross-check: gate output (child) vs runner-signed input (parent) ──

    #[test]
    fn cross_check_non_egress_child_is_not_gated() {
        assert_eq!(
            verify_ifc_flow_consistent(None, Some("trusted")),
            IfcFlowOutcome::NotGated
        );
    }

    #[test]
    fn cross_check_matching_signed_input_is_allow() {
        // anti-vacuity: an honest hop (gate allowed "trusted", parent signed
        // "trusted") must be accepted.
        assert_eq!(
            verify_ifc_flow_consistent(Some("trusted"), Some("trusted")),
            IfcFlowOutcome::Allow
        );
    }

    #[test]
    fn cross_check_rejects_input_output_mismatch() {
        // The gate co-committed "trusted" but the runner signed "adversarial"
        // upstream — the gate evaluated a downgraded value. Reject.
        match verify_ifc_flow_consistent(Some("trusted"), Some("adversarial")) {
            IfcFlowOutcome::Inconsistent {
                effective_integrity,
            } => {
                assert_eq!(effective_integrity, "trusted");
            }
            other => panic!("expected Inconsistent, got {other:?}"),
        }
        // Also reject when the parent didn't sign an effective integrity at all
        // (can't confirm the gate input).
        assert!(!verify_ifc_flow_consistent(Some("trusted"), None).is_consistent());
    }

    #[test]
    fn cross_check_inherits_allow_rule() {
        // A child gated on "adversarial" is rejected by the allow-rule before the
        // input/output comparison even matters.
        assert!(
            !verify_ifc_flow_consistent(Some("adversarial"), Some("adversarial")).is_consistent()
        );
    }
}
