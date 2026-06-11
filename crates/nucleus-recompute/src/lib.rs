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
