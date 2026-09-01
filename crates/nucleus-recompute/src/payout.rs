//! # Payout — the receipt IS the payout claim
//!
//! [`verify_receipt`](crate::verify_receipt) answers *"did this clearing compute
//! the right number?"*. This module answers the question one step downstream:
//! *"and was that number split among the parties the way it was claimed?"*
//!
//! ## Why this is the whole design
//!
//! Agent-commerce standards (AdCP, AP2, ACP, x402) settle a price. None of them
//! defines attribution: AdCP's own documentation puts attribution out of scope
//! and defers it to third-party measurement. The research that *does* build
//! verifiable agent receipts names its own missing piece — "adoption incentives:
//! why services would implement receiver attestation" (arXiv 2606.04193).
//!
//! The answer here is structural: **the receipt is the payout claim.** A runtime
//! emits verifiable evidence because that evidence is what its share is computed
//! from. There is no separate reporting channel to be honest on, and no operator
//! whose ledger has to be trusted — any party recomputes the split itself.
//!
//! ## No new economics
//!
//! A revenue split *is* a commons routing. `route_to_commons` is already the
//! proven kernel (`Commons.lean`'s `routed_conserves`): a pool, a set of
//! basis-point shares that must sum to exactly 10 000, and a conservation
//! theorem that the allocations neither skim nor over-allocate. Re-using it
//! means the payout math inherits a Lean proof instead of acquiring a new
//! trusted numeric path.
//!
//! So [`verify_payout`] is a two-stage recomputation:
//!
//! 1. the clearing this payout distributes must itself re-derive
//!    ([`verify_receipt`](crate::verify_receipt)) — a payout over a fabricated
//!    price is caught here, before the split is even looked at;
//! 2. the pool is *derived* from that clearing, never declared separately, and
//!    `route_to_commons` must reproduce the claimed allocations exactly.
//!
//! Stage 1 is the load-bearing one. Letting the payout declare its own pool
//! would leave the split honest and the number arbitrary.
//!
//! ## What this does NOT claim
//!
//! Recompute checks that the split is the proven function of the **declared**
//! inputs. It says nothing about whether those inputs are truthful — the same
//! honest boundary [`verify_receipt`](crate::verify_receipt) documents.
//!
//! Specifically, [`Attribution`] is *carried, not verified* here. That a
//! particular workload surfaced a particular offer is a claim about the world;
//! this module binds it into the signed content hash so it cannot be altered
//! after the fact, and leaves proving it to the layers that can — SPIFFE
//! attestation for the workload, and the disclosure record for the offer. A
//! verifier that wants more than "these numbers re-derive" must check the
//! attribution's `assurance` against an independently derived
//! `VerifiedAttestation`, exactly as `MediationReceipt` requires.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use nucleus_econ_kernels::{
    commons::{route_to_commons, CommonsAllocation, CommonsError, CommonsShare},
    settlement::seller_gross,
};

use crate::{mismatch, verify_receipt, ClearingReceipt, RecomputeOutcome};

/// Domain separator for the canonical payout bytes (versioned).
const PAYOUT_DOMAIN: &[u8] = b"nucleus-recompute/payout-receipt/v1\0";

/// Who earned a payout, and on what evidence.
///
/// Every field is a claim *bound* by the payout's content hash, not a claim
/// *proven* by this crate. Binding is still the point: an operator cannot
/// re-attribute a settled payout after the fact without producing a different
/// hash, which breaks the lineage edge that committed to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribution {
    /// SPIFFE id of the workload that earned this payout.
    pub workload_spiffe_id: String,
    /// The workload's attestation assurance level, as
    /// `nucleus_identity::AssuranceLevel` discriminant (0 = bearer, 1 =
    /// software, 2 = device, 3 = measured boot).
    ///
    /// Self-claimed, exactly as `MediationReceipt.signer_assurance` is. A
    /// relying party that cares must compare it against a `VerifiedAttestation`
    /// derived independently; a receipt claiming L3 proves nothing on its own.
    pub assurance: u8,
    /// Content hash of the offer that was surfaced, hex SHA-256.
    pub offer_hash_hex: String,
    /// Content hash of the disclosure record for that offer, hex SHA-256.
    ///
    /// Empty for a payout with no sponsored component. When non-empty it binds
    /// the payout to the disclosure that accompanied it, so "was this sponsored
    /// placement disclosed?" is answerable from the receipt alone rather than
    /// from the operator's word.
    pub disclosure_hash_hex: String,
}

/// A payout claim: the clearing being distributed, the declared shares, and the
/// claimed per-payee allocations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayoutClaim {
    /// Declared input: the clearing whose proceeds are being split. The pool is
    /// derived from this, never declared on its own.
    pub clearing: ClearingReceipt,
    /// Declared input: the payees and their basis-point shares (must sum to
    /// 10 000 — `route_to_commons` rejects anything else, so a skimmed split
    /// cannot produce a standing receipt).
    pub shares: Vec<CommonsShare>,
    /// Declared input: who earned it, and on what evidence.
    pub attribution: Attribution,
    /// Claimed output: the per-payee amounts.
    pub allocations: Vec<CommonsAllocation>,
}

/// The pool a clearing makes available to split.
///
/// A settlement's distributable proceeds are the seller's gross — the buyer's
/// refund is not the marketplace's to allocate. `Commons` and `Vcg` clearings
/// are not distributable pools in this sense and are rejected rather than
/// guessed at: a `Commons` receipt is *already* a routing (splitting it again
/// would double-route), and a `Vcg` clearing settles per-winner payments rather
/// than producing one pool.
fn pool_of(clearing: &ClearingReceipt) -> Result<u64, String> {
    match clearing {
        ClearingReceipt::Settlement(c) => Ok(seller_gross(c.price_micro, c.delivered_bps)),
        ClearingReceipt::Commons(_) => {
            Err("a commons receipt is already a routing; splitting it again would double-route"
                .to_string())
        }
        ClearingReceipt::Vcg(_) => {
            Err("a VCG clearing settles per-winner payments, not one distributable pool"
                .to_string())
        }
    }
}

/// Re-derive a payout's claimed split from its declared inputs and compare.
///
/// Two stages, in this order:
///
/// 1. the underlying clearing must recompute — a payout over a fabricated price
///    fails here, before the split is examined;
/// 2. the pool is derived from that clearing and `route_to_commons` must
///    reproduce the claimed allocations exactly.
///
/// [`RecomputeOutcome::Match`] iff both hold.
pub fn verify_payout(payout: &PayoutClaim) -> RecomputeOutcome {
    // Stage 1. The pool has to be real before the split can be honest.
    match verify_receipt(&payout.clearing) {
        RecomputeOutcome::Match => {}
        other => return other,
    }

    let pool = match pool_of(&payout.clearing) {
        Ok(p) => p,
        Err(e) => return RecomputeOutcome::Invalid(e),
    };

    // Stage 2. The split is `route_to_commons`, whose conservation is proven.
    match route_to_commons(pool, &payout.shares) {
        Ok(allocs) => {
            if allocs == payout.allocations {
                RecomputeOutcome::Match
            } else {
                mismatch("allocations", &payout.allocations, &allocs)
            }
        }
        Err(e) => RecomputeOutcome::Invalid(e.to_string()),
    }
}

/// Issue a payout by running the proven kernels on the declared inputs — the
/// producer dual of [`verify_payout`].
///
/// Honest by construction: the allocations are not supplied by the caller, they
/// are computed. Errors if the clearing is not a distributable pool or if the
/// shares are ill-formed, so a malformed split cannot produce a standing receipt.
pub fn issue_payout(
    clearing: ClearingReceipt,
    shares: Vec<CommonsShare>,
    attribution: Attribution,
) -> Result<PayoutClaim, PayoutError> {
    let pool = pool_of(&clearing).map_err(PayoutError::NotDistributable)?;
    let allocations = route_to_commons(pool, &shares)?;
    Ok(PayoutClaim {
        clearing,
        shares,
        attribution,
        allocations,
    })
}

/// Why a payout could not be issued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayoutError {
    /// The clearing does not yield a single distributable pool.
    #[error("clearing is not a distributable pool: {0}")]
    NotDistributable(String),
    /// The declared shares were rejected by the proven routing kernel.
    #[error(transparent)]
    Shares(#[from] CommonsError),
}

/// Canonical, domain-tagged bytes for a payout. Deterministic: the payout types
/// contain no maps, so serde's field/element order is stable.
pub fn payout_canonical_bytes(payout: &PayoutClaim) -> Vec<u8> {
    let mut out = Vec::with_capacity(PAYOUT_DOMAIN.len() + 512);
    out.extend_from_slice(PAYOUT_DOMAIN);
    // Infallible for these concrete, map-free types.
    serde_json::to_writer(&mut out, payout).expect("payout serialization is infallible");
    out
}

/// `sha256` over [`payout_canonical_bytes`], hex-encoded — the value a
/// `nucleus-lineage` `Settlement` or `Allocation` edge's `content_hash_hex`
/// carries for a payout.
///
/// The domain separator differs from the clearing's, so a clearing receipt and a
/// payout over it can never collide in a content-addressed store even when the
/// payout embeds that exact clearing.
pub fn payout_content_hash_hex(payout: &PayoutClaim) -> String {
    let mut h = Sha256::new();
    h.update(payout_canonical_bytes(payout));
    hex::encode(h.finalize())
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    pub(crate) fn attribution() -> Attribution {
        Attribution {
            workload_spiffe_id: "spiffe://nucleus.local/runtime/acme".into(),
            assurance: 1,
            offer_hash_hex: "a".repeat(64),
            disclosure_hash_hex: "b".repeat(64),
        }
    }

    pub(crate) fn shares() -> Vec<CommonsShare> {
        vec![
            CommonsShare {
                destination: "spiffe://nucleus.local/runtime/acme".into(),
                bps: 3_000,
            },
            CommonsShare {
                destination: "spiffe://vendor.example/seller".into(),
                bps: 6_500,
            },
            CommonsShare {
                destination: "commons".into(),
                bps: 500,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::*;
    use super::*;
    use crate::issue_settlement;

    /// The happy path, and the shape the whole design rests on: a third party
    /// with nothing but the receipt re-derives every payee's amount.
    #[test]
    fn an_issued_payout_reverifies() {
        let clearing = issue_settlement(1_000_000, 10_000);
        let payout = issue_payout(clearing, shares(), attribution()).expect("well-formed");

        assert_eq!(verify_payout(&payout), RecomputeOutcome::Match);
        // Conservation: full delivery means the whole price is distributed.
        let total: u64 = payout.allocations.iter().map(|a| a.amount_micro).sum();
        assert_eq!(total, 1_000_000, "routed_conserves — nothing skimmed");
    }

    /// THE BITE. Tamper with one payee's amount; recomputation must diverge.
    /// A payout ledger nobody has watched fail is a promise, not a proof.
    #[test]
    fn tampering_with_one_allocation_is_caught() {
        let clearing = issue_settlement(1_000_000, 10_000);
        let mut payout = issue_payout(clearing, shares(), attribution()).expect("well-formed");

        payout.allocations[0].amount_micro += 1;

        match verify_payout(&payout) {
            RecomputeOutcome::Mismatch { field, .. } => assert_eq!(field, "allocations"),
            other => panic!("a skimmed payout must not verify, got {other:?}"),
        }
    }

    /// Stage 1 is load-bearing. If the payout could declare its own pool, the
    /// split would be honest and the number arbitrary — so a payout whose
    /// underlying clearing lies must fail BEFORE the split is examined.
    #[test]
    fn a_payout_over_a_fabricated_clearing_fails_on_the_clearing() {
        let ClearingReceipt::Settlement(mut claim) = issue_settlement(1_000_000, 10_000) else {
            panic!("issue_settlement returns a settlement");
        };
        // Claim the seller earned more than the proven kernel allows.
        claim.seller_gross += 500_000;
        let lying = ClearingReceipt::Settlement(claim);

        // Build the payout by hand — `issue_payout` would recompute honestly.
        let payout = PayoutClaim {
            clearing: lying,
            shares: shares(),
            attribution: attribution(),
            allocations: vec![],
        };

        match verify_payout(&payout) {
            RecomputeOutcome::Mismatch { field, .. } => {
                assert_eq!(field, "seller_gross", "must fail on the CLEARING, not the split");
            }
            other => panic!("a fabricated pool must not verify, got {other:?}"),
        }
    }

    /// A partial delivery splits the seller's gross, not the full price: the
    /// buyer's refund is not the marketplace's to allocate.
    #[test]
    fn the_pool_is_the_sellers_gross_not_the_price() {
        let clearing = issue_settlement(1_000_000, 5_000); // 50% delivered
        let payout = issue_payout(clearing, shares(), attribution()).expect("well-formed");

        let total: u64 = payout.allocations.iter().map(|a| a.amount_micro).sum();
        assert_eq!(total, 500_000, "only the seller's gross is distributable");
        assert_eq!(verify_payout(&payout), RecomputeOutcome::Match);
    }

    /// Shares that do not sum to 10 000 bps would skim or over-allocate. The
    /// proven kernel rejects them, so no standing receipt can be issued.
    #[test]
    fn a_skimming_share_set_cannot_be_issued() {
        let clearing = issue_settlement(1_000_000, 10_000);
        let skimming = vec![CommonsShare {
            destination: "operator".into(),
            bps: 9_000, // 1000 bps unaccounted for
        }];

        match issue_payout(clearing, skimming, attribution()) {
            Err(PayoutError::Shares(CommonsError::SharesMustSumTo10000 { got })) => {
                assert_eq!(got, 9_000);
            }
            other => panic!("a skimming split must not issue, got {other:?}"),
        }
    }

    /// Re-splitting a commons routing would double-route. Rejected, not guessed.
    #[test]
    fn a_commons_receipt_is_not_a_distributable_pool() {
        let commons = crate::issue_commons(
            1_000_000,
            vec![CommonsShare {
                destination: "d".into(),
                bps: 10_000,
            }],
        )
        .expect("well-formed");

        assert!(matches!(
            issue_payout(commons, shares(), attribution()),
            Err(PayoutError::NotDistributable(_))
        ));
    }

    /// The attribution is bound by the hash even though it is not verified here.
    /// Re-attributing a settled payout must produce a different hash, which
    /// breaks any lineage edge that committed to the original.
    #[test]
    fn re_attributing_a_payout_changes_its_content_hash() {
        let clearing = issue_settlement(1_000_000, 10_000);
        let payout = issue_payout(clearing.clone(), shares(), attribution()).expect("ok");

        let mut stolen = attribution();
        stolen.workload_spiffe_id = "spiffe://nucleus.local/runtime/thief".into();
        let reattributed = issue_payout(clearing, shares(), stolen).expect("ok");

        assert_ne!(
            payout_content_hash_hex(&payout),
            payout_content_hash_hex(&reattributed),
            "attribution must be inside the commitment"
        );
        // ...and both still recompute: binding is not verification, and the
        // docs must not claim otherwise.
        assert_eq!(verify_payout(&reattributed), RecomputeOutcome::Match);
    }

    /// A payout and the clearing it distributes must never collide in a
    /// content-addressed store, even though the payout embeds that clearing.
    #[test]
    fn payout_and_clearing_hashes_are_domain_separated() {
        let clearing = issue_settlement(1_000_000, 10_000);
        let payout = issue_payout(clearing.clone(), shares(), attribution()).expect("ok");

        assert_ne!(
            crate::content_hash_hex(&clearing),
            payout_content_hash_hex(&payout)
        );
    }
}

/// Travel a payout as a signed receipt (feature `envelope`).
///
/// A [`PayoutClaim`] on its own is *unsigned*: verification is pure
/// recomputation, so it says "this split re-derives" but not "who claimed it".
/// This module wires it into `nucleus-receipt`'s Ed25519 envelope so one object
/// carries both guarantees — signature (who) and recompute (the numbers).
///
/// ## Wire shape (stable)
///
/// A payout rides in `Projection::Economic` under a *different inner
/// discriminant* from a clearing:
///
/// ```json
/// { "kind": "payout", "payout": { "clearing": {...}, "shares": [...], ... } }
/// ```
///
/// This deliberately uses the extension point the economic projection already
/// documents — the inner `kind` exists precisely "so other economic bodies can
/// coexist under the same projection kind". Adding a new `Projection` variant
/// would have been a wider change to a sealed sum for no additional guarantee.
#[cfg(feature = "envelope")]
pub mod envelope {
    use super::{verify_payout, PayoutClaim};
    use nucleus_receipt::Projection;

    /// The inner discriminant for a payout body inside `Projection::Economic`.
    pub const ECONOMIC_PAYOUT_KIND: &str = "payout";

    /// Why a projection could not be narrowed to a [`PayoutClaim`].
    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    pub enum PayoutNarrowError {
        /// The projection is not `Projection::Economic` at all.
        #[error("projection kind is `{found}`, expected `economic`")]
        NotEconomic {
            /// The wire discriminant of the projection supplied.
            found: &'static str,
        },
        /// The economic body's inner `kind` is not `"payout"`.
        #[error("economic body kind is `{found}`, expected `payout`")]
        NotPayout {
            /// The inner `kind` found, or `<missing>`.
            found: String,
        },
        /// The body claimed to be a payout but does not deserialize as one.
        #[error("economic payout body is malformed: {0}")]
        MalformedBody(String),
    }

    /// Lift a [`PayoutClaim`] into a `Projection::Economic` body.
    pub fn to_payout_projection(payout: &PayoutClaim) -> Projection {
        Projection::Economic(serde_json::json!({
            "kind": ECONOMIC_PAYOUT_KIND,
            "payout": payout,
        }))
    }

    /// Narrow a [`Projection`] back to a typed [`PayoutClaim`].
    ///
    /// Narrowing verifies nothing: verify the envelope signature first, and
    /// [`verify_payout`] the narrowed value after.
    pub fn payout_from_projection(
        projection: &Projection,
    ) -> Result<PayoutClaim, PayoutNarrowError> {
        let Projection::Economic(body) = projection else {
            return Err(PayoutNarrowError::NotEconomic {
                found: projection.kind(),
            });
        };
        match body.get("kind").and_then(serde_json::Value::as_str) {
            Some(ECONOMIC_PAYOUT_KIND) => {}
            Some(other) => {
                return Err(PayoutNarrowError::NotPayout {
                    found: other.to_string(),
                })
            }
            None => {
                return Err(PayoutNarrowError::NotPayout {
                    found: "<missing>".to_string(),
                })
            }
        }
        let payout = body
            .get("payout")
            .ok_or_else(|| PayoutNarrowError::MalformedBody("missing `payout` field".to_string()))?;
        serde_json::from_value(payout.clone())
            .map_err(|e| PayoutNarrowError::MalformedBody(e.to_string()))
    }

    /// The verdict from checking a signed payout.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum SignedPayoutVerdict {
        /// The Ed25519 signature did not verify — checked FIRST, before any
        /// recompute. A forged envelope never reaches the kernels.
        BadSignature,
        /// Signature verified, but the projection is not a narrowable payout.
        Malformed(PayoutNarrowError),
        /// Signature verified + narrowed; the recompute outcome. Fully verified
        /// iff this is [`RecomputeOutcome::Match`](crate::RecomputeOutcome::Match).
        Recomputed(crate::RecomputeOutcome),
    }

    /// Verify a signed payout end to end: signature, then recompute.
    ///
    /// This is the function that makes the revenue share trustless. A runtime
    /// operator can sign whatever it likes; a signature-valid payout claiming a
    /// share the proven kernels do not produce still comes back
    /// `Recomputed(Mismatch)`. That is precisely what a signature-only verifier
    /// cannot catch, and it is why the payee never has to trust the payer.
    pub fn verify_signed_payout(
        signed: &nucleus_receipt::Receipt,
        verifying_key_bytes: &[u8; 32],
    ) -> SignedPayoutVerdict {
        if signed.verify(verifying_key_bytes).is_err() {
            return SignedPayoutVerdict::BadSignature;
        }
        match signed.projections.first() {
            Some(p) => match payout_from_projection(p) {
                Ok(payout) => SignedPayoutVerdict::Recomputed(verify_payout(&payout)),
                Err(e) => SignedPayoutVerdict::Malformed(e),
            },
            None => SignedPayoutVerdict::Malformed(PayoutNarrowError::NotEconomic {
                found: "none",
            }),
        }
    }
}

#[cfg(all(test, feature = "envelope"))]
mod envelope_tests {
    use super::envelope::*;
    use super::tests_support::*;
    use super::*;
    use crate::RecomputeOutcome;
    use ed25519_dalek::SigningKey;
    use nucleus_receipt::{Receipt, Session};

    fn session() -> Session {
        Session {
            session_id: "spiffe://nucleus.local/runtime/acme".into(),
            issuer_kid: "acme-kid".into(),
            issued_at_micros: 1_717_000_000_000_000,
            parent_chain: vec![],
        }
    }

    /// The full round trip a third party actually runs: sign, ship, verify the
    /// signature, narrow, recompute.
    #[test]
    fn a_signed_payout_round_trips_and_recomputes() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let payout = issue_payout(
            crate::issue_settlement(1_000_000, 10_000),
            shares(),
            attribution(),
        )
        .expect("well-formed");

        let signed = Receipt::sign(session(), vec![to_payout_projection(&payout)], &sk);
        let vk = sk.verifying_key().to_bytes();

        assert_eq!(
            verify_signed_payout(&signed, &vk),
            SignedPayoutVerdict::Recomputed(RecomputeOutcome::Match)
        );
        assert_eq!(payout_from_projection(&signed.projections[0]).unwrap(), payout);
    }

    /// **The load-bearing test for the whole revenue-share design.** The operator
    /// signs honestly — the signature verifies — but claims a share the proven
    /// kernels do not produce. A signature-only verifier accepts this. Recompute
    /// must not.
    #[test]
    fn a_validly_signed_but_skimmed_payout_is_rejected() {
        let sk = SigningKey::from_bytes(&[12u8; 32]);
        let mut payout = issue_payout(
            crate::issue_settlement(1_000_000, 10_000),
            shares(),
            attribution(),
        )
        .expect("well-formed");

        // The operator quietly moves 1 micro-USD from the commons to itself.
        payout.allocations[0].amount_micro += 1;
        payout.allocations[2].amount_micro -= 1;

        let signed = Receipt::sign(session(), vec![to_payout_projection(&payout)], &sk);
        let vk = sk.verifying_key().to_bytes();

        // The signature is genuinely good — this is not a forgery test.
        assert!(signed.verify(&vk).is_ok(), "the envelope really is signed");

        match verify_signed_payout(&signed, &vk) {
            SignedPayoutVerdict::Recomputed(RecomputeOutcome::Mismatch { field, .. }) => {
                assert_eq!(field, "allocations");
            }
            other => panic!("a skimmed payout must not verify, got {other:?}"),
        }
    }

    /// Signature is checked before recompute, so a tampered envelope never
    /// reaches the kernels.
    #[test]
    fn a_wrong_key_fails_before_recompute() {
        let sk = SigningKey::from_bytes(&[13u8; 32]);
        let other = SigningKey::from_bytes(&[14u8; 32]);
        let payout = issue_payout(
            crate::issue_settlement(1_000_000, 10_000),
            shares(),
            attribution(),
        )
        .expect("well-formed");
        let signed = Receipt::sign(session(), vec![to_payout_projection(&payout)], &sk);

        assert_eq!(
            verify_signed_payout(&signed, &other.verifying_key().to_bytes()),
            SignedPayoutVerdict::BadSignature
        );
    }

    /// A clearing and a payout share the `Economic` projection but not the inner
    /// discriminant, so neither can be narrowed as the other.
    #[test]
    fn a_clearing_projection_is_not_narrowable_as_a_payout() {
        let clearing = crate::issue_settlement(1_000_000, 10_000);
        let projection = crate::envelope::to_economic_projection(&clearing);

        match payout_from_projection(&projection) {
            Err(PayoutNarrowError::NotPayout { found }) => assert_eq!(found, "clearing"),
            other => panic!("expected NotPayout, got {other:?}"),
        }
    }
}
