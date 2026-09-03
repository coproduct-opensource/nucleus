//! # Settlement attestation — binding the rail-side fact to the signed claim
//!
//! [`verify_payout`](crate::payout::verify_payout) proves a split is the proven
//! function of a real pool. It says nothing about whether anyone was *paid*.
//! This module closes that gap, and it exists in this shape because of a
//! specific defect found while building the payout layer.
//!
//! ## Why this is not just a field on the lineage edge
//!
//! `nucleus_lineage::EdgeKind::Settlement` already carries `tx_ref` and `rail`,
//! and it would be natural to treat those as the record of payment. They are
//! not trustworthy for that purpose: `canonical_edge_bytes` signs
//! `kind_tag(&kind)` — the **discriminant only** — so a `Settlement` edge's
//! `tx_ref` and `rail` are outside the signature, as is `attrs`. Two settlement
//! edges differing only in rail-side transaction id produce byte-identical
//! canonical bytes. (Pinned by `settlement_tx_ref_and_attrs_are_outside_the_signature`
//! in `nucleus-lineage`.)
//!
//! The edge's *authoritative* field is `content_hash_hex`, which **is** signed.
//! So the settlement facts have to live inside the object that hash commits to.
//! That object is this one.
//!
//! ## What a verified settlement means
//!
//! [`verify_settlement`] answers: *does this payment discharge the obligation
//! this payout created?* It checks three things, and nothing else:
//!
//! 1. the attestation names **this** payout, by content hash;
//! 2. its destination is one the payout actually allocates to;
//! 3. its amount is exactly that allocation — a payer cannot round a payee down.
//!
//! [`verify_settlement_set`] asks the harder question a payee actually cares
//! about: *was **everyone** paid, exactly once?* One attestation verifying in
//! isolation is compatible with an operator that paid two of three payees and
//! showed you only your own receipt.
//!
//! ## What this does NOT claim
//!
//! **The rail is not consulted.** Nothing here reaches out to a chain, a card
//! network, or a bank to confirm `tx_ref` exists or moved what it says. A
//! settlement attestation is the payer's signed *statement* about a rail-side
//! fact, bound so it cannot be altered afterwards and checked for internal
//! consistency against the proven split. Confirming it against the rail is a
//! separate step requiring a rail client, and it is deliberately not smuggled
//! in here — an offline verifier that silently did network I/O would be worse
//! than one that admits it cannot.
//!
//! What this *does* remove is the payer's freedom to misreport the split it was
//! settling. That is the part a recomputation can decide.
//!
//! **Partial refunds are not modelled.** A reversal must be full: the magnitude
//! equals the allocation. Partial reversal needs a running balance across
//! attestations, which is a ledger, not a check.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::payout::{PayoutClaim, payout_content_hash_hex};

/// Domain separator for the canonical settlement-attestation bytes (versioned).
const SETTLEMENT_DOMAIN: &[u8] = b"nucleus-recompute/settlement-attestation/v1\0";

/// A payer's signed statement that it moved money on a rail to discharge one
/// allocation of a payout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAttestation {
    /// The payout being discharged, by [`payout_content_hash_hex`]. Naming the
    /// payout by hash is what stops a settlement being re-pointed at a
    /// different, more favourable split after the fact.
    pub payout_hash_hex: String,
    /// The settlement protocol: `"x402-evm"`, `"stripe-connect"`, `"ach"`, ….
    pub rail: String,
    /// The rail-side transaction id — an onchain tx hash, a Stripe `ch_…`, an
    /// ACH trace number.
    pub tx_ref: String,
    /// Which payee this settles. Must be one the payout allocates to.
    pub destination: String,
    /// Amount moved, micro-USD, signed. Positive pays the destination; negative
    /// reverses a prior payment to it. Signed because a refund is not a distinct
    /// kind — it is a settlement in the opposite direction, matching
    /// `EdgeKind::Settlement`'s documented refund semantics.
    pub amount_micro_usd_signed: i64,
}

/// The result of checking one attestation against its payout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementOutcome {
    /// The attestation discharges its allocation exactly.
    Match,
    /// The attestation names a different payout than the one supplied.
    PayoutMismatch {
        /// The hash the attestation claims.
        claimed: String,
        /// The hash the supplied payout actually has.
        actual: String,
    },
    /// The destination is not one this payout allocates to — money moved, but
    /// not to anyone this split owes.
    UnknownDestination {
        /// The destination named by the attestation.
        destination: String,
    },
    /// The amount does not discharge the allocation. This is the case that
    /// matters most: it is how a payer rounding a payee down is caught.
    AmountMismatch {
        /// The destination whose payment is wrong.
        destination: String,
        /// What the attestation says was moved.
        claimed: i64,
        /// What the proven split says is owed (negated for a reversal).
        expected: i64,
    },
}

impl SettlementOutcome {
    /// `true` only for [`SettlementOutcome::Match`].
    pub fn is_match(&self) -> bool {
        matches!(self, SettlementOutcome::Match)
    }
}

/// Check that one attestation discharges its allocation in the given payout.
///
/// The payout is passed in rather than fetched: this is an offline check, and a
/// verifier that resolved hashes over the network would be making a trust
/// decision it did not disclose.
pub fn verify_settlement(
    attestation: &SettlementAttestation,
    payout: &PayoutClaim,
) -> SettlementOutcome {
    let actual = payout_content_hash_hex(payout);
    if attestation.payout_hash_hex != actual {
        return SettlementOutcome::PayoutMismatch {
            claimed: attestation.payout_hash_hex.clone(),
            actual,
        };
    }

    let Some(alloc) = payout
        .allocations
        .iter()
        .find(|a| a.destination == attestation.destination)
    else {
        return SettlementOutcome::UnknownDestination {
            destination: attestation.destination.clone(),
        };
    };

    // A reversal must be full: its magnitude is the allocation, its sign is
    // negative. Partial reversal is not modelled (see the module docs).
    let owed = i64::try_from(alloc.amount_micro).unwrap_or(i64::MAX);
    let expected = if attestation.amount_micro_usd_signed < 0 {
        -owed
    } else {
        owed
    };

    if attestation.amount_micro_usd_signed != expected {
        return SettlementOutcome::AmountMismatch {
            destination: attestation.destination.clone(),
            claimed: attestation.amount_micro_usd_signed,
            expected,
        };
    }
    SettlementOutcome::Match
}

/// Why a set of attestations does not fully discharge a payout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementSetOutcome {
    /// Every allocation is discharged exactly once, and nothing else was paid.
    Complete,
    /// One attestation failed on its own terms.
    Invalid(SettlementOutcome),
    /// Allocations with no settlement — someone was not paid.
    ///
    /// This is the failure a per-attestation check cannot see, and the one a
    /// payee should care about: an operator can pay two of three payees and show
    /// each of them a receipt that verifies.
    Unsettled {
        /// Destinations still owed.
        destinations: Vec<String>,
    },
    /// The same destination settled more than once. Not necessarily fraud — it
    /// is how a reversal appears — but it means the set no longer says "paid
    /// exactly once", so a naive sum over it would be wrong.
    Duplicate {
        /// The destination settled more than once.
        destination: String,
    },
}

/// Check that a set of attestations discharges **every** allocation of a payout,
/// exactly once.
///
/// Reversals are deliberately rejected here rather than netted: a set containing
/// a payment and its reversal is not "complete", it is a payment that was undone,
/// and collapsing the two would report the payee as paid. Netting belongs in a
/// ledger that carries balances over time, not in a check that answers one
/// question about one payout.
pub fn verify_settlement_set(
    attestations: &[SettlementAttestation],
    payout: &PayoutClaim,
) -> SettlementSetOutcome {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for a in attestations {
        match verify_settlement(a, payout) {
            SettlementOutcome::Match => {}
            other => return SettlementSetOutcome::Invalid(other),
        }
        if !seen.insert(a.destination.as_str()) {
            return SettlementSetOutcome::Duplicate {
                destination: a.destination.clone(),
            };
        }
    }

    let unsettled: Vec<String> = payout
        .allocations
        .iter()
        .filter(|a| !seen.contains(a.destination.as_str()))
        .map(|a| a.destination.clone())
        .collect();

    if unsettled.is_empty() {
        SettlementSetOutcome::Complete
    } else {
        SettlementSetOutcome::Unsettled {
            destinations: unsettled,
        }
    }
}

/// Issue an attestation for one allocation — the producer dual of
/// [`verify_settlement`].
///
/// The amount is **not** a parameter: it is read from the payout's proven
/// allocation. A payer therefore cannot mint an attestation for an amount it did
/// not owe, which is the same "honest by construction" discipline the `issue_*`
/// functions follow. Returns `None` if the destination is not one this payout
/// allocates to.
pub fn issue_settlement_attestation(
    payout: &PayoutClaim,
    destination: &str,
    rail: impl Into<String>,
    tx_ref: impl Into<String>,
) -> Option<SettlementAttestation> {
    let alloc = payout
        .allocations
        .iter()
        .find(|a| a.destination == destination)?;
    Some(SettlementAttestation {
        payout_hash_hex: payout_content_hash_hex(payout),
        rail: rail.into(),
        tx_ref: tx_ref.into(),
        destination: destination.to_string(),
        amount_micro_usd_signed: i64::try_from(alloc.amount_micro).unwrap_or(i64::MAX),
    })
}

/// Canonical, domain-tagged bytes for an attestation.
pub fn attestation_canonical_bytes(a: &SettlementAttestation) -> Vec<u8> {
    let mut out = Vec::with_capacity(SETTLEMENT_DOMAIN.len() + 256);
    out.extend_from_slice(SETTLEMENT_DOMAIN);
    // Infallible for this concrete, map-free type.
    serde_json::to_writer(&mut out, a).expect("attestation serialization is infallible");
    out
}

/// `sha256` over [`attestation_canonical_bytes`], hex-encoded.
///
/// **This is the value a `Settlement` lineage edge's `content_hash_hex` must
/// carry** — not the payout's hash, and not a hash of the amount. It is the only
/// part of that edge the signature covers, so it is the only place the `tx_ref`
/// and amount are tamper-evident.
pub fn attestation_content_hash_hex(a: &SettlementAttestation) -> String {
    let mut h = Sha256::new();
    h.update(attestation_canonical_bytes(a));
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payout::{issue_payout, tests_support::*};

    fn payout() -> PayoutClaim {
        issue_payout(
            crate::issue_settlement(1_000_000, 10_000),
            shares(),
            attribution(),
        )
        .expect("well-formed")
    }

    fn attest(p: &PayoutClaim, dest: &str) -> SettlementAttestation {
        issue_settlement_attestation(p, dest, "x402-evm", "0xabc").expect("known destination")
    }

    #[test]
    fn an_issued_attestation_discharges_its_allocation() {
        let p = payout();
        let a = attest(&p, "spiffe://vendor.example/seller");
        assert_eq!(verify_settlement(&a, &p), SettlementOutcome::Match);
    }

    /// THE BITE. A payer rounds a payee down by one micro-USD and reports the
    /// rest. Recomputation against the proven split catches it.
    #[test]
    fn shorting_a_payee_is_caught() {
        let p = payout();
        let mut a = attest(&p, "spiffe://vendor.example/seller");
        a.amount_micro_usd_signed -= 1;

        match verify_settlement(&a, &p) {
            SettlementOutcome::AmountMismatch {
                claimed, expected, ..
            } => assert_eq!(expected - claimed, 1),
            other => panic!("a short payment must not verify, got {other:?}"),
        }
    }

    /// The attestation names its payout by hash, so it cannot be re-pointed at a
    /// different, more favourable split after the fact. This is the property the
    /// whole module exists for: the lineage edge's own `tx_ref` is unsigned, so
    /// the binding has to live here.
    #[test]
    fn an_attestation_cannot_be_repointed_at_another_payout() {
        let p = payout();
        let a = attest(&p, "spiffe://vendor.example/seller");

        // A different payout — same parties, half the delivery, so smaller
        // obligations. An operator would love to claim it settled THIS one.
        let cheaper = issue_payout(
            crate::issue_settlement(1_000_000, 5_000),
            shares(),
            attribution(),
        )
        .expect("well-formed");

        match verify_settlement(&a, &cheaper) {
            SettlementOutcome::PayoutMismatch { .. } => {}
            other => panic!("must not verify against another payout, got {other:?}"),
        }
    }

    /// Paying someone the split does not owe is not a discharge of anything.
    #[test]
    fn paying_a_stranger_discharges_nothing() {
        let p = payout();
        let mut a = attest(&p, "spiffe://vendor.example/seller");
        a.destination = "spiffe://attacker.example/wallet".into();

        match verify_settlement(&a, &p) {
            SettlementOutcome::UnknownDestination { destination } => {
                assert!(destination.contains("attacker"));
            }
            other => panic!("expected UnknownDestination, got {other:?}"),
        }
    }

    /// A reversal is a settlement in the opposite direction, and must be full.
    #[test]
    fn a_full_reversal_verifies_and_a_partial_one_does_not() {
        let p = payout();
        let mut full = attest(&p, "commons");
        full.amount_micro_usd_signed = -full.amount_micro_usd_signed;
        assert_eq!(verify_settlement(&full, &p), SettlementOutcome::Match);

        let mut partial = full.clone();
        partial.amount_micro_usd_signed += 1; // less than a full reversal
        assert!(
            !verify_settlement(&partial, &p).is_match(),
            "partial reversal is not modelled and must not silently pass"
        );
    }

    /// **The question a payee actually cares about.** Each attestation below
    /// verifies on its own — an operator could show any single payee a receipt
    /// that checks out — but the set does not discharge the payout.
    #[test]
    fn paying_two_of_three_payees_is_caught_only_by_the_set_check() {
        let p = payout();
        let paid = [
            attest(&p, "spiffe://nucleus.local/runtime/acme"),
            attest(&p, "spiffe://vendor.example/seller"),
        ];

        // Individually honest.
        for a in &paid {
            assert_eq!(verify_settlement(a, &p), SettlementOutcome::Match);
        }

        // Collectively incomplete.
        match verify_settlement_set(&paid, &p) {
            SettlementSetOutcome::Unsettled { destinations } => {
                assert_eq!(destinations, vec!["commons".to_string()]);
            }
            other => panic!("an unpaid payee must surface, got {other:?}"),
        }
    }

    #[test]
    fn settling_every_allocation_once_is_complete() {
        let p = payout();
        let all: Vec<_> = p
            .allocations
            .iter()
            .map(|a| attest(&p, &a.destination))
            .collect();
        assert_eq!(
            verify_settlement_set(&all, &p),
            SettlementSetOutcome::Complete
        );
    }

    /// A payment and its reversal is not "everyone was paid". Netting them would
    /// report a payee as settled when the money came back.
    #[test]
    fn a_payment_and_its_reversal_do_not_net_to_complete() {
        let p = payout();
        let pay = attest(&p, "commons");
        let mut back = pay.clone();
        back.amount_micro_usd_signed = -back.amount_micro_usd_signed;
        back.tx_ref = "0xreversal".into();

        match verify_settlement_set(&[pay, back], &p) {
            SettlementSetOutcome::Duplicate { destination } => assert_eq!(destination, "commons"),
            other => panic!("a reversal must not read as payment, got {other:?}"),
        }
    }

    /// The producer cannot mint an attestation for money it did not owe: the
    /// amount comes from the proven allocation, never from the caller.
    #[test]
    fn an_attestation_cannot_be_issued_for_an_unowed_destination() {
        let p = payout();
        assert!(issue_settlement_attestation(&p, "nobody", "x402-evm", "0x1").is_none());
    }

    /// The attestation hash covers the rail-side facts — which is the entire
    /// reason this type exists, given the lineage edge's `tx_ref` is unsigned.
    #[test]
    fn the_hash_covers_tx_ref_and_amount() {
        let p = payout();
        let a = attest(&p, "commons");

        let mut other_tx = a.clone();
        other_tx.tx_ref = "0xdifferent".into();
        assert_ne!(
            attestation_content_hash_hex(&a),
            attestation_content_hash_hex(&other_tx),
            "tx_ref must be inside the commitment"
        );

        let mut other_amt = a.clone();
        other_amt.amount_micro_usd_signed += 1;
        assert_ne!(
            attestation_content_hash_hex(&a),
            attestation_content_hash_hex(&other_amt),
            "amount must be inside the commitment"
        );
    }
}
