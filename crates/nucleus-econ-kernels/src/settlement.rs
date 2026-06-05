//! Verified settlement decision (Bet B) — a Rust port of
//! `lean/Nucleus/Auctions/SettlementDecision.lean`, parity-pinned to it.
//!
//! Given a delivery score in basis points, decide how a cleared price splits
//! between the seller and a refund to the bidder:
//!
//! - `reverse`  — `delivered_bps == 0`            → full refund, seller gets 0.
//! - `partial`  — `0 < delivered_bps < 10_000`    → split.
//! - `release`  — `delivered_bps >= 10_000`        → full payout to seller (v1).
//!
//! The load-bearing invariant (Lean `theorem conservation`): `seller_gross +
//! refund == price`, exactly — no value is created or destroyed in settlement.
//! Integer micro-USD; `refund` is defined as the residual so conservation holds
//! by construction and the parity test confirms it matches the proof.
//!
//! HONESTY: `delivered_bps` is an INPUT — the proof says nothing about whether
//! the seller *actually delivered* that fraction. Producing a trustworthy
//! `delivered_bps` is the Proof-of-Task-Execution (PoTE) seam, which is the one
//! unsolved part of Bet B (see `docs/rfcs/credible-clearing-settlement.md`).

use serde::{Deserialize, Serialize};

/// Basis-point scale (100% = 10_000 bps). Mirrors Lean `bpsScale`.
pub const BPS_SCALE: u64 = 10_000;

/// The settlement verdict (mirrors Lean `Verdict`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// `delivered_bps == 0`: full refund to the bidder, nothing to the seller.
    Reverse,
    /// `0 < delivered_bps < 10_000`: split between seller and refund.
    Partial,
    /// `delivered_bps >= 10_000`: full payout to the seller (the v1 happy path).
    Release,
}

/// Classify a delivery score into a [`Verdict`] (mirrors Lean `classify`).
pub fn classify(delivered_bps: u64) -> Verdict {
    if delivered_bps == 0 {
        Verdict::Reverse
    } else if delivered_bps < BPS_SCALE {
        Verdict::Partial
    } else {
        Verdict::Release
    }
}

/// The seller's payout for a cleared `price_micro` at `delivered_bps` (clamped to
/// 100%). Mirrors Lean `sellerGross`; `u128` math avoids overflow.
pub fn seller_gross(price_micro: u64, delivered_bps: u64) -> u64 {
    let bps = delivered_bps.min(BPS_SCALE) as u128;
    ((price_micro as u128 * bps) / BPS_SCALE as u128) as u64
}

/// The bidder's refund: the residual after the seller's payout. Defined as
/// `price - seller_gross` so `seller_gross + refund == price` holds exactly
/// (Lean `theorem conservation`).
pub fn refund(price_micro: u64, delivered_bps: u64) -> u64 {
    price_micro - seller_gross(price_micro, delivered_bps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_matches_lean_total() {
        assert_eq!(classify(0), Verdict::Reverse);
        assert_eq!(classify(1), Verdict::Partial);
        assert_eq!(classify(9_999), Verdict::Partial);
        assert_eq!(classify(10_000), Verdict::Release);
        assert_eq!(classify(50_000), Verdict::Release); // clamped to release
    }

    #[test]
    fn release_is_full_payout_reverse_is_full_refund() {
        // Lean: release_is_full_payout / reverse_is_full_refund.
        assert_eq!(seller_gross(1_000_000, 10_000), 1_000_000);
        assert_eq!(refund(1_000_000, 10_000), 0);
        assert_eq!(seller_gross(1_000_000, 0), 0);
        assert_eq!(refund(1_000_000, 0), 1_000_000);
    }

    #[test]
    fn conservation_holds_for_a_battery_of_inputs() {
        // Lean `theorem conservation`: seller_gross + refund == price, exactly,
        // for every price × delivery-score. Parity-checked here at runtime.
        for &price in &[0u64, 1, 999, 1_000_000, 7_654_321, u64::MAX / 2] {
            for &bps in &[0u64, 1, 2_500, 5_000, 9_999, 10_000, 25_000] {
                assert_eq!(
                    seller_gross(price, bps) + refund(price, bps),
                    price,
                    "conservation violated: price={price} bps={bps}"
                );
                assert!(seller_gross(price, bps) <= price, "sellerGross ≤ price");
            }
        }
    }

    #[test]
    fn seller_gross_monotone_refund_antitone() {
        // Lean sellerGross_mono / refund_antitone over the delivery score.
        let price = 1_000_000;
        let mut last_gross = 0u64;
        let mut last_refund = price;
        for bps in [0u64, 1_000, 5_000, 9_000, 10_000] {
            let g = seller_gross(price, bps);
            let r = refund(price, bps);
            assert!(g >= last_gross, "sellerGross must be monotone in bps");
            assert!(r <= last_refund, "refund must be antitone in bps");
            last_gross = g;
            last_refund = r;
        }
    }
}
