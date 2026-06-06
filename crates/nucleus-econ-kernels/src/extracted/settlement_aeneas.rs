//! Aeneas-grade mirror of `lean/Nucleus/Auctions/SettlementDecision.lean`.
//!
//! Each function below is byte-faithful to its Lean counterpart; reviewers
//! comparing changes should diff against the Lean source line-by-line. The parity
//! proptests in `tests/settlement_commons_parity.rs` exercise the equivalence
//! between these mirrors and the production kernel (`crate::settlement`) over
//! randomized inputs — added coverage the fixed golden vectors don't have.
//!
//! Status (same tier as `vcg_aeneas` / `pigou_aeneas`): **hand-transcribed**
//! Aeneas-subset Rust, not yet Charon-extracted. The real Charon → LLBC → Aeneas
//! → Lean pipeline (live for `portcullis-core`, see `.github/workflows/aeneas.yml`)
//! extends to these roots once it runs against `nucleus-econ-kernels`; until then
//! the mirror is faithful-by-review + proptest-bound. See docs/PROOFS.md §5.

#![deny(clippy::float_arithmetic)]

/// Mirror of Lean `bpsScale`.
pub const BPS_SCALE: u64 = 10_000;

/// Mirror of Lean `Verdict` as a stable integer tag: `0 = reverse`, `1 = partial`,
/// `2 = release` (the same encoding the golden vectors use). Integer-only keeps
/// the mirror inside the Aeneas-translatable subset.
pub const VERDICT_REVERSE: u8 = 0;
pub const VERDICT_PARTIAL: u8 = 1;
pub const VERDICT_RELEASE: u8 = 2;

/// Rust mirror of `Nucleus.Auctions.SettlementDecision.classify`.
///
/// Lean definition (verbatim):
///
/// ```text
/// def classify (deliveredBps : Nat) : Verdict :=
///   if deliveredBps = 0 then Verdict.Reverse
///   else if deliveredBps ≥ bpsScale then Verdict.Release
///   else Verdict.Partial
/// ```
pub fn classify(delivered_bps: u64) -> u8 {
    if delivered_bps == 0 {
        VERDICT_REVERSE
    } else if delivered_bps >= BPS_SCALE {
        VERDICT_RELEASE
    } else {
        VERDICT_PARTIAL
    }
}

/// Rust mirror of `Nucleus.Auctions.SettlementDecision.sellerGross`.
///
/// Lean definition (verbatim):
///
/// ```text
/// def sellerGross (price deliveredBps : Nat) : Nat :=
///   price * (min deliveredBps bpsScale) / bpsScale
/// ```
///
/// `u128` intermediate bridges Lean's unbounded `Nat` to `u64` without overflow;
/// floor division matches `Nat` division exactly.
pub fn seller_gross(price: u64, delivered_bps: u64) -> u64 {
    let clamped = if delivered_bps < BPS_SCALE {
        delivered_bps
    } else {
        BPS_SCALE
    };
    ((price as u128 * clamped as u128) / BPS_SCALE as u128) as u64
}

/// Rust mirror of `Nucleus.Auctions.SettlementDecision.refund`.
///
/// Lean definition (verbatim):
///
/// ```text
/// def refund (price deliveredBps : Nat) : Nat :=
///   price - sellerGross price deliveredBps
/// ```
///
/// `saturating_sub` mirrors Lean truncated `Nat` subtraction; the Lean theorem
/// `sellerGross_le_price` guarantees the subtrahend never exceeds `price`, so
/// `seller_gross + refund == price` holds by construction (conservation).
pub fn refund(price: u64, delivered_bps: u64) -> u64 {
    price.saturating_sub(seller_gross(price, delivered_bps))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_buckets() {
        assert_eq!(classify(0), VERDICT_REVERSE);
        assert_eq!(classify(1), VERDICT_PARTIAL);
        assert_eq!(classify(9_999), VERDICT_PARTIAL);
        assert_eq!(classify(10_000), VERDICT_RELEASE);
        assert_eq!(classify(25_000), VERDICT_RELEASE);
    }

    #[test]
    fn seller_gross_and_refund_extremes() {
        assert_eq!(seller_gross(1_000_000, 0), 0);
        assert_eq!(refund(1_000_000, 0), 1_000_000);
        assert_eq!(seller_gross(1_000_000, 10_000), 1_000_000);
        assert_eq!(refund(1_000_000, 10_000), 0);
        // Clamp above full delivery.
        assert_eq!(seller_gross(1_000_000, 25_000), 1_000_000);
    }

    #[test]
    fn conservation_holds() {
        for &price in &[0u64, 1, 999, 1_000_000, 7_654_321] {
            for &bps in &[0u64, 1, 2_500, 9_999, 10_000, 25_000] {
                assert_eq!(seller_gross(price, bps) + refund(price, bps), price);
            }
        }
    }
}
