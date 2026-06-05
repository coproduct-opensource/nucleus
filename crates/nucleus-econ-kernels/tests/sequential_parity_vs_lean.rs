//! **C4 acceptance — sequential Pigouvian welfare bound.**
//!
//! Closes the "verified spec, unverified impl" gap the 2026-05-29
//! audit surfaced: the Lean theorem `sequential_welfare_bounded_above`
//! (in `Nucleus.Auctions.PigouvianVcgSequential`) proves
//!
//!   `sequentialPigouWelfare auctions scale ≤ sumRawBids auctions`
//!
//! for any sequence of auctions, but until this proptest existed the
//! claim wasn't pinned to the production kernel function the hub's
//! `/match` route now calls (via `nucleus_auction_hub::AuctionHub::
//! match_auction_vcg` → `run_vcg_with_externalities` →
//! `effective_minus_pigou_micro` per bid).
//!
//! This file pins the bound at the production-function level:
//! 256 random sequences of `(bid, rate, ext)` tuples, length 1..16,
//! with the kernel-side per-bid Pigouvian re-weight summed and the
//! raw bids summed; assert the kernel sum ≤ raw sum.
//!
//! Together with the U4 per-bid parity in `pigou_parity.rs` (kernel
//! ≡ Lean-extracted byte-for-byte), this gives the Lean F6.1 bound
//! as an end-to-end property of the production /match route — the
//! "F theorem ↔ production" claim is now testable, not asserted.

use nucleus_econ_kernels::{effective_minus_pigou_micro, PigouvianRates};
use nucleus_externality::{sign_claim, ExternalityProfile, ResourceDim, SignedExternalityClaim};
use proptest::prelude::*;

fn one_dim_profile(ext_units: u64) -> ExternalityProfile {
    use ed25519_dalek::SigningKey;
    let sk = SigningKey::from_bytes(&[77u8; 32]);
    let mut p = ExternalityProfile::new();
    p.insert(
        ResourceDim::GpuSeconds,
        sign_claim(
            &sk,
            SignedExternalityClaim {
                resource: ResourceDim::GpuSeconds,
                units_micro: ext_units,
                ts_unix_micros: 1_700_000_000_000_000,
                not_after_unix_micros: 1_700_000_000_000_000 + 3_600_000_000,
                subject_identity: "spiffe://x".into(),
                kid: "k".into(),
                sig_b64: String::new(),
            },
        ),
    );
    p
}

fn rates(rate: u64) -> PigouvianRates {
    let mut r = PigouvianRates::zero();
    r.rates.insert(ResourceDim::GpuSeconds, rate);
    r
}

// ── Named fixture tests ────────────────────────────────────────────────

#[test]
fn empty_sequence_yields_zero_welfare() {
    let seq: Vec<(u64, u64, u64)> = Vec::new();
    let pigou_sum: u128 = seq
        .iter()
        .map(|(b, r, e)| effective_minus_pigou_micro(*b, &one_dim_profile(*e), &rates(*r)) as u128)
        .sum();
    let raw_sum: u128 = seq.iter().map(|(b, _, _)| *b as u128).sum();
    assert_eq!(pigou_sum, 0);
    assert_eq!(raw_sum, 0);
}

#[test]
fn zero_rate_sequence_preserves_raw_sum() {
    // Mirrors Lean `sequential_welfare_zero_rate_identity` (F6.3).
    let seq = [
        (100_000u64, 0u64, 5u64),
        (250_000, 0, 10),
        (1_000_000, 0, 0),
    ];
    let pigou_sum: u128 = seq
        .iter()
        .map(|(b, r, e)| effective_minus_pigou_micro(*b, &one_dim_profile(*e), &rates(*r)) as u128)
        .sum();
    let raw_sum: u128 = seq.iter().map(|(b, _, _)| *b as u128).sum();
    assert_eq!(pigou_sum, raw_sum, "zero-rate must be sum-preserving");
}

#[test]
fn nonzero_rate_strictly_decreases_welfare() {
    // Sanity: with a positive rate AND positive externality on every
    // bid, total Pigouvian welfare must be strictly less than raw sum.
    let seq = [(1_000_000u64, 100u64, 2_000_000u64); 5];
    let pigou_sum: u128 = seq
        .iter()
        .map(|(b, r, e)| effective_minus_pigou_micro(*b, &one_dim_profile(*e), &rates(*r)) as u128)
        .sum();
    let raw_sum: u128 = seq.iter().map(|(b, _, _)| *b as u128).sum();
    assert!(
        pigou_sum < raw_sum,
        "positive rate × positive ext must reduce welfare: pigou={pigou_sum} raw={raw_sum}"
    );
}

// ── Proptest sweep ────────────────────────────────────────────────────

proptest! {
    /// **C4 acceptance** (audit 2026-05-29): the production kernel's
    /// `effective_minus_pigou_micro` summed over a sequence of
    /// `(bid, rate, ext)` tuples must be ≤ the sum of raw bids.
    ///
    /// This is the Rust analogue of the Lean theorem
    /// `Nucleus.Auctions.PigouvianVcgSequential.sequential_welfare_bounded_above`.
    /// The hub's `/match` route calls `match_auction_vcg`, which
    /// invokes this per-bid Pigouvian re-weight, so the proptest
    /// pins the bound at the function the network actually runs.
    #[test]
    fn sequential_pigou_welfare_bounded_above(
        seq in proptest::collection::vec(
            (0u64..1_000_000, 0u64..1_000, 0u64..1_000_000),
            1..16,
        ),
    ) {
        let pigou_sum: u128 = seq
            .iter()
            .map(|(b, r, e)| {
                effective_minus_pigou_micro(*b, &one_dim_profile(*e), &rates(*r)) as u128
            })
            .sum();
        let raw_sum: u128 = seq.iter().map(|(b, _, _)| *b as u128).sum();
        prop_assert!(
            pigou_sum <= raw_sum,
            "Lean F6.1 violated: pigou_sum={pigou_sum} raw_sum={raw_sum}",
        );
    }

    /// Companion sweep: monotonicity in the rate. Holding (bid, ext)
    /// fixed across a sequence, increasing the rate can only DECREASE
    /// Pigouvian welfare (or leave it equal at the saturation floor).
    /// Mirrors the spirit of Lean's
    /// `sequential_welfare_monotone_in_head_bid` invariant applied
    /// across the rate dimension.
    #[test]
    fn higher_rate_means_lower_or_equal_welfare(
        bid in 1u64..1_000_000,
        ext in 1u64..1_000_000,
        rate_low in 0u64..500,
        delta in 1u64..500,
    ) {
        let rate_high = rate_low + delta;
        let seq = [(bid, rate_low, ext); 4];
        let low: u128 = seq
            .iter()
            .map(|(b, r, e)| {
                effective_minus_pigou_micro(*b, &one_dim_profile(*e), &rates(*r)) as u128
            })
            .sum();
        let seq_high = [(bid, rate_high, ext); 4];
        let high: u128 = seq_high
            .iter()
            .map(|(b, r, e)| {
                effective_minus_pigou_micro(*b, &one_dim_profile(*e), &rates(*r)) as u128
            })
            .sum();
        prop_assert!(
            high <= low,
            "rate_high={rate_high} should not exceed rate_low={rate_low} welfare: high={high} low={low}",
        );
    }
}
