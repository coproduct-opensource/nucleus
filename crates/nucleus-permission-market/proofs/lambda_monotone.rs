//! #2540 acceptance: Kani-verified overflow-freedom and monotonicity of the
//! integer λ curve.
//!
//! `compute_lambda_micro` replaces an `f64` `exp()` with a fixed-point
//! exponential in `u128`: range reduction, eight Taylor terms, ten squarings.
//! Every loop count is fixed, which is what makes this harness tractable —
//! there is no data-dependent iteration for Kani to unroll.
//!
//! # The harness
//!
//! For every `bps ≤ 10_000` (Kani's symbolic enumeration), the curve:
//!
//! 1. Does not panic from arithmetic overflow. With Kani's default overflow
//!    checking on, the absence of a reported overflow is the proof; the
//!    saturating/checked operators in the implementation are belt to that
//!    brace.
//! 2. Is bounded by `HARD_LAMBDA_MAX_MICRO`.
//! 3. Is monotone non-decreasing in `bps`: `λ(bps) ≤ λ(bps + 1)`. A price
//!    curve that dipped as pressure rose would let a bidder wait for a cheaper
//!    moment that pressure itself created.
//!
//! Non-vacuity is asserted too: `λ(10_000)` exceeds `19_000_000`, so the
//! bounds above are about a curve that actually rises, not a function that
//! returns zero.
//!
//! Pattern: `nucleus-econ-kernels/proofs/welfare_no_overflow.rs`.

#![cfg(kani)]

use crate::market::{HARD_LAMBDA_MAX_MICRO, compute_lambda_micro};

/// `cargo kani --harness lambda_monotone_and_bounded` certifies the integer λ
/// curve over every basis point.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(12)]
fn lambda_monotone_and_bounded() {
    let bps: u32 = kani::any();
    kani::assume(bps <= 10_000);

    let here = compute_lambda_micro(bps);
    let next = compute_lambda_micro(bps.saturating_add(1));

    assert!(here <= HARD_LAMBDA_MAX_MICRO);
    assert!(here <= next);
}

/// The curve is not degenerate: the monotonicity above is about something.
#[kani::proof]
#[kani::unwind(12)]
fn lambda_is_not_zero_everywhere() {
    assert!(compute_lambda_micro(10_000) > 19_000_000);
    assert_eq!(compute_lambda_micro(5_000), 0);
}
