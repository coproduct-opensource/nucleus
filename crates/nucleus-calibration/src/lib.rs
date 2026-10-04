//! Recomputable calibration receipts for decision models.
//!
//! # The claim this crate makes checkable
//!
//! A decision model emits a probability. Whether that probability *means*
//! anything — whether "80%" is right about 80% of the time — is calibration,
//! and it is the entire value of a model that returns numbers instead of
//! text. It is also, today, asserted rather than shown: a vendor reports an
//! ECE, a dashboard draws a reliability diagram, and a buyer gates production
//! routing on a number nobody outside the vendor can re-derive.
//!
//! Calibration is the one evaluation claim where that can be fixed *today*,
//! because it is a **deterministic function of declared inputs**. Given the
//! (probability, outcome) pairs, Brier and ECE are arithmetic. There is no
//! judge, no sampling of a non-deterministic generator, no rubric. So a
//! calibration claim can sit at the same rung as a clearing receipt: declared
//! inputs beside claimed outputs, and a verifier that recomputes and says
//! `Match` or `Mismatch` (`nucleus_recompute::RecomputeOutcome`, reused rather
//! than redefined).
//!
//! # The number nobody prints
//!
//! A finite sample of a *perfectly* calibrated model does not score ECE = 0.
//! Binomial noise inside each confidence bin puts a floor under the estimate,
//! and the floor is large at small `n`: an independent re-analysis of a
//! decision model's launch benchmark found that at `n = 60`, **a perfect model
//! scores ECE ≈ 0.045** — so the benchmark could not have distinguished a
//! calibrated model from a miscalibrated one, and was cited as if it had.
//!
//! That is ADR 0007 rule A-2 in another field: *"I could not look" is never
//! "I looked and it was fine."* This crate prints the floor beside every
//! estimate and refuses to render a verdict the sample cannot support:
//!
//! * [`Verdict::CouldNotLook`] — the floor at this `n` is at or above the
//!   tolerance the caller asked about. No observed ECE from this sample, high
//!   or low, can establish calibration to that tolerance. **Not a pass.**
//! * [`Verdict::Miscalibrated`] — the observed ECE exceeds what a perfectly
//!   calibrated model produces at this `n` (the 95th percentile of the
//!   simulated floor). Measurably worse than perfect.
//! * [`Verdict::ConsistentWithCalibrated`] — the observed ECE is within the
//!   floor, and the floor is below the tolerance, so that is a meaningful
//!   statement rather than a vacuous one.
//!
//! # Why the floor is simulated, and why that is the honest choice
//!
//! The closed form for the expected ECE of a calibrated model involves square
//! roots and π, which this crate will not compute in floating point on a money-
//! adjacent path. It also depends on the *actual* confidence distribution: a
//! model that only ever says 50% has a different floor from one that says 99%.
//!
//! So the floor is defined by construction: *what a perfectly calibrated model
//! would score on exactly these confidences* — outcomes drawn as
//! `Bernoulli(p_i)` from a declared seed, ECE computed the same way, repeated a
//! declared number of times. Integer-only, and recomputable to the bit by
//! anyone holding the receipt, which is the property this crate exists for.
//!
//! # Scope honesty
//!
//! * Binary outcomes and a single probability per prediction — the
//!   reliability-diagram framing (bin by `p`, compare mean `p` to mean `y`).
//!   Multi-class calibration is a different estimator.
//! * ECE with equal-width bins is the estimator the field reports, and it is
//!   known to be binning-sensitive. The bin count is a declared input so the
//!   recompute is exact, not a hidden default.
//! * "Consistent with calibrated" is a statement about this sample at this
//!   tolerance, not a proof of calibration. A model can drift tomorrow; a
//!   receipt is about the data it was issued over.
//! * Nothing here checks that the declared outcomes are *true*. That is the
//!   attested half of the two-layer model in
//!   `docs/rfcs/agent-efficiency-credit.md`; this crate is the recomputed half.
//!
//! No vendor is named anywhere in this crate, by mandate: it is for any model
//! that emits a probability.

#![forbid(unsafe_code)]
// A function whose type says `-> T` and panics is lying about its type, and
// this crate decides whether a number may be trusted. Denied for the shipped
// build only: `assert!` IS a panic, so denying inside `#[cfg(test)]` would
// forbid the thing tests are made of.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

pub mod floor;
pub mod metrics;
pub mod receipt;
pub mod verdict;

pub use floor::{FloorParams, noise_floor_micro};
pub use metrics::{MICRO, MetricError, Prediction, brier_micro, ece_micro};
pub use receipt::{Assessment, CalibrationClaim, content_hash_hex, issue, verify};
pub use verdict::{Verdict, assess};
