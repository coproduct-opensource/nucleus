//! **Pigouvian U4 — differential parity Rust ↔ Lean.**
//!
//! Asserts that the kernel-side `effective_minus_pigou_micro` (which
//! the production Pigouvian-VCG path calls per bid) produces results
//! byte-faithful to the Lean-extracted `pigouvian_re_weight`. Any
//! drift is a CI red — bidder utility under the Rust kernel and the
//! Lean-proved truthfulness property would diverge if the math drifts.
//!
//! Mirrors the A4 `lean_model_parity.rs` pattern. The Lean side is
//! `Nucleus.Auctions.PigouvianVcg.effectivePigou` (and its three
//! corollaries — `pigouvian_welfare_optimal_on_lattice`,
//! `zero_rate_is_identity`, `zero_externality_is_identity`).
//!
//! `cargo test -p nucleus-econ-kernels --test pigou_parity` → green
//! is the U4 acceptance.

use ed25519_dalek::SigningKey;
use nucleus_econ_kernels::extracted::pigou_aeneas::{
    pigouvian_re_weight, pigouvian_re_weight_multi_dim,
};
use nucleus_econ_kernels::{effective_minus_pigou_micro, PigouvianRates};
use nucleus_externality::{sign_claim, ExternalityProfile, ResourceDim, SignedExternalityClaim};
use proptest::prelude::*;

/// Build a single-dimension externality profile with `units_micro =
/// ext` for `ResourceDim::GpuSeconds` (a negative externality so the
/// Pigouvian path treats it as a tax).
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
fn parity_single_dim_zero_rate() {
    // Mirrors Lean `zero_rate_is_identity`.
    let profile = one_dim_profile(5_000_000);
    let lean = pigouvian_re_weight(1_000_000, 0, 5_000_000, 1_000_000);
    let rust = effective_minus_pigou_micro(1_000_000, &profile, &rates(0));
    assert_eq!(lean, rust);
    assert_eq!(rust, 1_000_000);
}

#[test]
fn parity_single_dim_zero_externality() {
    // Mirrors Lean `zero_externality_is_identity`.
    let profile = one_dim_profile(0);
    let lean = pigouvian_re_weight(1_000_000, 100, 0, 1_000_000);
    let rust = effective_minus_pigou_micro(1_000_000, &profile, &rates(100));
    assert_eq!(lean, rust);
    assert_eq!(rust, 1_000_000);
}

#[test]
fn parity_single_dim_concrete_discount() {
    // λ = 100 · ext = 2_000_000 → tax 200; bid 1_000_000 → 999_800.
    let profile = one_dim_profile(2_000_000);
    let lean = pigouvian_re_weight(1_000_000, 100, 2_000_000, 1_000_000);
    let rust = effective_minus_pigou_micro(1_000_000, &profile, &rates(100));
    assert_eq!(lean, rust);
    assert_eq!(rust, 999_800);
}

#[test]
fn parity_heavy_tax_saturates_to_zero() {
    // Mirrors Lean's saturating-Nat-sub behavior (Lean: Nat 0 - n = 0).
    let profile = one_dim_profile(u64::MAX);
    let lean = pigouvian_re_weight(1_000_000, u64::MAX, u64::MAX, 1_000_000);
    let rust = effective_minus_pigou_micro(1_000_000, &profile, &rates(u64::MAX));
    assert_eq!(lean, rust);
    assert_eq!(rust, 0);
}

// ── Proptest sweep ────────────────────────────────────────────────────

proptest! {
    /// **U4 named acceptance — `pigou_re_weight_matches_lean`.**
    /// 256 random `(bid, rate, ext)` tuples; assert the kernel's
    /// `effective_minus_pigou_micro` over a single-dim profile equals
    /// the Lean-extracted `pigouvian_re_weight` byte-for-byte.
    #[test]
    fn pigou_re_weight_matches_lean(
        bid in 0u64..1_000_000_000,
        rate in 0u64..10_000,
        ext in 0u64..100_000_000,
    ) {
        let profile = one_dim_profile(ext);
        let lean = pigouvian_re_weight(bid, rate, ext, 1_000_000);
        let rust = effective_minus_pigou_micro(bid, &profile, &rates(rate));
        prop_assert_eq!(lean, rust);
    }

    /// **E4.3 acceptance — multi-dim kernel ↔ extracted parity.**
    ///
    /// For 256 random multi-dim externality profiles, asserts that
    /// the kernel's `effective_minus_pigou_micro` produces the same
    /// result as the Lean-mirrored `pigouvian_re_weight_multi_dim`.
    /// Closes the multi-dim half of the C4 audit gap: now the
    /// production function is byte-faithful to the Lean spec
    /// `PigouvianVcgMultiDim.effectivePigouMultiDim`, not just the
    /// single-dim primitive.
    #[test]
    fn multi_dim_matches_kernel(
        bid in 0u64..1_000_000_000,
        // Each tuple = (dim-index 0..6, rate 0..10_000, ext 0..100_000_000).
        // Length 1..7 sweeps the full ResourceDim::all() cardinality.
        dims in proptest::collection::vec(
            (0u8..7, 0u64..10_000, 0u64..100_000_000),
            1..=7,
        ),
    ) {
        let all_dims = ResourceDim::all();
        // Build the kernel-side profile + rates. Dedupe per dim
        // (BTreeMap absorbs duplicates by key — last write wins),
        // matching how the profile would be constructed in production.
        let mut profile = ExternalityProfile::new();
        let mut rates_map = PigouvianRates::zero();
        let mut seen_dims = std::collections::BTreeSet::new();
        let mut taxes: Vec<(u64, u64)> = Vec::new();
        let mut subsidies: Vec<(u64, u64)> = Vec::new();
        let sk = SigningKey::from_bytes(&[77u8; 32]);
        for (di, rate, ext) in &dims {
            let dim = all_dims[(*di as usize) % all_dims.len()];
            if !seen_dims.insert(dim) {
                // Duplicate dim — skip so kernel + extracted see the
                // same single contribution per dim (the kernel uses
                // BTreeMap so dups would collapse anyway).
                continue;
            }
            profile.insert(
                dim,
                sign_claim(
                    &sk,
                    SignedExternalityClaim {
                        resource: dim,
                        units_micro: *ext,
                        ts_unix_micros: 1_700_000_000_000_000,
                        not_after_unix_micros: 1_700_000_000_000_000
                            + 3_600_000_000,
                        subject_identity: "spiffe://x".into(),
                        kid: "k".into(),
                        sig_b64: String::new(),
                    },
                ),
            );
            rates_map.rates.insert(dim, *rate);
            if dim.is_positive_externality() {
                subsidies.push((*rate, *ext));
            } else {
                taxes.push((*rate, *ext));
            }
        }
        let kernel = effective_minus_pigou_micro(bid, &profile, &rates_map);
        let extracted =
            pigouvian_re_weight_multi_dim(bid, 1_000_000, &taxes, &subsidies);
        prop_assert_eq!(
            kernel,
            extracted,
            "kernel={} extracted={} bid={} taxes={:?} subsidies={:?}",
            kernel,
            extracted,
            bid,
            taxes,
            subsidies
        );
    }
}
