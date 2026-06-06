//! Differential parity: production kernels ↔ Aeneas-subset mirrors (gap G2c′).
//!
//! Asserts that the kernel functions the money path actually runs
//! (`crate::settlement::{classify, seller_gross, refund}`,
//! `crate::commons::route_to_commons`) are byte-identical to the hand-transcribed,
//! Lean-faithful mirrors in `extracted/{settlement,commons}_aeneas.rs` — over
//! RANDOMIZED inputs, not just the fixed golden vectors. The Lean theorems certify
//! the Lean defs; the mirrors are faithful to the Lean (by review); these proptests
//! bind mirror ↔ kernel. Any drift between the kernel and the proven model turns
//! CI red. Mirrors the `pigou_parity` / `lean_model_parity` pattern.

use nucleus_econ_kernels::extracted::{commons_aeneas, settlement_aeneas};
use nucleus_econ_kernels::{
    classify, refund, route_to_commons, seller_gross, CommonsShare, Verdict,
};
use proptest::prelude::*;

/// Kernel `Verdict` → the mirror's integer tag (0=reverse, 1=partial, 2=release).
fn verdict_tag(v: Verdict) -> u8 {
    match v {
        Verdict::Reverse => settlement_aeneas::VERDICT_REVERSE,
        Verdict::Partial => settlement_aeneas::VERDICT_PARTIAL,
        Verdict::Release => settlement_aeneas::VERDICT_RELEASE,
    }
}

proptest! {
    /// Settlement: classify / seller_gross / refund agree kernel ↔ mirror.
    #[test]
    fn settlement_kernel_matches_mirror(price in any::<u64>(), bps in 0u64..=30_000) {
        prop_assert_eq!(verdict_tag(classify(bps)), settlement_aeneas::classify(bps));
        prop_assert_eq!(seller_gross(price, bps), settlement_aeneas::seller_gross(price, bps));
        prop_assert_eq!(refund(price, bps), settlement_aeneas::refund(price, bps));
        // Conservation holds on both (the Lean `conservation` theorem).
        prop_assert_eq!(
            settlement_aeneas::seller_gross(price, bps) + settlement_aeneas::refund(price, bps),
            price
        );
    }

    /// Commons: route_to_commons amounts agree with the mirror's `routed`, over
    /// random pools and random valid 3-way splits (bps summing to 10_000).
    #[test]
    fn commons_kernel_matches_mirror(
        // Keep the pool bounded so `pool * bps` stays well within u128.
        pool in 0u64..=1_000_000_000_000u64,
        s0 in 0u64..=10_000,
        split in 0u64..=10_000,
    ) {
        // A random valid split: s0 + s1 + s2 == 10_000.
        let s0 = s0.min(10_000);
        let rem = 10_000 - s0;
        let s1 = split % (rem + 1);
        let s2 = rem - s1;
        let bps = [s0, s1, s2];

        let shares = vec![
            CommonsShare { destination: "a".into(), bps: bps[0] },
            CommonsShare { destination: "b".into(), bps: bps[1] },
            CommonsShare { destination: "c".into(), bps: bps[2] },
        ];

        let kernel: Vec<u64> = route_to_commons(pool, &shares)
            .expect("valid shares sum to 10_000")
            .iter()
            .map(|a| a.amount_micro)
            .collect();
        let mirror = commons_aeneas::routed(pool, &bps);

        prop_assert_eq!(&kernel, &mirror);
        // No-skim conservation on both (the Lean `routed_conserves` theorem).
        prop_assert_eq!(mirror.iter().sum::<u64>(), pool);
    }
}
