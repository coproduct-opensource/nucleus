//! Aeneas-grade mirror of `lean/Nucleus/Commons.lean`.
//!
//! Byte-faithful to the Lean `floorAllocs` / `routed` definitions; the parity
//! proptests in `tests/settlement_commons_parity.rs` bind these mirrors to the
//! production kernel (`crate::commons::route_to_commons`) over randomized inputs.
//!
//! Same tier as the other `extracted/*` mirrors: hand-transcribed Aeneas-subset
//! Rust, faithful-by-review + proptest-bound, pending the real Charon pipeline
//! (docs/PROOFS.md §5). Lean `List Nat` ↔ Rust `Vec<u64>`.

#![deny(clippy::float_arithmetic)]

/// Mirror of Lean `Commons` basis-point scale.
pub const BPS_SCALE: u64 = 10_000;

/// Rust mirror of `Nucleus.Commons.floorAllocs`.
///
/// Lean definition (verbatim):
///
/// ```text
/// def floorAllocs (pool : Nat) (bps : List Nat) : List Nat :=
///   bps.map (fun b => pool * b / 10000)
/// ```
pub fn floor_allocs(pool: u64, bps: &[u64]) -> Vec<u64> {
    bps.iter()
        .map(|&b| ((pool as u128 * b as u128) / BPS_SCALE as u128) as u64)
        .collect()
}

/// Rust mirror of `Nucleus.Commons.routed`.
///
/// Lean definition (verbatim):
///
/// ```text
/// def routed (pool : Nat) (bps : List Nat) : List Nat :=
///   match floorAllocs pool bps with
///   | [] => []
///   | a :: rest => (a + (pool - (a :: rest).sum)) :: rest
/// ```
///
/// The dust `pool - Σfloors` is assigned to the FIRST share, so the result sums
/// to exactly `pool` (the Lean theorem `routed_conserves`, no-skim). `saturating_*`
/// mirrors `Nat` arithmetic; `floorAllocs_sum_le` guarantees `Σfloors ≤ pool`.
pub fn routed(pool: u64, bps: &[u64]) -> Vec<u64> {
    let mut allocs = floor_allocs(pool, bps);
    if let Some((first, rest)) = allocs.split_first_mut() {
        let sum: u64 = first.saturating_add(rest.iter().copied().sum());
        *first = first.saturating_add(pool.saturating_sub(sum));
    }
    allocs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_empty() {
        assert_eq!(routed(1_000_000, &[]), Vec::<u64>::new());
    }

    #[test]
    fn proportional_split_with_dust_to_first() {
        // 60/25/15 of 1_000_000 — exact, no dust.
        assert_eq!(
            routed(1_000_000, &[6_000, 2_500, 1_500]),
            vec![600_000, 250_000, 150_000]
        );
        // pool = 7: floors 4/1/1 = 6, dust 1 → first = 5 (matches the kernel + golden).
        assert_eq!(routed(7, &[6_000, 2_500, 1_500]), vec![5, 1, 1]);
    }

    #[test]
    fn no_skim_conservation() {
        for &pool in &[0u64, 1, 7, 1_000_000, 9_999_999] {
            let allocs = routed(pool, &[6_000, 2_500, 1_500]);
            assert_eq!(allocs.iter().sum::<u64>(), pool, "skim/loss at pool={pool}");
        }
    }
}
