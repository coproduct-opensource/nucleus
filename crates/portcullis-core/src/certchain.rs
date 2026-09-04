//! The **monotone-attenuation walk** of a certificate chain, stated once over
//! an abstract lattice so it can be Aeneas-extracted and proven (#2451).
//!
//! `portcullis::certificate::verify_certificate` walks a `LatticeCertificate`
//! and, at every delegation block, checks that the block's effective
//! permissions are `≤` its parent's (step 4c, `MonotoneViolation`). That
//! walk is interleaved with Ed25519 signature checks, SHA-256 hash-chain
//! linkage, and expiry — none of which Aeneas can translate (they live in
//! `ring`, `sha2`, `chrono`). This module restates the ONE decision the
//! monotonicity theorem is about, [`chain_attenuates`], over any
//! [`Lattice`], with no `String`, no allocation, and no crypto, so its
//! reachable subgraph stays inside Aeneas's supported subset — the same
//! discipline as [`crate::attenuation::chain_effective_authority`] and the
//! `nucleus-ifc-kernel` extraction roots.
//!
//! The binding to the production walk is a **parity test** in
//! `portcullis::certificate` (`chain_attenuates_agrees_with_verify_certificate`):
//! over real, fully signed certificates, `verify_certificate` accepts iff
//! this function returns `true` on the chain's effective permissions, and
//! a widened hop is refused by both. The Lean theorem
//! (`lean/CertChainMonotoneExtracted.lean`) is then proven over the Aeneas
//! output of THIS function: `chain_attenuates` returning `true` implies every
//! block is `leq` its parent, for chains of any length.
//!
//! # Shape
//!
//! A `fold` with a two-field accumulator `(ok, prev)`, mirroring the
//! production loop's `prev_permissions` variable. Aeneas does not extract the
//! body of `core::slice::iter::Iter::fold` (it is standard-library code
//! outside the scoped extraction), so the Lean side hand-writes the fold
//! SHAPE over `List L` and proves its step equal — by `rfl` — to the
//! genuinely extracted closure body, exactly as
//! `AttenuationChainExtracted.lean` does. The closure is written so the
//! extracted step is a plain `if ok then leq next prev else false`.

use crate::category::Lattice;

/// Does every hop of a delegation chain attenuate?
///
/// `root` is the authority block's permissions; `effective[i]` is block
/// `i`'s effective permissions. Returns `true` iff `effective[0] ≤ root`
/// and `effective[i+1] ≤ effective[i]` for every `i` — the invariant
/// `verify_certificate` enforces at step 4c. An empty chain attenuates
/// trivially (the root IS the leaf).
///
/// The accumulator carries the verdict so far and the previous element;
/// once a hop widens, `ok` stays `false` for the rest of the walk (the
/// production walk returns at the first violation; the verdicts agree).
pub fn chain_attenuates<L: Lattice>(root: &L, effective: &[L]) -> bool {
    effective
        .iter()
        .fold((true, root.clone()), |(ok, prev), next| {
            let step = if ok { next.leq(&prev) } else { false };
            (step, next.clone())
        })
        .0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny total order — enough to see every branch.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Level(u8);
    impl Lattice for Level {
        fn meet(&self, other: &Self) -> Self {
            Level(self.0.min(other.0))
        }
        fn join(&self, other: &Self) -> Self {
            Level(self.0.max(other.0))
        }
        fn leq(&self, other: &Self) -> bool {
            self.0 <= other.0
        }
    }

    #[test]
    fn a_descending_chain_attenuates_and_a_widening_hop_does_not() {
        assert!(chain_attenuates(&Level(5), &[]));
        assert!(chain_attenuates(
            &Level(5),
            &[Level(5), Level(3), Level(3), Level(0)]
        ));
        assert!(
            !chain_attenuates(&Level(5), &[Level(6)]),
            "wider than the root"
        );
        assert!(
            !chain_attenuates(&Level(5), &[Level(3), Level(4)]),
            "wider than the parent, though narrower than the root"
        );
        assert!(
            !chain_attenuates(&Level(5), &[Level(3), Level(4), Level(1)]),
            "a later narrowing does not forgive an earlier widening"
        );
    }
}
