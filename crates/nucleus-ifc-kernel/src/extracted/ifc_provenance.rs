//! Provenance-axis IFC decision — the source-set axis, the FIFTH and final
//! extracted `flows_to` conjunct (completing integrity, confidentiality,
//! authority, derivation).
//!
//! # What this is
//!
//! `ProvenanceSet` is a `u8` bitset over six sources (USER, TOOL, WEB, MEMORY,
//! MODEL, SYSTEM). Unlike the four enum axes, its lattice is the powerset under
//! `⊆`: `union` is bitwise OR (combining data ADDS sources — the set only grows),
//! and the `flows_to` conjunct is `self.provenance.is_subset_of(target.provenance)`
//! — data may flow to a sink iff every source it carries is one the sink accepts.
//! So a sink that does not accept `WEB` rejects any datum carrying the `WEB` bit,
//! and because the fold only UNIONS in more sources, a forbidden source once
//! present can never be removed.
//!
//! The operations are pure `u8` bitwise (`|`, `&`, `==`) — `String`/`Vec`-free —
//! so the slice is cleanly Aeneas-extractable. Because `flows_to` is a
//! conjunction, a single-axis noninterference theorem over this slice is a SOUND
//! statement about the production admission decision (one false conjunct ⇒ the
//! whole `flows_to` false).
//!
//! # Faithfulness
//!
//! The functions take the raw `u8` bitmask (`ProvenanceSet::bits()`), mirroring
//! the production `ProvenanceSet` methods clause-for-clause:
//!
//! - [`punion`] mirrors `ProvenanceSet::union`: `ProvenanceSet(self.0 | other.0)`.
//! - [`psubset`] mirrors `ProvenanceSet::is_subset_of`: `(self.0 & other.0) == self.0`.
//! - [`prun_step`] the per-operation fold step used by the Lean noninterference
//!   fold (`= punion`).
//!
//! The `#[cfg(test)]` block binds each to the real `ProvenanceSet` /
//! `IFCLabel::flows_to` enforcement by EXHAUSTIVE analysis over the full 6-bit
//! production mask domain (all 64 masks; `ProvenanceSet::from_bits` masks `& 0x3F`
//! and every source is one of bits 0..5, so a real set never carries bits 6..7).
//! The extracted functions are nonetheless total, correct bitset ops on ALL of
//! `u8` — the Lean noninterference proof quantifies over every `u8`.

/// Provenance union — combining data ADDS sources, so the running effective
/// provenance is the bitwise OR of the two masks (the set only grows).
///
/// Mirrors `ProvenanceSet::union` (ifc_lattice.rs): `ProvenanceSet(self.0 |
/// other.0)`, on the raw `u8` mask.
pub fn punion(a: u8, b: u8) -> u8 {
    a | b
}

/// Provenance subset (the lattice order used by `flows_to`): the source mask `a`
/// flows to a sink accepting mask `ceiling` iff every source bit in `a` is also
/// in `ceiling`, i.e. `(a & ceiling) == a`.
///
/// Mirrors `ProvenanceSet::is_subset_of` (ifc_lattice.rs): `(self.0 & other.0)
/// == self.0`, on the raw `u8` mask. This is the derivation conjunct's dual: it
/// grows (union) rather than being a total order, so noninterference rests on
/// "the fold only adds sources".
pub fn psubset(a: u8, ceiling: u8) -> bool {
    (a & ceiling) == a
}

/// Per-operation fold step: fold a source label's provenance into the running
/// effective provenance. This is the step the Lean noninterference fold (`prun`)
/// applies per operation; it is exactly [`punion`].
pub fn prun_step(eff: u8, src: u8) -> u8 {
    punion(eff, src)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The six named source bits, for the flow-direction test.
    const WEB: u8 = 1 << 2;
    const USER: u8 = 1 << 0;

    // The production domain is the lower 6 bits: `ProvenanceSet::from_bits` masks
    // `& 0x3F` and every constructor uses bits 0..5, so a real `ProvenanceSet`
    // never carries bits 6..7. Parity is asserted over that full real domain
    // (all 64 masks); the extracted `punion`/`psubset` are nonetheless correct
    // bitset operations on ALL of `u8` (the Lean proof quantifies over every u8).
    const MAX_MASK: u8 = 0x3F;

    #[test]
    fn punion_matches_real_provenanceset_union() {
        // Exhaustive over the full 6-bit mask domain: the extracted `punion`
        // equals the raw bits of the real `ProvenanceSet::union` for every pair.
        for a in 0u8..=MAX_MASK {
            for b in 0u8..=MAX_MASK {
                let extracted = punion(a, b);
                let real = crate::ProvenanceSet::from_bits(a)
                    .union(crate::ProvenanceSet::from_bits(b))
                    .bits();
                assert_eq!(extracted, real, "punion parity failed for ({a}, {b})");
            }
        }
    }

    #[test]
    fn psubset_matches_real_provenanceset_is_subset_of() {
        // Exhaustive over the full 6-bit mask domain: the extracted `psubset`
        // equals the real `ProvenanceSet::is_subset_of` for every pair.
        for a in 0u8..=MAX_MASK {
            for ceiling in 0u8..=MAX_MASK {
                let extracted = psubset(a, ceiling);
                let real = crate::ProvenanceSet::from_bits(a)
                    .is_subset_of(crate::ProvenanceSet::from_bits(ceiling));
                assert_eq!(
                    extracted, real,
                    "psubset parity failed for a={a}, ceiling={ceiling}"
                );
            }
        }
    }

    #[test]
    fn psubset_matches_real_ifclabel_flows_to_provenance_axis() {
        // The extracted `psubset` equals the provenance conjunct of the real
        // `IFCLabel::flows_to`. Source and target share all non-provenance axes
        // (Default), so flows_to == the provenance clause. Checked over all pairs
        // of the six named single-source masks plus EMPTY (the flow-relevant set).
        let masks = [0u8, 1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4, 1 << 5];
        for &a in &masks {
            for &ceiling in &masks {
                let src = crate::IFCLabel {
                    provenance: crate::ProvenanceSet::from_bits(a),
                    ..Default::default()
                };
                let tgt = crate::IFCLabel {
                    provenance: crate::ProvenanceSet::from_bits(ceiling),
                    ..Default::default()
                };
                assert_eq!(
                    psubset(a, ceiling),
                    src.flows_to(tgt),
                    "psubset vs flows_to mismatch for a={a}, ceiling={ceiling}"
                );
            }
        }
    }

    #[test]
    fn web_source_does_not_flow_to_a_sink_that_omits_web() {
        // Non-vacuity + the flow direction: a datum carrying the WEB source bit
        // cannot flow to a sink whose accepted set is USER-only (omits WEB);
        // and the union of any op only ADDS sources, so it stays blocked.
        assert!(!psubset(WEB, USER), "WEB ⤳ USER-only sink must be blocked");
        assert!(
            psubset(USER, USER | WEB),
            "USER ⤳ {{USER,WEB}} must be allowed"
        );
        // union only grows: WEB stays present after folding in USER.
        assert_eq!(prun_step(WEB, USER), WEB | USER);
        assert!(
            !psubset(prun_step(WEB, USER), USER),
            "folding cannot remove WEB"
        );
    }
}
