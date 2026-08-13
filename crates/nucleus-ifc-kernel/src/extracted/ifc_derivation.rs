//! Derivation-axis IFC decision — the determinism-provenance axis, the FOURTH
//! extracted `flows_to` conjunct (after integrity, confidentiality, authority).
//!
//! # What this is
//!
//! `DerivationClass` tracks whether a datum was deterministically computed, AI-
//! generated, mixed, human-promoted, or from an opaque external source. Unlike
//! the three totally-ordered axes, it is a genuine **lattice (a diamond)**:
//!
//! ```text
//!       OpaqueExternal  (top)
//!            |
//!          Mixed
//!         /     \
//!   AIDerived  HumanPromoted
//!         \     /
//!       Deterministic  (bottom)
//! ```
//!
//! `join` is the least upper bound (combining data can only move UP the lattice
//! toward "less reproducible"), and `leq a b := join a b == b` is the induced
//! order. The `flows_to` conjunct is `self.derivation.leq(target.derivation)`:
//! data may flow to a sink iff its derivation is at most what the sink allows —
//! so a sink that requires `Deterministic` (reproducible) provenance rejects any
//! AI-derived / opaque data. The crate's documented key invariant is **no silent
//! cleansing**: `AIDerived.join(x)` is never `Deterministic` — AI-derived data
//! can never be laundered back to a reproducible class.
//!
//! It is a 5-variant enum, `String`/`Vec`-free, so it is cleanly
//! Aeneas-extractable; because `flows_to` is a conjunction, a single-axis
//! noninterference theorem over this slice is a SOUND statement about the
//! production admission decision (one false conjunct ⇒ the whole `flows_to`
//! false).
//!
//! # Faithfulness
//!
//! - [`DerivationClass`] mirrors `crate::DerivationClass` (ifc_lattice.rs),
//!   including the `#[repr(u8)]` discriminants
//!   (`Deterministic=0, AIDerived=1, Mixed=2, HumanPromoted=3, OpaqueExternal=4`).
//! - [`djoin`] transcribes the `match (self, other)` arms of
//!   `DerivationClass::join` VERBATIM.
//! - [`dleq`] mirrors `DerivationClass::leq`: `self.join(other) == other`.
//! - [`drun_step`] the per-operation fold step used by the Lean noninterference
//!   fold (`= djoin`).
//!
//! The extracted `dleq` uses derived `PartialEq` on the enum, which Aeneas
//! translates to a concrete `read_discriminant` comparison (no opaque `Ord`/`Eq`
//! axiom) — so `#print axioms` over the theorem stays clean.
//!
//! The `#[cfg(test)]` block binds each definition to the real `IFCLabel`
//! enforcement by EXHAUSTIVE 5×5 case analysis.

/// Determinism-provenance class — a lattice (diamond), NOT a chain.
///
/// Byte-faithful mirror of [`crate::DerivationClass`] (ifc_lattice.rs), including
/// the `#[repr(u8)]` discriminants. Kept as a *local* enum so the Aeneas
/// extraction subgraph rooted at this module is self-contained. Parity with
/// `crate::DerivationClass` is asserted exhaustively in the tests below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DerivationClass {
    /// Reproducible: pure transform, deterministic fetch, parser output (bottom).
    Deterministic = 0,
    /// LLM-generated, not reproducible.
    AIDerived = 1,
    /// Combination of deterministic and AI-derived inputs.
    Mixed = 2,
    /// AI-derived data explicitly approved by a human. Preserves ancestry.
    HumanPromoted = 3,
    /// External system with unknown determinism profile (top).
    OpaqueExternal = 4,
}

/// Derivation join — least upper bound. Transcribes the `match (self, other)`
/// arms of `DerivationClass::join` (ifc_lattice.rs) top-to-bottom, verbatim:
///
/// - `Deterministic` is bottom (identity for join)
/// - `OpaqueExternal` is top (absorbs everything)
/// - same class is idempotent
/// - any other pair of distinct non-bottom/non-top classes → `Mixed`
///
/// The order of arms matters and matches the production `match`.
pub fn djoin(a: DerivationClass, b: DerivationClass) -> DerivationClass {
    use DerivationClass::*;
    match (a, b) {
        (Deterministic, x) => x,
        (x, Deterministic) => x,
        (OpaqueExternal, _) => OpaqueExternal,
        (_, OpaqueExternal) => OpaqueExternal,
        (AIDerived, AIDerived) => AIDerived,
        (HumanPromoted, HumanPromoted) => HumanPromoted,
        (Mixed, Mixed) => Mixed,
        _ => Mixed,
    }
}

/// Derivation flows-to (the lattice order): data labelled `a` may be used where
/// `ceiling` derivation is required iff `a` is at most as un-reproducible as
/// `ceiling`, i.e. `join(a, ceiling) == ceiling`.
///
/// Mirrors `DerivationClass::leq` (`self.join(other) == other`) applied as the
/// derivation conjunct of `IFCLabel::flows_to` (`self.derivation.leq(target)`).
pub fn dleq(a: DerivationClass, ceiling: DerivationClass) -> bool {
    djoin(a, ceiling) == ceiling
}

/// Per-operation fold step: fold a source label's derivation into the running
/// effective derivation. This is the step the Lean noninterference fold (`drun`)
/// applies per operation; it is exactly [`djoin`].
pub fn drun_step(eff: DerivationClass, src: DerivationClass) -> DerivationClass {
    djoin(eff, src)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All five points of the derivation lattice.
    const LEVELS: [DerivationClass; 5] = [
        DerivationClass::Deterministic,
        DerivationClass::AIDerived,
        DerivationClass::Mixed,
        DerivationClass::HumanPromoted,
        DerivationClass::OpaqueExternal,
    ];

    /// Map the local mirror to the production `crate::DerivationClass`.
    fn to_real(l: DerivationClass) -> crate::DerivationClass {
        match l {
            DerivationClass::Deterministic => crate::DerivationClass::Deterministic,
            DerivationClass::AIDerived => crate::DerivationClass::AIDerived,
            DerivationClass::Mixed => crate::DerivationClass::Mixed,
            DerivationClass::HumanPromoted => crate::DerivationClass::HumanPromoted,
            DerivationClass::OpaqueExternal => crate::DerivationClass::OpaqueExternal,
        }
    }

    /// Build a production `IFCLabel` whose derivation axis is `l` and whose other
    /// axes are fixed (Default) so the derivation conjunct is the binding one.
    /// Every non-derivation conjunct is then `x ⋈ x` (reflexive), so `flows_to`
    /// reduces to exactly the derivation clause.
    fn label_with_derivation(l: DerivationClass) -> crate::IFCLabel {
        crate::IFCLabel {
            derivation: to_real(l),
            ..Default::default()
        }
    }

    #[test]
    fn discriminants_match_real_derivationclass() {
        for l in LEVELS {
            assert_eq!(l as u8, to_real(l) as u8, "discriminant drift for {l:?}");
        }
    }

    #[test]
    fn djoin_matches_real_ifclabel_join_derivation_axis() {
        // Exhaustive 5×5: the extracted `djoin` equals the derivation field of
        // the real `IFCLabel::join` for every pair.
        for a in LEVELS {
            for b in LEVELS {
                let extracted = djoin(a, b);
                let real = label_with_derivation(a)
                    .join(label_with_derivation(b))
                    .derivation;
                assert_eq!(
                    to_real(extracted),
                    real,
                    "djoin parity failed for ({a:?}, {b:?})"
                );
            }
        }
    }

    #[test]
    fn dleq_matches_real_ifclabel_flows_to_derivation_axis() {
        // Exhaustive 5×5: the extracted `dleq` equals the derivation conjunct of
        // the real `IFCLabel::flows_to`. Source and target share all
        // non-derivation axes (Default), so flows_to == the derivation clause.
        for a in LEVELS {
            for ceiling in LEVELS {
                let extracted = dleq(a, ceiling);
                let real = label_with_derivation(a).flows_to(label_with_derivation(ceiling));
                assert_eq!(
                    extracted, real,
                    "dleq parity failed for a={a:?}, ceiling={ceiling:?}"
                );
            }
        }
    }

    #[test]
    fn no_silent_cleansing_and_top_never_flows_to_bottom() {
        // The crate's documented key invariant: AI-derived data never joins back
        // to Deterministic — it cannot be laundered to a reproducible class.
        for x in LEVELS {
            assert_ne!(
                djoin(DerivationClass::AIDerived, x),
                DerivationClass::Deterministic,
                "AIDerived joined with {x:?} laundered to Deterministic"
            );
        }
        // Non-vacuity + the flow direction: opaque/AI data cannot reach a sink
        // that requires Deterministic provenance; Deterministic flows anywhere.
        assert!(
            !dleq(
                DerivationClass::OpaqueExternal,
                DerivationClass::Deterministic
            ),
            "OpaqueExternal ⤳ Deterministic must be blocked"
        );
        assert!(
            !dleq(DerivationClass::AIDerived, DerivationClass::Deterministic),
            "AIDerived ⤳ Deterministic must be blocked"
        );
        assert!(
            dleq(
                DerivationClass::Deterministic,
                DerivationClass::OpaqueExternal
            ),
            "Deterministic ⤳ anything must be allowed"
        );
    }

    #[test]
    fn drun_step_is_djoin() {
        for a in LEVELS {
            for b in LEVELS {
                assert_eq!(drun_step(a, b), djoin(a, b));
            }
        }
    }
}
