//! Integrity-axis IFC decision — the slice the noninterference theorem is
//! proven *over* after Charon→Aeneas→Lean extraction.
//!
//! # What this is
//!
//! `IFCLabel::flows_to` (lib.rs) is a *conjunction* over six axes
//! (confidentiality, integrity, authority, provenance, freshness, derivation).
//! Only the **integrity** conjunct gates the privileged sinks
//! (`SinkClass::GitPush` etc. require `IntegLevel::Trusted`). The integrity
//! axis is a 3-point chain (Biba integrity, inverted BLP) and is entirely
//! `String`/`Vec`-free — so it is cleanly Aeneas-extractable, whereas the full
//! multi-axis `flows_to` drags in `ProvenanceSet`/`DerivationClass` set/ord
//! machinery that pushes the whole-crate translation past Aeneas's subset.
//!
//! Because `flows_to` is a conjunction, **failure on the integrity conjunct
//! alone makes the whole `flows_to` false** — so a noninterference theorem
//! about this integrity slice is a *sound* (if single-axis) statement about
//! the production admission decision: if integrity alone would block a sink,
//! the sink stays blocked regardless of the other axes.
//!
//! # Faithfulness
//!
//! Every definition here mirrors a specific clause of the production code:
//!
//! - [`IntegLevel`]            mirrors `crate::IntegLevel` (lib.rs:1430-1438)
//! - [`irank`]                 mirrors the `#[repr(u8)]` discriminants:
//!                             `Adversarial=0, Untrusted=1, Trusted=2`
//! - [`imeet`]                 mirrors the integrity clause of
//!                             `IFCLabel::join` (lib.rs:1745-1749):
//!                             `if self.integrity <= other.integrity { self }
//!                              else { other }`
//! - [`iflows_to`]             mirrors the integrity clause of
//!                             `IFCLabel::flows_to` (lib.rs:1774):
//!                             `self.integrity >= target.integrity`
//! - [`irun_step`]             the per-operation fold step used by the Lean
//!                             noninterference fold (`= imeet`)
//!
//! # Why explicit `u8` rank comparison (not derived `Ord`)
//!
//! The ordering is expressed as an explicit comparison on the rank
//! ([`irank`]) rather than via `derive(Ord)`. A `derive`d `PartialOrd::le`
//! is emitted by Aeneas as an OPAQUE axiom (it does not translate the
//! compiler-synthesized body), which would put an unspecified comparison
//! axiom on the proof's critical path. Writing the comparison as
//! `irank(a) <= irank(b)` makes it a *translated* function with NO opaque
//! external dependency — `#[print axioms]` over the theorem stays clean.
//!
//! The `#[cfg(test)]` block at the bottom binds each of these to the real
//! `IFCLabel`/`SinkClass` enforcement by EXHAUSTIVE case analysis over the
//! 3-point enum (stronger than a randomized proptest for a finite domain).

/// Integrity level — CONTRAVARIANT (meet = min, least-trusted wins).
///
/// Byte-faithful mirror of [`crate::IntegLevel`] (lib.rs:1430-1438), including
/// the `#[repr(u8)]` discriminants. Kept as a *local* enum (rather than
/// re-using `crate::IntegLevel`) so the Aeneas extraction subgraph rooted at
/// this module is self-contained and does not pull in the full `IFCLabel`
/// struct and its non-subset axes. Parity with `crate::IntegLevel` is asserted
/// exhaustively in the tests below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum IntegLevel {
    /// Adversarially controlled (public issue bodies, web scraping results).
    Adversarial = 0,
    /// Untrusted but not adversarial (MCP tool output, cached data).
    Untrusted = 1,
    /// Trusted (user prompts, system config, verified sources).
    Trusted = 2,
}

/// Numeric rank — `Adversarial=0 < Untrusted=1 < Trusted=2`, exactly the
/// `#[repr(u8)]` discriminants. The rank order IS the integrity order; the
/// production code relies on the same discriminant-derived `Ord`.
pub fn irank(l: IntegLevel) -> u8 {
    match l {
        IntegLevel::Adversarial => 0,
        IntegLevel::Untrusted => 1,
        IntegLevel::Trusted => 2,
    }
}

/// Integrity meet — taint pulls trust DOWN, so the running effective integrity
/// is the MIN of the two by rank.
///
/// Mirrors the integrity clause of `IFCLabel::join` (lib.rs:1745-1749):
/// `integrity: if self.integrity <= other.integrity { self } else { other }`.
/// The `<=` is the discriminant order, restated here as `irank(a) <= irank(b)`
/// so Aeneas translates a concrete body (no opaque `Ord` axiom).
pub fn imeet(a: IntegLevel, b: IntegLevel) -> IntegLevel {
    if irank(a) <= irank(b) {
        a
    } else {
        b
    }
}

/// Integrity flows-to: data labeled `a` may be used where `ceiling` is required
/// iff `a` is at least as trusted as `ceiling`.
///
/// Mirrors the integrity conjunct of `IFCLabel::flows_to` (lib.rs:1774):
/// `self.integrity >= target.integrity`, restated as
/// `irank(a) >= irank(ceiling)`.
pub fn iflows_to(a: IntegLevel, ceiling: IntegLevel) -> bool {
    irank(a) >= irank(ceiling)
}

/// Per-operation fold step: fold a source label's integrity into the running
/// effective integrity. This is the step the Lean noninterference fold
/// (`irun`) applies per operation; it is exactly [`imeet`].
pub fn irun_step(eff: IntegLevel, src: IntegLevel) -> IntegLevel {
    imeet(eff, src)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All three points of the integrity chain, in rank order.
    const LEVELS: [IntegLevel; 3] = [
        IntegLevel::Adversarial,
        IntegLevel::Untrusted,
        IntegLevel::Trusted,
    ];

    /// Map the local mirror to the production `crate::IntegLevel`.
    fn to_real(l: IntegLevel) -> crate::IntegLevel {
        match l {
            IntegLevel::Adversarial => crate::IntegLevel::Adversarial,
            IntegLevel::Untrusted => crate::IntegLevel::Untrusted,
            IntegLevel::Trusted => crate::IntegLevel::Trusted,
        }
    }

    /// Build a production `IFCLabel` whose integrity axis is `l` and whose
    /// other axes are fixed so the integrity conjunct is the binding one.
    fn label_with_integrity(l: IntegLevel) -> crate::IFCLabel {
        let mut lab = crate::IFCLabel::default();
        lab.integrity = to_real(l);
        lab
    }

    #[test]
    fn discriminants_match_real_integlevel() {
        // The local mirror must carry the SAME repr(u8) discriminants as the
        // production enum, since both `imeet` and `iflows_to` (and the Lean
        // extraction's ordering) rest on the rank order.
        for l in LEVELS {
            assert_eq!(l as u8, to_real(l) as u8, "discriminant drift for {l:?}");
            // irank equals the repr(u8) discriminant of BOTH enums.
            assert_eq!(irank(l), l as u8, "irank != discriminant for {l:?}");
            assert_eq!(irank(l), to_real(l) as u8, "irank != real discriminant");
        }
    }

    #[test]
    fn imeet_matches_real_ifclabel_join_integrity_axis() {
        // Exhaustive 3×3: the extracted `imeet` equals the integrity field of
        // the real `IFCLabel::join` for every pair.
        for a in LEVELS {
            for b in LEVELS {
                let extracted = imeet(a, b);
                let real = label_with_integrity(a)
                    .join(label_with_integrity(b))
                    .integrity;
                assert_eq!(
                    to_real(extracted),
                    real,
                    "imeet parity failed for ({a:?}, {b:?})"
                );
            }
        }
    }

    #[test]
    fn iflows_to_matches_real_ifclabel_flows_to_integrity_axis() {
        // Exhaustive 3×3: the extracted `iflows_to` equals the integrity
        // conjunct of the real `IFCLabel::flows_to`. We isolate the integrity
        // conjunct by holding the other axes at values that always satisfy
        // their own conjunct (same label on every non-integrity axis), so the
        // overall `flows_to` result is exactly the integrity conjunct.
        for a in LEVELS {
            for ceiling in LEVELS {
                let extracted = iflows_to(a, ceiling);
                // Source and target share all non-integrity axes (default),
                // differing only on integrity, so flows_to == integrity clause.
                let src = label_with_integrity(a);
                let tgt = label_with_integrity(ceiling);
                let real = src.flows_to(tgt);
                assert_eq!(
                    extracted, real,
                    "iflows_to parity failed for a={a:?}, ceiling={ceiling:?}"
                );
            }
        }
    }

    #[test]
    fn gitpush_requires_trusted() {
        // The instantiation target of the noninterference theorem: the GitPush
        // sink's required integrity is `Trusted`. Corroborates the production
        // unit test and pins the `req = Trusted` instantiation.
        assert_eq!(
            crate::SinkClass::GitPush.required_integrity(),
            crate::IntegLevel::Trusted
        );
        // And `Adversarial` data does NOT flow to that ceiling (non-vacuity).
        assert!(!iflows_to(IntegLevel::Adversarial, IntegLevel::Trusted));
    }

    #[test]
    fn irun_step_is_imeet() {
        for a in LEVELS {
            for b in LEVELS {
                assert_eq!(irun_step(a, b), imeet(a, b));
            }
        }
    }
}
