//! Authority-axis IFC decision — the slice the authority noninterference
//! theorem is extracted over (order-twin of `ifc_integrity.rs`; the SECOND of
//! the two contravariant "trust" axes that gate privileged sinks).
//!
//! # What this is
//!
//! `IFCLabel::flows_to` (ifc_lattice.rs) is a *conjunction* over five gating
//! axes (confidentiality, integrity, authority, provenance, derivation). The
//! **authority** conjunct is what blocks *indirect prompt injection*: web
//! content is labelled `NoAuthority` and a directive-privileged action requires
//! `Directive`, so web content can be READ but can never INSTRUCT — regardless
//! of what the model decides to do with it. Integrity ("is this data trusted?")
//! and authority ("may this data *direct* the agent?") are distinct axes; only
//! integrity's half was machine-extracted before this slice, so the authority
//! half of the prompt-injection guarantee was proven over a hand model only.
//!
//! Authority is a 4-point chain (`NoAuthority < Informational < Suggestive <
//! Directive`) and — like integrity — CONTRAVARIANT: combining sources pulls
//! authority DOWN to the least-authoritative (`ameet` = MIN), and data labelled
//! `a` may be used where `ceiling` authority is required iff `a` is at least as
//! authoritative (`aflows_to a ceiling = rank a ≥ rank ceiling`). It is entirely
//! `String`/`Vec`-free, so it is cleanly Aeneas-extractable, whereas the full
//! multi-axis `flows_to` drags in `ProvenanceSet`/`DerivationClass` set/ord
//! machinery outside Aeneas's subset.
//!
//! Because `flows_to` is a conjunction, **failure on the authority conjunct
//! alone makes the whole `flows_to` false** — so a noninterference theorem about
//! this authority slice is a *sound* (single-axis) statement about the
//! production admission decision: if authority alone would block a sink, the
//! sink stays blocked regardless of the other axes.
//!
//! # Faithfulness
//!
//! Every definition here mirrors a specific clause of the production code:
//!
//! - [`AuthorityLevel`] mirrors `crate::AuthorityLevel` (ifc_lattice.rs)
//! - [`arank`] mirrors the `#[repr(u8)]` discriminants:
//!   `NoAuthority=0, Informational=1, Suggestive=2, Directive=3`
//! - [`ameet`] mirrors the authority clause of `IFCLabel::join`:
//!   `if self.authority <= other.authority { self } else { other }`
//! - [`aflows_to`] mirrors the authority clause of `IFCLabel::flows_to`:
//!   `self.authority >= target.authority`
//! - [`arun_step`] the per-operation fold step used by the Lean
//!   noninterference fold (`= ameet`)
//!
//! # Why explicit `u8` rank comparison (not derived `Ord`)
//!
//! The ordering is expressed as an explicit comparison on the rank ([`arank`])
//! rather than via `derive(Ord)`. A `derive`d `PartialOrd::le` is emitted by
//! Aeneas as an OPAQUE axiom (it does not translate the compiler-synthesized
//! body), which would put an unspecified comparison axiom on the proof's
//! critical path. Writing the comparison as `arank(a) <= arank(b)` makes it a
//! *translated* function with NO opaque external dependency — `#print axioms`
//! over the theorem stays clean (`[propext, Classical.choice, Quot.sound]`).
//!
//! The `#[cfg(test)]` block at the bottom binds each of these to the real
//! `IFCLabel` enforcement by EXHAUSTIVE case analysis over the 4-point enum
//! (stronger than a randomized proptest for a finite domain).

/// Authority level — CONTRAVARIANT (meet = min, least-authoritative wins).
///
/// Byte-faithful mirror of [`crate::AuthorityLevel`] (ifc_lattice.rs), including
/// the `#[repr(u8)]` discriminants. Kept as a *local* enum (rather than re-using
/// `crate::AuthorityLevel`) so the Aeneas extraction subgraph rooted at this
/// module is self-contained and does not pull in the full `IFCLabel` struct and
/// its non-subset axes. Parity with `crate::AuthorityLevel` is asserted
/// exhaustively in the tests below.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum AuthorityLevel {
    /// Cannot instruct the agent in any way (web content, public issue bodies).
    NoAuthority = 0,
    /// Informational only — can provide context but not direct actions.
    Informational = 1,
    /// Can suggest actions but requires approval (MCP tool descriptions).
    Suggestive = 2,
    /// Full authority to direct agent actions (user prompts, system config).
    Directive = 3,
}

/// Numeric rank — `NoAuthority=0 < Informational=1 < Suggestive=2 < Directive=3`,
/// exactly the `#[repr(u8)]` discriminants. The rank order IS the authority
/// order; the production code relies on the same discriminant-derived `Ord`.
pub fn arank(l: AuthorityLevel) -> u8 {
    match l {
        AuthorityLevel::NoAuthority => 0,
        AuthorityLevel::Informational => 1,
        AuthorityLevel::Suggestive => 2,
        AuthorityLevel::Directive => 3,
    }
}

/// Authority meet — combining data cannot RAISE its right to direct the agent,
/// so the running effective authority is the MIN of the two by rank.
///
/// Mirrors the authority clause of `IFCLabel::join`:
/// `authority: if self.authority <= other.authority { self } else { other }`.
/// The `<=` is the discriminant order, restated here as `arank(a) <= arank(b)`
/// so Aeneas translates a concrete body (no opaque `Ord` axiom).
pub fn ameet(a: AuthorityLevel, b: AuthorityLevel) -> AuthorityLevel {
    if arank(a) <= arank(b) { a } else { b }
}

/// Authority flows-to: data labelled `a` may be used where `ceiling` authority
/// is required iff `a` is at least as authoritative as `ceiling`.
///
/// Mirrors the authority conjunct of `IFCLabel::flows_to`:
/// `self.authority >= target.authority`, restated as
/// `arank(a) >= arank(ceiling)`. "Can't use `NoAuthority` where `Directive` is
/// needed" — the anti-prompt-injection direction.
pub fn aflows_to(a: AuthorityLevel, ceiling: AuthorityLevel) -> bool {
    arank(a) >= arank(ceiling)
}

/// Per-operation fold step: fold a source label's authority into the running
/// effective authority. This is the step the Lean noninterference fold (`arun`)
/// applies per operation; it is exactly [`ameet`].
pub fn arun_step(eff: AuthorityLevel, src: AuthorityLevel) -> AuthorityLevel {
    ameet(eff, src)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All four points of the authority chain, in rank order.
    const LEVELS: [AuthorityLevel; 4] = [
        AuthorityLevel::NoAuthority,
        AuthorityLevel::Informational,
        AuthorityLevel::Suggestive,
        AuthorityLevel::Directive,
    ];

    /// Map the local mirror to the production `crate::AuthorityLevel`.
    fn to_real(l: AuthorityLevel) -> crate::AuthorityLevel {
        match l {
            AuthorityLevel::NoAuthority => crate::AuthorityLevel::NoAuthority,
            AuthorityLevel::Informational => crate::AuthorityLevel::Informational,
            AuthorityLevel::Suggestive => crate::AuthorityLevel::Suggestive,
            AuthorityLevel::Directive => crate::AuthorityLevel::Directive,
        }
    }

    /// Build a production `IFCLabel` whose authority axis is `l` and whose other
    /// axes are fixed (Default) so the authority conjunct is the binding one.
    /// Every non-authority conjunct is then `x ⋈ x` (reflexive), so `flows_to`
    /// reduces to exactly the authority clause.
    fn label_with_authority(l: AuthorityLevel) -> crate::IFCLabel {
        crate::IFCLabel {
            authority: to_real(l),
            ..Default::default()
        }
    }

    #[test]
    fn discriminants_match_real_authoritylevel() {
        // The local mirror must carry the SAME repr(u8) discriminants as the
        // production enum, since `ameet`, `aflows_to` (and the Lean extraction's
        // ordering) all rest on the rank order.
        for l in LEVELS {
            assert_eq!(l as u8, to_real(l) as u8, "discriminant drift for {l:?}");
            assert_eq!(arank(l), l as u8, "arank != discriminant for {l:?}");
            assert_eq!(arank(l), to_real(l) as u8, "arank != real discriminant");
        }
    }

    #[test]
    fn ameet_matches_real_ifclabel_join_authority_axis() {
        // Exhaustive 4×4: the extracted `ameet` equals the authority field of the
        // real `IFCLabel::join` for every pair.
        for a in LEVELS {
            for b in LEVELS {
                let extracted = ameet(a, b);
                let real = label_with_authority(a)
                    .join(label_with_authority(b))
                    .authority;
                assert_eq!(
                    to_real(extracted),
                    real,
                    "ameet parity failed for ({a:?}, {b:?})"
                );
            }
        }
    }

    #[test]
    fn aflows_to_matches_real_ifclabel_flows_to_authority_axis() {
        // Exhaustive 4×4: the extracted `aflows_to` equals the authority conjunct
        // of the real `IFCLabel::flows_to`. Source and target share all
        // non-authority axes (Default), so flows_to == the authority clause.
        for a in LEVELS {
            for ceiling in LEVELS {
                let extracted = aflows_to(a, ceiling);
                let real = label_with_authority(a).flows_to(label_with_authority(ceiling));
                assert_eq!(
                    extracted, real,
                    "aflows_to parity failed for a={a:?}, ceiling={ceiling:?}"
                );
            }
        }
    }

    #[test]
    fn no_authority_cannot_direct_but_directive_can() {
        // Non-vacuity + the anti-prompt-injection direction: `NoAuthority` (web
        // content) can never be used where `Directive` authority is required;
        // `Directive` (a user prompt) satisfies any authority ceiling. Twin of
        // integrity's `gitpush_requires_trusted` / `secret_does_not_flow_public`.
        assert!(
            !aflows_to(AuthorityLevel::NoAuthority, AuthorityLevel::Directive),
            "NoAuthority ⤳ Directive must be blocked (prompt injection)"
        );
        assert!(
            aflows_to(AuthorityLevel::Directive, AuthorityLevel::NoAuthority),
            "Directive ⤳ NoAuthority must be allowed"
        );
        // Combining a directive source with web content strips directive
        // authority (contravariant meet): the result cannot direct.
        assert_eq!(
            arun_step(AuthorityLevel::Directive, AuthorityLevel::NoAuthority),
            AuthorityLevel::NoAuthority
        );
    }

    #[test]
    fn arun_step_is_ameet() {
        for a in LEVELS {
            for b in LEVELS {
                assert_eq!(arun_step(a, b), ameet(a, b));
            }
        }
    }
}
