//! Confidentiality-axis IFC decision — the slice the confidentiality
//! noninterference theorem is extracted over (D1 milestone C1; dual of
//! `ifc_integrity.rs`).
//!
//! Confidentiality is the BLP ("no read up → no write down") axis. Unlike
//! integrity (which is contravariant — taint pulls trust *down*), confidentiality
//! is COVARIANT: combining two sources raises the result to the *more* confidential
//! of the two. So the join clause is MAX (here `cjoin`), and the flows-to clause is
//! `≤` (data labeled `a` may leave to a sink whose ceiling is *at least* as
//! confidential): exactly the dual of integrity's MIN / `≥`.
//!
//! Aeneas translates each function to a CONCRETE body (no opaque `Ord` axiom), so
//! the extracted Lean mirrors the production `IFCLabel` confidentiality clause. The
//! exhaustive parity tests below pin the mirror to the real `IFCLabel::{join,
//! flows_to}` confidentiality conjunct.

/// Confidentiality level — mirrors the production `crate::ConfLevel`. The
/// `#[repr(u8)]` discriminants ARE the confidentiality order.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfLevel {
    /// Public — no confidentiality restriction (the bottom).
    Public = 0,
    /// Internal — organisation-confidential.
    Internal = 1,
    /// Secret — credentials, keys, private data (the top).
    Secret = 2,
}

/// Numeric rank — `Public=0 < Internal=1 < Secret=2`, exactly the `#[repr(u8)]`
/// discriminants. The rank order IS the confidentiality order; the production
/// code relies on the same discriminant-derived `Ord`.
pub fn crank(l: ConfLevel) -> u8 {
    match l {
        ConfLevel::Public => 0,
        ConfLevel::Internal => 1,
        ConfLevel::Secret => 2,
    }
}

/// Confidentiality join — combining data raises confidentiality, so the running
/// effective confidentiality is the MAX of the two by rank.
///
/// Mirrors the confidentiality clause of `IFCLabel::join` (lib.rs):
/// `confidentiality: if self.confidentiality >= other.confidentiality { self }
/// else { other }`. The `>=` is the discriminant order, restated here as
/// `crank(a) >= crank(b)` so Aeneas translates a concrete body.
pub fn cjoin(a: ConfLevel, b: ConfLevel) -> ConfLevel {
    if crank(a) >= crank(b) { a } else { b }
}

/// Confidentiality flows-to: data labeled `a` may flow to a sink whose ceiling is
/// `ceiling` iff `a` is at most as confidential as `ceiling` (BLP no-read-up).
///
/// Mirrors the confidentiality conjunct of `IFCLabel::flows_to` (lib.rs):
/// `self.confidentiality <= target.confidentiality`, restated as
/// `crank(a) <= crank(ceiling)`.
pub fn cflows_to(a: ConfLevel, ceiling: ConfLevel) -> bool {
    crank(a) <= crank(ceiling)
}

/// Per-operation fold step: fold a source label's confidentiality into the
/// running effective confidentiality. This is the step the Lean noninterference
/// fold (`crun`) applies per operation; it is exactly [`cjoin`].
pub fn crun_step(eff: ConfLevel, src: ConfLevel) -> ConfLevel {
    cjoin(eff, src)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All three points of the confidentiality chain, in rank order.
    const LEVELS: [ConfLevel; 3] = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];

    /// Map the local mirror to the production `crate::ConfLevel`.
    fn to_real(l: ConfLevel) -> crate::ConfLevel {
        match l {
            ConfLevel::Public => crate::ConfLevel::Public,
            ConfLevel::Internal => crate::ConfLevel::Internal,
            ConfLevel::Secret => crate::ConfLevel::Secret,
        }
    }

    /// Build a production `IFCLabel` whose confidentiality axis is `l` and whose
    /// other axes are fixed (Default) so the confidentiality conjunct is binding.
    fn label_with_confidentiality(l: ConfLevel) -> crate::IFCLabel {
        crate::IFCLabel {
            confidentiality: to_real(l),
            ..Default::default()
        }
    }

    #[test]
    fn discriminants_match_real_conflevel() {
        for l in LEVELS {
            assert_eq!(l as u8, to_real(l) as u8, "discriminant drift for {l:?}");
            assert_eq!(crank(l), l as u8, "crank != discriminant for {l:?}");
            assert_eq!(crank(l), to_real(l) as u8, "crank != real discriminant");
        }
    }

    #[test]
    fn cjoin_matches_real_ifclabel_join_confidentiality_axis() {
        // Exhaustive 3×3: the extracted `cjoin` equals the confidentiality field
        // of the real `IFCLabel::join` for every pair.
        for a in LEVELS {
            for b in LEVELS {
                let extracted = cjoin(a, b);
                let real = label_with_confidentiality(a)
                    .join(label_with_confidentiality(b))
                    .confidentiality;
                assert_eq!(
                    to_real(extracted),
                    real,
                    "cjoin parity failed for ({a:?}, {b:?})"
                );
            }
        }
    }

    #[test]
    fn cflows_to_matches_real_ifclabel_flows_to_confidentiality_axis() {
        // Exhaustive 3×3: extracted `cflows_to` equals the confidentiality
        // conjunct of the real `IFCLabel::flows_to`. Source and target share all
        // non-confidentiality axes (Default), so flows_to == the conf clause.
        for a in LEVELS {
            for ceiling in LEVELS {
                let extracted = cflows_to(a, ceiling);
                let real =
                    label_with_confidentiality(a).flows_to(label_with_confidentiality(ceiling));
                assert_eq!(
                    extracted, real,
                    "cflows_to parity failed for a={a:?}, ceiling={ceiling:?}"
                );
            }
        }
    }

    #[test]
    fn secret_does_not_flow_to_public_but_public_does() {
        // Non-vacuity + the BLP direction: Secret cannot leave to a Public sink;
        // Public flows everywhere. (Dual of `gitpush_requires_trusted`.)
        assert!(
            !cflows_to(ConfLevel::Secret, ConfLevel::Public),
            "Secret ⤳ Public must be blocked"
        );
        assert!(
            cflows_to(ConfLevel::Public, ConfLevel::Secret),
            "Public ⤳ Secret must be allowed"
        );
        assert_eq!(
            crun_step(ConfLevel::Public, ConfLevel::Secret),
            ConfLevel::Secret
        );
    }
}
