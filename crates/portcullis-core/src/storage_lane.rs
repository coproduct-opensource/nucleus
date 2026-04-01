// SPDX-License-Identifier: MIT
//! Dual-lane storage routing based on [`DerivationClass`].
//!
//! Every datum entering the portcullis pipeline must be routed to one of three
//! storage lanes:
//!
//! | Lane          | Purpose                                         |
//! |---------------|-------------------------------------------------|
//! | **Proposed**  | Default holding area; accepts any derivation.    |
//! | **Verified**  | Only deterministic or human-promoted data.       |
//! | **Quarantined** | Holding pen for opaque/untrusted externals.    |
//!
//! [`StorageLane::required_lane`] is the deterministic routing function:
//! given a derivation class, it returns the lane where the datum *should*
//! initially land. [`StorageLane::accepts`] is the gate predicate: it
//! answers whether a lane *would* accept data of a given derivation class.

use crate::DerivationClass;
use core::fmt;

/// A storage lane in the dual-lane (plus quarantine) model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum StorageLane {
    /// Default lane for data awaiting verification.
    /// Accepts all derivation classes.
    Proposed,
    /// Lane for data that has been verified as trustworthy.
    /// Only accepts `Deterministic` and `HumanPromoted` derivations.
    Verified,
    /// Holding pen for untrusted or opaque data.
    /// Accepts all derivation classes.
    Quarantined,
}

impl StorageLane {
    /// Deterministic routing: maps a [`DerivationClass`] to its required
    /// initial storage lane.
    ///
    /// - `Deterministic` → `Verified` (reproducible, can be auto-verified)
    /// - `HumanPromoted` → `Verified` (explicitly attested by a human)
    /// - `AIDerived` → `Proposed` (needs verification before promotion)
    /// - `Mixed` → `Proposed` (contains AI-derived components)
    /// - `OpaqueExternal` → `Quarantined` (unknown provenance)
    pub fn required_lane(derivation: DerivationClass) -> StorageLane {
        match derivation {
            DerivationClass::Deterministic => StorageLane::Verified,
            DerivationClass::HumanPromoted => StorageLane::Verified,
            DerivationClass::AIDerived => StorageLane::Proposed,
            DerivationClass::Mixed => StorageLane::Proposed,
            DerivationClass::OpaqueExternal => StorageLane::Quarantined,
        }
    }

    /// Gate predicate: does this lane accept data of the given derivation class?
    ///
    /// - `Proposed`: accepts everything (it is the default intake lane).
    /// - `Verified`: only `Deterministic` and `HumanPromoted`.
    /// - `Quarantined`: accepts everything (it is a holding pen).
    pub fn accepts(&self, derivation: DerivationClass) -> bool {
        match self {
            StorageLane::Proposed => true,
            StorageLane::Quarantined => true,
            StorageLane::Verified => matches!(
                derivation,
                DerivationClass::Deterministic | DerivationClass::HumanPromoted
            ),
        }
    }
}

impl fmt::Display for StorageLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageLane::Proposed => f.write_str("Proposed"),
            StorageLane::Verified => f.write_str("Verified"),
            StorageLane::Quarantined => f.write_str("Quarantined"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_routes_to_verified() {
        assert_eq!(
            StorageLane::required_lane(DerivationClass::Deterministic),
            StorageLane::Verified
        );
    }

    #[test]
    fn human_promoted_routes_to_verified() {
        assert_eq!(
            StorageLane::required_lane(DerivationClass::HumanPromoted),
            StorageLane::Verified
        );
    }

    #[test]
    fn ai_derived_routes_to_proposed() {
        assert_eq!(
            StorageLane::required_lane(DerivationClass::AIDerived),
            StorageLane::Proposed
        );
    }

    #[test]
    fn mixed_routes_to_proposed() {
        assert_eq!(
            StorageLane::required_lane(DerivationClass::Mixed),
            StorageLane::Proposed
        );
    }

    #[test]
    fn opaque_external_routes_to_quarantined() {
        assert_eq!(
            StorageLane::required_lane(DerivationClass::OpaqueExternal),
            StorageLane::Quarantined
        );
    }

    #[test]
    fn proposed_accepts_all() {
        let lane = StorageLane::Proposed;
        assert!(lane.accepts(DerivationClass::Deterministic));
        assert!(lane.accepts(DerivationClass::AIDerived));
        assert!(lane.accepts(DerivationClass::Mixed));
        assert!(lane.accepts(DerivationClass::HumanPromoted));
        assert!(lane.accepts(DerivationClass::OpaqueExternal));
    }

    #[test]
    fn verified_rejects_ai_derived() {
        assert!(!StorageLane::Verified.accepts(DerivationClass::AIDerived));
    }

    #[test]
    fn verified_rejects_mixed() {
        assert!(!StorageLane::Verified.accepts(DerivationClass::Mixed));
    }

    #[test]
    fn verified_rejects_opaque_external() {
        assert!(!StorageLane::Verified.accepts(DerivationClass::OpaqueExternal));
    }

    #[test]
    fn verified_accepts_deterministic_and_human_promoted() {
        assert!(StorageLane::Verified.accepts(DerivationClass::Deterministic));
        assert!(StorageLane::Verified.accepts(DerivationClass::HumanPromoted));
    }

    #[test]
    fn quarantined_accepts_all() {
        let lane = StorageLane::Quarantined;
        assert!(lane.accepts(DerivationClass::Deterministic));
        assert!(lane.accepts(DerivationClass::AIDerived));
        assert!(lane.accepts(DerivationClass::Mixed));
        assert!(lane.accepts(DerivationClass::HumanPromoted));
        assert!(lane.accepts(DerivationClass::OpaqueExternal));
    }

    #[test]
    fn display_impl() {
        assert_eq!(StorageLane::Proposed.to_string(), "Proposed");
        assert_eq!(StorageLane::Verified.to_string(), "Verified");
        assert_eq!(StorageLane::Quarantined.to_string(), "Quarantined");
    }

    #[test]
    fn required_lane_is_always_accepted() {
        // Invariant: the lane a derivation routes to must accept that derivation.
        let all = [
            DerivationClass::Deterministic,
            DerivationClass::AIDerived,
            DerivationClass::Mixed,
            DerivationClass::HumanPromoted,
            DerivationClass::OpaqueExternal,
        ];
        for d in all {
            let lane = StorageLane::required_lane(d);
            assert!(
                lane.accepts(d),
                "required_lane({d:?}) = {lane}, but {lane} does not accept {d:?}"
            );
        }
    }
}
