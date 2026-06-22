//! Projection from a [`MemoryRecord`]'s `MemoryLabel` to the runtime
//! [`IFCLabel`] consumed by the live flow tracker.
//!
//! A recalled record must enter the flow graph carrying ITS OWN label, not the
//! fixed `intrinsic_label(MemoryRead)` — otherwise an adversarial record would be
//! laundered to the benign `memory_entry` label. Pair this with
//! `FlowTracker::observe_with_label` so the recalled label drives the sink
//! decision: a `MayNotAuthorize`/Adversarial record taints the session and is
//! blocked at the egress gate; a `declassify`-promoted (Untrusted/MayInform)
//! record is not tainted and may inform an action.
//!
//! [`MemoryRecord`]: crate::record::MemoryRecord

use portcullis_core::memory::{MemoryAuthority, MemoryLabel};
use portcullis_core::{AuthorityLevel, Freshness, IFCLabel, ProvenanceSet};

/// Project a memory record's [`MemoryLabel`] into a runtime [`IFCLabel`].
///
/// - confidentiality / integrity / derivation flow straight through;
/// - authority is derived from integrity exactly as the record's own
///   [`MemoryRecord::authority`](crate::record::MemoryRecord::authority):
///   `MayInform → Informational`, `MayNotAuthorize → NoAuthority`;
/// - provenance is tagged [`ProvenanceSet::MEMORY`];
/// - freshness is stamped at `now` with no TTL (the record's own integrity, not
///   staleness, is the control here).
pub fn memory_ifc_label(label: &MemoryLabel, now: u64) -> IFCLabel {
    let authority = match MemoryAuthority::from_integrity(label.integ_level()) {
        MemoryAuthority::MayInform => AuthorityLevel::Informational,
        MemoryAuthority::MayNotAuthorize => AuthorityLevel::NoAuthority,
    };
    IFCLabel {
        confidentiality: label.conf_level(),
        integrity: label.integ_level(),
        provenance: ProvenanceSet::MEMORY,
        freshness: Freshness {
            observed_at: now,
            ttl_secs: 0,
        },
        authority,
        derivation: label.derivation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::{ConfLevel, DerivationClass, IntegLevel};

    #[test]
    fn adversarial_record_projects_to_tainting_label() {
        // A poisoned web-ingest record: Adversarial integrity, OpaqueExternal.
        let lbl = MemoryLabel::from_levels_with_derivation(
            ConfLevel::Public,
            IntegLevel::Adversarial,
            DerivationClass::OpaqueExternal,
        );
        let ifc = memory_ifc_label(&lbl, 0);
        assert_eq!(ifc.integrity, IntegLevel::Adversarial);
        assert_eq!(ifc.authority, AuthorityLevel::NoAuthority);
        assert_eq!(ifc.derivation, DerivationClass::OpaqueExternal);
        assert_eq!(ifc.provenance, ProvenanceSet::MEMORY);
    }

    #[test]
    fn declassified_record_projects_to_informing_label() {
        // After declassify: integrity raised to Untrusted, derivation carries
        // the human-promotion (not Deterministic).
        let lbl = MemoryLabel::from_levels_with_derivation(
            ConfLevel::Public,
            IntegLevel::Untrusted,
            DerivationClass::HumanPromoted,
        );
        let ifc = memory_ifc_label(&lbl, 0);
        assert_eq!(ifc.integrity, IntegLevel::Untrusted);
        assert_eq!(ifc.authority, AuthorityLevel::Informational);
    }

    #[test]
    fn projection_preserves_confidentiality() {
        let lbl = MemoryLabel::from_levels_with_derivation(
            ConfLevel::Secret,
            IntegLevel::Trusted,
            DerivationClass::Deterministic,
        );
        let ifc = memory_ifc_label(&lbl, 0);
        assert_eq!(ifc.confidentiality, ConfLevel::Secret);
        assert_eq!(ifc.authority, AuthorityLevel::Informational);
    }
}
