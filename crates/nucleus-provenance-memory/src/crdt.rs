//! [`ProvenanceMemorySet`] — a recompute-gated, conflict-free replicated set of
//! memory records, keyed by [`ContentHash`].
//!
//! Ported in structure from the proven `nucleus_creditworthiness::ReputationSet`:
//! the same join-semilattice discipline (idempotent / commutative / associative)
//! and the same principle — **trust is the recompute, never set membership**. A
//! record joins only through [`ProvenanceMemorySet::verified_admit`], which
//! re-derives it from its cited parents via [`verify_admission`]; a forged record
//! (one whose value or label does not follow from its lineage) never joins.
//!
//! Difference from `ReputationSet`: records carry an IFC [`MemoryLabel`] that is
//! *excluded* from the content hash, so two correctly-admitted replicas of the
//! same content always carry the same (recomputed) label. Should two labels ever
//! diverge for one content hash, [`ProvenanceMemorySet::join`] resolves
//! **fail-closed** to the most-restrictive label (conf-join, integ-meet,
//! derivation-join) — a deterministic, convergent lattice merge — rather than
//! converging on the more-trusting of the two.

use std::collections::BTreeMap;

use portcullis_core::memory::MemoryLabel;

use crate::hash::ContentHash;
use crate::recompute::{
    conf_join, integ_meet, verify_admission, RecomputeMemory, RecomputeVerdict,
};
use crate::record::MemoryRecord;

/// Fail-closed label merge for the same content under divergent labels: the
/// most-restrictive label — confidentiality joined up, integrity met down,
/// derivation class joined (so an AIDerived/OpaqueExternal ancestry is never
/// laundered away). This is a proper lattice op, so the set stays a
/// join-semilattice.
fn most_restrictive(a: MemoryLabel, b: MemoryLabel) -> MemoryLabel {
    MemoryLabel::from_levels_with_derivation(
        conf_join(a.conf_level(), b.conf_level()),
        integ_meet(a.integ_level(), b.integ_level()),
        a.derivation.join(b.derivation),
    )
}

/// A conflict-free replicated set of recompute-verified [`MemoryRecord`]s, keyed
/// by [`ContentHash`]. Replicas that admitted the same records converge on the
/// same set regardless of gossip order or duplication.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProvenanceMemorySet {
    /// Records keyed by content hash. `BTreeMap` gives a canonical, order-free
    /// layout (structural equality is order-independent) and a stable fold order.
    records: BTreeMap<ContentHash, MemoryRecord>,
}

impl ProvenanceMemorySet {
    /// The empty set — the join-semilattice identity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct admitted records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Whether a record with this content hash is admitted.
    pub fn contains(&self, hash: &ContentHash) -> bool {
        self.records.contains_key(hash)
    }

    /// Look up an admitted record by content hash.
    pub fn get(&self, hash: &ContentHash) -> Option<&MemoryRecord> {
        self.records.get(hash)
    }

    /// Iterate admitted records in canonical (content-hash-sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = &MemoryRecord> {
        self.records.values()
    }

    /// Merge two sets — the **join-semilattice** operation: idempotent,
    /// commutative, associative. On a shared content hash with divergent labels,
    /// resolves fail-closed to [`most_restrictive`].
    pub fn join(&self, other: &Self) -> Self {
        let mut merged = self.records.clone();
        for (hash, incoming) in &other.records {
            match merged.get(hash) {
                Some(existing) if existing == incoming => { /* idempotent */ }
                Some(existing) => {
                    let label = most_restrictive(existing.label.clone(), incoming.label.clone());
                    // value/schema/derivation are identical (same content hash);
                    // only the label could differ, and we take the safe one.
                    let mut resolved = incoming.clone();
                    resolved.label = label;
                    merged.insert(*hash, resolved);
                }
                None => {
                    merged.insert(*hash, incoming.clone());
                }
            }
        }
        Self { records: merged }
    }

    /// **Fail-closed admission gate.** Re-derive `record` from its cited parents
    /// (which must already be in the set) via [`verify_admission`] and admit it
    /// ONLY on [`RecomputeVerdict::Match`]. Returns the verdict either way; the
    /// set is unchanged unless the verdict is `Match`.
    ///
    /// A missing cited parent yields [`RecomputeVerdict::Invalid`] — lineage must
    /// be present to be verified.
    pub fn verified_admit(
        &mut self,
        record: &MemoryRecord,
        registry: &dyn RecomputeMemory,
    ) -> RecomputeVerdict {
        let verdict = {
            let inputs = record.derivation.input_record_hashes();
            let mut parents = Vec::with_capacity(inputs.len());
            for h in &inputs {
                match self.records.get(h) {
                    Some(p) => parents.push(p),
                    None => {
                        return RecomputeVerdict::Invalid {
                            reason: format!("missing cited parent {}", h.to_hex()),
                        }
                    }
                }
            }
            verify_admission(record, &parents, registry)
        };
        if verdict.is_match() {
            self.insert_verified(record.clone());
        }
        verdict
    }

    /// Insert an already-verified record, keyed by content hash. Idempotent;
    /// fail-closed (most-restrictive) on label divergence for identical content.
    fn insert_verified(&mut self, record: MemoryRecord) {
        let key = record.content_hash();
        match self.records.get(&key) {
            Some(existing) if *existing == record => { /* idempotent */ }
            Some(existing) => {
                let label = most_restrictive(existing.label.clone(), record.label.clone());
                let mut resolved = record;
                resolved.label = label;
                self.records.insert(key, resolved);
            }
            None => {
                self.records.insert(key, record);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::{MemoryDerivation, TransformId};
    use nucleus_lineage::SourceClass;
    use portcullis_core::memory::SchemaType;
    use portcullis_core::{ConfLevel, DerivationClass, IntegLevel};

    fn registry() -> crate::recompute::TransformRegistry {
        let mut r = crate::recompute::TransformRegistry::new();
        r.register(TransformId::new("concat"), |inputs| {
            Ok(inputs
                .iter()
                .map(|i| i.value.as_str())
                .collect::<Vec<_>>()
                .join(""))
        });
        r
    }

    fn raw(value: &str, sc: SourceClass) -> MemoryRecord {
        let d = MemoryDerivation::RawIngest {
            source_class: sc,
            source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
        };
        let label = crate::recompute::derive_label(&d, &[]);
        MemoryRecord::new(value, SchemaType::String, label, d)
    }

    #[test]
    fn verified_admit_accepts_valid_and_dedups() {
        let mut set = ProvenanceMemorySet::new();
        let r = raw("hello", SourceClass::LocalFile);
        assert!(set.verified_admit(&r, &registry()).is_match());
        assert_eq!(set.len(), 1);
        // Idempotent: admitting again is a no-op.
        assert!(set.verified_admit(&r, &registry()).is_match());
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn verified_admit_rejects_missing_parent() {
        let mut set = ProvenanceMemorySet::new();
        let a = raw("foo", SourceClass::LocalFile);
        // Deterministic record cites `a` but `a` was never admitted.
        let d = MemoryDerivation::Deterministic {
            input_hashes: vec![a.content_hash()],
            transform: TransformId::new("concat"),
        };
        let label = crate::recompute::derive_label(&d, &[&a]);
        let rec = MemoryRecord::new("foo", SchemaType::String, label, d);
        assert!(matches!(
            set.verified_admit(&rec, &registry()),
            RecomputeVerdict::Invalid { .. }
        ));
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn verified_admit_rejects_forged_derived_value() {
        let mut set = ProvenanceMemorySet::new();
        let a = raw("foo", SourceClass::LocalFile);
        let b = raw("bar", SourceClass::LocalFile);
        set.verified_admit(&a, &registry());
        set.verified_admit(&b, &registry());
        let d = MemoryDerivation::Deterministic {
            input_hashes: vec![a.content_hash(), b.content_hash()],
            transform: TransformId::new("concat"),
        };
        let label = crate::recompute::derive_label(&d, &[&a, &b]);
        let forged = MemoryRecord::new("evil", SchemaType::String, label, d);
        assert!(matches!(
            set.verified_admit(&forged, &registry()),
            RecomputeVerdict::Mismatch { .. }
        ));
        assert_eq!(set.len(), 2); // forged record NOT admitted
    }

    #[test]
    fn join_is_idempotent_commutative_associative() {
        let mut a = ProvenanceMemorySet::new();
        a.verified_admit(&raw("a", SourceClass::LocalFile), &registry());
        let mut b = ProvenanceMemorySet::new();
        b.verified_admit(&raw("b", SourceClass::LocalFile), &registry());
        let mut c = ProvenanceMemorySet::new();
        c.verified_admit(&raw("c", SourceClass::LocalFile), &registry());

        // idempotent
        assert_eq!(a.join(&a), a);
        // commutative
        assert_eq!(a.join(&b), b.join(&a));
        // associative
        assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
        // duplication-insensitive: a ⊔ b ⊔ a == a ⊔ b
        assert_eq!(a.join(&b).join(&a), a.join(&b));
    }

    #[test]
    fn join_resolves_divergent_label_fail_closed() {
        // Two replicas hold the same content with different (hand-forced) labels.
        // The join must take the most-restrictive (adversarial integrity wins).
        let d = MemoryDerivation::RawIngest {
            source_class: SourceClass::Web,
            source_hash: ContentHash::of_canonical_bytes(b"s"),
        };
        let trusting = MemoryRecord::new(
            "v",
            SchemaType::String,
            MemoryLabel::from_levels_with_derivation(
                ConfLevel::Public,
                IntegLevel::Trusted,
                DerivationClass::Deterministic,
            ),
            d.clone(),
        );
        let restrictive = MemoryRecord::new(
            "v",
            SchemaType::String,
            MemoryLabel::from_levels_with_derivation(
                ConfLevel::Secret,
                IntegLevel::Adversarial,
                DerivationClass::OpaqueExternal,
            ),
            d,
        );
        assert_eq!(trusting.content_hash(), restrictive.content_hash());

        let mut s1 = ProvenanceMemorySet::new();
        s1.insert_verified(trusting);
        let mut s2 = ProvenanceMemorySet::new();
        s2.insert_verified(restrictive);

        let merged = s1.join(&s2);
        let rec = merged
            .get(&merged.iter().next().unwrap().content_hash())
            .unwrap();
        assert_eq!(rec.label.integ_level(), IntegLevel::Adversarial);
        assert_eq!(rec.label.conf_level(), ConfLevel::Secret);
        assert_eq!(rec.label.derivation, DerivationClass::OpaqueExternal);
        // and commutative even under divergence
        assert_eq!(s1.join(&s2), s2.join(&s1));
    }
}
