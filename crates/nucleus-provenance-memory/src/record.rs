//! [`MemoryRecord`] — the one content-addressed, taint-labeled, lineage-anchored
//! memory object, and its [`MemoryDerivation`] (how it was produced).

use nucleus_lineage::SourceClass;
use portcullis_core::memory::{MemoryAuthority, MemoryLabel, SchemaType};
use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;

/// Names a registered, deterministic transform (the only kind whose output is
/// recomputable). Resolved against a [`crate::recompute::TransformRegistry`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TransformId(pub String);

impl TransformId {
    /// Construct from any string-like name.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
}

/// How a record's value was produced — the provenance claim the admission gate
/// re-derives against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum MemoryDerivation {
    /// Ingested verbatim from an external source. No derivation to recompute;
    /// the label is fixed by the source's trust class (Web/RagIndex/Memory are
    /// adversarial). `source_hash` pins exactly what was ingested.
    RawIngest {
        /// Trust class of the origin.
        source_class: SourceClass,
        /// Content hash of the ingested bytes.
        source_hash: ContentHash,
    },
    /// Produced by a **deterministic** transform over cited source records. This
    /// is the recomputable class: the admission gate re-runs `transform` over the
    /// `input_hashes` records and requires the result to hash-match.
    Deterministic {
        /// Content hashes of the cited source records (must already be admitted).
        input_hashes: Vec<ContentHash>,
        /// The registered transform that maps the inputs to this value.
        transform: TransformId,
    },
    /// Produced by a non-deterministic LLM step. **Not recomputable** — quarantined
    /// as `AIDerived` / `MayNotAuthorize`; can never reach `MayInform` without an
    /// explicit `HumanPromoted` declassify witness.
    OpaqueLlm {
        /// Content hashes of the records fed to the model (context lineage).
        input_hashes: Vec<ContentHash>,
        /// Opaque model identifier (for audit, not trust).
        model_tag: String,
    },
}

impl MemoryDerivation {
    /// The cited parent hashes (for the lineage DAG), regardless of kind. For
    /// [`MemoryDerivation::RawIngest`] this is the hash of the ingested bytes —
    /// a leaf source, NOT an admitted record (see [`Self::input_record_hashes`]).
    pub fn parent_hashes(&self) -> Vec<ContentHash> {
        match self {
            MemoryDerivation::RawIngest { source_hash, .. } => vec![*source_hash],
            MemoryDerivation::Deterministic { input_hashes, .. }
            | MemoryDerivation::OpaqueLlm { input_hashes, .. } => input_hashes.clone(),
        }
    }

    /// The hashes of cited **admitted records** this derivation depends on (which
    /// the CRDT must already hold to recompute). Empty for
    /// [`MemoryDerivation::RawIngest`] — its `source_hash` is raw ingested bytes,
    /// not a [`MemoryRecord`].
    pub fn input_record_hashes(&self) -> Vec<ContentHash> {
        match self {
            MemoryDerivation::RawIngest { .. } => Vec::new(),
            MemoryDerivation::Deterministic { input_hashes, .. }
            | MemoryDerivation::OpaqueLlm { input_hashes, .. } => input_hashes.clone(),
        }
    }
}

/// The identity-bearing fields of a record — everything the [`ContentHash`]
/// commits to. **Excludes** `label`/`authority`: those are *derived* from the
/// derivation + parents and *validated* on admission, so a mislabeled record with
/// otherwise-identical content collides on the same key and is caught fail-closed
/// by [`crate::ProvenanceMemorySet`] rather than silently coexisting.
#[derive(Serialize)]
struct RecordIdentity<'a> {
    value: &'a str,
    schema: &'a SchemaType,
    derivation: &'a MemoryDerivation,
}

/// A provenance-backed, taint-labeled memory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRecord {
    /// The stored value.
    pub value: String,
    /// Value schema (string / json / binary).
    pub schema: SchemaType,
    /// IFC label: confidentiality × integrity × derivation class. Derived from
    /// the derivation + parents by the admission gate and validated to match.
    pub label: MemoryLabel,
    /// How this value was produced — the recompute claim.
    pub derivation: MemoryDerivation,
}

impl MemoryRecord {
    /// Construct a record with an explicit (claimed) label. The label is only
    /// *trusted* once [`crate::ProvenanceMemorySet::verified_admit`] confirms it
    /// equals the label recomputed from the derivation + parents.
    pub fn new(
        value: impl Into<String>,
        schema: SchemaType,
        label: MemoryLabel,
        derivation: MemoryDerivation,
    ) -> Self {
        Self {
            value: value.into(),
            schema,
            label,
            derivation,
        }
    }

    /// Canonical identity bytes: domain-tagged serialization of the
    /// identity-bearing fields (value, schema, derivation). Label is excluded
    /// (see [`RecordIdentity`]).
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let id = RecordIdentity {
            value: &self.value,
            schema: &self.schema,
            derivation: &self.derivation,
        };
        // Infallible for these concrete, map-free types.
        serde_json::to_vec(&id).expect("record identity serialization is infallible")
    }

    /// The content address of this record (over its identity bytes).
    pub fn content_hash(&self) -> ContentHash {
        ContentHash::of_canonical_bytes(&self.canonical_bytes())
    }

    /// The authority of this record, derived from its integrity level. Not
    /// stored: `Adversarial` ⇒ `MayNotAuthorize`, otherwise `MayInform`.
    pub fn authority(&self) -> MemoryAuthority {
        MemoryAuthority::from_integrity(self.label.integ_level())
    }

    /// The cited parent hashes (lineage DAG edges).
    pub fn parent_hashes(&self) -> Vec<ContentHash> {
        self.derivation.parent_hashes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::{ConfLevel, DerivationClass, IntegLevel};

    fn lbl(c: ConfLevel, i: IntegLevel, d: DerivationClass) -> MemoryLabel {
        MemoryLabel::from_levels_with_derivation(c, i, d)
    }

    #[test]
    fn content_hash_excludes_label() {
        // Same value+schema+derivation but different labels ⇒ SAME content hash.
        // (The CRDT then catches the label divergence fail-closed.)
        let deriv = MemoryDerivation::RawIngest {
            source_class: SourceClass::Web,
            source_hash: ContentHash::of_canonical_bytes(b"src"),
        };
        let a = MemoryRecord::new(
            "v",
            SchemaType::String,
            lbl(
                ConfLevel::Public,
                IntegLevel::Adversarial,
                DerivationClass::OpaqueExternal,
            ),
            deriv.clone(),
        );
        let b = MemoryRecord::new(
            "v",
            SchemaType::String,
            lbl(
                ConfLevel::Secret,
                IntegLevel::Trusted,
                DerivationClass::Deterministic,
            ),
            deriv,
        );
        assert_eq!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn content_hash_tracks_value_and_derivation() {
        let d = MemoryDerivation::RawIngest {
            source_class: SourceClass::Web,
            source_hash: ContentHash::of_canonical_bytes(b"s"),
        };
        let r1 = MemoryRecord::new(
            "a",
            SchemaType::String,
            lbl(
                ConfLevel::Public,
                IntegLevel::Untrusted,
                DerivationClass::Deterministic,
            ),
            d.clone(),
        );
        let r2 = MemoryRecord::new(
            "b",
            SchemaType::String,
            lbl(
                ConfLevel::Public,
                IntegLevel::Untrusted,
                DerivationClass::Deterministic,
            ),
            d,
        );
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn authority_follows_integrity() {
        let adversarial = MemoryRecord::new(
            "x",
            SchemaType::String,
            lbl(
                ConfLevel::Public,
                IntegLevel::Adversarial,
                DerivationClass::OpaqueExternal,
            ),
            MemoryDerivation::RawIngest {
                source_class: SourceClass::Web,
                source_hash: ContentHash::of_canonical_bytes(b"s"),
            },
        );
        assert_eq!(adversarial.authority(), MemoryAuthority::MayNotAuthorize);
    }
}
