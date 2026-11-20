//! [`MemoryRecord`] — the one content-addressed, taint-labeled, lineage-anchored
//! memory object, and its [`MemoryDerivation`] (how it was produced).

use nucleus_lineage::SourceClass;
use portcullis_core::ConfLevel;
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

/// What a record's writer had read when it wrote the record (Program C, C1).
///
/// A record's label used to be derived from its derivation alone, so every root was Public
/// whatever its writer's session had read: a session that read Secret data and then wrote a
/// literal it selected wrote a Public record. A stamped record's confidentiality is joined with
/// its writer's **floor** — the session's floating confidentiality (everything it HAS READ, a
/// ratchet, not its clearance), captured by the writer's mediator under the same lock that
/// decided the write. The workload never chooses it.
///
/// The stamp travels with the record: it is in every commit's head hash beside the label, and,
/// like the label, outside the content hash, so one value derived one way is one record however
/// it is stamped. Replay re-derives the label against the RECORDED floor, never a fresh session.
///
/// [`LabelStamp::Unstamped`] is not a floor of Public: it says the writer recorded nothing (a v1
/// record, a guest that predates the stamp, a migrated store), so its confidentiality is
/// unknown, and [`MemoryRecord::effective_confidentiality`] treats it as Secret. Its label is
/// still re-derived by the rule it was written under (derivation alone), so a journal written
/// before the stamp existed replays unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LabelStamp {
    /// The writer recorded no dependency context. Unknown, so Secret wherever it is delivered.
    Unstamped,
    /// The writer's session floor when it wrote: joined into the record's confidentiality.
    Stamped {
        /// The session's floating confidentiality at the write.
        writer_floor: ConfLevel,
    },
}

impl LabelStamp {
    /// What a record that carries no `stamp` field is: written before stamps existed, or by a
    /// writer that does not record them.
    pub const fn unstamped() -> Self {
        LabelStamp::Unstamped
    }

    /// Whether this is [`LabelStamp::Unstamped`] (the serialized form omits it, so an
    /// unstamped record encodes exactly as it did before stamps existed).
    pub const fn is_unstamped(&self) -> bool {
        matches!(self, LabelStamp::Unstamped)
    }

    /// The floor joined into a derived label's confidentiality at admission: the recorded
    /// writer floor, or Public for an unstamped record, whose label was derived from its
    /// derivation alone and is re-derived the same way.
    pub const fn admission_floor(&self) -> ConfLevel {
        match self {
            LabelStamp::Unstamped => ConfLevel::Public,
            LabelStamp::Stamped { writer_floor } => *writer_floor,
        }
    }

    /// The merge of two stamps on one content hash, fail closed: two floors join; an unstamped
    /// copy is unknown, so its merge with a stamped one is stamped Secret (never the stamped
    /// copy's lower floor, which would read an unknown record as known). A lattice join:
    /// idempotent, commutative, associative.
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (LabelStamp::Unstamped, LabelStamp::Unstamped) => LabelStamp::Unstamped,
            (LabelStamp::Stamped { writer_floor: a }, LabelStamp::Stamped { writer_floor: b }) => {
                LabelStamp::Stamped {
                    writer_floor: a.max(b),
                }
            }
            (LabelStamp::Unstamped, LabelStamp::Stamped { .. })
            | (LabelStamp::Stamped { .. }, LabelStamp::Unstamped) => LabelStamp::Stamped {
                writer_floor: ConfLevel::Secret,
            },
        }
    }
}

/// The identity-bearing fields of a record — everything the [`ContentHash`]
/// commits to. **Excludes** `label`/`stamp`/`authority`: those are *derived* from the
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
    /// What the writer had read (Program C, C1). Omitted from the encoding when unstamped, so
    /// a record written before stamps existed encodes, and hashes into its commit, unchanged.
    #[serde(
        default = "LabelStamp::unstamped",
        skip_serializing_if = "LabelStamp::is_unstamped"
    )]
    pub stamp: LabelStamp,
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
            stamp: LabelStamp::Unstamped,
        }
    }

    /// This record carrying `stamp`. The label is not changed: admission requires it to equal
    /// the derivation's label joined with the stamp's floor
    /// ([`crate::recompute::derive_label`]).
    pub fn with_stamp(mut self, stamp: LabelStamp) -> Self {
        self.stamp = stamp;
        self
    }

    /// The confidentiality this record is delivered and viewed at: its label's for a stamped
    /// record, and Secret for an unstamped one, whose writer recorded nothing of what it had
    /// read (unknown is the top, never the bottom).
    pub fn effective_confidentiality(&self) -> ConfLevel {
        match self.stamp {
            LabelStamp::Unstamped => ConfLevel::Secret,
            LabelStamp::Stamped { .. } => self.label.conf_level(),
        }
    }

    /// This record as a stamped receiver holds one whose dependencies are unknown (it, or a
    /// record it cites, is unstamped): stamped Secret, with its confidentiality Secret — what
    /// [`Self::effective_confidentiality`] says an unstamped record is — and its integrity and
    /// derivation class as stored. The content hash is unchanged, and the result re-derives
    /// under [`crate::recompute::verify_admission`] over parents held the same way (a Secret
    /// floor dominates every parent's confidentiality).
    pub fn held_secret(&self) -> Self {
        let mut held = self.clone();
        held.label = MemoryLabel::from_levels_with_derivation(
            ConfLevel::Secret,
            self.label.integ_level(),
            self.label.derivation,
        );
        held.stamp = LabelStamp::Stamped {
            writer_floor: ConfLevel::Secret,
        };
        held
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
