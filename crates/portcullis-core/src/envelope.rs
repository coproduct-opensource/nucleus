//! Canonical labeled data containers for the DPI dual-lane storage model.
//!
//! [`FieldEnvelope`] wraps a single datum with its IFC label, derivation class,
//! effect classification, and causal lineage. [`RowEnvelope`] aggregates fields
//! into a labeled row where the row-level label and derivation class are the
//! automatic join (least upper bound) of all constituent fields.
//!
//! These envelopes are the serialization boundary: data leaving the flow graph
//! carries its provenance metadata. Downstream consumers can inspect the
//! envelope to determine verification requirements without re-deriving lineage.
//!
//! # Invariant
//!
//! For every `RowEnvelope`:
//! ```text
//! row_label >= field_label   ∀ field ∈ fields
//! row_derivation >= field_derivation   ∀ field ∈ fields
//! ```
//! where `>=` is the lattice ordering (least upper bound).

use std::collections::BTreeMap;

use crate::IFCLabel;
use crate::effect::{DerivationClass, EffectKind};
use crate::flow::NodeId;

// ═══════════════════════════════════════════════════════════════════════════
// DerivationClass lattice ordering
// ═══════════════════════════════════════════════════════════════════════════

/// Lattice rank for [`DerivationClass`].
///
/// Higher rank = higher verification burden. The ordering reflects how much
/// trust infrastructure is needed to verify data of that class:
///
/// ```text
/// Deterministic(0) ≤ Replayed(1) ≤ External(2) ≤ Human(3) ≤ Generative(4)
/// ```
///
/// - **Deterministic**: re-execute to verify (cheapest).
/// - **Replayed**: replay log exists, but must be trusted.
/// - **External**: foreign provenance chain, requires cross-system trust.
/// - **Human**: attestation required — a human claimed this.
/// - **Generative**: witness bundle required — non-reproducible model output.
const fn derivation_rank(d: DerivationClass) -> u8 {
    match d {
        DerivationClass::Deterministic => 0,
        DerivationClass::Replayed => 1,
        DerivationClass::External => 2,
        DerivationClass::Human => 3,
        DerivationClass::Generative => 4,
    }
}

/// Least upper bound of two derivation classes.
///
/// Returns the class with the higher verification burden.
pub const fn derivation_join(a: DerivationClass, b: DerivationClass) -> DerivationClass {
    if derivation_rank(a) >= derivation_rank(b) {
        a
    } else {
        b
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// SourceRef — provenance pointer to an upstream data source
// ═══════════════════════════════════════════════════════════════════════════

/// Reference to an upstream data source that contributed to this field.
///
/// `content_hash` is the SHA-256 of the source content at fetch time,
/// enabling downstream consumers to verify that the source has not changed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SourceRef {
    /// Classification of the source (e.g. "api", "database", "file", "web").
    pub source_class: String,
    /// SHA-256 hash of the source content at fetch time.
    pub content_hash: [u8; 32],
    /// Unix timestamp (seconds) when the source was fetched.
    pub fetched_at: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// TransformRef — pointer to a registered transform that produced this field
// ═══════════════════════════════════════════════════════════════════════════

/// Reference to a deterministic or registered transform that produced
/// this field's value from one or more inputs.
///
/// For deterministic transforms, re-executing the transform on the
/// `input_hashes` should reproduce `output_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TransformRef {
    /// Unique identifier for the transform (e.g. "json_parse", "sha256").
    pub transform_id: String,
    /// Version of the transform implementation.
    pub version: String,
    /// SHA-256 hashes of each input to the transform.
    pub input_hashes: Vec<[u8; 32]>,
    /// SHA-256 hash of the transform output.
    pub output_hash: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════
// FieldEnvelope — a single labeled datum
// ═══════════════════════════════════════════════════════════════════════════

/// A single datum wrapped with its IFC label, derivation metadata, and
/// causal lineage.
///
/// This is the atomic unit of the DPI storage model. Every piece of data
/// that flows through the system is wrapped in a `FieldEnvelope` before
/// storage or transmission.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FieldEnvelope {
    /// The raw value bytes. Interpretation depends on `schema_type`.
    pub value_bytes: Vec<u8>,

    /// Schema type descriptor (e.g. "string", "json", "protobuf:MyMessage").
    pub schema_type: String,

    /// IFC label — confidentiality, integrity, provenance, freshness, authority.
    pub label: IFCLabel,

    /// Coarse derivation class (Deterministic, Generative, Human, etc.).
    pub derivation_class: DerivationClass,

    /// Fine-grained effect classification of the computation step that
    /// produced this value.
    pub effect_kind: EffectKind,

    /// Flow graph node that produced this value.
    pub source_node_id: NodeId,

    /// Flow graph nodes that are causal parents of this value.
    pub causal_parents: Vec<NodeId>,

    /// References to upstream data sources.
    pub source_refs: Vec<SourceRef>,

    /// References to transforms applied to produce this value.
    pub transform_refs: Vec<TransformRef>,

    /// Optional witness bundle ID for generative derivations.
    /// When `derivation_class == Generative`, this should be `Some(...)`.
    pub witness_bundle_id: Option<String>,

    /// Principal who promoted this field (e.g. from proposed to verified).
    pub promoted_by: Option<String>,

    /// Reason for promotion (human attestation text).
    pub promoted_reason: Option<String>,

    /// Unix timestamp (seconds) when this envelope was created.
    pub created_at: u64,

    /// SHA-256 hash of `value_bytes`. Computed via [`Self::compute_content_hash`].
    pub content_hash: [u8; 32],
}

impl FieldEnvelope {
    /// Compute the SHA-256 content hash of the value bytes.
    ///
    /// This is a pure function: `SHA-256(self.value_bytes)`.
    /// Callers should verify `self.content_hash == self.compute_content_hash()`
    /// when receiving envelopes from untrusted sources.
    pub fn compute_content_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.value_bytes);
        hasher.finalize().into()
    }

    /// Verify that the stored content hash matches the value bytes.
    pub fn verify_content_hash(&self) -> bool {
        self.content_hash == self.compute_content_hash()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// RowEnvelope — a labeled row of fields
// ═══════════════════════════════════════════════════════════════════════════

/// A row of labeled fields with automatic label and derivation aggregation.
///
/// The `row_label` is the join (least upper bound) of all field labels.
/// The `row_derivation_class` is the join (highest verification burden)
/// of all field derivation classes.
///
/// # Invariant
///
/// ```text
/// row_label == ⊔ { f.label | f ∈ fields }
/// row_derivation_class == ⊔ { f.derivation_class | f ∈ fields }
/// ```
///
/// Use [`RowEnvelope::new`] to construct with automatic LUB computation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RowEnvelope {
    /// Unique row identifier.
    pub row_id: String,

    /// Table or collection name this row belongs to.
    pub table_name: String,

    /// The fields in this row, keyed by field name.
    pub fields: BTreeMap<String, FieldEnvelope>,

    /// IFC label for the entire row — join of all field labels.
    pub row_label: IFCLabel,

    /// Derivation class for the entire row — LUB of all field classes.
    pub row_derivation_class: DerivationClass,

    /// Optional receipt ID linking to a `VerdictReceipt` in the receipt chain.
    pub receipt_id: Option<String>,

    /// Policy version that was in effect when this row was created.
    pub policy_version: String,

    /// Unix timestamp (seconds) when this row envelope was created.
    pub created_at: u64,
}

impl RowEnvelope {
    /// Construct a new `RowEnvelope` with automatically computed row-level
    /// label and derivation class from the constituent fields.
    ///
    /// If `fields` is empty, the row label defaults to [`IFCLabel::default()`]
    /// (minimum privilege) and derivation class to [`DerivationClass::Deterministic`]
    /// (minimum verification burden).
    pub fn new(
        row_id: String,
        table_name: String,
        fields: BTreeMap<String, FieldEnvelope>,
        receipt_id: Option<String>,
        policy_version: String,
        created_at: u64,
    ) -> Self {
        let (row_label, row_derivation_class) = Self::compute_row_label_and_derivation(&fields);
        Self {
            row_id,
            table_name,
            fields,
            row_label,
            row_derivation_class,
            receipt_id,
            policy_version,
            created_at,
        }
    }

    /// Compute the row-level label and derivation class from field envelopes.
    ///
    /// - Row label = join (LUB) of all field labels.
    /// - Row derivation = join (highest verification burden) of all field classes.
    pub fn compute_row_label_and_derivation(
        fields: &BTreeMap<String, FieldEnvelope>,
    ) -> (IFCLabel, DerivationClass) {
        let mut label = IFCLabel::default();
        let mut derivation = DerivationClass::Deterministic;

        for field in fields.values() {
            label = label.join(field.label);
            derivation = derivation_join(derivation, field.derivation_class);
        }

        (label, derivation)
    }

    /// Re-derive the row-level derivation class from the current fields.
    ///
    /// Returns the LUB of all field derivation classes.
    pub fn compute_derivation_class(&self) -> DerivationClass {
        let mut derivation = DerivationClass::Deterministic;
        for field in self.fields.values() {
            derivation = derivation_join(derivation, field.derivation_class);
        }
        derivation
    }

    /// Verify that the row-level label and derivation class are consistent
    /// with the constituent fields.
    pub fn verify_invariant(&self) -> bool {
        let (expected_label, expected_derivation) =
            Self::compute_row_label_and_derivation(&self.fields);
        self.row_label == expected_label && self.row_derivation_class == expected_derivation
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorityLevel, ConfLevel, IntegLevel};

    /// Helper: build a minimal FieldEnvelope with the given value and derivation.
    fn make_field(
        value: &[u8],
        derivation_class: DerivationClass,
        label: IFCLabel,
    ) -> FieldEnvelope {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(value);
        let content_hash: [u8; 32] = hasher.finalize().into();

        FieldEnvelope {
            value_bytes: value.to_vec(),
            schema_type: "bytes".to_string(),
            label,
            derivation_class,
            effect_kind: EffectKind::PureTransform,
            source_node_id: 0,
            causal_parents: vec![],
            source_refs: vec![],
            transform_refs: vec![],
            witness_bundle_id: None,
            promoted_by: None,
            promoted_reason: None,
            created_at: 1000,
            content_hash,
        }
    }

    #[test]
    fn content_hash_roundtrip() {
        let field = make_field(
            b"hello world",
            DerivationClass::Deterministic,
            IFCLabel::default(),
        );
        assert!(field.verify_content_hash());
    }

    #[test]
    fn content_hash_detects_tampering() {
        let mut field = make_field(
            b"hello world",
            DerivationClass::Deterministic,
            IFCLabel::default(),
        );
        field.value_bytes = b"tampered".to_vec();
        assert!(!field.verify_content_hash());
    }

    #[test]
    fn empty_row_defaults() {
        let row = RowEnvelope::new(
            "row-1".into(),
            "test_table".into(),
            BTreeMap::new(),
            None,
            "v1".into(),
            1000,
        );
        assert_eq!(row.row_label, IFCLabel::default());
        assert_eq!(row.row_derivation_class, DerivationClass::Deterministic);
        assert!(row.verify_invariant());
    }

    #[test]
    fn row_lub_single_field() {
        let label = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            ..Default::default()
        };
        let field = make_field(b"data", DerivationClass::Generative, label);

        let mut fields = BTreeMap::new();
        fields.insert("f1".into(), field);

        let row = RowEnvelope::new("row-1".into(), "t".into(), fields, None, "v1".into(), 1000);
        assert_eq!(row.row_derivation_class, DerivationClass::Generative);
        assert_eq!(row.row_label.confidentiality, ConfLevel::Internal);
        assert!(row.verify_invariant());
    }

    #[test]
    fn row_lub_multiple_fields() {
        let label_public = IFCLabel::default();
        let label_internal = IFCLabel {
            confidentiality: ConfLevel::Internal,
            integrity: IntegLevel::Trusted,
            authority: AuthorityLevel::Directive,
            ..Default::default()
        };

        let f1 = make_field(b"public", DerivationClass::Deterministic, label_public);
        let f2 = make_field(b"internal", DerivationClass::Human, label_internal);

        let mut fields = BTreeMap::new();
        fields.insert("public_field".into(), f1);
        fields.insert("internal_field".into(), f2);

        let row = RowEnvelope::new("row-2".into(), "t".into(), fields, None, "v1".into(), 2000);

        // Derivation LUB: Human > Deterministic → Human
        assert_eq!(row.row_derivation_class, DerivationClass::Human);

        // Confidentiality is covariant: max(Public, Internal) = Internal
        assert_eq!(row.row_label.confidentiality, ConfLevel::Internal);

        // Integrity is contravariant: min(Untrusted, Verified) = Untrusted
        assert_eq!(row.row_label.integrity, IntegLevel::Untrusted);

        // Authority is contravariant: min(NoAuthority, FullAuthority) = NoAuthority
        assert_eq!(row.row_label.authority, AuthorityLevel::NoAuthority);

        assert!(row.verify_invariant());
    }

    #[test]
    fn derivation_join_ordering() {
        // Deterministic is bottom
        assert_eq!(
            derivation_join(
                DerivationClass::Deterministic,
                DerivationClass::Deterministic
            ),
            DerivationClass::Deterministic
        );

        // Generative dominates everything
        assert_eq!(
            derivation_join(DerivationClass::Deterministic, DerivationClass::Generative),
            DerivationClass::Generative
        );
        assert_eq!(
            derivation_join(DerivationClass::Human, DerivationClass::Generative),
            DerivationClass::Generative
        );

        // Human > External > Replayed > Deterministic
        assert_eq!(
            derivation_join(DerivationClass::External, DerivationClass::Human),
            DerivationClass::Human
        );
        assert_eq!(
            derivation_join(DerivationClass::Replayed, DerivationClass::External),
            DerivationClass::External
        );
        assert_eq!(
            derivation_join(DerivationClass::Deterministic, DerivationClass::Replayed),
            DerivationClass::Replayed
        );
    }

    #[test]
    fn derivation_join_is_commutative() {
        let classes = [
            DerivationClass::Deterministic,
            DerivationClass::Replayed,
            DerivationClass::External,
            DerivationClass::Human,
            DerivationClass::Generative,
        ];
        for &a in &classes {
            for &b in &classes {
                assert_eq!(
                    derivation_join(a, b),
                    derivation_join(b, a),
                    "join({a:?}, {b:?}) should be commutative"
                );
            }
        }
    }

    #[test]
    fn derivation_join_is_associative() {
        let classes = [
            DerivationClass::Deterministic,
            DerivationClass::Replayed,
            DerivationClass::External,
            DerivationClass::Human,
            DerivationClass::Generative,
        ];
        for &a in &classes {
            for &b in &classes {
                for &c in &classes {
                    assert_eq!(
                        derivation_join(derivation_join(a, b), c),
                        derivation_join(a, derivation_join(b, c)),
                        "join is not associative for ({a:?}, {b:?}, {c:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn derivation_join_is_idempotent() {
        let classes = [
            DerivationClass::Deterministic,
            DerivationClass::Replayed,
            DerivationClass::External,
            DerivationClass::Human,
            DerivationClass::Generative,
        ];
        for &a in &classes {
            assert_eq!(
                derivation_join(a, a),
                a,
                "join({a:?}, {a:?}) should be idempotent"
            );
        }
    }

    #[test]
    fn source_ref_and_transform_ref() {
        let src = SourceRef {
            source_class: "api".to_string(),
            content_hash: [0xAA; 32],
            fetched_at: 1000,
        };
        let xform = TransformRef {
            transform_id: "json_parse".to_string(),
            version: "1.0.0".to_string(),
            input_hashes: vec![[0xAA; 32]],
            output_hash: [0xBB; 32],
        };

        let mut field = make_field(b"data", DerivationClass::Deterministic, IFCLabel::default());
        field.source_refs.push(src.clone());
        field.transform_refs.push(xform.clone());

        assert_eq!(field.source_refs.len(), 1);
        assert_eq!(field.source_refs[0].source_class, "api");
        assert_eq!(field.transform_refs.len(), 1);
        assert_eq!(field.transform_refs[0].transform_id, "json_parse");
    }

    #[test]
    fn generative_field_with_witness_bundle() {
        let label = IFCLabel {
            confidentiality: ConfLevel::Secret,
            integrity: IntegLevel::Untrusted,
            ..Default::default()
        };
        let mut field = make_field(b"model output", DerivationClass::Generative, label);
        field.effect_kind = EffectKind::LLMGenerate;
        field.witness_bundle_id = Some("wb-abc123".to_string());

        assert_eq!(field.derivation_class, DerivationClass::Generative);
        assert_eq!(field.witness_bundle_id.as_deref(), Some("wb-abc123"));
        assert!(field.verify_content_hash());
    }

    #[test]
    fn row_with_receipt_and_policy() {
        let field = make_field(b"v", DerivationClass::Deterministic, IFCLabel::default());
        let mut fields = BTreeMap::new();
        fields.insert("col".into(), field);

        let row = RowEnvelope::new(
            "row-99".into(),
            "audit_log".into(),
            fields,
            Some("receipt-abc".into()),
            "policy-v2.1".into(),
            5000,
        );

        assert_eq!(row.receipt_id.as_deref(), Some("receipt-abc"));
        assert_eq!(row.policy_version, "policy-v2.1");
        assert_eq!(row.created_at, 5000);
        assert!(row.verify_invariant());
    }
}
