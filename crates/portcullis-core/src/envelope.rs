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
use std::fmt;

use crate::DerivationClass;
use crate::IFCLabel;
use crate::effect::EffectKind;
use crate::flow::NodeId;

// ═══════════════════════════════════════════════════════════════════════════
// EnvelopeError — verification failures for envelope invariants
// ═══════════════════════════════════════════════════════════════════════════

/// Errors arising from envelope invariant checks.
///
/// These are not construction errors — envelopes can always be created.
/// Instead, these signal that an envelope does not satisfy the requirements
/// for entering the **verified** storage lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// A non-deterministic derivation class requires a `witness_bundle_id`,
    /// but the field has `None`.
    MissingWitness {
        /// The derivation class that triggered the requirement.
        derivation: DerivationClass,
    },

    /// A `HumanPromoted` field requires `promoted_by` to be set.
    MissingPromoter {
        /// The derivation class (always `HumanPromoted`).
        derivation: DerivationClass,
    },

    /// One or more fields in a row are not verified-ready.
    FieldNotVerifiedReady {
        /// Field name that failed the check.
        field_name: String,
        /// The underlying error for that field.
        reason: Box<EnvelopeError>,
    },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::MissingWitness { derivation } => {
                write!(
                    f,
                    "derivation class {derivation:?} requires witness_bundle_id for verified lane"
                )
            }
            EnvelopeError::MissingPromoter { derivation } => {
                write!(
                    f,
                    "derivation class {derivation:?} requires promoted_by for verified lane"
                )
            }
            EnvelopeError::FieldNotVerifiedReady { field_name, reason } => {
                write!(f, "field '{field_name}' not verified-ready: {reason}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

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

    /// Coarse derivation class (Deterministic, AIDerived, HumanPromoted, etc.).
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

    /// Optional witness bundle ID for AI-derived data.
    /// When `derivation_class == AIDerived`, this should be `Some(...)`.
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

    /// Check whether this field satisfies derivation-specific requirements
    /// for the **verified** storage lane.
    ///
    /// Rules:
    /// - `Deterministic`: no witness needed — reproducible by definition.
    /// - `AIDerived` / `Mixed` / `OpaqueExternal`: `witness_bundle_id` required.
    /// - `HumanPromoted`: `witness_bundle_id` AND `promoted_by` required.
    ///
    /// This does NOT prevent construction — callers in the proposed lane may
    /// create envelopes without witnesses. This method gates promotion to
    /// verified storage.
    pub fn verify_derivation_requirements(&self) -> Result<(), EnvelopeError> {
        match self.derivation_class {
            DerivationClass::Deterministic => Ok(()),
            DerivationClass::HumanPromoted => {
                if self.witness_bundle_id.is_none() {
                    return Err(EnvelopeError::MissingWitness {
                        derivation: self.derivation_class,
                    });
                }
                if self.promoted_by.is_none() {
                    return Err(EnvelopeError::MissingPromoter {
                        derivation: self.derivation_class,
                    });
                }
                Ok(())
            }
            DerivationClass::AIDerived
            | DerivationClass::Mixed
            | DerivationClass::OpaqueExternal => {
                if self.witness_bundle_id.is_none() {
                    return Err(EnvelopeError::MissingWitness {
                        derivation: self.derivation_class,
                    });
                }
                Ok(())
            }
        }
    }

    /// Returns `true` if this field is ready for the verified storage lane.
    ///
    /// Equivalent to `self.verify_derivation_requirements().is_ok()`.
    pub fn is_verified_ready(&self) -> bool {
        self.verify_derivation_requirements().is_ok()
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
            derivation = derivation.join(field.derivation_class);
        }

        (label, derivation)
    }

    /// Re-derive the row-level derivation class from the current fields.
    ///
    /// Returns the LUB of all field derivation classes.
    pub fn compute_derivation_class(&self) -> DerivationClass {
        let mut derivation = DerivationClass::Deterministic;
        for field in self.fields.values() {
            derivation = derivation.join(field.derivation_class);
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

    /// Check derivation requirements for **all** fields in this row.
    ///
    /// Returns the first error encountered, wrapped in
    /// [`EnvelopeError::FieldNotVerifiedReady`] with the offending field name.
    pub fn verify_derivation_requirements(&self) -> Result<(), EnvelopeError> {
        for (name, field) in &self.fields {
            if let Err(e) = field.verify_derivation_requirements() {
                return Err(EnvelopeError::FieldNotVerifiedReady {
                    field_name: name.clone(),
                    reason: Box::new(e),
                });
            }
        }
        Ok(())
    }

    /// Returns `true` if **every** field in this row is verified-ready.
    pub fn is_verified_ready(&self) -> bool {
        self.verify_derivation_requirements().is_ok()
    }

    /// Promote a single field's derivation class to `HumanPromoted`.
    ///
    /// Delegates to [`crate::promotion::promote`] for the named field,
    /// then re-derives `row_derivation_class` from all fields to maintain
    /// the row-level LUB invariant.
    ///
    /// # Errors
    ///
    /// Returns [`crate::promotion::PromotionError`] if the field does not
    /// exist or if the underlying promotion validation fails.
    pub fn promote_field(
        &mut self,
        field_name: &str,
        request: &crate::promotion::PromotionRequest,
        witness: Option<&crate::witness::ValidatedWitness>,
        now: u64,
    ) -> Result<crate::promotion::PromotionResult, PromotionApiError> {
        let field = self
            .fields
            .get_mut(field_name)
            .ok_or_else(|| PromotionApiError::FieldNotFound(field_name.to_string()))?;

        let result = crate::promotion::promote(field, request, witness, now)
            .map_err(PromotionApiError::Promotion)?;

        // Re-derive row-level derivation class after mutation.
        self.row_derivation_class = self.compute_derivation_class();

        Ok(result)
    }

    /// Promote all non-`Deterministic` fields in the row.
    ///
    /// Iterates over every field whose derivation class is not
    /// `Deterministic` and applies the promotion. The `request.target_field`
    /// is updated per-field, and `request.from_derivation` is set to match
    /// each field's current derivation class.
    ///
    /// Fields that are already `HumanPromoted` or `Deterministic` are
    /// skipped (they do not need promotion).
    ///
    /// After all promotions, `row_derivation_class` is re-derived.
    ///
    /// # Errors
    ///
    /// Returns on the first promotion failure. Fields promoted before the
    /// failure remain promoted (partial application).
    pub fn promote_all(
        &mut self,
        request: &crate::promotion::PromotionRequest,
        witness: Option<&crate::witness::ValidatedWitness>,
        now: u64,
    ) -> Result<Vec<(String, crate::promotion::PromotionResult)>, PromotionApiError> {
        // Collect field names and their current derivation classes to avoid
        // borrow conflicts with the mutable iteration.
        let candidates: Vec<(String, DerivationClass)> = self
            .fields
            .iter()
            .filter(|(_, f)| {
                !matches!(
                    f.derivation_class,
                    DerivationClass::Deterministic | DerivationClass::HumanPromoted
                )
            })
            .map(|(name, f)| (name.clone(), f.derivation_class))
            .collect();

        let mut results = Vec::with_capacity(candidates.len());

        for (name, current_derivation) in candidates {
            let field = self.fields.get_mut(&name).expect("field exists");
            let mut per_field_request = request.clone();
            per_field_request.target_field = name.clone();
            per_field_request.from_derivation = current_derivation;

            let result = crate::promotion::promote(field, &per_field_request, witness, now)
                .map_err(PromotionApiError::Promotion)?;
            results.push((name, result));
        }

        // Re-derive row-level derivation class after all mutations.
        self.row_derivation_class = self.compute_derivation_class();

        Ok(results)
    }
}

/// Errors from the row-level promotion API.
///
/// Wraps [`crate::promotion::PromotionError`] with row-specific context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionApiError {
    /// The named field does not exist in the row.
    FieldNotFound(String),
    /// The underlying promotion validation failed.
    Promotion(crate::promotion::PromotionError),
}

impl fmt::Display for PromotionApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldNotFound(name) => write!(f, "field '{name}' not found in row"),
            Self::Promotion(e) => write!(f, "promotion failed: {e}"),
        }
    }
}

impl std::error::Error for PromotionApiError {}

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
        let field = make_field(b"data", DerivationClass::AIDerived, label);

        let mut fields = BTreeMap::new();
        fields.insert("f1".into(), field);

        let row = RowEnvelope::new("row-1".into(), "t".into(), fields, None, "v1".into(), 1000);
        assert_eq!(row.row_derivation_class, DerivationClass::AIDerived);
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
        let f2 = make_field(b"internal", DerivationClass::HumanPromoted, label_internal);

        let mut fields = BTreeMap::new();
        fields.insert("public_field".into(), f1);
        fields.insert("internal_field".into(), f2);

        let row = RowEnvelope::new("row-2".into(), "t".into(), fields, None, "v1".into(), 2000);

        // Derivation LUB: HumanPromoted > Deterministic → HumanPromoted
        assert_eq!(row.row_derivation_class, DerivationClass::HumanPromoted);

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
            DerivationClass::Deterministic.join(DerivationClass::Deterministic),
            DerivationClass::Deterministic
        );

        // OpaqueExternal is top — absorbs everything
        assert_eq!(
            DerivationClass::Deterministic.join(DerivationClass::OpaqueExternal),
            DerivationClass::OpaqueExternal
        );
        assert_eq!(
            DerivationClass::AIDerived.join(DerivationClass::OpaqueExternal),
            DerivationClass::OpaqueExternal
        );

        // AIDerived ⊔ HumanPromoted = Mixed (diamond lattice)
        assert_eq!(
            DerivationClass::AIDerived.join(DerivationClass::HumanPromoted),
            DerivationClass::Mixed
        );

        // Mixed ⊔ AIDerived = Mixed
        assert_eq!(
            DerivationClass::Mixed.join(DerivationClass::AIDerived),
            DerivationClass::Mixed
        );

        // Deterministic ⊔ AIDerived = AIDerived
        assert_eq!(
            DerivationClass::Deterministic.join(DerivationClass::AIDerived),
            DerivationClass::AIDerived
        );
    }

    #[test]
    fn derivation_join_is_commutative() {
        let classes = [
            DerivationClass::Deterministic,
            DerivationClass::AIDerived,
            DerivationClass::Mixed,
            DerivationClass::HumanPromoted,
            DerivationClass::OpaqueExternal,
        ];
        for &a in &classes {
            for &b in &classes {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "join({a:?}, {b:?}) should be commutative"
                );
            }
        }
    }

    #[test]
    fn derivation_join_is_associative() {
        let classes = [
            DerivationClass::Deterministic,
            DerivationClass::AIDerived,
            DerivationClass::Mixed,
            DerivationClass::HumanPromoted,
            DerivationClass::OpaqueExternal,
        ];
        for &a in &classes {
            for &b in &classes {
                for &c in &classes {
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(b.join(c)),
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
            DerivationClass::AIDerived,
            DerivationClass::Mixed,
            DerivationClass::HumanPromoted,
            DerivationClass::OpaqueExternal,
        ];
        for &a in &classes {
            assert_eq!(a.join(a), a, "join({a:?}, {a:?}) should be idempotent");
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
        let mut field = make_field(b"model output", DerivationClass::AIDerived, label);
        field.effect_kind = EffectKind::LLMGenerate;
        field.witness_bundle_id = Some("wb-abc123".to_string());

        assert_eq!(field.derivation_class, DerivationClass::AIDerived);
        assert_eq!(field.witness_bundle_id.as_deref(), Some("wb-abc123"));
        assert!(field.verify_content_hash());
    }

    // ═══════════════════════════════════════════════════════════════════
    // Verified-readiness tests (issue #743)
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn deterministic_is_verified_ready_without_witness() {
        let field = make_field(b"pure", DerivationClass::Deterministic, IFCLabel::default());
        assert!(field.is_verified_ready());
        assert!(field.verify_derivation_requirements().is_ok());
    }

    #[test]
    fn ai_derived_without_witness_not_verified_ready() {
        let field = make_field(
            b"llm output",
            DerivationClass::AIDerived,
            IFCLabel::default(),
        );
        assert!(!field.is_verified_ready());
        assert_eq!(
            field.verify_derivation_requirements().unwrap_err(),
            EnvelopeError::MissingWitness {
                derivation: DerivationClass::AIDerived,
            }
        );
    }

    #[test]
    fn ai_derived_with_witness_is_verified_ready() {
        let mut field = make_field(
            b"llm output",
            DerivationClass::AIDerived,
            IFCLabel::default(),
        );
        field.witness_bundle_id = Some("wb-001".into());
        assert!(field.is_verified_ready());
    }

    #[test]
    fn mixed_without_witness_not_verified_ready() {
        let field = make_field(b"mixed", DerivationClass::Mixed, IFCLabel::default());
        assert!(!field.is_verified_ready());
        assert_eq!(
            field.verify_derivation_requirements().unwrap_err(),
            EnvelopeError::MissingWitness {
                derivation: DerivationClass::Mixed,
            }
        );
    }

    #[test]
    fn opaque_external_without_witness_not_verified_ready() {
        let field = make_field(b"ext", DerivationClass::OpaqueExternal, IFCLabel::default());
        assert!(!field.is_verified_ready());
    }

    #[test]
    fn human_promoted_requires_witness_and_promoter() {
        // Neither witness nor promoter
        let field = make_field(
            b"promoted",
            DerivationClass::HumanPromoted,
            IFCLabel::default(),
        );
        assert!(!field.is_verified_ready());
        assert_eq!(
            field.verify_derivation_requirements().unwrap_err(),
            EnvelopeError::MissingWitness {
                derivation: DerivationClass::HumanPromoted,
            }
        );

        // Witness but no promoter
        let mut field2 = make_field(
            b"promoted",
            DerivationClass::HumanPromoted,
            IFCLabel::default(),
        );
        field2.witness_bundle_id = Some("wb-002".into());
        assert!(!field2.is_verified_ready());
        assert_eq!(
            field2.verify_derivation_requirements().unwrap_err(),
            EnvelopeError::MissingPromoter {
                derivation: DerivationClass::HumanPromoted,
            }
        );

        // Both witness and promoter
        let mut field3 = make_field(
            b"promoted",
            DerivationClass::HumanPromoted,
            IFCLabel::default(),
        );
        field3.witness_bundle_id = Some("wb-003".into());
        field3.promoted_by = Some("alice@example.com".into());
        assert!(field3.is_verified_ready());
    }

    #[test]
    fn row_verified_ready_all_deterministic() {
        let f1 = make_field(b"a", DerivationClass::Deterministic, IFCLabel::default());
        let f2 = make_field(b"b", DerivationClass::Deterministic, IFCLabel::default());
        let mut fields = BTreeMap::new();
        fields.insert("c1".into(), f1);
        fields.insert("c2".into(), f2);
        let row = RowEnvelope::new("r1".into(), "t".into(), fields, None, "v1".into(), 1000);
        assert!(row.is_verified_ready());
    }

    #[test]
    fn row_not_verified_ready_if_any_field_missing_witness() {
        let f1 = make_field(b"a", DerivationClass::Deterministic, IFCLabel::default());
        let f2 = make_field(b"b", DerivationClass::AIDerived, IFCLabel::default()); // no witness
        let mut fields = BTreeMap::new();
        fields.insert("det".into(), f1);
        fields.insert("gen".into(), f2);
        let row = RowEnvelope::new("r2".into(), "t".into(), fields, None, "v1".into(), 1000);
        assert!(!row.is_verified_ready());

        let err = row.verify_derivation_requirements().unwrap_err();
        match err {
            EnvelopeError::FieldNotVerifiedReady { field_name, .. } => {
                assert_eq!(field_name, "gen");
            }
            other => panic!("expected FieldNotVerifiedReady, got {other:?}"),
        }
    }

    #[test]
    fn row_verified_ready_with_mixed_fields_all_witnessed() {
        let f1 = make_field(b"a", DerivationClass::Deterministic, IFCLabel::default());
        let mut f2 = make_field(b"b", DerivationClass::AIDerived, IFCLabel::default());
        f2.witness_bundle_id = Some("wb-100".into());
        let mut fields = BTreeMap::new();
        fields.insert("det".into(), f1);
        fields.insert("gen".into(), f2);
        let row = RowEnvelope::new("r3".into(), "t".into(), fields, None, "v1".into(), 1000);
        assert!(row.is_verified_ready());
    }

    #[test]
    fn envelope_error_display() {
        let err = EnvelopeError::MissingWitness {
            derivation: DerivationClass::AIDerived,
        };
        let msg = format!("{err}");
        assert!(msg.contains("witness_bundle_id"));
        assert!(msg.contains("AIDerived"));
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

    // ═══════════════════════════════════════════════════════════════════
    // DPI-3 witness requirement — test mirrors (non-Kani)
    // ═══════════════════════════════════════════════════════════════════

    /// Mirror of Kani proof `proof_verified_write_requires_witness`:
    /// For every non-Deterministic derivation class, `is_verified_ready()`
    /// is false when `witness_bundle_id` is None.
    #[test]
    fn mirror_verified_write_requires_witness_exhaustive() {
        use crate::DerivationClass::*;
        let needs_witness = [AIDerived, Mixed, OpaqueExternal, HumanPromoted];
        for &d in &needs_witness {
            let field = make_field(b"data", d, IFCLabel::default());
            assert!(
                field.witness_bundle_id.is_none(),
                "precondition: make_field should produce None witness"
            );
            assert!(
                !field.is_verified_ready(),
                "DPI-3 violated: {:?} with no witness must not be verified-ready",
                d
            );
        }
    }

    /// Mirror of Kani proof `proof_ai_derived_never_verified_ready_without_witness`:
    /// AIDerived, Mixed, and OpaqueExternal specifically must fail without witness.
    #[test]
    fn mirror_ai_derived_never_verified_ready_without_witness() {
        use crate::DerivationClass::*;
        let ai_classes = [AIDerived, Mixed, OpaqueExternal];
        for &d in &ai_classes {
            let field = make_field(b"data", d, IFCLabel::default());
            assert!(!field.is_verified_ready());
            match field.verify_derivation_requirements() {
                Err(EnvelopeError::MissingWitness { derivation }) => {
                    assert_eq!(derivation, d);
                }
                other => panic!("expected MissingWitness for {:?}, got {:?}", d, other),
            }
        }
    }

    /// Mirror of Kani proof `proof_verified_lane_implies_witness_or_deterministic`:
    /// For every derivation class accepted by StorageLane::Verified, if a field
    /// passes is_verified_ready(), then either it is Deterministic or it has a
    /// witness_bundle_id.
    #[test]
    fn mirror_verified_lane_implies_witness_or_deterministic() {
        use crate::DerivationClass::*;
        use crate::storage_lane::StorageLane;

        let all = [
            Deterministic,
            AIDerived,
            Mixed,
            HumanPromoted,
            OpaqueExternal,
        ];
        for &d in &all {
            // Only test derivation classes that the Verified lane accepts
            if !StorageLane::Verified.accepts(d) {
                continue;
            }
            // Without witness
            let field_no_witness = make_field(b"data", d, IFCLabel::default());
            if field_no_witness.is_verified_ready() {
                // Must be Deterministic — the only class that doesn't need a witness
                assert_eq!(
                    d, Deterministic,
                    "DPI-3 violated: {:?} is verified-ready without witness but is not Deterministic",
                    d
                );
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Promotion API tests (issue #718)
    // ═══════════════════════════════════════════════════════════════════

    use crate::promotion::{PromotionRequest, PromotionScope};
    use crate::witness::{ParserStep, ReductionWitness, ValidatedWitness, ValidationResult};

    fn envelope_sha256(data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).into()
    }

    fn make_valid_witness() -> ValidatedWitness {
        let source = envelope_sha256(b"raw web content");
        let parsed = envelope_sha256(b"parsed json");
        let witness = ReductionWitness {
            source_hash: source,
            parser_steps: vec![ParserStep {
                parser_id: "json_parser".to_string(),
                parser_version: "1.0.0".to_string(),
                parser_hash: envelope_sha256(b"json_parser_binary"),
                input_hash: source,
                output_hash: parsed,
            }],
            validation_steps: vec![ValidationResult {
                validator_id: "schema_check".to_string(),
                version: "1.0.0".to_string(),
                passed: true,
            }],
            output_hash: parsed,
        };
        ValidatedWitness::validate(witness).expect("test witness should be valid")
    }

    fn base_promotion_request(field: &str, from: DerivationClass) -> PromotionRequest {
        PromotionRequest {
            target_field: field.into(),
            from_derivation: from,
            principal: "alice@example.com".into(),
            reason: "Reviewed and confirmed accuracy".into(),
            scope: PromotionScope::AllVerifiedSinks,
            expires_at: None,
        }
    }

    #[test]
    fn promote_single_field() {
        let f1 = make_field(b"pure", DerivationClass::Deterministic, IFCLabel::default());
        let mut f2 = make_field(
            b"generated",
            DerivationClass::AIDerived,
            IFCLabel::default(),
        );
        f2.witness_bundle_id = Some("wb-001".into());

        let mut fields = BTreeMap::new();
        fields.insert("det".into(), f1);
        fields.insert("gen".into(), f2);
        let mut row = RowEnvelope::new("r1".into(), "t".into(), fields, None, "v1".into(), 1000);

        // Before promotion: row derivation is AIDerived (LUB of Deterministic and AIDerived).
        assert_eq!(row.row_derivation_class, DerivationClass::AIDerived);

        let req = base_promotion_request("gen", DerivationClass::AIDerived);
        let witness = make_valid_witness();
        let result = row
            .promote_field("gen", &req, Some(&witness), 2000)
            .expect("should succeed");

        assert!(result.promoted);
        assert_eq!(result.original_derivation, DerivationClass::AIDerived);
        assert_eq!(result.new_derivation, DerivationClass::HumanPromoted);
        assert_eq!(result.promoted_at, 2000);

        // After promotion: field is HumanPromoted.
        assert_eq!(
            row.fields["gen"].derivation_class,
            DerivationClass::HumanPromoted,
        );
        assert_eq!(
            row.fields["gen"].promoted_by.as_deref(),
            Some("alice@example.com"),
        );

        // Row derivation re-derived: LUB(Deterministic, HumanPromoted) = HumanPromoted.
        assert_eq!(row.row_derivation_class, DerivationClass::HumanPromoted);
        assert!(row.verify_invariant());
    }

    #[test]
    fn promote_field_not_found() {
        let f1 = make_field(b"a", DerivationClass::Deterministic, IFCLabel::default());
        let mut fields = BTreeMap::new();
        fields.insert("det".into(), f1);
        let mut row = RowEnvelope::new("r1".into(), "t".into(), fields, None, "v1".into(), 1000);

        let req = base_promotion_request("nonexistent", DerivationClass::AIDerived);
        let err = row
            .promote_field("nonexistent", &req, None, 2000)
            .unwrap_err();
        assert_eq!(err, PromotionApiError::FieldNotFound("nonexistent".into()),);
    }

    #[test]
    fn promote_all_non_deterministic() {
        let f_det = make_field(b"pure", DerivationClass::Deterministic, IFCLabel::default());
        let mut f_ai = make_field(b"ai", DerivationClass::AIDerived, IFCLabel::default());
        f_ai.witness_bundle_id = Some("wb-ai".into());
        let mut f_mixed = make_field(b"mix", DerivationClass::Mixed, IFCLabel::default());
        f_mixed.witness_bundle_id = Some("wb-mix".into());

        let mut fields = BTreeMap::new();
        fields.insert("det".into(), f_det);
        fields.insert("ai_field".into(), f_ai);
        fields.insert("mixed_field".into(), f_mixed);
        let mut row = RowEnvelope::new("r2".into(), "t".into(), fields, None, "v1".into(), 1000);

        // Row derivation is Mixed (LUB of Deterministic, AIDerived, Mixed).
        assert_eq!(row.row_derivation_class, DerivationClass::Mixed);

        let req = base_promotion_request("ignored", DerivationClass::AIDerived);
        let witness = make_valid_witness();
        let results = row
            .promote_all(&req, Some(&witness), 3000)
            .expect("should succeed");

        // Two fields promoted (AIDerived and Mixed); Deterministic skipped.
        assert_eq!(results.len(), 2);
        for (name, result) in &results {
            assert!(result.promoted);
            assert_eq!(result.new_derivation, DerivationClass::HumanPromoted);
            assert_eq!(result.promoted_at, 3000);
            assert!(
                name == "ai_field" || name == "mixed_field",
                "unexpected field promoted: {name}",
            );
        }

        // All non-Deterministic fields are now HumanPromoted.
        assert_eq!(
            row.fields["ai_field"].derivation_class,
            DerivationClass::HumanPromoted,
        );
        assert_eq!(
            row.fields["mixed_field"].derivation_class,
            DerivationClass::HumanPromoted,
        );
        // Deterministic field unchanged.
        assert_eq!(
            row.fields["det"].derivation_class,
            DerivationClass::Deterministic,
        );

        // Row derivation re-derived: LUB(Deterministic, HumanPromoted, HumanPromoted) = HumanPromoted.
        assert_eq!(row.row_derivation_class, DerivationClass::HumanPromoted);
        assert!(row.verify_invariant());
    }

    #[test]
    fn row_verified_ready_after_promotion() {
        // Start with a row that is NOT verified-ready (AIDerived field without witness).
        let f_det = make_field(b"pure", DerivationClass::Deterministic, IFCLabel::default());
        let mut f_ai = make_field(b"ai", DerivationClass::AIDerived, IFCLabel::default());
        f_ai.witness_bundle_id = Some("wb-001".into());

        let mut fields = BTreeMap::new();
        fields.insert("det".into(), f_det);
        fields.insert("gen".into(), f_ai);
        let mut row = RowEnvelope::new("r3".into(), "t".into(), fields, None, "v1".into(), 1000);

        // Before promotion: the AIDerived field has a witness so it IS verified-ready,
        // but after promotion it should also be verified-ready (HumanPromoted with witness + promoter).
        assert!(row.is_verified_ready());

        let req = base_promotion_request("gen", DerivationClass::AIDerived);
        let witness = make_valid_witness();
        row.promote_field("gen", &req, Some(&witness), 2000)
            .expect("should succeed");

        // After promotion: HumanPromoted with witness_bundle_id + promoted_by => verified-ready.
        assert!(row.is_verified_ready());
        assert!(row.verify_invariant());
    }

    #[test]
    fn row_becomes_verified_ready_after_promote_all() {
        // Row with an AIDerived field that has a witness => already verified-ready.
        // After promote_all, all fields become HumanPromoted => still verified-ready.
        let f_det = make_field(b"a", DerivationClass::Deterministic, IFCLabel::default());
        let mut f_ai = make_field(b"b", DerivationClass::AIDerived, IFCLabel::default());
        f_ai.witness_bundle_id = Some("wb-100".into());
        let mut f_opaque = make_field(b"c", DerivationClass::OpaqueExternal, IFCLabel::default());
        f_opaque.witness_bundle_id = Some("wb-200".into());

        let mut fields = BTreeMap::new();
        fields.insert("det".into(), f_det);
        fields.insert("ai".into(), f_ai);
        fields.insert("ext".into(), f_opaque);
        let mut row = RowEnvelope::new("r4".into(), "t".into(), fields, None, "v1".into(), 1000);

        let req = base_promotion_request("ignored", DerivationClass::AIDerived);
        let witness = make_valid_witness();
        row.promote_all(&req, Some(&witness), 4000)
            .expect("should succeed");

        // All promoted fields now have witness_bundle_id + promoted_by.
        assert!(row.is_verified_ready());
        assert!(row.verify_invariant());
    }

    #[test]
    fn promote_all_skips_already_promoted() {
        let mut f_hp = make_field(
            b"already",
            DerivationClass::HumanPromoted,
            IFCLabel::default(),
        );
        f_hp.witness_bundle_id = Some("wb-old".into());
        f_hp.promoted_by = Some("bob@example.com".into());

        let mut fields = BTreeMap::new();
        fields.insert("hp".into(), f_hp);
        let mut row = RowEnvelope::new("r5".into(), "t".into(), fields, None, "v1".into(), 1000);

        let req = base_promotion_request("ignored", DerivationClass::HumanPromoted);
        let results = row.promote_all(&req, None, 5000).expect("should succeed");

        // No fields to promote.
        assert!(results.is_empty());
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Kani BMC harnesses — DPI-3: witness requirement for verified writes
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(kani)]
mod kani_witness_requirement_proofs {
    use super::*;
    use crate::DerivationClass;
    use crate::IFCLabel;
    use crate::effect::EffectKind;
    use crate::storage_lane::StorageLane;

    /// Generate a symbolic DerivationClass (5 variants — exhaustive).
    fn any_derivation() -> DerivationClass {
        let v: u8 = kani::any();
        kani::assume(v <= 4);
        match v {
            0 => DerivationClass::Deterministic,
            1 => DerivationClass::AIDerived,
            2 => DerivationClass::Mixed,
            3 => DerivationClass::HumanPromoted,
            _ => DerivationClass::OpaqueExternal,
        }
    }

    /// Build a minimal FieldEnvelope with symbolic derivation and no witness.
    /// Content hash is zeroed (not relevant to derivation checks).
    fn envelope_no_witness(derivation: DerivationClass) -> FieldEnvelope {
        FieldEnvelope {
            value_bytes: vec![],
            schema_type: String::new(),
            label: IFCLabel::default(),
            derivation_class: derivation,
            effect_kind: EffectKind::PureTransform,
            source_node_id: 0,
            causal_parents: vec![],
            source_refs: vec![],
            transform_refs: vec![],
            witness_bundle_id: None,
            promoted_by: None,
            promoted_reason: None,
            created_at: 0,
            content_hash: [0u8; 32],
        }
    }

    /// **DPI-3a — Verified write requires witness.**
    ///
    /// For all DerivationClass values: if the derivation class is NOT
    /// Deterministic, then a FieldEnvelope with `witness_bundle_id = None`
    /// must NOT be verified-ready. Equivalently: the only derivation class
    /// that can pass `is_verified_ready()` without a witness is Deterministic.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_verified_write_requires_witness() {
        let d = any_derivation();
        let envelope = envelope_no_witness(d);

        // If the envelope is verified-ready without a witness, it must be Deterministic.
        if envelope.is_verified_ready() {
            assert!(
                d == DerivationClass::Deterministic,
                "non-Deterministic envelope is verified-ready without witness"
            );
        }
    }

    /// **DPI-3b — AI-derived classes never verified-ready without witness.**
    ///
    /// For AIDerived, Mixed, and OpaqueExternal: `is_verified_ready()` is
    /// always false when `witness_bundle_id` is None. This is a stronger
    /// statement than DPI-3a for the AI-tainted subset.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_ai_derived_never_verified_ready_without_witness() {
        let v: u8 = kani::any();
        kani::assume(v <= 2);
        let d = match v {
            0 => DerivationClass::AIDerived,
            1 => DerivationClass::Mixed,
            _ => DerivationClass::OpaqueExternal,
        };

        let envelope = envelope_no_witness(d);
        assert!(
            !envelope.is_verified_ready(),
            "AI-tainted derivation class must not be verified-ready without witness"
        );
    }

    /// **DPI-3c — Verified lane acceptance implies witness-or-deterministic.**
    ///
    /// For all derivation classes accepted by `StorageLane::Verified`: if
    /// `is_verified_ready()` returns true with no witness, the derivation
    /// class must be Deterministic. This ties the storage lane gate to the
    /// envelope verification gate.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_verified_lane_implies_witness_or_deterministic() {
        let d = any_derivation();
        kani::assume(StorageLane::Verified.accepts(d));

        let envelope = envelope_no_witness(d);
        if envelope.is_verified_ready() {
            assert!(
                d == DerivationClass::Deterministic,
                "Verified-lane-accepted envelope is verified-ready without witness \
                 but is not Deterministic"
            );
        }
    }
}
