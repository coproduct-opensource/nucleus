//! Human promotion service — field-scoped, principal-bound, expiring promotion.
//!
//! Converts `DerivationClass::AIDerived` or `DerivationClass::Mixed` data to
//! `DerivationClass::HumanPromoted` via explicit human attestation. Unlike
//! `DeclassificationToken` (which operates on IFC label dimensions), promotion
//! acts on the **derivation class** of individual fields within a
//! [`FieldEnvelope`].
//!
//! # Design principles
//!
//! - **Additive, not destructive**: Promotion does NOT erase the prior
//!   derivation chain. The envelope's `source_refs` and `transform_refs`
//!   remain intact. The original derivation class is preserved in the
//!   [`PromotionResult`] for audit.
//! - **Principal-bound**: Every promotion records *who* approved it.
//! - **Scoped**: [`PromotionScope`] restricts which downstream sinks may
//!   consume the promoted data.
//! - **Time-bounded**: Optional expiry allows temporary promotions.
//!
//! # Relationship to `DeclassificationToken`
//!
//! `DeclassificationToken` in `declassify.rs` lowers IFC labels (confidentiality,
//! integrity, authority). This module promotes the *derivation class* — an
//! orthogonal dimension. Both may be needed for a single datum to flow to a
//! verified sink.

use crate::DerivationClass;
use crate::SinkClass;
use crate::envelope::FieldEnvelope;
use crate::witness::ReductionWitness;

// ═══════════════════════════════════════════════════════════════════════════
// PromotionScope — where promoted data may flow
// ═══════════════════════════════════════════════════════════════════════════

/// Restricts which downstream sinks may consume the promoted data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionScope {
    /// The promoted data may flow to any sink that accepts verified data.
    AllVerifiedSinks,
    /// The promoted data may only flow to the listed sink classes.
    SpecificSinks(Vec<SinkClass>),
    /// The promotion applies only to the targeted field — no downstream
    /// propagation beyond the field's own envelope.
    SingleField,
}

// ═══════════════════════════════════════════════════════════════════════════
// PromotionRequest — what the human is attesting
// ═══════════════════════════════════════════════════════════════════════════

/// A request to promote a field's derivation class to `HumanPromoted`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionRequest {
    /// The field name being promoted (for audit trail matching).
    pub target_field: String,
    /// The derivation class we expect the field to currently hold.
    /// Must match the envelope's actual class or the promotion is rejected.
    pub from_derivation: DerivationClass,
    /// Human-readable principal identity (email, SPIFFE ID, etc.).
    pub principal: String,
    /// Free-text reason for the promotion (human attestation).
    pub reason: String,
    /// Which downstream sinks may consume the promoted data.
    pub scope: PromotionScope,
    /// Optional expiry as a Unix timestamp (seconds). After this time the
    /// promotion should be considered stale by downstream consumers.
    pub expires_at: Option<u64>,
}

// ═══════════════════════════════════════════════════════════════════════════
// PromotionResult — the receipt of a successful promotion
// ═══════════════════════════════════════════════════════════════════════════

/// The outcome of a successful promotion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromotionResult {
    /// Whether the promotion was applied.
    pub promoted: bool,
    /// The new derivation class (always `HumanPromoted` on success).
    pub new_derivation: DerivationClass,
    /// The original derivation class before promotion (preserved for audit).
    pub original_derivation: DerivationClass,
    /// Unix timestamp (seconds) when the promotion was applied.
    pub promoted_at: u64,
    /// Optional receipt ID for linking into the receipt chain.
    pub receipt_id: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// PromotionError — why a promotion was rejected
// ═══════════════════════════════════════════════════════════════════════════

/// Errors that prevent a promotion from being applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionError {
    /// The `principal` field was empty.
    EmptyPrincipal,
    /// The `reason` field was empty.
    EmptyReason,
    /// The request's `from_derivation` does not match the envelope's current
    /// derivation class.
    DerivationMismatch {
        /// What the request expected.
        expected: DerivationClass,
        /// What the envelope actually holds.
        actual: DerivationClass,
    },
    /// The promotion has expired (current time >= `expires_at`).
    Expired {
        /// The expiry timestamp from the request.
        expires_at: u64,
        /// The current time that exceeded it.
        now: u64,
    },
    /// Cannot promote data that is already `HumanPromoted`.
    AlreadyPromoted,
    /// Cannot promote `Deterministic` data — it is already the strongest
    /// reproducibility class and does not need human attestation.
    CannotPromoteDeterministic,
    /// Content was evacuated from the airlock. A valid `ReductionWitness`
    /// is required to promote non-deterministic data, but was missing or
    /// invalid.
    AirlockEvacuated {
        /// Human-readable explanation of why the content was evacuated.
        reason: String,
    },
}

impl core::fmt::Display for PromotionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyPrincipal => write!(f, "principal must not be empty"),
            Self::EmptyReason => write!(f, "reason must not be empty"),
            Self::DerivationMismatch { expected, actual } => {
                write!(
                    f,
                    "derivation mismatch: expected {expected:?}, found {actual:?}"
                )
            }
            Self::Expired { expires_at, now } => {
                write!(
                    f,
                    "promotion expired at {expires_at}, current time is {now}"
                )
            }
            Self::AlreadyPromoted => write!(f, "field is already HumanPromoted"),
            Self::CannotPromoteDeterministic => {
                write!(f, "deterministic data does not need promotion")
            }
            Self::AirlockEvacuated { reason } => {
                write!(f, "airlock evacuated: {reason}")
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// promote — the core operation
// ═══════════════════════════════════════════════════════════════════════════

/// Promote a field envelope's derivation class to `HumanPromoted`.
///
/// This is an **additive** operation: the envelope's `source_refs`,
/// `transform_refs`, and `causal_parents` are preserved. Only the
/// `derivation_class`, `promoted_by`, and `promoted_reason` fields are
/// updated.
///
/// # Errors
///
/// Returns [`PromotionError`] if any validation check fails (empty principal,
/// empty reason, derivation mismatch, expiry, already promoted, or
/// deterministic source).
pub fn promote(
    envelope: &mut FieldEnvelope,
    request: &PromotionRequest,
    witness: Option<&ReductionWitness>,
    now: u64,
) -> Result<PromotionResult, PromotionError> {
    // --- validation ---

    if request.principal.is_empty() {
        return Err(PromotionError::EmptyPrincipal);
    }
    if request.reason.is_empty() {
        return Err(PromotionError::EmptyReason);
    }
    if let Some(exp) = request.expires_at
        && now >= exp
    {
        return Err(PromotionError::Expired {
            expires_at: exp,
            now,
        });
    }
    if envelope.derivation_class == DerivationClass::HumanPromoted {
        return Err(PromotionError::AlreadyPromoted);
    }
    if envelope.derivation_class == DerivationClass::Deterministic {
        return Err(PromotionError::CannotPromoteDeterministic);
    }
    if request.from_derivation != envelope.derivation_class {
        return Err(PromotionError::DerivationMismatch {
            expected: request.from_derivation,
            actual: envelope.derivation_class,
        });
    }

    // --- reduction witness gate ---
    //
    // Non-deterministic derivation classes require a valid ReductionWitness.
    // This ensures raw content cannot be promoted without being processed
    // through a deterministic parser chain first.
    match envelope.derivation_class {
        DerivationClass::AIDerived | DerivationClass::Mixed | DerivationClass::OpaqueExternal => {
            match witness {
                None => {
                    return Err(PromotionError::AirlockEvacuated {
                        reason: format!(
                            "{:?} content requires a ReductionWitness for promotion",
                            envelope.derivation_class
                        ),
                    });
                }
                Some(w) if !w.is_valid() => {
                    return Err(PromotionError::AirlockEvacuated {
                        reason: "ReductionWitness is invalid: chain broken or validation failed"
                            .to_string(),
                    });
                }
                Some(_) => { /* valid witness, proceed */ }
            }
        }
        // Deterministic and HumanPromoted are handled above (early returns).
        _ => {}
    }

    // --- apply promotion ---

    let original = envelope.derivation_class;
    envelope.derivation_class = DerivationClass::HumanPromoted;
    envelope.promoted_by = Some(request.principal.clone());
    envelope.promoted_reason = Some(request.reason.clone());

    Ok(PromotionResult {
        promoted: true,
        new_derivation: DerivationClass::HumanPromoted,
        original_derivation: original,
        promoted_at: now,
        receipt_id: None,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IFCLabel;
    use crate::effect::EffectKind;
    use crate::witness::{ParserStep, ValidationResult};
    use sha2::{Digest, Sha256};

    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Helper: build a minimal `FieldEnvelope` with the given derivation class.
    fn make_envelope(derivation: DerivationClass) -> FieldEnvelope {
        let value = b"test-value";
        let content_hash: [u8; 32] = Sha256::digest(value).into();
        FieldEnvelope {
            value_bytes: value.to_vec(),
            schema_type: "string".into(),
            label: IFCLabel::default(),
            derivation_class: derivation,
            effect_kind: EffectKind::PureTransform,
            source_node_id: 0,
            causal_parents: vec![],
            source_refs: vec![],
            transform_refs: vec![],
            witness_bundle_id: Some("witness-1".into()),
            promoted_by: None,
            promoted_reason: None,
            created_at: 1000,
            content_hash,
        }
    }

    fn base_request() -> PromotionRequest {
        PromotionRequest {
            target_field: "summary".into(),
            from_derivation: DerivationClass::AIDerived,
            principal: "alice@example.com".into(),
            reason: "Reviewed and confirmed accuracy".into(),
            scope: PromotionScope::AllVerifiedSinks,
            expires_at: None,
        }
    }

    fn make_valid_witness() -> ReductionWitness {
        let source = sha256(b"raw web content");
        let parsed = sha256(b"parsed json");
        ReductionWitness {
            source_hash: source,
            parser_steps: vec![ParserStep {
                parser_id: "json_parser".to_string(),
                parser_version: "1.0.0".to_string(),
                parser_hash: sha256(b"json_parser_binary"),
                input_hash: source,
                output_hash: parsed,
            }],
            validation_steps: vec![ValidationResult {
                validator_id: "schema_check".to_string(),
                version: "1.0.0".to_string(),
                passed: true,
            }],
            output_hash: parsed,
        }
    }

    #[test]
    fn successful_promotion() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let req = base_request();
        let witness = make_valid_witness();
        let result =
            promote(&mut env, &req, Some(&witness), 2000).expect("promotion should succeed");

        assert!(result.promoted);
        assert_eq!(result.new_derivation, DerivationClass::HumanPromoted);
        assert_eq!(result.original_derivation, DerivationClass::AIDerived);
        assert_eq!(result.promoted_at, 2000);

        // Envelope is updated
        assert_eq!(env.derivation_class, DerivationClass::HumanPromoted);
        assert_eq!(env.promoted_by.as_deref(), Some("alice@example.com"));
        assert_eq!(
            env.promoted_reason.as_deref(),
            Some("Reviewed and confirmed accuracy")
        );

        // Ancestry is preserved
        assert_eq!(env.source_refs.len(), 0); // unchanged
        assert_eq!(env.transform_refs.len(), 0); // unchanged
        assert_eq!(env.witness_bundle_id.as_deref(), Some("witness-1"));
    }

    #[test]
    fn mixed_derivation_promotion() {
        let mut env = make_envelope(DerivationClass::Mixed);
        let mut req = base_request();
        req.from_derivation = DerivationClass::Mixed;
        let witness = make_valid_witness();
        let result =
            promote(&mut env, &req, Some(&witness), 2000).expect("mixed promotion should succeed");

        assert_eq!(result.original_derivation, DerivationClass::Mixed);
        assert_eq!(env.derivation_class, DerivationClass::HumanPromoted);
    }

    #[test]
    fn principal_required() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let mut req = base_request();
        req.principal = String::new();

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        assert_eq!(err, PromotionError::EmptyPrincipal);
        assert_eq!(env.derivation_class, DerivationClass::AIDerived);
    }

    #[test]
    fn reason_required() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let mut req = base_request();
        req.reason = String::new();

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        assert_eq!(err, PromotionError::EmptyReason);
    }

    #[test]
    fn derivation_mismatch_rejected() {
        let mut env = make_envelope(DerivationClass::Mixed);
        let req = base_request();

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        assert_eq!(
            err,
            PromotionError::DerivationMismatch {
                expected: DerivationClass::AIDerived,
                actual: DerivationClass::Mixed,
            }
        );
        assert_eq!(env.derivation_class, DerivationClass::Mixed);
    }

    #[test]
    fn expired_promotion_rejected() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let mut req = base_request();
        req.expires_at = Some(1500);

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        assert_eq!(
            err,
            PromotionError::Expired {
                expires_at: 1500,
                now: 2000,
            }
        );
    }

    #[test]
    fn not_yet_expired_succeeds() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let mut req = base_request();
        req.expires_at = Some(3000);
        let witness = make_valid_witness();

        let result =
            promote(&mut env, &req, Some(&witness), 2000).expect("should succeed before expiry");
        assert!(result.promoted);
    }

    #[test]
    fn already_promoted_rejected() {
        let mut env = make_envelope(DerivationClass::HumanPromoted);
        let mut req = base_request();
        req.from_derivation = DerivationClass::HumanPromoted;

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        assert_eq!(err, PromotionError::AlreadyPromoted);
    }

    #[test]
    fn deterministic_cannot_be_promoted() {
        let mut env = make_envelope(DerivationClass::Deterministic);
        let mut req = base_request();
        req.from_derivation = DerivationClass::Deterministic;

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        assert_eq!(err, PromotionError::CannotPromoteDeterministic);
    }

    #[test]
    fn specific_sinks_scope() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let mut req = base_request();
        req.scope =
            PromotionScope::SpecificSinks(vec![SinkClass::WorkspaceWrite, SinkClass::GitCommit]);
        let witness = make_valid_witness();

        let result =
            promote(&mut env, &req, Some(&witness), 2000).expect("scoped promotion should succeed");
        assert!(result.promoted);
    }

    #[test]
    fn single_field_scope() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let mut req = base_request();
        req.scope = PromotionScope::SingleField;
        let witness = make_valid_witness();

        let result = promote(&mut env, &req, Some(&witness), 2000)
            .expect("single-field promotion should succeed");
        assert!(result.promoted);
    }

    #[test]
    fn opaque_external_can_be_promoted() {
        let mut env = make_envelope(DerivationClass::OpaqueExternal);
        let mut req = base_request();
        req.from_derivation = DerivationClass::OpaqueExternal;
        let witness = make_valid_witness();

        let result = promote(&mut env, &req, Some(&witness), 2000)
            .expect("opaque external promotion should succeed");
        assert_eq!(result.original_derivation, DerivationClass::OpaqueExternal);
        assert_eq!(env.derivation_class, DerivationClass::HumanPromoted);
    }

    // ReductionWitness gate tests (issue #860)

    #[test]
    fn raw_content_without_witness_evacuated() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let req = base_request();

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        match &err {
            PromotionError::AirlockEvacuated { reason } => {
                assert!(reason.contains("ReductionWitness"));
            }
            other => panic!("expected AirlockEvacuated, got {other:?}"),
        }
        assert_eq!(env.derivation_class, DerivationClass::AIDerived);
    }

    #[test]
    fn opaque_external_without_witness_evacuated() {
        let mut env = make_envelope(DerivationClass::OpaqueExternal);
        let mut req = base_request();
        req.from_derivation = DerivationClass::OpaqueExternal;

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        match &err {
            PromotionError::AirlockEvacuated { reason } => {
                assert!(reason.contains("ReductionWitness"));
            }
            other => panic!("expected AirlockEvacuated, got {other:?}"),
        }
    }

    #[test]
    fn mixed_without_witness_evacuated() {
        let mut env = make_envelope(DerivationClass::Mixed);
        let mut req = base_request();
        req.from_derivation = DerivationClass::Mixed;

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        match &err {
            PromotionError::AirlockEvacuated { reason } => {
                assert!(reason.contains("ReductionWitness"));
            }
            other => panic!("expected AirlockEvacuated, got {other:?}"),
        }
    }

    #[test]
    fn web_content_with_valid_witness_cleared() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let req = base_request();
        let witness = make_valid_witness();

        let result = promote(&mut env, &req, Some(&witness), 2000)
            .expect("promotion with valid witness should succeed");
        assert!(result.promoted);
        assert_eq!(env.derivation_class, DerivationClass::HumanPromoted);
    }

    #[test]
    fn invalid_witness_broken_chain_evacuated() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let req = base_request();

        let mut witness = make_valid_witness();
        witness.parser_steps[0].input_hash = [0xDE; 32];
        assert!(!witness.is_valid());

        let err = promote(&mut env, &req, Some(&witness), 2000).unwrap_err();
        match &err {
            PromotionError::AirlockEvacuated { reason } => {
                assert!(reason.contains("invalid"));
            }
            other => panic!("expected AirlockEvacuated, got {other:?}"),
        }
        assert_eq!(env.derivation_class, DerivationClass::AIDerived);
    }

    #[test]
    fn invalid_witness_failed_validation_evacuated() {
        let mut env = make_envelope(DerivationClass::AIDerived);
        let req = base_request();

        let mut witness = make_valid_witness();
        witness.validation_steps[0].passed = false;

        let err = promote(&mut env, &req, Some(&witness), 2000).unwrap_err();
        match &err {
            PromotionError::AirlockEvacuated { reason } => {
                assert!(reason.contains("invalid"));
            }
            other => panic!("expected AirlockEvacuated, got {other:?}"),
        }
    }

    #[test]
    fn deterministic_without_witness_ok() {
        let mut env = make_envelope(DerivationClass::Deterministic);
        let mut req = base_request();
        req.from_derivation = DerivationClass::Deterministic;

        let err = promote(&mut env, &req, None, 2000).unwrap_err();
        assert_eq!(err, PromotionError::CannotPromoteDeterministic);
    }
}
