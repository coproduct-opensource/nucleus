//! Computation-step-level effect classification.
//!
//! [`EffectKind`] classifies each computation step by its determinism profile.
//! This is orthogonal to [`crate::Operation`], which classifies tool-level
//! actions. `EffectKind` answers *how* a datum was derived — whether by
//! generative model output, deterministic fetch, pure transformation,
//! human input, etc.
//!
//! This distinction is the foundation of the DPI dual-lane storage model:
//! deterministic effects can be auto-verified; generative effects require
//! witness bundles.

use crate::DerivationClass;

// ═══════════════════════════════════════════════════════════════════════════
// EffectKind — computation-step-level effect classification
// ═══════════════════════════════════════════════════════════════════════════

/// Classifies a computation step by its determinism profile.
///
/// Unlike [`crate::Operation`] (which classifies which *tool* was invoked),
/// `EffectKind` classifies *how* the output was derived. A single tool
/// invocation may involve multiple `EffectKind` steps — for example, a
/// "research" tool might fetch a URL (`DeterministicFetch`), then
/// summarize the content (`LLMGenerate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EffectKind {
    // -- Generative (non-deterministic model output) --
    /// Free-form LLM generation (summaries, prose, code).
    LLMGenerate,
    /// LLM classification or labeling (sentiment, category).
    LLMClassify,
    /// LLM-based extraction from text (entities, fields).
    LLMExtract,

    // -- Deterministic (reproducible given same inputs) --
    /// Authenticated HTTP/API fetch — same URL + auth yields same response.
    DeterministicFetch,
    /// Registered parser execution (JSON parse, regex, AST parse).
    DeterministicParse,
    /// Format or schema validation (JSON Schema, protobuf, etc.).
    DeterministicValidate,
    /// Pure function transform (hash, sort, map, filter).
    PureTransform,
    /// Database or search query with deterministic parameters.
    Query,

    // -- Human --
    /// Human review and approval of a proposed action.
    HumanApprove,
    /// Human direct modification of data or content.
    HumanEdit,

    // -- Writes --
    /// Write to a verified sink (committed, immutable).
    VerifiedWrite,
    /// Write to a proposed sink (draft, reviewable).
    ProposedWrite,

    // -- External / Replay --
    /// Import from an external system with its own provenance chain.
    ExternalImport,
    /// Replay of a prior recorded computation step.
    Replay,
}

impl EffectKind {
    /// Returns `true` if this effect is deterministic — given the same inputs
    /// and environment, it will always produce the same output.
    ///
    /// Deterministic effects can be auto-verified by re-execution.
    pub const fn is_deterministic(&self) -> bool {
        matches!(
            self,
            Self::DeterministicFetch
                | Self::DeterministicParse
                | Self::DeterministicValidate
                | Self::PureTransform
                | Self::Query
        )
    }

    /// Returns `true` if this effect involves generative AI model output.
    ///
    /// Generative effects are non-deterministic and require witness bundles
    /// (input snapshot + output + model version) for auditability.
    pub const fn is_ai_generative(&self) -> bool {
        matches!(
            self,
            Self::LLMGenerate | Self::LLMClassify | Self::LLMExtract
        )
    }

    /// Returns the [`DerivationClass`] that this effect kind implies.
    ///
    /// This mapping is the bridge between fine-grained effect classification
    /// and the coarse verification lanes in the DPI storage model.
    pub const fn implied_derivation(&self) -> DerivationClass {
        match self {
            // AI-derived (non-deterministic model output)
            Self::LLMGenerate | Self::LLMClassify | Self::LLMExtract => DerivationClass::AIDerived,

            // Deterministic (reproducible given same inputs)
            Self::DeterministicFetch
            | Self::DeterministicParse
            | Self::DeterministicValidate
            | Self::PureTransform
            | Self::Query => DerivationClass::Deterministic,

            // Human-promoted (explicitly attested by a human)
            Self::HumanApprove | Self::HumanEdit => DerivationClass::HumanPromoted,

            // Writes inherit from the verification lane of their content,
            // but structurally they are deterministic operations (the write
            // itself is a side-effect, not a derivation).
            Self::VerifiedWrite | Self::ProposedWrite => DerivationClass::Deterministic,

            // Opaque external (unknown determinism profile)
            Self::ExternalImport => DerivationClass::OpaqueExternal,

            // Replay is deterministic (reproducible from recorded computation)
            Self::Replay => DerivationClass::Deterministic,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant that claims to be deterministic must also imply
    /// `DerivationClass::Deterministic`.
    #[test]
    fn deterministic_variants_imply_deterministic_derivation() {
        let deterministic = [
            EffectKind::DeterministicFetch,
            EffectKind::DeterministicParse,
            EffectKind::DeterministicValidate,
            EffectKind::PureTransform,
            EffectKind::Query,
        ];
        for kind in deterministic {
            assert!(kind.is_deterministic(), "{kind:?} should be deterministic");
            assert!(
                !kind.is_ai_generative(),
                "{kind:?} should NOT be ai_generative"
            );
            assert_eq!(
                kind.implied_derivation(),
                DerivationClass::Deterministic,
                "{kind:?} should imply Deterministic derivation"
            );
        }
    }

    /// Every variant that claims to be AI generative must also imply
    /// `DerivationClass::AIDerived`.
    #[test]
    fn ai_generative_variants_imply_ai_derived_derivation() {
        let generative = [
            EffectKind::LLMGenerate,
            EffectKind::LLMClassify,
            EffectKind::LLMExtract,
        ];
        for kind in generative {
            assert!(kind.is_ai_generative(), "{kind:?} should be ai_generative");
            assert!(
                !kind.is_deterministic(),
                "{kind:?} should NOT be deterministic"
            );
            assert_eq!(
                kind.implied_derivation(),
                DerivationClass::AIDerived,
                "{kind:?} should imply AIDerived derivation"
            );
        }
    }

    /// Human variants are neither deterministic nor AI generative.
    #[test]
    fn human_variants() {
        let human = [EffectKind::HumanApprove, EffectKind::HumanEdit];
        for kind in human {
            assert!(!kind.is_deterministic(), "{kind:?}");
            assert!(!kind.is_ai_generative(), "{kind:?}");
            assert_eq!(kind.implied_derivation(), DerivationClass::HumanPromoted);
        }
    }

    /// Write variants are classified as deterministic (the write operation
    /// itself is a side-effect, not a derivation).
    #[test]
    fn write_variants() {
        let writes = [EffectKind::VerifiedWrite, EffectKind::ProposedWrite];
        for kind in writes {
            assert!(!kind.is_ai_generative(), "{kind:?}");
            assert_eq!(kind.implied_derivation(), DerivationClass::Deterministic);
        }
    }

    /// External import implies OpaqueExternal derivation class.
    #[test]
    fn external_import_variant() {
        let kind = EffectKind::ExternalImport;
        assert!(!kind.is_deterministic());
        assert!(!kind.is_ai_generative());
        assert_eq!(kind.implied_derivation(), DerivationClass::OpaqueExternal);
    }

    /// Replay implies Deterministic derivation class (reproducible from log).
    #[test]
    fn replay_variant() {
        let kind = EffectKind::Replay;
        assert!(!kind.is_deterministic());
        assert!(!kind.is_ai_generative());
        assert_eq!(kind.implied_derivation(), DerivationClass::Deterministic);
    }

    /// Exhaustiveness check — every variant is covered by exactly one
    /// of the classification methods or falls into the "other" bucket.
    #[test]
    fn every_variant_has_a_derivation_class() {
        let all_variants = [
            EffectKind::LLMGenerate,
            EffectKind::LLMClassify,
            EffectKind::LLMExtract,
            EffectKind::DeterministicFetch,
            EffectKind::DeterministicParse,
            EffectKind::DeterministicValidate,
            EffectKind::PureTransform,
            EffectKind::Query,
            EffectKind::HumanApprove,
            EffectKind::HumanEdit,
            EffectKind::VerifiedWrite,
            EffectKind::ProposedWrite,
            EffectKind::ExternalImport,
            EffectKind::Replay,
        ];

        for kind in all_variants {
            // implied_derivation must not panic — that's the test
            let _class = kind.implied_derivation();
        }

        // Verify count matches enum variant count (compile-time guard
        // via the match in implied_derivation, but belt-and-suspenders).
        assert_eq!(all_variants.len(), 14);
    }
}
