//! NIST AI 100-4 provenance metadata (#963).
//!
//! Machine-readable metadata aligned with NIST AI 100-4 for AI-generated
//! content provenance. Fields: model identifier (generic), generation
//! timestamp, input data sources, derivation class.

use serde::Serialize;

/// NIST AI 100-4 aligned provenance metadata.
#[derive(Debug, Clone, Serialize)]
pub struct NistProvenanceMetadata {
    /// NIST AI 100-4 version this metadata conforms to.
    pub nist_version: String,
    /// Model identifier (vendor-agnostic — e.g., "llm-agent-v1").
    pub model_id: String,
    /// Generation timestamp (ISO 8601).
    pub generated_at: String,
    /// Input data source identifiers.
    pub input_sources: Vec<NistInputSource>,
    /// Overall derivation: "deterministic", "ai_derived", or "mixed".
    pub derivation_class: String,
    /// Whether human review was applied.
    pub human_reviewed: bool,
    /// Nucleus-specific: receipt chain head hash.
    pub receipt_chain_head: String,
    /// Nucleus-specific: WitnessBundle digest (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_digest: Option<String>,
}

/// An input data source referenced in the provenance.
#[derive(Debug, Clone, Serialize)]
pub struct NistInputSource {
    /// Source type: "web", "file", "database", "api", "user".
    pub source_type: String,
    /// Source identifier (URL, file path, etc.).
    pub identifier: String,
    /// Content hash at capture time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// Whether this source was processed deterministically.
    pub deterministic: bool,
}

impl NistProvenanceMetadata {
    /// Build from a ProvenanceOutput.
    #[cfg(feature = "artifact")]
    pub fn from_provenance(output: &crate::provenance_output::ProvenanceOutput) -> Self {
        let has_deterministic = output
            .fields
            .values()
            .any(|f| f.provenance.derivation == "Deterministic");
        let has_ai = output.header.contains_ai_derived;

        let derivation_class = match (has_deterministic, has_ai) {
            (true, true) => "mixed",
            (true, false) => "deterministic",
            (false, true) => "ai_derived",
            (false, false) => "none",
        };

        let input_sources = output
            .fields
            .values()
            .filter_map(|f| {
                f.provenance
                    .source_content_hash
                    .as_ref()
                    .map(|hash| NistInputSource {
                        source_type: if f.provenance.derivation == "Deterministic" {
                            "api".into()
                        } else {
                            "model".into()
                        },
                        identifier: f.provenance.source_url.clone().unwrap_or_default(),
                        content_hash: Some(hash.clone()),
                        deterministic: f.provenance.derivation == "Deterministic",
                    })
            })
            .collect();

        Self {
            nist_version: "AI-100-4".into(),
            model_id: output.header.nucleus_version.clone(),
            generated_at: output.header.completed_at.clone(),
            input_sources,
            derivation_class: derivation_class.into(),
            human_reviewed: false,
            receipt_chain_head: output.header.receipt_chain_head.clone(),
            witness_digest: None,
        }
    }
}

#[cfg(all(test, feature = "artifact"))]
mod tests {
    use super::*;

    #[test]
    fn nist_input_source_serializes() {
        let source = NistInputSource {
            source_type: "api".into(),
            identifier: "https://example.com".into(),
            content_hash: Some("sha256:abc".into()),
            deterministic: true,
        };
        let json = serde_json::to_string(&source).unwrap();
        assert!(json.contains("deterministic"));
    }

    #[test]
    fn metadata_serializes() {
        let meta = NistProvenanceMetadata {
            nist_version: "AI-100-4".into(),
            model_id: "test".into(),
            generated_at: "2026-04-03".into(),
            input_sources: vec![],
            derivation_class: "mixed".into(),
            human_reviewed: false,
            receipt_chain_head: "sha256:head".into(),
            witness_digest: None,
        };
        let json = serde_json::to_string_pretty(&meta).unwrap();
        assert!(json.contains("AI-100-4"));
        assert!(json.contains("derivation_class"));
    }
}
