//! C2PA assertion types for nucleus provenance (#958, #1014).
//!
//! Defines the nucleus-to-C2PA assertion mapping as pure Rust types.
//! No c2pa-rs dependency — these serialize to the JSON that c2pa-rs
//! expects when adding assertions to a manifest.
//!
//! ## Assertions
//!
//! | C2PA Label | Nucleus Source |
//! |---|---|
//! | `c2pa.actions` | ProvenanceOutput fields (one action per field) |
//! | `c2pa.hash.data` | WitnessBundle digest |
//! | `nucleus.provenance.v1` | Full ProvenanceOutput JSON |
//! | `nucleus.witness_digest` | Hex witness bundle digest |
//! | `stds.schema.org.CreativeWork` | AI transparency metadata |

use serde::Serialize;

// ═══════════════════════════════════════════════════════════════════════════
// C2PA Actions assertion (c2pa.actions)
// ═══════════════════════════════════════════════════════════════════════════

/// C2PA actions assertion — one action per provenance field.
#[derive(Debug, Clone, Serialize)]
pub struct C2paActionsAssertion {
    pub actions: Vec<C2paAction>,
}

/// A single C2PA action entry.
#[derive(Debug, Clone, Serialize)]
pub struct C2paAction {
    /// Action type: "c2pa.created", "c2pa.edited", or custom.
    pub action: String,
    /// Software agent that performed the action.
    #[serde(rename = "softwareAgent")]
    pub software_agent: String,
    /// When the action occurred (ISO 8601).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub when: Option<String>,
    /// Additional parameters.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<C2paActionParameters>,
}

/// Parameters attached to a C2PA action.
#[derive(Debug, Clone, Serialize)]
pub struct C2paActionParameters {
    /// Nucleus derivation class: "Deterministic" or "AIDerived".
    #[serde(rename = "nucleus:derivation")]
    pub derivation: String,
    /// Field name in the provenance schema.
    #[serde(rename = "nucleus:field")]
    pub field: String,
    /// Parser ID (for deterministic fields).
    #[serde(rename = "nucleus:parser", skip_serializing_if = "Option::is_none")]
    pub parser: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// AI Transparency assertion (stds.schema.org.CreativeWork)
// ═══════════════════════════════════════════════════════════════════════════

/// AI transparency assertion per EU AI Act Article 50.
#[derive(Debug, Clone, Serialize)]
pub struct AiTransparencyAssertion {
    /// Schema.org context.
    #[serde(rename = "@context")]
    pub context: String,
    /// Type: "CreativeWork".
    #[serde(rename = "@type")]
    pub type_: String,
    /// Whether the output contains AI-generated content.
    #[serde(rename = "nucleus:containsAiDerived")]
    pub contains_ai_derived: bool,
    /// Number of deterministic (non-AI) fields.
    #[serde(rename = "nucleus:deterministicFieldCount")]
    pub deterministic_field_count: usize,
    /// Number of AI-derived fields.
    #[serde(rename = "nucleus:aiDerivedFieldCount")]
    pub ai_derived_field_count: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Witness digest assertion (nucleus.witness_digest)
// ═══════════════════════════════════════════════════════════════════════════

/// Nucleus witness bundle digest assertion.
#[derive(Debug, Clone, Serialize)]
pub struct WitnessDigestAssertion {
    /// SHA-256 digest of the WitnessBundle in hex.
    pub digest: String,
    /// Algorithm used: "sha256".
    pub algorithm: String,
    /// Witness bundle ID.
    pub witness_id: String,
}

// ═══════════════════════════════════════════════════════════════════════════
// Conversion from ProvenanceOutput
// ═══════════════════════════════════════════════════════════════════════════

impl C2paActionsAssertion {
    /// Build from a ProvenanceOutput.
    pub fn from_provenance(output: &crate::provenance_output::ProvenanceOutput) -> Self {
        let actions = output
            .fields
            .iter()
            .map(|(name, field)| {
                let derivation = &field.provenance.derivation;
                let action_type = if derivation == "Deterministic" {
                    "c2pa.created" // deterministic extraction = creation from source
                } else {
                    "c2pa.edited" // AI-derived = model edited/generated
                };

                C2paAction {
                    action: action_type.into(),
                    software_agent: format!("nucleus/{}", env!("CARGO_PKG_VERSION")),
                    when: None,
                    parameters: Some(C2paActionParameters {
                        derivation: derivation.clone(),
                        field: name.clone(),
                        parser: field.provenance.parser.clone(),
                    }),
                }
            })
            .collect();

        Self { actions }
    }
}

impl AiTransparencyAssertion {
    /// Build from a ProvenanceOutput header.
    pub fn from_provenance(output: &crate::provenance_output::ProvenanceOutput) -> Self {
        let det_count = output
            .fields
            .values()
            .filter(|f| f.provenance.derivation == "Deterministic")
            .count();
        let ai_count = output
            .fields
            .values()
            .filter(|f| f.provenance.derivation == "AIDerived")
            .count();

        Self {
            context: "https://schema.org".into(),
            type_: "CreativeWork".into(),
            contains_ai_derived: output.header.contains_ai_derived,
            deterministic_field_count: det_count,
            ai_derived_field_count: ai_count,
        }
    }
}

impl WitnessDigestAssertion {
    /// Build from a witness bundle digest and ID.
    pub fn new(digest_hex: &str, witness_id: &str) -> Self {
        Self {
            digest: digest_hex.into(),
            algorithm: "sha256".into(),
            witness_id: witness_id.into(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_output() -> crate::provenance_output::ProvenanceOutput {
        use crate::provenance_output::{ProvenanceHeader, ProvenanceOutput};

        let mut output = ProvenanceOutput::new(ProvenanceHeader {
            schema_hash: "sha256:test".into(),
            schema_version: 1,
            completed_at: "2026-04-02T18:00:00Z".into(),
            receipt_chain_head: "sha256:chain".into(),
            nucleus_version: "1.0.0".into(),
            contains_ai_derived: false,
        });
        output.add_deterministic(
            "revenue",
            serde_json::json!(100),
            "h1",
            "jq",
            Some(".rev"),
            "h2",
        );
        output.add_ai_derived("summary", serde_json::json!("text"), None);
        output
    }

    #[test]
    fn actions_from_provenance() {
        let output = sample_output();
        let actions = C2paActionsAssertion::from_provenance(&output);
        assert_eq!(actions.actions.len(), 2);

        let det = actions
            .actions
            .iter()
            .find(|a| a.action == "c2pa.created")
            .unwrap();
        assert_eq!(det.parameters.as_ref().unwrap().derivation, "Deterministic");
        assert_eq!(det.parameters.as_ref().unwrap().field, "revenue");

        let ai = actions
            .actions
            .iter()
            .find(|a| a.action == "c2pa.edited")
            .unwrap();
        assert_eq!(ai.parameters.as_ref().unwrap().derivation, "AIDerived");
    }

    #[test]
    fn transparency_from_provenance() {
        let output = sample_output();
        let transparency = AiTransparencyAssertion::from_provenance(&output);
        assert!(transparency.contains_ai_derived);
        assert_eq!(transparency.deterministic_field_count, 1);
        assert_eq!(transparency.ai_derived_field_count, 1);
    }

    #[test]
    fn witness_digest_assertion() {
        let assertion = WitnessDigestAssertion::new("sha256:abc123", "wtn_test");
        assert_eq!(assertion.algorithm, "sha256");
        let json = serde_json::to_string(&assertion).unwrap();
        assert!(json.contains("sha256:abc123"));
    }

    #[test]
    fn actions_serialize_to_json() {
        let output = sample_output();
        let actions = C2paActionsAssertion::from_provenance(&output);
        let json = serde_json::to_string_pretty(&actions).unwrap();
        assert!(json.contains("c2pa.created"));
        assert!(json.contains("nucleus:derivation"));
        assert!(json.contains("softwareAgent"));
    }

    #[test]
    fn transparency_has_schema_org_context() {
        let output = sample_output();
        let t = AiTransparencyAssertion::from_provenance(&output);
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("schema.org"));
        assert!(json.contains("CreativeWork"));
    }
}
