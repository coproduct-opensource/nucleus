//! Per-field provenance attestation output format (#923).
//!
//! When a provenance schema is fully populated, this module produces a JSON
//! output where each field carries its provenance metadata — derivation class,
//! content hashes, parser ID, and receipt chain reference.
//!
//! Aligned with [AI Provenance Protocol (APP)](https://github.com/AI-Provenance-Protocol/ai-provenance-protocol)
//! and EU AI Act Article 50 requirements for machine-readable AI output marking.

use serde::Serialize;
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════════════════
// ProvenanceOutput — the attestation artifact an auditor verifies
// ═══════════════════════════════════════════════════════════════════════════

/// Top-level provenance output document.
///
/// Serializes to JSON with a `_provenance` header and per-field entries.
#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceOutput {
    /// Provenance header with schema and chain metadata.
    #[serde(rename = "_provenance")]
    pub header: ProvenanceHeader,
    /// Per-field values with provenance attestation.
    #[serde(flatten)]
    pub fields: BTreeMap<String, FieldOutput>,
}

/// Provenance header — metadata about the overall output.
#[derive(Debug, Clone, Serialize)]
pub struct ProvenanceHeader {
    /// SHA-256 hash of the schema that declared the methodology.
    pub schema_hash: String,
    /// Schema version number.
    pub schema_version: u32,
    /// ISO 8601 timestamp when the output was completed.
    pub completed_at: String,
    /// SHA-256 hash of the receipt chain head at output time.
    pub receipt_chain_head: String,
    /// Nucleus version that produced this output.
    pub nucleus_version: String,
    /// Whether any field is AI-derived (transparency flag per EU AI Act Art. 50).
    pub contains_ai_derived: bool,
}

/// A single field's value with its provenance attestation.
#[derive(Debug, Clone, Serialize)]
pub struct FieldOutput {
    /// The field's value (as a JSON value).
    pub value: serde_json::Value,
    /// Provenance metadata for this field.
    pub provenance: FieldProvenance,
}

/// Per-field provenance attestation.
#[derive(Debug, Clone, Serialize)]
pub struct FieldProvenance {
    /// Derivation class: "Deterministic" or "AIDerived".
    pub derivation: String,
    /// Authority level of the data source.
    pub authority: String,
    /// Source URL or identifier (for deterministic fields).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// SHA-256 of the source content (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_content_hash: Option<String>,
    /// Parser ID that produced the output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser: Option<String>,
    /// Parser expression (e.g., jq filter).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_expression: Option<String>,
    /// SHA-256 of the parser output (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_output_hash: Option<String>,
    /// Reference to the WitnessBundle (hex-encoded digest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_bundle_ref: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Builder
// ═══════════════════════════════════════════════════════════════════════════

impl ProvenanceOutput {
    /// Create a new empty provenance output with the given header.
    pub fn new(header: ProvenanceHeader) -> Self {
        Self {
            header,
            fields: BTreeMap::new(),
        }
    }

    /// Add a deterministic field with full provenance chain.
    pub fn add_deterministic(
        &mut self,
        name: impl Into<String>,
        value: serde_json::Value,
        source_hash: &str,
        parser: &str,
        expression: Option<&str>,
        output_hash: &str,
    ) {
        self.fields.insert(
            name.into(),
            FieldOutput {
                value,
                provenance: FieldProvenance {
                    derivation: "Deterministic".into(),
                    authority: "Directive".into(),
                    source_url: None,
                    source_content_hash: Some(source_hash.into()),
                    parser: Some(parser.into()),
                    parser_expression: expression.map(Into::into),
                    parser_output_hash: Some(output_hash.into()),
                    witness_bundle_ref: None,
                },
            },
        );
    }

    /// Add an AI-derived field with honest labeling.
    pub fn add_ai_derived(
        &mut self,
        name: impl Into<String>,
        value: serde_json::Value,
        source_hash: Option<&str>,
    ) {
        self.header.contains_ai_derived = true;
        self.fields.insert(
            name.into(),
            FieldOutput {
                value,
                provenance: FieldProvenance {
                    derivation: "AIDerived".into(),
                    authority: "Informational".into(),
                    source_url: None,
                    source_content_hash: source_hash.map(Into::into),
                    parser: None,
                    parser_expression: None,
                    parser_output_hash: None,
                    witness_bundle_ref: None,
                },
            },
        );
    }

    /// Serialize to pretty-printed JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> ProvenanceHeader {
        ProvenanceHeader {
            schema_hash: "sha256:abcd1234".into(),
            schema_version: 1,
            completed_at: "2026-04-02T18:00:00Z".into(),
            receipt_chain_head: "sha256:ef567890".into(),
            nucleus_version: "1.0.0".into(),
            contains_ai_derived: false,
        }
    }

    #[test]
    fn empty_output_serializes() {
        let output = ProvenanceOutput::new(test_header());
        let json = output.to_json().unwrap();
        assert!(json.contains("_provenance"));
        assert!(json.contains("schema_hash"));
    }

    #[test]
    fn deterministic_field_has_full_chain() {
        let mut output = ProvenanceOutput::new(test_header());
        output.add_deterministic(
            "revenue",
            serde_json::json!(383_285_000_000u64),
            "sha256:1111",
            "jq",
            Some(".hits[0].revenue"),
            "sha256:2222",
        );

        let json = output.to_json().unwrap();
        assert!(json.contains("\"derivation\": \"Deterministic\""));
        assert!(json.contains("\"parser\": \"jq\""));
        assert!(json.contains("\"parser_output_hash\": \"sha256:2222\""));
        assert!(!output.header.contains_ai_derived);
    }

    #[test]
    fn ai_derived_field_sets_transparency_flag() {
        let mut output = ProvenanceOutput::new(test_header());
        output.add_ai_derived(
            "summary",
            serde_json::json!("A summary"),
            Some("sha256:3333"),
        );

        assert!(output.header.contains_ai_derived);
        let json = output.to_json().unwrap();
        assert!(json.contains("\"derivation\": \"AIDerived\""));
        assert!(json.contains("\"contains_ai_derived\": true"));
    }

    #[test]
    fn mixed_fields_serialize_correctly() {
        let mut output = ProvenanceOutput::new(test_header());
        output.add_deterministic(
            "revenue",
            serde_json::json!(100),
            "sha256:a",
            "jq",
            None,
            "sha256:b",
        );
        output.add_ai_derived("summary", serde_json::json!("text"), None);

        let json = output.to_json().unwrap();
        // Both fields present
        assert!(json.contains("revenue"));
        assert!(json.contains("summary"));
        // Header reflects AI content
        assert!(json.contains("\"contains_ai_derived\": true"));
    }

    #[test]
    fn output_roundtrips_through_json() {
        let mut output = ProvenanceOutput::new(test_header());
        output.add_deterministic("x", serde_json::json!(42), "h1", "p1", None, "h2");

        let json = output.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // _provenance header accessible
        assert!(parsed["_provenance"]["schema_hash"].is_string());
        // Field value accessible
        assert_eq!(parsed["x"]["value"], 42);
        assert_eq!(parsed["x"]["provenance"]["derivation"], "Deterministic");
    }
}
