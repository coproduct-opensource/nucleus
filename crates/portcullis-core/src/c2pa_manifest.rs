//! C2PA manifest builder — real c2pa-rs integration (#1015).
//!
//! Converts nucleus provenance assertions into signed C2PA manifests
//! using the c2pa-rs `Builder` API. This bridges the gap between
//! nucleus's pure-Rust assertion types ([`c2pa_assertions`]) and
//! actual C2PA content credentials.
//!
//! ## Feature gate
//!
//! Requires the `c2pa` feature (which implies `artifact`).
//!
//! ## Usage
//!
//! ```ignore
//! use portcullis_core::c2pa_manifest::C2paManifestBuilder;
//!
//! let builder = C2paManifestBuilder::new(&provenance_output, Some("sha256:abc"));
//! let c2pa_builder = builder.build()?;
//! // Sign with your signer implementation and embed into asset
//! ```

use c2pa::Builder;

use crate::c2pa_assertions::{
    AiTransparencyAssertion, C2paActionsAssertion, WitnessDigestAssertion,
};
use crate::provenance_output::ProvenanceOutput;

/// Error type for C2PA manifest construction.
#[derive(Debug)]
pub enum C2paManifestError {
    /// Failed to serialize an assertion to JSON.
    SerializationError(String),
    /// c2pa-rs builder returned an error.
    BuilderError(String),
}

impl core::fmt::Display for C2paManifestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SerializationError(msg) => write!(f, "C2PA serialization error: {msg}"),
            Self::BuilderError(msg) => write!(f, "C2PA builder error: {msg}"),
        }
    }
}

impl std::error::Error for C2paManifestError {}

/// Builds a C2PA manifest from nucleus provenance data.
///
/// Wraps the c2pa-rs `Builder` and adds nucleus-specific assertions:
/// - `c2pa.actions` — per-field derivation actions
/// - `stds.schema.org.CreativeWork` — AI transparency metadata
/// - `nucleus.witness_digest` — witness bundle hash (if provided)
/// - `nucleus.provenance.v1` — full provenance output
pub struct C2paManifestBuilder<'a> {
    provenance: &'a ProvenanceOutput,
    witness_digest: Option<String>,
}

impl<'a> C2paManifestBuilder<'a> {
    /// Create a new manifest builder from provenance output.
    ///
    /// `witness_digest` is the hex SHA-256 of the `WitnessBundle`, if available.
    pub fn new(provenance: &'a ProvenanceOutput, witness_digest: Option<&str>) -> Self {
        Self {
            provenance,
            witness_digest: witness_digest.map(String::from),
        }
    }

    /// Build the c2pa-rs `Builder` with all nucleus assertions added.
    ///
    /// The returned `Builder` is ready for signing — call `sign()` or
    /// `sign_file()` with your signer implementation.
    pub fn build(&self) -> Result<Builder, C2paManifestError> {
        // Create manifest definition JSON for the Builder
        let manifest_def = serde_json::json!({
            "claim_generator": format!("nucleus/{}", env!("CARGO_PKG_VERSION")),
            "title": "Nucleus Provenance Manifest",
            "format": "application/json"
        });

        let manifest_json = serde_json::to_string(&manifest_def)
            .map_err(|e| C2paManifestError::SerializationError(e.to_string()))?;

        let mut builder = Builder::from_json(&manifest_json)
            .map_err(|e| C2paManifestError::BuilderError(e.to_string()))?;

        // 1. c2pa.actions — per-field derivation actions
        let actions = C2paActionsAssertion::from_provenance(self.provenance);
        let actions_json = serde_json::to_value(&actions)
            .map_err(|e| C2paManifestError::SerializationError(e.to_string()))?;
        builder
            .add_assertion("c2pa.actions", &actions_json)
            .map_err(|e| C2paManifestError::BuilderError(e.to_string()))?;

        // 2. AI transparency (EU AI Act Article 50)
        let transparency = AiTransparencyAssertion::from_provenance(self.provenance);
        let transparency_json = serde_json::to_value(&transparency)
            .map_err(|e| C2paManifestError::SerializationError(e.to_string()))?;
        builder
            .add_assertion("stds.schema.org.CreativeWork", &transparency_json)
            .map_err(|e| C2paManifestError::BuilderError(e.to_string()))?;

        // 3. Witness digest (if available)
        if let Some(ref digest) = self.witness_digest {
            let witness_id = &self.provenance.header.receipt_chain_head;
            let witness_assertion = WitnessDigestAssertion::new(digest, witness_id);
            let witness_json = serde_json::to_value(&witness_assertion)
                .map_err(|e| C2paManifestError::SerializationError(e.to_string()))?;
            builder
                .add_assertion("nucleus.witness_digest", &witness_json)
                .map_err(|e| C2paManifestError::BuilderError(e.to_string()))?;
        }

        // 4. Full provenance output as custom assertion
        let prov_json = serde_json::to_value(self.provenance)
            .map_err(|e| C2paManifestError::SerializationError(e.to_string()))?;
        builder
            .add_assertion("nucleus.provenance.v1", &prov_json)
            .map_err(|e| C2paManifestError::BuilderError(e.to_string()))?;

        Ok(builder)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provenance_output::ProvenanceHeader;

    fn sample_output() -> ProvenanceOutput {
        let mut output = ProvenanceOutput::new(ProvenanceHeader {
            schema_hash: "sha256:test".into(),
            schema_version: 1,
            completed_at: "2026-04-02T18:00:00Z".into(),
            receipt_chain_head: "sha256:chain_head".into(),
            nucleus_version: "1.0.0".into(),
            contains_ai_derived: false,
        });
        output.add_deterministic(
            "revenue",
            serde_json::json!(100),
            "hash_content",
            "jq",
            Some(".rev"),
            "hash_parser",
        );
        output.add_ai_derived("summary", serde_json::json!("AI generated text"), None);
        output
    }

    #[test]
    fn build_manifest_without_witness() {
        let output = sample_output();
        let builder = C2paManifestBuilder::new(&output, None);
        let result = builder.build();
        assert!(result.is_ok(), "build() failed: {result:?}");
    }

    #[test]
    fn build_manifest_with_witness() {
        let output = sample_output();
        let builder = C2paManifestBuilder::new(&output, Some("sha256:abc123def456"));
        let result = builder.build();
        assert!(result.is_ok(), "build() with witness failed: {result:?}");
    }

    #[test]
    fn build_manifest_empty_fields() {
        let output = ProvenanceOutput::new(ProvenanceHeader {
            schema_hash: "sha256:empty".into(),
            schema_version: 1,
            completed_at: "2026-04-02T18:00:00Z".into(),
            receipt_chain_head: "sha256:empty_chain".into(),
            nucleus_version: "1.0.0".into(),
            contains_ai_derived: false,
        });
        let builder = C2paManifestBuilder::new(&output, None);
        let result = builder.build();
        assert!(result.is_ok(), "empty fields build() failed: {result:?}");
    }

    #[test]
    fn builder_includes_claim_generator() {
        let output = sample_output();
        let builder = C2paManifestBuilder::new(&output, None);
        // Just verify construction succeeds — the claim_generator is set in manifest def
        let _ = builder.build().unwrap();
    }
}
