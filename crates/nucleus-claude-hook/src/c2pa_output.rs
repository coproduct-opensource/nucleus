#![allow(clippy::disallowed_types)] // #1216: migration pending
//! C2PA sidecar emission for provenance output (#1017).
//!
//! After `provenance-output.json` is written at SessionEnd, this module
//! optionally generates a `.c2pa` sidecar manifest if a signer is configured.
//!
//! ## Configuration
//!
//! Set `NUCLEUS_C2PA_CERT` and `NUCLEUS_C2PA_KEY` environment variables
//! with PEM-encoded X.509 certificate chain and private key.
//! Optionally set `NUCLEUS_C2PA_ALG` (default: `ps256`) and `NUCLEUS_C2PA_TSA`.
//!
//! When these are absent, C2PA emission is silently skipped.

use std::path::Path;

use portcullis_core::c2pa_manifest::C2paManifestBuilder;
use portcullis_core::c2pa_signer::C2paSignerConfig;
use portcullis_core::provenance_output::ProvenanceOutput;

/// Error type for C2PA sidecar emission.
#[derive(Debug)]
pub enum C2paOutputError {
    /// Signer configuration is invalid (not missing — that's a silent skip).
    SignerConfig(String),
    /// Manifest construction failed.
    ManifestBuild(String),
    /// Signing operation failed.
    Sign(String),
    /// Failed to write sidecar file.
    Write(std::io::Error),
}

impl core::fmt::Display for C2paOutputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SignerConfig(msg) => write!(f, "C2PA signer config: {msg}"),
            Self::ManifestBuild(msg) => write!(f, "C2PA manifest build: {msg}"),
            Self::Sign(msg) => write!(f, "C2PA sign: {msg}"),
            Self::Write(e) => write!(f, "C2PA write sidecar: {e}"),
        }
    }
}

/// Attempt to emit a C2PA sidecar manifest alongside provenance output.
///
/// Returns `Ok(Some(path))` if sidecar was written, `Ok(None)` if signer
/// not configured (normal case), or `Err` on failure.
pub fn try_emit_c2pa_sidecar(
    output: &ProvenanceOutput,
    witness_digest: Option<&str>,
    output_dir: &Path,
) -> Result<Option<std::path::PathBuf>, C2paOutputError> {
    // Load signer config from env — silent no-op if not configured.
    let signer_config = match C2paSignerConfig::from_env() {
        Ok(config) => config,
        Err(portcullis_core::c2pa_signer::SignerConfigError::MissingEnv(_)) => return Ok(None),
        Err(e) => return Err(C2paOutputError::SignerConfig(e.to_string())),
    };

    // Build the C2PA manifest with all nucleus assertions.
    let manifest_builder = C2paManifestBuilder::new(output, witness_digest);
    let mut builder = manifest_builder
        .build()
        .map_err(|e| C2paOutputError::ManifestBuild(e.to_string()))?;

    // Create the signer.
    let signer = signer_config
        .create_signer()
        .map_err(|e| C2paOutputError::SignerConfig(e.to_string()))?;

    // Serialize provenance output as the "asset" for the sidecar.
    let asset_json =
        serde_json::to_vec(output).map_err(|e| C2paOutputError::ManifestBuild(e.to_string()))?;

    // Sign and produce sidecar: write manifest to .c2pa file.
    let sidecar_path = output_dir.join("provenance-output.c2pa");
    let mut source = std::io::Cursor::new(&asset_json);
    let mut dest = std::io::Cursor::new(Vec::new());

    builder
        .sign(signer.as_ref(), "application/json", &mut source, &mut dest)
        .map_err(|e| C2paOutputError::Sign(e.to_string()))?;

    std::fs::write(&sidecar_path, dest.into_inner()).map_err(C2paOutputError::Write)?;

    Ok(Some(sidecar_path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::provenance_output::ProvenanceHeader;

    #[test]
    fn skips_when_no_signer_configured() {
        let output = ProvenanceOutput::new(ProvenanceHeader {
            schema_hash: "sha256:test".into(),
            schema_version: 1,
            completed_at: "2026-04-03T18:00:00Z".into(),
            receipt_chain_head: "sha256:chain".into(),
            nucleus_version: "1.0.0".into(),
            contains_ai_derived: false,
        });
        let dir = std::env::temp_dir();
        let result = try_emit_c2pa_sidecar(&output, None, &dir);
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}
