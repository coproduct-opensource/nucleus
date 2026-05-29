//! PyO3 bindings for `nucleus_envelope::verify_bundle`.
//!
//! Mirrors the JS SDK semantics:
//!
//! ```python
//! from nucleus_verifier import verify_bundle
//!
//! report = verify_bundle(bundle_json, trust_anchor_json)
//! assert report["ok"] is True
//! assert report["trust_domain"] == "prod.example.com"
//! ```
//!
//! What this SDK does NOT do:
//!
//! - Produce bundles. Signing keys + entropy stay server-side by
//!   design. Use `nucleus-control-plane-server`.
//! - Fetch JWKS over the network. The caller obtains the trust anchor
//!   out of band and passes it as JSON.
//! - Cache results. The caller decides retention.

use nucleus_envelope::{verify_bundle as envelope_verify_bundle, Bundle, TrustAnchor};
use nucleus_lineage::Jwks;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde::Deserialize;

/// Wire shape mirroring the JS SDK's `TrustAnchorInput` so the same
/// JSON works for both surfaces.
#[derive(Debug, Deserialize)]
struct TrustAnchorInput {
    #[serde(default)]
    trust_jwks: Option<Jwks>,
    #[serde(default)]
    allow_empty: bool,
    #[serde(default)]
    trust_witness_pubkey_hex: Option<String>,
    #[serde(default)]
    trusted_witnesses_hex: Vec<String>,
    #[serde(default)]
    cosignature_threshold: usize,
    #[serde(default)]
    require_payload_binding: bool,
}

/// Build a `TrustAnchor` from caller-supplied JSON. Decoupled from
/// the PyO3-layer so it can be unit-tested in plain Rust.
fn build_anchor(input: TrustAnchorInput) -> Result<TrustAnchor, String> {
    let mut anchor = match input.trust_jwks {
        Some(jwks) => TrustAnchor::from_jwks(jwks),
        None => TrustAnchor::self_check_only(),
    };
    if input.allow_empty {
        anchor = anchor.allow_empty();
    }
    if let Some(hex_str) = input.trust_witness_pubkey_hex {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| format!("trust_witness_pubkey_hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "trust_witness_pubkey_hex must decode to 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        anchor = anchor.with_witness_pubkey(arr);
    }
    for hex_str in &input.trusted_witnesses_hex {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| format!("trusted_witnesses_hex entry: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!(
                "trusted_witnesses_hex entries must decode to 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        anchor = anchor.with_trusted_witness(arr);
    }
    if input.cosignature_threshold > 0 {
        anchor = anchor.cosignature_threshold(input.cosignature_threshold);
    }
    if input.require_payload_binding {
        anchor = anchor.require_payload_binding();
    }
    Ok(anchor)
}

/// Verify a portable nucleus bundle.
///
/// Args:
///     bundle_json (str): `Bundle` serialized as JSON.
///     trust_anchor_json (str): trust anchor configuration as JSON.
///
/// Returns:
///     dict: verification report (see README for shape).
///
/// Raises:
///     ValueError: invalid JSON, malformed hex, or out-of-range field.
///     RuntimeError: verification rejected.
#[pyfunction]
#[pyo3(text_signature = "(bundle_json, trust_anchor_json, /)")]
fn verify_bundle(
    py: Python<'_>,
    bundle_json: &str,
    trust_anchor_json: &str,
) -> PyResult<Py<PyDict>> {
    let bundle: Bundle = serde_json::from_str(bundle_json)
        .map_err(|e| PyValueError::new_err(format!("bundle JSON: {e}")))?;
    let input: TrustAnchorInput = serde_json::from_str(trust_anchor_json)
        .map_err(|e| PyValueError::new_err(format!("trust anchor JSON: {e}")))?;
    let anchor = build_anchor(input).map_err(PyValueError::new_err)?;
    let report = envelope_verify_bundle(&bundle, &anchor)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

    let trust_mode = if report.trust_mode_self_check_only {
        "self_check_only"
    } else {
        "out_of_band"
    };

    let dict = PyDict::new(py);
    dict.set_item("ok", true)?;
    dict.set_item("trust_mode", trust_mode)?;
    dict.set_item("trust_domain", report.trust_domain.clone())?;
    dict.set_item("edge_count", report.edge_count)?;
    dict.set_item("checkpoint_count", report.checkpoint_count)?;
    dict.set_item("head_edge_hash_hex", report.head_edge_hash_hex.clone())?;
    dict.set_item("schema_version", bundle.envelope.meta.schema_version)?;
    let kids = PyList::new(py, report.kids.iter().map(String::as_str))?;
    dict.set_item("kids", kids)?;
    dict.set_item("merkle_verified", report.merkle_verified)?;
    dict.set_item("cosignatures_verified", report.cosignatures_verified)?;
    let witnesses = PyList::new(
        py,
        report.matched_witness_pubkeys_hex.iter().map(String::as_str),
    )?;
    dict.set_item("matched_witness_pubkeys_hex", witnesses)?;
    dict.set_item("payload_binding_verified", report.payload_binding_verified)?;
    Ok(dict.into())
}

/// Envelope schema version this SDK build supports.
#[pyfunction]
fn supported_envelope_schema_version() -> u32 {
    nucleus_envelope::bundle::ENVELOPE_SCHEMA_VERSION
}

/// SDK semver, for diagnostics.
#[pyfunction]
fn sdk_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn nucleus_verifier(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(verify_bundle, m)?)?;
    m.add_function(wrap_pyfunction!(supported_envelope_schema_version, m)?)?;
    m.add_function(wrap_pyfunction!(sdk_version, m)?)?;
    Ok(())
}
