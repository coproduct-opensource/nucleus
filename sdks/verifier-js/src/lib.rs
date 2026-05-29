//! WASM bindings for `nucleus_envelope::verify_bundle`.
//!
//! Compiled to `wasm32-unknown-unknown` and packaged as an npm
//! module via wasm-pack. Customers verify bundles in their own
//! browser / Node process — the verifier service is convenience,
//! NOT the trust root.
//!
//! # API
//!
//! ```ignore
//! import init, { verify_bundle } from "@coproduct/verifier";
//!
//! await init();
//! const report = verify_bundle(JSON.stringify(bundle), JSON.stringify(trustAnchor));
//! // report = { ok: true, edge_count, trust_domain, head_edge_hash_hex, ... }
//! ```
//!
//! # What this SDK does NOT do
//!
//! - **Produce** bundles. Producing requires a signing key + entropy —
//!   stays out of the browser by design. Use `nucleus-control-plane-server`.
//! - **Trust** the verifier service. Callers pass their own out-of-band
//!   trust JWKS; the SDK only validates the math.

use nucleus_envelope::{verify_bundle as envelope_verify_bundle, Bundle, TrustAnchor};
use nucleus_lineage::Jwks;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Activate Rust panic → console.error wiring so JS callers see real
/// stack traces instead of an opaque "unreachable". Called
/// automatically the first time `verify_bundle` runs.
fn set_panic_hook() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Wire shape for the trust anchor input. Mirrors the verifier-service
/// HTTP request shape so the same JSON works for both surfaces.
#[derive(Debug, Deserialize)]
struct TrustAnchorInput {
    /// Out-of-band JWKS. When `None`, the SDK uses self-check mode
    /// (proves internal consistency only — not provenance).
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

/// Wire shape returned to the JS caller.
#[derive(Debug, Serialize)]
struct VerifyReport {
    ok: bool,
    trust_mode: &'static str,
    trust_domain: String,
    edge_count: usize,
    checkpoint_count: usize,
    head_edge_hash_hex: String,
    schema_version: u32,
    kids: Vec<String>,
    merkle_verified: bool,
    cosignatures_verified: usize,
    matched_witness_pubkeys_hex: Vec<String>,
    payload_binding_verified: bool,
}

/// Verify a portable nucleus bundle. Throws on any verification
/// failure with a typed error message.
///
/// # Arguments
///
/// * `bundle_json` — `Bundle` serialized as JSON
/// * `trust_anchor_json` — `TrustAnchorInput` serialized as JSON
///
/// # Returns
///
/// `VerifyReport` as a JS object.
#[wasm_bindgen(js_name = verifyBundle)]
pub fn verify_bundle_js(bundle_json: &str, trust_anchor_json: &str) -> Result<JsValue, JsError> {
    set_panic_hook();

    let bundle: Bundle =
        serde_json::from_str(bundle_json).map_err(|e| JsError::new(&format!("bundle JSON: {e}")))?;
    let input: TrustAnchorInput = serde_json::from_str(trust_anchor_json)
        .map_err(|e| JsError::new(&format!("trust anchor JSON: {e}")))?;

    let mut anchor = match input.trust_jwks {
        Some(jwks) => TrustAnchor::from_jwks(jwks),
        None => TrustAnchor::self_check_only(),
    };
    if input.allow_empty {
        anchor = anchor.allow_empty();
    }
    if let Some(hex_str) = input.trust_witness_pubkey_hex {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| JsError::new(&format!("trust_witness_pubkey_hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(JsError::new(&format!(
                "trust_witness_pubkey_hex must decode to 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        anchor = anchor.with_witness_pubkey(arr);
    }
    for hex_str in &input.trusted_witnesses_hex {
        let bytes = hex::decode(hex_str.trim())
            .map_err(|e| JsError::new(&format!("trusted_witnesses_hex entry: {e}")))?;
        if bytes.len() != 32 {
            return Err(JsError::new(&format!(
                "trusted_witnesses_hex entries must decode to 32 bytes, got {}",
                bytes.len()
            )));
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

    let report =
        envelope_verify_bundle(&bundle, &anchor).map_err(|e| JsError::new(&e.to_string()))?;

    let trust_mode = if report.trust_mode_self_check_only {
        "self_check_only"
    } else {
        "out_of_band"
    };

    let wire = VerifyReport {
        ok: true,
        trust_mode,
        trust_domain: report.trust_domain.clone(),
        edge_count: report.edge_count,
        checkpoint_count: report.checkpoint_count,
        head_edge_hash_hex: report.head_edge_hash_hex.clone(),
        schema_version: bundle.envelope.meta.schema_version,
        kids: report.kids.clone(),
        merkle_verified: report.merkle_verified,
        cosignatures_verified: report.cosignatures_verified,
        matched_witness_pubkeys_hex: report.matched_witness_pubkeys_hex.clone(),
        payload_binding_verified: report.payload_binding_verified,
    };

    serde_wasm_bindgen::to_value(&wire).map_err(|e| JsError::new(&format!("serialize report: {e}")))
}

/// Returns the envelope-schema version the bundled `nucleus-envelope`
/// supports. Useful for SDK feature-detection in JS.
#[wasm_bindgen(js_name = supportedEnvelopeSchemaVersion)]
pub fn supported_envelope_schema_version() -> u32 {
    nucleus_envelope::bundle::ENVELOPE_SCHEMA_VERSION
}

/// SDK semver, exposed for "verify the SDK version" diagnostics.
#[wasm_bindgen(js_name = sdkVersion)]
pub fn sdk_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
