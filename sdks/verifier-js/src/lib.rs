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

    let bundle: Bundle = serde_json::from_str(bundle_json)
        .map_err(|e| JsError::new(&format!("bundle JSON: {e}")))?;
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

// ── RECOMPUTE: re-derive the IFC verdict, don't just trust the signature ──────
//
// `verifyBundle` proves a receipt was *signed*; `recomputeVerdict` proves the
// in-bounds *decision* was correct by re-running the EXACT same gate function
// (`nucleus_ifc::decision`, shared verbatim with the production seller). This is
// the structural differentiator: a verdict a counterparty can independently
// re-derive, not a vendor's signature over the vendor's own claim. Honesty:
// model-level over the DECLARED inputs (coverage-limited, per-call); fails closed
// on an unknown input token.

/// Wire shape returned by `recomputeVerdict`.
#[derive(Debug, Serialize)]
struct RecomputeReport {
    /// The independently re-derived decision.
    allow: bool,
    /// Audit reason (`"safe"` on allow, the `SafetyCheck` form on deny).
    reason: String,
    /// The (sorted, deduped) declared inputs the verdict was derived over.
    declared_inputs: Vec<String>,
    /// Canonical binding string (`allow\0inputs`) for comparison to a receipt.
    canonical: String,
}

/// Re-derive the IFC verdict from a call's declared inputs, running the same
/// `FlowDeclaration::decide` the production gate runs.
///
/// # Arguments
/// * `declared_inputs_json` — a JSON array of input tokens, e.g.
///   `["user_prompt","web_content"]` (the set carried in a receipt's verdict).
/// * `requires_authority` — whether the action requires `Directive` authority.
/// * `sink_public` — whether the response is publicly visible (vs. delivered to
///   the authenticated counterparty).
///
/// # Returns
/// A `RecomputeReport`. Throws (fails closed) if any token is unrecognised.
#[wasm_bindgen(js_name = recomputeVerdict)]
pub fn recompute_verdict_js(
    declared_inputs_json: &str,
    requires_authority: bool,
    sink_public: bool,
) -> Result<JsValue, JsError> {
    set_panic_hook();
    let tokens: Vec<String> = serde_json::from_str(declared_inputs_json)
        .map_err(|e| JsError::new(&format!("declared_inputs JSON: {e}")))?;
    let decl = nucleus_ifc::decision::FlowDeclaration::from_tokens(
        tokens.iter().map(String::as_str),
        requires_authority,
        sink_public,
    )
    .ok_or_else(|| JsError::new("unknown declared-input token (recompute fails closed)"))?;
    let verdict = decl.decide();
    let report = RecomputeReport {
        canonical: verdict.canonical(),
        allow: verdict.allow,
        reason: verdict.reason,
        declared_inputs: verdict.declared_inputs,
    };
    serde_wasm_bindgen::to_value(&report).map_err(|e| JsError::new(&e.to_string()))
}

/// Convenience: recompute and compare to a *claimed* verdict (e.g. the one bound
/// into a receipt). Returns `true` iff the re-derived `allow` + declared set
/// match. This is the one-liner that turns "trust the receipt" into "verify it".
#[wasm_bindgen(js_name = checkVerdict)]
pub fn check_verdict_js(
    declared_inputs_json: &str,
    requires_authority: bool,
    sink_public: bool,
    claimed_allow: bool,
) -> Result<bool, JsError> {
    set_panic_hook();
    let tokens: Vec<String> = serde_json::from_str(declared_inputs_json)
        .map_err(|e| JsError::new(&format!("declared_inputs JSON: {e}")))?;
    let decl = nucleus_ifc::decision::FlowDeclaration::from_tokens(
        tokens.iter().map(String::as_str),
        requires_authority,
        sink_public,
    )
    .ok_or_else(|| JsError::new("unknown declared-input token (recompute fails closed)"))?;
    Ok(decl.decide().allow == claimed_allow)
}

// ── RECOMPUTE THE CLEARED PRICE (+ Pigou) + settlement + commons routing ──────
//
// The recompute extended from the IFC verdict to the *economics*: re-derive the
// VCG clearing + truthful prices, the Pigouvian-VCG clearing (price incl. the
// externality charge), the settlement split, and where the externality pool is
// routed — all running the EXACT proven `nucleus-econ-kernels` functions
// (parity-pinned to the Lean), in the caller's process. A counterparty verifies
// the price, the externality charge, the payout, AND that the externality revenue
// reaches the commons — not a vendor's word for any of it.

/// Re-derive the truthful VCG clearing (winners + Clarke-pivot payments) from a
/// bid set. Inputs are JSON arrays of `IntegerBid` / `IntegerProposal` + a budget.
#[wasm_bindgen(js_name = recomputeVcg)]
pub fn recompute_vcg_js(
    bids_json: &str,
    proposals_json: &str,
    budget_micro_usd: u64,
) -> Result<JsValue, JsError> {
    set_panic_hook();
    let bids: Vec<nucleus_econ_kernels::IntegerBid> =
        serde_json::from_str(bids_json).map_err(|e| JsError::new(&format!("bids JSON: {e}")))?;
    let proposals: Vec<nucleus_econ_kernels::IntegerProposal> =
        serde_json::from_str(proposals_json)
            .map_err(|e| JsError::new(&format!("proposals JSON: {e}")))?;
    let clearing = nucleus_econ_kernels::run_vcg(&bids, &proposals, budget_micro_usd)
        .map_err(|e| JsError::new(&format!("vcg: {e}")))?;
    serde_wasm_bindgen::to_value(&clearing).map_err(|e| JsError::new(&e.to_string()))
}

/// Re-derive the **Pigouvian-VCG** clearing — the cleared price *including* the
/// internalised externality charge + the resulting rebate pool. `externalities`
/// is a JSON array of `ExternalityProfile`; `rates` is `PigouvianRates` JSON.
#[wasm_bindgen(js_name = recomputeVcgPigou)]
pub fn recompute_vcg_pigou_js(
    bids_json: &str,
    proposals_json: &str,
    budget_micro_usd: u64,
    externalities_json: &str,
    rates_json: &str,
) -> Result<JsValue, JsError> {
    set_panic_hook();
    let bids: Vec<nucleus_econ_kernels::IntegerBid> =
        serde_json::from_str(bids_json).map_err(|e| JsError::new(&format!("bids JSON: {e}")))?;
    let proposals: Vec<nucleus_econ_kernels::IntegerProposal> =
        serde_json::from_str(proposals_json)
            .map_err(|e| JsError::new(&format!("proposals JSON: {e}")))?;
    let externalities: Vec<nucleus_externality::ExternalityProfile> =
        serde_json::from_str(externalities_json)
            .map_err(|e| JsError::new(&format!("externalities JSON: {e}")))?;
    let rates: nucleus_econ_kernels::PigouvianRates =
        serde_json::from_str(rates_json).map_err(|e| JsError::new(&format!("rates JSON: {e}")))?;
    let clearing = nucleus_econ_kernels::run_vcg_with_externalities(
        &bids,
        &proposals,
        budget_micro_usd,
        &externalities,
        &rates,
    )
    .map_err(|e| JsError::new(&format!("pigou-vcg: {e}")))?;
    serde_wasm_bindgen::to_value(&clearing).map_err(|e| JsError::new(&e.to_string()))
}

/// Re-derive the settlement split for a cleared `price_micro` at a delivery score
/// (basis points): `{ verdict, seller_gross, refund }` with `seller_gross +
/// refund == price` (the Lean conservation theorem).
#[wasm_bindgen(js_name = recomputeSettlement)]
pub fn recompute_settlement_js(price_micro: u64, delivered_bps: u64) -> Result<JsValue, JsError> {
    set_panic_hook();
    #[derive(Serialize)]
    struct SettlementReport {
        verdict: nucleus_econ_kernels::Verdict,
        seller_gross: u64,
        refund: u64,
    }
    let report = SettlementReport {
        verdict: nucleus_econ_kernels::classify(delivered_bps),
        seller_gross: nucleus_econ_kernels::seller_gross(price_micro, delivered_bps),
        refund: nucleus_econ_kernels::refund(price_micro, delivered_bps),
    };
    serde_wasm_bindgen::to_value(&report).map_err(|e| JsError::new(&e.to_string()))
}

/// Re-derive the externality→commons routing: given the Pigouvian `pool` and a
/// JSON array of `CommonsShare`, return the allocations. Conservation (no skim) is
/// guaranteed by the kernel; the caller can sum and check it equals the pool.
#[wasm_bindgen(js_name = recomputeCommons)]
pub fn recompute_commons_js(pool_micro: u64, shares_json: &str) -> Result<JsValue, JsError> {
    set_panic_hook();
    let shares: Vec<nucleus_econ_kernels::CommonsShare> = serde_json::from_str(shares_json)
        .map_err(|e| JsError::new(&format!("shares JSON: {e}")))?;
    let allocations = nucleus_econ_kernels::route_to_commons(pool_micro, &shares)
        .map_err(|e| JsError::new(&format!("commons: {e}")))?;
    serde_wasm_bindgen::to_value(&allocations).map_err(|e| JsError::new(&e.to_string()))
}
