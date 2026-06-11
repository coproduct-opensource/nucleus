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

// ── COLIMIT RECEIPT: verify the nucleus-receipt envelope ──────────────────────
//
// `verifyBundle` covers the lineage envelope; this covers the OTHER signed
// artifact — the colimit receipt (`nucleus-receipt`: Session + Projection[]
// signed Ed25519 over BLAKE3 of the RFC 8785 canonical bytes). The SDK runs the
// EXACT `Receipt::verify` everything upstream runs, so there is one verifier
// code path for every receipt kind: a receipt signed by any nucleus binary
// verifies byte-for-byte identically in the caller's browser/Node process.

/// Wire shape returned by `verifyReceipt`. A *structured verdict*: a
/// cryptographic rejection is an ordinary value the caller branches on
/// (`outcome`), not a thrown exception — only malformed *inputs* throw.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum ReceiptVerdict {
    /// Signature + root hash verified against the supplied key.
    Verified {
        version: u32,
        session_id: String,
        issuer_kid: String,
        /// Wire `kind` of every projection the signature covers, in order.
        projection_kinds: Vec<&'static str>,
        /// BLAKE3 of the canonical signing bytes (independently recomputed).
        root_hash_hex: String,
    },
    /// The envelope content does not hash to its claimed `root_hash_hex` —
    /// the session or a projection was tampered after signing.
    RootHashMismatch { expected: String, actual: String },
    /// Content is self-consistent but the Ed25519 signature does not verify
    /// under the supplied key — wrong issuer key or forged signature.
    SignatureMismatch { reason: String },
}

/// Pure core behind `verifyReceipt` — no wasm types, so native `cargo test`
/// exercises the exact logic the wasm export ships.
fn receipt_verdict(
    receipt_json: &str,
    verifying_key_bytes: &[u8],
) -> Result<ReceiptVerdict, String> {
    let receipt: nucleus_receipt::Receipt =
        serde_json::from_str(receipt_json).map_err(|e| format!("receipt JSON: {e}"))?;
    let key: [u8; 32] = verifying_key_bytes.try_into().map_err(|_| {
        format!(
            "verifying key must be 32 bytes, got {}",
            verifying_key_bytes.len()
        )
    })?;
    match receipt.verify(&key) {
        Ok(()) => Ok(ReceiptVerdict::Verified {
            version: receipt.version,
            session_id: receipt.session.session_id.clone(),
            issuer_kid: receipt.session.issuer_kid.clone(),
            projection_kinds: receipt.projections.iter().map(|p| p.kind()).collect(),
            root_hash_hex: receipt.root_hash_hex.clone(),
        }),
        Err(nucleus_receipt::ReceiptError::RootHashMismatch { expected, actual }) => {
            Ok(ReceiptVerdict::RootHashMismatch { expected, actual })
        }
        Err(nucleus_receipt::ReceiptError::SignatureMismatch(reason)) => {
            Ok(ReceiptVerdict::SignatureMismatch { reason })
        }
        // InvalidKey / InvalidSignatureEncoding (+ any future variant of the
        // non_exhaustive error): structurally unusable input → input error.
        Err(other) => Err(other.to_string()),
    }
}

/// Verify a **colimit receipt** (`nucleus-receipt` envelope) against the
/// issuer's 32-byte Ed25519 verifying key. Runs the SAME `Receipt::verify`
/// every upstream signer/verifier runs: re-canonicalizes (RFC 8785),
/// recomputes the BLAKE3 root hash, and re-verifies the signature — in the
/// caller's process, trusting no server.
///
/// # Arguments
/// * `receipt_json` — a `Receipt` serialized as JSON
///   (`{version, session, projections, root_hash_hex, signature_b64}`).
/// * `verifying_key_bytes` — the issuer's raw 32-byte Ed25519 public key
///   (as found in the issuer's JWKS `x` field, decoded).
///
/// # Returns
/// A structured verdict: `{ outcome: "verified", ... }`,
/// `{ outcome: "root_hash_mismatch", expected, actual }` (content tampered
/// after signing), or `{ outcome: "signature_mismatch", reason }` (wrong key
/// or forged signature). Throws only on malformed input (bad JSON, wrong key
/// length, undecodable signature encoding).
#[wasm_bindgen(js_name = verifyReceipt)]
pub fn verify_receipt_js(
    receipt_json: &str,
    verifying_key_bytes: &[u8],
) -> Result<JsValue, JsError> {
    set_panic_hook();
    let verdict =
        receipt_verdict(receipt_json, verifying_key_bytes).map_err(|e| JsError::new(&e))?;
    serde_wasm_bindgen::to_value(&verdict).map_err(|e| JsError::new(&e.to_string()))
}

// ── AGENT CARD: verify the counterparty's signed identity BEFORE acting ───────
//
// `verifyBundle` answers WHAT happened (provenance), `verifyReceipt` answers
// what was SIGNED — `verifyAgentCard` answers WHO you are about to act with.
// The SDK runs the EXACT `nucleus_agent_card::verify_card` every native
// recipient runs (JCS re-canonicalization + detached ES256 JWS + advertised-
// JWKS usability), against a key the caller resolved OUT-OF-BAND. The card's
// own key material is never trusted — a card verified against an attacker-
// supplied key is "verified garbage", by design.

/// Summary of a verified card's declared runtime-guarantee (IFC) profile.
/// Authentic + tamper-evident (covered by the card's JCS signature) — but
/// **attestation, not enforcement**: it proves the agent issued this exact
/// declaration, not that the rules are enforced.
#[derive(Debug, Serialize)]
struct RuntimeGuaranteeSummary {
    profile_version: String,
    tracked_sources: Vec<String>,
    /// Names of the declared IFC enforcement rules.
    enforcement_rules: Vec<String>,
    attestation_reference: Option<String>,
}

/// Wire shape returned by `verifyAgentCard`. Same convention as
/// `ReceiptVerdict`: a cryptographic rejection is an ordinary value the
/// caller branches on (`outcome`) — only malformed *inputs* throw.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum CardVerdict {
    /// The card's detached JWS verified against the resolved key and its
    /// advertised JWKS is usable as a trust anchor.
    Verified {
        spiffe_id: String,
        did: String,
        supported_envelope_schema_versions: Vec<String>,
        /// Key ids of the advertised (now trustworthy) bundle-signing JWKS.
        trust_jwks_kids: Vec<String>,
        /// The card's declared runtime-guarantee profile, if any.
        runtime_guarantees: Option<RuntimeGuaranteeSummary>,
    },
    /// Structurally well-formed, but NOT verified: no signatures, signature
    /// mismatch (wrong key / tampered card), or an unusable advertised JWKS.
    Rejected { reason: String },
}

/// Pure core behind `verifyAgentCard` — no wasm types, so native `cargo test`
/// exercises the exact logic the wasm export ships.
///
/// The caller hands us the card as RAW JSON, so verification goes through
/// `verify_card_json` — A2A §8.4.3 over *the received document*: a member
/// injected after signing is rejected even when the typed card does not
/// model it, and a card signed by a newer producer over an unmodeled
/// member still verifies.
fn agent_card_verdict(
    signed_card_json: &str,
    resolved_jwk_json: &str,
) -> Result<CardVerdict, String> {
    // Input validation up front: malformed JSON (or JSON that is not an
    // AgentCard shape) is an input ERROR the caller must fix, not a
    // cryptographic verdict.
    let _shape_check: nucleus_agent_card::AgentCard =
        serde_json::from_str(signed_card_json).map_err(|e| format!("signed card JSON: {e}"))?;
    let jwk: nucleus_agent_card::JsonWebKey =
        serde_json::from_str(resolved_jwk_json).map_err(|e| format!("resolved JWK JSON: {e}"))?;
    match nucleus_agent_card::verify_card_json(signed_card_json, &jwk) {
        Ok(verified) => Ok(CardVerdict::Verified {
            spiffe_id: verified.claims.spiffe_id.clone(),
            did: verified.claims.did.clone(),
            supported_envelope_schema_versions: verified
                .claims
                .supported_envelope_schema_versions
                .clone(),
            trust_jwks_kids: verified
                .advertised_jwks()
                .keys
                .iter()
                .map(|k| k.kid.clone())
                .collect(),
            runtime_guarantees: verified.claims.runtime_guarantees.as_ref().map(|p| {
                RuntimeGuaranteeSummary {
                    profile_version: p.profile_version.clone(),
                    tracked_sources: p.tracked_sources.clone(),
                    enforcement_rules: p.enforcement_rules.iter().map(|r| r.name.clone()).collect(),
                    attestation_reference: p.attestation_reference.clone(),
                }
            }),
        }),
        Err(e) => Ok(CardVerdict::Rejected {
            reason: e.to_string(),
        }),
    }
}

/// Verify a **signed A2A Agent Card** against a key the caller resolved
/// out-of-band (DID resolution, a pinned JWKS, an operator file). Runs the
/// SAME `verify_card` every native recipient runs — verify-before-you-act,
/// in the caller's browser/Node process, trusting no server.
///
/// # Arguments
/// * `signed_card_json` — a signed A2A v1.0 `AgentCard` serialized as JSON
///   (flat card object; JWS signatures embedded in its `signatures` field,
///   nucleus claims in its `capabilities.extensions`).
/// * `resolved_jwk_json` — the out-of-band-resolved verification key as a
///   JWK JSON (`{"kty":"EC","crv":"P-256","x":"...","y":"..."}`). NEVER
///   taken from the card itself.
///
/// # Returns
/// A structured verdict: `{ outcome: "verified", spiffe_id, did, ...,
/// runtime_guarantees }` (the runtime-guarantee profile summary is authentic
/// attestation, not enforcement) or `{ outcome: "rejected", reason }` (no
/// signatures, signature mismatch, tampered card, or unusable advertised
/// JWKS). Throws only on malformed input — distinct messages for malformed
/// card JSON vs malformed JWK JSON.
#[wasm_bindgen(js_name = verifyAgentCard)]
pub fn verify_agent_card_js(
    signed_card_json: &str,
    resolved_jwk_json: &str,
) -> Result<JsValue, JsError> {
    set_panic_hook();
    let verdict =
        agent_card_verdict(signed_card_json, resolved_jwk_json).map_err(|e| JsError::new(&e))?;
    // serialize_missing_as_null keeps the typed `runtime_guarantees:
    // RuntimeGuaranteeSummary | null` contract (undefined otherwise).
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_missing_as_null(true);
    verdict
        .serialize(&serializer)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// Wire shape returned by `verifyAgentCardSignature`. Same convention as
/// `CardVerdict`: a cryptographic rejection is a value (`outcome`), not a
/// thrown exception — only malformed *inputs* throw.
#[derive(Debug, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum CardSignatureVerdict {
    /// At least one of the card's detached JWS signatures verified against
    /// the resolved key, over the document exactly as received.
    Verified,
    /// No signatures, or no signature that both conforms to A2A §8.4.2
    /// (non-empty `kid`) and verifies against the resolved key.
    Rejected { reason: String },
}

/// Pure core behind `verifyAgentCardSignature` — no wasm types, so native
/// `cargo test` exercises the exact logic the wasm export ships.
fn agent_card_signature_verdict(
    signed_card_json: &str,
    resolved_jwk_json: &str,
) -> Result<CardSignatureVerdict, String> {
    let received: serde_json::Value =
        serde_json::from_str(signed_card_json).map_err(|e| format!("signed card JSON: {e}"))?;
    let jwk: nucleus_agent_card::JsonWebKey =
        serde_json::from_str(resolved_jwk_json).map_err(|e| format!("resolved JWK JSON: {e}"))?;
    match nucleus_agent_card::verify_card_signature_json(&received, &jwk) {
        Ok(()) => Ok(CardSignatureVerdict::Verified),
        Err(e) => Ok(CardSignatureVerdict::Rejected {
            reason: e.to_string(),
        }),
    }
}

/// Verify ONLY the **A2A v1.0 §8.4.3 signature** of an Agent Card against a
/// key the caller resolved out-of-band — no nucleus claims policy. This is
/// the interop entry point: a validly signed *plain* A2A card (no nucleus
/// extension, e.g. one published by any other A2A implementation) verifies
/// here, while `verifyAgentCard` additionally requires the nucleus claims
/// and would reject it as a policy matter.
///
/// Verification runs over the card document exactly as received (§8.4.3
/// steps 3–6 operate on "the received Agent Card"): the `signatures`
/// member is removed, every other member — including members this build
/// does not model — stays in the JCS canonical payload, and EVERY entry of
/// the `signatures` array is checked against the resolved key (§8.4.3
/// allows multiple signatures for key rotation; any one verifying
/// suffices). Same pure-Rust p256 core as `verifyAgentCard`; the card's
/// own key material (and the protected header's `kid`/`jku`) is never used
/// to select a key.
///
/// # Arguments
/// * `signed_card_json` — the signed A2A v1.0 Agent Card as received
///   (JSON; JWS signatures embedded in its `signatures` field).
/// * `resolved_jwk_json` — the out-of-band-resolved verification key as a
///   JWK JSON (`{"kty":"EC","crv":"P-256","x":"...","y":"..."}`). NEVER
///   taken from the card itself.
///
/// # Returns
/// A structured verdict: `{ outcome: "verified" }` or
/// `{ outcome: "rejected", reason }`. Throws only on malformed input —
/// distinct messages for malformed card JSON vs malformed JWK JSON.
#[wasm_bindgen(js_name = verifyAgentCardSignature)]
pub fn verify_agent_card_signature_js(
    signed_card_json: &str,
    resolved_jwk_json: &str,
) -> Result<JsValue, JsError> {
    set_panic_hook();
    let verdict = agent_card_signature_verdict(signed_card_json, resolved_jwk_json)
        .map_err(|e| JsError::new(&e))?;
    serde_wasm_bindgen::to_value(&verdict).map_err(|e| JsError::new(&e.to_string()))
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

/// Re-derive a **clearing receipt**: given a `ClearingReceipt` JSON (the declared
/// inputs + claimed outputs of a settlement / commons / VCG outcome), re-run the
/// PROVEN kernels on the inputs and report whether every claimed number matches.
/// This is `nucleus-recompute::verify_receipt` in the browser — the keystone
/// "verify, don't trust" check a relying party who never saw the auction can run.
///
/// Returns `{ outcome: "match" }`, `{ outcome: "mismatch", field, claimed,
/// recomputed }` (a MISPRICE / skimmed split / fabricated payment), or
/// `{ outcome: "invalid", reason }` (malformed inputs the kernel rejects).
#[wasm_bindgen(js_name = recomputeReceipt)]
pub fn recompute_receipt_js(receipt_json: &str) -> Result<JsValue, JsError> {
    set_panic_hook();
    let receipt: nucleus_recompute::ClearingReceipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("receipt JSON: {e}")))?;

    // RecomputeOutcome isn't Serialize (its Mismatch.field is &'static str); mirror
    // it into a wire shape with a stable `outcome` tag.
    #[derive(Serialize)]
    #[serde(tag = "outcome", rename_all = "snake_case")]
    enum OutcomeWire {
        Match,
        Mismatch {
            field: String,
            claimed: String,
            recomputed: String,
        },
        Invalid {
            reason: String,
        },
    }

    let wire = match nucleus_recompute::verify_receipt(&receipt) {
        nucleus_recompute::RecomputeOutcome::Match => OutcomeWire::Match,
        nucleus_recompute::RecomputeOutcome::Mismatch {
            field,
            claimed,
            recomputed,
        } => OutcomeWire::Mismatch {
            field: field.to_string(),
            claimed,
            recomputed,
        },
        nucleus_recompute::RecomputeOutcome::Invalid(reason) => OutcomeWire::Invalid { reason },
    };
    serde_wasm_bindgen::to_value(&wire).map_err(|e| JsError::new(&e.to_string()))
}

/// Surface the **assurance rung** of an externality profile — *how much trust*
/// each dimension's `units_micro` demands, and the profile's overall
/// (weakest-link) rung. `layers_json` is a JSON array of per-dimension
/// verification outcomes:
/// `[{ dimension, signature_ok, tee_ok, multi_source_disputed, zk_envelope_ok }]`.
///
/// Returns `{ overall_rung, dimensions: [{ dimension, rung }] }`, where each
/// `rung` is DERIVED from what actually verified (never self-asserted — an
/// unsigned dimension is `self_reported` no matter what else is attached) and
/// `overall_rung` is the **minimum** across dimensions (a profile is only as
/// trustworthy as its weakest-attested dimension). `overall_rung` is `null` for
/// an empty profile. This is the anti-greenwashing primitive: the receipt states
/// its own assurance level, checkable by anyone.
#[wasm_bindgen(js_name = recomputeAssuranceRung)]
pub fn recompute_assurance_rung_js(layers_json: &str) -> Result<JsValue, JsError> {
    set_panic_hook();

    #[derive(Deserialize)]
    struct LayerOutcome {
        dimension: String,
        #[serde(default)]
        signature_ok: bool,
        #[serde(default)]
        tee_ok: bool,
        #[serde(default)]
        multi_source_disputed: bool,
        #[serde(default)]
        zk_envelope_ok: bool,
    }
    #[derive(Serialize)]
    struct DimRung {
        dimension: String,
        rung: nucleus_externality::AssuranceRung,
    }
    #[derive(Serialize)]
    struct Report {
        overall_rung: Option<nucleus_externality::AssuranceRung>,
        dimensions: Vec<DimRung>,
    }

    let layers: Vec<LayerOutcome> = serde_json::from_str(layers_json)
        .map_err(|e| JsError::new(&format!("layers JSON: {e}")))?;
    let dimensions: Vec<DimRung> = layers
        .iter()
        .map(|l| DimRung {
            dimension: l.dimension.clone(),
            rung: nucleus_externality::assess_rung(
                l.signature_ok,
                l.tee_ok,
                l.multi_source_disputed,
                l.zk_envelope_ok,
            ),
        })
        .collect();
    // Weakest link = the rung a consumer of the receipt should actually trust.
    let overall_rung = dimensions.iter().map(|d| d.rung).min();
    // Serialize `None` as JSON `null` (not the default `undefined`) so the empty
    // profile honours the typed `overall_rung: AssuranceRung | null` contract.
    let serializer = serde_wasm_bindgen::Serializer::new().serialize_missing_as_null(true);
    Report {
        overall_rung,
        dimensions,
    }
    .serialize(&serializer)
    .map_err(|e| JsError::new(&e.to_string()))
}

// ── Reputation→capital standing (the flywheel, made actionable) ──────────────

/// Re-derive the **minimum bond** a counterparty should require of an agent, given
/// the agent's worst-case one-shot defection exposure and its (verified) reputation
/// value at risk. Runs the PROVEN `nucleus-witness-olog::required_bond`
/// (`ReputationCapital.lean`: antitone in reputation, `sybil_no_discount`, floored
/// by `under_collateralized_not_deterred`). u64 µ-amounts in/out.
///
/// This is the flywheel made actionable: more verifiable clean history ⇒ a lower
/// bond the agent must lock — recomputable by anyone, no server trust.
#[wasm_bindgen(js_name = recomputeRequiredBond)]
pub fn recompute_required_bond_js(max_defection_gain_micro: u64, reputation_micro: u64) -> u64 {
    set_panic_hook();
    nucleus_witness_olog::required_bond(max_defection_gain_micro, reputation_micro).0
}

/// Re-derive whether a posted `bond` plus `reputation_micro` (reputation value at
/// risk) deters a one-shot defection worth `max_defection_gain_micro`. Runs the
/// proven `nucleus-witness-olog::deters` (`gain ≤ bond + rep`).
#[wasm_bindgen(js_name = recomputeDeters)]
pub fn recompute_deters_js(
    bond_micro: u64,
    reputation_micro: u64,
    max_defection_gain_micro: u64,
) -> bool {
    set_panic_hook();
    nucleus_witness_olog::deters(
        nucleus_witness_olog::AmountMicro(bond_micro),
        reputation_micro,
        max_defection_gain_micro,
    )
}

// ── CREDITWORTHINESS: an agent's whole history → its required bond ─────────────
// `recomputeRequiredBond` above takes a bare `reputation_micro`. These close the
// loop: hand the SDK an agent's clearing RECEIPTS and it (1) recomputes each one
// against the proven kernels, (2) folds the honest ones up — a caught lie BURNS
// standing instead of building it — and (3) prices the bond. The full
// receipt→recompute→credit-file→bond pipeline, in-browser, trusting no server.

/// Re-derive an agent's bond-substituting **reputation** (micro-USD) from its
/// clearing receipts: each is recomputed; a Match builds standing, a Mismatch (a
/// caught defection — the recompute is the fraud proof) burns it, an Invalid
/// receipt is ignored. Returns the financial-dimension reputation (the reserved
/// Pigouvian dimension is dormant). `receipts_json` is a JSON array of
/// `ClearingReceipt`.
#[wasm_bindgen(js_name = creditReputationFromReceipts)]
pub fn credit_reputation_from_receipts_js(receipts_json: &str) -> Result<u64, JsError> {
    set_panic_hook();
    let receipts: Vec<nucleus_recompute::ClearingReceipt> = serde_json::from_str(receipts_json)
        .map_err(|e| JsError::new(&format!("receipts JSON: {e}")))?;
    Ok(nucleus_creditworthiness::mint::credit_file_from_receipts(&receipts).reputation_micro())
}

/// Re-derive the **minimum bond** an agent must post to deter a one-shot
/// defection worth `max_defection_gain_micro`, GIVEN the reputation its receipts
/// earn it. The flywheel end-to-end: more recompute-verified clean history ⇒ a
/// lower bond — computed in your process, no server trust. `receipts_json` is a
/// JSON array of `ClearingReceipt`. Composes the proven `required_bond`.
#[wasm_bindgen(js_name = requiredBondFromReceipts)]
pub fn required_bond_from_receipts_js(
    receipts_json: &str,
    max_defection_gain_micro: u64,
) -> Result<u64, JsError> {
    set_panic_hook();
    let receipts: Vec<nucleus_recompute::ClearingReceipt> = serde_json::from_str(receipts_json)
        .map_err(|e| JsError::new(&format!("receipts JSON: {e}")))?;
    Ok(
        nucleus_creditworthiness::mint::credit_file_from_receipts(&receipts)
            .required_bond(max_defection_gain_micro)
            .0,
    )
}

// ── Native tests for the receipt-verdict core ─────────────────────────────────
// The crate is also an rlib, so the wasm-free `receipt_verdict` core runs under
// plain `cargo test` on the host — sign with the real `nucleus-receipt` crate,
// verify through the SDK path. (The JsValue boundary is pinned separately by
// tests/web.rs + the Node tests against the built pkg.)
#[cfg(test)]
mod receipt_tests {
    use super::*;
    use nucleus_receipt::{Projection, Receipt, Session};

    fn signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn signed_receipt() -> Receipt {
        let session = Session {
            session_id: "spiffe://test/agent-x".into(),
            issuer_kid: "test-kid".into(),
            issued_at_micros: 1_717_000_000_000_000,
            parent_chain: vec![],
        };
        let projections = vec![
            Projection::Identity(serde_json::json!({"sub": "spiffe://test/agent-x"})),
            Projection::Economic(serde_json::json!({"price_micro_usd": 1_250_000})),
        ];
        Receipt::sign(session, projections, &signing_key())
    }

    #[test]
    fn round_trip_signed_receipt_is_verified() {
        let receipt = signed_receipt();
        let vk = signing_key().verifying_key().to_bytes();
        let json = serde_json::to_string(&receipt).unwrap();
        match receipt_verdict(&json, &vk).expect("well-formed input") {
            ReceiptVerdict::Verified {
                version,
                session_id,
                issuer_kid,
                projection_kinds,
                root_hash_hex,
            } => {
                assert_eq!(version, nucleus_receipt::RECEIPT_VERSION);
                assert_eq!(session_id, "spiffe://test/agent-x");
                assert_eq!(issuer_kid, "test-kid");
                assert_eq!(projection_kinds, vec!["identity", "economic"]);
                assert_eq!(root_hash_hex, receipt.root_hash_hex);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn tampered_projection_is_root_hash_mismatch() {
        let mut receipt = signed_receipt();
        // Inflate the claimed price after signing — the classic tamper.
        receipt.projections[1] =
            Projection::Economic(serde_json::json!({"price_micro_usd": 9_999_999}));
        let vk = signing_key().verifying_key().to_bytes();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(matches!(
            receipt_verdict(&json, &vk).expect("well-formed input"),
            ReceiptVerdict::RootHashMismatch { .. }
        ));
    }

    #[test]
    fn wrong_key_is_signature_mismatch() {
        let receipt = signed_receipt();
        let wrong_vk = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32])
            .verifying_key()
            .to_bytes();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(matches!(
            receipt_verdict(&json, &wrong_vk).expect("well-formed input"),
            ReceiptVerdict::SignatureMismatch { .. }
        ));
    }

    #[test]
    fn malformed_json_is_a_clean_input_error() {
        let vk = signing_key().verifying_key().to_bytes();
        let err = receipt_verdict("not valid json", &vk).unwrap_err();
        assert!(err.starts_with("receipt JSON:"), "got: {err}");
    }

    #[test]
    fn wrong_key_length_is_a_clean_input_error() {
        let receipt = signed_receipt();
        let json = serde_json::to_string(&receipt).unwrap();
        let err = receipt_verdict(&json, &[0u8; 31]).unwrap_err();
        assert!(err.contains("32 bytes"), "got: {err}");
        let err = receipt_verdict(&json, &[0u8; 33]).unwrap_err();
        assert!(err.contains("32 bytes"), "got: {err}");
    }

    #[test]
    fn undecodable_signature_encoding_is_an_input_error_not_a_verdict() {
        let mut receipt = signed_receipt();
        receipt.signature_b64 = "%%% not base64 %%%".into();
        let vk = signing_key().verifying_key().to_bytes();
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(receipt_verdict(&json, &vk).is_err());
    }
}

// ── Native tests for the agent-card verdict core ──────────────────────────────
// Mint+sign a REAL card via nucleus-agent-card's `sign` feature (native-only
// dev-dependency — its ring closure is exactly what verification was freed
// of), then verify through the SDK path. Gated off wasm because the signing
// dev-deps don't exist there; the JsValue boundary is pinned by tests/web.rs.
#[cfg(all(test, not(target_arch = "wasm32")))]
mod agent_card_tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use nucleus_agent_card::{
        sign_card, AgentCapabilities, AgentCard, AgentInterface, EnforcementRule, NucleusClaims,
        RuntimeGuaranteeProfile, A2A_PROTOCOL_VERSION,
    };
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    /// Fresh P-256 keypair: (PKCS#8 DER, matching public JWK as JSON).
    fn p256_keypair() -> (Vec<u8>, String) {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let der = pkcs8.as_ref().to_vec();
        let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &der, &rng).unwrap();
        // public_key() is the uncompressed EC point: 0x04 || x[32] || y[32].
        let pk = kp.public_key().as_ref();
        let jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(&pk[1..33]),
            "y": URL_SAFE_NO_PAD.encode(&pk[33..65]),
        });
        (der, jwk.to_string())
    }

    /// A usable advertised JWKS: a REAL Ed25519 verifying key (an arbitrary
    /// 32-byte string would fail point decompression in the usability check).
    fn usable_jwks() -> nucleus_lineage::Jwks {
        let vk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        nucleus_lineage::Jwks {
            keys: vec![nucleus_lineage::Jwk {
                kty: "OKP".to_string(),
                crv: Some("Ed25519".to_string()),
                kid: "issuer-k1".to_string(),
                x: Some(URL_SAFE_NO_PAD.encode(vk.to_bytes())),
                alg: Some("EdDSA".to_string()),
                use_: Some("sig".to_string()),
                not_before: None,
                not_after: None,
            }],
        }
    }

    fn sample_claims() -> NucleusClaims {
        NucleusClaims {
            spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
            did: "did:web:coder.prod.example.com".to_string(),
            supported_envelope_schema_versions: vec!["1".to_string(), "2".to_string()],
            jwks_uri: None,
            trust_jwks: usable_jwks(),
            runtime_guarantees: Some(RuntimeGuaranteeProfile {
                profile_version: "1.0".to_string(),
                tracked_sources: vec!["web_content".to_string(), "secret".to_string()],
                enforcement_rules: vec![EnforcementRule {
                    name: "no_adversarial_to_outbound".to_string(),
                    description: "deny outbound actions tainted by adversarial content".to_string(),
                }],
                attestation_reference: None,
            }),
        }
    }

    fn sample_card() -> AgentCard {
        AgentCard {
            name: "Coder Agent".to_string(),
            description: "SDK verdict-core tests".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: "https://coder.prod.example.com/a2a/v1".to_string(),
                protocol_binding: "JSONRPC".to_string(),
                tenant: None,
                protocol_version: A2A_PROTOCOL_VERSION.to_string(),
            }],
            provider: None,
            version: "1.0.0".to_string(),
            documentation_url: None,
            capabilities: AgentCapabilities::default(),
            security_schemes: serde_json::Map::new(),
            security_requirements: vec![],
            default_input_modes: vec!["application/json".to_string()],
            default_output_modes: vec!["application/json".to_string()],
            skills: vec![],
            signatures: vec![],
            icon_url: None,
        }
        .with_nucleus_claims(&sample_claims())
        .unwrap()
    }

    fn signed_card_json(der: &[u8]) -> String {
        let signed = sign_card(sample_card(), der, "card-key-1").unwrap();
        serde_json::to_string(&signed).unwrap()
    }

    #[test]
    fn round_trip_signed_card_is_verified_with_profile_summary() {
        let (der, jwk_json) = p256_keypair();
        let verdict =
            agent_card_verdict(&signed_card_json(&der), &jwk_json).expect("well-formed input");
        match verdict {
            CardVerdict::Verified {
                spiffe_id,
                did,
                supported_envelope_schema_versions,
                trust_jwks_kids,
                runtime_guarantees,
            } => {
                assert_eq!(spiffe_id, "spiffe://prod.example.com/ns/agents/sa/coder");
                assert_eq!(did, "did:web:coder.prod.example.com");
                assert_eq!(supported_envelope_schema_versions, vec!["1", "2"]);
                assert_eq!(trust_jwks_kids, vec!["issuer-k1"]);
                let prof = runtime_guarantees.expect("profile summary present");
                assert_eq!(prof.profile_version, "1.0");
                assert_eq!(prof.tracked_sources, vec!["web_content", "secret"]);
                assert_eq!(prof.enforcement_rules, vec!["no_adversarial_to_outbound"]);
                assert_eq!(prof.attestation_reference, None);
            }
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn card_without_profile_verifies_with_none_summary() {
        let (der, jwk_json) = p256_keypair();
        let mut claims = sample_claims();
        claims.runtime_guarantees = None;
        let card = sample_card().with_nucleus_claims(&claims).unwrap();
        let signed = sign_card(card, &der, "card-key-1").unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        match agent_card_verdict(&json, &jwk_json).expect("well-formed input") {
            CardVerdict::Verified {
                runtime_guarantees, ..
            } => assert!(runtime_guarantees.is_none()),
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn tampered_card_is_rejected() {
        let (der, jwk_json) = p256_keypair();
        let mut signed: AgentCard = serde_json::from_str(&signed_card_json(&der)).unwrap();
        // Mutate the claims AFTER signing — the detached JWS no longer matches.
        let mut claims = signed.nucleus_claims().unwrap().unwrap();
        claims.did = "did:web:attacker.example.com".to_string();
        signed = signed.with_nucleus_claims(&claims).unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        assert!(matches!(
            agent_card_verdict(&json, &jwk_json).expect("well-formed input"),
            CardVerdict::Rejected { .. }
        ));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let (der, _jwk_json) = p256_keypair();
        let (_other_der, other_jwk_json) = p256_keypair();
        // A perfectly valid signature by key A is worthless under key B.
        assert!(matches!(
            agent_card_verdict(&signed_card_json(&der), &other_jwk_json)
                .expect("well-formed input"),
            CardVerdict::Rejected { .. }
        ));
    }

    #[test]
    fn card_with_no_signatures_is_rejected() {
        let (_der, jwk_json) = p256_keypair();
        let unsigned = sample_card(); // signatures: []
        let json = serde_json::to_string(&unsigned).unwrap();
        match agent_card_verdict(&json, &jwk_json).expect("well-formed input") {
            CardVerdict::Rejected { reason } => {
                assert!(reason.contains("no signatures"), "got: {reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn malformed_card_json_is_a_clean_input_error() {
        let (_der, jwk_json) = p256_keypair();
        let err = agent_card_verdict("not valid json", &jwk_json).unwrap_err();
        assert!(err.starts_with("signed card JSON:"), "got: {err}");
    }

    #[test]
    fn malformed_jwk_json_is_a_clean_input_error() {
        let (der, _jwk_json) = p256_keypair();
        let card_json = signed_card_json(&der);
        // Not JSON at all.
        let err = agent_card_verdict(&card_json, "not valid json").unwrap_err();
        assert!(err.starts_with("resolved JWK JSON:"), "got: {err}");
        // Valid JSON but not a JWK (missing required fields).
        let err = agent_card_verdict(&card_json, "{}").unwrap_err();
        assert!(err.starts_with("resolved JWK JSON:"), "got: {err}");
    }

    /// A plain extension-free A2A card (signed exactly as any non-nucleus
    /// implementation would): the pure §8.4.3 path accepts it; the
    /// policy-layered path rejects it AS POLICY, not as a bad signature.
    fn plain_signed_card_json(der: &[u8]) -> String {
        let mut card = sample_card();
        card.capabilities.extensions.clear();
        let signed = sign_card(card, der, "plain-card-key-1").unwrap();
        serde_json::to_string(&signed).unwrap()
    }

    #[test]
    fn plain_card_signature_verifies_but_policy_path_rejects_it() {
        let (der, jwk_json) = p256_keypair();
        let json = plain_signed_card_json(&der);

        assert!(matches!(
            agent_card_signature_verdict(&json, &jwk_json).expect("well-formed input"),
            CardSignatureVerdict::Verified
        ));
        match agent_card_verdict(&json, &jwk_json).expect("well-formed input") {
            CardVerdict::Rejected { reason } => {
                assert!(reason.contains("nucleus claims policy"), "got: {reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn plain_card_under_the_wrong_key_is_a_signature_rejection() {
        let (der, _jwk_json) = p256_keypair();
        let (_other_der, other_jwk_json) = p256_keypair();
        let json = plain_signed_card_json(&der);
        match agent_card_signature_verdict(&json, &other_jwk_json).expect("well-formed input") {
            CardSignatureVerdict::Rejected { reason } => {
                assert!(reason.contains("JWS verification failed"), "got: {reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    /// §8.4.3 operates on the RECEIVED document: a member injected into the
    /// card JSON after signing is rejected by both card paths, even though
    /// the typed AgentCard does not model the member.
    #[test]
    fn injected_unsigned_member_is_rejected_on_both_paths() {
        let (der, jwk_json) = p256_keypair();
        let mut doc: serde_json::Value = serde_json::from_str(&signed_card_json(&der)).unwrap();
        doc.as_object_mut().unwrap().insert(
            "injectedByAttacker".to_string(),
            serde_json::json!("not covered by the signature"),
        );
        let tampered = doc.to_string();

        assert!(matches!(
            agent_card_signature_verdict(&tampered, &jwk_json).expect("well-formed input"),
            CardSignatureVerdict::Rejected { .. }
        ));
        assert!(matches!(
            agent_card_verdict(&tampered, &jwk_json).expect("well-formed input"),
            CardVerdict::Rejected { .. }
        ));
    }

    #[test]
    fn signature_path_malformed_inputs_are_clean_input_errors() {
        let (der, jwk_json) = p256_keypair();
        let err = agent_card_signature_verdict("not valid json", &jwk_json).unwrap_err();
        assert!(err.starts_with("signed card JSON:"), "got: {err}");
        let card_json = signed_card_json(&der);
        let err = agent_card_signature_verdict(&card_json, "{}").unwrap_err();
        assert!(err.starts_with("resolved JWK JSON:"), "got: {err}");
    }
}
