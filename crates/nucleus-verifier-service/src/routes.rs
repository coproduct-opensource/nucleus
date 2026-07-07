//! Route handlers.

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use nucleus_envelope::{canonical_bundle_hash, verify_bundle, Bundle, TrustAnchor};
use nucleus_lineage::Jwks;
use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::db;
use crate::error::VerifyApiError;
use crate::log as txlog;
use crate::signing::canonical_sth_bytes;
use axum::extract::Query;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

/// **HIGH-1 (#1648 / audit) fix.** Defense-in-depth cap on the number of
/// trusted-witness keys a single verify request may declare. Each entry
/// triggers Ed25519 key parsing + (in the worst case) one verify per
/// cosig in the bundle. Combined with `MAX_COSIGNATURES_PER_STH = 64`
/// from nucleus-envelope, an uncapped `trusted_witnesses_hex` lets a
/// single request force `64 * len(trusted) * (per-cosig dispatch)`
/// Ed25519 operations — pinning a verifier worker. 32 entries is well
/// past any production federation (typical 3–5 trusted witnesses).
const MAX_TRUSTED_WITNESSES_PER_REQUEST: usize = 32;

/// `GET /healthz` — liveness.
pub async fn healthz() -> &'static str {
    "ok"
}

/// Embedded marketing landing page. Static, compiled into the binary
/// so the verifier ships its own front door — no separate hosting
/// needed.
const LANDING_HTML: &str = include_str!("../static/index.html");
const LANDING_CSS: &str = include_str!("../static/style.css");
const QUICKSTART_HTML: &str = include_str!("../static/quickstart.html");
const QUICKSTART_CSS: &str = include_str!("../static/quickstart.css");
const QUICKSTART_JS: &str = include_str!("../static/quickstart.js");
/// Vendored copy of the wasm-pack-generated SDK shim. Kept in
/// `static/wasm/` so it's served from the same origin as the HTML
/// without needing a separate CDN.
const WASM_JS_SHIM: &str = include_str!("../../../sdks/verifier-js/pkg/nucleus_verifier_wasm.js");
const WASM_BINARY: &[u8] =
    include_bytes!("../../../sdks/verifier-js/pkg/nucleus_verifier_wasm_bg.wasm");

/// Strict CSP for the landing page. No `unsafe-inline` per the project
/// guidelines — only same-origin resources, no remote scripts/styles,
/// no inline JS.
const LANDING_CSP: &str = "default-src 'self'; \
                           script-src 'self'; \
                           style-src 'self'; \
                           img-src 'self' data:; \
                           connect-src 'self'; \
                           base-uri 'self'; \
                           form-action 'self'; \
                           frame-ancestors 'none'";

/// CSP for the quickstart page. Same as [`LANDING_CSP`] plus
/// `wasm-unsafe-eval` in `script-src` (required for instantiating
/// the wasm module via `WebAssembly.instantiate`). No `unsafe-eval`
/// or `unsafe-inline` — wasm-unsafe-eval is narrowly scoped to
/// WebAssembly instantiation only.
const QUICKSTART_CSP: &str = "default-src 'self'; \
                              script-src 'self' 'wasm-unsafe-eval'; \
                              style-src 'self'; \
                              img-src 'self' data:; \
                              connect-src 'self'; \
                              base-uri 'self'; \
                              form-action 'self'; \
                              frame-ancestors 'none'";

/// `GET /` — marketing landing page. HTML + CSS embedded in the
/// binary so the verifier-service ships its own front door (the docs,
/// the SDK quickstarts, the endpoint inventory) without depending on
/// external hosting.
pub async fn root() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(LANDING_CSP),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    (headers, Html(LANDING_HTML))
}

// ── #73 witness federation endpoints ──────────────────────────

#[derive(Debug, serde::Deserialize)]
pub struct PeerSthRequest {
    pub peer_pubkey_hex: String,
    pub sth_json: String,
    pub signature_b64: String,
}

/// `POST /v1/witness/peer-sth` — accept a peer-verifier cosignature
/// of an STH. The peer's pubkey must be in the configured allowlist;
/// signature is Ed25519 over `sth_json` bytes (iter-1 wire format —
/// iter-2 conforms to C2SP `cosignature/v1`).
pub async fn witness_accept_peer_sth(
    State(state): State<AppState>,
    Json(req): Json<PeerSthRequest>,
) -> Result<axum::http::StatusCode, VerifyApiError> {
    let fed = state.witness.as_ref().ok_or_else(|| {
        VerifyApiError::PersistenceDisabled(
            "witness federation disabled; configure peer allowlist to enable".into(),
        )
    })?;
    use crate::witness::WitnessError;
    match fed
        .accept(&req.peer_pubkey_hex, &req.sth_json, &req.signature_b64)
        .await
    {
        Ok(()) => Ok(axum::http::StatusCode::ACCEPTED),
        Err(WitnessError::UnknownPeer) => Err(VerifyApiError::BadRequest(
            "peer pubkey not in allowlist".to_string(),
        )),
        Err(WitnessError::BadSignature) => Err(VerifyApiError::BadRequest(
            "signature did not verify against peer pubkey".to_string(),
        )),
    }
}

/// `GET /v1/witness/peers` — return the in-memory ring of accepted
/// peer cosignatures (oldest first).
pub async fn witness_list_peers(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, VerifyApiError> {
    let fed = state
        .witness
        .as_ref()
        .ok_or_else(|| VerifyApiError::PersistenceDisabled("witness federation disabled".into()))?;
    let snap = fed.ring.read().await.snapshot();
    Ok(Json(serde_json::json!({
        "count": snap.len(),
        "cosignatures": snap,
    })))
}

/// `GET /metrics` — Prometheus exposition format.
///
/// Returns 503 when no `PrometheusHandle` is configured (the test
/// harness path; metrics are a process-global side effect so
/// production main.rs explicitly opts in).
pub async fn metrics_endpoint(State(state): State<AppState>) -> Result<Response, VerifyApiError> {
    let handle = state.metrics.as_ref().ok_or_else(|| {
        VerifyApiError::PersistenceDisabled(
            "metrics endpoint disabled; pass --metrics to enable".into(),
        )
    })?;
    let body = handle.render();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    Ok((headers, body).into_response())
}

/// `GET /quickstart` — drag-and-drop verify page using the wasm SDK.
pub async fn quickstart() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(QUICKSTART_CSP),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    (headers, Html(QUICKSTART_HTML))
}

/// Static-file helper: respond with given body + Content-Type +
/// short-lived cache.
fn static_response(body: &'static str, content_type: &'static str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    (headers, body).into_response()
}

fn static_bytes_response(body: &'static [u8], content_type: &'static str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    (headers, body).into_response()
}

/// `GET /static/style.css` — embedded CSS for the landing page.
pub async fn landing_css() -> Response {
    static_response(LANDING_CSS, "text/css; charset=utf-8")
}

/// `GET /static/quickstart.css` — quickstart-specific styles.
pub async fn quickstart_css() -> Response {
    static_response(QUICKSTART_CSS, "text/css; charset=utf-8")
}

/// `GET /static/quickstart.js` — drag-and-drop logic + wasm boot.
pub async fn quickstart_js() -> Response {
    static_response(QUICKSTART_JS, "application/javascript; charset=utf-8")
}

/// `GET /static/wasm/nucleus_verifier_wasm.js` — wasm-pack-generated
/// JS shim.
pub async fn wasm_js_shim() -> Response {
    static_response(WASM_JS_SHIM, "application/javascript; charset=utf-8")
}

/// `GET /static/wasm/nucleus_verifier_wasm_bg.wasm` — the compiled
/// verifier module.
pub async fn wasm_binary() -> Response {
    static_bytes_response(WASM_BINARY, "application/wasm")
}

#[allow(dead_code)]
fn _quickstart_css_placeholder() -> Response {
    static_response(QUICKSTART_CSS, "text/css; charset=utf-8")
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The portable provenance bundle to verify.
    pub bundle: Bundle,
    /// JWKS to verify against. Omit (or pass `null`) for self-check
    /// mode, which proves internal consistency only, not provenance.
    #[serde(default)]
    pub trust_jwks: Option<Jwks>,
    /// **v2 trust extension** (RFC 6962 / CT-style transparency-log
    /// witness): 32-byte Ed25519 verifying key of the witness that
    /// signed any `merkle_anchor.sth` in the bundle. Hex-encoded
    /// without the `0x` prefix.
    ///
    /// When omitted, bundles carrying a `merkle_anchor` are rejected
    /// (the verifier won't silently downgrade the producer's claim).
    /// When the bundle has no `merkle_anchor`, this field is ignored.
    #[serde(default)]
    pub trust_witness_pubkey_hex: Option<String>,
    /// **v2.1 witness federation.** Optional list of trusted external
    /// witness verifying keys (each 32 bytes, hex-encoded). Cosignatures
    /// from witnesses NOT in this set are ignored.
    #[serde(default)]
    pub trusted_witnesses_hex: Vec<String>,
    /// **v2.1 witness federation.** Minimum number of trusted-witness
    /// cosignatures required. Default 0 (federation optional).
    #[serde(default)]
    pub cosignature_threshold: usize,
    /// **v2.2 payload binding.** When true, reject bundles without a
    /// PayloadBinding. Default false (backwards-compat).
    #[serde(default)]
    pub require_payload_binding: bool,
    /// Accept envelopes with zero edges. Off by default — empty
    /// envelopes authenticate nothing.
    #[serde(default)]
    pub allow_empty: bool,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub ok: bool,
    /// `"out_of_band"` when a `trust_jwks` was supplied, `"self_check_only"`
    /// otherwise. A downstream auditor MUST refuse to treat
    /// `"self_check_only"` as a provenance claim.
    pub trust_mode: &'static str,
    pub report: ReportPayload,
}

/// Wire shape for the verification report. Mirrors
/// `nucleus_envelope::VerificationReport` plus a few cross-referenced
/// envelope fields.
#[derive(Debug, Serialize)]
pub struct ReportPayload {
    pub session_root: String,
    pub trust_domain: String,
    pub edge_count: usize,
    pub kids: Vec<String>,
    pub checkpoint_count: usize,
    pub head_edge_hash_hex: String,
    pub schema_version: u32,
    /// `true` if the bundle's Merkle anchor was present and verified
    /// against `trust_witness_pubkey_hex`. The strongest provenance
    /// claim this service makes; downstream consumers should require
    /// it when accepting bundles from untrusted producers.
    pub merkle_verified: bool,
    /// **v2.1.** Number of DISTINCT trusted witnesses whose
    /// cosignatures verified. ≥ the requested `cosignature_threshold`
    /// when the response is 200.
    pub cosignatures_verified: usize,
    /// **v2.1.1.** Hex-encoded public keys of the witnesses whose
    /// cosignatures verified — auditable diversity check.
    pub matched_witness_pubkeys_hex: Vec<String>,
    /// **v2.2.** `true` if the bundle carried a PayloadBinding AND
    /// it verified against the trust JWKS — proves payload integrity.
    pub payload_binding_verified: bool,
}

/// `POST /v1/clearing/verify` request: a signed clearing-receipt envelope + the
/// issuer's verifying key.
#[derive(Debug, Deserialize)]
pub struct ClearingVerifyRequest {
    /// The signed `nucleus_receipt::Receipt` carrying an economic clearing
    /// projection (e.g. from `nucleus_recompute::issue_*` + `Receipt::sign`).
    pub receipt: nucleus_receipt::Receipt,
    /// 32-byte Ed25519 verifying key of the issuer, hex-encoded (no `0x`).
    pub verifying_key_hex: String,
}

/// `POST /v1/clearing/verify` response: BOTH guarantees collapsed to one verdict.
#[derive(Debug, Serialize)]
pub struct ClearingVerifyResponse {
    /// `true` iff the signature verified AND every cleared number re-derives from
    /// the proven kernels — the only "fully verified" state.
    pub verified: bool,
    /// Machine verdict: `verified` | `bad_signature` | `malformed:<e>` |
    /// `mismatch:<field>` | `invalid:<e>`.
    pub verdict: String,
}

/// `POST /v1/clearing/verify` — the public recompute verifier for signed clearing
/// receipts. Checks the Ed25519 signature FIRST, then narrows and RECOMPUTES every
/// cleared number via the proven kernels. A signature-valid receipt with a forged
/// number is rejected (`mismatch:<field>`) — the thing a signature-only verifier
/// cannot catch. (R2 of shipping the recompute layer e2e.)
pub async fn clearing_verify(
    State(_state): State<AppState>,
    Json(req): Json<ClearingVerifyRequest>,
) -> Result<Json<ClearingVerifyResponse>, VerifyApiError> {
    use nucleus_recompute::envelope::{verify_signed_clearing, SignedClearingVerdict};
    use nucleus_recompute::RecomputeOutcome;

    let bytes = hex::decode(req.verifying_key_hex.trim().trim_start_matches("0x"))
        .map_err(|e| VerifyApiError::BadRequest(format!("verifying_key_hex invalid: {e}")))?;
    let vk: [u8; 32] = bytes.try_into().map_err(|b: Vec<u8>| {
        VerifyApiError::BadRequest(format!(
            "verifying_key_hex must decode to 32 bytes, got {}",
            b.len()
        ))
    })?;

    let (verified, verdict) = match verify_signed_clearing(&req.receipt, &vk) {
        SignedClearingVerdict::Recomputed(RecomputeOutcome::Match) => {
            (true, "verified".to_string())
        }
        SignedClearingVerdict::Recomputed(RecomputeOutcome::Mismatch { field, .. }) => {
            (false, format!("mismatch:{field}"))
        }
        SignedClearingVerdict::Recomputed(RecomputeOutcome::Invalid(m)) => {
            (false, format!("invalid:{m}"))
        }
        SignedClearingVerdict::BadSignature => (false, "bad_signature".to_string()),
        SignedClearingVerdict::Malformed(e) => (false, format!("malformed:{e}")),
    };
    Ok(Json(ClearingVerifyResponse { verified, verdict }))
}

/// `POST /v1/verify` — run [`verify_bundle`] against the caller-supplied
/// trust anchor.
///
/// When persistence is enabled ([`AppState::db`] is `Some`), the result
/// is recorded in the `verifications` table keyed by the canonical
/// bundle hash so subsequent `GET /v1/bundles/{hash}/verify` requests
/// can return the report without re-uploading the bundle. Persistence
/// is **best-effort**: a DB error doesn't fail the request, it's
/// logged via `tracing::warn` and the verify response is returned
/// unchanged.
pub async fn verify(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, VerifyApiError> {
    // Audit HIGH-4: a verifier requesting require_payload_binding=true
    // alongside the self-check path would silently produce a wrong
    // answer (self-check skips binding verification by design). Reject
    // at the API edge.
    if req.trust_jwks.is_none() && req.require_payload_binding {
        return Err(VerifyApiError::BadRequest(
            "require_payload_binding requires trust_jwks (self-check mode does not verify bindings)"
                .into(),
        ));
    }
    let anchor = match req.trust_jwks {
        Some(jwks) => TrustAnchor::from_jwks(jwks),
        None => TrustAnchor::self_check_only(),
    };
    let anchor = if req.allow_empty {
        anchor.allow_empty()
    } else {
        anchor
    };
    // Plumb the optional witness pubkey into the trust anchor. We
    // decode it here so a malformed hex string surfaces as 400 before
    // we even attempt verification.
    let anchor = match req.trust_witness_pubkey_hex {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim()).map_err(|e| {
                VerifyApiError::BadRequest(format!("trust_witness_pubkey_hex invalid: {e}"))
            })?;
            if bytes.len() != 32 {
                return Err(VerifyApiError::BadRequest(format!(
                    "trust_witness_pubkey_hex must decode to 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            anchor.with_witness_pubkey(arr)
        }
        None => anchor,
    };
    // v2.1: plumb federation parameters. Trusted witness keys are
    // decoded at the API edge so malformed inputs surface as 400.
    //
    // **HIGH-1 fix.** Cap the trusted-witness count BEFORE per-entry
    // hex decode so a hostile client can't even force the parse work.
    if req.trusted_witnesses_hex.len() > MAX_TRUSTED_WITNESSES_PER_REQUEST {
        return Err(VerifyApiError::BadRequest(format!(
            "trusted_witnesses_hex has {} entries; max {}",
            req.trusted_witnesses_hex.len(),
            MAX_TRUSTED_WITNESSES_PER_REQUEST
        )));
    }
    let mut anchor = anchor;
    for hex_str in &req.trusted_witnesses_hex {
        let bytes = hex::decode(hex_str.trim()).map_err(|e| {
            VerifyApiError::BadRequest(format!("trusted_witnesses_hex entry invalid: {e}"))
        })?;
        if bytes.len() != 32 {
            return Err(VerifyApiError::BadRequest(format!(
                "trusted_witnesses_hex entries must decode to 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        anchor = anchor.with_trusted_witness(arr);
    }
    if req.cosignature_threshold > 0 {
        anchor = anchor.cosignature_threshold(req.cosignature_threshold);
    }
    if req.require_payload_binding {
        anchor = anchor.require_payload_binding();
    }

    // Compute the canonical bundle hash BEFORE verify_bundle moves
    // ownership of the bundle — it's the primary key for the
    // `verifications` table and the URL component for the hash-lookup
    // endpoint.
    let bundle_hash_hex = hex::encode(canonical_bundle_hash(&req.bundle));

    let verify_outcome = verify_bundle(&req.bundle, &anchor);

    // Best-effort persistence: record both successes and failures so
    // the hash-lookup endpoint can return a typed answer either way.
    // DB errors are logged but never block the response — verification
    // is the load-bearing function, persistence is an observability
    // side-channel.
    if let Some(pool) = state.db.as_ref() {
        let now = chrono::Utc::now().timestamp();
        let payload_size_bytes = serde_json::to_vec(&req.bundle)
            .map(|v| v.len() as i64)
            .unwrap_or(0);
        let rec = match &verify_outcome {
            Ok(report) => db::VerificationRecord {
                envelope_hash: bundle_hash_hex.clone(),
                submitted_at: now,
                payload_size_bytes,
                ok: true,
                error_kind: None,
                report_json: serde_json::to_string(&serialize_report(&req.bundle, report)).ok(),
            },
            Err(e) => db::VerificationRecord {
                envelope_hash: bundle_hash_hex.clone(),
                submitted_at: now,
                payload_size_bytes,
                ok: false,
                error_kind: Some(error_kind_discriminant(e)),
                report_json: None,
            },
        };
        if let Err(persist_err) = db::record_verification(pool, &rec).await {
            tracing::warn!(
                envelope_hash = %bundle_hash_hex,
                error = %persist_err,
                "verifier db record_verification failed; continuing without persistence"
            );
        } else if rec.ok {
            // Only append to the transparency log for successful
            // verifications — recording a failed bundle in the
            // public log would let an attacker pollute the chain
            // with garbage entries.
            let ts_ms = chrono::Utc::now().timestamp_millis();
            match txlog::append_entry(pool, &bundle_hash_hex, ts_ms).await {
                Ok((_seq, entry_hash)) => {
                    // Mirror the append into the in-memory Merkle
                    // tree so /v1/log/sth + the proof endpoints stay
                    // in sync with the persisted chain.
                    if let Some(merkle) = state.merkle.as_ref() {
                        merkle.write().await.push(&entry_hash);
                    }
                }
                Err(log_err) => {
                    tracing::warn!(
                        envelope_hash = %bundle_hash_hex,
                        error = %log_err,
                        "verifier transparency log append failed; chain head NOT advanced"
                    );
                }
            }
        }
    }

    // Metric: total verifications, labelled by outcome. Both arms hit
    // regardless of whether persistence is enabled, so /metrics shows
    // real activity even in stateless deployments.
    let outcome_label = if verify_outcome.is_ok() { "ok" } else { "fail" };
    metrics::counter!(
        "nucleus_verifier_verifications_total",
        "result" => outcome_label
    )
    .increment(1);

    let report = verify_outcome.map_err(|e| VerifyApiError::VerificationFailed(e.to_string()))?;

    let trust_mode = if report.trust_mode_self_check_only {
        "self_check_only"
    } else {
        "out_of_band"
    };

    Ok(Json(VerifyResponse {
        ok: true,
        trust_mode,
        report: serialize_report(&req.bundle, &report),
    }))
}

/// Stable discriminant for `VerifyBundleError`. Used as the
/// `error_kind` column on persisted failure records.
///
/// Extracts the leading variant name from `Debug`. Robust against
/// future enum additions — a new variant gets a new discriminant
/// string without requiring code changes here. The trade-off is
/// that renaming a variant (which is a public-API break of
/// nucleus-envelope already) changes the discriminant string we
/// store; that's the right behavior given downstream clients are
/// already keyed off the enum's identity.
fn error_kind_discriminant(err: &nucleus_envelope::VerifyBundleError) -> String {
    let dbg = format!("{err:?}");
    dbg.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .next()
        .unwrap_or("Unknown")
        .to_string()
}

/// Helper to build the wire-shape ReportPayload from an
/// envelope-level VerificationReport + the original bundle.
fn serialize_report(
    bundle: &Bundle,
    report: &nucleus_envelope::VerificationReport,
) -> ReportPayload {
    ReportPayload {
        session_root: bundle.envelope.session_root.to_string(),
        trust_domain: report.trust_domain.clone(),
        edge_count: report.edge_count,
        kids: report.kids.clone(),
        checkpoint_count: report.checkpoint_count,
        head_edge_hash_hex: report.head_edge_hash_hex.clone(),
        schema_version: bundle.envelope.meta.schema_version,
        merkle_verified: report.merkle_verified,
        cosignatures_verified: report.cosignatures_verified,
        matched_witness_pubkeys_hex: report.matched_witness_pubkeys_hex.clone(),
        payload_binding_verified: report.payload_binding_verified,
    }
}

// ─── Transparency log endpoints (#69 iter-1) ───────────────────────

/// `GET /v1/log/size` — returns the current entry count of the
/// append-only verification log. Always succeeds (0 on empty log,
/// 503 if persistence disabled).
pub async fn log_size_endpoint(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, VerifyApiError> {
    let pool = state
        .db
        .as_ref()
        .ok_or_else(|| VerifyApiError::PersistenceDisabled("log/size requires --db".into()))?;
    let size = txlog::log_size(pool)
        .await
        .map_err(|e| VerifyApiError::Internal(format!("log_size: {e}")))?;
    Ok(Json(serde_json::json!({ "tree_size": size })))
}

/// Response shape for the STH endpoint. Signed when [`AppState::signer`]
/// is `Some`; otherwise the chain head is returned unsigned.
#[derive(Debug, Serialize)]
pub struct SthResponse {
    /// Number of entries in the log at the time of this STH.
    pub tree_size: i64,
    /// Hex-encoded chain-head hash. For an empty log this is the
    /// all-zeros sentinel. Kept for backwards-compat with iter-1
    /// clients; new clients should prefer [`Self::merkle_root_hex`].
    pub root_hash_hex: String,
    /// **Iter-3 of #69 (#95).** Hex-encoded RFC 9162 Merkle tree
    /// root. Same leaves as `root_hash_hex` but the canonical CT
    /// commitment — clients that pull inclusion/consistency proofs
    /// verify them against THIS value, not the chain head.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_root_hex: Option<String>,
    /// Wall-clock at the tip.
    pub timestamp_ms: i64,
    /// `true` when `signature` is populated by the verifier's STH
    /// signer (production posture). `false` in stateless / no-signer
    /// configurations.
    pub signed: bool,
    /// Base64 (standard) Ed25519 signature over
    /// [`canonical_sth_bytes`]`(tree_size, timestamp_ms, root_hash)`.
    /// Present iff `signed == true`. Verifies against the public key
    /// published at `/.well-known/jwks.json` whose `kid` matches the
    /// `kid` field here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<String>,
    /// JWS-style key id for signature verification. Present iff
    /// `signed == true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

/// `GET /v1/log/sth` — returns the current Signed Tree Head. When
/// the service is configured with a signer
/// ([`AppState::signer`] is `Some`), the STH is Ed25519-signed and
/// the public key is published at `/.well-known/jwks.json`. Without a
/// signer the response carries the chain head unsigned (iter-1
/// behavior).
pub async fn log_sth_endpoint(
    State(state): State<AppState>,
) -> Result<Json<SthResponse>, VerifyApiError> {
    let pool = state
        .db
        .as_ref()
        .ok_or_else(|| VerifyApiError::PersistenceDisabled("log/sth requires --db".into()))?;
    let sth = txlog::current_sth(pool)
        .await
        .map_err(|e| VerifyApiError::Internal(format!("current_sth: {e}")))?;

    let (signed, signature_b64, kid) = if let Some(signer) = state.signer.as_ref() {
        let root_bytes: [u8; 32] = hex::decode(&sth.root_hash_hex)
            .ok()
            .and_then(|v| v.as_slice().try_into().ok())
            .ok_or_else(|| VerifyApiError::Internal("STH root hash decode failed".to_string()))?;
        let canonical = canonical_sth_bytes(sth.tree_size, sth.timestamp_ms, &root_bytes);
        let sig = signer.sign(&canonical);
        (true, Some(B64.encode(sig)), Some(signer.kid().to_string()))
    } else {
        (false, None, None)
    };

    // Iter-3: surface the Merkle root when the in-memory tree is
    // available. The chain-hash root_hash_hex stays in place for
    // backward compatibility.
    let merkle_root_hex = match state.merkle.as_ref() {
        Some(merkle) => Some(merkle.read().await.root_hex()),
        None => None,
    };

    Ok(Json(SthResponse {
        tree_size: sth.tree_size,
        root_hash_hex: sth.root_hash_hex,
        merkle_root_hex,
        timestamp_ms: sth.timestamp_ms,
        signed,
        signature_b64,
        kid,
    }))
}

// ── #95 inclusion / consistency proof endpoints ────────────────

#[derive(Debug, Deserialize)]
pub struct InclusionProofQuery {
    /// 0-indexed leaf position to prove inclusion of.
    pub leaf_index: usize,
}

#[derive(Debug, Serialize)]
pub struct InclusionProofResponse {
    pub tree_size: usize,
    pub leaf_index: usize,
    /// RFC 9162 audit-path bytes, hex-encoded.
    pub proof_hex: String,
    /// Merkle root at the time of the proof. Clients verify the
    /// proof against this root.
    pub root_hex: String,
}

/// `GET /v1/log/inclusion-proof?leaf_index=N` — RFC 9162 inclusion
/// proof for leaf N against the current Merkle root.
pub async fn log_inclusion_proof(
    State(state): State<AppState>,
    Query(q): Query<InclusionProofQuery>,
) -> Result<Json<InclusionProofResponse>, VerifyApiError> {
    let merkle = state.merkle.as_ref().ok_or_else(|| {
        VerifyApiError::PersistenceDisabled("Merkle log disabled; pass --db to enable".into())
    })?;
    let guard = merkle.read().await;
    let proof = guard.inclusion_proof(q.leaf_index).ok_or_else(|| {
        VerifyApiError::NotFound(format!(
            "leaf_index {} out of range (tree_size = {})",
            q.leaf_index,
            guard.size()
        ))
    })?;
    Ok(Json(InclusionProofResponse {
        tree_size: guard.size(),
        leaf_index: q.leaf_index,
        proof_hex: hex::encode(&proof),
        root_hex: guard.root_hex(),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ConsistencyProofQuery {
    /// Prior log size the caller has anchored. Must be > 0 and ≤
    /// current `tree_size`.
    pub from: usize,
}

#[derive(Debug, Serialize)]
pub struct ConsistencyProofResponse {
    pub from_size: usize,
    pub to_size: usize,
    /// RFC 9162 consistency-proof bytes, hex-encoded.
    pub proof_hex: String,
    pub root_hex: String,
}

/// `GET /v1/log/consistency-proof?from=A` — RFC 9162 consistency
/// proof from `from` to current size. Lets a client who anchored
/// the log at `from` confirm the operator only appended (no rollback).
pub async fn log_consistency_proof(
    State(state): State<AppState>,
    Query(q): Query<ConsistencyProofQuery>,
) -> Result<Json<ConsistencyProofResponse>, VerifyApiError> {
    let merkle = state.merkle.as_ref().ok_or_else(|| {
        VerifyApiError::PersistenceDisabled("Merkle log disabled; pass --db to enable".into())
    })?;
    let guard = merkle.read().await;
    let to_size = guard.size();
    let proof = guard.consistency_proof(q.from).ok_or_else(|| {
        VerifyApiError::BadRequest(format!(
            "from={} is out of range (must be 0 < from <= tree_size = {})",
            q.from, to_size
        ))
    })?;
    Ok(Json(ConsistencyProofResponse {
        from_size: q.from,
        to_size,
        proof_hex: hex::encode(&proof),
        root_hex: guard.root_hex(),
    }))
}

/// `GET /.well-known/jwks.json` — publishes the verifier's STH
/// verifying key as a JWKS. Returns an empty `keys` array when the
/// service is running without a signer.
pub async fn well_known_jwks(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(match state.signer.as_ref() {
        Some(signer) => signer.jwks(),
        None => serde_json::json!({"keys": []}),
    })
}

/// `GET /.well-known/agent-card.json` — the service's own signed A2A
/// v1.0 Agent Card (verify-before-you-act identity document).
///
/// Returns the [`nucleus_agent_card::AgentCard`] configured in
/// [`AppState::agent_card`]. The card's detached RFC 7515 JWS (carried in
/// the card's own `signatures` field per A2A §8.4) verifies against the
/// operator's out-of-band-resolved key — NEVER against a key embedded in
/// the card. Returns 404 when no card is configured (the service makes no
/// identity claim in that mode).
pub async fn well_known_agent_card(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, VerifyApiError> {
    let card = state.agent_card.as_ref().ok_or_else(|| {
        VerifyApiError::NotFound("no agent card configured for this service".into())
    })?;
    let value = serde_json::to_value(card.as_ref())
        .map_err(|e| VerifyApiError::Internal(format!("serialize agent card: {e}")))?;
    Ok(Json(value))
}

/// `GET /.well-known/nucleus-verifier-configuration` — service
/// description document, modeled on RFC 8414 (OAuth Authorization
/// Server Metadata) and OIDC discovery conventions. SDKs read this
/// at bootstrap to auto-discover endpoints, supported envelope
/// versions, and signing posture without hardcoding URLs.
///
/// The path `/.well-known/<service>-configuration` is the convention
/// reserved by RFC 8615 for well-known URIs.
pub async fn well_known_configuration(State(state): State<AppState>) -> Json<serde_json::Value> {
    let sth_signed = state.signer.is_some();
    let persistence_enabled = state.db.is_some();
    let credit_ledger_enabled = state.credit_store.is_some();
    Json(serde_json::json!({
        "service": "nucleus-verifier",
        "service_version": env!("CARGO_PKG_VERSION"),
        "envelope_schema_version_supported": [
            nucleus_envelope::bundle::ENVELOPE_SCHEMA_VERSION,
        ],
        "jwks_uri": "/.well-known/jwks.json",
        "endpoints": {
            "verify": "/v1/verify",
            "bundle_lookup": "/v1/bundles/{hash}/verify",
            "log_size": "/v1/log/size",
            "log_sth": "/v1/log/sth",
            "credit_stateless": "/v1/credit",
            "credit_accrue": "/v1/credit/{agent_id}/accrue",
            "credit_standing": "/v1/credit/{agent_id}",
        },
        // The stateful credit endpoints. `accrue` is authenticated; `standing`
        // is a public, recomputable read. SDKs learn the auth contract here
        // without reading source.
        "credit": {
            "enabled": credit_ledger_enabled,
            "accrue_auth": {
                "scheme": "detached-ed25519",
                "note": "Sign the EXACT request body bytes; this is a detached \
                         Ed25519 signature, NOT an RFC-7515 JWS.",
                "pubkey_header": crate::auth::PUBKEY_HEADER,
                "signature_header": crate::auth::SIGNATURE_HEADER,
                "pubkey_encoding": "lowercase-hex(32-byte Ed25519 verifying key)",
                "signature_encoding": "base64-standard(64-byte Ed25519 signature)",
                "identity": "agent_id == hex(verifying_key); a path mismatch is 403",
            },
            "standing_auth": "public (no signature required)",
        },
        "sth": {
            "signed": sth_signed,
            "domain_separator": String::from_utf8_lossy(
                crate::signing::STH_DOMAIN_SEPARATOR,
            )
            .trim_end()
            .to_string(),
            "signing_algorithm": "EdDSA",
        },
        "persistence": {
            "enabled": persistence_enabled,
            "bundle_lookup_supported": persistence_enabled,
            "transparency_log_supported": persistence_enabled,
        },
        "limits": {
            // Keep these in sync with `app::MAX_BODY_BYTES` /
            // `MAX_CONCURRENT_REQUESTS` if those constants ever move.
            // Hardcoded here for the wire contract — public clients
            // shouldn't have to read our source to know our limits.
            "max_bundle_bytes": 2 * 1024 * 1024,
            "max_concurrent_requests": 256,
            "request_timeout_seconds": 30,
        },
        "security": {
            "disclosure_email": "security@coproduct.io",
        },
    }))
}

/// Response shape for the hash-lookup endpoint.
#[derive(Debug, Serialize)]
pub struct BundleLookupResponse {
    /// Hex SHA-256 of the canonical bundle hash. Echoed back so
    /// clients caching by URL can verify the response matches.
    pub envelope_hash: String,
    /// `true` if the verifier accepted the bundle when it was submitted.
    pub ok: bool,
    /// Unix-seconds timestamp of the verification.
    pub submitted_at: i64,
    /// Size of the bundle JSON in bytes (telemetry signal).
    pub payload_size_bytes: i64,
    /// Discriminant of `VerifyBundleError` when `ok=false`, omitted
    /// when `ok=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<String>,
    /// Stored `VerificationReport` (only present on successful
    /// verifications). Wire shape matches the POST response's
    /// `report` field byte-for-byte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<serde_json::Value>,
}

/// `GET /v1/bundles/{hash}/verify` — look up a previously-verified
/// bundle by its canonical SHA-256 hash. Returns:
///
/// - `200` with [`BundleLookupResponse`] when the hash is known.
/// - `404` when the hash has not been submitted.
/// - `503` when persistence is disabled (`AppState::db` is `None`).
///
/// The 503 case is intentional: returning 404 would conflate
/// "persistence disabled" with "hash not seen" and silently lie
/// about a deployment misconfiguration. Operators can sanity-check
/// `--db` by hitting this endpoint against an empty bundle hash.
pub async fn bundle_verify_lookup(
    State(state): State<AppState>,
    Path(hash): Path<String>,
) -> Result<Json<BundleLookupResponse>, VerifyApiError> {
    // Hash sanity: SHA-256 hex is 64 lowercase chars. Reject malformed
    // inputs at the API edge before touching the DB to keep a hostile
    // client from polluting query logs.
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(VerifyApiError::BadRequest(
            "envelope hash must be 64-char lowercase hex (SHA-256)".to_string(),
        ));
    }

    let pool = state.db.as_ref().ok_or_else(|| {
        VerifyApiError::PersistenceDisabled(
            "bundle hash-lookup requires --db; service is running in stateless mode".into(),
        )
    })?;

    let rec = db::fetch_verification(pool, &hash)
        .await
        .map_err(|e| VerifyApiError::Internal(format!("db: {e}")))?
        .ok_or(VerifyApiError::NotFound(hash.clone()))?;

    let report = rec
        .report_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());

    Ok(Json(BundleLookupResponse {
        envelope_hash: rec.envelope_hash,
        ok: rec.ok,
        submitted_at: rec.submitted_at,
        payload_size_bytes: rec.payload_size_bytes,
        error_kind: rec.error_kind,
        report,
    }))
}

// ── POST /v1/credit — price an agent's creditworthiness from its receipts ──────

/// Request body for [`credit`].
#[derive(Debug, Deserialize)]
pub struct CreditRequest {
    /// The agent's clearing receipts — any mix of settlement / commons / VCG.
    pub receipts: Vec<nucleus_recompute::ClearingReceipt>,
    /// The worst-case one-shot defection gain to deter, micro-USD.
    pub max_defection_gain_micro: u64,
}

/// Response for [`credit`].
#[derive(Debug, Serialize)]
pub struct CreditResponse {
    /// Bond-substituting reputation derived from the receipts (financial
    /// dimension; the reserved Pigouvian dimension is dormant), micro-USD.
    pub reputation_micro: u64,
    /// How many receipts contributed an event (`Invalid` receipts are skipped).
    pub event_count: u64,
    /// The minimum bond the agent must post to deter `max_defection_gain_micro`,
    /// given its reputation — the proven `required_bond`, in micro-USD.
    pub required_bond_micro: u64,
    /// The defection gain the bond was priced against (echoed for auditability).
    pub max_defection_gain_micro: u64,
}

/// `POST /v1/credit` — derive an agent's creditworthiness from its receipts.
///
/// Recomputes each receipt against the proven kernels, folds the honest ones
/// into a credit file (a Match builds standing, a Mismatch — a caught defection
/// — burns it, an Invalid receipt is skipped), and returns its bond-substituting
/// reputation plus the minimum bond for the declared defection gain.
///
/// **Honest scope:** stateless + a convenience. This endpoint trusts no number
/// it does not itself recompute — and the SAME result is reproducible
/// client-side with `@coproduct/verify`
/// (`creditReputationFromReceipts` / `requiredBondFromReceipts`), so the service
/// is never the trust root. Malformed JSON is rejected by the extractor (400).
pub async fn credit(Json(req): Json<CreditRequest>) -> Json<CreditResponse> {
    let file = nucleus_creditworthiness::mint::credit_file_from_receipts(&req.receipts);
    Json(CreditResponse {
        reputation_micro: file.reputation_micro(),
        event_count: file.event_count(),
        required_bond_micro: file.required_bond(req.max_defection_gain_micro).0,
        max_defection_gain_micro: req.max_defection_gain_micro,
    })
}

// ── Stateful credit ledger — POST /v1/credit/{agent_id}/accrue + GET standing ──
//
// These two endpoints are the durable counterpart of the stateless POST
// /v1/credit: they persist an agent's recompute-verified history into an
// append-only, hash-chained, per-identity ledger (redb) so standing survives a
// restart. They are live ONLY when the service is started with --credit-db
// (NUCLEUS_CREDIT_DB_PATH); otherwise both return 503 and the default,
// stateless deployment is unchanged.
//
// Auth posture: `accrue` (the write that MINTS standing) is AUTHENTICATED — it
// requires a detached Ed25519 signature over the body and keys the ledger by
// the signer's derived identity `hex(vk)` (see `crate::auth`). `GET standing`
// stays PUBLIC: standing is reputation — an append-only, verify_chain'd,
// secret-free read meant to be recomputable by anyone; only the mint needs
// identity binding. With authenticated accrual, the ledger id IS the agent's
// pubkey hex, so a reader queries standing by that same hex id.

/// Request body for [`credit_accrue`].
#[derive(Debug, Deserialize)]
pub struct CreditAccrueRequest {
    /// The agent's clearing receipts to recompute and accrue — the same type
    /// the stateless [`credit`] endpoint takes.
    pub receipts: Vec<nucleus_recompute::ClearingReceipt>,
    /// The worst-case one-shot defection gain to price the post-accrual bond
    /// against, micro-USD.
    pub max_defection_gain_micro: u64,
}

/// Response for [`credit_accrue`]: the post-accrual standing (the
/// [`CreditResponse`] fields) plus how many events were newly appended and the
/// identity's new portable head commitment.
#[derive(Debug, Serialize)]
pub struct CreditAccrueResponse {
    /// Bond-substituting reputation after this accrual, micro-USD.
    pub reputation_micro: u64,
    /// Total events folded into the identity's persisted file.
    pub event_count: u64,
    /// Minimum bond to deter `max_defection_gain_micro` at this reputation —
    /// the proven `required_bond`, micro-USD.
    pub required_bond_micro: u64,
    /// The defection gain the bond was priced against (echoed for auditability).
    pub max_defection_gain_micro: u64,
    /// How many submitted receipts minted a NEW ledger entry. Already-seen
    /// receipt hashes are deduped (counted 0), so re-POSTing the same receipts
    /// is idempotent.
    pub appended: u64,
    /// The identity's new head hash (hex) — the portable commitment a caller
    /// retains to detect a later prefix rewrite (the append-extension check).
    /// `None` only when the identity has no entries (all receipts Invalid).
    pub head_hash_hex: Option<String>,
}

/// Query string for [`credit_standing`].
#[derive(Debug, Deserialize)]
pub struct StandingQuery {
    /// The worst-case one-shot defection gain to price the bond against,
    /// micro-USD.
    pub max_defection_gain_micro: u64,
}

/// `POST /v1/credit/{agent_id}/accrue` — append an agent's recompute-verified
/// receipts to its durable, hash-chained credit ledger and return its
/// post-accrual standing.
///
/// Mints events with the SAME `mint::mint_events` the stateless endpoint uses
/// (honest receipt → credit, caught defection → debit, Invalid → skipped),
/// appends each to the per-identity chain (deduping already-seen receipt
/// hashes), then re-folds the persisted events — the crate's proven commutative
/// monoid — to price the bond. Re-POSTing the same receipts is idempotent
/// (`appended == 0`, unchanged standing).
///
/// **Identity is AUTHENTICATED.** The caller MUST present a detached Ed25519
/// signature over the EXACT request body bytes via two headers (see
/// [`crate::auth`]):
/// - `x-nucleus-agent-pubkey`: 64-char lowercase hex of the 32-byte Ed25519
///   verifying key.
/// - `x-nucleus-signature`: STANDARD base64 of the 64-byte signature over the
///   body.
///
/// The signer's own key IS the identity: the ledger is keyed by the DERIVED
/// `canonical_id = hex(vk)`, never by a caller-chosen string. The `{agent_id}`
/// path segment is retained for a self-documenting route but MUST equal the
/// derived id — a mismatch is the confused-deputy case and returns 403 with
/// nothing written. Missing / malformed / forged signatures return 401 with
/// nothing written (fail closed).
///
/// Because the id is derived from the verifying key (not chosen), an attacker
/// can mint keys but CANNOT accrue under an identity it does not control, and
/// cross-identity double-claim of a receipt is PREVENTED: re-pointing a
/// captured signed envelope at another id requires re-signing (impossible
/// without the key) and any path/id mismatch 403s. Replaying the signer's OWN
/// envelope is a harmless no-op (per-identity `receipt_hash` dedup ⇒
/// `appended == 0`). There is no nonce/expiry, so this is replay-safe-by-
/// idempotence, not replay-prevented (see [`crate::auth`]).
///
/// This is a detached Ed25519 signature (the same primitive `/v1/witness/
/// peer-sth` ships), NOT an RFC-7515 JWS, and adds no new dependency. Returns
/// 503 when `--credit-db` is unset.
///
/// **Standing is NOT yet safe to price real money.** Authenticated identity
/// closes the *spoofing* gap (you can only accrue under a key you hold), but it
/// is necessary, not sufficient. A [`nucleus_recompute::ClearingReceipt`] carries
/// no provenance: `verify_receipt` accepts any *internally self-consistent*
/// receipt, so a key can fabricate arbitrary high-value receipts and farm
/// standing without limit. And under this self-write binding the caught-defection
/// debit is adversarially unreachable (only the key-holder writes its own ledger,
/// so no counterparty can record its defection). Therefore `required_bond` from
/// this endpoint MUST NOT price real funds until receipts are provenance-bound
/// (counterparty-signed or transparency-log/settlement-anchored) and
/// authenticated defection evidence can debit standing.
pub async fn credit_accrue(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<CreditAccrueResponse>, VerifyApiError> {
    let store = state.credit_store.as_ref().ok_or_else(|| {
        VerifyApiError::PersistenceDisabled(
            "credit accrual requires --credit-db (NUCLEUS_CREDIT_DB_PATH); service is stateless"
                .into(),
        )
    })?;

    // ── Authenticated identity binding (fail closed before any write) ──
    // Require a detached Ed25519 signature over the EXACT body bytes; the
    // signer's own key IS the identity.
    let pubkey_hex = headers
        .get(crate::auth::PUBKEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            VerifyApiError::Unauthorized(format!(
                "missing or non-ASCII {} header",
                crate::auth::PUBKEY_HEADER
            ))
        })?;
    let sig_b64 = headers
        .get(crate::auth::SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            VerifyApiError::Unauthorized(format!(
                "missing or non-ASCII {} header",
                crate::auth::SIGNATURE_HEADER
            ))
        })?;
    // Verifies the signature over the body and returns the SAME key we then
    // derive the identity from (any failure ⇒ 401, no write).
    let vk = crate::auth::verify_detached_ed25519(pubkey_hex, sig_b64, &body)?;
    let canonical_id = crate::auth::canonical_id(&vk);

    // Confused-deputy guard: authenticated as key K, but the path names another
    // identity. 403, write NOTHING. Equality is over public data — no
    // constant-time compare needed.
    if agent_id != canonical_id {
        return Err(VerifyApiError::Forbidden(format!(
            "path identity {agent_id:?} does not match the signing key's identity {canonical_id:?}"
        )));
    }

    // Signature verified over these exact bytes — now parse the request body.
    let req: CreditAccrueRequest = serde_json::from_slice(&body)
        .map_err(|e| VerifyApiError::BadRequest(format!("invalid accrue body: {e}")))?;

    // Reuse the proven mint bridge — no economic logic lives in the handler.
    // The store key is the DERIVED, authenticated identity — never the raw path.
    let events = nucleus_creditworthiness::mint::mint_events(&req.receipts);
    let mut appended = 0u64;
    for event in events {
        if store
            .append(&canonical_id, event)
            .map_err(|e| VerifyApiError::Internal(format!("credit store append: {e}")))?
            .is_some()
        {
            appended += 1;
        }
    }

    // Re-fold the persisted chain (verify_chain runs inside) = post-accrual
    // standing.
    let file = store
        .credit_file(&canonical_id)
        .map_err(|e| VerifyApiError::Internal(format!("credit store read: {e}")))?;
    let head_hash_hex = store
        .head(&canonical_id)
        .map_err(|e| VerifyApiError::Internal(format!("credit store head: {e}")))?
        .map(|(_, h)| hex::encode(h));

    Ok(Json(CreditAccrueResponse {
        reputation_micro: file.reputation_micro(),
        event_count: file.event_count(),
        required_bond_micro: file.required_bond(req.max_defection_gain_micro).0,
        max_defection_gain_micro: req.max_defection_gain_micro,
        appended,
        head_hash_hex,
    }))
}

/// `GET /v1/credit/{agent_id}?max_defection_gain_micro=N` — an agent's persisted
/// credit standing, re-folded from its durable ledger.
///
/// The ledger is `verify_chain`'d before folding, so a tampered chain is refused
/// (500). Reuses [`CreditResponse`] verbatim — the durable standing is
/// value-identical to the stateless POST /v1/credit result for the same events.
///
/// PUBLIC by design (no signature required): standing is reputation — a
/// secret-free, recomputable read. Since authenticated accrual keys the ledger
/// by `hex(vk)`, `{agent_id}` here is the agent's pubkey hex. Returns 503 when
/// `--credit-db` is unset.
pub async fn credit_standing(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    Query(q): Query<StandingQuery>,
) -> Result<Json<CreditResponse>, VerifyApiError> {
    let store = state.credit_store.as_ref().ok_or_else(|| {
        VerifyApiError::PersistenceDisabled(
            "credit standing requires --credit-db (NUCLEUS_CREDIT_DB_PATH); service is stateless"
                .into(),
        )
    })?;

    let file = store
        .credit_file(&agent_id)
        .map_err(|e| VerifyApiError::Internal(format!("credit store read: {e}")))?;

    Ok(Json(CreditResponse {
        reputation_micro: file.reputation_micro(),
        event_count: file.event_count(),
        required_bond_micro: file.required_bond(q.max_defection_gain_micro).0,
        max_defection_gain_micro: q.max_defection_gain_micro,
    }))
}

#[cfg(test)]
mod credit_tests {
    use super::*;

    fn honest_settlement(
        price_micro: u64,
        delivered_bps: u64,
    ) -> nucleus_recompute::ClearingReceipt {
        use nucleus_econ_kernels::{classify, refund, seller_gross};
        nucleus_recompute::ClearingReceipt::Settlement(nucleus_recompute::SettlementClaim {
            price_micro,
            delivered_bps,
            verdict: classify(delivered_bps),
            seller_gross: seller_gross(price_micro, delivered_bps),
            refund: refund(price_micro, delivered_bps),
        })
    }

    #[tokio::test]
    async fn credit_endpoint_prices_the_bond_from_history() {
        let req = CreditRequest {
            receipts: vec![
                honest_settlement(400_000, 10_000),
                honest_settlement(300_000, 10_000),
            ],
            max_defection_gain_micro: 1_000_000,
        };
        let Json(resp) = credit(Json(req)).await;
        assert_eq!(resp.reputation_micro, 700_000);
        assert_eq!(resp.event_count, 2);
        // 1M gain − 700k verified reputation = 300k bond.
        assert_eq!(resp.required_bond_micro, 300_000);
        assert_eq!(resp.max_defection_gain_micro, 1_000_000);
    }

    #[tokio::test]
    async fn a_fresh_agent_pays_the_full_bond() {
        let req = CreditRequest {
            receipts: vec![],
            max_defection_gain_micro: 1_000_000,
        };
        let Json(resp) = credit(Json(req)).await;
        assert_eq!(resp.reputation_micro, 0);
        assert_eq!(resp.required_bond_micro, 1_000_000);
    }
}
