//! Route handlers.

use axum::Json;
use nucleus_envelope::{verify_bundle, Bundle, TrustAnchor};
use nucleus_lineage::Jwks;
use serde::{Deserialize, Serialize};

use crate::error::VerifyApiError;

/// `GET /healthz` — liveness.
pub async fn healthz() -> &'static str {
    "ok"
}

/// `GET /` — a tiny human-readable description so a curious visitor
/// pointed at the bare host gets a useful response rather than a 404.
pub async fn root() -> &'static str {
    "nucleus-verifier-service: POST /v1/verify with {bundle, trust_jwks?, allow_empty?}; \
     see https://github.com/coproduct-opensource/nucleus for docs"
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The portable provenance bundle to verify.
    pub bundle: Bundle,
    /// JWKS to verify against. Omit (or pass `null`) for self-check
    /// mode, which proves internal consistency only, not provenance.
    #[serde(default)]
    pub trust_jwks: Option<Jwks>,
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
}

/// `POST /v1/verify` — run [`verify_bundle`] against the caller-supplied
/// trust anchor.
pub async fn verify(
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, VerifyApiError> {
    let anchor = match req.trust_jwks {
        Some(jwks) => TrustAnchor::from_jwks(jwks),
        None => TrustAnchor::self_check_only(),
    };
    let anchor = if req.allow_empty {
        anchor.allow_empty()
    } else {
        anchor
    };

    let report = verify_bundle(&req.bundle, &anchor)
        .map_err(|e| VerifyApiError::VerificationFailed(e.to_string()))?;

    let trust_mode = if report.trust_mode_self_check_only {
        "self_check_only"
    } else {
        "out_of_band"
    };

    Ok(Json(VerifyResponse {
        ok: true,
        trust_mode,
        report: ReportPayload {
            session_root: req.bundle.envelope.session_root.to_string(),
            trust_domain: report.trust_domain,
            edge_count: report.edge_count,
            kids: report.kids,
            checkpoint_count: report.checkpoint_count,
            head_edge_hash_hex: report.head_edge_hash_hex,
            schema_version: req.bundle.envelope.meta.schema_version,
        },
    }))
}
