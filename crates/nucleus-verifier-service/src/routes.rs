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

/// `POST /v1/verify` — run [`verify_bundle`] against the caller-supplied
/// trust anchor.
pub async fn verify(
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
            merkle_verified: report.merkle_verified,
            cosignatures_verified: report.cosignatures_verified,
            matched_witness_pubkeys_hex: report.matched_witness_pubkeys_hex,
            payload_binding_verified: report.payload_binding_verified,
        },
    }))
}
