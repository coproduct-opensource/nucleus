//! Shared binding for buffered and staged effects, after host resolution.
//!
//! The canonical representation is derived (ADR 0007 F-1). The identity and
//! credential authority are fixed by the per-pod broker; secrets never enter
//! the digest. Justification is audit evidence, not authorization. The retry
//! key indexes this binding and is not part of the effect it names.

use nucleus_cred_protocol::PerformRequest;
use nucleus_decision_protocol::ArgsDigest;
use sha2::{Digest, Sha256};

use super::Resolved;

/// Shared with the actual HTTP caller, so the digest describes what it sends.
pub(crate) const METHOD: reqwest::Method = reqwest::Method::POST;
pub(crate) const CONTENT_TYPE: &str = "application/json";

#[derive(serde::Serialize)]
struct Effect<'a> {
    operation: &'a str,
    upstream: &'a str,
    url: &'a str,
    method: &'a str,
    credential_header: &'a str,
    content_type: &'a str,
    body_sha256: [u8; 32],
    body_bytes: u64,
    call_charge_micro_usd: Option<u64>,
}

pub(super) fn digest(
    request: &PerformRequest,
    resolved: &Resolved<'_>,
) -> Result<ArgsDigest, serde_json::Error> {
    digest_body(
        &request.operation,
        resolved,
        CONTENT_TYPE,
        Sha256::digest(&request.body).into(),
        request.body.len() as u64,
    )
}

/// Shared canonical effect for buffered and staged streaming requests.
/// `body_sha256` is calculated by the host from bytes it owns, never from OPEN.
pub(crate) fn digest_body(
    operation: &str,
    resolved: &Resolved<'_>,
    content_type: &str,
    body_sha256: [u8; 32],
    body_bytes: u64,
) -> Result<ArgsDigest, serde_json::Error> {
    let effect = Effect {
        operation,
        upstream: &resolved.entry().spec().name,
        url: resolved.url(),
        method: METHOD.as_str(),
        credential_header: &resolved.entry().spec().header,
        content_type,
        body_sha256,
        body_bytes,
        call_charge_micro_usd: resolved
            .entry()
            .call_charge()
            .ok()
            .map(|charge| charge.micro_usd()),
    };
    let mut hash = Sha256::new();
    hash.update(b"nucleus-broker-effect-v3\0");
    hash.update(serde_json::to_vec(&effect)?);
    Ok(ArgsDigest::new(hash.finalize().into()))
}
