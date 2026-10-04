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
    Ok(ArgsDigest::new(
        describe_body(operation, resolved, content_type, body_sha256, body_bytes).digest()?,
    ))
}

pub(crate) fn describe_body(
    operation: &str,
    resolved: &Resolved<'_>,
    content_type: &str,
    body_sha256: [u8; 32],
    body_bytes: u64,
) -> nucleus_spec::host_effect_approval::EffectRequest {
    nucleus_spec::host_effect_approval::EffectRequest {
        require_approval: false,
        operation: operation.into(),
        upstream: resolved.entry().spec().name.clone(),
        url: resolved.url().into(),
        method: METHOD.as_str().into(),
        credential_header: resolved.entry().spec().header.clone(),
        content_type: content_type.into(),
        body_sha256,
        body_bytes,
        call_charge_micro_usd: resolved
            .entry()
            .call_charge()
            .ok()
            .map(|charge| charge.micro_usd()),
    }
}

pub(super) fn capture_review(
    policy: &mut crate::host_decide::PodPolicy,
    request: &PerformRequest,
    resolved: &Resolved<'_>,
    effect: ArgsDigest,
    now: u64,
) -> Result<(), String> {
    if policy.review_requested(effect, now) {
        let metadata = describe_body(
            &request.operation,
            resolved,
            CONTENT_TYPE,
            Sha256::digest(&request.body).into(),
            request.body.len() as u64,
        );
        policy.attach_review(effect, metadata, &request.body, now)?;
    }
    Ok(())
}
