//! The governor declassification endpoint — the live caller of the one-shot,
//! sink-scoped token path.
//!
//! # Threat model (why this is safe on the workload-facing surface)
//!
//! The tool-proxy's HTTP/vsock surface is reachable BY THE WORKLOAD — the
//! adversary in nucleus's model. This endpoint is nonetheless safe because the
//! authority is the token's **Ed25519 signature**, verified against the
//! kernel's configured trusted keys (`NUCLEUS_DECLASSIFY_TRUSTED_KEYS`), not the
//! transport. A workload cannot forge a governor signature, so it can only
//! apply tokens a governor actually signed — and the released value is fixed by
//! the signed `target_node_id` / `rule` / `allowed_sinks`, which it cannot
//! alter without invalidating the signature. This is the same shape the
//! escalate endpoint uses (a separate principal's cryptographic identity
//! authorizes; the workload's proxy secret does not).
//!
//! Two backstops make "the adversary cannot influence which values get
//! released" (robust declassification) hold at the *who* dimension:
//!
//! * With no trusted keys configured, `apply_declassification_token` refuses
//!   outright — fail-closed, so an un-provisioned pod cannot declassify at all.
//! * No agent-reachable path may write the trusted-key set:
//!   `Kernel::set_trusted_keys` is called only at construction from the
//!   node-controlled env, never from a request handler. This is asserted by
//!   `scripts/check-declassify-governor-keys-sealed.sh`.
//!
//! The scope itself (a token clears its node only for the sinks it signed) is
//! enforced in `FlowGraph` and proven over the extracted decision core
//! (`DeclassifySinkScopeExtracted.lean`); the one-shot burn (a token applies at
//! most once) is enforced by the kernel's spent-signature ledger and proven as
//! the absorbing `declass_step` machine.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::{ApiError, AppState};
use nucleus::portcullis::declassify::{DeclassificationToken, TokenApplyResult};
use nucleus::portcullis::kernel::DenyReason;

/// Parse governor trusted keys from a comma-separated hex env value.
///
/// Malformed entries are dropped rather than crashing the pod — declassification
/// is fail-closed, so a bad key only removes a governor, never opens a hole —
/// but each drop is logged loudly so an operator typo is visible instead of
/// silently disabling a governor. Returns the accepted 32-byte keys.
pub fn governor_keys_from_env(raw: Option<&str>) -> Vec<[u8; 32]> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    for (i, entry) in raw.split(',').map(str::trim).enumerate() {
        if entry.is_empty() {
            continue;
        }
        match hex::decode(entry)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        {
            Some(k) => keys.push(k),
            None => tracing::warn!(
                index = i,
                "NUCLEUS_DECLASSIFY_TRUSTED_KEYS entry {i} is not a 32-byte hex key — \
                 rejected (that governor will be unable to declassify)"
            ),
        }
    }
    keys
}

/// A governor's request to apply a single-use declassification token.
///
/// The token carries its own Ed25519 signature; this endpoint is a thin,
/// signature-gated wrapper over `Kernel::apply_declassification_token`.
#[derive(Debug, Deserialize)]
pub(crate) struct DeclassifyRequest {
    /// The governor-signed token. Its `signature` field is what authorizes the
    /// release; every other field is bound by that signature.
    pub token: DeclassificationToken,
}

/// The outcome of a declassification attempt.
#[derive(Debug, Serialize)]
pub(crate) struct DeclassifyResponse {
    /// `true` iff the token was applied and its scope recorded.
    pub applied: bool,
    /// The node the token targeted.
    pub target_node_id: u64,
    /// The sinks the released view now reaches (the token's signed allowlist).
    pub released_for_sinks: Vec<String>,
}

/// `POST /v1/declassify` — apply a governor-signed, single-use, sink-scoped
/// declassification token to the session's flow graph.
///
/// Fail-closed at every edge: no trusted keys ⇒ refused; bad/absent signature
/// ⇒ refused; already spent ⇒ refused; node already declassified ⇒ refused.
/// None of the refusals burn the token except a successful `Applied`.
pub(crate) async fn apply_declassification(
    State(state): State<AppState>,
    Json(req): Json<DeclassifyRequest>,
) -> Result<Json<DeclassifyResponse>, ApiError> {
    // Rate-limit: a governor endpoint is a high-value target and a signature
    // verification is not free. Reuse the approval limiter.
    if !state.approval_rate_limiter.try_acquire() {
        return Err(ApiError::RateLimited);
    }

    let token = req.token;
    let sinks: Vec<String> = token
        .allowed_sinks
        .iter()
        .map(|op| op.to_string())
        .collect();
    let target = token.target_node_id;

    // Re-home (Phase 4.5): the scope must land on the session's authoritative
    // `state.flow_graph` — the graph the live egress verdict reads — not the
    // kernel's separate, never-populated `flow_graph`. Lock order MUST be
    // (kernel, then flow_graph) to match `http_kernel_decide` and the ingest
    // path, or the two lock sites could deadlock.
    let kernel = state.kernel.lock().await;
    let mut graph = state.flow_graph.lock().await;
    match kernel.apply_declassification_token_on(&mut graph, &token) {
        Ok(TokenApplyResult::Applied { .. }) => Ok(Json(DeclassifyResponse {
            applied: true,
            target_node_id: target,
            released_for_sinks: sinks,
        })),
        // Well-formed but not applied — the request was valid, the token was
        // not usable. Distinguish replay/already-declassified (409) from the
        // rest (403), so a governor can tell "spent" from "rejected".
        Ok(TokenApplyResult::AlreadyDeclassified) => Err(ApiError::DeclassificationConflict(
            format!("node {target} is already declassified"),
        )),
        Ok(TokenApplyResult::Expired { valid_until, now }) => Err(ApiError::Declassification(
            format!("token expired (valid_until={valid_until}, now={now})"),
        )),
        Ok(TokenApplyResult::PreconditionUnmet) => Err(ApiError::Declassification(
            "token rule precondition did not match the node's label".to_string(),
        )),
        Ok(TokenApplyResult::NodeNotFound) => Err(ApiError::Declassification(format!(
            "target node {target} not found in the flow graph"
        ))),
        Ok(TokenApplyResult::InvalidSignature) => Err(ApiError::Declassification(
            "token signature is missing or not signed by a trusted governor key".to_string(),
        )),
        // Value binding (Phase 3): the release does not name the specific value
        // the governor committed to — the token is unbound, the node has no
        // monitor-recorded content hash, or the recorded hash does not equal the
        // token's content_commitment. Fail-closed 403; the one-shot token was NOT
        // spent, so a governor who signs a token bound to the value actually in
        // the node can still release it. This denies steering WHICH value a
        // signed release clears (C5).
        Ok(TokenApplyResult::ContentMismatch) => Err(ApiError::Declassification(format!(
            "token content_commitment does not match the recorded value of node {target}              (unbound token, node without a recorded content hash, or a substituted value)              — release refused (fail-closed)"
        ))),
        Err(DenyReason::DeclassificationReplayed { .. }) => {
            Err(ApiError::DeclassificationConflict(format!(
                "token already spent for node {target} (one-shot)"
            )))
        }
        Err(DenyReason::InvalidDeclassification { detail }) => {
            Err(ApiError::Declassification(detail))
        }
        // Any other kernel refusal keeps the kernel's own words.
        Err(other) => Err(ApiError::Declassification(format!("{other:?}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::governor_keys_from_env;

    #[test]
    fn absent_env_yields_no_keys() {
        assert!(governor_keys_from_env(None).is_empty());
    }

    #[test]
    fn valid_hex_keys_parse() {
        let k1 = "11".repeat(32); // 32 bytes
        let k2 = "22".repeat(32);
        let raw = format!("{k1},{k2}");
        let keys = governor_keys_from_env(Some(&raw));
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], [0x11u8; 32]);
        assert_eq!(keys[1], [0x22u8; 32]);
    }

    #[test]
    fn malformed_keys_are_dropped_not_fatal() {
        // A too-short key and a non-hex entry are rejected; the valid one
        // survives. Fail-closed: a bad key removes a governor, never opens a
        // hole, and never crashes the pod.
        let good = "ab".repeat(32);
        let raw = format!("{good}, deadbeef , not-hex-!!");
        let keys = governor_keys_from_env(Some(&raw));
        assert_eq!(keys.len(), 1, "only the well-formed 32-byte key is kept");
        assert_eq!(keys[0], [0xabu8; 32]);
    }

    #[test]
    fn whitespace_and_empty_entries_ignored() {
        let good = "cd".repeat(32);
        let raw = format!("  {good}  ,,  ");
        let keys = governor_keys_from_env(Some(&raw));
        assert_eq!(keys.len(), 1);
    }
}
