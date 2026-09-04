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

use axum::Json;
use axum::extract::State;
use serde::{Deserialize, Serialize};

use crate::auth;
use crate::{ApiError, AppState, actor_from_auth};
use nucleus::portcullis::declassify::{DeclassificationToken, TokenApplyResult};
use nucleus::portcullis::kernel::DenyReason;
use portcullis::Operation;
use portcullis::verdict_sink::{VerdictContext, VerdictOutcome};
use std::collections::BTreeMap;
use tracing::warn;

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
    auth: Option<axum::Extension<auth::AuthContext>>,
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
    let applied = {
        let kernel = state.kernel.lock().await;
        let mut graph = state.flow_graph.lock().await;
        kernel.apply_declassification_token_on(&mut graph, &token)
    };

    let result = classify_apply_result(applied, target, &sinks);

    // Audit record (mirrors `/v1/escalate`): a declassification is the one
    // place a value's confidentiality is lowered at runtime, and it is
    // reachable by the workload, so every attempt — applied or refused — is a
    // verdict worth keeping. Recording failure is logged as an audit gap, never
    // turned into a request failure, so it cannot be used to suppress the
    // release itself.
    let outcome = match &result {
        Ok(_) => VerdictOutcome::Allow,
        Err(e) => VerdictOutcome::Deny {
            reason: e.to_string(),
        },
    };
    let mut extensions = BTreeMap::new();
    extensions.insert("target_node_id".to_string(), target.to_string());
    extensions.insert("allowed_sinks".to_string(), sinks.join(","));
    if let Err(e) = state.verdict_sink.record(VerdictContext {
        operation: Operation::ManagePods, // meta-operation: governor declassification
        subject: format!("declassify:node={target} sinks=[{}]", sinks.join(",")),
        outcome,
        actor: actor_from_auth(auth.as_ref().map(|ext| &ext.0)),
        policy_rule: Some(DECLASSIFY_POLICY_RULE.to_string()),
        extensions,
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }

    result.map(Json)
}

/// The `policy_rule` every declassification verdict is recorded under, so an
/// audit consumer can select releases without parsing the subject string.
pub(crate) const DECLASSIFY_POLICY_RULE: &str = "declassification-token";

/// Map the kernel's apply result onto the HTTP contract. Pure, so the mapping
/// (and the fact that every non-`Applied` arm is a refusal) is unit-testable
/// without a running kernel.
///
/// Well-formed but not applied — the request was valid, the token was not
/// usable. Replay/already-declassified is a 409 (`DeclassificationConflict`),
/// everything else a 403 (`Declassification`), so a governor can tell "spent"
/// from "rejected".
fn classify_apply_result(
    applied: Result<TokenApplyResult, DenyReason>,
    target: u64,
    sinks: &[String],
) -> Result<DeclassifyResponse, ApiError> {
    match applied {
        Ok(TokenApplyResult::Applied { .. }) => Ok(DeclassifyResponse {
            applied: true,
            target_node_id: target,
            released_for_sinks: sinks.to_vec(),
        }),
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
            "token content_commitment does not match the recorded value of node {target} \
             (unbound token, node without a recorded content hash, or a substituted value) \
             — release refused (fail-closed)"
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
    use super::{classify_apply_result, governor_keys_from_env};
    use nucleus::portcullis::declassify::TokenApplyResult;
    use nucleus::portcullis::kernel::DenyReason;
    use portcullis_core::IFCLabel;

    /// Every non-`Applied` kernel result is a refusal at the HTTP edge, and
    /// therefore a `Deny` verdict in the audit record; only `Applied` is an
    /// `Allow`. Replay-shaped results are the 409 conflict, the rest 403.
    #[test]
    fn only_applied_maps_to_success() {
        use crate::ApiError;
        let sinks = vec!["web_fetch".to_string()];
        let ok = classify_apply_result(
            Ok(TokenApplyResult::Applied {
                original_label: IFCLabel::default(),
                new_label: IFCLabel::default(),
            }),
            7,
            &sinks,
        )
        .expect("Applied is the one success");
        assert!(ok.applied);
        assert_eq!(ok.target_node_id, 7);
        assert_eq!(ok.released_for_sinks, sinks);

        let refusals: Vec<Result<TokenApplyResult, DenyReason>> = vec![
            Ok(TokenApplyResult::AlreadyDeclassified),
            Ok(TokenApplyResult::Expired {
                valid_until: 1,
                now: 2,
            }),
            Ok(TokenApplyResult::PreconditionUnmet),
            Ok(TokenApplyResult::NodeNotFound),
            Ok(TokenApplyResult::InvalidSignature),
            Ok(TokenApplyResult::ContentMismatch),
            Err(DenyReason::DeclassificationReplayed {
                target_node: "7".into(),
            }),
            Err(DenyReason::InvalidDeclassification {
                detail: "bad".into(),
            }),
        ];
        let n = refusals.len();
        let mut conflicts = 0;
        for r in refusals {
            match classify_apply_result(r, 7, &sinks) {
                Ok(_) => panic!("a non-Applied result must not be a success"),
                Err(ApiError::DeclassificationConflict(_)) => conflicts += 1,
                Err(ApiError::Declassification(_)) => {}
                Err(other) => panic!("unexpected error class: {other:?}"),
            }
        }
        assert_eq!(n, 8, "the refusal table must cover every arm");
        assert_eq!(
            conflicts, 2,
            "AlreadyDeclassified and Replayed are the 409s"
        );
    }

    /// Structural pin: the handler records BOTH outcomes through the shared
    /// verdict sink. The Phase-1 audit found this endpoint recorded nothing.
    #[test]
    fn handler_records_allow_and_deny_verdicts() {
        let src = include_str!("declassify.rs");
        let body = src
            .split("pub(crate) async fn apply_declassification(")
            .nth(1)
            .expect("handler present")
            .split("fn classify_apply_result(")
            .next()
            .expect("handler body ends at the classifier");
        assert!(body.contains("state.verdict_sink.record(VerdictContext {"));
        assert!(body.contains("VerdictOutcome::Allow"));
        assert!(body.contains("VerdictOutcome::Deny {"));
        assert!(
            body.contains("audit gap"),
            "a recording failure must be logged, never swallowed"
        );
    }

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
