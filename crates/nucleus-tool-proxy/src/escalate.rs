//! Runtime permission escalation.
//!
//! Extracted from `main.rs` unchanged, to keep that file under its line ratchet.
//! The handler is a coherent unit on its own: it is the one place a pod's
//! permissions can widen at runtime, which is worth being able to find.

use axum::extract::State;
use axum::Json;

use axum::http::HeaderMap;
use tracing::warn;

use crate::auth;
use crate::{
    actor_from_auth, deserialize_trace_chain, escalation_error_to_string, now_unix,
    preset_to_permissions, EscalateRequest, EscalateResponse,
};
use nucleus::portcullis::escalation::{EscalationGrant, EscalationRequest};
use portcullis::verdict_sink::{VerdictContext, VerdictOutcome};
use portcullis::Operation;
use std::collections::BTreeMap;

use crate::{ApiError, AppState};

/// Escalate permissions for an agent using SPIFFE trace chains.
///
/// This endpoint allows agents to request elevated permissions, bounded by:
/// 1. The approver's ceiling (their trace chain's meet)
/// 2. The escalation policy's max_grant
/// 3. Time limits defined by the policy
///
/// The request must be made by an authenticated SPIFFE identity (via mTLS)
/// that matches an approver pattern in the escalation policy.
pub(crate) async fn escalate_permissions(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<EscalateRequest>,
) -> Result<Json<EscalateResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::ManagePods; // meta-operation: escalation
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Rate limit escalation requests
    if !state.approval_rate_limiter.try_acquire() {
        return Err(ApiError::RateLimited);
    }

    // SECURITY: Validate nonce to prevent replay attacks
    // This is critical - without nonce protection, an attacker can replay
    // a captured escalation request within the drand tolerance window (~60s)
    if req.nonce.is_empty() {
        return Err(ApiError::Escalation(
            "escalation nonce required".to_string(),
        ));
    }

    let now = now_unix();
    // Use a longer expiry for escalation nonces (5 minutes) since escalations
    // are higher-value targets than regular approvals
    let nonce_expiry = now + 300; // 5 minutes
    if !state
        .approval_nonces
        .check_and_insert(&req.nonce, nonce_expiry, now)
    {
        tracing::warn!(
            nonce = %req.nonce,
            "REJECTING: escalation nonce already used (potential replay attack)"
        );
        return Err(ApiError::Escalation(
            "escalation nonce already used (potential replay attack)".to_string(),
        ));
    }

    // Check if escalation policies are configured
    if !state.policy_engine.has_escalation_policies() {
        return Err(ApiError::Escalation(
            "no escalation policies configured".to_string(),
        ));
    }

    // Extract approver's SPIFFE identity from mTLS
    let approver_spiffe_id = auth_ctx
        .as_ref()
        .and_then(|a| a.spiffe_id.clone())
        .ok_or_else(|| {
            ApiError::Escalation("escalation requires SPIFFE mTLS authentication".to_string())
        })?;

    // Reconstruct the requestor's trace chain
    let requestor_chain = deserialize_trace_chain(&req.requestor_chain)?;

    // Reconstruct the approver's trace chain from the request
    // SECURITY: The approver MUST submit their full chain - we don't construct it server-side
    let approver_chain = deserialize_trace_chain(&req.approver_chain)?;

    // SECURITY: Verify the submitted approver chain's leaf matches the mTLS identity
    // This prevents an attacker from submitting someone else's chain
    let approver_chain_leaf = approver_chain.current_spiffe_id().ok_or_else(|| {
        ApiError::Escalation("approver chain must have at least one link".to_string())
    })?;

    if approver_chain_leaf != approver_spiffe_id {
        tracing::warn!(
            submitted_leaf = %approver_chain_leaf,
            authenticated_id = %approver_spiffe_id,
            "approver chain leaf does not match authenticated identity"
        );
        return Err(ApiError::Escalation(
            "approver chain leaf must match authenticated SPIFFE identity".to_string(),
        ));
    }

    // SECURITY: Verify the approver chain is valid (non-expired, monotonic)
    if !approver_chain.verify() {
        let result = approver_chain.verify_detailed();
        let reason = match result {
            portcullis::escalation::ChainVerificationResult::Invalid { reason, .. } => reason,
            _ => "unknown".to_string(),
        };
        tracing::warn!(
            chain_id = %approver_chain.id,
            reason = %reason,
            "approver chain verification failed"
        );
        return Err(ApiError::Escalation(format!(
            "approver chain is invalid: {}",
            reason
        )));
    }

    // Get the requested permissions
    let requested = preset_to_permissions(&req.requested_preset);

    // Fetch current drand round for cryptographic timestamping
    let drand_round = if let Some(ref audit_log) = state.audit.drand_client {
        match audit_log.current_round().await {
            Ok(round) => round,
            Err(e) => {
                tracing::warn!("failed to fetch drand round for escalation: {e}");
                return Err(ApiError::Escalation(
                    "failed to fetch drand round for cryptographic timestamp".to_string(),
                ));
            }
        }
    } else {
        return Err(ApiError::Escalation(
            "drand anchoring required for escalation but not configured".to_string(),
        ));
    };

    // Create the escalation request
    let escalation_request = EscalationRequest::new(
        requestor_chain.clone(),
        requested,
        &req.reason,
        req.ttl_seconds,
    );

    // Validate against escalation policies
    let policy_result = state
        .policy_engine
        .escalation_policies()
        .validate_escalation(&escalation_request, &approver_chain);

    let escalation_subject = format!(
        "escalation:{} -> {} (ttl={}s)",
        requestor_chain.current_spiffe_id().unwrap_or("unknown"),
        req.requested_preset,
        req.ttl_seconds
    );

    match policy_result {
        Ok(_policy) => {
            // Create the grant
            match EscalationGrant::new(&escalation_request, approver_chain, drand_round) {
                Ok(grant) => {
                    if let Err(e) = sink.record(VerdictContext {
                        operation,
                        subject: escalation_subject,
                        outcome: VerdictOutcome::Allow,
                        actor,
                        policy_rule: None,
                        extensions: BTreeMap::new(),
                    }) {
                        warn!(error = %e, "verdict recording failed -- audit gap");
                    }

                    tracing::info!(
                        requestor = %requestor_chain.current_spiffe_id().unwrap_or("unknown"),
                        approver = %approver_spiffe_id,
                        preset = %req.requested_preset,
                        ttl_seconds = %req.ttl_seconds,
                        drand_round = %drand_round,
                        grant_id = %grant.id,
                        event = "escalation_granted",
                        "escalation request approved"
                    );

                    Ok(Json(EscalateResponse {
                        granted: true,
                        grant_id: Some(grant.id.to_string()),
                        granted_preset: Some(req.requested_preset.clone()),
                        expires_at: Some(grant.expires_at.timestamp() as u64),
                        drand_round: Some(drand_round),
                        error: None,
                    }))
                }
                Err(e) => {
                    let error_msg = escalation_error_to_string(&e);

                    if let Err(e) = sink.record(VerdictContext {
                        operation,
                        subject: escalation_subject,
                        outcome: VerdictOutcome::Deny {
                            reason: error_msg.clone(),
                        },
                        actor,
                        policy_rule: None,
                        extensions: BTreeMap::new(),
                    }) {
                        warn!(error = %e, "verdict recording failed -- audit gap");
                    }

                    tracing::warn!(
                        requestor = %requestor_chain.current_spiffe_id().unwrap_or("unknown"),
                        approver = %approver_spiffe_id,
                        error = %error_msg,
                        event = "escalation_denied",
                        "escalation grant creation failed"
                    );

                    Ok(Json(EscalateResponse {
                        granted: false,
                        grant_id: None,
                        granted_preset: None,
                        expires_at: None,
                        drand_round: None,
                        error: Some(error_msg),
                    }))
                }
            }
        }
        Err(e) => {
            let error_msg = escalation_error_to_string(&e);

            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: escalation_subject,
                outcome: VerdictOutcome::Deny {
                    reason: error_msg.clone(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }

            tracing::warn!(
                requestor = %requestor_chain.current_spiffe_id().unwrap_or("unknown"),
                approver = %approver_spiffe_id,
                error = %error_msg,
                event = "escalation_denied",
                "escalation request denied by policy"
            );

            Ok(Json(EscalateResponse {
                granted: false,
                grant_id: None,
                granted_preset: None,
                expires_at: None,
                drand_round: None,
                error: Some(error_msg),
            }))
        }
    }
}
