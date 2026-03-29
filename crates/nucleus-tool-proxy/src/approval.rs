//! Approval registry, nonce cache, rate limiting, and approval bundle handling.

use std::collections::HashMap;
use std::sync::Mutex;

use nucleus_identity::approval_bundle::{compute_manifest_hash, ApprovalBundleVerifier};
use tracing::info;

use crate::types::ApiError;

// ---------------------------------------------------------------------------
// Approval Registry
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct ApprovalRegistry {
    approvals: Mutex<HashMap<String, ApprovalEntry>>,
}

#[derive(Clone, Copy)]
pub(crate) struct ApprovalEntry {
    count: usize,
    expires_at_unix: Option<u64>,
}

impl ApprovalRegistry {
    pub(crate) fn approve(&self, operation: &str, count: usize, expires_at_unix: Option<u64>) {
        let mut guard = self.approvals.lock().unwrap();
        let entry = guard.entry(operation.to_string()).or_insert(ApprovalEntry {
            count: 0,
            expires_at_unix,
        });
        entry.count += count;
        entry.expires_at_unix = merge_expiry(entry.expires_at_unix, expires_at_unix);
    }

    pub(crate) fn consume(&self, operation: &str) -> bool {
        let mut guard = self.approvals.lock().unwrap();
        if let Some(entry) = guard.get_mut(operation) {
            if is_expired(entry.expires_at_unix) {
                guard.remove(operation);
                return false;
            }
            if entry.count > 0 {
                entry.count -= 1;
                if entry.count == 0 {
                    guard.remove(operation);
                }
                return true;
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Nonce Cache
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct ApprovalNonceCache {
    entries: Mutex<HashMap<String, u64>>,
}

impl ApprovalNonceCache {
    pub(crate) fn check_and_insert(&self, nonce: &str, expires_at_unix: u64, now: u64) -> bool {
        let mut guard = self.entries.lock().unwrap();
        guard.retain(|_, exp| *exp > now);
        if guard.contains_key(nonce) {
            return false;
        }
        guard.insert(nonce.to_string(), expires_at_unix);
        true
    }
}

// ---------------------------------------------------------------------------
// Rate Limiter
// ---------------------------------------------------------------------------

/// Simple token bucket rate limiter for the approval endpoint.
/// Prevents DoS attacks by limiting approval requests per second.
pub(crate) struct ApprovalRateLimiter {
    /// Maximum tokens (burst capacity)
    max_tokens: u32,
    /// Tokens added per second
    refill_rate: u32,
    /// Current token count and last refill timestamp
    state: Mutex<(u32, u64)>,
}

impl ApprovalRateLimiter {
    pub(crate) fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            max_tokens,
            refill_rate,
            state: Mutex::new((max_tokens, crate::now_unix())),
        }
    }

    /// Try to consume a token. Returns true if allowed, false if rate limited.
    pub(crate) fn try_acquire(&self) -> bool {
        let mut guard = self.state.lock().unwrap();
        let (tokens, last_refill) = &mut *guard;
        let now = crate::now_unix();

        // Refill tokens based on elapsed time
        let elapsed = now.saturating_sub(*last_refill);
        if elapsed > 0 {
            let refill = (elapsed as u32).saturating_mul(self.refill_rate);
            *tokens = (*tokens).saturating_add(refill).min(self.max_tokens);
            *last_refill = now;
        }

        // Try to consume a token
        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }
}

impl Default for ApprovalRateLimiter {
    fn default() -> Self {
        // Allow 10 approvals per second with burst of 20
        Self::new(20, 10)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) fn merge_expiry(existing: Option<u64>, incoming: Option<u64>) -> Option<u64> {
    match (existing, incoming) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

pub(crate) fn is_expired(expires_at_unix: Option<u64>) -> bool {
    match expires_at_unix {
        Some(ts) => ts <= crate::now_unix(),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Approval Bundle
// ---------------------------------------------------------------------------

/// Load and verify a signed approval bundle from the NUCLEUS_APPROVAL_BUNDLE env var.
///
/// If present and valid, populates the ApprovalRegistry with the approved operations.
/// If `require` is true, the function returns an error when the env var is missing.
pub(crate) fn load_approval_bundle(
    spec_contents: &str,
    approvals: &ApprovalRegistry,
    require: bool,
) -> Result<(), ApiError> {
    let jws = match std::env::var("NUCLEUS_APPROVAL_BUNDLE") {
        Ok(val) if !val.is_empty() => val,
        _ => {
            if require {
                return Err(ApiError::Spec(
                    "--require-approval-bundle is set but NUCLEUS_APPROVAL_BUNDLE is not set"
                        .to_string(),
                ));
            }
            return Ok(());
        }
    };

    verify_and_load_approval_bundle(&jws, spec_contents, approvals)
}

/// Verify a JWS approval bundle and populate the ApprovalRegistry.
pub(crate) fn verify_and_load_approval_bundle(
    jws: &str,
    spec_contents: &str,
    approvals: &ApprovalRegistry,
) -> Result<(), ApiError> {
    use base64::Engine as _;

    let manifest_hash = compute_manifest_hash(spec_contents.as_bytes());

    // Extract the embedded JWK from the JWS header for self-trust verification.
    let header = {
        let header_b64 = jws.split('.').next().ok_or_else(|| {
            ApiError::Spec("approval bundle is not a valid JWS (no header)".to_string())
        })?;
        let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| ApiError::Spec(format!("approval bundle header decode error: {e}")))?;
        let header: nucleus_identity::approval_bundle::ApprovalBundleHeader =
            serde_json::from_slice(&header_bytes)
                .map_err(|e| ApiError::Spec(format!("approval bundle header parse error: {e}")))?;
        header
    };

    let verifier = ApprovalBundleVerifier::new();
    let claims = verifier
        .verify(jws, &header.jwk, &manifest_hash)
        .map_err(|e| ApiError::Spec(format!("approval bundle verification failed: {e}")))?;

    // Populate the ApprovalRegistry with the approved operations
    let count = claims.max_uses.map(|n| n as usize).unwrap_or(usize::MAX);
    let expiry = Some(claims.exp as u64);
    for op in &claims.approved_operations {
        approvals.approve(op, count, expiry);
        info!(
            operation = %op,
            count = count,
            expires_at = claims.exp,
            event = "approval_bundle_loaded",
            "pre-approved operation from signed bundle"
        );
    }

    info!(
        issuer = %claims.iss,
        jti = %claims.jti,
        operations = ?claims.approved_operations,
        manifest_hash = %claims.manifest_hash,
        event = "approval_bundle_verified",
        "signed approval bundle verified and loaded"
    );

    Ok(())
}
