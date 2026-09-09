//! The approval machinery of `/v1/approve`: the grant registry, its nonce
//! cache and rate limiter, the bounded grant count, and the signed
//! approval-bundle loader.
//!
//! Extracted from `main.rs` to stay under the line ratchet
//! (`scripts/check-line-ratchet.sh`), and because it is one coherent unit:
//! everything here is about how a principal's approval is admitted, bounded,
//! and spent exactly once. The decision-path consult lives in
//! `http_kernel_decide` (main.rs) and the runtime's `CallbackApprover` is
//! built over [`ApprovalRegistry`] at startup; both read this registry, and
//! the handlers peek (`has`) while the approver consumes.

use std::collections::HashMap;
use std::sync::Mutex;

use nucleus_identity::approval_bundle::{ApprovalBundleVerifier, compute_manifest_hash};
use tracing::info;

use crate::{ApiError, now_unix};

/// The most uses one `/v1/approve` grant may carry. A grant is consumed one
/// use per mediated action; an unbounded count (`usize::MAX` was reachable
/// from a bundle with no `max_uses`) is a standing waiver, not an approval.
pub(crate) const MAX_APPROVAL_COUNT: usize = 16;

/// Bound a requested grant count: zero is not a grant, and more than
/// [`MAX_APPROVAL_COUNT`] is refused rather than clamped, so a caller learns
/// the ceiling instead of silently getting less than it asked for.
pub(crate) fn bounded_approval_count(count: usize) -> Result<usize, ApiError> {
    if count == 0 {
        return Err(ApiError::Spec(
            "approval count must be at least 1".to_string(),
        ));
    }
    if count > MAX_APPROVAL_COUNT {
        return Err(ApiError::Spec(format!(
            "approval count {count} exceeds the ceiling of {MAX_APPROVAL_COUNT} uses per grant"
        )));
    }
    Ok(count)
}

#[derive(Default)]
pub(crate) struct ApprovalRegistry {
    approvals: Mutex<HashMap<String, ApprovalEntry>>,
}

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
            state: Mutex::new((max_tokens, now_unix())),
        }
    }

    /// Try to consume a token. Returns true if allowed, false if rate limited.
    pub(crate) fn try_acquire(&self) -> bool {
        let mut guard = self.state.lock().unwrap();
        let (tokens, last_refill) = &mut *guard;
        let now = now_unix();

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
    pub(crate) fn default() -> Self {
        // Allow 10 approvals per second with burst of 20
        Self::new(20, 10)
    }
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

    /// Whether an unexpired grant with uses left exists — WITHOUT spending
    /// one. The handlers peek here and let the runtime's approver (the
    /// `CallbackApprover` built over this registry at startup) do the single
    /// consume inside `request_approval`; peeking-then-consuming used to be
    /// consuming-then-consuming, so every grant cost two uses (#2406).
    pub(crate) fn has(&self, operation: &str) -> bool {
        let mut guard = self.approvals.lock().unwrap();
        match guard.get(operation) {
            Some(entry) if is_expired(entry.expires_at_unix) => {
                guard.remove(operation);
                false
            }
            Some(entry) => entry.count > 0,
            None => false,
        }
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
        Some(ts) => ts <= now_unix(),
        None => false,
    }
}

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

    let trusted_keys = parse_approval_trusted_keys();
    verify_and_load_approval_bundle(&jws, spec_contents, approvals, &trusted_keys)
}

/// Parse the pinned trusted approver keys from `NUCLEUS_APPROVAL_TRUSTED_KEYS`
/// (a JSON array of JWKs). Unset / empty / parse-error ⇒ empty set ⇒ approval
/// bundles are refused fail-closed. Mirrors the `NUCLEUS_DECLASSIFY_TRUSTED_KEYS`
/// pinned-trust-anchor pattern.
pub(crate) fn parse_approval_trusted_keys() -> Vec<nucleus_identity::did::JsonWebKey> {
    match std::env::var("NUCLEUS_APPROVAL_TRUSTED_KEYS") {
        Ok(val) if !val.trim().is_empty() => {
            match serde_json::from_str::<Vec<nucleus_identity::did::JsonWebKey>>(&val) {
                Ok(keys) => keys,
                Err(e) => {
                    warn!(
                        error = %e,
                        "NUCLEUS_APPROVAL_TRUSTED_KEYS is set but is not a valid JSON array of \
                         JWKs — treating as empty (approval bundles will be refused fail-closed)"
                    );
                    Vec::new()
                }
            }
        }
        _ => Vec::new(),
    }
}

/// Verify a JWS approval bundle against a PINNED set of trusted approver keys and
/// populate the ApprovalRegistry.
///
/// SECURITY: the bundle is verified against `trusted_keys` (the pinned approver
/// trust anchors), NOT against the key embedded in the JWS header. Trusting the
/// header's own JWK would be vacuous — an attacker could sign a bundle with their
/// own key, embed that key in the header, and self-verify, bypassing the
/// human-in-the-loop approval gate. Fail-closed: if no trusted approver key is
/// configured, the bundle is refused.
pub(crate) fn verify_and_load_approval_bundle(
    jws: &str,
    spec_contents: &str,
    approvals: &ApprovalRegistry,
    trusted_keys: &[nucleus_identity::did::JsonWebKey],
) -> Result<(), ApiError> {
    let manifest_hash = compute_manifest_hash(spec_contents.as_bytes());

    // Fail-closed: never self-trust the bundle's embedded key. Without a pinned
    // trusted approver key there is no authority to check against, so refuse.
    if trusted_keys.is_empty() {
        return Err(ApiError::Spec(
            "no trusted approver keys configured (set NUCLEUS_APPROVAL_TRUSTED_KEYS) — refusing \
             to load an approval bundle fail-closed (the embedded JWS key is never self-trusted)"
                .to_string(),
        ));
    }

    let verifier = ApprovalBundleVerifier::new();
    // Verify against each PINNED trusted approver key; accept the first that the
    // bundle validly matches (correct key + valid signature + manifest binding).
    // A bundle signed by any non-trusted key is rejected.
    let claims = trusted_keys
        .iter()
        .find_map(|tk| verifier.verify(jws, tk, &manifest_hash).ok())
        .ok_or_else(|| {
            ApiError::Spec(
                "approval bundle signer is not a trusted approver key (or the signature / \
                 manifest binding is invalid)"
                    .to_string(),
            )
        })?;

    // Populate the ApprovalRegistry with the approved operations. A bundle
    // without `max_uses` used to mean usize::MAX uses — a standing waiver for
    // the TTL. It now means the same ceiling every grant has.
    let count = claims
        .max_uses
        .map(|n| (n as usize).min(MAX_APPROVAL_COUNT))
        .unwrap_or(MAX_APPROVAL_COUNT);
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

#[derive(Debug, Deserialize)]
pub(crate) struct ReadRequest {
    path: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReadResponse {
    contents: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WriteRequest {
    path: String,
    contents: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct WriteResponse {
    ok: bool,
}

// `/v1/run` request/response are the SHARED wire types (`nucleus-api-types`):
// the same struct the MCP face posts, so the two cannot drift again. Argv is
// canonical; the legacy `command` string is split into argv by the type
// itself and never reaches a shell. `timeout_seconds` is honoured below via
// the sealed async spawn (it was `#[allow(dead_code)]` here for a year).
use nucleus_api_types::{RunRequest, RunResponse};
