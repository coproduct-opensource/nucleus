//! Human approvals: the one way an operation the kernel parked on
//! `RequiresApproval` becomes allowed.
//!
//! # The defect this module was built from
//!
//! Until 2026-09-27 an approval was granted by
//! `ApprovalRegistry::approve(&self, operation: &str, count, expiry)`. Nothing
//! about that signature needed an approver: whoever could reach the handler
//! could call it, and the handler trusted `auth_middleware` to have checked a
//! signature. The middleware consulted SPIFFE first (`auth::select_auth_tier`),
//! so any workload holding a certificate under the trust bundle reached the
//! handler with NO approver signature and granted itself whatever it had been
//! told to ask a person for.
//!
//! The ordering bug is fixed in `select_auth_tier`
//! (`the_approval_path_outranks_spiffe`). This module fixes the shape that let
//! an ordering bug become a bypass: a grant is now a [`VerifiedApproval`], a
//! witness with private fields and no derives (ADR 0007 C-1, C-5), minted only
//! by the two functions that check an approver's signature (C-2), and
//! [`ApprovalRegistry::approve`] takes it by value (C-4). A caller that has not
//! verified a signature has nothing to hand the registry, whatever the
//! middleware did or did not do.
//!
//! # Where verification happens, and why twice is still one verifier
//!
//! `auth_middleware` authenticates `/v1/approve` with
//! [`ApprovalKeys::authenticate`] because every request needs an `AuthContext`.
//! The handler mints its witness with [`VerifiedApproval::verify_request`],
//! which calls the same function. One implementation, called twice; the
//! signature check is pure, so the second call costs microseconds and decides
//! nothing the first did not. The one stateful step — burning the nonce —
//! happens only in the mint. The handler cannot take the witness from the
//! middleware instead: axum request extensions require `Clone`, and a witness
//! that can be cloned can be spent twice.

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Duration;

use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::HeaderMap;
use nucleus::portcullis::Operation;
use nucleus_identity::approval_bundle::{ApprovalBundleVerifier, compute_manifest_hash};
use portcullis::verdict_sink::{ActorIdentity, VerdictContext, VerdictOutcome};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::auth::{self, AuthConfig, AuthContext, AuthError};
use crate::{ApiError, AppState, now_unix};

/// The longest an approval requested over `/v1/approve` may live.
pub(crate) const MAX_APPROVAL_TTL_SECS: u64 = 300;

/// The body of `/v1/approve`. Parsed only from bytes whose signature has
/// already been checked — never by an axum `Json` extractor, which would parse
/// before anything is verified.
#[derive(Debug, Deserialize)]
struct ApproveRequest {
    operation: String,
    #[serde(default = "default_approve_count")]
    count: usize,
    #[serde(default)]
    expires_at_unix: Option<u64>,
    #[serde(default)]
    nonce: Option<String>,
}

fn default_approve_count() -> usize {
    1
}

#[derive(Debug, Serialize)]
pub(crate) struct ApproveResponse {
    ok: bool,
}

/// How many operations one approval buys.
///
/// The bundle path used to write "until expiry" as `usize::MAX`, a count that
/// looked finite and overflowed the registry's `+=` the second time a bundle
/// named the same operation. It is a separate case, so it is a separate
/// constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApprovalCount {
    /// Exactly this many uses.
    Bounded(NonZeroUsize),
    /// Any number of uses until the approval expires. Only a signed bundle
    /// with no `max_uses` produces this.
    UntilExpiry,
}

impl ApprovalCount {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::Bounded(a), Self::Bounded(b)) => Self::Bounded(a.saturating_add(b.get())),
            (Self::UntilExpiry, _) | (_, Self::UntilExpiry) => Self::UntilExpiry,
        }
    }
}

/// Who signed an approval. Carried for the audit line, never for a decision.
#[derive(Debug)]
enum ApprovalIssuer {
    /// A `/v1/approve` request signed by an approver key (Ed25519) or the
    /// approval secret (HMAC).
    Request {
        actor: Option<String>,
        drand_round: Option<u64>,
        method: auth::AuthMethod,
    },
    /// A JWS approval bundle signed by a pinned trusted approver key.
    Bundle { iss: String, jti: String },
}

impl std::fmt::Display for ApprovalIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request {
                actor,
                drand_round,
                method,
            } => write!(
                f,
                "request signed by {} ({method:?}, drand round {})",
                actor.as_deref().unwrap_or("<no actor>"),
                drand_round.map_or_else(|| "none".to_string(), |r| r.to_string()),
            ),
            Self::Bundle { iss, jti } => write!(f, "bundle {jti} issued by {iss}"),
        }
    }
}

/// Evidence that an approver signed this approval.
///
/// No derives, private fields, `#[must_use]`: constructed only by
/// [`Self::verify_request`] and [`Self::verify_bundle`], each of which checks
/// the signature before building one, and spent by value in
/// [`ApprovalRegistry::approve`].
#[must_use = "a verified approval grants nothing until it is handed to ApprovalRegistry::approve"]
pub(crate) struct VerifiedApproval {
    operation: String,
    count: ApprovalCount,
    expires_at_unix: u64,
    issuer: ApprovalIssuer,
}

impl std::fmt::Debug for VerifiedApproval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedApproval")
            .field("operation", &self.operation)
            .field("count", &self.count)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("issuer", &self.issuer)
            .finish()
    }
}

/// The approval authority this proxy was provisioned with.
///
/// Ed25519 approver PUBLIC keys when `--approval-pubkeys` is set — and then
/// exclusively, so a residual copy of the old secret forges nothing — or the
/// legacy drand-anchored HMAC secret otherwise.
#[derive(Clone, Copy)]
pub(crate) enum ApprovalKeys<'a> {
    Ed25519(&'a auth::ApprovalVerifier),
    Hmac(&'a AuthConfig),
}

impl<'a> ApprovalKeys<'a> {
    pub(crate) fn of(state: &'a AppState) -> Self {
        match state.approval_verifier {
            Some(ref verifier) => Self::Ed25519(verifier),
            None => Self::Hmac(&state.approval_auth),
        }
    }

    /// Check the approver's signature over `"{round}.{ts}.{actor}.{body}"`.
    /// The ONE approval-signature check; see the module doc for its two callers.
    pub(crate) fn authenticate(
        self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<AuthContext, AuthError> {
        match self {
            Self::Ed25519(verifier) => {
                auth::verify_http_with_ed25519_drand(headers, body, verifier)
            }
            Self::Hmac(config) => auth::verify_http_with_drand(headers, body, config),
        }
    }

    /// How far a signed timestamp may be from now — so how long the same
    /// signed bytes stay acceptable, and so how long their nonce must be kept.
    fn max_skew(self) -> Duration {
        match self {
            Self::Ed25519(verifier) => verifier.max_skew(),
            Self::Hmac(config) => config.max_skew(),
        }
    }
}

impl VerifiedApproval {
    /// Mint from a `/v1/approve` request.
    ///
    /// The order is the point: the signature is checked FIRST, the body is
    /// parsed from the bytes the signature covered, and the nonce is burned
    /// LAST. An unsigned or malformed request therefore burns nothing, so it
    /// cannot pre-spend the nonce of a legitimate approval it has observed.
    pub(crate) fn verify_request(
        headers: &HeaderMap,
        body: &[u8],
        keys: ApprovalKeys<'_>,
        nonces: &ApprovalNonceCache,
        now: u64,
    ) -> Result<Self, ApiError> {
        let ctx = keys.authenticate(headers, body)?;
        let req: ApproveRequest = serde_json::from_slice(body)
            .map_err(|e| ApiError::Body(format!("invalid approval request: {e}")))?;
        let count = NonZeroUsize::new(req.count)
            .ok_or_else(|| ApiError::Spec("approval count must be at least 1".to_string()))?;
        let expires_at_unix = resolve_approval_expiry(req.expires_at_unix, now)?;
        let nonce = req
            .nonce
            .as_deref()
            .ok_or_else(|| ApiError::Spec("approval nonce required".to_string()))?;
        // Keep the nonce at least as long as the signed bytes stay acceptable.
        // A timestamp is accepted within `max_skew` either side of now, so the
        // same request verifies until `now + 2·skew` at the latest. Keeping the
        // nonce only until a short approval's own expiry would let the request
        // be replayed inside that window once the nonce had been purged.
        let replay_window = now.saturating_add(keys.max_skew().as_secs().saturating_mul(2));
        if !nonces.check_and_insert(nonce, expires_at_unix.max(replay_window), now) {
            return Err(ApiError::Spec("approval nonce replayed".to_string()));
        }
        Ok(Self {
            operation: req.operation,
            count: ApprovalCount::Bounded(count),
            expires_at_unix,
            issuer: ApprovalIssuer::Request {
                actor: ctx.actor,
                drand_round: ctx.drand_round,
                method: ctx.auth_method,
            },
        })
    }

    /// Mint from a JWS approval bundle, one approval per operation it names.
    ///
    /// SECURITY: the bundle is verified against `trusted` (the pinned approver
    /// trust anchors), NOT against the key embedded in the JWS header. Trusting
    /// the header's own JWK would be vacuous — an attacker could sign a bundle
    /// with their own key, embed that key in the header, and self-verify.
    /// Fail-closed: with no trusted approver key configured, nothing mints.
    pub(crate) fn verify_bundle(
        jws: &str,
        manifest_hash: &str,
        trusted: &[nucleus_identity::did::JsonWebKey],
    ) -> Result<Vec<Self>, ApiError> {
        if trusted.is_empty() {
            return Err(ApiError::Spec(
                "no trusted approver keys configured (set NUCLEUS_APPROVAL_TRUSTED_KEYS) — refusing \
                 to load an approval bundle fail-closed (the embedded JWS key is never self-trusted)"
                    .to_string(),
            ));
        }
        let verifier = ApprovalBundleVerifier::new();
        let claims = trusted
            .iter()
            .find_map(|tk| verifier.verify(jws, tk, manifest_hash).ok())
            .ok_or_else(|| {
                ApiError::Spec(
                    "approval bundle signer is not a trusted approver key (or the signature / \
                     manifest binding is invalid)"
                        .to_string(),
                )
            })?;
        let expires_at_unix = u64::try_from(claims.exp).map_err(|_| {
            ApiError::Spec(format!("approval bundle expiry {} is negative", claims.exp))
        })?;
        // A bundle with `max_uses: 0` authorizes nothing; refuse it rather
        // than register a grant that could never be spent. No `max_uses` at
        // all is the bundle format's "until expiry".
        let count = match claims.max_uses {
            Some(n) => ApprovalCount::Bounded(NonZeroUsize::new(n as usize).ok_or_else(|| {
                ApiError::Spec("approval bundle max_uses must be at least 1".to_string())
            })?),
            None => ApprovalCount::UntilExpiry,
        };
        info!(
            issuer = %claims.iss,
            jti = %claims.jti,
            operations = ?claims.approved_operations,
            manifest_hash = %claims.manifest_hash,
            event = "approval_bundle_verified",
            "signed approval bundle verified"
        );
        Ok(claims
            .approved_operations
            .iter()
            .map(|op| Self {
                operation: op.clone(),
                count,
                expires_at_unix,
                issuer: ApprovalIssuer::Bundle {
                    iss: claims.iss.clone(),
                    jti: claims.jti.clone(),
                },
            })
            .collect())
    }
}

/// The live grants, keyed by operation.
///
/// The map is private to this module: the only writer is [`Self::approve`],
/// which takes a [`VerifiedApproval`].
pub(crate) struct ApprovalRegistry {
    approvals: Mutex<HashMap<String, ApprovalEntry>>,
}

/// Written by hand, at the restrictive end (ADR 0007 B-1): no grants.
impl Default for ApprovalRegistry {
    fn default() -> Self {
        Self {
            approvals: Mutex::new(HashMap::new()),
        }
    }
}

struct ApprovalEntry {
    count: ApprovalCount,
    expires_at_unix: u64,
}

impl ApprovalRegistry {
    /// Register an approval. Takes the witness by value (C-4): one verified
    /// signature is one registration.
    pub(crate) fn approve(&self, approval: VerifiedApproval) {
        let VerifiedApproval {
            operation,
            count,
            expires_at_unix,
            issuer,
        } = approval;
        info!(
            operation = %operation,
            count = ?count,
            expires_at = expires_at_unix,
            issuer = %issuer,
            event = "approval_granted",
            "approval registered"
        );
        let mut guard = self.approvals.lock().unwrap();
        match guard.get_mut(&operation) {
            Some(entry) => {
                entry.count = entry.count.merge(count);
                entry.expires_at_unix = entry.expires_at_unix.min(expires_at_unix);
            }
            None => {
                guard.insert(
                    operation,
                    ApprovalEntry {
                        count,
                        expires_at_unix,
                    },
                );
            }
        }
    }

    pub(crate) fn consume(&self, operation: &str) -> bool {
        let mut guard = self.approvals.lock().unwrap();
        let Some(entry) = guard.get_mut(operation) else {
            return false;
        };
        if is_expired(entry.expires_at_unix) {
            guard.remove(operation);
            return false;
        }
        match entry.count {
            ApprovalCount::UntilExpiry => {}
            ApprovalCount::Bounded(n) => match NonZeroUsize::new(n.get() - 1) {
                Some(rest) => entry.count = ApprovalCount::Bounded(rest),
                None => {
                    guard.remove(operation);
                }
            },
        }
        true
    }

    /// Whether a live grant exists for `operation`, WITHOUT spending it.
    ///
    /// One human approval must buy exactly one operation, and an operation
    /// crosses two independent approval gates on its way through: the kernel's
    /// `RequiresApproval` verdict at the HTTP chokepoint, and the sandbox's own
    /// capability guard. Both used to want to `consume`, which is #2406's other
    /// half — a grant of `count: 1` was spent by whichever gate read it first
    /// and the next gate found nothing, so the caller had to grant more than
    /// they meant to approve for the write to land at all.
    ///
    /// So the gates split the two questions. Every gate before the last asks
    /// *is this approved* (here); the sandbox approver, which is the last thing
    /// between the request and the bytes, is the single site that spends it.
    /// A peek that reports a live grant is therefore always followed by exactly
    /// one `consume`, or by a refusal further down that spends nothing.
    ///
    /// Expiry is evaluated and purged here exactly as in [`Self::consume`], so
    /// a peek cannot report a grant that a spend would then reject.
    pub(crate) fn is_granted(&self, operation: &str) -> bool {
        let mut guard = self.approvals.lock().unwrap();
        match guard.get(operation) {
            Some(entry) if is_expired(entry.expires_at_unix) => {
                guard.remove(operation);
                false
            }
            // Every stored count is non-zero by construction.
            Some(_) => true,
            None => false,
        }
    }
}

impl crate::mediation::ApprovalGrants for ApprovalRegistry {
    fn is_granted(&self, operation: &str) -> bool {
        ApprovalRegistry::is_granted(self, operation)
    }
}

fn is_expired(expires_at_unix: u64) -> bool {
    expires_at_unix <= now_unix()
}

/// Nonces seen on `/v1/approve` and `/v1/escalate`, kept until they expire.
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
    fn new(max_tokens: u32, refill_rate: u32) -> Self {
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
    fn default() -> Self {
        // Allow 10 approvals per second with burst of 20
        Self::new(20, 10)
    }
}

/// Clamp a requested expiry to [`MAX_APPROVAL_TTL_SECS`] from now; absent
/// means the maximum. An expiry in the past is refused, not clamped up.
fn resolve_approval_expiry(expires_at_unix: Option<u64>, now: u64) -> Result<u64, ApiError> {
    let max_allowed = now.saturating_add(MAX_APPROVAL_TTL_SECS);
    let requested = expires_at_unix.unwrap_or(max_allowed);
    if requested < now {
        return Err(ApiError::Spec("approval expiry is in the past".to_string()));
    }
    Ok(requested.min(max_allowed))
}

/// `POST /v1/approve`. Verifies the approver's signature itself — see the
/// module doc for why it cannot take the witness from the middleware.
pub(crate) async fn approve_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ApproveResponse>, ApiError> {
    // Rate limit approval requests to prevent DoS
    if !state.approval_rate_limiter.try_acquire() {
        return Err(ApiError::RateLimited);
    }
    let approval = VerifiedApproval::verify_request(
        &headers,
        &body,
        ApprovalKeys::of(&state),
        &state.approval_nonces,
        now_unix(),
    )?;
    let subject = approval.operation.clone();
    state.approvals.approve(approval);
    if let Err(e) = state.verdict_sink.record(VerdictContext {
        operation: Operation::ManagePods, // meta-operation: approval grant
        subject,
        outcome: VerdictOutcome::Allow,
        actor: ActorIdentity::Unknown,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    Ok(Json(ApproveResponse { ok: true }))
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
fn parse_approval_trusted_keys() -> Vec<nucleus_identity::did::JsonWebKey> {
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

/// Verify a JWS approval bundle bound to `spec_contents` and register every
/// approval it carries. See [`VerifiedApproval::verify_bundle`].
fn verify_and_load_approval_bundle(
    jws: &str,
    spec_contents: &str,
    approvals: &ApprovalRegistry,
    trusted_keys: &[nucleus_identity::did::JsonWebKey],
) -> Result<(), ApiError> {
    let manifest_hash = compute_manifest_hash(spec_contents.as_bytes());
    for approval in VerifiedApproval::verify_bundle(jws, &manifest_hash, trusted_keys)? {
        approvals.approve(approval);
    }
    Ok(())
}

#[cfg(test)]
#[path = "approval_tests.rs"]
mod tests;
