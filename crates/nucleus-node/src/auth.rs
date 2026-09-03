use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::Sha256;
use tonic::metadata::MetadataMap;
use tracing::warn;

const HEADER_TIMESTAMP: &str = "x-nucleus-timestamp";
const HEADER_SIGNATURE: &str = "x-nucleus-signature";
const HEADER_ACTOR: &str = "x-nucleus-actor";
/// Optional per-request uniqueness token. When present it is bound into the
/// signed message, so it cannot be stripped: removing the header changes the
/// message the server reconstructs and the signature stops verifying.
const HEADER_NONCE: &str = "x-nucleus-nonce";

/// Default bound on remembered signatures. At the 30 s window the node ships
/// with, this is far more than a real client produces, and reaching it means
/// something is flooding — see `ReplayCache::remember` for why that fails
/// closed rather than evicting.
const DEFAULT_REPLAY_CAPACITY: usize = 8192;

/// Remembers recently-accepted signatures so a captured request cannot be sent
/// again inside the timestamp window.
///
/// # Why the key is the signature
///
/// A replay is byte-identical to the original, so it produces the identical
/// signature and collides here. A *legitimate* repeat that carries a fresh
/// `x-nucleus-nonce` signs a different message, so it does not. One key handles
/// both cases, and clients that do not send a nonce still get replay protection
/// — they merely cannot repeat a byte-identical request inside the window,
/// which is indistinguishable from a replay anyway.
///
/// # Why it is not a plain LRU
///
/// A bounded LRU evicts the oldest entry to make room. That reopens the exact
/// hole this closes: flood the cache with fresh signatures, push a captured
/// signature out while its timestamp is still inside the acceptance window, and
/// replay it. So an entry is only ever dropped once it is **expired** — once
/// `ensure_skew` would reject its timestamp anyway. If the cache is full of
/// still-live entries, the request is refused rather than making room.
#[derive(Debug)]
pub struct ReplayCache {
    seen: Mutex<HashMap<String, i64>>,
    capacity: usize,
}

impl ReplayCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Record a signature as used. `Err(AuthError::Replay)` if it was already
    /// seen inside the window.
    ///
    /// Callers MUST verify the signature first. Remembering unverified
    /// signatures would let anyone fill the cache with garbage and trip the
    /// capacity refusal below — turning a replay defence into a denial of
    /// service.
    fn remember(&self, signature: &str, timestamp: i64, window: Duration) -> Result<(), AuthError> {
        let now = unix_now();
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());

        // Expired entries can never be replayed again — `ensure_skew` rejects
        // their timestamp — so dropping them is free.
        let window = window.as_secs() as i64;
        seen.retain(|_, ts| now.saturating_sub(*ts) <= window);

        if seen.contains_key(signature) {
            return Err(AuthError::Replay);
        }
        if seen.len() >= self.capacity {
            // Everything still held is live. Evicting to make room is what
            // would let a flood push a capturable signature out early.
            return Err(AuthError::ReplayCapacity);
        }
        seen.insert(signature.to_string(), timestamp);
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Global flag to suppress repeated HMAC deprecation warnings after the first few.
static HMAC_DEPRECATION_WARNED: AtomicBool = AtomicBool::new(false);

/// Authentication method used for a request.
///
/// This enum tracks how a client authenticated, enabling different authorization
/// policies and deprecation warnings for older methods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// HMAC-SHA256 signed request (being deprecated).
    ///
    /// Uses timestamp, actor, and method/body to create a signed message.
    /// This method is being phased out in favor of mTLS with SPIFFE.
    Hmac,

    /// mTLS with SPIFFE client certificate.
    ///
    /// The client presented a valid X.509 certificate with a SPIFFE ID in the
    /// Subject Alternative Name (SAN) extension. This is the preferred method.
    Spiffe {
        /// The SPIFFE ID from the client certificate.
        /// Format: `spiffe://trust-domain/path`
        spiffe_id: String,
    },
}

impl AuthMethod {
    /// Returns true if this is the deprecated HMAC method.
    #[allow(dead_code)]
    pub fn is_hmac(&self) -> bool {
        matches!(self, AuthMethod::Hmac)
    }

    /// Returns true if this is mTLS with SPIFFE.
    #[allow(dead_code)]
    pub fn is_spiffe(&self) -> bool {
        matches!(self, AuthMethod::Spiffe { .. })
    }

    /// Returns the SPIFFE ID if authenticated via mTLS.
    #[allow(dead_code)]
    pub fn spiffe_id(&self) -> Option<&str> {
        match self {
            AuthMethod::Spiffe { spiffe_id } => Some(spiffe_id),
            AuthMethod::Hmac => None,
        }
    }

    /// Returns the trust domain if authenticated via SPIFFE.
    #[allow(dead_code)]
    pub fn trust_domain(&self) -> Option<&str> {
        self.spiffe_id().and_then(|id| {
            id.strip_prefix("spiffe://")
                .and_then(|rest| rest.split('/').next())
        })
    }

    /// Log a deprecation warning if this is HMAC authentication.
    ///
    /// Call this after successful authentication to warn about deprecated auth methods.
    /// Only logs the first warning to avoid log spam.
    #[allow(dead_code)]
    pub fn warn_if_deprecated(&self, actor: Option<&str>) {
        if self.is_hmac() {
            // Only warn once to avoid log spam
            if !HMAC_DEPRECATION_WARNED.swap(true, Ordering::Relaxed) {
                warn!(
                    actor = actor.unwrap_or("unknown"),
                    "HMAC authentication is deprecated and will be removed in a future version. \
                     Please migrate to mTLS with SPIFFE. See: https://nucleus.dev/docs/auth/mtls"
                );
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    secret: Arc<Vec<u8>>,
    max_skew: Duration,
    replay: Arc<ReplayCache>,
}

impl AuthConfig {
    pub fn new(secret: impl AsRef<[u8]>, max_skew: Duration) -> Self {
        Self {
            secret: Arc::new(secret.as_ref().to_vec()),
            max_skew,
            replay: Arc::new(ReplayCache::new(DEFAULT_REPLAY_CAPACITY)),
        }
    }

    #[cfg(test)]
    pub fn with_replay_capacity(mut self, capacity: usize) -> Self {
        self.replay = Arc::new(ReplayCache::new(capacity));
        self
    }

    pub fn max_skew(&self) -> Duration {
        self.max_skew
    }
}

/// Context from a successfully authenticated request.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AuthContext {
    /// The actor identifier (from HMAC headers or SPIFFE path).
    pub actor: Option<String>,
    /// Timestamp of the request (for HMAC) or authentication time (for SPIFFE).
    pub timestamp: i64,
    /// The authentication method used.
    pub method: AuthMethod,
}

impl AuthContext {
    /// Creates a new auth context from HMAC verification.
    pub fn from_hmac(actor: Option<String>, timestamp: i64) -> Self {
        Self {
            actor,
            timestamp,
            method: AuthMethod::Hmac,
        }
    }

    /// Creates a new auth context from SPIFFE/mTLS verification.
    #[allow(dead_code)]
    pub fn from_spiffe(spiffe_id: String) -> Self {
        // Extract actor from SPIFFE path (last segment)
        let actor = spiffe_id
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.split('/').next_back())
            .map(|s| s.to_string());

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            actor,
            timestamp,
            method: AuthMethod::Spiffe { spiffe_id },
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing auth header: {0}")]
    MissingHeader(&'static str),
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("timestamp skew too large")]
    Skew,
    #[error("request replayed")]
    Replay,
    #[error("replay cache is full of live entries; retry after the skew window")]
    ReplayCapacity,
}

pub fn verify_http(
    headers: &HeaderMap,
    body: &[u8],
    auth: &AuthConfig,
) -> Result<AuthContext, AuthError> {
    let ts = header_value(headers, HEADER_TIMESTAMP)?;
    let sig = header_value(headers, HEADER_SIGNATURE)?;
    let actor = headers
        .get(HEADER_ACTOR)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let actor_value = actor.clone().unwrap_or_default();

    let nonce = headers.get(HEADER_NONCE).and_then(|v| v.to_str().ok());

    let timestamp = parse_timestamp(ts)?;
    ensure_skew(timestamp, auth.max_skew())?;

    let message = build_message(ts.as_bytes(), actor_value.as_bytes(), nonce, body);
    verify_signature(&auth.secret, &message, sig)?;

    // Only now, with the signature proven, is this signature worth remembering.
    auth.replay.remember(sig, timestamp, auth.max_skew())?;

    Ok(AuthContext::from_hmac(actor, timestamp))
}

pub fn verify_grpc(
    metadata: &MetadataMap,
    method: &str,
    auth: &AuthConfig,
) -> Result<AuthContext, AuthError> {
    let ts = metadata
        .get(HEADER_TIMESTAMP)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::MissingHeader(HEADER_TIMESTAMP))?;
    let sig = metadata
        .get(HEADER_SIGNATURE)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::MissingHeader(HEADER_SIGNATURE))?;
    let actor = metadata
        .get(HEADER_ACTOR)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let actor_value = actor.clone().unwrap_or_default();

    let nonce = metadata.get(HEADER_NONCE).and_then(|v| v.to_str().ok());

    let timestamp = parse_timestamp(ts)?;
    ensure_skew(timestamp, auth.max_skew())?;

    let message = build_message(
        ts.as_bytes(),
        actor_value.as_bytes(),
        nonce,
        method.as_bytes(),
    );
    verify_signature(&auth.secret, &message, sig)?;

    auth.replay.remember(sig, timestamp, auth.max_skew())?;

    Ok(AuthContext::from_hmac(actor, timestamp))
}

/// `{ts}.{actor}.{tail}`, or `{ts}.{actor}.{nonce}.{tail}` when a nonce is sent.
///
/// The nonce sits INSIDE the signed bytes on purpose. A stripped nonce header
/// makes the server rebuild the shorter form, which no longer matches the
/// signature — so an attacker cannot downgrade a nonce-bearing request into a
/// replayable one.
fn build_message(ts: &[u8], actor: &[u8], nonce: Option<&str>, tail: &[u8]) -> Vec<u8> {
    let nonce_len = nonce.map_or(0, |n| n.len() + 1);
    let mut message = Vec::with_capacity(ts.len() + actor.len() + 2 + nonce_len + tail.len());
    message.extend_from_slice(ts);
    message.push(b'.');
    message.extend_from_slice(actor);
    message.push(b'.');
    if let Some(nonce) = nonce {
        message.extend_from_slice(nonce.as_bytes());
        message.push(b'.');
    }
    message.extend_from_slice(tail);
    message
}

fn header_value<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, AuthError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::MissingHeader(name))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn parse_timestamp(ts: &str) -> Result<i64, AuthError> {
    ts.parse::<i64>()
        .map_err(|_| AuthError::InvalidHeader(HEADER_TIMESTAMP))
}

fn ensure_skew(timestamp: i64, max_skew: Duration) -> Result<(), AuthError> {
    let now = unix_now();
    let skew = (now - timestamp).unsigned_abs();
    if skew > max_skew.as_secs() {
        return Err(AuthError::Skew);
    }
    Ok(())
}

fn verify_signature(secret: &[u8], message: &[u8], signature_hex: &str) -> Result<(), AuthError> {
    let signature = hex::decode(signature_hex).map_err(|_| AuthError::InvalidSignature)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| AuthError::InvalidSignature)?;
    mac.update(message);
    mac.verify_slice(&signature)
        .map_err(|_| AuthError::InvalidSignature)
}

/// Public wrapper so the Article 12 collector can authenticate a body without
/// duplicating the HMAC comparison — one implementation, constant-time compare.
pub fn verify_signature_pub(
    secret: &[u8],
    message: &[u8],
    signature_hex: &str,
) -> Result<(), AuthError> {
    verify_signature(secret, message, signature_hex)
}

#[allow(dead_code)]
pub fn sign_message(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTHORIZATION
// ═══════════════════════════════════════════════════════════════════════════

/// Operations that can be authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // PodManagement is used in match arms for grouping
pub enum Operation {
    /// Create a new pod.
    CreatePod,
    /// List existing pods.
    ListPods,
    /// Get details of a specific pod.
    GetPod,
    /// Cancel a running pod.
    CancelPod,
    /// Stream logs from a pod.
    StreamLogs,
    /// Get execution receipt for a pod.
    GetReceipt,
    /// Any pod management operation (used for matching).
    PodManagement,
}

/// Authorization policy for nucleus operations.
///
/// This policy defines what SPIFFE identities are allowed to do.
/// By default, all identities within the trust domain can perform all operations.
#[derive(Clone, Debug)]
pub struct AuthorizationPolicy {
    /// Trust domain that identities must belong to.
    trust_domain: String,
    /// Whether HMAC authentication is allowed (deprecated fallback).
    allow_hmac: bool,
    /// Allowed SPIFFE ID prefixes for orchestrators.
    /// Identities matching these prefixes can perform any operation.
    orchestrator_prefixes: Vec<String>,
    /// Allowed SPIFFE ID prefixes for CI/CD (GitHub OIDC).
    /// These identities can only manage pods with matching labels.
    cicd_prefixes: Vec<String>,
}

impl Default for AuthorizationPolicy {
    fn default() -> Self {
        Self {
            trust_domain: "nucleus.local".to_string(),
            allow_hmac: false, // Fail-closed: mTLS-only by default; opt in explicitly via .allow_hmac()
            orchestrator_prefixes: vec![
                "spiffe://nucleus.local/ns/default/sa/".to_string(),
                "spiffe://nucleus.local/ns/workstream-kg/sa/".to_string(),
            ],
            cicd_prefixes: vec!["spiffe://nucleus.local/ns/github/sa/".to_string()],
        }
    }
}

#[allow(dead_code)] // Builder methods used in tests and future config
impl AuthorizationPolicy {
    /// Create a new authorization policy for the given trust domain.
    pub fn new(trust_domain: impl Into<String>) -> Self {
        let trust_domain = trust_domain.into();
        Self {
            orchestrator_prefixes: vec![
                format!("spiffe://{}/ns/default/sa/", trust_domain),
                format!("spiffe://{}/ns/workstream-kg/sa/", trust_domain),
            ],
            cicd_prefixes: vec![format!("spiffe://{}/ns/github/sa/", trust_domain)],
            trust_domain,
            ..Default::default()
        }
    }

    /// Disable HMAC authentication (require mTLS only).
    ///
    /// This is now the default; retained for explicitness at call sites.
    pub fn require_mtls(mut self) -> Self {
        self.allow_hmac = false;
        self
    }

    /// Explicitly allow legacy HMAC shared-secret authentication.
    ///
    /// HMAC is disabled by default (fail-closed). Callers that still need the
    /// deprecated shared-secret fallback during migration must opt in here.
    pub fn allow_hmac(mut self) -> Self {
        self.allow_hmac = true;
        self
    }

    /// Add an orchestrator prefix.
    pub fn with_orchestrator_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.orchestrator_prefixes.push(prefix.into());
        self
    }

    /// Add a CI/CD prefix.
    pub fn with_cicd_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.cicd_prefixes.push(prefix.into());
        self
    }

    /// Check if an authentication context is authorized to perform an operation.
    ///
    /// # Returns
    ///
    /// `Ok(())` if authorized, `Err(AuthorizationError)` otherwise.
    pub fn authorize(&self, ctx: &AuthContext, op: Operation) -> Result<(), AuthorizationError> {
        match &ctx.method {
            AuthMethod::Hmac => {
                if !self.allow_hmac {
                    return Err(AuthorizationError::HmacNotAllowed);
                }
                // HMAC authenticated requests are allowed all operations
                // (during migration period - will be removed)
                warn!(
                    actor = ?ctx.actor,
                    operation = ?op,
                    "Allowing HMAC-authenticated request (deprecated)"
                );
                Ok(())
            }
            AuthMethod::Spiffe { spiffe_id } => self.authorize_spiffe(spiffe_id, op),
        }
    }

    /// Check if a SPIFFE ID is authorized to perform an operation.
    fn authorize_spiffe(&self, spiffe_id: &str, op: Operation) -> Result<(), AuthorizationError> {
        // Verify trust domain
        let expected_prefix = format!("spiffe://{}/", self.trust_domain);
        if !spiffe_id.starts_with(&expected_prefix) {
            return Err(AuthorizationError::WrongTrustDomain {
                expected: self.trust_domain.clone(),
                got: spiffe_id.to_string(),
            });
        }

        // Check if this is an orchestrator identity (full access)
        for prefix in &self.orchestrator_prefixes {
            if spiffe_id.starts_with(prefix) {
                tracing::debug!(
                    spiffe_id = %spiffe_id,
                    operation = ?op,
                    "Authorized orchestrator operation"
                );
                return Ok(());
            }
        }

        // Check if this is a CI/CD identity (limited access)
        for prefix in &self.cicd_prefixes {
            if spiffe_id.starts_with(prefix) {
                // CI/CD identities can only perform pod management operations
                match op {
                    Operation::CreatePod
                    | Operation::GetPod
                    | Operation::CancelPod
                    | Operation::StreamLogs
                    | Operation::ListPods
                    | Operation::GetReceipt
                    | Operation::PodManagement => {
                        tracing::debug!(
                            spiffe_id = %spiffe_id,
                            operation = ?op,
                            "Authorized CI/CD operation"
                        );
                        return Ok(());
                    }
                }
            }
        }

        // Unknown identity type
        Err(AuthorizationError::NotAuthorized {
            identity: spiffe_id.to_string(),
            operation: format!("{:?}", op),
        })
    }
}

/// Authorization errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("HMAC authentication is no longer allowed; use mTLS with SPIFFE")]
    HmacNotAllowed,

    #[error("identity from wrong trust domain: expected {expected}, got {got}")]
    WrongTrustDomain { expected: String, got: String },

    #[error("identity {identity} is not authorized for operation {operation}")]
    NotAuthorized { identity: String, operation: String },
}

// ═══════════════════════════════════════════════════════════════════════════
// SPIFFE ID EXTRACTION FROM PEER CERTIFICATES
// ═══════════════════════════════════════════════════════════════════════════

/// Extracts the SPIFFE ID from a DER-encoded X.509 certificate.
///
/// The SPIFFE ID is stored in the Subject Alternative Name (SAN) extension
/// as a URI starting with "spiffe://".
pub fn extract_spiffe_id_from_cert(cert_der: &[u8]) -> Option<String> {
    // Delegated to nucleus-identity so this AUTHORIZATION path cannot disagree
    // with any other component about who a peer is. The local copy this
    // replaced returned the FIRST `spiffe://` SAN, so a certificate naming two
    // identities was accepted and resolved by DER encoding order.
    nucleus_identity::spiffe_uri_from_svid(cert_der).ok()
}

/// Extracts SPIFFE ID from a tonic Request's peer certificates.
///
/// This is used for gRPC mTLS authentication. Returns `None` if:
/// - No TLS connection info is available
/// - No peer certificates were provided
/// - The certificate doesn't contain a SPIFFE ID
pub fn extract_spiffe_id_from_request<T>(request: &tonic::Request<T>) -> Option<String> {
    // Use tonic's built-in peer_certs() method which extracts from TlsConnectInfo
    let peer_certs = request.peer_certs()?;

    if peer_certs.is_empty() {
        return None;
    }

    // The first certificate is the end-entity (client) certificate
    let client_cert_der = peer_certs[0].as_ref();
    extract_spiffe_id_from_cert(client_cert_der)
}

/// Authenticate a gRPC request using mTLS or HMAC.
///
/// This function tries mTLS first (if peer certificates are available),
/// then falls back to HMAC authentication.
///
/// # Arguments
///
/// * `request` - The tonic Request to authenticate
/// * `method` - The gRPC method being called (for HMAC verification)
/// * `auth_config` - HMAC authentication configuration
/// * `mtls_enabled` - Whether mTLS is configured on the server
///
/// # Returns
///
/// An `AuthContext` describing how the request was authenticated.
pub fn authenticate_grpc_request<T>(
    request: &tonic::Request<T>,
    method: &str,
    auth_config: &AuthConfig,
    mtls_enabled: bool,
) -> Result<AuthContext, AuthError> {
    // Try mTLS authentication first (if enabled and certs available)
    if mtls_enabled {
        if let Some(spiffe_id) = extract_spiffe_id_from_request(request) {
            tracing::debug!(
                spiffe_id = %spiffe_id,
                method = %method,
                "Authenticated via mTLS with SPIFFE ID"
            );
            return Ok(AuthContext::from_spiffe(spiffe_id));
        }

        // mTLS is enabled but no SPIFFE ID found - check if HMAC headers present
        if request.metadata().get(HEADER_SIGNATURE).is_some() {
            tracing::warn!(
                method = %method,
                "mTLS enabled but falling back to HMAC authentication (no valid client cert)"
            );
        }
    }

    // Fall back to HMAC verification
    verify_grpc(request.metadata(), method, auth_config)
}

/// Extract the AuthContext from a request's extensions.
///
/// This should be called in gRPC handlers after the interceptor has authenticated
/// the request and stored the context.
pub fn get_auth_context<T>(request: &tonic::Request<T>) -> Option<&AuthContext> {
    request.extensions().get::<AuthContext>()
}

/// Check authorization for a gRPC operation.
///
/// This is a convenience function that extracts the auth context from the request
/// and checks if the operation is authorized according to the policy.
///
/// # Returns
///
/// * `Ok(())` if authorized
/// * `Err(Status)` with appropriate error message if not authorized
pub fn authorize_grpc_operation<T>(
    request: &tonic::Request<T>,
    policy: &AuthorizationPolicy,
    operation: Operation,
) -> Result<(), tonic::Status> {
    let auth_ctx =
        get_auth_context(request).ok_or_else(|| tonic::Status::internal("missing auth context"))?;

    policy
        .authorize(auth_ctx, operation)
        .map_err(|e| tonic::Status::permission_denied(e.to_string()))
}

#[cfg(test)]
mod tests {

    // ── replay protection (#1631) ──────────────────────────────────────────

    fn hdrs(ts: &str, sig: &str, nonce: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(HEADER_TIMESTAMP, ts.parse().unwrap());
        h.insert(HEADER_SIGNATURE, sig.parse().unwrap());
        h.insert(HEADER_ACTOR, "tester".parse().unwrap());
        if let Some(n) = nonce {
            h.insert(HEADER_NONCE, n.parse().unwrap());
        }
        h
    }

    fn signed(secret: &[u8], ts: i64, nonce: Option<&str>, body: &[u8]) -> HeaderMap {
        let ts = ts.to_string();
        let msg = build_message(ts.as_bytes(), b"tester", nonce, body);
        hdrs(&ts, &sign_message(secret, &msg), nonce)
    }

    #[test]
    fn an_identical_request_replayed_inside_the_window_is_refused() {
        let secret = b"s3cret";
        let auth = AuthConfig::new(secret, Duration::from_secs(30));
        let body = b"{\"kind\":\"Pod\"}";
        let h = signed(secret, unix_now(), None, body);

        // Non-vacuity: the FIRST send must succeed, or "refused" below would be
        // proving nothing more than that the request was malformed.
        assert!(verify_http(&h, body, &auth).is_ok(), "first send must pass");
        assert!(matches!(
            verify_http(&h, body, &auth),
            Err(AuthError::Replay)
        ));
    }

    #[test]
    fn a_nonce_lets_an_otherwise_identical_request_repeat() {
        let secret = b"s3cret";
        let auth = AuthConfig::new(secret, Duration::from_secs(30));
        let body = b"{}";
        let ts = unix_now();
        // Same timestamp, same actor, same body — only the nonce differs.
        assert!(verify_http(&signed(secret, ts, Some("n1"), body), body, &auth).is_ok());
        assert!(verify_http(&signed(secret, ts, Some("n2"), body), body, &auth).is_ok());
    }

    #[test]
    fn stripping_the_nonce_header_does_not_downgrade_the_request() {
        let secret = b"s3cret";
        let auth = AuthConfig::new(secret, Duration::from_secs(30));
        let body = b"{}";
        let ts = unix_now().to_string();
        let msg = build_message(ts.as_bytes(), b"tester", Some("n1"), body);
        let sig = sign_message(secret, &msg);
        // Signature made over the nonce-bearing message, nonce header removed.
        let stripped = hdrs(&ts, &sig, None);
        assert!(matches!(
            verify_http(&stripped, body, &auth),
            Err(AuthError::InvalidSignature)
        ));
    }

    #[test]
    fn a_full_cache_refuses_rather_than_evicting_a_live_entry() {
        let secret = b"s3cret";
        let auth = AuthConfig::new(secret, Duration::from_secs(30)).with_replay_capacity(2);
        let body = b"{}";
        let ts = unix_now();
        assert!(verify_http(&signed(secret, ts, Some("a"), body), body, &auth).is_ok());
        let victim = signed(secret, ts, Some("b"), body);
        assert!(verify_http(&victim, body, &auth).is_ok());

        // Cache is now full of LIVE entries. A plain LRU would evict "a" here,
        // which is precisely how a flood would make room to replay it.
        assert!(matches!(
            verify_http(&signed(secret, ts, Some("c"), body), body, &auth),
            Err(AuthError::ReplayCapacity)
        ));
        // And the entry a flood would have evicted is still remembered.
        assert!(matches!(
            verify_http(&victim, body, &auth),
            Err(AuthError::Replay)
        ));
    }

    #[test]
    fn expired_entries_are_dropped_because_skew_already_refuses_them() {
        let cache = ReplayCache::new(8);
        let window = Duration::from_secs(30);
        // An entry older than the window can never be replayed: ensure_skew
        // rejects its timestamp before the cache is consulted.
        cache.remember("old", unix_now() - 600, window).unwrap();
        assert_eq!(cache.len(), 1);
        cache.remember("fresh", unix_now(), window).unwrap();
        assert_eq!(cache.len(), 1, "the expired entry should have been pruned");
    }

    #[test]
    fn an_unsigned_request_never_reaches_the_cache() {
        let secret = b"s3cret";
        let auth = AuthConfig::new(secret, Duration::from_secs(30)).with_replay_capacity(1);
        let body = b"{}";
        let ts = unix_now().to_string();
        // Garbage signature: if this were remembered, one anonymous request
        // would fill a capacity-1 cache and lock out every real caller.
        let bogus = hdrs(&ts, &"ab".repeat(32), None);
        assert!(verify_http(&bogus, body, &auth).is_err());
        assert!(verify_http(&signed(secret, unix_now(), None, body), body, &auth).is_ok());
    }

    use super::*;

    #[test]
    fn test_auth_method_spiffe_id() {
        let method = AuthMethod::Spiffe {
            spiffe_id: "spiffe://nucleus.local/ns/default/sa/worker".to_string(),
        };
        assert!(method.is_spiffe());
        assert!(!method.is_hmac());
        assert_eq!(
            method.spiffe_id(),
            Some("spiffe://nucleus.local/ns/default/sa/worker")
        );
        assert_eq!(method.trust_domain(), Some("nucleus.local"));
    }

    #[test]
    fn test_auth_method_hmac() {
        let method = AuthMethod::Hmac;
        assert!(method.is_hmac());
        assert!(!method.is_spiffe());
        assert_eq!(method.spiffe_id(), None);
        assert_eq!(method.trust_domain(), None);
    }

    #[test]
    fn test_auth_context_from_spiffe() {
        let ctx = AuthContext::from_spiffe(
            "spiffe://nucleus.local/ns/workstream-kg/sa/orchestrator".to_string(),
        );
        assert_eq!(ctx.actor, Some("orchestrator".to_string()));
        assert!(matches!(ctx.method, AuthMethod::Spiffe { .. }));
    }

    #[test]
    fn test_authorization_policy_orchestrator_allowed() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let ctx =
            AuthContext::from_spiffe("spiffe://nucleus.local/ns/default/sa/worker".to_string());

        // Orchestrator should be allowed all operations
        assert!(policy.authorize(&ctx, Operation::CreatePod).is_ok());
        assert!(policy.authorize(&ctx, Operation::ListPods).is_ok());
        assert!(policy.authorize(&ctx, Operation::GetPod).is_ok());
        assert!(policy.authorize(&ctx, Operation::CancelPod).is_ok());
        assert!(policy.authorize(&ctx, Operation::StreamLogs).is_ok());
    }

    #[test]
    fn test_authorization_policy_cicd_allowed() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let ctx = AuthContext::from_spiffe(
            "spiffe://nucleus.local/ns/github/sa/myorg/myrepo".to_string(),
        );

        // CI/CD should be allowed pod management operations
        assert!(policy.authorize(&ctx, Operation::CreatePod).is_ok());
        assert!(policy.authorize(&ctx, Operation::ListPods).is_ok());
        assert!(policy.authorize(&ctx, Operation::GetPod).is_ok());
        assert!(policy.authorize(&ctx, Operation::CancelPod).is_ok());
        assert!(policy.authorize(&ctx, Operation::StreamLogs).is_ok());
    }

    #[test]
    fn test_authorization_policy_wrong_trust_domain() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let ctx =
            AuthContext::from_spiffe("spiffe://other.domain/ns/default/sa/worker".to_string());

        let result = policy.authorize(&ctx, Operation::CreatePod);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthorizationError::WrongTrustDomain { .. }
        ));
    }

    #[test]
    fn test_authorization_policy_unknown_identity() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        // An identity that doesn't match any known prefix
        let ctx =
            AuthContext::from_spiffe("spiffe://nucleus.local/ns/unknown/sa/worker".to_string());

        let result = policy.authorize(&ctx, Operation::CreatePod);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthorizationError::NotAuthorized { .. }
        ));
    }

    #[test]
    fn test_authorization_policy_hmac_denied_by_default() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let ctx = AuthContext::from_hmac(Some("worker".to_string()), 12345);

        // Fail-closed: HMAC is denied unless explicitly enabled.
        let result = policy.authorize(&ctx, Operation::CreatePod);
        assert!(matches!(
            result.unwrap_err(),
            AuthorizationError::HmacNotAllowed
        ));
    }

    #[test]
    fn test_authorization_policy_hmac_allowed_when_opted_in() {
        let policy = AuthorizationPolicy::new("nucleus.local").allow_hmac();
        let ctx = AuthContext::from_hmac(Some("worker".to_string()), 12345);

        // HMAC is allowed only after explicit opt-in.
        assert!(policy.authorize(&ctx, Operation::CreatePod).is_ok());
    }

    #[test]
    fn test_authorization_policy_hmac_denied_when_required_mtls() {
        let policy = AuthorizationPolicy::new("nucleus.local").require_mtls();
        let ctx = AuthContext::from_hmac(Some("worker".to_string()), 12345);

        let result = policy.authorize(&ctx, Operation::CreatePod);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthorizationError::HmacNotAllowed
        ));
    }

    #[test]
    fn test_authorization_policy_custom_prefixes() {
        let policy = AuthorizationPolicy::new("nucleus.local")
            .with_orchestrator_prefix("spiffe://nucleus.local/ns/custom/sa/")
            .with_cicd_prefix("spiffe://nucleus.local/ns/jenkins/sa/");

        // Custom orchestrator prefix
        let ctx = AuthContext::from_spiffe(
            "spiffe://nucleus.local/ns/custom/sa/my-orchestrator".to_string(),
        );
        assert!(policy.authorize(&ctx, Operation::CreatePod).is_ok());

        // Custom CI/CD prefix
        let ctx = AuthContext::from_spiffe(
            "spiffe://nucleus.local/ns/jenkins/sa/build-agent".to_string(),
        );
        assert!(policy.authorize(&ctx, Operation::CreatePod).is_ok());
    }
}
