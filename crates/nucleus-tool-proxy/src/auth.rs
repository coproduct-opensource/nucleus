//! Request authentication and signature verification.
//!
//! This module provides multiple authentication modes for tool-proxy requests:
//!
//! 1. **HMAC-based auth**: Traditional shared-secret signatures with optional
//!    drand anchoring to prevent pre-computation attacks.
//!
//! 2. **SPIFFE mTLS auth**: Zero-secret authentication using SPIFFE workload
//!    identity certificates. The client's identity is derived from their
//!    X.509 certificate's SPIFFE URI SAN, not from static secrets.
//!
//! # Security Model
//!
//! - **HMAC mode**: Requires shared secrets, vulnerable to secret extraction
//! - **mTLS mode**: No secrets to extract; identity is attested by CA
//! - **Drand anchoring**: Limits HMAC attack window to ~60 seconds
//!
//! The recommended configuration is mTLS mode with SPIFFE certificates,
//! which eliminates static secrets entirely.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use hmac::{digest::KeyInit, Hmac, Mac};
use nucleus_client::drand::{self, DrandConfig, DrandFailMode};
use sha2::Sha256;

const HEADER_TIMESTAMP: &str = "x-nucleus-timestamp";
const HEADER_SIGNATURE: &str = "x-nucleus-signature";
const HEADER_ACTOR: &str = "x-nucleus-actor";
const HEADER_DRAND_ROUND: &str = "x-nucleus-drand-round";

/// Configuration for request authentication.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    secret: Arc<Vec<u8>>,
    max_skew: Duration,
    drand_config: Option<DrandConfig>,
}

impl AuthConfig {
    /// Create a new auth config with the given secret and maximum timestamp skew.
    pub fn new(secret: impl AsRef<[u8]>, max_skew: Duration) -> Self {
        Self {
            secret: Arc::new(secret.as_ref().to_vec()),
            max_skew,
            drand_config: None,
        }
    }

    /// Add drand configuration for anchored signature verification.
    ///
    /// When drand is configured, the verifier will check for and validate
    /// drand round numbers in approval requests.
    pub fn with_drand(mut self, config: DrandConfig) -> Self {
        self.drand_config = Some(config);
        self
    }

    /// Get the maximum allowed timestamp skew.
    pub fn max_skew(&self) -> Duration {
        self.max_skew
    }

    /// Get the HMAC secret.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Get the drand configuration, if any.
    #[allow(dead_code)]
    pub fn drand_config(&self) -> Option<&DrandConfig> {
        self.drand_config.as_ref()
    }

    /// Check if drand anchoring is enabled.
    #[allow(dead_code)]
    pub fn drand_enabled(&self) -> bool {
        self.drand_config
            .as_ref()
            .is_some_and(|config| config.enabled)
    }
}

/// Context extracted from a verified request.
#[derive(Clone, Debug)]
pub struct AuthContext {
    /// The actor (user/service) that made the request.
    #[allow(dead_code)]
    pub actor: Option<String>,
    /// The Unix timestamp from the request.
    #[allow(dead_code)]
    pub timestamp: i64,
    /// The drand round, if the request was drand-anchored.
    pub drand_round: Option<u64>,
    /// The SPIFFE identity, if authenticated via mTLS.
    pub spiffe_id: Option<String>,
    /// The authentication method used.
    pub auth_method: AuthMethod,
    /// How identity was bound to permissions (SPIFFE identity fusion).
    pub identity_binding: IdentityBinding,
}

/// The method used to authenticate the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthMethod {
    /// HMAC-based signature verification (legacy).
    Hmac,
    /// HMAC with drand anchoring (prevents pre-computation).
    HmacDrand,
    /// SPIFFE mTLS certificate (no shared secrets).
    SpiffeMtls,
    /// The request arrived on a vsock listener that accepts only the host.
    ///
    /// No shared secret and no certificate: the guest kernel sets the peer CID
    /// on an accepted AF_VSOCK connection and a guest process cannot forge it,
    /// so "this came from the host" is enforced below the application rather
    /// than asserted by it. See `pod_mgmt::peer_is_host`.
    HostVsock,
}

/// How the request's identity was bound to its permissions.
///
/// Part of the SPIFFE identity fusion: tracks whether the authenticated identity
/// has been cryptographically bound to a delegation certificate's permissions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityBinding {
    /// No delegation cert present; permissions from policy engine only.
    PolicyOnly,
    /// Delegation cert present and leaf_identity verified against auth identity.
    DelegationVerified {
        /// The leaf identity from the delegation certificate.
        leaf_identity: String,
    },
    /// CA-attested binding: permission fingerprint embedded in X.509 extension.
    Fused {
        /// SHA-256 fingerprint of the LatticeCertificate.
        permission_fingerprint: [u8; 32],
    },
}

/// Errors that can occur during authentication.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// A required header is missing.
    #[error("missing auth header: {0}")]
    MissingHeader(&'static str),

    /// A header has an invalid value.
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),

    /// The HMAC signature is invalid.
    #[error("invalid signature")]
    InvalidSignature,

    /// The timestamp is too far from the current time.
    #[error("timestamp skew too large")]
    Skew,

    /// The drand round is expired or invalid.
    #[error("drand round {provided} is not current (expected {expected} ± {tolerance})")]
    DrandRoundExpired {
        provided: u64,
        expected: u64,
        tolerance: u64,
    },

    /// Drand is required but no round was provided.
    #[error("drand anchoring required but no round provided")]
    DrandRequired,
}

/// Verify an HTTP request with standard timestamp-based authentication.
///
/// Message format: `"{timestamp}.{actor}.{body}"`
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

    let timestamp = parse_timestamp(ts)?;
    ensure_skew(timestamp, auth.max_skew())?;

    let mut message = Vec::with_capacity(ts.len() + actor_value.len() + 2 + body.len());
    message.extend_from_slice(ts.as_bytes());
    message.push(b'.');
    message.extend_from_slice(actor_value.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);

    verify_signature(auth.secret(), &message, sig)?;

    Ok(AuthContext {
        actor,
        timestamp,
        drand_round: None,
        spiffe_id: None,
        auth_method: AuthMethod::Hmac,
        identity_binding: IdentityBinding::PolicyOnly,
    })
}

/// Verify an HTTP request with optional drand anchoring.
///
/// This function checks for a drand round header and validates accordingly:
///
/// - If drand is enabled and a round is provided: Validates the round is current
///   and verifies the drand-anchored signature.
/// - If drand is enabled but no round is provided: Behavior depends on fail mode.
/// - If drand is disabled: Falls back to standard verification.
///
/// # Message Formats
///
/// - **With drand**: `"{round}.{timestamp}.{actor}.{body}"`
/// - **Without drand**: `"{timestamp}.{actor}.{body}"`
///
/// # Security Note
///
/// Drand anchoring prevents pre-computation attacks. Even if an attacker extracts
/// the HMAC secret, they cannot pre-compute valid signatures because they don't
/// know future drand rounds. The attack window is limited to ~60 seconds.
pub fn verify_http_with_drand(
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

    let timestamp = parse_timestamp(ts)?;
    ensure_skew(timestamp, auth.max_skew())?;

    // Check for drand round header
    let drand_round = headers
        .get(HEADER_DRAND_ROUND)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    // Handle drand verification if configured
    if let Some(ref drand_config) = auth.drand_config {
        if drand_config.enabled {
            match drand_round {
                Some(round) => {
                    // Validate round is current
                    let expected = drand::current_expected_round();
                    if !drand::validate_round(round, drand_config.round_tolerance) {
                        return Err(AuthError::DrandRoundExpired {
                            provided: round,
                            expected,
                            tolerance: drand_config.round_tolerance,
                        });
                    }

                    // Build message with drand round prefix
                    let round_str = round.to_string();
                    let mut message = Vec::with_capacity(
                        round_str.len() + ts.len() + actor_value.len() + 3 + body.len(),
                    );
                    message.extend_from_slice(round_str.as_bytes());
                    message.push(b'.');
                    message.extend_from_slice(ts.as_bytes());
                    message.push(b'.');
                    message.extend_from_slice(actor_value.as_bytes());
                    message.push(b'.');
                    message.extend_from_slice(body);

                    verify_signature(auth.secret(), &message, sig)?;

                    return Ok(AuthContext {
                        actor,
                        timestamp,
                        drand_round: Some(round),
                        spiffe_id: None,
                        auth_method: AuthMethod::HmacDrand,
                        identity_binding: IdentityBinding::PolicyOnly,
                    });
                }
                None => {
                    // No round provided - behavior depends on fail mode
                    match drand_config.fail_mode {
                        DrandFailMode::Strict => {
                            return Err(AuthError::DrandRequired);
                        }
                        DrandFailMode::Cached => {
                            // In cached mode, we allow fallback to non-drand verification
                            // but this should only happen during brief drand outages
                            tracing::warn!(
                                "drand anchoring enabled but no round provided, accepting without anchoring (cached mode)"
                            );
                        }
                    }
                }
            }
        }
    }

    // Fall back to non-drand verification
    let mut message = Vec::with_capacity(ts.len() + actor_value.len() + 2 + body.len());
    message.extend_from_slice(ts.as_bytes());
    message.push(b'.');
    message.extend_from_slice(actor_value.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);

    verify_signature(auth.secret(), &message, sig)?;

    Ok(AuthContext {
        actor,
        timestamp,
        drand_round: None,
        spiffe_id: None,
        auth_method: AuthMethod::Hmac,
        identity_binding: IdentityBinding::PolicyOnly,
    })
}

/// Authenticate a request purely from the transport it arrived on.
///
/// # Why this needs no secret
///
/// `pod_mgmt::VsockAxumListener` drops every peer whose CID is not
/// `VMADDR_CID_HOST`, and the guest kernel — not the caller — sets that CID.
/// So a request that reaches the router over that listener has already been
/// proven to come from the host, by a mechanism no guest process can influence.
///
/// This replaces `verify_http`'s HMAC on the vsock path. The HMAC key travelled
/// on the kernel command line, where the agent could read it out of
/// `/proc/cmdline` and sign its own requests — a trust boundary drawn inside a
/// single trust domain, which cannot hold. Verified empirically on a real
/// kernel: an in-guest loopback peer arrives as CID 1, never CID 2.
///
/// Deliberately NOT a fallback. It is selected only when the server was started
/// on a host-verified vsock listener; every other transport keeps its existing
/// mechanism.
pub fn verify_host_vsock() -> AuthContext {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    AuthContext {
        actor: Some("host".to_string()),
        timestamp: now,
        drand_round: None,
        spiffe_id: None,
        auth_method: AuthMethod::HostVsock,
        identity_binding: IdentityBinding::PolicyOnly,
    }
}

/// Verify a request using SPIFFE mTLS identity.
///
/// This function validates that a SPIFFE identity was extracted from the
/// client's mTLS certificate. No HMAC signature verification is required
/// because the identity is cryptographically attested by the CA.
///
/// # Arguments
///
/// * `spiffe_id` - The SPIFFE ID extracted from the client certificate
///
/// # Returns
///
/// An `AuthContext` with the SPIFFE identity as the actor.
///
/// # Security Note
///
/// This is the most secure authentication method because:
/// 1. No static secrets that can be extracted
/// 2. Identity is attested by the CA, not self-declared
/// 3. Certificates auto-rotate, limiting compromise window
pub fn verify_spiffe_mtls(spiffe_id: &str) -> AuthContext {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    AuthContext {
        actor: Some(spiffe_id.to_string()),
        timestamp: now,
        drand_round: None,
        spiffe_id: Some(spiffe_id.to_string()),
        auth_method: AuthMethod::SpiffeMtls,
        identity_binding: IdentityBinding::PolicyOnly,
    }
}

/// Which authentication mechanism a request should be judged by.
///
/// Extracted from the request handler so the PRECEDENCE is unit-testable. The
/// order is security-critical and easy to get wrong invisibly: if
/// [`AuthTier::HostVsock`] were consulted after the HMAC fallback it would be
/// dead code, and every request would still need a key the agent can read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthTier {
    /// A client certificate was presented — strongest, and independent of how
    /// the server was bound.
    SpiffeMtls,
    /// The approval endpoint, which has its own drand-anchored HMAC.
    ApprovalHmacDrand,
    /// The transport already proved the peer is the host.
    HostVsock,
    /// Shared-secret HMAC. The residual path, for transports that prove nothing.
    Hmac,
}

/// Choose the tier from facts about the request and the binding.
///
/// `host_verified_transport` is a property of how the server was STARTED, never
/// of the request — see `AppState::host_verified_transport`.
pub fn select_auth_tier(
    has_spiffe_identity: bool,
    is_approval_path: bool,
    host_verified_transport: bool,
) -> AuthTier {
    if has_spiffe_identity {
        AuthTier::SpiffeMtls
    } else if is_approval_path {
        AuthTier::ApprovalHmacDrand
    } else if host_verified_transport {
        AuthTier::HostVsock
    } else {
        AuthTier::Hmac
    }
}

/// Check if a request has valid SPIFFE mTLS credentials.
///
/// Returns the SPIFFE ID if present and valid, None otherwise.
pub fn extract_spiffe_id_from_extensions(extensions: &axum::http::Extensions) -> Option<String> {
    use crate::mtls::{ClientCertInfo, MtlsConnectInfo};

    // Try MtlsConnectInfo first (standard path)
    if let Some(info) = extensions.get::<MtlsConnectInfo>() {
        if let Some(ref cert) = info.client_cert {
            return cert.spiffe_id.clone();
        }
    }

    // Fall back to direct ClientCertInfo
    if let Some(cert) = extensions.get::<ClientCertInfo>() {
        return cert.spiffe_id.clone();
    }

    None
}

fn header_value<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, AuthError> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .ok_or(AuthError::MissingHeader(name))
}

fn parse_timestamp(ts: &str) -> Result<i64, AuthError> {
    ts.parse::<i64>()
        .map_err(|_| AuthError::InvalidHeader(HEADER_TIMESTAMP))
}

fn ensure_skew(timestamp: i64, max_skew: Duration) -> Result<(), AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
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

/// Sign a message with HMAC-SHA256.
pub fn sign_message(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn make_headers(timestamp: i64, signature: &str, actor: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_TIMESTAMP,
            HeaderValue::from_str(&timestamp.to_string()).unwrap(),
        );
        headers.insert(HEADER_SIGNATURE, HeaderValue::from_str(signature).unwrap());
        if let Some(a) = actor {
            headers.insert(HEADER_ACTOR, HeaderValue::from_str(a).unwrap());
        }
        headers
    }

    fn make_drand_headers(
        timestamp: i64,
        round: u64,
        signature: &str,
        actor: Option<&str>,
    ) -> HeaderMap {
        let mut headers = make_headers(timestamp, signature, actor);
        headers.insert(
            HEADER_DRAND_ROUND,
            HeaderValue::from_str(&round.to_string()).unwrap(),
        );
        headers
    }

    fn current_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    #[test]
    fn test_verify_http_success() {
        let secret = b"test-secret";
        let body = b"test body";
        let ts = current_timestamp();
        let actor = "test-actor";

        let message = format!("{}.{}.{}", ts, actor, String::from_utf8_lossy(body));
        let signature = sign_message(secret, message.as_bytes());

        let headers = make_headers(ts, &signature, Some(actor));
        let auth = AuthConfig::new(secret, Duration::from_secs(60));

        let result = verify_http(&headers, body, &auth);
        assert!(result.is_ok());

        let ctx = result.unwrap();
        assert_eq!(ctx.actor, Some("test-actor".to_string()));
        assert_eq!(ctx.timestamp, ts);
        assert!(ctx.drand_round.is_none());
    }

    #[test]
    fn test_verify_http_with_drand_success() {
        let secret = b"test-secret";
        let body = b"test body";
        let ts = current_timestamp();
        let actor = "test-actor";
        let round = drand::current_expected_round();

        // Build drand-anchored message: "{round}.{timestamp}.{actor}.{body}"
        let message = format!(
            "{}.{}.{}.{}",
            round,
            ts,
            actor,
            String::from_utf8_lossy(body)
        );
        let signature = sign_message(secret, message.as_bytes());

        let headers = make_drand_headers(ts, round, &signature, Some(actor));
        let auth =
            AuthConfig::new(secret, Duration::from_secs(60)).with_drand(DrandConfig::default());

        let result = verify_http_with_drand(&headers, body, &auth);
        assert!(result.is_ok(), "expected success, got {:?}", result);

        let ctx = result.unwrap();
        assert_eq!(ctx.actor, Some("test-actor".to_string()));
        assert_eq!(ctx.timestamp, ts);
        assert_eq!(ctx.drand_round, Some(round));
    }

    #[test]
    fn test_verify_http_with_drand_expired_round() {
        let secret = b"test-secret";
        let body = b"test body";
        let ts = current_timestamp();
        let actor = "test-actor";
        let old_round = 1u64; // Very old round

        let message = format!(
            "{}.{}.{}.{}",
            old_round,
            ts,
            actor,
            String::from_utf8_lossy(body)
        );
        let signature = sign_message(secret, message.as_bytes());

        let headers = make_drand_headers(ts, old_round, &signature, Some(actor));
        let auth =
            AuthConfig::new(secret, Duration::from_secs(60)).with_drand(DrandConfig::default());

        let result = verify_http_with_drand(&headers, body, &auth);
        assert!(matches!(result, Err(AuthError::DrandRoundExpired { .. })));
    }

    #[test]
    fn test_verify_http_with_drand_required_but_missing() {
        let secret = b"test-secret";
        let body = b"test body";
        let ts = current_timestamp();
        let actor = "test-actor";

        // Non-drand message format
        let message = format!("{}.{}.{}", ts, actor, String::from_utf8_lossy(body));
        let signature = sign_message(secret, message.as_bytes());

        // No drand round header
        let headers = make_headers(ts, &signature, Some(actor));
        let auth = AuthConfig::new(secret, Duration::from_secs(60)).with_drand(DrandConfig {
            enabled: true,
            fail_mode: DrandFailMode::Strict,
            ..Default::default()
        });

        let result = verify_http_with_drand(&headers, body, &auth);
        assert!(matches!(result, Err(AuthError::DrandRequired)));
    }

    #[test]
    fn test_verify_http_with_drand_cached_mode() {
        let secret = b"test-secret";
        let body = b"test body";
        let ts = current_timestamp();
        let actor = "test-actor";

        // Non-drand message format
        let message = format!("{}.{}.{}", ts, actor, String::from_utf8_lossy(body));
        let signature = sign_message(secret, message.as_bytes());

        // No drand round header, but cached mode allows fallback
        let headers = make_headers(ts, &signature, Some(actor));
        let auth = AuthConfig::new(secret, Duration::from_secs(60)).with_drand(DrandConfig {
            enabled: true,
            fail_mode: DrandFailMode::Cached,
            ..Default::default()
        });

        let result = verify_http_with_drand(&headers, body, &auth);
        assert!(
            result.is_ok(),
            "cached mode should accept without drand during fallback"
        );

        let ctx = result.unwrap();
        assert!(ctx.drand_round.is_none());
    }

    #[test]
    fn test_verify_http_with_drand_disabled() {
        let secret = b"test-secret";
        let body = b"test body";
        let ts = current_timestamp();
        let actor = "test-actor";

        // Non-drand message format
        let message = format!("{}.{}.{}", ts, actor, String::from_utf8_lossy(body));
        let signature = sign_message(secret, message.as_bytes());

        let headers = make_headers(ts, &signature, Some(actor));
        let auth =
            AuthConfig::new(secret, Duration::from_secs(60)).with_drand(DrandConfig::disabled());

        let result = verify_http_with_drand(&headers, body, &auth);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_spiffe_mtls() {
        let spiffe_id = "spiffe://nucleus.local/ns/default/sa/test-agent";
        let ctx = verify_spiffe_mtls(spiffe_id);

        assert_eq!(ctx.actor, Some(spiffe_id.to_string()));
        assert_eq!(ctx.spiffe_id, Some(spiffe_id.to_string()));
        assert_eq!(ctx.auth_method, AuthMethod::SpiffeMtls);
        assert!(ctx.drand_round.is_none());
    }

    #[test]
    fn test_auth_method_equality() {
        assert_eq!(AuthMethod::Hmac, AuthMethod::Hmac);
        assert_eq!(AuthMethod::HmacDrand, AuthMethod::HmacDrand);
        assert_eq!(AuthMethod::SpiffeMtls, AuthMethod::SpiffeMtls);
        assert_ne!(AuthMethod::Hmac, AuthMethod::SpiffeMtls);
        assert_ne!(AuthMethod::HmacDrand, AuthMethod::SpiffeMtls);
    }

    #[test]
    fn test_verify_http_returns_hmac_auth_method() {
        let secret = b"test-secret";
        let body = b"test body";
        let ts = current_timestamp();
        let actor = "test-actor";

        let message = format!("{}.{}.{}", ts, actor, String::from_utf8_lossy(body));
        let signature = sign_message(secret, message.as_bytes());

        let headers = make_headers(ts, &signature, Some(actor));
        let auth = AuthConfig::new(secret, Duration::from_secs(60));

        let ctx = verify_http(&headers, body, &auth).unwrap();
        assert_eq!(ctx.auth_method, AuthMethod::Hmac);
        assert!(ctx.spiffe_id.is_none());
    }

    #[test]
    fn test_verify_http_with_drand_returns_hmac_drand_auth_method() {
        let secret = b"test-secret";
        let body = b"test body";
        let ts = current_timestamp();
        let actor = "test-actor";
        let round = drand::current_expected_round();

        let message = format!(
            "{}.{}.{}.{}",
            round,
            ts,
            actor,
            String::from_utf8_lossy(body)
        );
        let signature = sign_message(secret, message.as_bytes());

        let headers = make_drand_headers(ts, round, &signature, Some(actor));
        let auth =
            AuthConfig::new(secret, Duration::from_secs(60)).with_drand(DrandConfig::default());

        let ctx = verify_http_with_drand(&headers, body, &auth).unwrap();
        assert_eq!(ctx.auth_method, AuthMethod::HmacDrand);
        assert!(ctx.spiffe_id.is_none());
    }
}

#[cfg(test)]
mod host_vsock_auth_tests {
    use super::*;

    /// Transport-derived auth carries no secret and no certificate — the
    /// transport itself is the evidence.
    #[test]
    fn host_vsock_context_names_its_method_and_holds_no_credential() {
        let ctx = verify_host_vsock();
        assert_eq!(ctx.auth_method, AuthMethod::HostVsock);
        assert_eq!(ctx.actor.as_deref(), Some("host"));
        assert!(ctx.spiffe_id.is_none(), "no certificate is involved");
        assert!(ctx.drand_round.is_none(), "no drand anchoring is involved");
    }

    /// `HostVsock` must be a DISTINCT method, not an alias of the HMAC path.
    /// Collapsing them would make an audit record unable to say whether a
    /// request was proven by the kernel or by a key the agent could read.
    #[test]
    fn host_vsock_is_distinguishable_from_the_secret_based_methods() {
        let ctx = verify_host_vsock();
        assert_ne!(ctx.auth_method, AuthMethod::Hmac);
        assert_ne!(ctx.auth_method, AuthMethod::HmacDrand);
        assert_ne!(ctx.auth_method, AuthMethod::SpiffeMtls);
    }

    /// It takes NO arguments. That is the security property in the signature:
    /// there is no header, token or field a request could supply to select this
    /// method — it is chosen from how the server was bound, never from input.
    /// If this ever grows a parameter derived from the request, the guarantee
    /// is gone.
    #[test]
    fn host_vsock_cannot_be_influenced_by_request_data() {
        let a = verify_host_vsock();
        let b = verify_host_vsock();
        assert_eq!(a.auth_method, b.auth_method);
        assert_eq!(a.actor, b.actor);
    }
}

#[cfg(test)]
mod auth_tier_precedence_tests {
    use super::*;

    /// THE ORDERING PROPERTY. On a host-verified transport, a plain request
    /// must reach `HostVsock` and NOT fall through to the shared-secret HMAC.
    /// If the tiers were reordered, this is what fails.
    #[test]
    fn a_host_verified_transport_skips_the_shared_secret_hmac() {
        assert_eq!(
            select_auth_tier(false, false, true),
            AuthTier::HostVsock,
            "a request on a host-only vsock listener must not need the HMAC key"
        );
    }

    /// Without a host-verified transport the HMAC remains — this change removes
    /// a secret where the transport replaces it, it does not remove auth.
    #[test]
    fn other_transports_still_require_the_hmac() {
        assert_eq!(select_auth_tier(false, false, false), AuthTier::Hmac);
    }

    /// A certificate outranks the transport: mTLS identifies WHO, the transport
    /// only identifies WHERE FROM. Losing the SPIFFE identity would discard the
    /// stronger claim.
    #[test]
    fn mtls_outranks_the_transport() {
        assert_eq!(select_auth_tier(true, false, true), AuthTier::SpiffeMtls);
        assert_eq!(select_auth_tier(true, true, true), AuthTier::SpiffeMtls);
    }

    /// The approval path keeps its drand anchoring even on a host-verified
    /// transport. Being from the host proves origin, not freshness — drand is
    /// what stops pre-computation, and the transport says nothing about that.
    #[test]
    fn the_approval_path_keeps_drand_even_on_a_host_verified_transport() {
        assert_eq!(
            select_auth_tier(false, true, true),
            AuthTier::ApprovalHmacDrand,
            "origin is not freshness — approvals must stay drand-anchored"
        );
    }

    /// Exhaustive over all eight inputs, so no combination is unconsidered.
    #[test]
    fn every_combination_is_pinned() {
        let cases = [
            ((false, false, false), AuthTier::Hmac),
            ((false, false, true), AuthTier::HostVsock),
            ((false, true, false), AuthTier::ApprovalHmacDrand),
            ((false, true, true), AuthTier::ApprovalHmacDrand),
            ((true, false, false), AuthTier::SpiffeMtls),
            ((true, false, true), AuthTier::SpiffeMtls),
            ((true, true, false), AuthTier::SpiffeMtls),
            ((true, true, true), AuthTier::SpiffeMtls),
        ];
        for ((spiffe, approval, host), expected) in cases {
            assert_eq!(
                select_auth_tier(spiffe, approval, host),
                expected,
                "spiffe={spiffe} approval={approval} host_verified={host}"
            );
        }
    }
}
