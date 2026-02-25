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
use hmac::{Hmac, Mac};
use nucleus_client::drand::{self, DrandConfig, DrandFailMode};
use nucleus_proto::headers::{HEADER_ACTOR, HEADER_DRAND_ROUND, HEADER_SIGNATURE, HEADER_TIMESTAMP};
use sha2::Sha256;

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
    })
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
