//! Client-side signing utilities for nucleus node/proxy APIs.
//!
//! This crate provides HMAC-based request signing for authenticating requests
//! to nucleus-node and nucleus-tool-proxy.
//!
//! # Standard Signing
//!
//! For regular authenticated requests, use [`sign_http_headers`] or [`sign_grpc_headers`]:
//!
//! ```rust
//! use nucleus_client::sign_http_headers;
//!
//! let secret = b"my-secret-key";
//! let body = b"request body";
//! let headers = sign_http_headers(secret, Some("user@example.com"), body);
//!
//! // Add headers to your HTTP request
//! for (key, value) in headers.headers {
//!     // request.header(key, value);
//! }
//! ```
//!
//! # Drand-Anchored Signing
//!
//! For approval requests that require protection against pre-computation attacks,
//! use [`sign_approval_headers`] with a drand round number:
//!
//! ```rust
//! use nucleus_client::{sign_approval_headers, drand::current_expected_round};
//!
//! let secret = b"approval-secret";
//! let body = b"approve read /etc/passwd";
//! let round = current_expected_round();
//! let headers = sign_approval_headers(secret, round, Some("user@example.com"), body);
//!
//! // The signature now includes the drand round, preventing pre-computation
//! ```

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

pub mod drand;

/// Signed headers for an HTTP request.
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// Unix timestamp used in the signature.
    pub timestamp: i64,
    /// Optional actor identifier.
    pub actor: Option<String>,
    /// Header key/value pairs.
    pub headers: Vec<(String, String)>,
}

/// Signed headers with drand anchoring for approval requests.
///
/// These headers include a drand round number that prevents pre-computation
/// attacks even if the HMAC secret is compromised.
#[derive(Debug, Clone)]
pub struct DrandSignedHeaders {
    /// Unix timestamp used in the signature.
    pub timestamp: i64,
    /// Drand round number anchoring the signature.
    pub drand_round: u64,
    /// Optional actor identifier.
    pub actor: Option<String>,
    /// Header key/value pairs.
    pub headers: Vec<(String, String)>,
}

/// Sign an HTTP request body.
///
/// The server expects: `signature = HMAC_SHA256(secret, "{ts}.{actor}.{body}")`.
pub fn sign_http_headers(secret: &[u8], actor: Option<&str>, body: &[u8]) -> SignedHeaders {
    let timestamp = now_unix();
    let actor_value = actor.unwrap_or("");
    let message = build_message(timestamp, actor_value, body);
    let signature = sign_message(secret, &message);

    let mut headers = vec![
        ("x-nucleus-timestamp".to_string(), timestamp.to_string()),
        ("x-nucleus-signature".to_string(), signature),
    ];

    if !actor_value.is_empty() {
        headers.push(("x-nucleus-actor".to_string(), actor_value.to_string()));
    }

    SignedHeaders {
        timestamp,
        actor: actor.map(|s| s.to_string()),
        headers,
    }
}

/// Sign a gRPC method invocation.
///
/// The server expects: `signature = HMAC_SHA256(secret, "{ts}.{actor}.{method}")`.
pub fn sign_grpc_headers(secret: &[u8], actor: Option<&str>, method: &str) -> SignedHeaders {
    let timestamp = now_unix();
    let actor_value = actor.unwrap_or("");
    let message = format!("{timestamp}.{actor_value}.{method}");
    let signature = sign_message(secret, message.as_bytes());

    let mut headers = vec![
        ("x-nucleus-timestamp".to_string(), timestamp.to_string()),
        ("x-nucleus-signature".to_string(), signature),
        ("x-nucleus-method".to_string(), method.to_string()),
    ];

    if !actor_value.is_empty() {
        headers.push(("x-nucleus-actor".to_string(), actor_value.to_string()));
    }

    SignedHeaders {
        timestamp,
        actor: actor.map(|s| s.to_string()),
        headers,
    }
}

/// Sign an approval request with drand anchoring.
///
/// This function creates a signature that includes a drand round number, preventing
/// pre-computation attacks. Even if an attacker extracts the HMAC secret, they cannot
/// pre-compute valid signatures because they don't know future drand rounds.
///
/// The server expects: `signature = HMAC_SHA256(secret, "{round}.{ts}.{actor}.{body}")`.
///
/// # Security Model
///
/// Without drand anchoring:
/// - Attacker extracts secret from compromised VM
/// - Attacker pre-computes signatures for future timestamps
/// - Attacker uses pre-computed tokens indefinitely
///
/// With drand anchoring:
/// - Attacker extracts secret from compromised VM
/// - Attacker cannot predict future drand rounds
/// - Signatures become invalid after ~60 seconds (when round changes)
/// - Attack window is limited to realtime compromise only
///
/// # Example
///
/// ```rust
/// use nucleus_client::{sign_approval_headers, drand::current_expected_round};
///
/// let secret = b"approval-secret";
/// let body = b"approve write /etc/hosts";
/// let round = current_expected_round();
///
/// let headers = sign_approval_headers(secret, round, Some("admin"), body);
///
/// // Headers include x-nucleus-drand-round
/// assert!(headers.headers.iter().any(|(k, _)| k == "x-nucleus-drand-round"));
/// ```
pub fn sign_approval_headers(
    secret: &[u8],
    drand_round: u64,
    actor: Option<&str>,
    body: &[u8],
) -> DrandSignedHeaders {
    let timestamp = now_unix();
    let actor_value = actor.unwrap_or("");
    let message = build_drand_message(drand_round, timestamp, actor_value, body);
    let signature = sign_message(secret, &message);

    let mut headers = vec![
        ("x-nucleus-timestamp".to_string(), timestamp.to_string()),
        ("x-nucleus-drand-round".to_string(), drand_round.to_string()),
        ("x-nucleus-signature".to_string(), signature),
    ];

    if !actor_value.is_empty() {
        headers.push(("x-nucleus-actor".to_string(), actor_value.to_string()));
    }

    DrandSignedHeaders {
        timestamp,
        drand_round,
        actor: actor.map(|s| s.to_string()),
        headers,
    }
}

/// Verify a drand-anchored signature.
///
/// This is useful for testing or when implementing custom verification logic.
/// The tool-proxy uses this format when validating approval requests.
///
/// # Example
///
/// ```rust
/// use nucleus_client::{sign_approval_headers, verify_drand_signature, drand::current_expected_round};
///
/// let secret = b"test-secret";
/// let body = b"test body";
/// let round = current_expected_round();
///
/// let headers = sign_approval_headers(secret, round, Some("actor"), body);
///
/// // Extract values from headers
/// let signature = headers.headers.iter()
///     .find(|(k, _)| k == "x-nucleus-signature")
///     .map(|(_, v)| v.as_str())
///     .unwrap();
///
/// assert!(verify_drand_signature(
///     secret,
///     round,
///     headers.timestamp,
///     Some("actor"),
///     body,
///     signature
/// ));
/// ```
pub fn verify_drand_signature(
    secret: &[u8],
    drand_round: u64,
    timestamp: i64,
    actor: Option<&str>,
    body: &[u8],
    signature: &str,
) -> bool {
    let actor_value = actor.unwrap_or("");
    let message = build_drand_message(drand_round, timestamp, actor_value, body);
    let expected = sign_message(secret, &message);

    // Constant-time comparison to prevent timing attacks
    constant_time_eq(signature.as_bytes(), expected.as_bytes())
}

/// Verify a standard (non-drand) signature.
pub fn verify_signature(
    secret: &[u8],
    timestamp: i64,
    actor: Option<&str>,
    body: &[u8],
    signature: &str,
) -> bool {
    let actor_value = actor.unwrap_or("");
    let message = build_message(timestamp, actor_value, body);
    let expected = sign_message(secret, &message);

    constant_time_eq(signature.as_bytes(), expected.as_bytes())
}

fn build_message(timestamp: i64, actor: &str, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(body.len() + actor.len() + 32);
    message.extend_from_slice(timestamp.to_string().as_bytes());
    message.push(b'.');
    message.extend_from_slice(actor.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    message
}

fn build_drand_message(drand_round: u64, timestamp: i64, actor: &str, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(body.len() + actor.len() + 64);
    message.extend_from_slice(drand_round.to_string().as_bytes());
    message.push(b'.');
    message.extend_from_slice(timestamp.to_string().as_bytes());
    message.push(b'.');
    message.extend_from_slice(actor.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    message
}

fn sign_message(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Maximum age of a sandbox token before it's considered expired.
const MAX_TOKEN_AGE_SECS: u64 = 300;

/// Verified sandbox token payload (pod_id and spec_hash).
#[derive(Debug, Clone)]
pub struct SandboxTokenPayload {
    /// The pod ID embedded in the token.
    pub pod_id: String,
    /// The spec hash embedded in the token.
    pub spec_hash: String,
}

/// Generate an HMAC-signed sandbox token for injection into spawned tool-proxy processes.
///
/// Token format: `sandbox-proof.{pod_id}.{spec_hash}.{timestamp}.{hmac_hex}`
///
/// The token proves that the process was spawned by an authorized orchestrator
/// (nucleus-node) that possesses the shared `auth_secret`.
pub fn generate_sandbox_token(secret: &[u8], pod_id: &str, spec_hash: &str) -> String {
    let timestamp = now_unix() as u64;
    let message = format!("sandbox-proof.{pod_id}.{spec_hash}.{timestamp}");
    let signature = sign_message(secret, message.as_bytes());
    format!("{message}.{signature}")
}

/// Verify an HMAC-signed sandbox token.
///
/// Returns the verified payload (pod_id, spec_hash) on success,
/// or an error string on failure.
pub fn verify_sandbox_token(secret: &[u8], token: &str) -> Result<SandboxTokenPayload, String> {
    if token.is_empty() {
        return Err("empty token".to_string());
    }

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 {
        return Err(format!(
            "malformed token: expected 5 dot-separated parts, got {}",
            parts.len()
        ));
    }

    let prefix = parts[0];
    let pod_id = parts[1];
    let spec_hash = parts[2];
    let timestamp_str = parts[3];
    let provided_sig = parts[4];

    if prefix != "sandbox-proof" {
        return Err(format!(
            "invalid token prefix: expected 'sandbox-proof', got '{prefix}'"
        ));
    }

    // Verify timestamp freshness
    let token_ts: u64 = timestamp_str
        .parse()
        .map_err(|_| format!("invalid timestamp: {timestamp_str}"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now > token_ts + MAX_TOKEN_AGE_SECS {
        return Err(format!(
            "token expired: issued at {token_ts}, now {now}, max age {MAX_TOKEN_AGE_SECS}s"
        ));
    }
    // Also reject tokens from the future (clock skew tolerance: 60s)
    if token_ts > now + 60 {
        return Err(format!(
            "token from the future: issued at {token_ts}, now {now}"
        ));
    }

    // Verify HMAC signature
    let signed_message = format!("sandbox-proof.{pod_id}.{spec_hash}.{timestamp_str}");
    let expected_sig = sign_message(secret, signed_message.as_bytes());

    if !constant_time_eq(provided_sig.as_bytes(), expected_sig.as_bytes()) {
        return Err("invalid signature".to_string());
    }

    Ok(SandboxTokenPayload {
        pod_id: pod_id.to_string(),
        spec_hash: spec_hash.to_string(),
    })
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_http_headers() {
        let secret = b"test-secret";
        let body = b"test body";

        let headers = sign_http_headers(secret, Some("test-actor"), body);

        assert!(headers.timestamp > 0);
        assert_eq!(headers.actor, Some("test-actor".to_string()));
        assert!(headers
            .headers
            .iter()
            .any(|(k, _)| k == "x-nucleus-signature"));
        assert!(headers
            .headers
            .iter()
            .any(|(k, _)| k == "x-nucleus-timestamp"));
        assert!(headers.headers.iter().any(|(k, _)| k == "x-nucleus-actor"));
    }

    #[test]
    fn test_sign_http_headers_no_actor() {
        let secret = b"test-secret";
        let body = b"test body";

        let headers = sign_http_headers(secret, None, body);

        assert!(headers.actor.is_none());
        assert!(!headers.headers.iter().any(|(k, _)| k == "x-nucleus-actor"));
    }

    #[test]
    fn test_sign_approval_headers() {
        let secret = b"test-secret";
        let body = b"test body";
        let round = 12345u64;

        let headers = sign_approval_headers(secret, round, Some("test-actor"), body);

        assert!(headers.timestamp > 0);
        assert_eq!(headers.drand_round, 12345);
        assert_eq!(headers.actor, Some("test-actor".to_string()));
        assert!(headers
            .headers
            .iter()
            .any(|(k, _)| k == "x-nucleus-drand-round"));
        assert!(headers
            .headers
            .iter()
            .any(|(k, v)| k == "x-nucleus-drand-round" && v == "12345"));
    }

    #[test]
    fn test_verify_drand_signature() {
        let secret = b"test-secret";
        let body = b"test body";
        let round = 12345u64;

        let headers = sign_approval_headers(secret, round, Some("actor"), body);

        let signature = headers
            .headers
            .iter()
            .find(|(k, _)| k == "x-nucleus-signature")
            .map(|(_, v)| v.as_str())
            .unwrap();

        // Correct verification
        assert!(verify_drand_signature(
            secret,
            round,
            headers.timestamp,
            Some("actor"),
            body,
            signature
        ));

        // Wrong round
        assert!(!verify_drand_signature(
            secret,
            round + 1,
            headers.timestamp,
            Some("actor"),
            body,
            signature
        ));

        // Wrong secret
        assert!(!verify_drand_signature(
            b"wrong-secret",
            round,
            headers.timestamp,
            Some("actor"),
            body,
            signature
        ));

        // Wrong body
        assert!(!verify_drand_signature(
            secret,
            round,
            headers.timestamp,
            Some("actor"),
            b"wrong body",
            signature
        ));
    }

    #[test]
    fn test_verify_signature() {
        let secret = b"test-secret";
        let body = b"test body";

        let headers = sign_http_headers(secret, Some("actor"), body);

        let signature = headers
            .headers
            .iter()
            .find(|(k, _)| k == "x-nucleus-signature")
            .map(|(_, v)| v.as_str())
            .unwrap();

        assert!(verify_signature(
            secret,
            headers.timestamp,
            Some("actor"),
            body,
            signature
        ));
    }

    #[test]
    fn test_generate_sandbox_token_format() {
        let secret = b"test-secret";
        let token = generate_sandbox_token(secret, "pod-abc", "deadbeef");

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[0], "sandbox-proof");
        assert_eq!(parts[1], "pod-abc");
        assert_eq!(parts[2], "deadbeef");
        // parts[3] is timestamp (numeric)
        assert!(parts[3].parse::<u64>().is_ok());
        // parts[4] is hex HMAC (64 chars for SHA-256)
        assert_eq!(parts[4].len(), 64);
    }

    #[test]
    fn test_verify_sandbox_token_roundtrip() {
        let secret = b"test-secret";
        let token = generate_sandbox_token(secret, "pod-xyz", "cafebabe");

        let payload = verify_sandbox_token(secret, &token).unwrap();
        assert_eq!(payload.pod_id, "pod-xyz");
        assert_eq!(payload.spec_hash, "cafebabe");
    }

    #[test]
    fn test_verify_sandbox_token_wrong_secret() {
        let token = generate_sandbox_token(b"correct", "pod-1", "hash-1");
        assert!(verify_sandbox_token(b"wrong", &token).is_err());
    }

    #[test]
    fn test_verify_sandbox_token_malformed() {
        assert!(verify_sandbox_token(b"s", "").is_err());
        assert!(verify_sandbox_token(b"s", "too.few.parts").is_err());
        assert!(verify_sandbox_token(b"s", "wrong-prefix.a.b.123.deadbeef").is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"hello", b"hell"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }
}
