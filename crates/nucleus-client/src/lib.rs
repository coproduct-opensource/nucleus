//! Client-side signing utilities for nucleus node/proxy APIs.
//!
//! This crate provides request signing: HMAC request signers, which the SDKs'
//! `HmacAuth` still uses (whether any server still accepts them is traced in
//! `docs/design/zero-static-secrets.md`, item 2), and the Ed25519 approval
//! signer the tool-proxy's `/v1/approve` accepts.
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
//! # Approvals
//!
//! An approval is signed with an approver's Ed25519 key, anchored to a drand
//! round, using [`sign_approval_headers_ed25519`]. The tool-proxy holds only
//! the approver's PUBLIC key, so nothing it stores can sign one:
//!
//! ```rust
//! use nucleus_client::{sign_approval_headers_ed25519, drand::current_expected_round};
//!
//! let approver = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
//! let body = b"{\"operation\":\"read /etc/hosts\",\"count\":1,\"nonce\":\"n-1\"}";
//! let round = current_expected_round();
//! let headers = sign_approval_headers_ed25519(&approver, round, Some("approver"), body);
//!
//! assert!(headers.headers.iter().any(|(k, _)| k == "x-nucleus-drand-round"));
//! ```
//!
//! The HMAC approval signer this crate used to export (`sign_approval_headers`,
//! keyed by a shared approval secret) is deleted with the tool-proxy tier that
//! accepted it (2026-11-21): a shared key is held by the verifier, so the
//! verifier could forge what it checked.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::Sha256;

pub mod drand;
/// Egress admission proofs: a host the pod's policy allows.
pub mod egress;
/// Where a client reaches the tool-proxy: the one parser of a proxy URL.
pub mod endpoint;
/// The tool-proxy's file and command wire format, declared once.
pub mod wire;

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
/// These headers include a drand round number, so a signature cannot be made
/// ahead of the round it names ([`sign_approval_headers_ed25519`]).
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
/// The bytes an Article 12 record's signature must cover: the DESTINATION as
/// well as the payload.
///
/// # The defect this closes
///
/// `art12_append` verified the signature over the request BODY alone, while the
/// `session_id` that decides which chain the record lands in came from the URL
/// path and was only sanitised against traversal. So a validly-signed record
/// could be replayed into ANY session's chain by changing the path — and every
/// pod configured with the node-wide receipt secret can sign. On the evidence
/// path (EU AI Act Article 12 record-keeping), that is one tenant able to write
/// into another tenant's audit chain.
///
/// A signature that authenticates a payload but not its destination is not
/// authenticating the thing that matters.
///
/// # Framing
///
/// Length-prefixed, not concatenated. `session_id || body` is ambiguous: a
/// session id ending in digits and a body starting with them can be re-split,
/// so two different (session, body) pairs could share one signature. The
/// domain tag makes these bytes unusable as any other signature in the system.
#[must_use]
pub fn art12_signed_bytes(session_id: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(session_id.len() + body.len() + 32);
    out.extend_from_slice(b"nucleus-art12-v2\0");
    out.extend_from_slice(&(session_id.len() as u64).to_be_bytes());
    out.extend_from_slice(session_id.as_bytes());
    out.extend_from_slice(body);
    out
}

/// The header a pod uses to state which pod it is.
///
/// Defined here, in the crate BOTH the node and the tool-proxy already depend on,
/// rather than as a literal on each side. The failure this prevents is quiet: if
/// the two spellings drifted, every caller would present nothing the node
/// recognises and be treated as unidentified -- the fail-OPEN direction, with no
/// error raised anywhere. One definition makes that drift a compile error instead
/// of a behaviour change nobody would notice.
pub const HEADER_POD_ID: &str = "x-nucleus-pod-id";

/// The header carrying the token that PROVES the claim in [`HEADER_POD_ID`].
/// The id alone is not a credential -- anyone can name a pod.
pub const HEADER_POD_TOKEN: &str = "x-nucleus-pod-token";

pub fn sign_http_headers(secret: &[u8], actor: Option<&str>, body: &[u8]) -> SignedHeaders {
    let timestamp = now_unix();
    let actor_value = actor.unwrap_or("");
    let nonce = fresh_nonce();
    let message = build_message(timestamp, actor_value, Some(&nonce), body);
    let signature = sign_message(secret, &message);

    let mut headers = vec![
        ("x-nucleus-timestamp".to_string(), timestamp.to_string()),
        ("x-nucleus-signature".to_string(), signature),
        ("x-nucleus-nonce".to_string(), nonce),
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
    let nonce = fresh_nonce();
    let message = format!("{timestamp}.{actor_value}.{nonce}.{method}");
    let signature = sign_message(secret, message.as_bytes());

    let mut headers = vec![
        ("x-nucleus-timestamp".to_string(), timestamp.to_string()),
        ("x-nucleus-signature".to_string(), signature),
        ("x-nucleus-nonce".to_string(), nonce),
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

/// Sign an approval with an Ed25519 approver key, drand-anchored.
///
/// The only approval signer: the tool-proxy's `/v1/approve` accepts an
/// approver's Ed25519 signature against the public keys it was provisioned
/// with (`nucleus.approval_pubkeys`) and nothing else. The HMAC signer
/// (`sign_approval_headers`) and its `verify_drand_signature` were deleted on
/// 2026-11-21 with the tool-proxy's HMAC approval tier: a shared key is held by
/// whoever verifies it, so the verifier could forge the approvals it checked.
///
/// The message is `{round}.{timestamp}.{actor}.` followed by the body, the
/// framing the deleted HMAC tier also used. The signature header
/// carries 128 hex characters, and the verifier uses `verify_strict`, which
/// rejects the small-order points a cofactored check would accept.
pub fn sign_approval_headers_ed25519(
    signing_key: &ed25519_dalek::SigningKey,
    drand_round: u64,
    actor: Option<&str>,
    body: &[u8],
) -> DrandSignedHeaders {
    use ed25519_dalek::Signer as _;
    let timestamp = now_unix();
    let actor_value = actor.unwrap_or("");
    let message = build_drand_message(drand_round, timestamp, actor_value, body);
    let signature = hex::encode(signing_key.sign(&message).to_bytes());

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

/// Verify a request signature.
///
/// `nonce` must be whatever the signer sent in `x-nucleus-nonce`, or `None` if
/// it sent none. It is a parameter rather than an assumption because the nonce
/// is part of the signed bytes: guessing wrong here does not weaken the check,
/// it just fails to verify a legitimate signature.
pub fn verify_signature(
    secret: &[u8],
    timestamp: i64,
    actor: Option<&str>,
    nonce: Option<&str>,
    body: &[u8],
    signature: &str,
) -> bool {
    // Fail-closed: never authenticate against a world-known (empty) key.
    if !auth_secret_is_usable(secret) {
        return false;
    }
    let actor_value = actor.unwrap_or("");
    let message = build_message(timestamp, actor_value, nonce, body);
    let expected = sign_message(secret, &message);

    constant_time_eq(signature.as_bytes(), expected.as_bytes())
}

/// `{ts}.{actor}.{nonce}.{tail}` — must stay byte-identical to the node's
/// `auth::build_message`, which reconstructs this to check the signature.
fn build_message(timestamp: i64, actor: &str, nonce: Option<&str>, body: &[u8]) -> Vec<u8> {
    let nonce_len = nonce.map_or(0, |n| n.len() + 1);
    let mut message = Vec::with_capacity(body.len() + actor.len() + nonce_len + 32);
    message.extend_from_slice(timestamp.to_string().as_bytes());
    message.push(b'.');
    message.extend_from_slice(actor.as_bytes());
    message.push(b'.');
    if let Some(nonce) = nonce {
        message.extend_from_slice(nonce.as_bytes());
        message.push(b'.');
    }
    message.extend_from_slice(body);
    message
}

/// A fresh per-request nonce.
///
/// Without one, two byte-identical requests in the same second produce the same
/// signature, and the node cannot tell the second from a replay — so it refuses
/// it. Polling the same endpoint twice a second is a normal thing for a client
/// to do, so the client always sends a nonce.
fn fresh_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
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

/// Fail-closed usability check for an HMAC auth secret.
///
/// `Hmac::<Sha256>::new_from_slice` accepts a key of ANY length, including the
/// empty key — so an empty `auth_secret` is a *world-known* key: an attacker can
/// compute `HMAC(∅, msg)` themselves and forge any signature.
/// Every verifier consults this first and refuses to authenticate against an
/// empty key, so a mis-provisioned (empty) secret fails closed instead of
/// silently accepting forgeries.
#[must_use]
pub fn auth_secret_is_usable(secret: &[u8]) -> bool {
    !secret.is_empty()
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
    fn empty_secret_never_verifies_request_signature() {
        let ts = now_unix();
        let body = b"payload";
        // World-known empty-key signature over the exact message the verifier builds.
        let forged = sign_message(b"", &build_message(ts, "", None, body));
        assert!(
            !verify_signature(b"", ts, None, None, body, &forged),
            "empty auth secret must never verify a request signature (fail-closed)"
        );
        // No regression: a real secret verifies.
        let real: &[u8] = b"a-real-16byte-secret!!";
        let sig = sign_message(real, &build_message(ts, "", None, body));
        assert!(verify_signature(real, ts, None, None, body, &sig));
    }

    #[test]
    fn auth_secret_usable_rejects_only_empty() {
        assert!(!auth_secret_is_usable(b""));
        assert!(auth_secret_is_usable(b"x"));
        assert!(auth_secret_is_usable(&[0u8; 16]));
    }

    #[test]
    fn test_sign_http_headers() {
        let secret = b"test-secret";
        let body = b"test body";

        let headers = sign_http_headers(secret, Some("test-actor"), body);

        assert!(headers.timestamp > 0);
        assert_eq!(headers.actor, Some("test-actor".to_string()));
        assert!(
            headers
                .headers
                .iter()
                .any(|(k, _)| k == "x-nucleus-signature")
        );
        assert!(
            headers
                .headers
                .iter()
                .any(|(k, _)| k == "x-nucleus-timestamp")
        );
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

        let nonce = headers
            .headers
            .iter()
            .find(|(k, _)| k == "x-nucleus-nonce")
            .map(|(_, v)| v.as_str());
        // The signer always sends a nonce now; if it stopped, this would be
        // None and the round-trip below would still have to hold.
        assert!(nonce.is_some(), "sign_http_headers must emit a nonce");

        assert!(verify_signature(
            secret,
            headers.timestamp,
            Some("actor"),
            nonce,
            body,
            signature
        ));

        // The nonce is inside the signed bytes: verifying without it must fail,
        // which is what stops a nonce header from being stripped in transit.
        assert!(
            !verify_signature(
                secret,
                headers.timestamp,
                Some("actor"),
                None,
                body,
                signature
            ),
            "a stripped nonce must not verify"
        );
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

#[cfg(test)]
mod art12_binding_tests {
    use super::art12_signed_bytes;

    /// The whole point: the same body aimed at a different session must produce
    /// different signed bytes, or the signature does not bind the destination.
    #[test]
    fn the_destination_changes_the_signed_bytes() {
        let body = br#"{"event":"x"}"#;
        assert_ne!(
            art12_signed_bytes("session-a", body),
            art12_signed_bytes("session-b", body)
        );
    }

    /// Length-prefixing, demonstrated rather than asserted in a comment: without
    /// it, ("ab", "cd") and ("abc", "d") would frame identically.
    #[test]
    fn framing_is_unambiguous_across_the_boundary() {
        assert_ne!(
            art12_signed_bytes("ab", b"cd"),
            art12_signed_bytes("abc", b"d")
        );
    }

    /// Same inputs, same bytes — the signature has to be reproducible.
    #[test]
    fn framing_is_deterministic() {
        assert_eq!(
            art12_signed_bytes("s", b"body"),
            art12_signed_bytes("s", b"body")
        );
    }
}
