//! Client-side signing utilities for nucleus node/proxy APIs.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

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

fn build_message(timestamp: i64, actor: &str, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(body.len() + actor.len() + 32);
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
