use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const HEADER_TIMESTAMP: &str = "x-nucleus-timestamp";
const HEADER_SIGNATURE: &str = "x-nucleus-signature";
const HEADER_ACTOR: &str = "x-nucleus-actor";

#[derive(Clone, Debug)]
pub struct AuthConfig {
    secret: Arc<Vec<u8>>,
    max_skew: Duration,
}

impl AuthConfig {
    pub fn new(secret: impl AsRef<[u8]>, max_skew: Duration) -> Self {
        Self {
            secret: Arc::new(secret.as_ref().to_vec()),
            max_skew,
        }
    }

    pub fn max_skew(&self) -> Duration {
        self.max_skew
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AuthContext {
    pub actor: Option<String>,
    pub timestamp: i64,
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

    let timestamp = parse_timestamp(ts)?;
    ensure_skew(timestamp, auth.max_skew())?;

    let mut message = Vec::with_capacity(ts.len() + actor_value.len() + 2 + body.len());
    message.extend_from_slice(ts.as_bytes());
    message.push(b'.');
    message.extend_from_slice(actor_value.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);

    verify_signature(auth.secret(), &message, sig)?;

    Ok(AuthContext { actor, timestamp })
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

pub fn sign_message(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}
