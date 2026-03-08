//! Approval types for approval-gated operations.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::error::{NucleusError, Result};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use sha2::Sha256;
use uuid::Uuid;

const DEFAULT_TOKEN_TTL_SECS: u64 = 300;

type HmacSha256 = Hmac<Sha256>;

/// A request for human approval for a specific operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    operation: String,
}

impl ApprovalRequest {
    /// Create a new approval request for the given operation string.
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
        }
    }

    /// Get the operation string for this request.
    pub fn operation(&self) -> &str {
        &self.operation
    }
}

/// A non-forgeable approval token scoped to a specific operation.
///
/// This token can only be constructed by this crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalToken {
    operation: String,
    nonce: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
    signature: String,
    _private: (),
}

impl ApprovalToken {
    pub(crate) fn new(operation: impl Into<String>) -> Self {
        Self::new_with_ttl(operation, Duration::from_secs(DEFAULT_TOKEN_TTL_SECS))
    }

    pub(crate) fn new_with_ttl(operation: impl Into<String>, ttl: Duration) -> Self {
        let operation = operation.into();
        let issued_at_unix = now_unix_secs();
        let expires_at_unix = issued_at_unix.saturating_add(ttl.as_secs());
        let nonce = Uuid::new_v4().to_string();
        let payload = signing_payload(&operation, &nonce, issued_at_unix, expires_at_unix);
        let signature = sign_payload(payload.as_bytes());
        Self {
            operation,
            nonce,
            issued_at_unix,
            expires_at_unix,
            signature,
            _private: (),
        }
    }

    /// Check whether this token matches the given operation.
    ///
    /// Tokens are single-use and time-limited:
    /// - Operation must match exactly
    /// - Token must be unexpired
    /// - Signature must validate
    /// - Nonce must not have been used before
    pub fn matches(&self, operation: &str) -> bool {
        if self.operation != operation {
            return false;
        }

        let now = now_unix_secs();
        if now >= self.expires_at_unix {
            return false;
        }

        let payload = signing_payload(
            &self.operation,
            &self.nonce,
            self.issued_at_unix,
            self.expires_at_unix,
        );
        let expected = sign_payload(payload.as_bytes());
        if expected != self.signature {
            return false;
        }

        consume_nonce_once(&self.nonce, self.expires_at_unix)
    }
}

/// Trait for approval providers.
pub trait Approver: Send + Sync {
    /// Approve or deny an operation and return a scoped token if approved.
    fn approve(&self, request: &ApprovalRequest) -> Result<ApprovalToken>;
}

/// Simple callback-based approver.
#[derive(Clone)]
pub struct CallbackApprover {
    callback: Arc<dyn Fn(&ApprovalRequest) -> bool + Send + Sync>,
}

impl CallbackApprover {
    /// Create a callback approver from a predicate.
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn(&ApprovalRequest) -> bool + Send + Sync + 'static,
    {
        Self {
            callback: Arc::new(callback),
        }
    }
}

impl Approver for CallbackApprover {
    fn approve(&self, request: &ApprovalRequest) -> Result<ApprovalToken> {
        if (self.callback)(request) {
            Ok(ApprovalToken::new(request.operation()))
        } else {
            Err(NucleusError::ApprovalRequired {
                operation: request.operation().to_string(),
            })
        }
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn signing_payload(
    operation: &str,
    nonce: &str,
    issued_at_unix: u64,
    expires_at_unix: u64,
) -> String {
    format!("{operation}|{nonce}|{issued_at_unix}|{expires_at_unix}")
}

fn signing_key() -> &'static [u8] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        key[..16].copy_from_slice(a.as_bytes());
        key[16..].copy_from_slice(b.as_bytes());
        key
    })
}

fn sign_payload(payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(signing_key()).expect("valid HMAC key");
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

fn nonce_cache() -> &'static Mutex<HashMap<String, u64>> {
    static CACHE: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn consume_nonce_once(nonce: &str, expires_at_unix: u64) -> bool {
    let now = now_unix_secs();
    let mut cache = nonce_cache().lock();

    // Opportunistically prune expired entries.
    cache.retain(|_, expiry| *expiry > now);

    if cache.contains_key(nonce) {
        return false;
    }

    cache.insert(nonce.to_string(), expires_at_unix);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_single_use() {
        let token = ApprovalToken::new("git push");
        assert!(token.matches("git push"));
        assert!(!token.matches("git push"));
    }

    #[test]
    fn token_rejects_wrong_operation() {
        let token = ApprovalToken::new("git push");
        assert!(!token.matches("git commit"));
        assert!(token.matches("git push"));
    }

    #[test]
    fn token_expires() {
        let token = ApprovalToken::new_with_ttl("git push", Duration::from_secs(0));
        assert!(!token.matches("git push"));
    }

    #[test]
    fn token_signature_prevents_tampering() {
        let mut token = ApprovalToken::new("git push");
        token.signature = "deadbeef".to_string();
        assert!(!token.matches("git push"));
    }
}
