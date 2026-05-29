//! `JwtKeyStore` — the OP's source of signing material.
//!
//! Closes `docs/local-issuer-prod-readiness-gap.md` GA-1 (no persistence),
//! GA-2 (KID not RFC 7638), GA-3 (no rotation), GA-13 (signing-key
//! accessor leak): the trait exposes a `sign(bytes)` method that signs
//! internally and **never returns the private key**, so callers
//! cannot accidentally leak it.
//!
//! # Trait shape
//!
//! Production callers depend on `Arc<dyn JwtKeyStore>` so the JWKS
//! endpoint (#35), discovery doc (#36), and token endpoint (#39) all
//! share one store. The trait is `Send + Sync` so an `Arc` clone is
//! the standard way to give each route a handle.
//!
//! # Rotation semantics
//!
//! - `rotate()` generates a fresh Ed25519 keypair, promotes it to
//!   active, and moves the old key into the verify-set with
//!   `not_after = now + grace_window`. The old `SigningKey` is
//!   dropped at the swap point; ed25519-dalek's `ZeroizeOnDrop`
//!   wipes it.
//! - `revoke(kid)` removes a verify-set entry immediately (no grace).
//!   Operators run this on suspected key compromise.
//! - `verify_key(kid)` returns a key from the verify-set if it is
//!   still within its grace window. Expired entries are pruned on
//!   every `rotate()`.
//!
//! See `crates/nucleus-oidc-provider/THREAT_MODEL.md` T01 (signing
//! key compromise), T13 (rotation gap) for the security context.

pub mod file;
pub mod memory;
pub mod rotator;

use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use file::FileKeyStore;
pub use memory::InMemoryKeyStore;
pub use rotator::KeyRotator;

/// Errors surfaced by any `JwtKeyStore` impl.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// The KID is not in the verify-set OR has aged out of the grace window.
    #[error("unknown or expired kid {0:?}")]
    UnknownKid(String),
    /// Internal lock poisoned. Treated as fatal — caller should fail the
    /// request and let the operator restart the service.
    #[error("key-store mutex poisoned")]
    Poisoned,
    /// Caller invoked `rotate()` / `revoke()` on a store that doesn't
    /// support them (e.g., a future static-bundle store for air-gapped
    /// verification-only deployments).
    #[error("key-store does not support rotation/revocation")]
    RotationUnsupported,
    /// Cannot revoke the active key directly. Operator must rotate
    /// first (which moves the old key to the verify-set with a fresh
    /// grace window) then revoke from there.
    #[error("cannot revoke the active key — rotate first")]
    CannotRevokeActive,
    /// Backend (filesystem, age decryption, etc.) failure.
    #[error("backend error: {0}")]
    Backend(String),
}

/// A verify-side key entry. Public material plus the validity window.
#[derive(Debug, Clone)]
pub struct VerifyKey {
    pub kid: String,
    pub verifying_key: VerifyingKey,
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

/// Result of a sign call. KID and ALG are returned alongside the raw
/// signature so the caller can populate the JWT header without
/// re-querying the store.
#[derive(Debug)]
pub struct SignedBytes {
    pub kid: String,
    /// Always `"EdDSA"` in v1. Pinned per `THREAT_MODEL.md` T04.
    pub alg: &'static str,
    pub signature: Vec<u8>,
}

/// Outcome of a successful `rotate()`. Useful for audit logs.
#[derive(Debug)]
pub struct RotateOutcome {
    pub new_kid: String,
    /// `None` only on the first activation of a freshly-created store.
    pub old_kid: Option<String>,
}

/// The OP's source of signing material.
///
/// `&self`-based — interior mutability via a `Mutex`. Implementors
/// MUST be `Send + Sync` so the store can be shared across the axum
/// router as `Arc<dyn JwtKeyStore>`.
pub trait JwtKeyStore: Send + Sync {
    /// Sign the given canonical bytes with the active key. Returns
    /// `(kid, alg, signature)`. The signing key is NEVER returned;
    /// callers must use this method rather than holding a key handle.
    fn sign(&self, bytes: &[u8]) -> Result<SignedBytes, KeyStoreError>;

    /// The KID of the currently-active signing key. Useful for log
    /// emission and JWT-header construction without a sign call.
    fn active_kid(&self) -> Result<String, KeyStoreError>;

    /// Resolve a verifying key by KID. Returns `UnknownKid` if the KID
    /// is unknown OR has aged out of the grace window.
    fn verify_key(&self, kid: &str) -> Result<Arc<VerifyKey>, KeyStoreError>;

    /// All currently-valid verify keys (active + grace-window entries).
    /// Used by the JWKS endpoint (#35) to render `/jwks.json`.
    fn all_verify_keys(&self) -> Result<Vec<Arc<VerifyKey>>, KeyStoreError>;

    /// Generate a fresh active key. Old active moves to the verify-set
    /// with `not_after = now + grace_window`. Implementations MAY persist.
    fn rotate(&self) -> Result<RotateOutcome, KeyStoreError>;

    /// Remove the given KID from the verify-set immediately. Returns
    /// `CannotRevokeActive` if the caller targets the active KID.
    /// Implementations MAY persist.
    fn revoke(&self, kid: &str) -> Result<(), KeyStoreError>;

    /// Sweep entries whose grace window has expired (`not_after <= now`).
    /// Returns the count of removed entries.
    ///
    /// **Note.** `verify_key()` and `all_verify_keys()` already filter
    /// by `not_after > now` at read time, so expired entries don't
    /// leak into responses regardless of sweep cadence. This method
    /// exists for memory hygiene under a `KeyRotator` background loop.
    fn sweep_expired(&self) -> Result<usize, KeyStoreError>;

    /// True if `rotate()` / `revoke()` change state. False for
    /// hypothetical read-only stores (none ship in v1).
    fn supports_rotation(&self) -> bool;
}

/// RFC 7638 JWK thumbprint of an Ed25519 public key, base64url-encoded
/// without padding.
///
/// The canonical JWK form for an OKP key per RFC 7638 §3.2 + RFC 8037 §2
/// includes exactly three required fields in lexicographic order with no
/// whitespace and no extra fields:
///
/// ```text
/// {"crv":"Ed25519","kty":"OKP","x":"<base64url(public_key_bytes)>"}
/// ```
///
/// SHA-256 of the UTF-8 byte representation, base64url-encoded without
/// padding, is the thumbprint and (per `THREAT_MODEL.md` T09) our KID.
pub fn rfc7638_kid(verifying_key: &VerifyingKey) -> String {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(verifying_key.as_bytes());
    // Canonical form: no whitespace, lexicographically-ordered fields.
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    let digest = Sha256::digest(canonical.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// Deterministic input → deterministic KID. Pins the wire format
    /// per RFC 7638; any drift in the canonical form changes the KID.
    #[test]
    fn rfc7638_kid_is_deterministic() {
        let sk = SigningKey::from_bytes(&[7; 32]);
        let vk = sk.verifying_key();
        let kid_a = rfc7638_kid(&vk);
        let kid_b = rfc7638_kid(&vk);
        assert_eq!(kid_a, kid_b);
        // Base64url-no-pad of SHA-256 is 43 chars.
        assert_eq!(kid_a.len(), 43);
        // No padding character.
        assert!(!kid_a.contains('='));
        // URL-safe alphabet only.
        assert!(kid_a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn rfc7638_kid_distinct_for_distinct_keys() {
        let kid_a = rfc7638_kid(&SigningKey::from_bytes(&[1; 32]).verifying_key());
        let kid_b = rfc7638_kid(&SigningKey::from_bytes(&[2; 32]).verifying_key());
        assert_ne!(kid_a, kid_b);
    }
}
