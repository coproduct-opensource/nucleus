//! Ed25519 signing primitive for the verifier service.
//!
//! Used to sign Signed Tree Heads (`UnsignedTreeHead` →
//! `SignedTreeHead`) and to publish the corresponding verifying key
//! as a JWKS at `/.well-known/jwks.json`. The signer's `kid` is an
//! RFC 7638-style short thumbprint, matching the convention used
//! throughout nucleus.
//!
//! Why not reuse `nucleus_lineage::LocalIssuer`?
//! That type is gated behind the `dev` feature because it's a
//! testing helper — it generates ephemeral keys, doesn't persist them,
//! and ships behind a test-only `EdgeSigner` impl. The verifier
//! service ships a production signing key (env-injected at deploy
//! time on Fly.io), so the primitives belong here.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use sha2::{Digest, Sha256};

/// Canonical domain separator for STH signing. Bumping this string
/// invalidates every signature ever issued — only do it on a
/// breaking wire-format change AND publish the new value in the
/// service description endpoint.
pub const STH_DOMAIN_SEPARATOR: &[u8] = b"nucleus-verifier-sth/v1\n";

/// Ed25519 signing context for the verifier service.
pub struct VerifierSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    /// Short, URL-safe, base64url-encoded thumbprint suitable for
    /// JWS `kid` (12 bytes ≈ 16 chars).
    kid: String,
}

impl fmt::Debug for VerifierSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never leak the secret bytes via Debug. Print kid + pubkey.
        f.debug_struct("VerifierSigner")
            .field("kid", &self.kid)
            .field(
                "verifying_key_b64url",
                &B64URL.encode(self.verifying_key.to_bytes()),
            )
            .finish()
    }
}

impl VerifierSigner {
    /// Generate a fresh ephemeral signer. Cycles on every restart
    /// — use [`Self::from_secret_hex`] in production so the kid
    /// (and therefore the trust anchor) is stable across deploys.
    pub fn random() -> Self {
        // Sample 32 raw bytes from the OS CSPRNG and feed
        // `SigningKey::from_bytes` — equivalent to `generate` but avoids the
        // cross-version `CryptoRng`/`rand_core` trait-identity mismatch that
        // breaks `SigningKey::generate(&mut rng)` when multiple rand_core
        // majors coexist in the workspace.
        //
        // rand 0.10 renamed the low-level `RngCore` trait to `Rng` (and the
        // old high-level `Rng` ext-trait to `RngExt`); `fill_bytes` travels
        // with the renamed trait. `rand::rng()` is the 0.9+ accessor for the
        // thread-local CSPRNG (formerly `thread_rng()`).
        use rand::Rng;
        let mut bytes = [0u8; SECRET_KEY_LENGTH];
        rand::rng().fill_bytes(&mut bytes);
        Self::from_signing_key(SigningKey::from_bytes(&bytes))
    }

    /// Construct from a 64-char hex secret key. Returns `None` on
    /// invalid hex or wrong length.
    pub fn from_secret_hex(hex_str: &str) -> Option<Self> {
        let bytes = hex::decode(hex_str.trim()).ok()?;
        if bytes.len() != SECRET_KEY_LENGTH {
            return None;
        }
        let mut sk = [0u8; SECRET_KEY_LENGTH];
        sk.copy_from_slice(&bytes);
        Some(Self::from_signing_key(SigningKey::from_bytes(&sk)))
    }

    fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        let kid = compute_kid(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            kid,
        }
    }

    /// JWS-style key id.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// 32-byte Ed25519 public key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Sign arbitrary bytes. The caller is responsible for canonical
    /// encoding — use [`canonical_sth_bytes`] for STHs.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing_key.sign(msg).to_bytes()
    }

    /// Publish the verifying key as a JWKS (RFC 7517 + RFC 8037
    /// for OKP/Ed25519). Lands at `/.well-known/jwks.json`.
    pub fn jwks(&self) -> serde_json::Value {
        let x = B64URL.encode(self.verifying_key.to_bytes());
        serde_json::json!({
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "alg": "EdDSA",
                    "use": "sig",
                    "kid": self.kid,
                    "x": x,
                }
            ]
        })
    }
}

/// Canonical byte encoding of a STH for signing.
///
/// Layout:
/// ```text
/// STH_DOMAIN_SEPARATOR
/// || tree_size      (8 bytes, big-endian i64)
/// || timestamp_ms   (8 bytes, big-endian i64)
/// || root_hash      (32 bytes, raw SHA-256)
/// ```
///
/// Total: 24 + 8 + 8 + 32 = 72 bytes. Stable across releases as
/// long as `STH_DOMAIN_SEPARATOR` is unchanged.
pub fn canonical_sth_bytes(tree_size: i64, timestamp_ms: i64, root_hash: &[u8; 32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(STH_DOMAIN_SEPARATOR.len() + 8 + 8 + 32);
    buf.extend_from_slice(STH_DOMAIN_SEPARATOR);
    buf.extend_from_slice(&tree_size.to_be_bytes());
    buf.extend_from_slice(&timestamp_ms.to_be_bytes());
    buf.extend_from_slice(root_hash);
    buf
}

/// RFC 7638-ish thumbprint short form: first 12 bytes of
/// SHA-256(canonical JWK), base64url-encoded.
fn compute_kid(vk: &VerifyingKey) -> String {
    // Canonical JWK form per RFC 7638: only the required members,
    // alphabetical key order.
    let x = B64URL.encode(vk.to_bytes());
    let canonical = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    let mut h = Sha256::new();
    h.update(canonical.as_bytes());
    let full = h.finalize();
    B64URL.encode(&full[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_random_signer() {
        let signer = VerifierSigner::random();
        let msg = b"hello world";
        let sig = signer.sign(msg);

        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        ed25519_dalek::Verifier::verify(signer.verifying_key(), msg, &signature)
            .expect("self-issued signature must verify");
    }

    #[test]
    fn from_secret_hex_is_deterministic() {
        let hex_key = hex::encode([42u8; SECRET_KEY_LENGTH]);
        let a = VerifierSigner::from_secret_hex(&hex_key).unwrap();
        let b = VerifierSigner::from_secret_hex(&hex_key).unwrap();
        assert_eq!(a.kid(), b.kid());
        assert_eq!(a.verifying_key().to_bytes(), b.verifying_key().to_bytes());
    }

    #[test]
    fn from_secret_hex_rejects_short_input() {
        assert!(VerifierSigner::from_secret_hex("deadbeef").is_none());
    }

    #[test]
    fn from_secret_hex_rejects_non_hex() {
        assert!(VerifierSigner::from_secret_hex(&"z".repeat(64)).is_none());
    }

    #[test]
    fn kid_is_url_safe_base64() {
        let signer = VerifierSigner::random();
        let kid = signer.kid();
        assert!(!kid.is_empty());
        // URL-safe base64 alphabet: A-Z, a-z, 0-9, -, _; no padding.
        for c in kid.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "kid must be URL-safe base64; got {c:?}"
            );
        }
    }

    #[test]
    fn canonical_sth_bytes_layout_is_stable() {
        let root = [7u8; 32];
        let buf = canonical_sth_bytes(5, 1_700_000_000, &root);
        assert_eq!(buf.len(), STH_DOMAIN_SEPARATOR.len() + 8 + 8 + 32);
        assert!(buf.starts_with(STH_DOMAIN_SEPARATOR));
        // tree_size bytes immediately after the separator:
        let ts_offset = STH_DOMAIN_SEPARATOR.len();
        assert_eq!(&buf[ts_offset..ts_offset + 8], &5i64.to_be_bytes());
    }

    #[test]
    fn distinct_tree_sizes_yield_distinct_signed_bytes() {
        let root = [0u8; 32];
        let b1 = canonical_sth_bytes(1, 100, &root);
        let b2 = canonical_sth_bytes(2, 100, &root);
        assert_ne!(b1, b2);
    }

    #[test]
    fn jwks_has_expected_shape() {
        let signer = VerifierSigner::random();
        let jwks = signer.jwks();
        let keys = jwks["keys"].as_array().expect("keys must be array");
        assert_eq!(keys.len(), 1);
        let k = &keys[0];
        assert_eq!(k["kty"], "OKP");
        assert_eq!(k["crv"], "Ed25519");
        assert_eq!(k["alg"], "EdDSA");
        assert_eq!(k["use"], "sig");
        assert_eq!(k["kid"], signer.kid());
        // x must decode to 32 raw bytes (the Ed25519 public key).
        let x = k["x"].as_str().unwrap();
        let decoded = B64URL.decode(x).unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded.as_slice(), signer.verifying_key().to_bytes());
    }

    #[test]
    fn jwks_kid_matches_thumbprint() {
        let signer = VerifierSigner::random();
        let jwks = signer.jwks();
        assert_eq!(jwks["keys"][0]["kid"], signer.kid());
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let signer = VerifierSigner::random();
        let s = format!("{signer:?}");
        // Verifying key is fine to print. The secret must not appear.
        let secret_hex = hex::encode(signer.signing_key.to_bytes());
        assert!(
            !s.contains(&secret_hex),
            "Debug must not leak the secret key bytes"
        );
    }

    #[test]
    fn sth_signature_verifies_end_to_end() {
        let signer = VerifierSigner::random();
        let root = [99u8; 32];
        let bytes = canonical_sth_bytes(42, 1_700_000_000_000, &root);
        let sig = signer.sign(&bytes);
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        ed25519_dalek::Verifier::verify(signer.verifying_key(), &bytes, &signature)
            .expect("STH signature must verify against verifying key");
    }
}
