// SPDX-License-Identifier: MIT
//
//! JWKS document + verifying-key resolution.
//!
//! Supports both RSA (RFC 7517 §6.3.1) and Ed25519 / OKP (RFC 8037 §2)
//! key entries. The crate returns a neutral [`JwkPublicKey`] enum
//! rather than a jsonwebtoken `DecodingKey` so consumers can use their
//! preferred crypto crate — and so the public crate stays free of the
//! algorithm-confusion CVE class that affects general-purpose JWT
//! libraries.
//!
//! See `crates/nucleus-oidc-provider/THREAT_MODEL.md` T04 (algorithm
//! downgrade) for the rationale.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

use crate::error::OidcError;

/// One key entry from a JWKS document (RFC 7517 §4).
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type — `"RSA"` or `"OKP"`. Other types (`"EC"`, `"oct"`)
    /// are rejected with [`OidcError::InvalidJwks`] in v1.
    pub kty: String,
    /// Key id used to select among multiple keys in the set.
    pub kid: String,
    /// Algorithm, if the issuer pins one. Informational; consumers
    /// MUST enforce their own alg allowlist per RFC 8725 §3.1.
    #[serde(default)]
    pub alg: Option<String>,
    /// `use` claim — `"sig"` for signature verification.
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    /// Curve identifier. For OKP this is `"Ed25519"`; for EC keys
    /// (`kty == "EC"`, used by SPIFFE JWT-SVID) this is `"P-256"`,
    /// `"P-384"`, or `"P-521"`. EC keys are consumed by
    /// [`crate::spiffe_federation`], not by [`Jwk::public_key`].
    #[serde(default)]
    pub crv: Option<String>,
    /// Public key x-coordinate. For OKP this is the 32-byte Ed25519
    /// public key (base64url); for EC this is the affine x-coordinate
    /// (base64url), paired with [`Jwk::y`].
    #[serde(default)]
    pub x: Option<String>,
    /// EC public key affine y-coordinate (base64url). Present only for
    /// `kty == "EC"`. Unused by [`Jwk::public_key`] (which rejects EC);
    /// consumed by [`crate::spiffe_federation`] for JWT-SVID verify.
    #[serde(default)]
    pub y: Option<String>,
    /// RSA modulus (base64url), present for `kty == "RSA"`.
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent (base64url), present for `kty == "RSA"`.
    #[serde(default)]
    pub e: Option<String>,
}

/// A JWKS document (RFC 7517 §5).
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// Neutral verifying-key form, agnostic to any JWT-library type.
///
/// Consumers pattern-match on the variant and convert to their
/// preferred crypto crate (`ed25519-dalek::VerifyingKey` for Ed25519,
/// `jsonwebtoken::DecodingKey::from_rsa_components` for RSA).
#[derive(Debug, Clone)]
pub enum JwkPublicKey {
    /// RSA public key components (modulus + exponent), both
    /// base64url-encoded.
    Rsa { n: String, e: String },
    /// Raw 32-byte Ed25519 public key.
    Ed25519([u8; 32]),
}

impl Jwk {
    /// Extract the verifying key in neutral form. Errors for
    /// unsupported `kty` values OR a malformed `x` / RSA component.
    pub fn public_key(&self) -> Result<JwkPublicKey, OidcError> {
        match self.kty.as_str() {
            "RSA" => {
                let n = self
                    .n
                    .as_deref()
                    .ok_or_else(|| OidcError::InvalidJwks("RSA jwk missing `n`".to_string()))?;
                let e = self
                    .e
                    .as_deref()
                    .ok_or_else(|| OidcError::InvalidJwks("RSA jwk missing `e`".to_string()))?;
                Ok(JwkPublicKey::Rsa {
                    n: n.to_string(),
                    e: e.to_string(),
                })
            }
            "OKP" => {
                let crv = self
                    .crv
                    .as_deref()
                    .ok_or_else(|| OidcError::InvalidJwks("OKP jwk missing `crv`".to_string()))?;
                if crv != "Ed25519" {
                    return Err(OidcError::InvalidJwks(format!(
                        "unsupported OKP curve {crv:?}"
                    )));
                }
                let x = self
                    .x
                    .as_deref()
                    .ok_or_else(|| OidcError::InvalidJwks("OKP jwk missing `x`".to_string()))?;
                let x_bytes = URL_SAFE_NO_PAD
                    .decode(x)
                    .map_err(|e| OidcError::InvalidJwks(format!("base64url decode x: {e}")))?;
                let arr: [u8; 32] = x_bytes.try_into().map_err(|v: Vec<u8>| {
                    OidcError::InvalidJwks(format!(
                        "Ed25519 x must decode to 32 bytes, got {}",
                        v.len()
                    ))
                })?;
                Ok(JwkPublicKey::Ed25519(arr))
            }
            other => Err(OidcError::InvalidJwks(format!(
                "unsupported key type {other:?}"
            ))),
        }
    }
}

/// Resolves a verifying key for a given `kid`.
#[async_trait]
pub trait KeyResolver: Send + Sync {
    /// Resolve the verifying key for `kid`. `issuer` tells a discovery-
    /// based resolver where to look; fixed resolvers ignore it.
    async fn resolve(&self, issuer: &str, kid: &str) -> Result<Arc<JwkPublicKey>, OidcError>;
}

/// A fixed set of verifying keys — for tests and air-gapped deployments.
#[derive(Default)]
pub struct StaticKeyResolver {
    keys: HashMap<String, Arc<JwkPublicKey>>,
}

impl StaticKeyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_key(mut self, kid: impl Into<String>, key: JwkPublicKey) -> Self {
        self.keys.insert(kid.into(), Arc::new(key));
        self
    }
}

#[async_trait]
impl KeyResolver for StaticKeyResolver {
    async fn resolve(&self, _issuer: &str, kid: &str) -> Result<Arc<JwkPublicKey>, OidcError> {
        self.keys
            .get(kid)
            .cloned()
            .ok_or_else(|| OidcError::KeyNotFound(kid.to_string()))
    }
}

/// Minimal slice of an OIDC discovery document.
#[derive(Debug, Deserialize)]
struct OpenIdConfig {
    jwks_uri: String,
}

/// Production resolver: discovers the issuer's JWKS and caches it.
///
/// On a cache miss, fetches `{issuer}/.well-known/openid-configuration`,
/// then `jwks_uri`, parses the JWKS, and caches the resulting
/// `kid → JwkPublicKey` map until the configured TTL expires.
pub struct DiscoveryKeyResolver {
    http: reqwest::Client,
    ttl: Duration,
    cache: Mutex<KeyCache>,
}

struct KeyCache {
    keys: HashMap<String, Arc<JwkPublicKey>>,
    fetched_at: Option<Instant>,
}

impl DiscoveryKeyResolver {
    /// A resolver with a 1-hour JWKS cache TTL.
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("reqwest client builds with default config"),
            ttl: Duration::from_secs(3600),
            cache: Mutex::new(KeyCache {
                keys: HashMap::new(),
                fetched_at: None,
            }),
        }
    }

    /// Override the JWKS cache TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    fn cached(&self, kid: &str) -> Option<Arc<JwkPublicKey>> {
        let cache = self.cache.lock().ok()?;
        match cache.fetched_at {
            Some(t) if t.elapsed() < self.ttl => cache.keys.get(kid).cloned(),
            _ => None,
        }
    }

    async fn refresh(&self, issuer: &str) -> Result<(), OidcError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let config: OpenIdConfig = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| OidcError::Discovery(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcError::Discovery(e.to_string()))?;

        let jwks: Jwks = self
            .http
            .get(&config.jwks_uri)
            .send()
            .await
            .map_err(|e| OidcError::Network(e.to_string()))?
            .error_for_status()
            .map_err(|e| OidcError::InvalidJwks(e.to_string()))?
            .json()
            .await
            .map_err(|e| OidcError::InvalidJwks(e.to_string()))?;

        let mut keys = HashMap::new();
        for jwk in &jwks.keys {
            // Skip individual keys we can't model rather than failing
            // the whole refresh — a JWKS may carry key types we don't use.
            if let Ok(key) = jwk.public_key() {
                keys.insert(jwk.kid.clone(), Arc::new(key));
            }
        }
        if keys.is_empty() {
            return Err(OidcError::InvalidJwks(
                "JWKS contained no usable keys".to_string(),
            ));
        }

        let mut cache = self
            .cache
            .lock()
            .map_err(|_| OidcError::Discovery("key cache lock poisoned".into()))?;
        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }
}

impl Default for DiscoveryKeyResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyResolver for DiscoveryKeyResolver {
    async fn resolve(&self, issuer: &str, kid: &str) -> Result<Arc<JwkPublicKey>, OidcError> {
        if let Some(key) = self.cached(kid) {
            return Ok(key);
        }
        self.refresh(issuer).await?;
        self.cache
            .lock()
            .map_err(|_| OidcError::KeyNotFound(kid.to_string()))?
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| OidcError::KeyNotFound(kid.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rsa_jwk() -> Jwk {
        Jwk {
            kty: "RSA".to_string(),
            kid: "rsa-1".to_string(),
            alg: Some("RS256".to_string()),
            use_: Some("sig".to_string()),
            crv: None,
            x: None,
            y: None,
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx".to_string()),
            e: Some("AQAB".to_string()),
        }
    }

    fn okp_jwk_ed25519() -> Jwk {
        Jwk {
            kty: "OKP".to_string(),
            kid: "ed-1".to_string(),
            alg: Some("EdDSA".to_string()),
            use_: Some("sig".to_string()),
            crv: Some("Ed25519".to_string()),
            // 32 bytes encoded — RFC 8037 example.
            x: Some("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo".to_string()),
            y: None,
            n: None,
            e: None,
        }
    }

    #[test]
    fn rsa_jwk_extracts_to_rsa_variant() {
        let jwk = rsa_jwk();
        let pk = jwk.public_key().unwrap();
        assert!(matches!(pk, JwkPublicKey::Rsa { .. }));
    }

    #[test]
    fn okp_ed25519_jwk_extracts_to_ed25519_variant() {
        let jwk = okp_jwk_ed25519();
        let pk = jwk.public_key().unwrap();
        match pk {
            JwkPublicKey::Ed25519(bytes) => assert_eq!(bytes.len(), 32),
            _ => panic!("expected Ed25519 variant"),
        }
    }

    #[test]
    fn unsupported_kty_rejected() {
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: "k1".to_string(),
            alg: None,
            use_: None,
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
        };
        assert!(matches!(jwk.public_key(), Err(OidcError::InvalidJwks(_))));
    }

    #[test]
    fn okp_with_non_ed25519_curve_rejected() {
        let mut jwk = okp_jwk_ed25519();
        jwk.crv = Some("X25519".to_string());
        let err = jwk.public_key().unwrap_err();
        assert!(matches!(err, OidcError::InvalidJwks(_)));
        assert!(err.to_string().contains("X25519"));
    }

    #[test]
    fn okp_with_wrong_length_x_rejected() {
        let mut jwk = okp_jwk_ed25519();
        // 31 bytes worth of base64url.
        jwk.x = Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
        let err = jwk.public_key().unwrap_err();
        assert!(matches!(err, OidcError::InvalidJwks(_)));
    }

    #[test]
    fn rsa_missing_n_rejected() {
        let mut jwk = rsa_jwk();
        jwk.n = None;
        let err = jwk.public_key().unwrap_err();
        assert!(matches!(err, OidcError::InvalidJwks(_)));
        assert!(err.to_string().contains("`n`"));
    }

    #[tokio::test]
    async fn static_resolver_returns_registered_key() {
        let pk = JwkPublicKey::Ed25519([42; 32]);
        let resolver = StaticKeyResolver::new().with_key("k1", pk);
        let key = resolver.resolve("iss", "k1").await.unwrap();
        assert!(matches!(*key, JwkPublicKey::Ed25519(_)));
    }

    #[tokio::test]
    async fn static_resolver_errors_on_missing() {
        let resolver = StaticKeyResolver::new();
        let err = resolver.resolve("iss", "missing").await.unwrap_err();
        assert_eq!(err, OidcError::KeyNotFound("missing".to_string()));
    }
}
