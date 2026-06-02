//! Verifying-key resolution and replay protection.
//!
//! [`KeyResolver`] abstracts "given a `kid`, hand me a verifying key". The
//! production [`DiscoveryKeyResolver`] performs OIDC discovery against the
//! issuer and caches the JWKS; [`StaticKeyResolver`] holds a fixed key set
//! for tests and air-gapped deployments.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;

use crate::error::OidcError;

/// Resolves a JWT verifying key for a given `kid`.
#[async_trait]
pub trait KeyResolver: Send + Sync {
    /// Resolve the verifying key for `kid`. `issuer` tells a discovery-based
    /// resolver where to look; fixed resolvers ignore it.
    async fn resolve(&self, issuer: &str, kid: &str) -> Result<Arc<DecodingKey>, OidcError>;
}

/// A fixed set of verifying keys — for tests and air-gapped deployments.
#[derive(Default)]
pub struct StaticKeyResolver {
    keys: HashMap<String, Arc<DecodingKey>>,
}

impl StaticKeyResolver {
    /// An empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a verifying key under `kid`.
    pub fn with_key(mut self, kid: impl Into<String>, key: DecodingKey) -> Self {
        self.keys.insert(kid.into(), Arc::new(key));
        self
    }
}

#[async_trait]
impl KeyResolver for StaticKeyResolver {
    async fn resolve(&self, _issuer: &str, kid: &str) -> Result<Arc<DecodingKey>, OidcError> {
        self.keys
            .get(kid)
            .cloned()
            .ok_or_else(|| OidcError::KeyNotFound(kid.to_string()))
    }
}

/// One key from a JWKS document.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// Key type (`RSA`, `EC`, `OKP`, ...).
    pub kty: String,
    /// Key id.
    pub kid: String,
    /// Algorithm, if the issuer pins one.
    #[serde(default)]
    pub alg: Option<String>,
    /// RSA modulus (base64url), present for `kty == "RSA"`.
    #[serde(default)]
    pub n: Option<String>,
    /// RSA exponent (base64url), present for `kty == "RSA"`.
    #[serde(default)]
    pub e: Option<String>,
}

/// A JWKS document.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    /// The keys in the set.
    pub keys: Vec<Jwk>,
}

impl Jwk {
    /// Build a [`DecodingKey`] from this JWK. Only RSA is supported today;
    /// Fly OIDC tokens are RS256.
    pub fn to_decoding_key(&self) -> Result<DecodingKey, OidcError> {
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
                DecodingKey::from_rsa_components(n, e)
                    .map_err(|err| OidcError::InvalidJwks(err.to_string()))
            }
            other => Err(OidcError::InvalidJwks(format!(
                "unsupported key type {other:?}"
            ))),
        }
    }
}

/// Minimal slice of an OIDC discovery document.
#[derive(Debug, Deserialize)]
struct OpenIdConfig {
    jwks_uri: String,
}

/// Production resolver: discovers the issuer's JWKS and caches it with a TTL.
pub struct DiscoveryKeyResolver {
    http: reqwest::Client,
    ttl: Duration,
    cache: Mutex<KeyCache>,
}

struct KeyCache {
    keys: HashMap<String, Arc<DecodingKey>>,
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

    /// Return a cached key if the cache is still fresh.
    fn cached(&self, kid: &str) -> Option<Arc<DecodingKey>> {
        let cache = self.cache.lock().expect("key cache mutex not poisoned");
        match cache.fetched_at {
            Some(t) if t.elapsed() < self.ttl => cache.keys.get(kid).cloned(),
            _ => None,
        }
    }

    /// Fetch the issuer's discovery document + JWKS and replace the cache.
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
            // Skip individual keys we can't model rather than failing the
            // whole refresh — a JWKS may carry key types we don't use.
            if let Ok(key) = jwk.to_decoding_key() {
                keys.insert(jwk.kid.clone(), Arc::new(key));
            }
        }
        if keys.is_empty() {
            return Err(OidcError::InvalidJwks(
                "JWKS contained no usable keys".to_string(),
            ));
        }

        let mut cache = self.cache.lock().expect("key cache mutex not poisoned");
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
    async fn resolve(&self, issuer: &str, kid: &str) -> Result<Arc<DecodingKey>, OidcError> {
        if let Some(key) = self.cached(kid) {
            return Ok(key);
        }
        self.refresh(issuer).await?;
        self.cache
            .lock()
            .expect("key cache mutex not poisoned")
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| OidcError::KeyNotFound(kid.to_string()))
    }
}

/// Tracks seen `jti` values to reject replayed tokens.
///
/// Entries are dropped once expired; the live set only ever holds the
/// unexpired tokens of the issuer's short (15-minute) validity window.
pub struct JtiCache {
    used: Mutex<HashMap<String, u64>>,
}

impl JtiCache {
    /// An empty replay cache.
    pub fn new() -> Self {
        Self {
            used: Mutex::new(HashMap::new()),
        }
    }

    /// Record `jti` as seen. Returns [`OidcError::TokenReplay`] if it was
    /// already present and not yet expired.
    pub fn check_and_mark(&self, jti: &str, exp: u64) -> Result<(), OidcError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut used = self.used.lock().expect("jti cache mutex not poisoned");
        used.retain(|_, expiry| *expiry > now);
        if used.contains_key(jti) {
            return Err(OidcError::TokenReplay(jti.to_string()));
        }
        used.insert(jti.to_string(), exp);
        Ok(())
    }
}

impl Default for JtiCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jti_cache_accepts_first_use_rejects_replay() {
        let cache = JtiCache::new();
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        cache.check_and_mark("jti-1", future).unwrap();
        let err = cache
            .check_and_mark("jti-1", future)
            .expect_err("replay must be rejected");
        assert_eq!(err, OidcError::TokenReplay("jti-1".to_string()));
    }

    #[test]
    fn jti_cache_distinct_ids_both_accepted() {
        let cache = JtiCache::new();
        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;
        cache.check_and_mark("jti-a", future).unwrap();
        cache.check_and_mark("jti-b", future).unwrap();
    }

    #[test]
    fn jwk_rejects_non_rsa_key_type() {
        let jwk = Jwk {
            kty: "oct".to_string(),
            kid: "k1".to_string(),
            alg: None,
            n: None,
            e: None,
        };
        assert!(matches!(
            jwk.to_decoding_key(),
            Err(OidcError::InvalidJwks(_))
        ));
    }

    #[tokio::test]
    async fn static_resolver_returns_registered_key_and_errors_on_missing() {
        // A dummy RSA component pair — only the lookup path is exercised.
        let key = DecodingKey::from_secret(b"unused");
        let resolver = StaticKeyResolver::new().with_key("k1", key);
        assert!(resolver.resolve("iss", "k1").await.is_ok());
        let err = resolver.resolve("iss", "missing").await.unwrap_err();
        assert_eq!(err, OidcError::KeyNotFound("missing".to_string()));
    }
}
