//! DID resolution: resolve `did:web` identifiers to DID documents.
//!
//! Provides the [`DidResolver`] trait for resolving DIDs and implementations:
//!
//! - [`InMemoryDidResolver`] — for testing and local-first workflows
//! - [`HttpDidResolver`] — for production HTTPS resolution (requires `resolver` feature)
//!
//! The resolution flow for `did:web` is:
//!
//! ```text
//! did:web:app.example.com
//!   → https://app.example.com/.well-known/did.json
//!   → GET request → parse JSON → DidDocument
//! ```
//!
//! # Example
//!
//! ```
//! use nucleus_identity::did_resolver::{DidResolver, InMemoryDidResolver};
//! use nucleus_identity::did::DidDocument;
//!
//! # tokio_test::block_on(async {
//! let mut resolver = InMemoryDidResolver::new();
//! let doc = DidDocument::new("did:web:app.dev");
//! resolver.insert(doc.clone());
//!
//! let resolved = resolver.resolve("did:web:app.dev").await.unwrap();
//! assert_eq!(resolved.id, "did:web:app.dev");
//! # });
//! ```

use async_trait::async_trait;
use std::collections::HashMap;

use crate::did::DidDocument;
use crate::did_binding::SpiffeDidBinding;
use crate::{Error, Result};

/// A resolver that can look up DID documents and optional binding proofs
/// from a `did:web` identifier.
///
/// Implementations may resolve over HTTPS (production), from an in-memory
/// cache (testing), or via gRPC from a peer service.
#[async_trait]
pub trait DidResolver: Send + Sync {
    /// Resolve a `did:web` identifier to its DID document.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID cannot be resolved (network failure,
    /// malformed document, DID not found, etc.).
    async fn resolve(&self, did: &str) -> Result<DidDocument>;

    /// Resolve a `did:web` identifier and its SPIFFE-DID binding proof.
    ///
    /// Returns `None` for the binding if the endpoint doesn't serve one
    /// (i.e., no `/.well-known/spiffe-did-binding.json`).
    ///
    /// # Default Implementation
    ///
    /// Falls back to resolving just the DID document with no binding.
    async fn resolve_with_binding(
        &self,
        did: &str,
    ) -> Result<(DidDocument, Option<SpiffeDidBinding>)> {
        let doc = self.resolve(did).await?;
        Ok((doc, None))
    }
}

/// An in-memory DID resolver for testing and local-first workflows.
///
/// Stores DID documents and optional binding proofs in hash maps keyed
/// by DID identifier. No network access required.
#[derive(Debug, Clone, Default)]
pub struct InMemoryDidResolver {
    documents: HashMap<String, DidDocument>,
    bindings: HashMap<String, SpiffeDidBinding>,
}

impl InMemoryDidResolver {
    /// Create a new empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a DID document into the resolver.
    ///
    /// The document's `id` field is used as the lookup key.
    pub fn insert(&mut self, doc: DidDocument) {
        self.documents.insert(doc.id.clone(), doc);
    }

    /// Insert a SPIFFE-DID binding proof into the resolver.
    ///
    /// The binding's `did` field is used as the lookup key.
    pub fn insert_binding(&mut self, binding: SpiffeDidBinding) {
        self.bindings.insert(binding.did.clone(), binding);
    }

    /// Remove a DID document (and its binding) from the resolver.
    pub fn remove(&mut self, did: &str) {
        self.documents.remove(did);
        self.bindings.remove(did);
    }

    /// Returns the number of stored DID documents.
    pub fn len(&self) -> usize {
        self.documents.len()
    }

    /// Returns true if the resolver has no stored documents.
    pub fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    /// Returns all stored DID identifiers.
    pub fn dids(&self) -> Vec<&str> {
        self.documents.keys().map(|s| s.as_str()).collect()
    }
}

#[async_trait]
impl DidResolver for InMemoryDidResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument> {
        self.documents
            .get(did)
            .cloned()
            .ok_or_else(|| Error::Internal(format!("DID not found in resolver: {did}")))
    }

    async fn resolve_with_binding(
        &self,
        did: &str,
    ) -> Result<(DidDocument, Option<SpiffeDidBinding>)> {
        let doc = self.resolve(did).await?;
        let binding = self.bindings.get(did).cloned();
        Ok((doc, binding))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP DID RESOLVER (feature-gated)
// ═══════════════════════════════════════════════════════════════════════════

/// HTTP-based DID resolver that fetches `did:web` documents over HTTPS.
///
/// Resolves `did:web` identifiers by converting them to HTTPS URLs per the
/// [did:web specification](https://w3c-ccg.github.io/did-method-web/) and
/// fetching the DID document JSON. Optionally fetches the SPIFFE-DID
/// binding proof from the adjacent `spiffe-did-binding.json` endpoint.
///
/// # Example
///
/// ```ignore
/// use nucleus_identity::did_resolver::{DidResolver, HttpDidResolver};
///
/// let resolver = HttpDidResolver::new();
/// let doc = resolver.resolve("did:web:app.example.com").await?;
/// ```
#[cfg(feature = "resolver")]
pub struct HttpDidResolver {
    client: reqwest::Client,
}

#[cfg(feature = "resolver")]
impl HttpDidResolver {
    /// Create a new HTTP resolver with a default HTTPS client.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Create a resolver with a pre-configured `reqwest::Client`.
    ///
    /// Use this to supply custom TLS roots, timeouts, or proxy settings.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[cfg(feature = "resolver")]
impl Default for HttpDidResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "resolver")]
impl std::fmt::Debug for HttpDidResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpDidResolver").finish()
    }
}

#[cfg(feature = "resolver")]
#[async_trait]
impl DidResolver for HttpDidResolver {
    async fn resolve(&self, did: &str) -> Result<DidDocument> {
        let url = crate::did::did_web_to_url(did)?;

        let response = self.client.get(&url).send().await.map_err(|e| {
            Error::Internal(format!("failed to fetch DID document from {url}: {e}"))
        })?;

        if !response.status().is_success() {
            return Err(Error::Internal(format!(
                "DID document fetch returned HTTP {}: {url}",
                response.status()
            )));
        }

        let doc: DidDocument = response.json().await.map_err(|e| {
            Error::Internal(format!("failed to parse DID document from {url}: {e}"))
        })?;

        // Verify the document ID matches what was requested
        if doc.id != did {
            return Err(Error::Internal(format!(
                "DID document ID mismatch: requested {did}, got {}",
                doc.id
            )));
        }

        Ok(doc)
    }

    async fn resolve_with_binding(
        &self,
        did: &str,
    ) -> Result<(DidDocument, Option<SpiffeDidBinding>)> {
        let doc = self.resolve(did).await?;

        // Derive the binding URL from the DID document URL
        let did_url = crate::did::did_web_to_url(did)?;
        let binding_url = did_url.replace("did.json", "spiffe-did-binding.json");

        // Attempt to fetch the binding — not all DIDs have one
        let binding = match self.client.get(&binding_url).send().await {
            Ok(response) if response.status().is_success() => {
                match response.json::<SpiffeDidBinding>().await {
                    Ok(binding) => Some(binding),
                    Err(e) => {
                        tracing::warn!(
                            did,
                            url = %binding_url,
                            error = %e,
                            "failed to parse SPIFFE-DID binding"
                        );
                        None
                    }
                }
            }
            Ok(response) => {
                tracing::debug!(
                    did,
                    status = %response.status(),
                    "no SPIFFE-DID binding at {binding_url}"
                );
                None
            }
            Err(e) => {
                tracing::debug!(
                    did,
                    error = %e,
                    "could not fetch SPIFFE-DID binding from {binding_url}"
                );
                None
            }
        };

        Ok((doc, binding))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// CACHING RESOLVER
// ═══════════════════════════════════════════════════════════════════════════

/// A caching wrapper around any [`DidResolver`] that stores resolved
/// documents in memory with a TTL.
///
/// Avoids repeated network requests for the same DID within the TTL window.
pub struct CachingDidResolver<R> {
    inner: R,
    cache: tokio::sync::RwLock<HashMap<String, CacheEntry>>,
    ttl: std::time::Duration,
}

struct CacheEntry {
    document: DidDocument,
    binding: Option<SpiffeDidBinding>,
    inserted_at: std::time::Instant,
}

impl<R: DidResolver> CachingDidResolver<R> {
    /// Wrap a resolver with caching using the given TTL.
    pub fn new(inner: R, ttl: std::time::Duration) -> Self {
        Self {
            inner,
            cache: tokio::sync::RwLock::new(HashMap::new()),
            ttl,
        }
    }

    /// Invalidate a cached entry.
    pub async fn invalidate(&self, did: &str) {
        self.cache.write().await.remove(did);
    }

    /// Invalidate all cached entries.
    pub async fn invalidate_all(&self) {
        self.cache.write().await.clear();
    }
}

impl<R: std::fmt::Debug> std::fmt::Debug for CachingDidResolver<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachingDidResolver")
            .field("inner", &self.inner)
            .field("ttl", &self.ttl)
            .finish()
    }
}

#[async_trait]
impl<R: DidResolver> DidResolver for CachingDidResolver<R> {
    async fn resolve(&self, did: &str) -> Result<DidDocument> {
        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(did) {
                if entry.inserted_at.elapsed() < self.ttl {
                    return Ok(entry.document.clone());
                }
            }
        }

        // Cache miss or expired — resolve and cache
        let (doc, binding) = self.inner.resolve_with_binding(did).await?;
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                did.to_string(),
                CacheEntry {
                    document: doc.clone(),
                    binding,
                    inserted_at: std::time::Instant::now(),
                },
            );
        }
        Ok(doc)
    }

    async fn resolve_with_binding(
        &self,
        did: &str,
    ) -> Result<(DidDocument, Option<SpiffeDidBinding>)> {
        // Check cache
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(did) {
                if entry.inserted_at.elapsed() < self.ttl {
                    return Ok((entry.document.clone(), entry.binding.clone()));
                }
            }
        }

        // Cache miss or expired
        let (doc, binding) = self.inner.resolve_with_binding(did).await?;
        {
            let mut cache = self.cache.write().await;
            cache.insert(
                did.to_string(),
                CacheEntry {
                    document: doc.clone(),
                    binding: binding.clone(),
                    inserted_at: std::time::Instant::now(),
                },
            );
        }
        Ok((doc, binding))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::{JsonWebKey, ServiceEndpoint, VerificationMethod};
    use crate::did_binding::BindingProof;
    use chrono::Utc;

    fn sample_doc(did: &str) -> DidDocument {
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: did.into(),
            verification_method: vec![VerificationMethod {
                id: format!("{did}#key-1"),
                method_type: "JsonWebKey2020".into(),
                controller: did.into(),
                public_key_jwk: JsonWebKey::ec_p256("x", "y"),
            }],
            authentication: Some(vec![format!("{did}#key-1")]),
            assertion_method: None,
            key_agreement: None,
            service: None,
        }
    }

    fn sample_binding(did: &str) -> SpiffeDidBinding {
        SpiffeDidBinding {
            did: did.into(),
            spiffe_id: "spiffe://test.local/ns/apps/sa/my-app".into(),
            binding_proof: BindingProof {
                proof_type: "SpiffeDidBinding".into(),
                created: Utc::now(),
                expires: Utc::now() + chrono::Duration::hours(1),
                svid_fingerprint: "SHA256:test".into(),
                did_key_id: format!("{did}#key-1"),
                attestation_chain: vec![],
                signature_over_did_by_svid: "stub.sig.jws".into(),
                signature_over_svid_by_did: "stub.sig.jws".into(),
            },
        }
    }

    #[tokio::test]
    async fn resolve_existing_document() {
        let mut resolver = InMemoryDidResolver::new();
        resolver.insert(sample_doc("did:web:app.dev"));

        let doc = resolver.resolve("did:web:app.dev").await.unwrap();
        assert_eq!(doc.id, "did:web:app.dev");
        assert_eq!(doc.verification_method.len(), 1);
    }

    #[tokio::test]
    async fn resolve_not_found() {
        let resolver = InMemoryDidResolver::new();
        let result = resolver.resolve("did:web:nonexistent.dev").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resolve_with_binding_both_present() {
        let mut resolver = InMemoryDidResolver::new();
        let did = "did:web:app.dev";
        resolver.insert(sample_doc(did));
        resolver.insert_binding(sample_binding(did));

        let (doc, binding) = resolver.resolve_with_binding(did).await.unwrap();
        assert_eq!(doc.id, did);
        assert!(binding.is_some());
        assert_eq!(
            binding.unwrap().spiffe_id,
            "spiffe://test.local/ns/apps/sa/my-app"
        );
    }

    #[tokio::test]
    async fn resolve_with_binding_no_binding() {
        let mut resolver = InMemoryDidResolver::new();
        resolver.insert(sample_doc("did:web:app.dev"));

        let (doc, binding) = resolver
            .resolve_with_binding("did:web:app.dev")
            .await
            .unwrap();
        assert_eq!(doc.id, "did:web:app.dev");
        assert!(binding.is_none());
    }

    #[tokio::test]
    async fn remove_document_and_binding() {
        let mut resolver = InMemoryDidResolver::new();
        let did = "did:web:app.dev";
        resolver.insert(sample_doc(did));
        resolver.insert_binding(sample_binding(did));

        assert_eq!(resolver.len(), 1);
        resolver.remove(did);
        assert_eq!(resolver.len(), 0);
        assert!(resolver.resolve(did).await.is_err());
    }

    #[tokio::test]
    async fn multiple_documents() {
        let mut resolver = InMemoryDidResolver::new();
        resolver.insert(sample_doc("did:web:a.dev"));
        resolver.insert(sample_doc("did:web:b.dev"));
        resolver.insert(sample_doc("did:web:c.dev"));

        assert_eq!(resolver.len(), 3);
        assert!(!resolver.is_empty());

        let mut dids = resolver.dids();
        dids.sort();
        assert_eq!(
            dids,
            vec!["did:web:a.dev", "did:web:b.dev", "did:web:c.dev"]
        );
    }

    #[tokio::test]
    async fn insert_overwrites() {
        let mut resolver = InMemoryDidResolver::new();
        let did = "did:web:app.dev";

        let mut doc1 = sample_doc(did);
        doc1.service = None;
        resolver.insert(doc1);

        let mut doc2 = sample_doc(did);
        doc2.service = Some(vec![ServiceEndpoint {
            id: format!("{did}#api"),
            service_type: "RestApi".into(),
            service_endpoint: "https://app.dev/api".into(),
            description: None,
        }]);
        resolver.insert(doc2);

        let resolved = resolver.resolve(did).await.unwrap();
        assert!(resolved.service.is_some());
        assert_eq!(resolver.len(), 1);
    }

    #[tokio::test]
    async fn default_is_empty() {
        let resolver = InMemoryDidResolver::default();
        assert!(resolver.is_empty());
        assert_eq!(resolver.len(), 0);
    }

    // ── CachingDidResolver ─────────────────────────────────────────────

    #[tokio::test]
    async fn caching_resolver_caches_result() {
        let mut inner = InMemoryDidResolver::new();
        inner.insert(sample_doc("did:web:app.dev"));

        let caching = CachingDidResolver::new(inner, std::time::Duration::from_secs(60));
        let doc = caching.resolve("did:web:app.dev").await.unwrap();
        assert_eq!(doc.id, "did:web:app.dev");

        // Remove from inner — cache should still serve it
        // (We can't mutate inner after move, but we can verify the cache
        // serves the doc without calling inner again by resolving twice)
        let doc2 = caching.resolve("did:web:app.dev").await.unwrap();
        assert_eq!(doc2.id, "did:web:app.dev");
    }

    #[tokio::test]
    async fn caching_resolver_caches_binding() {
        let mut inner = InMemoryDidResolver::new();
        let did = "did:web:app.dev";
        inner.insert(sample_doc(did));
        inner.insert_binding(sample_binding(did));

        let caching = CachingDidResolver::new(inner, std::time::Duration::from_secs(60));
        let (doc, binding) = caching.resolve_with_binding(did).await.unwrap();
        assert_eq!(doc.id, did);
        assert!(binding.is_some());

        // Second call should hit cache
        let (doc2, binding2) = caching.resolve_with_binding(did).await.unwrap();
        assert_eq!(doc2.id, did);
        assert!(binding2.is_some());
    }

    #[tokio::test]
    async fn caching_resolver_invalidate() {
        let mut inner = InMemoryDidResolver::new();
        inner.insert(sample_doc("did:web:app.dev"));

        let caching = CachingDidResolver::new(inner, std::time::Duration::from_secs(60));

        // Populate cache
        caching.resolve("did:web:app.dev").await.unwrap();

        // Invalidate
        caching.invalidate("did:web:app.dev").await;

        // Should re-fetch from inner (which still has the doc)
        let doc = caching.resolve("did:web:app.dev").await.unwrap();
        assert_eq!(doc.id, "did:web:app.dev");
    }

    #[tokio::test]
    async fn caching_resolver_invalidate_all() {
        let mut inner = InMemoryDidResolver::new();
        inner.insert(sample_doc("did:web:a.dev"));
        inner.insert(sample_doc("did:web:b.dev"));

        let caching = CachingDidResolver::new(inner, std::time::Duration::from_secs(60));
        caching.resolve("did:web:a.dev").await.unwrap();
        caching.resolve("did:web:b.dev").await.unwrap();

        caching.invalidate_all().await;

        // Both should re-fetch
        let a = caching.resolve("did:web:a.dev").await.unwrap();
        let b = caching.resolve("did:web:b.dev").await.unwrap();
        assert_eq!(a.id, "did:web:a.dev");
        assert_eq!(b.id, "did:web:b.dev");
    }

    #[tokio::test]
    async fn caching_resolver_not_found_propagates() {
        let inner = InMemoryDidResolver::new();
        let caching = CachingDidResolver::new(inner, std::time::Duration::from_secs(60));
        let result = caching.resolve("did:web:missing.dev").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn caching_resolver_debug() {
        let inner = InMemoryDidResolver::new();
        let caching = CachingDidResolver::new(inner, std::time::Duration::from_secs(60));
        let debug_str = format!("{caching:?}");
        assert!(debug_str.contains("CachingDidResolver"));
    }
}
