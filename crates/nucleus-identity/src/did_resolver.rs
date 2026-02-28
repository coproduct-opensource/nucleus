//! DID resolution: resolve `did:web` identifiers to DID documents.
//!
//! Provides the [`DidResolver`] trait for resolving DIDs and an
//! [`InMemoryDidResolver`] for testing and local-first workflows.
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
}
