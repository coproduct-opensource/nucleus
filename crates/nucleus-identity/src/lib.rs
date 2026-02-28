//! SPIFFE-based workload identity for Firecracker VMs.
//!
//! This crate provides SPIFFE identity management for nucleus pods running
//! in Firecracker VMs. It enables mTLS authentication for both in-node and
//! cross-cluster networking.
//!
//! # Components
//!
//! - [`identity`] - SPIFFE ID types and parsing
//! - [`session`] - Ephemeral session identity for AI agent conversations
//! - [`attestation`] - Launch attestation for VM integrity verification
//! - [`csr`] - CSR generation using P-256 ECDSA
//! - [`certificate`] - X.509 certificate handling
//! - [`manager`] - SecretManager for multi-identity cert caching and rotation
//! - [`verifier`] - SPIFFE-aware mTLS verification
//! - [`ca`] - CA client trait and implementations (self-signed, SPIRE)
//! - [`workload_api`] - Workload API server for VMs
//! - [`did`] - W3C DID Document types for did:web method
//! - [`did_binding`] - SPIFFE-DID binding proof types
//! - [`did_crypto`] - JWS ES256 signing/verification and EC key extraction
//! - [`did_builder`] - Higher-level DID document and binding proof builders
//! - [`did_resolver`] - DID resolution trait and in-memory resolver
//! - [`webfinger`] - WebFinger discovery protocol (RFC 7033)
//! - [`dpop`] - OAuth2 DPoP proof-of-possession tokens (RFC 9449)

pub mod attestation;
pub mod ca;
pub mod certificate;
pub mod csr;
pub mod did;
pub mod did_binding;
pub mod did_builder;
pub mod did_crypto;
pub mod did_resolver;
pub mod dpop;
pub mod identity;
pub mod manager;
pub mod oid;
pub mod session;
pub mod tls;
pub mod verifier;
pub mod wallet;
pub mod webfinger;
pub mod workload_api;

pub use attestation::{AttestationRequirements, LaunchAttestation};
#[cfg(feature = "spire")]
pub use ca::{auto_detect_ca, SpireCaClient, DEFAULT_SPIRE_SOCKET, SPIFFE_ENDPOINT_ENV};
pub use ca::{CaClient, SelfSignedCa};
pub use certificate::{TrustBundle, WorkloadCertificate};
pub use csr::{CertSign, CsrOptions};
pub use did::{did_web_to_url, DidDocument, JsonWebKey, ServiceEndpoint, VerificationMethod};
pub use did_binding::{BindingProof, BindingVerification, SpiffeDidBinding};
pub use did_builder::{
    build_binding, build_did_document, extract_svid_material, verify_binding, SvidMaterial,
};
pub use did_crypto::{
    cert_fingerprint, chain_from_base64url, chain_to_base64url, extract_ec_p256_jwk,
    jws_sign_es256, jws_verify_es256,
};
#[cfg(feature = "resolver")]
pub use did_resolver::HttpDidResolver;
pub use did_resolver::{CachingDidResolver, DidResolver, InMemoryDidResolver};
pub use dpop::{DpopClaims, DpopHeader, DpopProofBuilder, DpopVerifier};
pub use identity::Identity;
pub use manager::SecretManager;
pub use session::{SessionId, SessionIdentity};
pub use tls::{TlsClientConfig, TlsServerConfig};
pub use verifier::{IdentityVerifier, TrustDomainVerifier};
pub use wallet::{InMemoryWalletRegistry, WalletAddress, WalletMapping};
pub use webfinger::{
    parse_webfinger_resource, WebFingerLink, WebFingerResource, WebFingerResponse,
};
pub use workload_api::{MtlsWorkloadApiClient, VmRegistry, WorkloadApiClient, WorkloadApiServer};

/// Errors that can occur in nucleus-identity operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid SPIFFE URI format.
    #[error("invalid SPIFFE URI: {0}")]
    InvalidSpiffeUri(String),

    /// Certificate parsing error.
    #[error("certificate error: {0}")]
    Certificate(String),

    /// CSR generation error.
    #[error("CSR generation failed: {0}")]
    CsrGeneration(String),

    /// CA signing error.
    #[error("CA signing failed: {0}")]
    CaSigning(String),

    /// Certificate not found in cache.
    #[error("certificate not found for identity: {0}")]
    CertificateNotFound(String),

    /// Certificate expired.
    #[error("certificate expired")]
    CertificateExpired,

    /// Trust domain mismatch.
    #[error("trust domain mismatch: expected {expected}, got {actual}")]
    TrustDomainMismatch { expected: String, actual: String },

    /// Identity verification failed.
    #[error("identity verification failed: {0}")]
    VerificationFailed(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),

    /// Operation not supported by this implementation.
    #[error("not supported: {0}")]
    NotSupported(String),
}

/// Result type for nucleus-identity operations.
pub type Result<T> = std::result::Result<T, Error>;
