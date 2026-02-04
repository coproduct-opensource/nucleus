//! Certificate Authority (CA) client trait and implementations.
//!
//! This module provides a pluggable CA interface for signing workload certificates.
//! Implementations include:
//!
//! - [`SelfSignedCa`] - Self-signed CA for development and testing
//! - [`SpireCaClient`] - SPIRE Server integration for production (requires `spire` feature)
//!
//! # Security Note
//!
//! The trait methods require the private key to be provided alongside the CSR.
//! This ensures the CA never generates keys on behalf of workloads, preventing
//! key escrow vulnerabilities. The CSR is still validated for:
//! - Signature validity (proof of private key possession)
//! - SPIFFE URI matching the requested identity
//! - Trust domain membership

mod self_signed;
#[cfg(feature = "spire")]
mod spire;

pub use self_signed::SelfSignedCa;
#[cfg(feature = "spire")]
pub use spire::{auto_detect_ca, SpireCaClient, DEFAULT_SPIRE_SOCKET, SPIFFE_ENDPOINT_ENV};

use crate::attestation::LaunchAttestation;
use crate::certificate::WorkloadCertificate;
use crate::identity::Identity;
use crate::Result;
use async_trait::async_trait;
use std::time::Duration;

/// A Certificate Authority client that can sign CSRs.
///
/// # Security Model
///
/// All signing methods require both the CSR and the private key. This design:
/// 1. **Prevents key escrow**: The CA never generates keys, so it never holds
///    workload private keys.
/// 2. **Validates CSR integrity**: The CSR signature is verified to prove the
///    requester possesses the corresponding private key.
/// 3. **Enforces identity matching**: The SPIFFE URI in the CSR must match the
///    requested identity.
#[async_trait]
pub trait CaClient: Send + Sync {
    /// Signs a Certificate Signing Request and returns a workload certificate.
    ///
    /// # Arguments
    ///
    /// * `csr` - PEM-encoded Certificate Signing Request
    /// * `private_key` - PEM-encoded private key (must match CSR's public key)
    /// * `identity` - The SPIFFE identity for the certificate
    /// * `ttl` - Requested time-to-live for the certificate
    ///
    /// # Security
    ///
    /// This method validates that:
    /// 1. The CSR signature is valid (proof of private key possession)
    /// 2. The SPIFFE URI in the CSR matches the requested identity
    /// 3. The identity's trust domain matches this CA's trust domain
    ///
    /// The private key is required because the issued certificate must use
    /// the workload's own key pair. The CA never generates keys for workloads.
    ///
    /// # Returns
    ///
    /// A signed workload certificate with the requested identity.
    async fn sign_csr(
        &self,
        csr: &str,
        private_key: &str,
        identity: &Identity,
        ttl: Duration,
    ) -> Result<WorkloadCertificate>;

    /// Signs a CSR with launch attestation embedded as an X.509 extension.
    ///
    /// The attestation is embedded using a custom OID following TCG DICE conventions.
    /// This binds the certificate to a specific VM configuration, enabling verifiers
    /// to ensure the workload is running in an attested environment.
    ///
    /// # Arguments
    ///
    /// * `csr` - PEM-encoded Certificate Signing Request
    /// * `private_key` - PEM-encoded private key (must match CSR's public key)
    /// * `identity` - The SPIFFE identity for the certificate
    /// * `ttl` - Requested time-to-live for the certificate
    /// * `attestation` - Launch attestation containing VM integrity measurements
    ///
    /// # Security
    ///
    /// Same security guarantees as `sign_csr()`, plus:
    /// - The attestation is cryptographically bound to the certificate
    /// - Verifiers can require specific attestation hashes
    ///
    /// # Returns
    ///
    /// A signed workload certificate with attestation extension.
    ///
    /// # Default Implementation
    ///
    /// By default, this falls back to `sign_csr()` without the attestation extension.
    /// Implementations should override this to properly embed attestation.
    async fn sign_attested_csr(
        &self,
        csr: &str,
        private_key: &str,
        identity: &Identity,
        ttl: Duration,
        _attestation: &LaunchAttestation,
    ) -> Result<WorkloadCertificate> {
        // Default: ignore attestation, just sign normally
        // Implementations should override to embed attestation as X.509 extension
        self.sign_csr(csr, private_key, identity, ttl).await
    }

    /// Signs a CSR and returns only the certificate chain (not the private key).
    ///
    /// This is used for OIDC token exchange flows where the client generates
    /// and retains its own private key. The server validates the CSR but never
    /// sees or stores the private key.
    ///
    /// # Arguments
    ///
    /// * `csr` - PEM-encoded Certificate Signing Request
    /// * `identity` - The SPIFFE identity for the certificate
    /// * `ttl` - Requested time-to-live for the certificate
    ///
    /// # Security
    ///
    /// This method validates that:
    /// 1. The CSR signature is valid (proof of private key possession)
    /// 2. The SPIFFE URI in the CSR matches the requested identity
    /// 3. The identity's trust domain matches this CA's trust domain
    ///
    /// The client keeps its private key locally; this method only returns the
    /// certificate chain, not a full WorkloadCertificate with embedded key.
    ///
    /// # Returns
    ///
    /// PEM-encoded certificate chain (leaf cert + intermediates).
    async fn sign_csr_only(
        &self,
        csr: &str,
        identity: &Identity,
        ttl: Duration,
    ) -> Result<String>;

    /// Returns the trust bundle (root CA certificates) for this CA.
    fn trust_bundle(&self) -> &crate::certificate::TrustBundle;

    /// Returns the trust domain this CA serves.
    fn trust_domain(&self) -> &str;
}
