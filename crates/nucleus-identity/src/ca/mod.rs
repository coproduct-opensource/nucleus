//! Certificate Authority (CA) client trait and implementations.
//!
//! This module provides a pluggable CA interface for signing workload certificates.
//! Implementations include:
//!
//! - [`SelfSignedCa`] - Self-signed CA for development and testing
//! - Future: `SpireCaClient` - SPIRE Server integration for production

mod self_signed;

pub use self_signed::SelfSignedCa;

use crate::certificate::WorkloadCertificate;
use crate::identity::Identity;
use crate::Result;
use async_trait::async_trait;
use std::time::Duration;

/// A Certificate Authority client that can sign CSRs.
#[async_trait]
pub trait CaClient: Send + Sync {
    /// Signs a Certificate Signing Request and returns a workload certificate.
    ///
    /// # Arguments
    ///
    /// * `csr` - PEM-encoded Certificate Signing Request
    /// * `identity` - The SPIFFE identity for the certificate
    /// * `ttl` - Requested time-to-live for the certificate
    ///
    /// # Returns
    ///
    /// A signed workload certificate with the requested identity.
    async fn sign_csr(
        &self,
        csr: &str,
        identity: &Identity,
        ttl: Duration,
    ) -> Result<WorkloadCertificate>;

    /// Returns the trust bundle (root CA certificates) for this CA.
    fn trust_bundle(&self) -> &crate::certificate::TrustBundle;

    /// Returns the trust domain this CA serves.
    fn trust_domain(&self) -> &str;
}
