//! SPIRE Server CA client for production deployments.
//!
//! This module provides a CA client that connects to a SPIRE Agent's Workload API
//! to obtain X.509 SVIDs and trust bundles. Unlike the self-signed CA, this relies
//! on an external SPIRE deployment for identity issuance and trust management.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           SPIRE DEPLOYMENT                              │
//! │                                                                         │
//! │   ┌──────────────┐         ┌──────────────┐         ┌──────────────┐   │
//! │   │ SPIRE Server │────────▶│ SPIRE Agent  │────────▶│ Workload API │   │
//! │   │ (CA)         │  Attest │ (per-node)   │   UDS   │ (gRPC)       │   │
//! │   └──────────────┘         └──────────────┘         └──────┬───────┘   │
//! │                                                             │          │
//! └─────────────────────────────────────────────────────────────┼──────────┘
//!                                                               │
//!                                                               ▼
//!                                                    ┌──────────────────┐
//!                                                    │ SpireCaClient    │
//!                                                    │ (this module)    │
//!                                                    └──────────────────┘
//! ```
//!
//! # Security Model
//!
//! SPIRE provides workload attestation - the SPIRE Agent verifies the workload's
//! identity through platform-specific attestors (Kubernetes, Docker, etc.) before
//! issuing an SVID. This eliminates the need for pre-shared secrets.
//!
//! Key security properties:
//! - **No key generation**: The Workload API returns pre-generated SVIDs; we don't
//!   request CSR signing (SPIRE manages the key lifecycle)
//! - **Automatic rotation**: SVIDs are short-lived; use `stream_x509_svids()` for
//!   automatic renewal
//! - **Trust federation**: SPIRE can federate trust across clusters
//!
//! # Example
//!
//! ```rust,ignore
//! use nucleus_identity::ca::{CaClient, SpireCaClient};
//! use nucleus_identity::Identity;
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Connect to SPIRE Agent via default socket
//! let ca = SpireCaClient::connect_env().await?;
//!
//! // Fetch an SVID (SPIRE manages key generation)
//! let svid = ca.fetch_svid().await?;
//! println!("SPIFFE ID: {}", svid.spiffe_id());
//!
//! // Get trust bundle for verification
//! let bundle = ca.trust_bundle();
//! # Ok(())
//! # }
//! ```
//!
//! # Feature Flag
//!
//! This module is only available when the `spire` feature is enabled:
//!
//! ```toml
//! [dependencies]
//! nucleus-identity = { version = "0.1", features = ["spire"] }
//! ```

use crate::ca::CaClient;
use crate::certificate::{Certificate, PrivateKey, TrustBundle, WorkloadCertificate};
use crate::identity::Identity;
use crate::{Error, Result};
use async_trait::async_trait;
use spiffe::workload_api::WorkloadApiClient;
use spiffe::X509Svid;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Default SPIRE Agent socket path.
pub const DEFAULT_SPIRE_SOCKET: &str = "/tmp/spire-agent/public/api.sock";

/// Environment variable for SPIFFE endpoint socket.
pub const SPIFFE_ENDPOINT_ENV: &str = "SPIFFE_ENDPOINT_SOCKET";

/// SPIRE-based CA client that connects to a SPIRE Agent's Workload API.
///
/// This client fetches pre-issued X.509 SVIDs from SPIRE rather than generating
/// CSRs. SPIRE manages the full key lifecycle including generation, rotation,
/// and revocation.
///
/// # Thread Safety
///
/// This client is `Send + Sync` and can be shared across threads.
///
/// # Trust Bundle Refresh
///
/// The trust bundle is cached at construction time. To get updated bundles,
/// create a new `SpireCaClient` instance. This design ensures the `&TrustBundle`
/// reference remains valid for the client's lifetime without requiring interior
/// mutability hacks.
///
/// For continuous trust bundle updates, use the `WorkloadApiClient` directly
/// with `stream_x509_bundles()`.
pub struct SpireCaClient {
    /// The underlying SPIFFE Workload API client.
    client: WorkloadApiClient,
    /// Cached trust bundle (immutable after construction).
    /// Boxed to ensure stable address for `&TrustBundle` reference.
    trust_bundle: Box<TrustBundle>,
    /// Trust domain extracted from the first SVID.
    trust_domain: String,
}

impl SpireCaClient {
    /// Connects to SPIRE Agent using the `SPIFFE_ENDPOINT_SOCKET` environment variable.
    ///
    /// This is the recommended way to connect in production, as it respects the
    /// standard SPIFFE environment variable.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `SPIFFE_ENDPOINT_SOCKET` is not set
    /// - Connection to the SPIRE Agent fails
    /// - Initial SVID fetch fails
    pub async fn connect_env() -> Result<Self> {
        let endpoint =
            std::env::var(SPIFFE_ENDPOINT_ENV).map_err(|_| Error::Internal(format!(
                "{} environment variable not set; set it to the SPIRE Agent socket path (e.g., unix:/tmp/spire-agent/public/api.sock)",
                SPIFFE_ENDPOINT_ENV
            )))?;

        Self::connect_to(&endpoint).await
    }

    /// Connects to SPIRE Agent at the given endpoint.
    ///
    /// # Arguments
    ///
    /// * `endpoint` - SPIFFE endpoint string, e.g., `unix:/tmp/spire-agent/public/api.sock`
    ///   or `tcp:127.0.0.1:8081`
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let ca = SpireCaClient::connect_to("unix:/tmp/spire-agent/public/api.sock").await?;
    /// ```
    pub async fn connect_to(endpoint: &str) -> Result<Self> {
        info!(endpoint = %endpoint, "Connecting to SPIRE Agent");

        let client = WorkloadApiClient::connect_to(endpoint)
            .await
            .map_err(|e| Error::Internal(format!("failed to connect to SPIRE Agent: {e}")))?;

        Self::from_client(client).await
    }

    /// Connects to SPIRE Agent at the default socket path.
    ///
    /// Default path: `/tmp/spire-agent/public/api.sock`
    pub async fn connect_default() -> Result<Self> {
        let endpoint = format!("unix:{}", DEFAULT_SPIRE_SOCKET);
        Self::connect_to(&endpoint).await
    }

    /// Creates a SpireCaClient from an existing WorkloadApiClient.
    ///
    /// This is useful for advanced scenarios where you need custom channel
    /// configuration.
    pub async fn from_client(client: WorkloadApiClient) -> Result<Self> {
        // Fetch initial SVID to validate connection and extract trust domain
        let svid = client
            .fetch_x509_svid()
            .await
            .map_err(|e| Error::Internal(format!("failed to fetch initial SVID: {e}")))?;

        let trust_domain = Self::extract_trust_domain(&svid)?;
        debug!(trust_domain = %trust_domain, "Extracted trust domain from SVID");

        // Fetch initial trust bundle
        let bundles = client
            .fetch_x509_bundles()
            .await
            .map_err(|e| Error::Internal(format!("failed to fetch X.509 bundles: {e}")))?;

        let trust_bundle = Self::convert_bundle_set(&bundles, &trust_domain)?;

        info!(
            trust_domain = %trust_domain,
            bundle_roots = trust_bundle.roots().len(),
            "Connected to SPIRE Agent"
        );

        Ok(Self {
            client,
            trust_bundle: Box::new(trust_bundle),
            trust_domain,
        })
    }

    /// Fetches the default X.509 SVID from SPIRE.
    ///
    /// This returns a workload certificate with the SVID's certificate chain
    /// and private key. The certificate is ready for use with mTLS.
    pub async fn fetch_svid(&self) -> Result<WorkloadCertificate> {
        let svid = self
            .client
            .fetch_x509_svid()
            .await
            .map_err(|e| Error::Internal(format!("failed to fetch SVID: {e}")))?;

        self.convert_svid_to_workload_cert(&svid)
    }

    /// Fetches all available X.509 SVIDs from SPIRE.
    ///
    /// Some workloads may have multiple SVIDs for different purposes (e.g.,
    /// different services within the same process).
    pub async fn fetch_all_svids(&self) -> Result<Vec<WorkloadCertificate>> {
        let svids = self
            .client
            .fetch_all_x509_svids()
            .await
            .map_err(|e| Error::Internal(format!("failed to fetch SVIDs: {e}")))?;

        svids
            .iter()
            .map(|svid| self.convert_svid_to_workload_cert(svid))
            .collect()
    }

    /// Returns a reference to the underlying SPIFFE Workload API client.
    ///
    /// Use this for advanced operations like streaming SVIDs or bundles.
    pub fn workload_api_client(&self) -> &WorkloadApiClient {
        &self.client
    }

    /// Checks if the SPIRE Agent is healthy and responsive.
    pub async fn health_check(&self) -> bool {
        self.client.fetch_x509_svid().await.is_ok()
    }

    /// Converts an X509Svid to a WorkloadCertificate.
    fn convert_svid_to_workload_cert(&self, svid: &X509Svid) -> Result<WorkloadCertificate> {
        // Convert certificate chain
        let cert_chain: Vec<Certificate> = svid
            .cert_chain()
            .iter()
            .map(|cert| Certificate::from_der(cert.as_ref().to_vec()))
            .collect();

        if cert_chain.is_empty() {
            return Err(Error::Certificate(
                "SVID has empty certificate chain".to_string(),
            ));
        }

        // Extract expiry from leaf certificate
        let expiry = cert_chain[0].not_after()?;

        // Convert private key to PEM
        let private_key_der = svid.private_key().as_ref();
        let private_key_pem = Self::der_to_pem(private_key_der, "PRIVATE KEY");
        let private_key = PrivateKey::from_pem(&private_key_pem)?;

        // Parse SPIFFE ID to Identity
        let identity = Self::parse_spiffe_id(svid.spiffe_id().to_string().as_str())?;

        Ok(WorkloadCertificate::new(
            cert_chain,
            private_key,
            expiry,
            identity,
        ))
    }

    /// Extracts the trust domain from an SVID's SPIFFE ID.
    fn extract_trust_domain(svid: &X509Svid) -> Result<String> {
        let spiffe_id = svid.spiffe_id().to_string();
        Self::parse_trust_domain(&spiffe_id)
    }

    /// Parses the trust domain from a SPIFFE URI.
    fn parse_trust_domain(spiffe_uri: &str) -> Result<String> {
        // spiffe://trust-domain/path...
        let uri = spiffe_uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| Error::InvalidSpiffeUri(spiffe_uri.to_string()))?;

        let trust_domain = uri
            .split('/')
            .next()
            .ok_or_else(|| Error::InvalidSpiffeUri(format!("no trust domain in: {spiffe_uri}")))?;

        if trust_domain.is_empty() {
            return Err(Error::InvalidSpiffeUri(format!(
                "empty trust domain in: {spiffe_uri}"
            )));
        }

        Ok(trust_domain.to_string())
    }

    /// Parses a SPIFFE ID string into an Identity.
    ///
    /// Handles both standard SPIFFE paths and Kubernetes-style paths:
    /// - `spiffe://domain/ns/namespace/sa/service-account`
    /// - `spiffe://domain/workload-name`
    ///
    /// Note: The Identity type only allows alphanumeric, dash, underscore, and dot
    /// in service account names. Path components with slashes are converted to use
    /// the last segment only.
    fn parse_spiffe_id(spiffe_uri: &str) -> Result<Identity> {
        let uri = spiffe_uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| Error::InvalidSpiffeUri(spiffe_uri.to_string()))?;

        let parts: Vec<&str> = uri.split('/').collect();
        if parts.is_empty() || parts[0].is_empty() {
            return Err(Error::InvalidSpiffeUri(spiffe_uri.to_string()));
        }

        let trust_domain = parts[0].to_string();

        // Try to parse as Kubernetes-style: ns/<namespace>/sa/<service-account>
        if parts.len() >= 5 && parts[1] == "ns" && parts[3] == "sa" {
            let namespace = parts[2].to_string();
            // Use last segment only since Identity doesn't allow slashes
            let service_account = parts.last().unwrap_or(&"default").to_string();
            return Ok(Identity::new(trust_domain, namespace, service_account));
        }

        // Generic path: use last component as service account, "default" as namespace
        let service_account = if parts.len() > 1 {
            // Use last segment only since Identity doesn't allow slashes
            parts.last().unwrap_or(&"default").to_string()
        } else {
            "default".to_string()
        };

        Ok(Identity::new(trust_domain, "default", service_account))
    }

    /// Converts SPIFFE bundle set to our TrustBundle type.
    fn convert_bundle_set(
        bundles: &spiffe::bundle::x509::X509BundleSet,
        trust_domain: &str,
    ) -> Result<TrustBundle> {
        use spiffe::TrustDomain;

        let mut roots = Vec::new();

        // Parse our trust domain
        let td = TrustDomain::try_from(trust_domain)
            .map_err(|e| Error::Internal(format!("invalid trust domain: {e}")))?;

        // Get bundle for our trust domain
        if let Some(bundle) = bundles.get(&td) {
            for cert in bundle.authorities() {
                roots.push(Certificate::from_der(cert.as_bytes().to_vec()));
            }
        }

        // Also include federated bundles
        for (federated_td, bundle) in bundles.iter() {
            if *federated_td != td {
                for cert in bundle.authorities() {
                    roots.push(Certificate::from_der(cert.as_bytes().to_vec()));
                }
            }
        }

        if roots.is_empty() {
            return Err(Error::Certificate(format!(
                "no trust bundle found for domain: {trust_domain}"
            )));
        }

        Ok(TrustBundle::new(roots))
    }

    /// Converts DER bytes to PEM format.
    fn der_to_pem(der: &[u8], label: &str) -> String {
        let p = pem::Pem::new(label, der);
        pem::encode(&p)
    }
}

#[async_trait]
impl CaClient for SpireCaClient {
    /// Signs a CSR using SPIRE.
    ///
    /// **Note:** SPIRE's Workload API doesn't support CSR signing directly.
    /// Instead, it issues pre-generated SVIDs. This method is provided for
    /// trait compatibility but will return an error explaining the limitation.
    ///
    /// For SPIRE-based identity, use [`fetch_svid()`](SpireCaClient::fetch_svid)
    /// instead.
    async fn sign_csr(
        &self,
        _csr: &str,
        _private_key: &str,
        identity: &Identity,
        _ttl: Duration,
    ) -> Result<WorkloadCertificate> {
        // SPIRE doesn't support CSR signing via Workload API
        // Instead, fetch a pre-issued SVID and verify it matches the requested identity

        warn!(
            identity = %identity.to_spiffe_uri(),
            "sign_csr called on SpireCaClient; SPIRE uses pre-issued SVIDs, not CSR signing"
        );

        let svid = self.fetch_svid().await?;

        // Verify the SVID matches the requested identity
        let svid_uri = svid.identity().to_spiffe_uri();
        let requested_uri = identity.to_spiffe_uri();

        if svid_uri != requested_uri {
            return Err(Error::VerificationFailed(format!(
                "SPIRE SVID identity mismatch: requested {}, got {}. \
                 Configure SPIRE workload registration to issue the correct identity.",
                requested_uri, svid_uri
            )));
        }

        Ok(svid)
    }

    async fn sign_csr_only(
        &self,
        _csr: &str,
        identity: &Identity,
        _ttl: Duration,
    ) -> Result<String> {
        // SPIRE doesn't support external CSR signing via Workload API
        // The SPIRE agent generates keys internally and issues SVIDs
        //
        // For OIDC flows, either:
        // 1. Use SelfSignedCa for development/testing
        // 2. Configure SPIRE Server OIDC Federation directly
        //
        warn!(
            identity = %identity.to_spiffe_uri(),
            "sign_csr_only called on SpireCaClient; SPIRE does not support external CSR signing. \
             Use SPIRE's native OIDC federation or SelfSignedCa for testing."
        );

        Err(Error::NotSupported(
            "SPIRE Workload API does not support signing external CSRs. \
             Configure SPIRE OIDC federation or use SelfSignedCa for development."
                .to_string(),
        ))
    }

    fn trust_bundle(&self) -> &TrustBundle {
        &self.trust_bundle
    }

    fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
}

impl SpireCaClient {
    /// Runs an SVID rotation watcher that streams X.509 context updates from SPIRE.
    ///
    /// This uses the SPIRE Workload API's streaming interface to receive push
    /// notifications when SVIDs are rotated, rather than polling. The watcher
    /// invokes the provided callback with each new `WorkloadCertificate`.
    ///
    /// # Arguments
    ///
    /// * `on_update` - Callback invoked with each rotated SVID certificate.
    ///   The callback receives the new `WorkloadCertificate` and can update
    ///   caches, reload TLS configs, etc.
    /// * `shutdown` - A `watch::Receiver<bool>` that signals when to stop.
    ///   Send `true` to gracefully shut down the watcher.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use tokio::sync::watch;
    ///
    /// let ca = SpireCaClient::connect_env().await?;
    /// let (shutdown_tx, shutdown_rx) = watch::channel(false);
    ///
    /// tokio::spawn(async move {
    ///     ca.run_svid_watcher(
    ///         |cert| {
    ///             println!("SVID rotated: {}", cert.identity().to_spiffe_uri());
    ///         },
    ///         shutdown_rx,
    ///     ).await;
    /// });
    ///
    /// // Later, to stop:
    /// shutdown_tx.send(true).unwrap();
    /// ```
    pub async fn run_svid_watcher<F>(
        &self,
        on_update: F,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) where
        F: Fn(WorkloadCertificate) + Send + Sync,
    {
        use futures_util::StreamExt;

        let stream = match self.client.stream_x509_contexts().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to start SVID rotation stream; falling back to no-op");
                return;
            }
        };

        tokio::pin!(stream);

        info!("SVID rotation watcher started");

        loop {
            tokio::select! {
                item = stream.next() => {
                    match item {
                        Some(Ok(context)) => {
                            if let Some(svid) = context.default_svid() {
                                match self.convert_svid_to_workload_cert(svid) {
                                    Ok(cert) => {
                                        info!(
                                            spiffe_id = %cert.identity().to_spiffe_uri(),
                                            "SVID rotated via SPIRE stream"
                                        );
                                        on_update(cert);
                                    }
                                    Err(e) => {
                                        warn!(error = %e, "failed to convert rotated SVID");
                                    }
                                }
                            }
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "SVID rotation stream error");
                        }
                        None => {
                            info!("SVID rotation stream ended");
                            break;
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("SVID rotation watcher shutting down");
                        break;
                    }
                }
            }
        }
    }
}

impl std::fmt::Debug for SpireCaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpireCaClient")
            .field("trust_domain", &self.trust_domain)
            .finish()
    }
}

/// Auto-detect the best available CA client.
///
/// This function tries to connect to SPIRE first, falling back to a self-signed
/// CA if SPIRE is unavailable. Use this for environments that may or may not
/// have SPIRE deployed.
///
/// # Priority
///
/// 1. SPIRE via `SPIFFE_ENDPOINT_SOCKET` environment variable
/// 2. SPIRE via default socket `/tmp/spire-agent/public/api.sock`
/// 3. Self-signed CA for the given trust domain (development fallback)
///
/// # Example
///
/// ```rust,ignore
/// let ca = auto_detect_ca("nucleus.local").await?;
/// ```
pub async fn auto_detect_ca(fallback_trust_domain: &str) -> Result<Box<dyn CaClient>> {
    // Try SPIFFE_ENDPOINT_SOCKET first
    if std::env::var(SPIFFE_ENDPOINT_ENV).is_ok() {
        match SpireCaClient::connect_env().await {
            Ok(client) => {
                info!("Using SPIRE CA client via {}", SPIFFE_ENDPOINT_ENV);
                return Ok(Box::new(client));
            }
            Err(e) => {
                warn!(error = %e, "Failed to connect to SPIRE via env var, trying default socket");
            }
        }
    }

    // Try default SPIRE socket
    let default_socket = std::path::Path::new(DEFAULT_SPIRE_SOCKET);
    if default_socket.exists() {
        match SpireCaClient::connect_default().await {
            Ok(client) => {
                info!("Using SPIRE CA client via default socket");
                return Ok(Box::new(client));
            }
            Err(e) => {
                warn!(error = %e, "Failed to connect to SPIRE via default socket");
            }
        }
    }

    // Fall back to self-signed CA
    info!(
        trust_domain = fallback_trust_domain,
        "No SPIRE agent available, falling back to self-signed CA (development mode)"
    );
    let self_signed = crate::ca::SelfSignedCa::new(fallback_trust_domain)?;
    Ok(Box::new(self_signed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_trust_domain() {
        assert_eq!(
            SpireCaClient::parse_trust_domain("spiffe://example.org/ns/default/sa/web").unwrap(),
            "example.org"
        );
        assert_eq!(
            SpireCaClient::parse_trust_domain("spiffe://nucleus.local/workload").unwrap(),
            "nucleus.local"
        );
    }

    #[test]
    fn test_parse_trust_domain_invalid() {
        assert!(SpireCaClient::parse_trust_domain("http://example.org").is_err());
        assert!(SpireCaClient::parse_trust_domain("spiffe://").is_err());
    }

    #[test]
    fn test_parse_spiffe_id_kubernetes() {
        let identity =
            SpireCaClient::parse_spiffe_id("spiffe://example.org/ns/production/sa/api-server")
                .unwrap();
        assert_eq!(identity.trust_domain(), "example.org");
        assert_eq!(identity.namespace(), "production");
        assert_eq!(identity.service_account(), "api-server");
    }

    #[test]
    fn test_parse_spiffe_id_generic() {
        // Generic paths use the last segment as service account
        let identity =
            SpireCaClient::parse_spiffe_id("spiffe://example.org/workload/my-service").unwrap();
        assert_eq!(identity.trust_domain(), "example.org");
        assert_eq!(identity.namespace(), "default");
        assert_eq!(identity.service_account(), "my-service");

        // Single segment path
        let identity = SpireCaClient::parse_spiffe_id("spiffe://example.org/my-workload").unwrap();
        assert_eq!(identity.trust_domain(), "example.org");
        assert_eq!(identity.namespace(), "default");
        assert_eq!(identity.service_account(), "my-workload");
    }

    #[test]
    fn test_der_to_pem_roundtrip() {
        let der = b"test data";
        let pem_str = SpireCaClient::der_to_pem(der, "TEST");
        assert!(pem_str.contains("-----BEGIN TEST-----"));
        assert!(pem_str.contains("-----END TEST-----"));
        // Verify roundtrip
        let parsed = pem::parse(&pem_str).unwrap();
        assert_eq!(parsed.contents(), der);
    }
}
