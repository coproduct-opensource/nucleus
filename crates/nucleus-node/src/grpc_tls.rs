//! gRPC TLS/mTLS configuration for nucleus-node.
//!
//! This module provides TLS server configuration for the gRPC API,
//! supporting both server-only TLS and mutual TLS (mTLS) with SPIFFE
//! client certificate verification.
//!
//! # Security Model
//!
//! When mTLS is enabled:
//! 1. Server presents its SPIFFE certificate to clients
//! 2. Clients must present a valid certificate signed by the trust bundle
//! 3. Client SPIFFE ID is extracted and can be used for authorization
//!
//! When server-only TLS is used:
//! 1. Server presents its certificate to clients
//! 2. No client authentication is required (HMAC auth still applies)
//!
//! # Configuration
//!
//! - `--grpc-tls-cert`: Path to server certificate PEM file
//! - `--grpc-tls-key`: Path to server private key PEM file
//! - `--grpc-tls-ca`: Path to CA certificate PEM for client verification (enables mTLS)

use nucleus_identity::{TrustBundle, WorkloadCertificate};
use std::path::Path;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
use tracing::{debug, info};

/// Configuration for gRPC TLS.
#[derive(Clone, Debug)]
pub struct GrpcTlsConfig {
    /// Server certificate and key.
    pub server_identity: Identity,
    /// Trust bundle for client verification (enables mTLS if present).
    pub client_ca: Option<Certificate>,
}

/// Error type for TLS configuration.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Certificate variant may be used for future validation errors
pub enum TlsConfigError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("identity error: {0}")]
    Identity(#[from] nucleus_identity::Error),
    #[error("certificate error: {0}")]
    Certificate(String),
}

impl GrpcTlsConfig {
    /// Creates a new TLS configuration from PEM file paths.
    ///
    /// If `ca_path` is provided, mutual TLS is enabled and clients must
    /// present valid certificates signed by the CA.
    pub async fn from_paths(
        cert_path: &Path,
        key_path: &Path,
        ca_path: Option<&Path>,
    ) -> Result<Self, TlsConfigError> {
        let cert_pem = tokio::fs::read_to_string(cert_path).await?;
        let key_pem = tokio::fs::read_to_string(key_path).await?;

        let server_identity = Identity::from_pem(&cert_pem, &key_pem);

        let client_ca = if let Some(ca) = ca_path {
            let ca_pem = tokio::fs::read_to_string(ca).await?;
            Some(Certificate::from_pem(&ca_pem))
        } else {
            None
        };

        info!(
            cert_path = %cert_path.display(),
            mtls_enabled = client_ca.is_some(),
            "loaded gRPC TLS configuration"
        );

        Ok(Self {
            server_identity,
            client_ca,
        })
    }

    /// Creates a TLS configuration from a nucleus-identity WorkloadCertificate.
    ///
    /// This is useful when using SPIRE to obtain certificates dynamically.
    pub fn from_workload_cert(
        cert: &WorkloadCertificate,
        trust_bundle: Option<&TrustBundle>,
    ) -> Result<Self, TlsConfigError> {
        // Convert certificate chain to PEM
        let cert_pem = cert
            .chain()
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("\n");

        let key_pem = cert.private_key_pem().to_string();
        let server_identity = Identity::from_pem(&cert_pem, &key_pem);

        let client_ca = trust_bundle.map(|bundle| {
            let ca_pem = bundle
                .roots()
                .iter()
                .map(|c| c.to_pem())
                .collect::<Vec<_>>()
                .join("\n");
            Certificate::from_pem(&ca_pem)
        });

        debug!(
            mtls_enabled = client_ca.is_some(),
            "created gRPC TLS config from workload certificate"
        );

        Ok(Self {
            server_identity,
            client_ca,
        })
    }

    /// Builds a tonic ServerTlsConfig from this configuration.
    pub fn build_server_tls_config(&self) -> ServerTlsConfig {
        let mut config = ServerTlsConfig::new().identity(self.server_identity.clone());

        if let Some(ref ca) = self.client_ca {
            config = config.client_ca_root(ca.clone());
            debug!("mTLS enabled: requiring client certificates");
        }

        config
    }

    /// Returns whether mTLS is enabled (client certs required).
    pub fn mtls_enabled(&self) -> bool {
        self.client_ca.is_some()
    }
}

/// Client SPIFFE ID extracted from mTLS connection.
///
/// This is extracted from the client certificate's Subject Alternative Name
/// and can be used for authorization decisions.
#[derive(Clone, Debug)]
pub struct ClientSpiffeId(pub String);

impl ClientSpiffeId {
    /// Returns the trust domain from the SPIFFE ID.
    pub fn trust_domain(&self) -> Option<&str> {
        self.0
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.split('/').next())
    }

    /// Returns the full SPIFFE URI.
    pub fn uri(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_spiffe_id_trust_domain() {
        let id = ClientSpiffeId("spiffe://nucleus.local/ns/default/sa/worker".to_string());
        assert_eq!(id.trust_domain(), Some("nucleus.local"));
        assert_eq!(id.uri(), "spiffe://nucleus.local/ns/default/sa/worker");
    }

    #[test]
    fn test_client_spiffe_id_invalid() {
        let id = ClientSpiffeId("not-a-spiffe-id".to_string());
        assert_eq!(id.trust_domain(), None);
    }

    #[tokio::test]
    async fn test_grpc_tls_config_from_workload_cert() {
        use nucleus_identity::{CaClient, CsrOptions, Identity as NucleusIdentity, SelfSignedCa};
        use std::time::Duration;

        let ca = SelfSignedCa::new("test.local").unwrap();
        let identity = NucleusIdentity::new("test.local", "servers", "grpc-server");
        let csr = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let cert = ca
            .sign_csr(
                csr.csr(),
                csr.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // Server-only TLS
        let config = GrpcTlsConfig::from_workload_cert(&cert, None).unwrap();
        assert!(!config.mtls_enabled());

        // mTLS
        let config_mtls =
            GrpcTlsConfig::from_workload_cert(&cert, Some(ca.trust_bundle())).unwrap();
        assert!(config_mtls.mtls_enabled());
    }
}
