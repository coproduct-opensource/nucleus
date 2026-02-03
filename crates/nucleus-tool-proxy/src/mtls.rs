//! mTLS server support for tool-proxy.
//!
//! This module provides TLS-wrapped axum serving with client certificate
//! extraction for SPIFFE identity and attestation verification.
//!
//! # Security Model
//!
//! When mTLS is enabled:
//! 1. Clients must present a valid SPIFFE certificate signed by the trust bundle
//! 2. The client certificate is extracted and stored in request extensions
//! 3. Attestation (if present) is extracted from the certificate's custom OID
//! 4. SPIFFE identity is extracted and used for authorization decisions
//!
//! # Usage
//!
//! ```ignore
//! let mtls_config = MtlsConfig::new(server_cert, trust_bundle);
//! serve_mtls(listener, app, mtls_config).await?;
//! ```

use axum::extract::connect_info::Connected;
use axum::Router;
use nucleus_identity::{TlsServerConfig, TrustBundle, WorkloadCertificate};
use std::io;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tracing::{debug, error, info, warn};

/// Configuration for mTLS server.
#[derive(Clone)]
pub struct MtlsConfig {
    /// Server's workload certificate.
    pub server_cert: WorkloadCertificate,
    /// Trust bundle for client certificate verification.
    pub trust_bundle: TrustBundle,
}

impl MtlsConfig {
    /// Creates a new mTLS configuration.
    pub fn new(server_cert: WorkloadCertificate, trust_bundle: TrustBundle) -> Self {
        Self {
            server_cert,
            trust_bundle,
        }
    }

    /// Builds a TLS acceptor from this configuration.
    pub fn build_acceptor(&self) -> Result<tokio_rustls::TlsAcceptor, nucleus_identity::Error> {
        TlsServerConfig::new(self.server_cert.clone(), self.trust_bundle.clone()).build_acceptor()
    }
}

/// Client certificate information extracted from mTLS handshake.
#[derive(Clone, Debug)]
pub struct ClientCertInfo {
    /// The DER-encoded client certificate.
    pub cert_der: Vec<u8>,
    /// The SPIFFE identity extracted from the certificate, if present.
    pub spiffe_id: Option<String>,
}

impl ClientCertInfo {
    /// Creates a new ClientCertInfo from a DER-encoded certificate.
    pub fn from_der(cert_der: Vec<u8>) -> Self {
        let spiffe_id = extract_spiffe_id(&cert_der);
        Self { cert_der, spiffe_id }
    }

    /// Returns the DER-encoded certificate bytes.
    pub fn der(&self) -> &[u8] {
        &self.cert_der
    }

    /// Returns the SPIFFE identity, if present.
    pub fn spiffe_id(&self) -> Option<&str> {
        self.spiffe_id.as_deref()
    }
}

/// Extracts SPIFFE ID from a DER-encoded certificate.
fn extract_spiffe_id(cert_der: &[u8]) -> Option<String> {
    use x509_parser::prelude::*;

    let (_, cert) = X509Certificate::from_der(cert_der).ok()?;

    for ext in cert.extensions() {
        if ext.oid == oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
            if let Ok((_, san)) =
                x509_parser::extensions::SubjectAlternativeName::from_der(ext.value)
            {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::URI(uri) = name {
                        if uri.starts_with("spiffe://") {
                            return Some(uri.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Custom axum listener that wraps TCP connections with TLS and extracts client certs.
pub struct MtlsListener {
    tcp_listener: TcpListener,
    tls_acceptor: tokio_rustls::TlsAcceptor,
}

impl MtlsListener {
    /// Creates a new mTLS listener.
    pub fn new(
        tcp_listener: TcpListener,
        config: &MtlsConfig,
    ) -> Result<Self, nucleus_identity::Error> {
        let tls_acceptor = config.build_acceptor()?;
        Ok(Self {
            tcp_listener,
            tls_acceptor,
        })
    }

    /// Returns the local address this listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.tcp_listener.local_addr()
    }
}

/// Connection info that includes both peer address and client certificate.
#[derive(Clone, Debug)]
pub struct MtlsConnectInfo {
    /// The peer socket address.
    pub peer_addr: SocketAddr,
    /// The client certificate, if presented during TLS handshake.
    pub client_cert: Option<ClientCertInfo>,
}

/// A TLS stream with associated client certificate information.
pub struct MtlsStream {
    inner: TlsStream<TcpStream>,
    connect_info: MtlsConnectInfo,
}

impl MtlsStream {
    /// Returns the client certificate info, if present.
    pub fn client_cert(&self) -> Option<&ClientCertInfo> {
        self.connect_info.client_cert.as_ref()
    }

    /// Returns the peer address.
    pub fn peer_addr(&self) -> SocketAddr {
        self.connect_info.peer_addr
    }

    /// Returns the connection info for extraction.
    pub fn connect_info(&self) -> &MtlsConnectInfo {
        &self.connect_info
    }
}

// Implement AsyncRead for MtlsStream
impl tokio::io::AsyncRead for MtlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// Implement AsyncWrite for MtlsStream
impl tokio::io::AsyncWrite for MtlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Implement axum's Listener trait for MtlsListener
impl axum::serve::Listener for MtlsListener {
    type Io = MtlsStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.tcp_listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("accepted TCP connection from {}", addr);

                    // Perform TLS handshake
                    match self.tls_acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            // Extract client certificate from the TLS session
                            let client_cert = extract_client_cert_from_tls(&tls_stream);

                            // Log connection at info level for audit purposes
                            if let Some(ref cert) = client_cert {
                                if let Some(ref spiffe_id) = cert.spiffe_id {
                                    info!(
                                        peer_addr = %addr,
                                        spiffe_id = %spiffe_id,
                                        event = "mtls_connection_established",
                                        "mTLS connection established"
                                    );
                                } else {
                                    warn!(
                                        peer_addr = %addr,
                                        event = "mtls_connection_no_spiffe_id",
                                        "mTLS connection established but certificate has no SPIFFE ID"
                                    );
                                }
                            } else {
                                warn!(
                                    peer_addr = %addr,
                                    event = "mtls_connection_no_client_cert",
                                    "mTLS handshake complete but no client certificate presented"
                                );
                            }

                            let connect_info = MtlsConnectInfo {
                                peer_addr: addr,
                                client_cert,
                            };

                            return (
                                MtlsStream {
                                    inner: tls_stream,
                                    connect_info,
                                },
                                addr,
                            );
                        }
                        Err(e) => {
                            warn!(
                                peer_addr = %addr,
                                error = %e,
                                event = "mtls_handshake_failed",
                                "TLS handshake failed"
                            );
                            // Continue to accept next connection
                        }
                    }
                }
                Err(e) => {
                    error!("TCP accept error: {}", e);
                    // Continue trying to accept
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.tcp_listener.local_addr()
    }
}

/// Extracts the client certificate from a TLS stream.
fn extract_client_cert_from_tls(tls_stream: &TlsStream<TcpStream>) -> Option<ClientCertInfo> {
    let (_, server_conn) = tls_stream.get_ref();

    // Get peer certificates from the TLS session
    let certs = server_conn.peer_certificates()?;

    if certs.is_empty() {
        return None;
    }

    // The first certificate is the end-entity (client) certificate
    let client_cert_der = certs[0].as_ref().to_vec();
    Some(ClientCertInfo::from_der(client_cert_der))
}

/// Serves an axum router over mTLS.
///
/// This function wraps TCP connections with TLS, requiring and verifying
/// client certificates against the configured trust bundle.
pub async fn serve_mtls(
    listener: TcpListener,
    app: Router,
    config: MtlsConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mtls_listener = MtlsListener::new(listener, &config)?;
    let addr = mtls_listener.local_addr()?;

    info!("nucleus-tool-proxy listening on {} (mTLS)", addr);

    axum::serve(mtls_listener, app).await?;

    Ok(())
}

/// Implement Connected trait so axum can extract MtlsConnectInfo
/// This is called by axum's `into_make_service_with_connect_info` to extract
/// connection info from the incoming stream.
impl<'a> Connected<axum::serve::IncomingStream<'a, MtlsListener>> for MtlsConnectInfo {
    fn connect_info(target: axum::serve::IncomingStream<'a, MtlsListener>) -> Self {
        target.io().connect_info().clone()
    }
}

/// Extension trait to access client certificate from axum request extensions.
pub trait ClientCertExt {
    /// Gets the client certificate info from the request, if present.
    fn client_cert(&self) -> Option<&ClientCertInfo>;
}

impl<B> ClientCertExt for axum::http::Request<B> {
    fn client_cert(&self) -> Option<&ClientCertInfo> {
        // Try to get from MtlsConnectInfo first
        if let Some(info) = self.extensions().get::<MtlsConnectInfo>() {
            return info.client_cert.as_ref();
        }
        // Fall back to direct ClientCertInfo
        self.extensions().get::<ClientCertInfo>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_spiffe_id_none() {
        // Empty/invalid DER should return None
        let result = extract_spiffe_id(&[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_client_cert_info_from_der() {
        // Invalid DER, but should not panic
        let info = ClientCertInfo::from_der(vec![1, 2, 3]);
        assert!(info.spiffe_id.is_none());
        assert_eq!(info.der(), &[1, 2, 3]);
    }

    #[tokio::test]
    async fn test_mtls_config_creation() {
        // Test that MtlsConfig can be created with valid certificates
        use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa};
        use std::time::Duration;

        let trust_domain = "test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        let trust_bundle = ca.trust_bundle().clone();

        // Create a server identity and certificate
        let identity = Identity::new(trust_domain, "servers", "proxy-server");
        let csr = CsrOptions::new(identity.to_spiffe_uri()).generate().unwrap();

        let cert = ca
            .sign_csr(csr.csr(), csr.private_key(), &identity, Duration::from_secs(3600))
            .await
            .unwrap();

        // Create mTLS config
        let config = MtlsConfig::new(cert, trust_bundle);
        assert!(config.build_acceptor().is_ok());
    }

    #[tokio::test]
    async fn test_extract_spiffe_id_from_valid_cert() {
        // Generate a certificate with a SPIFFE ID and verify extraction
        use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa};
        use std::time::Duration;

        let trust_domain = "test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();

        let identity = Identity::new(trust_domain, "agents", "claude");
        let csr = CsrOptions::new(identity.to_spiffe_uri()).generate().unwrap();

        let cert = ca
            .sign_csr(csr.csr(), csr.private_key(), &identity, Duration::from_secs(3600))
            .await
            .unwrap();

        // Extract SPIFFE ID from certificate's leaf DER
        let spiffe_id = extract_spiffe_id(cert.leaf().der());
        assert!(spiffe_id.is_some());
        assert_eq!(
            spiffe_id.unwrap(),
            "spiffe://test.nucleus.local/ns/agents/sa/claude"
        );
    }

    #[tokio::test]
    async fn test_client_cert_info_with_valid_cert() {
        use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa};
        use std::time::Duration;

        let trust_domain = "mtls.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();

        let identity = Identity::new(trust_domain, "workloads", "test-worker");
        let csr = CsrOptions::new(identity.to_spiffe_uri()).generate().unwrap();

        let cert = ca
            .sign_csr(csr.csr(), csr.private_key(), &identity, Duration::from_secs(3600))
            .await
            .unwrap();

        // Create ClientCertInfo from leaf certificate DER
        let info = ClientCertInfo::from_der(cert.leaf().der().to_vec());

        // Verify SPIFFE ID is extracted
        assert!(info.spiffe_id().is_some());
        assert_eq!(
            info.spiffe_id().unwrap(),
            "spiffe://mtls.nucleus.local/ns/workloads/sa/test-worker"
        );

        // Verify DER bytes match
        assert_eq!(info.der(), cert.leaf().der());
    }

    #[test]
    fn test_mtls_connect_info_clone() {
        use std::net::{IpAddr, Ipv4Addr};

        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);

        let info = MtlsConnectInfo {
            peer_addr: peer,
            client_cert: Some(ClientCertInfo::from_der(vec![1, 2, 3])),
        };

        let cloned = info.clone();
        assert_eq!(cloned.peer_addr, peer);
        assert!(cloned.client_cert.is_some());
    }
}
