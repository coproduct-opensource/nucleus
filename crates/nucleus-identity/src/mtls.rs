//! Shared mTLS server support: TLS-wrapped axum serving with client
//! certificate extraction for SPIFFE identity and attestation verification.
//!
//! Promoted here from `nucleus-tool-proxy` (which now re-exports it) so a
//! second copy is structurally impossible rather than merely undesirable —
//! `nucleus-node`'s HTTP mTLS listener uses this same code. Two divergent
//! mTLS listeners, each accreting its own fixes, is exactly the shape of
//! defect this promotion exists to close off.
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

use crate::{TlsServerConfig, TrustBundle, WorkloadCertificate};
use axum::Router;
use axum::extract::connect_info::Connected;
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
    pub fn build_acceptor(&self) -> Result<tokio_rustls::TlsAcceptor, crate::Error> {
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
        Self {
            cert_der,
            spiffe_id,
        }
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
    // Delegated to nucleus-identity so this AUTHORIZATION path cannot disagree
    // with any other component about who a peer is. The local copy this
    // replaced returned the FIRST `spiffe://` SAN, so a certificate naming two
    // identities was accepted and resolved by DER encoding order.
    crate::spiffe_uri_from_svid(cert_der).ok()
}

/// Custom axum listener that wraps TCP connections with TLS and extracts client certs.
pub struct MtlsListener {
    tcp_listener: TcpListener,
    tls_acceptor: tokio_rustls::TlsAcceptor,
}

impl MtlsListener {
    /// Creates a new mTLS listener.
    pub fn new(tcp_listener: TcpListener, config: &MtlsConfig) -> Result<Self, crate::Error> {
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

/// Extracts the peer's SPIFFE ID from a SERVED request's extensions.
///
/// Reads `axum::extract::ConnectInfo<MtlsConnectInfo>` — what
/// `into_make_service_with_connect_info::<MtlsConnectInfo>()` actually
/// inserts. `AddExtension` (axum's internal service that does the insertion)
/// keys the extensions map by the type it was HANDED, which is
/// `ConnectInfo<MtlsConnectInfo>`, never bare `MtlsConnectInfo` — confirmed by
/// booting a real `MtlsListener` behind `axum::serve` and inspecting a live
/// request's extensions from inside a handler (`nucleus-tool-proxy`'s
/// `tests/mtls_connect_info_probe.rs`, since deleted once this landed).
///
/// A previous version of this logic (`ClientCertExt`, removed here, and a
/// duplicate that lived in `nucleus-tool-proxy::auth` before this promotion)
/// read `extensions.get::<MtlsConnectInfo>()` — the bare, un-wrapped type —
/// and so ALWAYS returned `None` against a real served request, even for a
/// client whose certificate the TLS handshake had genuinely verified. No
/// existing test caught this: every test exercising the extraction called it
/// with hand-built `Extensions` or a directly-constructed `MtlsConnectInfo`,
/// never through axum's actual `into_make_service_with_connect_info` path —
/// see `mtls_extraction_survives_the_real_serving_pipeline` below for the
/// regression test that would have failed against the old code.
///
/// The practical effect while this was broken: `AuthTier::SpiffeMtls` could
/// never actually be selected by a real mTLS connection in
/// `nucleus-tool-proxy`, so `--zero-prompt` (which requires exactly that
/// auth method) was unreachable even with `--mtls` correctly configured and
/// a valid client certificate presented.
pub fn extract_spiffe_id_from_extensions(extensions: &axum::http::Extensions) -> Option<String> {
    extensions
        .get::<axum::extract::ConnectInfo<MtlsConnectInfo>>()
        .and_then(|info| info.0.client_cert.as_ref())
        .and_then(|cert| cert.spiffe_id.clone())
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
        use crate::{CaClient, CsrOptions, Identity, SelfSignedCa};
        use std::time::Duration;

        let trust_domain = "test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        let trust_bundle = ca.trust_bundle().clone();

        // Create a server identity and certificate
        let identity = Identity::new(trust_domain, "servers", "proxy-server");
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

        // Create mTLS config
        let config = MtlsConfig::new(cert, trust_bundle);
        assert!(config.build_acceptor().is_ok());
    }

    #[tokio::test]
    async fn test_extract_spiffe_id_from_valid_cert() {
        // Generate a certificate with a SPIFFE ID and verify extraction
        use crate::{CaClient, CsrOptions, Identity, SelfSignedCa};
        use std::time::Duration;

        let trust_domain = "test.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();

        let identity = Identity::new(trust_domain, "agents", "agent");
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

        // Extract SPIFFE ID from certificate's leaf DER
        let spiffe_id = extract_spiffe_id(cert.leaf().der());
        assert!(spiffe_id.is_some());
        assert_eq!(
            spiffe_id.unwrap(),
            "spiffe://test.nucleus.local/ns/agents/sa/agent"
        );
    }

    #[tokio::test]
    async fn test_client_cert_info_with_valid_cert() {
        use crate::{CaClient, CsrOptions, Identity, SelfSignedCa};
        use std::time::Duration;

        let trust_domain = "mtls.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();

        let identity = Identity::new(trust_domain, "workloads", "test-worker");
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

    /// Every other test in this module checks `extract_spiffe_id_from_extensions`
    /// (or its predecessors) against hand-built `Extensions` or a directly
    /// constructed `MtlsConnectInfo` — none of them go through axum's actual
    /// `into_make_service_with_connect_info` machinery. That gap is exactly
    /// what let the bare-vs-`ConnectInfo`-wrapped defect described on
    /// `extract_spiffe_id_from_extensions` ship unnoticed. This test closes
    /// it: a REAL `MtlsListener` behind `axum::serve`, a REAL mTLS client
    /// connection, and a handler that calls the function under test on the
    /// request it actually received.
    #[tokio::test]
    async fn mtls_extraction_survives_the_real_serving_pipeline() {
        use crate::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsClientConfig};
        use axum::Router;
        use axum::extract::Request;
        use axum::routing::get;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let trust_domain = "pipeline.nucleus.local";
        let ca = SelfSignedCa::new(trust_domain).unwrap();
        let trust_bundle = ca.trust_bundle().clone();

        let server_identity = Identity::new(trust_domain, "servers", "pipeline-server");
        let server_csr = CsrOptions::new(server_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let server_cert = ca
            .sign_csr(
                server_csr.csr(),
                server_csr.private_key(),
                &server_identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let client_identity = Identity::new(trust_domain, "agents", "pipeline-client");
        let client_csr = CsrOptions::new(client_identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let client_cert = ca
            .sign_csr(
                client_csr.csr(),
                client_csr.private_key(),
                &client_identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();
        let expected_spiffe_id = client_identity.to_spiffe_uri();

        // The handler calls the EXACT function under test on a REQUEST IT
        // ACTUALLY RECEIVED, not on extensions the test assembled by hand.
        let app = Router::new().route(
            "/probe",
            get(|req: Request| async move {
                extract_spiffe_id_from_extensions(req.extensions())
                    .unwrap_or_else(|| "NONE".to_string())
            }),
        );

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_listener.local_addr().unwrap();
        let mtls_config = MtlsConfig::new(server_cert, trust_bundle.clone());
        let mtls_listener = MtlsListener::new(tcp_listener, &mtls_config).unwrap();

        let server_handle = tokio::spawn(async move {
            axum::serve(
                mtls_listener,
                app.into_make_service_with_connect_info::<MtlsConnectInfo>(),
            )
            .await
        });

        // Poll for the listener rather than a fixed sleep: `server_handle` is
        // spawned above and needs a scheduler turn before `accept()` is live.
        for _ in 0..50 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let connector = TlsClientConfig::new(client_cert, trust_bundle)
            .with_spiffe_trust_domain(trust_domain)
            .build_connector()
            .unwrap();
        let server_name =
            rustls::pki_types::ServerName::try_from(trust_domain.to_string()).unwrap();
        let mut tls = connector.connect(server_name, stream).await.unwrap();

        tls.write_all(
            format!("GET /probe HTTP/1.1\r\nHost: {trust_domain}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();

        let mut resp = Vec::new();
        tls.read_to_end(&mut resp).await.unwrap();
        let resp = String::from_utf8_lossy(&resp);

        server_handle.abort();

        assert!(
            resp.contains(&expected_spiffe_id),
            "handler did not see the SPIFFE ID through the real serving pipeline: {resp}"
        );
        assert!(
            !resp.contains("NONE"),
            "extraction returned None against a real, correctly-verified mTLS connection: {resp}"
        );
    }
}
