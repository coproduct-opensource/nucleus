//! End-to-end mTLS integration tests for nucleus-tool-proxy.
//!
//! These tests verify the complete mTLS flow:
//! 1. Server starts with mTLS configuration
//! 2. Client connects with valid SPIFFE certificate
//! 3. Client certificate is extracted and verified
//! 4. Requests are processed with identity context

use nucleus_identity::{
    CaClient, CsrOptions, Identity, SelfSignedCa, TrustBundle, WorkloadCertificate,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Helper to create a test CA and certificates.
async fn create_test_certs(
    trust_domain: &str,
) -> (
    Arc<SelfSignedCa>,
    WorkloadCertificate,
    WorkloadCertificate,
    TrustBundle,
) {
    let ca = Arc::new(SelfSignedCa::new(trust_domain).unwrap());
    let trust_bundle = ca.trust_bundle().clone();

    // Create server certificate
    let server_identity = Identity::new(trust_domain, "servers", "tool-proxy");
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

    // Create client certificate
    let client_identity = Identity::new(trust_domain, "agents", "claude");
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

    (ca, server_cert, client_cert, trust_bundle)
}

/// Test that the MtlsListener can be created with valid certificates.
#[tokio::test]
async fn test_mtls_listener_creation() {
    use nucleus_identity::TlsServerConfig;

    let (_ca, server_cert, _client_cert, trust_bundle) =
        create_test_certs("test.nucleus.local").await;

    // Build TLS acceptor - this validates the certificate configuration
    let config = TlsServerConfig::new(server_cert, trust_bundle);
    let acceptor = config.build_acceptor();

    assert!(acceptor.is_ok(), "should create acceptor with valid certs");
}

/// Test that a TLS handshake succeeds with matching trust bundles.
#[tokio::test]
async fn test_mtls_handshake_succeeds() {
    use nucleus_identity::{TlsClientConfig, TlsServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (_ca, server_cert, client_cert, trust_bundle) =
        create_test_certs("mtls.nucleus.local").await;

    // Start a TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server task
    let server_trust_bundle = trust_bundle.clone();
    let server_handle = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();

        let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
            .build_acceptor()
            .unwrap();

        let mut tls_stream = acceptor.accept(stream).await.unwrap();

        // Read a message from client
        let mut buf = vec![0u8; 1024];
        let n = tls_stream.read(&mut buf).await.unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(msg, "hello from client");

        // Send response
        tls_stream.write_all(b"hello from server").await.unwrap();
    });

    // Client task
    let client_handle = tokio::spawn(async move {
        use tokio::net::TcpStream;

        let stream = TcpStream::connect(addr).await.unwrap();

        let connector = TlsClientConfig::new(client_cert, trust_bundle)
            .with_spiffe_trust_domain("mtls.nucleus.local")
            .build_connector()
            .unwrap();

        let server_name =
            rustls::pki_types::ServerName::try_from("mtls.nucleus.local".to_string()).unwrap();

        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        // Send a message
        tls_stream.write_all(b"hello from client").await.unwrap();

        // Read response
        let mut buf = vec![0u8; 1024];
        let n = tls_stream.read(&mut buf).await.unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert_eq!(msg, "hello from server");
    });

    // Wait for both tasks
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test that TLS handshake fails with mismatched trust bundles.
#[tokio::test]
async fn test_mtls_handshake_fails_untrusted_client() {
    use nucleus_identity::TlsServerConfig;

    // Create two separate CAs
    let server_ca = Arc::new(SelfSignedCa::new("server.nucleus.local").unwrap());
    let client_ca = Arc::new(SelfSignedCa::new("attacker.nucleus.local").unwrap());

    // Server cert from server CA
    let server_identity = Identity::new("server.nucleus.local", "servers", "proxy");
    let server_csr = CsrOptions::new(server_identity.to_spiffe_uri())
        .generate()
        .unwrap();
    let server_cert = server_ca
        .sign_csr(
            server_csr.csr(),
            server_csr.private_key(),
            &server_identity,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

    // Client cert from attacker CA (untrusted)
    let client_identity = Identity::new("attacker.nucleus.local", "evil", "agent");
    let client_csr = CsrOptions::new(client_identity.to_spiffe_uri())
        .generate()
        .unwrap();
    let client_cert = client_ca
        .sign_csr(
            client_csr.csr(),
            client_csr.private_key(),
            &client_identity,
            Duration::from_secs(3600),
        )
        .await
        .unwrap();

    let server_trust_bundle = server_ca.trust_bundle().clone();
    let client_trust_bundle = client_ca.trust_bundle().clone();

    // Start a TCP listener
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Server task - will reject untrusted client
    let server_handle = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();

        let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
            .build_acceptor()
            .unwrap();

        // This should fail because client cert is from untrusted CA
        let result = acceptor.accept(stream).await;
        assert!(result.is_err(), "should reject untrusted client");
    });

    // Client task - using wrong trust bundle
    let client_handle = tokio::spawn(async move {
        use nucleus_identity::TlsClientConfig;
        use tokio::net::TcpStream;

        let stream = TcpStream::connect(addr).await.unwrap();

        let connector = TlsClientConfig::new(client_cert, client_trust_bundle)
            .with_spiffe_trust_domain("attacker.nucleus.local")
            .build_connector()
            .unwrap();

        let server_name =
            rustls::pki_types::ServerName::try_from("attacker.nucleus.local".to_string()).unwrap();

        // This should fail because server cert is from different CA
        let result = connector.connect(server_name, stream).await;
        assert!(result.is_err(), "should reject untrusted server");
    });

    // Wait for both tasks
    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Test that client certificate SPIFFE ID is correctly extracted.
#[tokio::test]
async fn test_client_spiffe_id_extraction() {
    use nucleus_identity::TlsServerConfig;
    use tokio::io::AsyncWriteExt;
    use tokio_rustls::server::TlsStream;

    let (_ca, server_cert, client_cert, trust_bundle) =
        create_test_certs("spiffe.nucleus.local").await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_trust_bundle = trust_bundle.clone();
    let server_handle = tokio::spawn(async move {
        let (stream, _peer) = listener.accept().await.unwrap();

        let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
            .build_acceptor()
            .unwrap();

        let tls_stream: TlsStream<tokio::net::TcpStream> = acceptor.accept(stream).await.unwrap();

        // Extract client certificate from TLS session
        let (_, server_conn) = tls_stream.get_ref();
        let certs = server_conn.peer_certificates();

        assert!(certs.is_some(), "client should present certificate");
        let client_certs = certs.unwrap();
        assert!(
            !client_certs.is_empty(),
            "certificate chain should not be empty"
        );

        // Parse the client certificate and extract SPIFFE ID
        let client_cert_der = client_certs[0].as_ref();
        let spiffe_id = extract_spiffe_id_from_cert(client_cert_der);

        assert!(spiffe_id.is_some(), "client cert should have SPIFFE ID");
        assert_eq!(
            spiffe_id.unwrap(),
            "spiffe://spiffe.nucleus.local/ns/agents/sa/claude"
        );
    });

    let client_handle = tokio::spawn(async move {
        use nucleus_identity::TlsClientConfig;
        use tokio::net::TcpStream;

        let stream = TcpStream::connect(addr).await.unwrap();

        let connector = TlsClientConfig::new(client_cert, trust_bundle)
            .with_spiffe_trust_domain("spiffe.nucleus.local")
            .build_connector()
            .unwrap();

        let server_name =
            rustls::pki_types::ServerName::try_from("spiffe.nucleus.local".to_string()).unwrap();

        let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

        // Just connect and close
        tls_stream.shutdown().await.ok();
    });

    let (server_result, client_result) = tokio::join!(server_handle, client_handle);
    server_result.unwrap();
    client_result.unwrap();
}

/// Helper to extract SPIFFE ID from a DER-encoded certificate.
fn extract_spiffe_id_from_cert(cert_der: &[u8]) -> Option<String> {
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

/// Test concurrent mTLS connections.
#[tokio::test]
async fn test_concurrent_mtls_connections() {
    use nucleus_identity::{TlsClientConfig, TlsServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (_ca, server_cert, client_cert, trust_bundle) =
        create_test_certs("concurrent.nucleus.local").await;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let num_clients = 5;
    let server_trust_bundle = trust_bundle.clone();

    // Server accepts multiple connections
    let server_handle = tokio::spawn(async move {
        let acceptor = TlsServerConfig::new(server_cert, server_trust_bundle)
            .build_acceptor()
            .unwrap();

        for i in 0..num_clients {
            let (stream, _peer) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();

            tokio::spawn(async move {
                let mut tls_stream = acceptor.accept(stream).await.unwrap();

                let mut buf = vec![0u8; 1024];
                let n = tls_stream.read(&mut buf).await.unwrap();
                let msg = String::from_utf8_lossy(&buf[..n]);

                // Echo back with server prefix
                let response = format!("server-{}: {}", i, msg);
                tls_stream.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });

    // Spawn multiple clients concurrently
    let mut client_handles = Vec::new();
    for i in 0..num_clients {
        let client_cert = client_cert.clone();
        let trust_bundle = trust_bundle.clone();

        let handle = tokio::spawn(async move {
            use tokio::net::TcpStream;

            let stream = TcpStream::connect(addr).await.unwrap();

            let connector = TlsClientConfig::new(client_cert, trust_bundle)
                .with_spiffe_trust_domain("concurrent.nucleus.local")
                .build_connector()
                .unwrap();

            let server_name =
                rustls::pki_types::ServerName::try_from("concurrent.nucleus.local".to_string())
                    .unwrap();

            let mut tls_stream = connector.connect(server_name, stream).await.unwrap();

            // Send unique message
            let msg = format!("client-{}", i);
            tls_stream.write_all(msg.as_bytes()).await.unwrap();

            // Read response
            let mut buf = vec![0u8; 1024];
            let n = tls_stream.read(&mut buf).await.unwrap();
            let response = String::from_utf8_lossy(&buf[..n]);

            assert!(
                response.contains(&format!("client-{}", i)),
                "response should contain client message"
            );
        });
        client_handles.push(handle);
    }

    // Wait for all clients
    for handle in client_handles {
        handle.await.unwrap();
    }

    // Give server time to finish
    tokio::time::sleep(Duration::from_millis(100)).await;
    server_handle.abort();
}
