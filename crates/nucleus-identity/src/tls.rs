//! TLS configuration for mTLS Workload API.
//!
//! This module provides TLS server and client configuration builders using
//! workload certificates from the identity system. The TLS layer wraps Unix
//! socket connections with mutual TLS authentication.
//!
//! # Security Model
//!
//! - Both server and client must present valid SPIFFE certificates
//! - Certificates are validated against the trust bundle
//! - Trust domain enforcement prevents cross-domain connections
//! - Attestation extensions can be verified for VM integrity
//!
//! # Example
//!
//! ```ignore
//! use nucleus_identity::tls::{TlsServerConfig, TlsClientConfig};
//! use nucleus_identity::{WorkloadCertificate, TrustBundle};
//!
//! // Server configuration
//! let server_config = TlsServerConfig::new(
//!     server_cert,
//!     trust_bundle,
//! ).build().unwrap();
//!
//! // Client configuration
//! let client_config = TlsClientConfig::new(
//!     client_cert,
//!     trust_bundle,
//! ).build().unwrap();
//! ```

use crate::certificate::{TrustBundle, WorkloadCertificate};
use crate::{Error, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme};
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Builder for TLS server configuration.
///
/// Creates a `rustls::ServerConfig` that requires client certificates,
/// enabling mutual TLS authentication.
pub struct TlsServerConfig {
    server_cert: WorkloadCertificate,
    trust_bundle: TrustBundle,
}

impl TlsServerConfig {
    /// Creates a new TLS server config builder.
    ///
    /// # Arguments
    ///
    /// * `server_cert` - The server's workload certificate
    /// * `trust_bundle` - Trust bundle containing allowed root CAs
    pub fn new(server_cert: WorkloadCertificate, trust_bundle: TrustBundle) -> Self {
        Self {
            server_cert,
            trust_bundle,
        }
    }

    /// Builds the TLS server configuration.
    ///
    /// The resulting configuration:
    /// - Requires client certificates (mutual TLS)
    /// - Validates client certs against the trust bundle
    /// - Uses the server's workload certificate
    pub fn build(self) -> Result<ServerConfig> {
        // Install ring as the crypto provider
        let _ = default_provider().install_default();

        // Build root cert store from trust bundle
        let mut roots = RootCertStore::empty();
        for root in self.trust_bundle.roots() {
            let cert_der = root.der();
            roots
                .add(CertificateDer::from(cert_der.to_vec()))
                .map_err(|e| Error::Certificate(format!("failed to add root cert: {}", e)))?;
        }

        // Create client verifier that requires client certs
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|e| Error::Certificate(format!("failed to build client verifier: {}", e)))?;

        // Parse server certificate chain
        let cert_chain = parse_cert_chain(&self.server_cert.chain_pem())?;
        let private_key = parse_private_key(self.server_cert.private_key_pem())?;

        // Build server config
        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| Error::Certificate(format!("failed to build server config: {}", e)))?;

        Ok(config)
    }

    /// Builds a TLS acceptor for use with tokio-rustls.
    pub fn build_acceptor(self) -> Result<TlsAcceptor> {
        let config = self.build()?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

/// Builder for TLS client configuration.
///
/// Creates a `rustls::ClientConfig` that presents a client certificate,
/// enabling mutual TLS authentication.
pub struct TlsClientConfig {
    client_cert: WorkloadCertificate,
    trust_bundle: TrustBundle,
    trust_domain: Option<String>,
}

impl TlsClientConfig {
    /// Creates a new TLS client config builder.
    ///
    /// # Arguments
    ///
    /// * `client_cert` - The client's workload certificate
    /// * `trust_bundle` - Trust bundle containing allowed root CAs
    pub fn new(client_cert: WorkloadCertificate, trust_bundle: TrustBundle) -> Self {
        Self {
            client_cert,
            trust_bundle,
            trust_domain: None,
        }
    }

    /// Sets the trust domain for SPIFFE verification.
    ///
    /// When set, the client will accept server certificates that contain a
    /// SPIFFE URI with this trust domain, rather than requiring DNS name matching.
    pub fn with_spiffe_trust_domain(mut self, trust_domain: impl Into<String>) -> Self {
        self.trust_domain = Some(trust_domain.into());
        self
    }

    /// Builds the TLS client configuration.
    ///
    /// The resulting configuration:
    /// - Presents the client certificate
    /// - Validates server certs against the trust bundle
    pub fn build(self) -> Result<ClientConfig> {
        // Install ring as the crypto provider
        let _ = default_provider().install_default();

        // Build root cert store from trust bundle
        let mut roots = RootCertStore::empty();
        for root in self.trust_bundle.roots() {
            let cert_der = root.der();
            roots
                .add(CertificateDer::from(cert_der.to_vec()))
                .map_err(|e| Error::Certificate(format!("failed to add root cert: {}", e)))?;
        }

        // Parse client certificate chain
        let cert_chain = parse_cert_chain(&self.client_cert.chain_pem())?;
        let private_key = parse_private_key(self.client_cert.private_key_pem())?;

        // Build client config with appropriate server verifier
        let config = if let Some(trust_domain) = self.trust_domain {
            // Use SPIFFE-aware verifier
            let verifier = SpiffeServerCertVerifier::new(Arc::new(roots), trust_domain);
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_client_auth_cert(cert_chain, private_key)
                .map_err(|e| Error::Certificate(format!("failed to build client config: {}", e)))?
        } else {
            // Use standard certificate verification
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_client_auth_cert(cert_chain, private_key)
                .map_err(|e| Error::Certificate(format!("failed to build client config: {}", e)))?
        };

        Ok(config)
    }

    /// Builds a TLS connector for use with tokio-rustls.
    pub fn build_connector(self) -> Result<TlsConnector> {
        let config = self.build()?;
        Ok(TlsConnector::from(Arc::new(config)))
    }
}

/// Server name for workload API connections.
///
/// Since we're using Unix sockets with mTLS, the server name is derived from
/// the trust domain (e.g., "nucleus.local").
pub fn server_name_from_trust_domain(trust_domain: &str) -> Result<ServerName<'static>> {
    ServerName::try_from(trust_domain.to_string())
        .map_err(|e| Error::Certificate(format!("invalid server name '{}': {}", trust_domain, e)))
}

/// SPIFFE-aware server certificate verifier.
///
/// This verifier implements proper certificate chain validation for SPIFFE workload
/// identities. Unlike standard TLS verification which validates against DNS names,
/// this verifier:
///
/// 1. Validates the certificate chain against the trust bundle using webpki
/// 2. Verifies the certificate contains a SPIFFE URI SAN for the expected trust domain
/// 3. Checks certificate validity period
///
/// This enables mTLS between workloads using SPIFFE identities without requiring
/// DNS infrastructure or certificate authority support for DNS name validation.
#[derive(Debug)]
struct SpiffeServerCertVerifier {
    roots: Arc<RootCertStore>,
    trust_domain: String,
}

impl SpiffeServerCertVerifier {
    fn new(roots: Arc<RootCertStore>, trust_domain: String) -> Self {
        Self {
            roots,
            trust_domain,
        }
    }

    /// Extracts SPIFFE URI from certificate's Subject Alternative Name extension.
    ///
    /// Returns the first SPIFFE URI found that matches the expected trust domain prefix,
    /// or None if no matching URI is found.
    fn extract_spiffe_uri(&self, cert_der: &[u8]) -> Option<String> {
        use x509_parser::prelude::FromDer;

        let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
        let expected_prefix = format!("spiffe://{}/", self.trust_domain);

        for ext in cert.extensions() {
            if ext.oid == x509_parser::oid_registry::OID_X509_EXT_SUBJECT_ALT_NAME {
                if let Ok((_, san)) =
                    x509_parser::extensions::SubjectAlternativeName::from_der(ext.value)
                {
                    for name in &san.general_names {
                        // x509_parser uses URI variant (not UniformResourceIdentifier)
                        if let x509_parser::extensions::GeneralName::URI(uri) = name {
                            if uri.starts_with(&expected_prefix) {
                                return Some(uri.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

impl ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // Step 1: Parse the end-entity certificate for webpki verification
        let cert = webpki::EndEntityCert::try_from(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // Step 2: Convert rustls TrustAnchors to webpki TrustAnchors
        // The RootCertStore.roots field contains TrustAnchor<'static> with public fields
        let anchors: Vec<webpki::types::TrustAnchor> = self
            .roots
            .roots
            .iter()
            .map(|ta| webpki::types::TrustAnchor {
                subject: webpki::types::Der::from_slice(ta.subject.as_ref()),
                subject_public_key_info: webpki::types::Der::from_slice(
                    ta.subject_public_key_info.as_ref(),
                ),
                name_constraints: ta
                    .name_constraints
                    .as_ref()
                    .map(|nc| webpki::types::Der::from_slice(nc.as_ref())),
            })
            .collect();

        // Step 3: Convert intermediates to the format webpki expects
        let intermediate_certs: Vec<CertificateDer<'_>> = intermediates.to_vec();

        // Step 4: Build the verification time
        let time = webpki::types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            now.as_secs(),
        ));

        // Step 5: Define supported signature algorithms for SPIFFE (P-256 and P-384 ECDSA)
        let sig_algs: &[&dyn webpki::types::SignatureVerificationAlgorithm] = &[
            webpki::ring::ECDSA_P256_SHA256,
            webpki::ring::ECDSA_P256_SHA384,
            webpki::ring::ECDSA_P384_SHA256,
            webpki::ring::ECDSA_P384_SHA384,
            webpki::ring::RSA_PKCS1_2048_8192_SHA256,
            webpki::ring::RSA_PKCS1_2048_8192_SHA384,
            webpki::ring::RSA_PKCS1_2048_8192_SHA512,
            webpki::ring::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
            webpki::ring::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
            webpki::ring::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
        ];

        // Step 6: Verify the certificate chain using webpki
        // This validates:
        // - Chain builds to a trust anchor
        // - All certificates are within validity period
        // - Signatures are valid
        // - Extended Key Usage includes serverAuth
        cert.verify_for_usage(
            sig_algs,
            &anchors,
            &intermediate_certs,
            time,
            webpki::KeyUsage::server_auth(),
            None, // No revocation checking (would need OCSP/CRL infrastructure)
            None, // No custom path verification callback
        )
        .map_err(|e| {
            tracing::debug!("webpki chain verification failed: {:?}", e);
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
        })?;

        // Step 7: Verify SPIFFE URI in the certificate matches our trust domain
        // This is the SPIFFE-specific check that replaces DNS name verification
        let spiffe_uri = self
            .extract_spiffe_uri(end_entity.as_ref())
            .ok_or_else(|| {
                tracing::debug!(
                    "certificate missing SPIFFE URI for trust domain: {}",
                    self.trust_domain
                );
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                )
            })?;

        tracing::debug!("verified SPIFFE identity: {}", spiffe_uri);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Parses a PEM-encoded certificate chain into DER certificates.
fn parse_cert_chain(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut certs = Vec::new();
    let mut current = String::new();
    let mut in_cert = false;

    for line in pem.lines() {
        if line.contains("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            current.clear();
            current.push_str(line);
            current.push('\n');
        } else if line.contains("-----END CERTIFICATE-----") {
            current.push_str(line);
            current.push('\n');
            in_cert = false;

            let der = pem_to_der(&current)?;
            certs.push(CertificateDer::from(der));
        } else if in_cert {
            current.push_str(line);
            current.push('\n');
        }
    }

    if certs.is_empty() {
        return Err(Error::Certificate(
            "no certificates found in PEM".to_string(),
        ));
    }

    Ok(certs)
}

/// Parses a PEM-encoded private key into DER format.
fn parse_private_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    let der = pem_to_der(pem)?;

    // Try PKCS#8 format first (BEGIN PRIVATE KEY)
    if pem.contains("BEGIN PRIVATE KEY") {
        return Ok(PrivateKeyDer::Pkcs8(der.into()));
    }

    // Try EC private key format (BEGIN EC PRIVATE KEY)
    if pem.contains("BEGIN EC PRIVATE KEY") {
        return Ok(PrivateKeyDer::Sec1(der.into()));
    }

    // Default to PKCS#8
    Ok(PrivateKeyDer::Pkcs8(der.into()))
}

/// Converts PEM to DER bytes.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let mut in_block = false;
    let mut base64_data = String::new();

    for line in pem.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") {
            in_block = true;
            continue;
        }
        if line.starts_with("-----END") {
            break;
        }
        if in_block {
            base64_data.push_str(line);
        }
    }

    if base64_data.is_empty() {
        return Err(Error::Certificate("empty PEM data".to_string()));
    }

    base64_decode(&base64_data)
}

/// Simple base64 decoder.
fn base64_decode(input: &str) -> Result<Vec<u8>> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits_collected = 0;

    for c in input.chars() {
        if c == '=' {
            break;
        }
        if c.is_whitespace() {
            continue;
        }

        let value = ALPHABET
            .iter()
            .position(|&x| x == c as u8)
            .ok_or_else(|| Error::Certificate(format!("invalid base64 character: {c}")))?;

        buffer = (buffer << 6) | (value as u32);
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            output.push((buffer >> bits_collected) as u8);
            buffer &= (1 << bits_collected) - 1;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaClient;
    use crate::{CsrOptions, Identity, SelfSignedCa};
    use std::time::Duration;

    fn create_test_cert() -> (WorkloadCertificate, TrustBundle) {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "test-service");
        let cert_sign = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let cert = rt
            .block_on(async {
                ca.sign_csr(
                    cert_sign.csr(),
                    cert_sign.private_key(),
                    &identity,
                    Duration::from_secs(3600),
                )
                .await
            })
            .unwrap();

        let bundle = ca.trust_bundle().clone();
        (cert, bundle)
    }

    #[test]
    fn test_server_config_build() {
        let (cert, bundle) = create_test_cert();
        let config = TlsServerConfig::new(cert, bundle).build();
        assert!(config.is_ok());
    }

    #[test]
    fn test_client_config_build() {
        let (cert, bundle) = create_test_cert();
        let config = TlsClientConfig::new(cert, bundle).build();
        assert!(config.is_ok());
    }

    #[test]
    fn test_server_name_from_trust_domain() {
        let name = server_name_from_trust_domain("nucleus.local");
        assert!(name.is_ok());
    }

    #[test]
    fn test_parse_cert_chain() {
        let (cert, _) = create_test_cert();
        let chain = parse_cert_chain(&cert.chain_pem());
        assert!(chain.is_ok());
        assert!(!chain.unwrap().is_empty());
    }

    #[test]
    fn test_parse_private_key() {
        let (cert, _) = create_test_cert();
        let key = parse_private_key(cert.private_key_pem());
        assert!(key.is_ok());
    }
}
