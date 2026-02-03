//! SPIFFE-aware TLS certificate verification.
//!
//! This module provides TLS certificate verifiers that validate SPIFFE identities
//! in X.509 certificates for mTLS authentication.
//!
//! # Components
//!
//! - [`TrustDomainVerifier`] - Verifies inbound client certificates belong to the trust domain
//! - [`IdentityVerifier`] - Verifies outbound server certificates match expected identities
//!
//! # Best Practices
//!
//! These verifiers follow SPIFFE standards:
//! - Short-lived certificates with automatic rotation
//! - Trust bundles for CA verification
//! - SPIFFE ID extraction from SAN URI extension
//!
//! Reference: <https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/>

use crate::certificate::{Certificate, TrustBundle};
use crate::identity::Identity;
use crate::{Error, Result};
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use std::sync::Arc;
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

/// Verifies that client certificates have valid SPIFFE identities in the trust domain.
///
/// This verifier is used for inbound mTLS connections to validate that the
/// connecting client has a valid certificate issued by a trusted CA with
/// a SPIFFE identity in the expected trust domain.
#[derive(Debug)]
pub struct TrustDomainVerifier {
    /// The trust domain to verify against.
    trust_domain: String,
    /// Root certificate store for chain validation.
    root_store: Arc<RootCertStore>,
    /// Crypto provider for signature verification.
    crypto_provider: Arc<CryptoProvider>,
}

impl TrustDomainVerifier {
    /// Creates a new trust domain verifier.
    pub fn new(trust_domain: impl Into<String>, trust_bundle: &TrustBundle) -> Result<Self> {
        let root_store = trust_bundle.to_rustls_root_store()?;
        Ok(Self {
            trust_domain: trust_domain.into(),
            root_store,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }

    /// Creates a verifier from a root certificate store.
    pub fn from_root_store(
        trust_domain: impl Into<String>,
        root_store: Arc<RootCertStore>,
    ) -> Self {
        Self {
            trust_domain: trust_domain.into(),
            root_store,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// Extracts and validates the SPIFFE identity from a certificate.
    fn verify_identity(&self, cert_der: &[u8]) -> Result<Identity> {
        let cert = Certificate::from_der(cert_der.to_vec());
        let identity = cert.extract_spiffe_identity()?;

        if !identity.is_in_trust_domain(&self.trust_domain) {
            return Err(Error::TrustDomainMismatch {
                expected: self.trust_domain.clone(),
                actual: identity.trust_domain().to_string(),
            });
        }

        Ok(identity)
    }
}

impl ClientCertVerifier for TrustDomainVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // RootCertStore::subjects() returns Vec, but the trait requires &[].
        // We leak the Vec to get a static reference - this is acceptable since
        // the verifier is typically long-lived. In practice, this should be
        // cached or the API should return an owned Vec.
        //
        // A proper implementation would store the subjects as a field.
        // For now, return an empty slice since root hints are optional.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, rustls::Error> {
        // First, verify the certificate chain using standard X.509 validation
        let verifier = rustls::server::WebPkiClientVerifier::builder(self.root_store.clone())
            .build()
            .map_err(|e| rustls::Error::General(format!("failed to build verifier: {e}")))?;

        verifier.verify_client_cert(end_entity, intermediates, now)?;

        // Then, verify the SPIFFE identity
        self.verify_identity(end_entity.as_ref()).map_err(|e| {
            rustls::Error::General(format!("SPIFFE identity verification failed: {e}"))
        })?;

        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

/// Verifies that server certificates match expected SPIFFE identities.
///
/// This verifier is used for outbound mTLS connections to validate that the
/// server has a certificate with one of the expected SPIFFE identities.
///
/// For SPIFFE, we verify the certificate chain and extract the SPIFFE ID
/// from the SAN URI extension, rather than verifying against DNS names.
pub struct IdentityVerifier {
    /// The identities we expect to connect to (empty = accept any valid identity).
    expected_identities: Vec<Identity>,
    /// Root certificate store for chain validation (kept for potential future use).
    #[allow(dead_code)]
    root_store: Arc<RootCertStore>,
    /// Trust anchors for webpki verification (owned for 'static lifetime).
    trust_anchors: Vec<TrustAnchor<'static>>,
    /// Crypto provider for signature verification.
    crypto_provider: Arc<CryptoProvider>,
    /// Key usage to verify (server_auth for ServerCertVerifier, client_auth for ClientCertVerifier).
    key_usage: KeyUsage,
}

impl IdentityVerifier {
    /// Creates a new identity verifier for the given expected identities.
    ///
    /// This verifier is used for ServerCertVerifier (verifying server certificates
    /// in outbound connections), so it uses server_auth key usage.
    pub fn new(expected_identities: Vec<Identity>, trust_bundle: &TrustBundle) -> Result<Self> {
        let root_store = trust_bundle.to_rustls_root_store()?;
        let trust_anchors = Self::build_trust_anchors(trust_bundle)?;
        Ok(Self {
            expected_identities,
            root_store,
            trust_anchors,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            key_usage: KeyUsage::server_auth(),
        })
    }

    /// Creates a verifier that accepts any identity from the trust bundle.
    pub fn any_identity(trust_bundle: &TrustBundle) -> Result<Self> {
        let root_store = trust_bundle.to_rustls_root_store()?;
        let trust_anchors = Self::build_trust_anchors(trust_bundle)?;
        Ok(Self {
            expected_identities: vec![],
            root_store,
            trust_anchors,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            key_usage: KeyUsage::server_auth(),
        })
    }

    /// Creates a verifier from a root certificate store.
    ///
    /// Note: This method builds trust anchors from the root store for proper
    /// cryptographic chain validation.
    pub fn from_root_store(
        expected_identities: Vec<Identity>,
        root_store: Arc<RootCertStore>,
    ) -> Self {
        // Clone trust anchors from the root store
        // RootCertStore.roots contains TrustAnchor<'static> values
        let trust_anchors: Vec<TrustAnchor<'static>> = root_store.roots.to_vec();

        Self {
            expected_identities,
            root_store,
            trust_anchors,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            key_usage: KeyUsage::server_auth(),
        }
    }

    /// Creates a verifier for client certificate verification.
    ///
    /// This is used when verifying client certificates in inbound connections,
    /// using client_auth key usage.
    pub fn for_client_auth(
        expected_identities: Vec<Identity>,
        trust_bundle: &TrustBundle,
    ) -> Result<Self> {
        let root_store = trust_bundle.to_rustls_root_store()?;
        let trust_anchors = Self::build_trust_anchors(trust_bundle)?;
        Ok(Self {
            expected_identities,
            root_store,
            trust_anchors,
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            key_usage: KeyUsage::client_auth(),
        })
    }

    /// Builds trust anchors from a trust bundle.
    fn build_trust_anchors(trust_bundle: &TrustBundle) -> Result<Vec<TrustAnchor<'static>>> {
        let mut anchors = Vec::new();
        for cert in trust_bundle.roots() {
            let der = CertificateDer::from(cert.der().to_vec());
            let anchor = anchor_from_trusted_cert(&der)
                .map_err(|e| Error::Certificate(format!("failed to parse trust anchor: {e:?}")))?;
            anchors.push(anchor.to_owned());
        }
        Ok(anchors)
    }

    /// Verifies the server certificate identity.
    fn verify_identity(&self, cert_der: &[u8]) -> Result<Identity> {
        let cert = Certificate::from_der(cert_der.to_vec());
        let identity = cert.extract_spiffe_identity()?;

        // If no specific identities are expected, accept any valid identity
        if self.expected_identities.is_empty() {
            return Ok(identity);
        }

        // Check if the identity matches any expected identity
        if self.expected_identities.contains(&identity) {
            Ok(identity)
        } else {
            Err(Error::VerificationFailed(format!(
                "server identity {} not in expected list: {:?}",
                identity, self.expected_identities
            )))
        }
    }

    /// Verifies the certificate chain cryptographically.
    ///
    /// This performs proper X.509 chain validation using webpki:
    /// 1. Verifies the end-entity certificate signature chains to a trusted root
    /// 2. Validates certificate dates (not_before, not_after)
    /// 3. Checks key usage constraints
    ///
    /// For SPIFFE, we skip DNS name validation (SPIFFE uses URI SANs instead).
    fn verify_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<(), rustls::Error> {
        // Parse the end-entity certificate using webpki
        let ee_cert = EndEntityCert::try_from(end_entity).map_err(|e| {
            tracing::warn!("failed to parse end-entity certificate: {e:?}");
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // Build the intermediate certificate chain
        let intermediate_certs: Vec<CertificateDer<'static>> = intermediates
            .iter()
            .map(|c| CertificateDer::from(c.as_ref().to_vec()))
            .collect();

        // Convert UnixTime to webpki UnixTime
        let time = webpki::types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(
            now.as_secs(),
        ));

        // Verify the certificate chain against our trust anchors
        // Use the configured key usage (server_auth for ServerCertVerifier, client_auth for ClientCertVerifier)
        ee_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &self.trust_anchors,
                &intermediate_certs,
                time,
                self.key_usage,
                None, // No revocation checking for now
                None, // No path verification callback
            )
            .map_err(|e| {
                tracing::warn!("certificate chain verification failed: {e:?}");
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
            })?;

        Ok(())
    }
}

impl std::fmt::Debug for IdentityVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityVerifier")
            .field("expected_identities", &self.expected_identities)
            .field("trust_anchors_count", &self.trust_anchors.len())
            .finish()
    }
}

impl ServerCertVerifier for IdentityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        // Verify the certificate chain
        self.verify_chain(end_entity, intermediates, now)?;

        // Verify the SPIFFE identity
        self.verify_identity(end_entity.as_ref()).map_err(|e| {
            rustls::Error::General(format!("SPIFFE identity verification failed: {e}"))
        })?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto_provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto_provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Extracts the SPIFFE identity from a DER-encoded certificate.
///
/// This is a convenience function for extracting identity from raw certificate bytes.
pub fn extract_identity(cert_der: &[u8]) -> Result<Identity> {
    let cert = Certificate::from_der(cert_der.to_vec());
    cert.extract_spiffe_identity()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaClient;
    use crate::SelfSignedCa;
    use std::time::Duration;

    #[tokio::test]
    async fn test_trust_domain_verifier_creation() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let verifier = TrustDomainVerifier::new("nucleus.local", ca.trust_bundle()).unwrap();
        assert_eq!(verifier.trust_domain, "nucleus.local");
    }

    #[tokio::test]
    async fn test_identity_verifier_creation() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "my-service");
        let verifier = IdentityVerifier::new(vec![identity], ca.trust_bundle()).unwrap();
        assert_eq!(verifier.expected_identities.len(), 1);
    }

    #[tokio::test]
    async fn test_identity_verifier_any() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let verifier = IdentityVerifier::any_identity(ca.trust_bundle()).unwrap();
        assert!(verifier.expected_identities.is_empty());
    }

    #[tokio::test]
    async fn test_identity_extraction() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "my-service");

        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let cert = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let extracted = extract_identity(cert.leaf().der()).unwrap();
        assert_eq!(extracted, identity);
    }

    #[tokio::test]
    async fn test_trust_domain_mismatch() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let verifier = TrustDomainVerifier::new("different.domain", ca.trust_bundle()).unwrap();

        let identity = Identity::new("nucleus.local", "default", "my-service");
        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let cert = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let result = verifier.verify_identity(cert.leaf().der());
        assert!(matches!(result, Err(Error::TrustDomainMismatch { .. })));
    }

    #[tokio::test]
    async fn test_identity_not_in_expected_list() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let expected = Identity::new("nucleus.local", "default", "expected-service");
        let verifier = IdentityVerifier::new(vec![expected], ca.trust_bundle()).unwrap();

        let actual = Identity::new("nucleus.local", "default", "other-service");
        let csr_options = crate::CsrOptions::new(actual.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let cert = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &actual,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let result = verifier.verify_identity(cert.leaf().der());
        assert!(matches!(result, Err(Error::VerificationFailed(_))));
    }

    #[tokio::test]
    async fn test_rejects_certificate_from_untrusted_ca() {
        // Create two independent CAs
        let trusted_ca = SelfSignedCa::new("trusted.local").unwrap();
        let rogue_ca = SelfSignedCa::new("rogue.local").unwrap();

        // Create verifier that only trusts the first CA
        let verifier = IdentityVerifier::any_identity(trusted_ca.trust_bundle()).unwrap();

        // Issue a certificate from the rogue CA
        let identity = Identity::new("rogue.local", "default", "attacker");
        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();
        let rogue_cert = rogue_ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // Build the certificate DER for verification
        let cert_der = CertificateDer::from(rogue_cert.leaf().der().to_vec());
        let intermediates: Vec<CertificateDer<'_>> = rogue_cert.chain()[1..]
            .iter()
            .map(|c| CertificateDer::from(c.der().to_vec()))
            .collect();

        let now = UnixTime::now();

        // This MUST fail - the certificate is not signed by a trusted CA
        let result = verifier.verify_chain(&cert_der, &intermediates, now);
        assert!(
            result.is_err(),
            "should reject certificate from untrusted CA"
        );
    }

    #[tokio::test]
    async fn test_accepts_valid_certificate_chain() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let verifier = IdentityVerifier::any_identity(ca.trust_bundle()).unwrap();

        let identity = Identity::new("nucleus.local", "default", "my-service");
        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();
        let cert = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let cert_der = CertificateDer::from(cert.leaf().der().to_vec());
        let intermediates: Vec<CertificateDer<'_>> = cert.chain()[1..]
            .iter()
            .map(|c| CertificateDer::from(c.der().to_vec()))
            .collect();

        let now = UnixTime::now();

        // Valid certificate from trusted CA should pass
        let result = verifier.verify_chain(&cert_der, &intermediates, now);
        assert!(
            result.is_ok(),
            "should accept certificate from trusted CA: {:?}",
            result
        );
    }
}
