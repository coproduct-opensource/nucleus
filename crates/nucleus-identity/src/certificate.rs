//! X.509 certificate handling for workload identities.
//!
//! This module provides types and utilities for working with X.509 certificates
//! that contain SPIFFE identities in their Subject Alternative Name (SAN) extensions.

use crate::identity::Identity;
use crate::{Error, Result};
use chrono::{DateTime, Utc};
use std::sync::Arc;

/// A workload certificate with its associated identity and metadata.
#[derive(Debug, Clone)]
pub struct WorkloadCertificate {
    /// The certificate chain (leaf first, then intermediates, root last).
    chain: Vec<Certificate>,
    /// The private key corresponding to the leaf certificate.
    private_key: PrivateKey,
    /// When this certificate expires.
    expiry: DateTime<Utc>,
    /// The SPIFFE identity from the certificate's SAN.
    identity: Identity,
}

impl WorkloadCertificate {
    /// Creates a new workload certificate.
    pub fn new(
        chain: Vec<Certificate>,
        private_key: PrivateKey,
        expiry: DateTime<Utc>,
        identity: Identity,
    ) -> Self {
        Self {
            chain,
            private_key,
            expiry,
            identity,
        }
    }

    /// Parses a workload certificate from PEM-encoded certificate chain and private key.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self> {
        let chain = parse_cert_chain_pem(cert_pem)?;
        if chain.is_empty() {
            return Err(Error::Certificate("empty certificate chain".to_string()));
        }

        let private_key = PrivateKey::from_pem(key_pem)?;

        // Parse the leaf certificate to extract identity and expiry
        let leaf = &chain[0];
        let identity = leaf.extract_spiffe_identity()?;
        let expiry = leaf.not_after()?;

        Ok(Self {
            chain,
            private_key,
            expiry,
            identity,
        })
    }

    /// Returns the certificate chain.
    pub fn chain(&self) -> &[Certificate] {
        &self.chain
    }

    /// Returns the leaf certificate.
    pub fn leaf(&self) -> &Certificate {
        &self.chain[0]
    }

    /// Returns the private key.
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Returns the expiry time.
    pub fn expiry(&self) -> DateTime<Utc> {
        self.expiry
    }

    /// Returns the SPIFFE identity.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Checks if this certificate is expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expiry
    }

    /// Checks if this certificate will expire within the given duration.
    pub fn expires_within(&self, duration: chrono::Duration) -> bool {
        Utc::now() + duration >= self.expiry
    }

    /// Returns the certificate chain as PEM.
    pub fn chain_pem(&self) -> String {
        self.chain
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("")
    }

    /// Returns the private key as PEM.
    pub fn private_key_pem(&self) -> &str {
        self.private_key.as_pem()
    }

    /// Converts the certificate to rustls types for TLS configuration.
    pub fn to_rustls_certified_key(&self) -> Result<rustls::sign::CertifiedKey> {
        let certs: Vec<rustls::pki_types::CertificateDer<'static>> = self
            .chain
            .iter()
            .map(|c| rustls::pki_types::CertificateDer::from(c.der().to_vec()))
            .collect();

        let key_der = self.private_key.to_der()?;
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
            .map_err(|e| Error::Certificate(format!("invalid private key: {e}")))?;

        let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&private_key)
            .map_err(|e| Error::Certificate(format!("failed to create signing key: {e}")))?;

        Ok(rustls::sign::CertifiedKey::new(certs, signing_key))
    }
}

/// An X.509 certificate.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// DER-encoded certificate data.
    der: Vec<u8>,
    /// PEM representation (cached).
    pem: String,
}

impl Certificate {
    /// Creates a certificate from DER-encoded bytes.
    pub fn from_der(der: Vec<u8>) -> Self {
        let pem = der_to_pem(&der, "CERTIFICATE");
        Self { der, pem }
    }

    /// Creates a certificate from PEM-encoded data.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let der = pem_to_der(pem, "CERTIFICATE")?;
        Ok(Self {
            der,
            pem: pem.to_string(),
        })
    }

    /// Returns the DER-encoded certificate.
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// Returns the PEM-encoded certificate.
    pub fn to_pem(&self) -> &str {
        &self.pem
    }

    /// Extracts the SPIFFE identity from the certificate's SAN extension.
    pub fn extract_spiffe_identity(&self) -> Result<Identity> {
        let (_, cert) = x509_parser::parse_x509_certificate(&self.der)
            .map_err(|e| Error::Certificate(format!("failed to parse certificate: {e}")))?;

        // Look for Subject Alternative Name extension
        for ext in cert.extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::URI(uri) = name {
                        if uri.starts_with("spiffe://") {
                            return Identity::from_spiffe_uri(uri);
                        }
                    }
                }
            }
        }

        Err(Error::Certificate(
            "no SPIFFE URI found in certificate SAN".to_string(),
        ))
    }

    /// Returns the certificate's not-after (expiry) time.
    pub fn not_after(&self) -> Result<DateTime<Utc>> {
        let (_, cert) = x509_parser::parse_x509_certificate(&self.der)
            .map_err(|e| Error::Certificate(format!("failed to parse certificate: {e}")))?;

        let not_after = cert.validity().not_after;
        let timestamp = not_after.timestamp();

        DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| Error::Certificate("invalid not_after timestamp".to_string()))
    }

    /// Returns the certificate's not-before time.
    pub fn not_before(&self) -> Result<DateTime<Utc>> {
        let (_, cert) = x509_parser::parse_x509_certificate(&self.der)
            .map_err(|e| Error::Certificate(format!("failed to parse certificate: {e}")))?;

        let not_before = cert.validity().not_before;
        let timestamp = not_before.timestamp();

        DateTime::from_timestamp(timestamp, 0)
            .ok_or_else(|| Error::Certificate("invalid not_before timestamp".to_string()))
    }

    /// Returns the certificate's subject as a string.
    pub fn subject(&self) -> Result<String> {
        let (_, cert) = x509_parser::parse_x509_certificate(&self.der)
            .map_err(|e| Error::Certificate(format!("failed to parse certificate: {e}")))?;

        Ok(cert.subject().to_string())
    }

    /// Returns the certificate's issuer as a string.
    pub fn issuer(&self) -> Result<String> {
        let (_, cert) = x509_parser::parse_x509_certificate(&self.der)
            .map_err(|e| Error::Certificate(format!("failed to parse certificate: {e}")))?;

        Ok(cert.issuer().to_string())
    }

    /// Checks if this certificate is a CA certificate.
    pub fn is_ca(&self) -> Result<bool> {
        let (_, cert) = x509_parser::parse_x509_certificate(&self.der)
            .map_err(|e| Error::Certificate(format!("failed to parse certificate: {e}")))?;

        Ok(cert.is_ca())
    }
}

/// A private key.
#[derive(Clone)]
pub struct PrivateKey {
    /// PEM-encoded private key.
    pem: String,
}

impl PrivateKey {
    /// Creates a private key from PEM-encoded data.
    pub fn from_pem(pem: &str) -> Result<Self> {
        // Validate that it's a valid PEM private key
        if !pem.contains("PRIVATE KEY") {
            return Err(Error::Certificate("not a private key PEM".to_string()));
        }
        Ok(Self {
            pem: pem.to_string(),
        })
    }

    /// Returns the PEM-encoded private key.
    pub fn as_pem(&self) -> &str {
        &self.pem
    }

    /// Converts to DER-encoded bytes.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        pem_to_der(&self.pem, "PRIVATE KEY")
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("pem", &"[REDACTED]")
            .finish()
    }
}

/// A trust bundle containing root CA certificates.
#[derive(Debug, Clone)]
pub struct TrustBundle {
    /// Root CA certificates.
    roots: Vec<Certificate>,
}

impl TrustBundle {
    /// Creates a new trust bundle from root certificates.
    pub fn new(roots: Vec<Certificate>) -> Self {
        Self { roots }
    }

    /// Creates a trust bundle from PEM-encoded certificates.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let roots = parse_cert_chain_pem(pem)?;
        Ok(Self { roots })
    }

    /// Returns the root certificates.
    pub fn roots(&self) -> &[Certificate] {
        &self.roots
    }

    /// Converts to a rustls RootCertStore.
    pub fn to_rustls_root_store(&self) -> Result<Arc<rustls::RootCertStore>> {
        let mut store = rustls::RootCertStore::empty();
        for cert in &self.roots {
            let der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
            store
                .add(der)
                .map_err(|e| Error::Certificate(format!("failed to add root cert: {e}")))?;
        }
        Ok(Arc::new(store))
    }
}

/// Parses a PEM-encoded certificate chain.
fn parse_cert_chain_pem(pem: &str) -> Result<Vec<Certificate>> {
    let mut certs = Vec::new();
    let mut current_pem = String::new();
    let mut in_cert = false;

    for line in pem.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            current_pem.clear();
        }

        if in_cert {
            current_pem.push_str(line);
            current_pem.push('\n');
        }

        if line.contains("END CERTIFICATE") {
            in_cert = false;
            certs.push(Certificate::from_pem(&current_pem)?);
        }
    }

    Ok(certs)
}

/// Converts DER bytes to PEM format.
fn der_to_pem(der: &[u8], label: &str) -> String {
    let p = pem::Pem::new(label, der);
    pem::encode(&p)
}

/// Converts PEM to DER bytes.
fn pem_to_der(pem_str: &str, _expected_label: &str) -> Result<Vec<u8>> {
    let parsed =
        pem::parse(pem_str).map_err(|e| Error::Certificate(format!("failed to parse PEM: {e}")))?;
    Ok(parsed.into_contents())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_to_pem_roundtrip() {
        let original = vec![0x30, 0x82, 0x01, 0x22]; // Sample DER data
        let pem = der_to_pem(&original, "CERTIFICATE");
        let decoded = pem_to_der(&pem, "CERTIFICATE").unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_private_key_debug_redacted() {
        let key = PrivateKey {
            pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
        };
        let debug = format!("{:?}", key);
        assert!(debug.contains("REDACTED"));
        assert!(!debug.contains("test"));
    }

    #[test]
    fn test_trust_bundle_new() {
        let cert = Certificate::from_der(vec![0x30, 0x00]); // Minimal DER
        let bundle = TrustBundle::new(vec![cert]);
        assert_eq!(bundle.roots().len(), 1);
    }
}
