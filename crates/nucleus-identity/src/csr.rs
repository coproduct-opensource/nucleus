//! Certificate Signing Request (CSR) generation.
//!
//! This module provides functionality for generating X.509 Certificate Signing
//! Requests (CSRs) with SPIFFE URI Subject Alternative Names (SANs) using
//! P-256 ECDSA keys.
//!
//! # Example
//!
//! ```
//! use nucleus_identity::CsrOptions;
//!
//! let options = CsrOptions::new("spiffe://nucleus.local/ns/default/sa/my-service");
//! let cert_sign = options.generate().unwrap();
//!
//! assert!(cert_sign.csr().starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
//! assert!(cert_sign.private_key().starts_with("-----BEGIN PRIVATE KEY-----"));
//! ```

use crate::{Error, Result};
use rcgen::{KeyPair, SanType};

/// Options for generating a Certificate Signing Request.
#[derive(Debug, Clone)]
pub struct CsrOptions {
    /// The SPIFFE URI to include as a Subject Alternative Name (SAN).
    san: String,
    /// Optional common name for the certificate subject.
    common_name: Option<String>,
}

impl CsrOptions {
    /// Creates new CSR options with the given SPIFFE URI as SAN.
    pub fn new(san: impl Into<String>) -> Self {
        Self {
            san: san.into(),
            common_name: None,
        }
    }

    /// Sets an optional common name for the certificate subject.
    pub fn with_common_name(mut self, cn: impl Into<String>) -> Self {
        self.common_name = Some(cn.into());
        self
    }

    /// Generates a CSR and private key pair using P-256 ECDSA.
    ///
    /// # Returns
    ///
    /// A `CertSign` struct containing the PEM-encoded CSR and private key.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or CSR creation fails.
    pub fn generate(&self) -> Result<CertSign> {
        // Generate P-256 ECDSA key pair
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::CsrGeneration(format!("key generation failed: {e}")))?;

        // Build certificate parameters for CSR
        let mut params = rcgen::CertificateParams::new(vec![])
            .map_err(|e| Error::CsrGeneration(format!("failed to create params: {e}")))?;

        // Convert SAN to Ia5String and set as URI type
        let san_ia5 = rcgen::string::Ia5String::try_from(self.san.clone())
            .map_err(|e| Error::CsrGeneration(format!("invalid SAN URI: {e}")))?;
        params.subject_alt_names = vec![SanType::URI(san_ia5)];

        // Set distinguished name if common name is provided
        if let Some(ref cn) = self.common_name {
            let mut dn = rcgen::DistinguishedName::new();
            dn.push(rcgen::DnType::CommonName, cn.clone());
            params.distinguished_name = dn;
        }

        // Generate the CSR
        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| Error::CsrGeneration(format!("CSR serialization failed: {e}")))?;

        let csr_pem = csr
            .pem()
            .map_err(|e| Error::CsrGeneration(format!("CSR PEM encoding failed: {e}")))?;

        Ok(CertSign {
            csr: csr_pem,
            private_key: key_pair.serialize_pem(),
        })
    }
}

/// A Certificate Signing Request and its corresponding private key.
#[derive(Debug, Clone)]
pub struct CertSign {
    /// PEM-encoded Certificate Signing Request.
    csr: String,
    /// PEM-encoded private key (PKCS#8 format).
    private_key: String,
}

impl CertSign {
    /// Creates a new CertSign from raw PEM strings.
    pub fn new(csr: String, private_key: String) -> Self {
        Self { csr, private_key }
    }

    /// Returns the PEM-encoded CSR.
    pub fn csr(&self) -> &str {
        &self.csr
    }

    /// Returns the PEM-encoded private key.
    pub fn private_key(&self) -> &str {
        &self.private_key
    }

    /// Consumes self and returns the CSR and private key as a tuple.
    pub fn into_parts(self) -> (String, String) {
        (self.csr, self.private_key)
    }

    /// Returns the DER-encoded CSR bytes.
    pub fn csr_der(&self) -> Result<Vec<u8>> {
        pem_to_der(&self.csr)
    }

    /// Returns the DER-encoded private key bytes.
    pub fn private_key_der(&self) -> Result<Vec<u8>> {
        pem_to_der(&self.private_key)
    }
}

/// Converts PEM to DER bytes.
fn pem_to_der(pem_str: &str) -> Result<Vec<u8>> {
    let parsed = pem::parse(pem_str)
        .map_err(|e| Error::CsrGeneration(format!("failed to parse PEM: {e}")))?;
    Ok(parsed.into_contents())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_csr() {
        let options = CsrOptions::new("spiffe://nucleus.local/ns/default/sa/my-service");
        let cert_sign = options.generate().unwrap();

        assert!(cert_sign.csr().contains("BEGIN CERTIFICATE REQUEST"));
        assert!(cert_sign.csr().contains("END CERTIFICATE REQUEST"));
        assert!(cert_sign.private_key().contains("BEGIN PRIVATE KEY"));
        assert!(cert_sign.private_key().contains("END PRIVATE KEY"));
    }

    #[test]
    fn test_generate_csr_with_common_name() {
        let options = CsrOptions::new("spiffe://nucleus.local/ns/default/sa/my-service")
            .with_common_name("my-service.default.svc.cluster.local");
        let cert_sign = options.generate().unwrap();

        assert!(cert_sign.csr().contains("BEGIN CERTIFICATE REQUEST"));
    }

    #[test]
    fn test_csr_der() {
        let options = CsrOptions::new("spiffe://nucleus.local/ns/default/sa/my-service");
        let cert_sign = options.generate().unwrap();

        let der = cert_sign.csr_der().unwrap();
        assert!(!der.is_empty());
        // DER-encoded CSRs start with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_private_key_der() {
        let options = CsrOptions::new("spiffe://nucleus.local/ns/default/sa/my-service");
        let cert_sign = options.generate().unwrap();

        let der = cert_sign.private_key_der().unwrap();
        assert!(!der.is_empty());
        // DER-encoded PKCS#8 keys start with SEQUENCE tag (0x30)
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn test_into_parts() {
        let options = CsrOptions::new("spiffe://nucleus.local/ns/default/sa/my-service");
        let cert_sign = options.generate().unwrap();

        let (csr, key) = cert_sign.into_parts();
        assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(key.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn test_multiple_generations_unique() {
        let options = CsrOptions::new("spiffe://nucleus.local/ns/default/sa/my-service");
        let cert_sign1 = options.generate().unwrap();
        let cert_sign2 = options.generate().unwrap();

        // Each generation should produce a unique key pair
        assert_ne!(cert_sign1.private_key(), cert_sign2.private_key());
    }
}
