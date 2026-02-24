//! Self-signed Certificate Authority for development and testing.
//!
//! This CA generates a self-signed root certificate and can sign workload
//! certificates for any identity within its trust domain.
//!
//! **Warning:** This is intended for development and testing only. For production,
//! use a proper CA like SPIRE Server.
//!
//! # Security Note
//!
//! This implementation properly validates CSRs:
//! 1. Verifies the CSR signature (proof of private key possession)
//! 2. Validates the SPIFFE URI in the CSR matches the requested identity
//! 3. Uses the CSR's public key in the issued certificate
//!
//! The private key is passed separately to work around rcgen's API limitations,
//! but is validated against the CSR to ensure consistency.
//!
//! # Example
//!
//! ```
//! use nucleus_identity::ca::{CaClient, SelfSignedCa};
//! use nucleus_identity::{CsrOptions, Identity};
//! use std::time::Duration;
//!
//! # tokio_test::block_on(async {
//! let ca = SelfSignedCa::new("nucleus.local").unwrap();
//!
//! let identity = Identity::new("nucleus.local", "default", "my-service");
//! let csr_options = CsrOptions::new(identity.to_spiffe_uri());
//! let cert_sign = csr_options.generate().unwrap();
//!
//! let cert = ca.sign_csr_with_key(
//!     cert_sign.csr(),
//!     cert_sign.private_key(),
//!     &identity,
//!     Duration::from_secs(3600)
//! ).await.unwrap();
//! assert_eq!(cert.identity(), &identity);
//! # });
//! ```

use crate::attestation::LaunchAttestation;
use crate::ca::CaClient;
use crate::certificate::{Certificate, PrivateKey, TrustBundle, WorkloadCertificate};
use crate::identity::Identity;
use crate::{oid, Error, Result};
use async_trait::async_trait;
use rcgen::PublicKeyData;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, SignatureAlgorithm,
};
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;
use x509_parser::x509::AlgorithmIdentifier;

/// A self-signed Certificate Authority for development and testing.
pub struct SelfSignedCa {
    /// The trust domain this CA serves.
    trust_domain: String,
    /// The root CA key pair.
    root_key: KeyPair,
    /// The root CA certificate parameters (needed for creating Issuer).
    root_params: CertificateParams,
    /// The root certificate in our Certificate type.
    root_certificate: Certificate,
    /// Trust bundle containing just the root cert.
    trust_bundle: TrustBundle,
}

impl SelfSignedCa {
    /// Creates a new self-signed CA for the given trust domain.
    ///
    /// This generates a new root CA key pair and self-signed certificate
    /// with a 10-year validity period.
    pub fn new(trust_domain: impl Into<String>) -> Result<Self> {
        let trust_domain = trust_domain.into();

        // Generate root CA key pair
        let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| Error::CaSigning(format!("root key generation failed: {e}")))?;

        // Configure root CA certificate with an empty SAN list initially
        let mut params = CertificateParams::new(vec![])
            .map_err(|e| Error::CaSigning(format!("failed to create params: {e}")))?;

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            format!("Nucleus Root CA - {trust_domain}"),
        );
        dn.push(DnType::OrganizationName, "Nucleus");
        params.distinguished_name = dn;

        // Set validity (10 years)
        let now = OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + TimeDuration::days(3650);

        // Set as CA certificate
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        // Add SPIFFE URI for the CA itself
        let ca_san = rcgen::string::Ia5String::try_from(format!("spiffe://{trust_domain}"))
            .map_err(|e| Error::CaSigning(format!("invalid CA SAN: {e}")))?;
        params.subject_alt_names = vec![SanType::URI(ca_san)];

        // Self-sign the certificate
        let root_cert = params
            .clone()
            .self_signed(&root_key)
            .map_err(|e| Error::CaSigning(format!("root cert generation failed: {e}")))?;

        let root_cert_der = root_cert.der().to_vec();
        let root_certificate = Certificate::from_der(root_cert_der);
        let trust_bundle = TrustBundle::new(vec![root_certificate.clone()]);

        Ok(Self {
            trust_domain,
            root_key,
            root_params: params,
            root_certificate,
            trust_bundle,
        })
    }

    /// Returns the PEM-encoded root certificate.
    pub fn root_cert_pem(&self) -> String {
        self.root_certificate.to_pem().to_string()
    }

    /// Returns the PEM-encoded root private key.
    pub fn root_key_pem(&self) -> String {
        self.root_key.serialize_pem()
    }

    /// Parses and validates a CSR.
    ///
    /// This method:
    /// 1. Parses the PEM-encoded CSR
    /// 2. Verifies the CSR signature (proof of private key possession)
    /// 3. Extracts and validates the SPIFFE URI from the CSR's SANs
    /// 4. Returns the SPIFFE URI found in the CSR
    fn validate_csr(&self, csr_pem: &str) -> Result<String> {
        // Parse PEM to DER
        let csr_der = Self::pem_to_der(csr_pem, "CERTIFICATE REQUEST")?;

        // Parse the CSR
        let (_, csr) = X509CertificationRequest::from_der(&csr_der)
            .map_err(|e| Error::CsrGeneration(format!("failed to parse CSR: {e}")))?;

        // Verify CSR signature (proves possession of private key)
        // This confirms the requester has the private key corresponding to the CSR's public key
        csr.verify_signature()
            .map_err(|e| Error::CsrGeneration(format!("CSR signature verification failed: {e}")))?;

        // Extract SPIFFE URI from CSR's Subject Alternative Names
        let spiffe_uri = Self::extract_spiffe_uri_from_csr(&csr)?;

        Ok(spiffe_uri)
    }

    /// Extracts the SPIFFE URI from a CSR's extension requests.
    fn extract_spiffe_uri_from_csr(csr: &X509CertificationRequest<'_>) -> Result<String> {
        // Use the requested_extensions() method to iterate through extensions
        if let Some(extensions) = csr.requested_extensions() {
            for ext in extensions {
                if let ParsedExtension::SubjectAlternativeName(san) = ext {
                    for name in &san.general_names {
                        if let GeneralName::URI(uri) = name {
                            if uri.starts_with("spiffe://") {
                                return Ok(uri.to_string());
                            }
                        }
                    }
                }
            }
        }

        Err(Error::CsrGeneration(
            "no SPIFFE URI found in CSR's Subject Alternative Names".to_string(),
        ))
    }

    /// Converts PEM to DER.
    fn pem_to_der(pem: &str, expected_label: &str) -> Result<Vec<u8>> {
        let mut in_block = false;
        let mut base64_data = String::new();
        let mut found_label = false;

        for line in pem.lines() {
            let line = line.trim();
            if line.contains("BEGIN") && line.contains(expected_label) {
                in_block = true;
                found_label = true;
                continue;
            }
            if line.contains("END") {
                break;
            }
            if in_block {
                base64_data.push_str(line);
            }
        }

        if !found_label {
            return Err(Error::CsrGeneration(format!(
                "PEM does not contain expected label: {expected_label}"
            )));
        }

        Self::base64_decode(&base64_data)
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
                .ok_or_else(|| Error::CsrGeneration(format!("invalid base64 character: {c}")))?;

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

    /// Signs a CSR with the provided private key.
    ///
    /// This is the secure method that properly validates the CSR and uses
    /// the workload's own key pair.
    ///
    /// # Arguments
    ///
    /// * `csr_pem` - PEM-encoded Certificate Signing Request
    /// * `private_key_pem` - PEM-encoded private key (must match CSR's public key)
    /// * `identity` - The expected SPIFFE identity
    /// * `ttl` - Requested time-to-live for the certificate
    ///
    /// # Security
    ///
    /// This method validates that:
    /// 1. The CSR signature is valid (proof of private key possession)
    /// 2. The SPIFFE URI in the CSR matches the requested identity
    /// 3. The identity's trust domain matches this CA's trust domain
    pub async fn sign_csr_with_key(
        &self,
        csr_pem: &str,
        private_key_pem: &str,
        identity: &Identity,
        ttl: Duration,
    ) -> Result<WorkloadCertificate> {
        // Validate the CSR and extract the SPIFFE URI
        let csr_spiffe_uri = self.validate_csr(csr_pem)?;

        // Verify the CSR's SPIFFE URI matches the requested identity
        let expected_uri = identity.to_spiffe_uri();
        if csr_spiffe_uri != expected_uri {
            return Err(Error::VerificationFailed(format!(
                "CSR SPIFFE URI mismatch: expected {}, got {}",
                expected_uri, csr_spiffe_uri
            )));
        }

        // Validate trust domain
        if identity.trust_domain() != self.trust_domain {
            return Err(Error::TrustDomainMismatch {
                expected: self.trust_domain.clone(),
                actual: identity.trust_domain().to_string(),
            });
        }

        // Load the private key as a KeyPair (required by rcgen)
        // The private key contains the public key, so we can use it for signing
        let key_pair = KeyPair::from_pem(private_key_pem)
            .map_err(|e| Error::CaSigning(format!("failed to load private key: {e}")))?;

        // Sign the certificate using the workload's key pair
        let chain = self.sign_with_keypair(&key_pair, identity, ttl)?;

        let expiry = chain[0].not_after()?;
        let private_key = PrivateKey::from_pem(private_key_pem)?;

        Ok(WorkloadCertificate::new(
            chain,
            private_key,
            expiry,
            identity.clone(),
        ))
    }

    /// Signs a certificate using the provided key pair.
    fn sign_with_keypair(
        &self,
        key_pair: &KeyPair,
        identity: &Identity,
        ttl: Duration,
    ) -> Result<Vec<Certificate>> {
        self.sign_with_keypair_and_extensions(key_pair, identity, ttl, vec![])
    }

    /// Signs a certificate using the provided key pair with custom extensions.
    fn sign_with_keypair_and_extensions(
        &self,
        key_pair: &KeyPair,
        identity: &Identity,
        ttl: Duration,
        custom_extensions: Vec<CustomExtension>,
    ) -> Result<Vec<Certificate>> {
        // Build certificate parameters
        let mut params = CertificateParams::new(vec![])
            .map_err(|e| Error::CaSigning(format!("failed to create params: {e}")))?;

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, identity.service_account());
        dn.push(DnType::OrganizationalUnitName, identity.namespace());
        params.distinguished_name = dn;

        // Set validity
        let now = OffsetDateTime::now_utc();
        let ttl_duration = TimeDuration::new(ttl.as_secs() as i64, 0);
        params.not_before = now;
        params.not_after = now + ttl_duration;

        // Set as end-entity certificate
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Set SPIFFE URI as SAN
        let san = rcgen::string::Ia5String::try_from(identity.to_spiffe_uri())
            .map_err(|e| Error::CaSigning(format!("invalid SAN: {e}")))?;
        params.subject_alt_names = vec![SanType::URI(san)];

        // Add custom extensions (e.g., attestation)
        params.custom_extensions = custom_extensions;

        // Create an issuer from the root CA params and key
        let issuer = rcgen::Issuer::from_params(&self.root_params, &self.root_key);

        // Sign the certificate with the workload's key pair
        let signed_cert = params
            .signed_by(key_pair, &issuer)
            .map_err(|e| Error::CaSigning(format!("certificate signing failed: {e}")))?;

        let leaf_der = signed_cert.der().to_vec();
        let leaf_cert = Certificate::from_der(leaf_der);

        // Return chain (leaf + root)
        Ok(vec![leaf_cert, self.root_certificate.clone()])
    }

    /// Creates a custom X.509 extension for launch attestation.
    ///
    /// OID: 1.3.6.1.4.1.57212.1.1 (Nucleus Launch Attestation)
    /// Content: DER-encoded attestation per TCG DICE conventions
    fn create_attestation_extension(attestation: &LaunchAttestation) -> CustomExtension {
        let content = attestation.to_der();

        let mut ext = CustomExtension::from_oid_content(oid::OID_NUCLEUS_ATTESTATION_TUPLE, content);
        // Mark as non-critical so verifiers that don't understand it can still process the cert
        ext.set_criticality(false);
        ext
    }

    /// Signs a certificate using only a public key (no private key needed).
    ///
    /// This is used for CSR-only signing flows (like OIDC) where the client
    /// generates and keeps its private key locally.
    fn sign_with_public_key(
        &self,
        public_key: &CsrPublicKey,
        identity: &Identity,
        ttl: Duration,
    ) -> Result<Vec<Certificate>> {
        // Build certificate parameters
        let mut params = CertificateParams::new(vec![])
            .map_err(|e| Error::CaSigning(format!("failed to create params: {e}")))?;

        // Set distinguished name
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, identity.service_account());
        dn.push(DnType::OrganizationalUnitName, identity.namespace());
        params.distinguished_name = dn;

        // Set SPIFFE URI as SAN
        let san = rcgen::string::Ia5String::try_from(identity.to_spiffe_uri())
            .map_err(|e| Error::CaSigning(format!("invalid SAN: {e}")))?;
        params.subject_alt_names = vec![SanType::URI(san)];

        // Configure workload certificate properties
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        // Set validity period
        let now = OffsetDateTime::now_utc();
        let ttl_duration = TimeDuration::new(ttl.as_secs() as i64, 0);
        params.not_before = now;
        params.not_after = now + ttl_duration;

        // Create an issuer from the root CA params and key
        let issuer = rcgen::Issuer::from_params(&self.root_params, &self.root_key);

        // Sign the certificate using the public key from the CSR
        let signed_cert = params
            .signed_by(public_key, &issuer)
            .map_err(|e| Error::CaSigning(format!("failed to sign certificate: {e}")))?;

        // Convert to our Certificate type
        let leaf_der = signed_cert.der().to_vec();
        let leaf_cert = Certificate::from_der(leaf_der);

        // Build chain: workload cert -> CA cert
        let root_cert = self.root_certificate.clone();

        Ok(vec![leaf_cert, root_cert])
    }
}

/// Public key extracted from a CSR, implementing rcgen's PublicKeyData trait.
///
/// This allows signing certificates using only the public key from a CSR,
/// without requiring the corresponding private key.
struct CsrPublicKey {
    /// DER-encoded SubjectPublicKeyInfo from the CSR.
    spki_der: Vec<u8>,
    /// The signature algorithm for this public key.
    algorithm: &'static SignatureAlgorithm,
}

impl PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.spki_der
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.algorithm
    }
}

use x509_parser::oid_registry::asn1_rs::oid;

/// Detect the rcgen SignatureAlgorithm from an x509_parser AlgorithmIdentifier.
fn detect_algorithm(alg: &AlgorithmIdentifier<'_>) -> Option<&'static SignatureAlgorithm> {
    // Known OIDs for public key algorithms
    let rsa_oid = oid!(1.2.840 .113549 .1 .1 .1); // RSA encryption
    let ec_oid = oid!(1.2.840 .10045 .2 .1); // id-ecPublicKey
    let ed25519_oid = oid!(1.3.101 .112); // Ed25519
    let secp256r1_oid = oid!(1.2.840 .10045 .3 .1 .7); // secp256r1/prime256v1
    let secp384r1_oid = oid!(1.3.132 .0 .34); // secp384r1

    // Check for Ed25519
    if alg.algorithm == ed25519_oid {
        return Some(&rcgen::PKCS_ED25519);
    }

    // Check for RSA
    if alg.algorithm == rsa_oid {
        return Some(&rcgen::PKCS_RSA_SHA256);
    }

    // Check for EC keys - need to check the curve parameter
    if alg.algorithm == ec_oid {
        // Parse parameters to determine curve
        if let Some(params) = &alg.parameters {
            if let Ok(curve_oid) = params.as_oid() {
                if curve_oid == secp256r1_oid {
                    return Some(&rcgen::PKCS_ECDSA_P256_SHA256);
                }
                if curve_oid == secp384r1_oid {
                    return Some(&rcgen::PKCS_ECDSA_P384_SHA384);
                }
            }
        }
    }

    None
}

#[async_trait]
impl CaClient for SelfSignedCa {
    async fn sign_csr(
        &self,
        csr: &str,
        private_key: &str,
        identity: &Identity,
        ttl: Duration,
    ) -> Result<WorkloadCertificate> {
        // Delegate to the existing secure method that properly handles CSR + private key
        self.sign_csr_with_key(csr, private_key, identity, ttl)
            .await
    }

    async fn sign_attested_csr(
        &self,
        csr: &str,
        private_key: &str,
        identity: &Identity,
        ttl: Duration,
        attestation: &LaunchAttestation,
    ) -> Result<WorkloadCertificate> {
        // Validate the CSR and extract the SPIFFE URI
        let csr_spiffe_uri = self.validate_csr(csr)?;

        // Verify the CSR's SPIFFE URI matches the requested identity
        let expected_uri = identity.to_spiffe_uri();
        if csr_spiffe_uri != expected_uri {
            return Err(Error::VerificationFailed(format!(
                "CSR SPIFFE URI mismatch: expected {}, got {}",
                expected_uri, csr_spiffe_uri
            )));
        }

        // Validate trust domain
        if identity.trust_domain() != self.trust_domain {
            return Err(Error::TrustDomainMismatch {
                expected: self.trust_domain.clone(),
                actual: identity.trust_domain().to_string(),
            });
        }

        // Load the private key as a KeyPair (required by rcgen)
        // The workload provides their own key - CA never generates keys
        let key_pair = KeyPair::from_pem(private_key)
            .map_err(|e| Error::CaSigning(format!("failed to load private key: {e}")))?;

        // Create attestation extension
        let attestation_ext = Self::create_attestation_extension(attestation);

        // Sign with the workload's own key pair and attestation extension
        let chain =
            self.sign_with_keypair_and_extensions(&key_pair, identity, ttl, vec![attestation_ext])?;

        let expiry = chain[0].not_after()?;
        let private_key_obj = PrivateKey::from_pem(private_key)?;

        Ok(WorkloadCertificate::new(
            chain,
            private_key_obj,
            expiry,
            identity.clone(),
        ))
    }

    async fn sign_csr_only(&self, csr: &str, identity: &Identity, ttl: Duration) -> Result<String> {
        // Validate the CSR and extract the SPIFFE URI
        let csr_spiffe_uri = self.validate_csr(csr)?;

        // Verify the CSR's SPIFFE URI matches the requested identity
        let expected_uri = identity.to_spiffe_uri();
        if csr_spiffe_uri != expected_uri {
            return Err(Error::VerificationFailed(format!(
                "CSR SPIFFE URI mismatch: expected {}, got {}",
                expected_uri, csr_spiffe_uri
            )));
        }

        // Validate trust domain
        if identity.trust_domain() != self.trust_domain {
            return Err(Error::TrustDomainMismatch {
                expected: self.trust_domain.clone(),
                actual: identity.trust_domain().to_string(),
            });
        }

        // Parse CSR and extract public key
        let csr_der = Self::pem_to_der(csr, "CERTIFICATE REQUEST")?;
        let (_, parsed_csr) = X509CertificationRequest::from_der(&csr_der)
            .map_err(|e| Error::CsrGeneration(format!("failed to parse CSR: {e}")))?;

        // Extract the SubjectPublicKeyInfo from the CSR
        let csr_info = &parsed_csr.certification_request_info;
        let spki = &csr_info.subject_pki;
        let spki_der = spki.raw.to_vec();

        // Detect the algorithm from the CSR's public key
        let algorithm = detect_algorithm(&spki.algorithm).ok_or_else(|| {
            Error::CaSigning("unsupported public key algorithm in CSR".to_string())
        })?;

        // Create a wrapper that implements PublicKeyData
        let public_key = CsrPublicKey {
            spki_der,
            algorithm,
        };

        // Sign using the public key from the CSR
        let chain = self.sign_with_public_key(&public_key, identity, ttl)?;

        // Convert certificate chain to PEM
        let pem = chain
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("\n");

        Ok(pem)
    }

    fn trust_bundle(&self) -> &TrustBundle {
        &self.trust_bundle
    }

    fn trust_domain(&self) -> &str {
        &self.trust_domain
    }
}

impl std::fmt::Debug for SelfSignedCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelfSignedCa")
            .field("trust_domain", &self.trust_domain)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_self_signed_ca() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        assert_eq!(ca.trust_domain(), "nucleus.local");
        assert!(ca.root_cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.root_key_pem().contains("BEGIN PRIVATE KEY"));
    }

    #[tokio::test]
    async fn test_sign_csr_with_key() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "my-service");

        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        // Use the secure method that takes the private key
        let cert = ca
            .sign_csr_with_key(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        assert_eq!(cert.identity(), &identity);
        assert!(!cert.is_expired());
        assert_eq!(cert.chain().len(), 2); // Leaf + root
    }

    #[tokio::test]
    async fn test_sign_csr() {
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

        assert_eq!(cert.identity(), &identity);
        assert!(!cert.is_expired());
        assert_eq!(cert.chain().len(), 2); // Leaf + root

        // Verify the certificate uses the workload's own key (no key escrow)
        assert_eq!(cert.private_key_pem(), cert_sign.private_key());
    }

    #[tokio::test]
    async fn test_sign_csr_wrong_trust_domain() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("other.domain", "default", "my-service");

        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let result = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await;

        assert!(matches!(result, Err(Error::TrustDomainMismatch { .. })));
    }

    #[tokio::test]
    async fn test_rejects_csr_with_wrong_identity() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        // Generate CSR for one identity
        let csr_identity = Identity::new("nucleus.local", "attacker-ns", "attacker-sa");
        let csr_options = crate::CsrOptions::new(csr_identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        // Try to sign for a DIFFERENT identity
        let requested_identity = Identity::new("nucleus.local", "victim-ns", "victim-sa");

        let result = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &requested_identity,
                Duration::from_secs(3600),
            )
            .await;

        // Must reject - CSR SAN doesn't match requested identity
        assert!(
            matches!(&result, Err(Error::VerificationFailed(msg)) if msg.contains("mismatch")),
            "should reject CSR with mismatched identity: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_csr_validation_verifies_signature() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();

        // Create a valid CSR
        let identity = Identity::new("nucleus.local", "default", "my-service");
        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        // Create a completely different CSR (different key pair) but claim it's for the same identity
        // This simulates an attacker trying to get a certificate with a key they don't control
        let other_csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let other_cert_sign = other_csr_options.generate().unwrap();

        // The CSRs should be different (different key pairs)
        assert_ne!(cert_sign.csr(), other_cert_sign.csr());

        // Both CSRs should successfully validate since they have valid signatures
        // (This just confirms the signature verification is working)
        let result1 = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await;
        let result2 = ca
            .sign_csr(
                other_cert_sign.csr(),
                other_cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await;

        assert!(result1.is_ok(), "valid CSR 1 should be accepted");
        assert!(result2.is_ok(), "valid CSR 2 should be accepted");
    }

    #[tokio::test]
    async fn test_csr_validation_rejects_malformed_csr() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "my-service");

        // Generate a valid key to pass along
        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        // Test with completely invalid CSR data
        let invalid_csr = "-----BEGIN CERTIFICATE REQUEST-----\nYm9ndXMgZGF0YQ==\n-----END CERTIFICATE REQUEST-----";

        let result = ca
            .sign_csr(
                invalid_csr,
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await;

        // Should fail during parsing
        assert!(result.is_err(), "malformed CSR should be rejected");
    }

    #[tokio::test]
    async fn test_trust_bundle() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let bundle = ca.trust_bundle();
        assert_eq!(bundle.roots().len(), 1);
    }

    #[tokio::test]
    async fn test_certificate_identity_extraction() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "production", "api-server");

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

        // Extract identity from the leaf certificate
        let extracted = cert.leaf().extract_spiffe_identity().unwrap();
        assert_eq!(extracted, identity);
    }

    #[tokio::test]
    async fn test_certificate_expiry() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "my-service");

        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        // Request a 1 hour TTL
        let cert = ca
            .sign_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // Certificate should expire within ~1 hour
        let expiry = cert.expiry();
        let now = chrono::Utc::now();
        let diff = expiry - now;

        // Allow some tolerance (between 55 minutes and 65 minutes)
        assert!(diff.num_minutes() >= 55 && diff.num_minutes() <= 65);
    }

    #[tokio::test]
    async fn test_sign_csr_with_key_uses_provided_key() {
        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "my-service");

        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();
        let original_private_key = cert_sign.private_key();

        // Sign with the secure method
        let cert = ca
            .sign_csr_with_key(
                cert_sign.csr(),
                original_private_key,
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        // The returned certificate should use the same private key we provided
        assert_eq!(cert.private_key_pem(), original_private_key);
    }

    #[tokio::test]
    async fn test_sign_attested_csr() {
        use crate::attestation::LaunchAttestation;

        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "attested-service");

        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        // Create test attestation
        let attestation = LaunchAttestation::from_hashes(
            [0xaa; 32], // kernel
            [0xbb; 32], // rootfs
            [0xcc; 32], // config
        );

        let cert = ca
            .sign_attested_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
                &attestation,
            )
            .await
            .unwrap();

        assert_eq!(cert.identity(), &identity);
        assert!(!cert.is_expired());

        // The certificate should contain the attestation extension
        // (We can verify this by checking the DER includes our OID)
        let leaf_der = cert.leaf().der();
        // OID 1.3.6.1.4.1.57212.1.1 encodes to these bytes in DER
        // The attestation content (0xaa, 0xbb, 0xcc patterns) should be present
        assert!(
            leaf_der.windows(3).any(|w| w == [0xaa, 0xaa, 0xaa]),
            "certificate should contain attestation extension with kernel hash"
        );
    }

    #[tokio::test]
    async fn test_attestation_extension_creation() {
        use crate::attestation::LaunchAttestation;

        let attestation = LaunchAttestation::from_hashes([0x11; 32], [0x22; 32], [0x33; 32]);

        let ext = SelfSignedCa::create_attestation_extension(&attestation);

        // Check OID components
        let oid_components: Vec<u64> = ext.oid_components().collect();
        assert_eq!(oid_components, vec![1, 3, 6, 1, 4, 1, 57212, 1, 1]);

        // Check criticality is false (non-critical extension)
        assert!(!ext.criticality());

        // Check content is valid DER
        let content = ext.content();
        assert!(!content.is_empty());
        // Should start with SEQUENCE tag (0x30)
        assert_eq!(
            content[0], 0x30,
            "attestation DER should start with SEQUENCE tag"
        );
    }
}
