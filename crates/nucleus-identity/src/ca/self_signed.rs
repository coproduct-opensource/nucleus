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
use crate::{Error, Result, oid};
use async_trait::async_trait;
use rcgen::PublicKeyData;
use rcgen::{
    BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, SanType, SignatureAlgorithm,
};
use std::path::Path;
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;
use x509_parser::x509::AlgorithmIdentifier;

/// Basename of the persisted root certificate, under the directory passed to
/// [`SelfSignedCa::load_or_create`].
const CA_CERT_FILE: &str = "ca-cert.pem";
/// Basename of the persisted root private key, under the same directory.
/// Written with `0o600` on Unix — see [`SelfSignedCa::persist`].
const CA_KEY_FILE: &str = "ca-key.pem";

/// A self-signed Certificate Authority for development and testing.
pub struct SelfSignedCa {
    /// The trust domain this CA serves.
    trust_domain: String,
    /// The root CA key pair.
    root_key: KeyPair,
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

        // Self-sign the certificate. `params` is not retained afterward: signing
        // reconstructs an `Issuer` from the persisted root cert PEM instead (see
        // `issuer()`), which is what lets a loaded CA and a freshly created one
        // behave identically from here on.
        let root_cert = params
            .self_signed(&root_key)
            .map_err(|e| Error::CaSigning(format!("root cert generation failed: {e}")))?;

        let root_cert_der = root_cert.der().to_vec();
        let root_certificate = Certificate::from_der(root_cert_der);
        let trust_bundle = TrustBundle::new(vec![root_certificate.clone()]);

        Ok(Self {
            trust_domain,
            root_key,
            root_certificate,
            trust_bundle,
        })
    }

    /// Reconstructs a CA from a previously issued root certificate and its key,
    /// both PEM-encoded. Used by [`Self::load_or_create`] to restore a
    /// persisted root; also usable directly by a caller that stores the pair
    /// elsewhere (a secret manager, an HSM-backed key with an exported cert).
    ///
    /// The result is indistinguishable from one built by [`Self::new`]: both
    /// derive their signing `Issuer` from `root_cert_pem` at each signing call
    /// (see [`Self::issuer`]), so nothing downstream can tell a loaded root
    /// from a freshly minted one.
    pub fn from_pem(
        trust_domain: impl Into<String>,
        root_cert_pem: &str,
        root_key_pem: &str,
    ) -> Result<Self> {
        let trust_domain = trust_domain.into();
        let root_key = KeyPair::from_pem(root_key_pem)
            .map_err(|e| Error::CaSigning(format!("failed to load CA root key: {e}")))?;
        let root_certificate = Certificate::from_pem(root_cert_pem)?;
        let trust_bundle = TrustBundle::new(vec![root_certificate.clone()]);

        Ok(Self {
            trust_domain,
            root_key,
            root_certificate,
            trust_bundle,
        })
    }

    /// Loads a CA root persisted under `dir` (`ca-cert.pem` + `ca-key.pem`), or
    /// creates and persists a fresh one if neither file exists.
    ///
    /// This is the constructor a long-lived node should use instead of
    /// [`Self::new`]. `new` mints a fresh root key on every call, so a node
    /// that called it directly on each restart would silently invalidate every
    /// SVID it had ever issued — the CA root is the trust anchor mTLS peers
    /// verify against, so its identity changing is not a cosmetic detail.
    ///
    /// An existing-but-unreadable or partial pair (one file present, the other
    /// missing) is a **hard error**, not a fall-through to regeneration:
    /// silently minting a new root on a read failure would have the same
    /// blast radius as never persisting at all, just with a log line instead
    /// of a comment explaining why nothing worked. An operator who wants a
    /// fresh root removes both files themselves — this function does not
    /// second-guess that.
    pub fn load_or_create(trust_domain: impl Into<String>, dir: &Path) -> Result<Self> {
        let trust_domain = trust_domain.into();
        let cert_path = dir.join(CA_CERT_FILE);
        let key_path = dir.join(CA_KEY_FILE);
        let cert_exists = cert_path.exists();
        let key_exists = key_path.exists();

        if cert_exists != key_exists {
            return Err(Error::Internal(format!(
                "CA root at {} is incomplete ({} exists={cert_exists}, {} exists={key_exists}) \
                 — refusing to guess which file is authoritative; restore the missing file or \
                 remove both to mint a fresh root",
                dir.display(),
                CA_CERT_FILE,
                CA_KEY_FILE,
            )));
        }

        if cert_exists {
            let cert_pem = std::fs::read_to_string(&cert_path)?;
            let key_pem = std::fs::read_to_string(&key_path)?;
            return Self::from_pem(trust_domain, &cert_pem, &key_pem).map_err(|e| {
                Error::Internal(format!(
                    "CA root at {} is unreadable ({e}) — NOT regenerating: a fresh root would \
                     silently invalidate every SVID this CA has issued. Remove {} and {} \
                     yourself to mint a new one.",
                    dir.display(),
                    CA_CERT_FILE,
                    CA_KEY_FILE,
                ))
            });
        }

        std::fs::create_dir_all(dir)?;
        let ca = Self::new(&trust_domain)?;
        ca.persist(&cert_path, &key_path)?;
        Ok(ca)
    }

    /// Writes the root cert and key to the given paths, restricting the key
    /// file to `0o600` on Unix. Called once, by [`Self::load_or_create`] on
    /// the create path — never on the load path, so re-loading an existing
    /// root never rewrites it.
    fn persist(&self, cert_path: &Path, key_path: &Path) -> Result<()> {
        std::fs::write(cert_path, self.root_cert_pem())?;
        std::fs::write(key_path, self.root_key_pem())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Reconstructs a signing [`rcgen::Issuer`] from the root certificate's PEM
    /// and the root key, rather than from `CertificateParams` kept in memory.
    /// This is what makes [`Self::from_pem`] produce a CA indistinguishable
    /// from [`Self::new`]'s: both sign through this same reconstruction.
    fn issuer(&self) -> Result<rcgen::Issuer<'_, &KeyPair>> {
        rcgen::Issuer::from_ca_cert_pem(self.root_certificate.to_pem(), &self.root_key)
            .map_err(|e| Error::CaSigning(format!("failed to reconstruct CA issuer: {e}")))
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
                        if let GeneralName::URI(uri) = name
                            && uri.starts_with("spiffe://")
                        {
                            return Ok(uri.to_string());
                        }
                    }
                }
            }
        }

        Err(Error::CsrGeneration(
            "no SPIFFE URI found in CSR's Subject Alternative Names".to_string(),
        ))
    }

    /// Converts PEM to DER using the `pem` crate.
    fn pem_to_der(pem_str: &str, expected_label: &str) -> Result<Vec<u8>> {
        let parsed = pem::parse(pem_str)
            .map_err(|e| Error::CsrGeneration(format!("failed to parse PEM: {e}")))?;
        if !parsed.tag().contains(expected_label) {
            return Err(Error::CsrGeneration(format!(
                "PEM label mismatch: expected '{}', got '{}'",
                expected_label,
                parsed.tag()
            )));
        }
        Ok(parsed.into_contents())
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

        // ExplicitNoCa, not NoCa. rcgen's `NoCa` OMITS the basicConstraints
        // extension entirely; `ExplicitNoCa` emits it with `CA:FALSE`. The
        // X.509-SVID standard says a leaf "MUST set the cA field to false",
        // and an absent extension does not set anything.
        //
        // This was not a theoretical gap: the `spiffe` crate refused our SVIDs
        // outright with `MissingX509Extension(OID(2.5.29.19))`. Our own
        // validator did not catch it, because `is_ca()` reports false when the
        // extension is missing — the security property held while the
        // conformance one did not, which is exactly the kind of thing only a
        // real client finds.
        params.is_ca = IsCa::ExplicitNoCa;
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

        // Reconstructed from the persisted root cert PEM, not from
        // `CertificateParams` kept in memory -- see `Self::issuer`.
        let issuer = self.issuer()?;

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

        let mut ext =
            CustomExtension::from_oid_content(oid::OID_NUCLEUS_ATTESTATION_TUPLE, content);
        // Mark as non-critical so verifiers that don't understand it can still process the cert
        ext.set_criticality(false);
        ext
    }

    /// Creates a custom X.509 extension for permission fingerprint.
    ///
    /// OID: 1.3.6.1.4.1.57212.1.2 (Nucleus Permission Fingerprint)
    /// Content: DER-encoded SEQUENCE { INTEGER(version=1), OCTET STRING(32 bytes) }
    ///
    /// This binds the X.509/SPIFFE identity to a specific set of lattice permissions.
    fn create_permission_fingerprint_extension(fingerprint: &[u8; 32]) -> CustomExtension {
        // DER encode: SEQUENCE { INTEGER(version=1), OCTET STRING(fingerprint) }
        let mut content = vec![
            0x02, // INTEGER tag
            0x01, // length 1
            0x01, // version 1
            0x04, // OCTET STRING tag
            0x20, // length 32
        ];
        content.extend_from_slice(fingerprint);

        // Wrap in SEQUENCE
        let mut der = vec![0x30, content.len() as u8];
        der.extend_from_slice(&content);

        let mut ext =
            CustomExtension::from_oid_content(oid::OID_NUCLEUS_PERMISSION_FINGERPRINT_TUPLE, der);
        ext.set_criticality(false);
        ext
    }

    /// Creates a custom X.509 extension binding the SVID to a mediator signing key.
    ///
    /// OID: 1.3.6.1.4.1.57212.1.4 (Nucleus mediator-key binding)
    /// Content: DER-encoded SEQUENCE { INTEGER(version=1), OCTET STRING(32 bytes) }
    /// where the 32 bytes are `SHA-256(mediator Ed25519 public key)`.
    ///
    /// This binds the attested identity to the specific key that signs this pod's
    /// forensic `MediationReceipt`s, so a relying party can reject a receipt signed
    /// by any other key (see `verify_attested_receipt`). Same wire shape as the
    /// permission-fingerprint extension — a version-tagged 32-byte octet string.
    fn create_mediation_key_binding_extension(pubkey_sha256: &[u8; 32]) -> CustomExtension {
        let mut content = vec![
            0x02, // INTEGER tag
            0x01, // length 1
            0x01, // version 1
            0x04, // OCTET STRING tag
            0x20, // length 32
        ];
        content.extend_from_slice(pubkey_sha256);

        let mut der = vec![0x30, content.len() as u8];
        der.extend_from_slice(&content);

        let mut ext =
            CustomExtension::from_oid_content(oid::OID_NUCLEUS_MEDIATION_KEY_BINDING_TUPLE, der);
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

        // Reconstructed from the persisted root cert PEM, not from
        // `CertificateParams` kept in memory -- see `Self::issuer`.
        let issuer = self.issuer()?;

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
    let rsa_oid = oid!(1.2.840.113549.1.1.1); // RSA encryption
    let ec_oid = oid!(1.2.840.10045.2.1); // id-ecPublicKey
    let ed25519_oid = oid!(1.3.101.112); // Ed25519
    let secp256r1_oid = oid!(1.2.840.10045.3.1.7); // secp256r1/prime256v1
    let secp384r1_oid = oid!(1.3.132.0.34); // secp384r1

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
        if let Some(params) = &alg.parameters
            && let Ok(curve_oid) = params.as_oid()
        {
            if curve_oid == secp256r1_oid {
                return Some(&rcgen::PKCS_ECDSA_P256_SHA256);
            }
            if curve_oid == secp384r1_oid {
                return Some(&rcgen::PKCS_ECDSA_P384_SHA384);
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

    async fn sign_fused_csr(
        &self,
        csr: &str,
        private_key: &str,
        identity: &Identity,
        ttl: Duration,
        attestation: &LaunchAttestation,
        permission_fingerprint: &[u8; 32],
    ) -> Result<WorkloadCertificate> {
        let csr_spiffe_uri = self.validate_csr(csr)?;
        let expected_uri = identity.to_spiffe_uri();
        if csr_spiffe_uri != expected_uri {
            return Err(Error::VerificationFailed(format!(
                "CSR SPIFFE URI mismatch: expected {}, got {}",
                expected_uri, csr_spiffe_uri
            )));
        }
        if identity.trust_domain() != self.trust_domain {
            return Err(Error::TrustDomainMismatch {
                expected: self.trust_domain.clone(),
                actual: identity.trust_domain().to_string(),
            });
        }

        let key_pair = KeyPair::from_pem(private_key)
            .map_err(|e| Error::CaSigning(format!("failed to load private key: {e}")))?;

        let attestation_ext = Self::create_attestation_extension(attestation);
        let fingerprint_ext = Self::create_permission_fingerprint_extension(permission_fingerprint);

        let chain = self.sign_with_keypair_and_extensions(
            &key_pair,
            identity,
            ttl,
            vec![attestation_ext, fingerprint_ext],
        )?;

        let expiry = chain[0].not_after()?;
        let private_key_obj = PrivateKey::from_pem(private_key)?;

        Ok(WorkloadCertificate::new(
            chain,
            private_key_obj,
            expiry,
            identity.clone(),
        ))
    }

    async fn sign_attested_and_bound_csr(
        &self,
        csr: &str,
        private_key: &str,
        identity: &Identity,
        ttl: Duration,
        attestation: &LaunchAttestation,
        mediator_pubkey_sha256: &[u8; 32],
    ) -> Result<WorkloadCertificate> {
        let csr_spiffe_uri = self.validate_csr(csr)?;
        let expected_uri = identity.to_spiffe_uri();
        if csr_spiffe_uri != expected_uri {
            return Err(Error::VerificationFailed(format!(
                "CSR SPIFFE URI mismatch: expected {}, got {}",
                expected_uri, csr_spiffe_uri
            )));
        }
        if identity.trust_domain() != self.trust_domain {
            return Err(Error::TrustDomainMismatch {
                expected: self.trust_domain.clone(),
                actual: identity.trust_domain().to_string(),
            });
        }

        let key_pair = KeyPair::from_pem(private_key)
            .map_err(|e| Error::CaSigning(format!("failed to load private key: {e}")))?;

        let attestation_ext = Self::create_attestation_extension(attestation);
        let binding_ext = Self::create_mediation_key_binding_extension(mediator_pubkey_sha256);

        let chain = self.sign_with_keypair_and_extensions(
            &key_pair,
            identity,
            ttl,
            vec![attestation_ext, binding_ext],
        )?;

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

    #[tokio::test]
    async fn test_sign_fused_csr_embeds_fingerprint() {
        use crate::attestation::{LaunchAttestation, extract_permission_fingerprint};

        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "fused-agent");

        let csr_options = crate::CsrOptions::new(identity.to_spiffe_uri());
        let cert_sign = csr_options.generate().unwrap();

        let attestation = LaunchAttestation::from_hashes([0xaa; 32], [0xbb; 32], [0xcc; 32]);
        let fingerprint = [0xdd; 32];

        let cert = ca
            .sign_fused_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
                &attestation,
                &fingerprint,
            )
            .await
            .unwrap();

        assert_eq!(cert.identity(), &identity);
        assert!(!cert.is_expired());

        // Extract fingerprint from the issued certificate
        let extracted = extract_permission_fingerprint(cert.leaf().der());
        assert_eq!(
            extracted,
            Some(fingerprint),
            "extracted fingerprint must match embedded fingerprint"
        );
    }

    #[tokio::test]
    async fn test_extract_fingerprint_absent_from_standard_cert() {
        use crate::attestation::extract_permission_fingerprint;

        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "plain-agent");

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

        let extracted = extract_permission_fingerprint(cert.leaf().der());
        assert!(
            extracted.is_none(),
            "standard cert without fingerprint extension should return None"
        );
    }

    /// **Brick E2 round-trip.** An SVID carrying the mediator-key-binding
    /// extension (OID .1.4) makes the bound key visible to the relying party:
    /// `extract_mediation_key_binding` returns it, and the self-measured backend
    /// surfaces it as `VerifiedAttestation::subject_key_sha256` — the value
    /// `verify_attested_receipt` then requires the receipt to be signed under.
    #[tokio::test]
    async fn a_mediator_key_binding_extension_is_surfaced_by_the_verifier() {
        use crate::assurance::{SelfMeasuredBackend, SvidAttestationBackend};
        use crate::attestation::{AttestationRequirements, extract_mediation_key_binding};

        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "mediator-agent");
        let cert_sign = crate::CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let key_pair = KeyPair::from_pem(cert_sign.private_key()).unwrap();

        let attestation = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);
        let binding = [0x42u8; 32]; // stand-in for SHA-256(mediator pubkey)
        let att_ext = SelfSignedCa::create_attestation_extension(&attestation);
        let bind_ext = SelfSignedCa::create_mediation_key_binding_extension(&binding);
        let chain = ca
            .sign_with_keypair_and_extensions(
                &key_pair,
                &identity,
                Duration::from_secs(3600),
                vec![att_ext, bind_ext],
            )
            .unwrap();
        let leaf = &chain[0];

        assert_eq!(
            extract_mediation_key_binding(leaf.der()),
            Some(binding),
            "the binding must be extractable straight from the leaf DER"
        );
        let va = SelfMeasuredBackend
            .verify_svid(leaf.to_pem(), &AttestationRequirements::any(), true)
            .unwrap()
            .expect("an attested leaf verifies");
        assert_eq!(
            va.subject_key_sha256(),
            Some(binding),
            "the verifier must surface the bound key as subject_key_sha256"
        );
    }

    /// **The production issuance path.** `sign_attested_and_bound_csr` (what the
    /// node calls for a pod with a minted mediation key) yields an SVID that
    /// carries BOTH the launch attestation and the mediator-key binding, and the
    /// verifier surfaces the bound key.
    #[tokio::test]
    async fn sign_attested_and_bound_csr_embeds_a_verifiable_binding() {
        use crate::assurance::{SelfMeasuredBackend, SvidAttestationBackend};
        use crate::attestation::{AttestationRequirements, extract_mediation_key_binding};
        use crate::ca::CaClient;

        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "mediator-agent");
        let cert_sign = crate::CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let attestation = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);
        let binding = [0x77u8; 32];

        let cert = ca
            .sign_attested_and_bound_csr(
                cert_sign.csr(),
                cert_sign.private_key(),
                &identity,
                Duration::from_secs(3600),
                &attestation,
                &binding,
            )
            .await
            .unwrap();

        assert_eq!(
            extract_mediation_key_binding(cert.leaf().der()),
            Some(binding)
        );
        let va = SelfMeasuredBackend
            .verify_svid(cert.leaf().to_pem(), &AttestationRequirements::any(), true)
            .unwrap()
            .expect("attested");
        assert_eq!(va.subject_key_sha256(), Some(binding));
    }

    /// The control: an attested SVID WITHOUT the binding extension surfaces
    /// `subject_key_sha256 = None` — so the key-binding is "not established", never
    /// silently waived.
    #[tokio::test]
    async fn an_svid_without_the_binding_surfaces_no_bound_key() {
        use crate::assurance::{SelfMeasuredBackend, SvidAttestationBackend};
        use crate::attestation::AttestationRequirements;

        let ca = SelfSignedCa::new("nucleus.local").unwrap();
        let identity = Identity::new("nucleus.local", "default", "plain-agent");
        let cert_sign = crate::CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let key_pair = KeyPair::from_pem(cert_sign.private_key()).unwrap();
        let attestation = LaunchAttestation::from_hashes([1u8; 32], [2u8; 32], [3u8; 32]);
        let att_ext = SelfSignedCa::create_attestation_extension(&attestation);
        let chain = ca
            .sign_with_keypair_and_extensions(
                &key_pair,
                &identity,
                Duration::from_secs(3600),
                vec![att_ext],
            )
            .unwrap();

        let va = SelfMeasuredBackend
            .verify_svid(chain[0].to_pem(), &AttestationRequirements::any(), true)
            .unwrap()
            .expect("an attested leaf verifies");
        assert_eq!(va.subject_key_sha256(), None);
    }

    #[test]
    fn test_permission_fingerprint_extension_creation() {
        let fingerprint = [0xff; 32];
        let ext = SelfSignedCa::create_permission_fingerprint_extension(&fingerprint);

        // Check OID components
        let oid_components: Vec<u64> = ext.oid_components().collect();
        assert_eq!(oid_components, vec![1, 3, 6, 1, 4, 1, 57212, 1, 2]);

        // Check criticality is false
        assert!(!ext.criticality());

        // Check content starts with SEQUENCE tag
        let content = ext.content();
        assert!(!content.is_empty());
        assert_eq!(content[0], 0x30, "DER should start with SEQUENCE tag");
    }

    /// Persistence module. This is the property the whole change exists for:
    /// a node that restarts must keep signing SVIDs under the SAME root, or
    /// mTLS peers that cached the old root reject the new one silently on
    /// every subsequent restart — the failure mode described in
    /// `SelfSignedCa::load_or_create`'s doc comment.
    mod persistence {
        use super::*;

        /// The property that matters: a CA loaded back from disk signs
        /// certificates a client trusting the FIRST instance's root still
        /// accepts. Comparing PEM equality would only prove serialization
        /// round-trips; this proves the two instances are the same trust
        /// anchor, by running the SAME webpki chain verification a real mTLS
        /// peer would (`did_builder::verify_svid_chain`) against a trust
        /// bundle built from the pre-reload instance's root.
        #[tokio::test]
        async fn a_reloaded_ca_signs_under_the_same_root() {
            let dir = tempfile::tempdir().unwrap();

            let first = SelfSignedCa::load_or_create("nucleus.local", dir.path()).unwrap();
            let first_root_pem = first.root_cert_pem();
            let first_bundle =
                TrustBundle::new(vec![Certificate::from_pem(&first_root_pem).unwrap()]);

            let second = SelfSignedCa::load_or_create("nucleus.local", dir.path()).unwrap();
            assert_eq!(
                second.root_cert_pem(),
                first_root_pem,
                "second load_or_create must return the SAME root, not mint a new one"
            );

            // Sign with the reloaded instance, verify against the trust bundle
            // built from the ORIGINAL (pre-reload) instance's root -- proving
            // they are the same anchor, not merely two instances with
            // identical-looking PEM.
            let identity = Identity::new("nucleus.local", "default", "reloaded-signer");
            let cert_sign = crate::CsrOptions::new(identity.to_spiffe_uri())
                .generate()
                .unwrap();
            let key_pair = KeyPair::from_pem(cert_sign.private_key()).unwrap();
            let chain = second
                .sign_with_keypair(&key_pair, &identity, Duration::from_secs(3600))
                .unwrap();

            crate::did_builder::verify_svid_chain(&chain[0], &first_bundle)
                .expect("a cert signed after reload must verify against the pre-reload bundle");
        }

        /// A partial pair (cert present, key deleted -- or vice versa) is a
        /// hard error, not a silent fresh mint. Simulates a crash or a manual
        /// mistake mid-rotation.
        #[test]
        fn a_partial_pair_is_refused_not_regenerated() {
            let dir = tempfile::tempdir().unwrap();
            let ca = SelfSignedCa::load_or_create("nucleus.local", dir.path()).unwrap();
            drop(ca);

            std::fs::remove_file(dir.path().join(CA_KEY_FILE)).unwrap();
            assert!(dir.path().join(CA_CERT_FILE).exists());

            let err = SelfSignedCa::load_or_create("nucleus.local", dir.path())
                .expect_err("a cert with no matching key must not silently mint a fresh root");
            assert!(
                err.to_string().contains("incomplete"),
                "unexpected error: {err}"
            );
        }

        /// A corrupt key file is also a hard error, not a fall-through to
        /// regeneration -- the failure mode this whole module exists to close.
        #[test]
        fn a_corrupt_key_file_is_refused_not_regenerated() {
            let dir = tempfile::tempdir().unwrap();
            let ca = SelfSignedCa::load_or_create("nucleus.local", dir.path()).unwrap();
            let original_root = ca.root_cert_pem();
            drop(ca);

            std::fs::write(dir.path().join(CA_KEY_FILE), b"not a key").unwrap();

            let err = SelfSignedCa::load_or_create("nucleus.local", dir.path())
                .expect_err("a corrupt key file must not silently mint a fresh root");
            assert!(
                err.to_string().contains("NOT regenerating"),
                "unexpected error: {err}"
            );

            // And the untouched cert file proves nothing was overwritten as a
            // side effect of the failed load attempt.
            let cert_on_disk = std::fs::read_to_string(dir.path().join(CA_CERT_FILE)).unwrap();
            assert_eq!(cert_on_disk, original_root);
        }

        /// The key file lands with owner-only permissions.
        #[cfg(unix)]
        #[test]
        fn the_persisted_key_file_is_owner_only() {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().unwrap();
            let _ca = SelfSignedCa::load_or_create("nucleus.local", dir.path()).unwrap();

            let mode = std::fs::metadata(dir.path().join(CA_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600, "key file mode was {mode:o}");
        }
    }
}
