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

    /// Extracts the SPIFFE identity from an X.509-SVID, enforcing the spec's
    /// validation rules.
    ///
    /// # Why this is strict
    ///
    /// This used to return the FIRST SAN entry starting with `spiffe://`. The
    /// X.509-SVID standard says an SVID "MUST contain exactly one URI SAN", and
    /// that validators MUST reject certificates carrying more. First-match is
    /// not a lenient reading of that rule — it is an **impersonation vector**:
    /// a certificate bearing both `spiffe://td/victim` and `spiffe://td/attacker`
    /// was accepted, and which identity nucleus believed depended on DER
    /// encoding order. Two components parsing the same peer could disagree.
    ///
    /// That matters because this is an authorization input. `nucleus-node`'s
    /// `auth` path and the tool-proxy's mTLS path both decide *who a peer is*
    /// from this value.
    ///
    /// # What is checked
    ///
    /// Per <https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md>:
    ///
    /// * exactly one URI SAN (not "the first one that looks right"),
    /// * `cA` is false — a CA certificate is not an SVID,
    /// * neither `keyCertSign` nor `cRLSign` is asserted.
    ///
    /// The remaining leaf rules — the `spiffe` scheme and a non-root path
    /// component — are enforced by [`Identity::from_spiffe_uri`], which rejects
    /// both a foreign scheme and `spiffe://trust.domain/`. They are not
    /// re-implemented here; one parser owning one rule is the point of this
    /// function.
    pub fn extract_spiffe_identity(&self) -> Result<Identity> {
        Identity::from_spiffe_uri(&spiffe_uri_from_svid(&self.der)?)
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

/// The validated SPIFFE URI of an X.509-SVID.
///
/// This is the single place nucleus decides what SPIFFE ID a certificate
/// carries. It existed in seven copies before — `certificate.rs`, `tls.rs`,
/// `ca/self_signed.rs`, `nucleus-node`'s `auth`, and the tool-proxy's `mtls`
/// and `sandbox_proof` — each looping the SAN list and returning the FIRST
/// entry starting with `spiffe://`.
///
/// That is not a lenient reading of the standard, it is an impersonation
/// vector. The X.509-SVID spec says an SVID "MUST contain exactly one URI SAN"
/// and that validators MUST reject certificates carrying more; with first-match
/// a certificate naming both `spiffe://td/victim` and `spiffe://td/attacker`
/// was accepted, and which identity nucleus believed depended on DER encoding
/// order. Two of those call sites — `auth` and `mtls` — decide *who a peer is*,
/// so two components could disagree about the same peer.
///
/// Enforced here, per
/// <https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md>:
///
/// * exactly one URI SAN,
/// * `cA` is false,
/// * neither `keyCertSign` nor `cRLSign` is asserted,
/// * the URI is a well-formed SPIFFE ID with a non-root path — delegated to
///   [`Identity::from_spiffe_uri`], which rejects a foreign scheme and a bare
///   `spiffe://trust.domain/`. The URI is returned as it appeared, so callers
///   that want the string do not pay for a reserialisation.
pub fn spiffe_uri_from_svid(cert_der: &[u8]) -> Result<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| Error::Certificate(format!("failed to parse certificate: {e}")))?;
    spiffe_uri_from_parsed_svid(&cert)
}

/// [`spiffe_uri_from_svid`] for a certificate that is already parsed.
///
/// Same rules, no re-parse. Call sites that hold an
/// `x509_parser::certificate::X509Certificate` (the tool-proxy's sandbox proof,
/// `nucleus-spiffe-hail`) use this so that converging on one validator does not
/// cost them a second DER parse.
pub fn spiffe_uri_from_parsed_svid(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> Result<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};

    // "Leaf certificates MUST set the cA field to false."
    if cert.is_ca() {
        return Err(Error::Certificate(
            "not an X.509-SVID: cA is true, which is a CA certificate, not a leaf SVID".to_string(),
        ));
    }

    // "MUST NOT set keyCertSign or cRLSign." Checked independently of `cA`: a
    // leaf able to sign certificates or CRLs can mint peers whatever its basic
    // constraints claim.
    for ext in cert.extensions() {
        if let ParsedExtension::KeyUsage(ku) = ext.parsed_extension() {
            if ku.key_cert_sign() || ku.crl_sign() {
                return Err(Error::Certificate(
                    "not an X.509-SVID: key usage asserts keyCertSign or cRLSign".to_string(),
                ));
            }
        }
    }

    // Collect EVERY URI SAN before deciding. Returning on the first match is
    // exactly the bug this function exists to remove.
    let mut uris = Vec::new();
    for ext in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    uris.push(*uri);
                }
            }
        }
    }

    match uris.as_slice() {
        [] => Err(Error::Certificate(
            "not an X.509-SVID: no URI SAN".to_string(),
        )),
        [uri] => {
            // Parse for validation (scheme, non-root path) but return the URI
            // as it appeared on the wire.
            Identity::from_spiffe_uri(uri)?;
            Ok((*uri).to_string())
        }
        many => Err(Error::Certificate(format!(
            "not an X.509-SVID: {} URI SANs, expected exactly one (a certificate carrying \
             several identities must be refused, not resolved by order): {}",
            many.len(),
            many.join(", ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- X.509-SVID validation --------------------------------------------
    //
    // Every case below CONSTRUCTS the offending certificate and asserts it
    // parses as a certificate first. Without that, a test could pass because
    // the DER was malformed rather than because the rule fired — a refusal for
    // the wrong reason proves nothing about the rule.

    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose, SanType,
    };

    /// Build a self-signed leaf with the given URI SANs and knobs.
    fn svid_like(uris: &[&str], is_ca: bool, key_usages: Vec<KeyUsagePurpose>) -> Vec<u8> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "test");
        params.distinguished_name = dn;
        params.is_ca = if is_ca {
            IsCa::Ca(BasicConstraints::Unconstrained)
        } else {
            IsCa::NoCa
        };
        params.key_usages = key_usages;
        params.subject_alt_names = uris
            .iter()
            .map(|u| SanType::URI(rcgen::string::Ia5String::try_from(u.to_string()).unwrap()))
            .collect();
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn parses_as_a_certificate(der: &[u8]) {
        assert!(
            x509_parser::parse_x509_certificate(der).is_ok(),
            "fixture is not a parseable certificate, so any rejection would be \
             meaningless"
        );
    }

    /// Non-vacuity for the whole group: a conformant SVID must still be
    /// ACCEPTED and yield the right identity. Without this, a validator that
    /// refused everything would pass every other test here.
    #[test]
    fn a_conformant_svid_is_accepted_and_yields_its_identity() {
        let der = svid_like(
            &["spiffe://nucleus.local/ns/default/sa/web"],
            false,
            vec![KeyUsagePurpose::DigitalSignature],
        );
        parses_as_a_certificate(&der);
        let id = Certificate::from_der(der)
            .extract_spiffe_identity()
            .unwrap();
        assert_eq!(id.trust_domain(), "nucleus.local");
        assert_eq!(id.namespace(), "default");
        assert_eq!(id.service_account(), "web");
    }

    /// THE case this hardening exists for. A certificate naming two identities
    /// must be refused outright — NOT resolved to whichever encodes first.
    #[test]
    fn a_certificate_bearing_two_spiffe_ids_is_refused_not_resolved() {
        let der = svid_like(
            &[
                "spiffe://nucleus.local/ns/default/sa/victim",
                "spiffe://nucleus.local/ns/default/sa/attacker",
            ],
            false,
            vec![KeyUsagePurpose::DigitalSignature],
        );
        parses_as_a_certificate(&der);

        let err = Certificate::from_der(der)
            .extract_spiffe_identity()
            .expect_err("a two-SAN certificate must be refused");
        let msg = err.to_string();
        assert!(msg.contains("expected exactly one"), "{msg}");
        // The old first-match behaviour returned `victim`. Naming either
        // identity as the answer is the failure mode, so assert we did not.
        assert!(
            !msg.starts_with("spiffe://"),
            "the error must not resolve to an identity: {msg}"
        );
    }

    /// Order independence: the same certificate with the SANs swapped must fail
    /// identically. If the rule were still order-sensitive, exactly one of these
    /// two tests would pass.
    #[test]
    fn the_refusal_does_not_depend_on_san_order() {
        let der = svid_like(
            &[
                "spiffe://nucleus.local/ns/default/sa/attacker",
                "spiffe://nucleus.local/ns/default/sa/victim",
            ],
            false,
            vec![KeyUsagePurpose::DigitalSignature],
        );
        parses_as_a_certificate(&der);
        assert!(Certificate::from_der(der)
            .extract_spiffe_identity()
            .is_err());
    }

    /// "Leaf certificates MUST set the cA field to false."
    #[test]
    fn a_ca_certificate_is_not_an_svid() {
        let der = svid_like(
            &["spiffe://nucleus.local/ns/default/sa/web"],
            true,
            vec![KeyUsagePurpose::DigitalSignature],
        );
        parses_as_a_certificate(&der);
        let msg = Certificate::from_der(der)
            .extract_spiffe_identity()
            .expect_err("a CA certificate must not validate as an SVID")
            .to_string();
        assert!(msg.contains("cA is true"), "{msg}");
    }

    /// "MUST NOT set keyCertSign or cRLSign" — checked independently of `cA`,
    /// because a leaf that can sign certificates can mint peers regardless of
    /// what its basic constraints claim.
    #[test]
    fn a_leaf_that_can_sign_certificates_is_not_an_svid() {
        for usage in [KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign] {
            let der = svid_like(
                &["spiffe://nucleus.local/ns/default/sa/web"],
                false,
                vec![KeyUsagePurpose::DigitalSignature, usage],
            );
            parses_as_a_certificate(&der);
            let msg = Certificate::from_der(der)
                .extract_spiffe_identity()
                .expect_err("keyCertSign/cRLSign must disqualify an SVID")
                .to_string();
            assert!(msg.contains("keyCertSign or cRLSign"), "{msg}");
        }
    }

    /// A certificate with no URI SAN at all is not an SVID.
    #[test]
    fn a_certificate_without_a_uri_san_is_not_an_svid() {
        let der = svid_like(&[], false, vec![KeyUsagePurpose::DigitalSignature]);
        parses_as_a_certificate(&der);
        let msg = Certificate::from_der(der)
            .extract_spiffe_identity()
            .expect_err("no URI SAN must be refused")
            .to_string();
        assert!(msg.contains("no URI SAN"), "{msg}");
    }

    /// The scheme and non-root-path rules are delegated to
    /// `Identity::from_spiffe_uri`. Delegation is only safe if it actually
    /// rejects, so pin that here rather than assuming it.
    #[test]
    fn the_delegated_scheme_and_path_rules_still_reject() {
        for uri in [
            "https://nucleus.local/ns/default/sa/web", // wrong scheme
            "spiffe://nucleus.local/",                 // root path only
        ] {
            let der = svid_like(&[uri], false, vec![KeyUsagePurpose::DigitalSignature]);
            parses_as_a_certificate(&der);
            assert!(
                Certificate::from_der(der)
                    .extract_spiffe_identity()
                    .is_err(),
                "{uri} must be refused"
            );
        }
    }

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
