//! Higher-level builders for DID documents and SPIFFE-DID binding proofs.
//!
//! Composes the crypto primitives from [`did_crypto`](crate::did_crypto) with
//! the types from [`did`](crate::did) and [`did_binding`](crate::did_binding)
//! to produce complete DID documents and binding proofs from a
//! [`WorkloadCertificate`](crate::certificate::WorkloadCertificate).
//!
//! # Example
//!
//! ```no_run
//! use nucleus_identity::did_builder::{extract_svid_material, build_did_document};
//! use nucleus_identity::did::ServiceEndpoint;
//! use nucleus_identity::certificate::WorkloadCertificate;
//!
//! # fn example(cert: &WorkloadCertificate) {
//! let material = extract_svid_material(cert).unwrap();
//! let doc = build_did_document(
//!     "did:web:my-app.example.com",
//!     &material.public_key_jwk,
//!     &material,
//!     vec![],
//! );
//! assert_eq!(doc.id, "did:web:my-app.example.com");
//! # }
//! ```

use chrono::{DateTime, Utc};

use crate::certificate::WorkloadCertificate;
use crate::did::{DidDocument, JsonWebKey, ServiceEndpoint, VerificationMethod};
use crate::did_binding::{BindingProof, SpiffeDidBinding};
use crate::did_crypto::{
    cert_fingerprint, chain_to_base64url, extract_ec_p256_jwk, jws_sign_es256,
};
use crate::Result;

/// Material extracted from an SVID (X.509 SPIFFE Verifiable Identity Document).
///
/// Contains everything needed to build DID documents and binding proofs
/// from a workload certificate.
#[derive(Debug, Clone)]
pub struct SvidMaterial {
    /// EC P-256 public key from the SVID leaf certificate, as a JWK.
    pub public_key_jwk: JsonWebKey,
    /// SHA-256 fingerprint of the leaf certificate (`"SHA256:<base64url>"`).
    pub fingerprint: String,
    /// Certificate chain as base64url-encoded DER strings (leaf first).
    pub chain_base64url: Vec<String>,
    /// When the SVID expires.
    pub expires: DateTime<Utc>,
}

/// Extract all DID-relevant material from a [`WorkloadCertificate`].
///
/// Parses the leaf certificate to extract the EC P-256 public key,
/// computes the certificate fingerprint, and encodes the full chain
/// as base64url DER.
///
/// # Errors
///
/// Returns an error if the leaf certificate doesn't contain an EC P-256 key.
pub fn extract_svid_material(cert: &WorkloadCertificate) -> Result<SvidMaterial> {
    let public_key_jwk = extract_ec_p256_jwk(cert.leaf())?;
    let fingerprint = cert_fingerprint(cert.leaf());
    let chain_base64url = chain_to_base64url(cert.chain());
    let expires = cert.expiry();

    Ok(SvidMaterial {
        public_key_jwk,
        fingerprint,
        chain_base64url,
        expires,
    })
}

/// Build a complete DID document from an app signing key and SVID material.
///
/// Creates a W3C DID Core v1.0 document with two verification methods:
///
/// 1. `#app-signing-key-1` — The application's signing key (used for assertions)
/// 2. `#svid-key-1` — The SVID's EC P-256 key (used for SPIFFE binding authentication)
///
/// # Arguments
///
/// * `did` - The `did:web` identifier (e.g., `"did:web:my-app.example.com"`)
/// * `app_key` - The application's signing public key as a JWK
/// * `svid_material` - Material extracted from the SVID via [`extract_svid_material`]
/// * `services` - Optional service endpoints to include in the document
pub fn build_did_document(
    did: &str,
    app_key: &JsonWebKey,
    svid_material: &SvidMaterial,
    services: Vec<ServiceEndpoint>,
) -> DidDocument {
    let app_key_id = format!("{did}#app-signing-key-1");
    let svid_key_id = format!("{did}#svid-key-1");

    let mut app_jwk = app_key.clone();
    app_jwk.kid = Some("app-signing-key-1".into());
    app_jwk.alg = Some("ES256".into());

    let mut svid_jwk = svid_material.public_key_jwk.clone();
    svid_jwk.kid = Some("svid-key-1".into());
    svid_jwk.alg = Some("ES256".into());

    DidDocument {
        context: vec![
            "https://www.w3.org/ns/did/v1".into(),
            "https://w3id.org/security/suites/jws-2020/v1".into(),
        ],
        id: did.to_string(),
        verification_method: vec![
            VerificationMethod {
                id: app_key_id.clone(),
                method_type: "JsonWebKey2020".into(),
                controller: did.to_string(),
                public_key_jwk: app_jwk,
            },
            VerificationMethod {
                id: svid_key_id.clone(),
                method_type: "JsonWebKey2020".into(),
                controller: did.to_string(),
                public_key_jwk: svid_jwk,
            },
        ],
        authentication: Some(vec![svid_key_id]),
        assertion_method: Some(vec![app_key_id]),
        key_agreement: None,
        service: if services.is_empty() {
            None
        } else {
            Some(services)
        },
    }
}

/// Build a SPIFFE-DID binding proof with cross-signatures.
///
/// Creates a [`SpiffeDidBinding`] document with bidirectional cryptographic proof:
///
/// - The SVID private key signs the DID string (proves the workload claims this DID)
/// - The app signing key signs the SPIFFE ID string (proves the DID claims this workload)
///
/// # Arguments
///
/// * `did` - The `did:web` identifier
/// * `spiffe_id` - The SPIFFE ID URI (e.g., `"spiffe://example.com/ns/apps/sa/my-app"`)
/// * `svid_material` - Material extracted from the SVID via [`extract_svid_material`]
/// * `svid_private_key_der` - PKCS#8-encoded SVID private key (DER bytes)
/// * `app_signing_key_der` - PKCS#8-encoded app signing key (DER bytes)
/// * `app_key_id` - Full DID URL of the app signing key (e.g., `"did:web:...#app-signing-key-1"`)
///
/// # Errors
///
/// Returns an error if either signing operation fails.
pub fn build_binding(
    did: &str,
    spiffe_id: &str,
    svid_material: &SvidMaterial,
    svid_private_key_der: &[u8],
    app_signing_key_der: &[u8],
    app_key_id: &str,
) -> Result<SpiffeDidBinding> {
    // SVID private key signs the DID string
    let signature_over_did_by_svid = jws_sign_es256(did.as_bytes(), svid_private_key_der)?;

    // App signing key signs the SPIFFE ID string
    let signature_over_svid_by_did = jws_sign_es256(spiffe_id.as_bytes(), app_signing_key_der)?;

    let now = Utc::now();

    Ok(SpiffeDidBinding {
        did: did.to_string(),
        spiffe_id: spiffe_id.to_string(),
        binding_proof: BindingProof {
            proof_type: "SpiffeDidBinding".into(),
            created: now,
            expires: svid_material.expires,
            svid_fingerprint: svid_material.fingerprint.clone(),
            did_key_id: app_key_id.to_string(),
            attestation_chain: svid_material.chain_base64url.clone(),
            signature_over_did_by_svid,
            signature_over_svid_by_did,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::SelfSignedCa;
    use crate::did_crypto::{extract_ec_p256_jwk, jws_verify_es256};
    use crate::identity::Identity;
    use crate::CsrOptions;
    use base64::Engine;
    use ring::signature::KeyPair as _;
    use std::time::Duration;

    /// Helper: generate a workload cert and return it with its private key DER.
    async fn make_cert() -> (WorkloadCertificate, Vec<u8>) {
        let ca = SelfSignedCa::new("test.local").unwrap();
        let identity = Identity::new("test.local", "apps", "my-app");
        let csr = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let pk_pem = csr.private_key().to_string();

        let cert = ca
            .sign_csr_with_key(
                csr.csr(),
                csr.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        let pk_der = crate::certificate::PrivateKey::from_pem(&pk_pem)
            .unwrap()
            .to_der()
            .unwrap();

        (cert, pk_der)
    }

    /// Helper: generate a separate app signing key pair (returns private DER + public JWK).
    fn make_app_key() -> (Vec<u8>, JsonWebKey) {
        let csr = CsrOptions::new("spiffe://test.local/ns/apps/sa/app-key")
            .generate()
            .unwrap();
        let pk_der = csr.private_key_der().unwrap();

        // Sign with SelfSignedCa to get a cert we can extract the public key from
        // But actually we just need the key pair — extract from the CSR's key directly.
        // Use ring to get the public key from the private key.
        let rng = ring::rand::SystemRandom::new();
        let key_pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &pk_der,
            &rng,
        )
        .unwrap();

        let pub_key = key_pair.public_key().as_ref();
        // pub_key is uncompressed point: 0x04 || x[32] || y[32]
        let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_key[1..33]);
        let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&pub_key[33..65]);

        (pk_der, JsonWebKey::ec_p256(x, y))
    }

    #[tokio::test]
    async fn extract_svid_material_from_cert() {
        let (cert, _) = make_cert().await;
        let material = extract_svid_material(&cert).unwrap();

        assert_eq!(material.public_key_jwk.kty, "EC");
        assert_eq!(material.public_key_jwk.crv, "P-256");
        assert!(material.fingerprint.starts_with("SHA256:"));
        assert!(!material.chain_base64url.is_empty());
        assert!(material.expires > Utc::now());
    }

    #[tokio::test]
    async fn build_did_document_structure() {
        let (cert, _) = make_cert().await;
        let material = extract_svid_material(&cert).unwrap();
        let (_, app_jwk) = make_app_key();

        let did = "did:web:my-app.test.local";
        let doc = build_did_document(did, &app_jwk, &material, vec![]);

        assert_eq!(doc.id, did);
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(
            doc.verification_method[0].id,
            "did:web:my-app.test.local#app-signing-key-1"
        );
        assert_eq!(
            doc.verification_method[1].id,
            "did:web:my-app.test.local#svid-key-1"
        );
        assert_eq!(
            doc.authentication,
            Some(vec!["did:web:my-app.test.local#svid-key-1".into()])
        );
        assert_eq!(
            doc.assertion_method,
            Some(vec!["did:web:my-app.test.local#app-signing-key-1".into()])
        );
        assert!(doc.service.is_none());
    }

    #[tokio::test]
    async fn build_did_document_w3c_json() {
        let (cert, _) = make_cert().await;
        let material = extract_svid_material(&cert).unwrap();
        let (_, app_jwk) = make_app_key();

        let doc = build_did_document("did:web:app.dev", &app_jwk, &material, vec![]);
        let json: serde_json::Value = serde_json::to_value(&doc).unwrap();

        assert!(json["@context"].is_array());
        assert_eq!(json["@context"][0], "https://www.w3.org/ns/did/v1");
        assert!(json["verificationMethod"].is_array());
        assert_eq!(json["verificationMethod"][0]["type"], "JsonWebKey2020");
    }

    #[tokio::test]
    async fn build_did_document_with_services() {
        let (cert, _) = make_cert().await;
        let material = extract_svid_material(&cert).unwrap();
        let (_, app_jwk) = make_app_key();

        let did = "did:web:app.dev";
        let services = vec![ServiceEndpoint {
            id: format!("{did}#api"),
            service_type: "RestApi".into(),
            service_endpoint: "https://app.dev/api/v1".into(),
            description: None,
        }];

        let doc = build_did_document(did, &app_jwk, &material, services);
        assert!(doc.service.is_some());
        assert_eq!(doc.service.as_ref().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn build_binding_cross_signatures_verify() {
        let (cert, svid_pk_der) = make_cert().await;
        let material = extract_svid_material(&cert).unwrap();
        let (app_pk_der, app_jwk) = make_app_key();

        let did = "did:web:my-app.test.local";
        let spiffe_id = "spiffe://test.local/ns/apps/sa/my-app";
        let app_key_id = format!("{did}#app-signing-key-1");

        let binding = build_binding(
            did,
            spiffe_id,
            &material,
            &svid_pk_der,
            &app_pk_der,
            &app_key_id,
        )
        .unwrap();

        assert_eq!(binding.did, did);
        assert_eq!(binding.spiffe_id, spiffe_id);
        assert_eq!(binding.binding_proof.proof_type, "SpiffeDidBinding");
        assert!(!binding.is_expired());

        // Verify the SVID-signed DID claim
        let svid_jwk = extract_ec_p256_jwk(cert.leaf()).unwrap();
        let recovered_did =
            jws_verify_es256(&binding.binding_proof.signature_over_did_by_svid, &svid_jwk).unwrap();
        assert_eq!(recovered_did, did.as_bytes());

        // Verify the app-signed SPIFFE ID claim
        let recovered_spiffe_id =
            jws_verify_es256(&binding.binding_proof.signature_over_svid_by_did, &app_jwk).unwrap();
        assert_eq!(recovered_spiffe_id, spiffe_id.as_bytes());
    }

    #[tokio::test]
    async fn binding_serde_roundtrip() {
        let (cert, svid_pk_der) = make_cert().await;
        let material = extract_svid_material(&cert).unwrap();
        let (app_pk_der, _) = make_app_key();

        let binding = build_binding(
            "did:web:app.dev",
            "spiffe://test.local/ns/apps/sa/my-app",
            &material,
            &svid_pk_der,
            &app_pk_der,
            "did:web:app.dev#app-signing-key-1",
        )
        .unwrap();

        let json = serde_json::to_string_pretty(&binding).unwrap();
        let parsed: SpiffeDidBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.did, binding.did);
        assert_eq!(parsed.spiffe_id, binding.spiffe_id);
        assert_eq!(
            parsed.binding_proof.svid_fingerprint,
            binding.binding_proof.svid_fingerprint
        );
    }
}
