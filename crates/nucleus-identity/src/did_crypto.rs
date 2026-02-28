//! JWS compact serialization (ES256) and EC public key extraction from X.509.
//!
//! Provides the cryptographic primitives needed for DID document proofs and
//! SPIFFE-DID binding cross-signatures:
//!
//! - [`extract_ec_p256_jwk`] — Extract an EC P-256 public key from a certificate as a JWK
//! - [`cert_fingerprint`] — SHA-256 fingerprint of a certificate in `SHA256:<base64url>` format
//! - [`jws_sign_es256`] — Create a JWS compact serialization (ES256) over a payload
//! - [`jws_verify_es256`] — Verify a JWS compact serialization against a JWK
//! - [`chain_to_base64url`] — Encode a certificate chain as base64url DER strings

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair};
use sha2::{Digest, Sha256};

use crate::certificate::Certificate;
use crate::did::JsonWebKey;
use crate::{Error, Result};

/// Extract EC P-256 public key coordinates from a certificate's SubjectPublicKeyInfo.
///
/// Parses the DER-encoded cert, extracts the SPKI, validates it's EC P-256,
/// then splits the uncompressed EC point (`0x04 || x[32] || y[32]`) into
/// base64url-encoded x and y coordinates for a [`JsonWebKey`].
///
/// # Errors
///
/// Returns an error if the certificate can't be parsed, isn't EC P-256,
/// or the public key isn't in uncompressed point format.
pub fn extract_ec_p256_jwk(cert: &Certificate) -> Result<JsonWebKey> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.der())
        .map_err(|e| Error::Certificate(format!("failed to parse certificate: {e}")))?;

    let spki = &parsed.tbs_certificate.subject_pki;

    // Validate this is an EC key on P-256
    let ec_oid = x509_parser::oid_registry::asn1_rs::oid!(1.2.840 .10045 .2 .1);
    let p256_oid = x509_parser::oid_registry::asn1_rs::oid!(1.2.840 .10045 .3 .1 .7);

    if spki.algorithm.algorithm != ec_oid {
        return Err(Error::Certificate(
            "public key is not an EC key".to_string(),
        ));
    }

    if let Some(params) = &spki.algorithm.parameters {
        let curve_oid = params
            .as_oid()
            .map_err(|_| Error::Certificate("failed to parse EC curve OID".to_string()))?;
        if curve_oid != p256_oid {
            return Err(Error::Certificate(format!(
                "unsupported EC curve: expected P-256, got {curve_oid}"
            )));
        }
    } else {
        return Err(Error::Certificate(
            "EC key missing curve parameters".to_string(),
        ));
    }

    // Extract the uncompressed EC point from the public key bit string
    let pk_data = &*spki.subject_public_key.data;

    // Uncompressed point format: 0x04 || x[32] || y[32] = 65 bytes
    if pk_data.len() != 65 || pk_data[0] != 0x04 {
        return Err(Error::Certificate(format!(
            "expected uncompressed EC point (65 bytes), got {} bytes with prefix 0x{:02x}",
            pk_data.len(),
            pk_data.first().copied().unwrap_or(0)
        )));
    }

    let x = URL_SAFE_NO_PAD.encode(&pk_data[1..33]);
    let y = URL_SAFE_NO_PAD.encode(&pk_data[33..65]);

    Ok(JsonWebKey::ec_p256(x, y))
}

/// Compute SHA-256 fingerprint of a certificate's DER encoding.
///
/// Returns the fingerprint in `"SHA256:<base64url>"` format, matching the
/// convention used in SPIFFE-DID binding documents.
pub fn cert_fingerprint(cert: &Certificate) -> String {
    let hash = Sha256::digest(cert.der());
    let encoded = URL_SAFE_NO_PAD.encode(hash);
    format!("SHA256:{encoded}")
}

/// Create a JWS compact serialization (ES256) over a payload.
///
/// Uses the PKCS#8-encoded private key to sign with P-256 ECDSA (SHA-256).
/// Returns the compact JWS string: `header.payload.signature` (all base64url).
///
/// # Arguments
///
/// * `payload` - The bytes to sign (will be base64url-encoded in the JWS)
/// * `private_key_pkcs8_der` - PKCS#8-encoded P-256 private key in DER format
///
/// # Errors
///
/// Returns an error if the private key is invalid or signing fails.
pub fn jws_sign_es256(payload: &[u8], private_key_pkcs8_der: &[u8]) -> Result<String> {
    // Construct the protected header
    let header = r#"{"alg":"ES256"}"#;
    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);

    // The signing input is: base64url(header) || '.' || base64url(payload)
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Create the key pair from PKCS#8 DER
    let rng = SystemRandom::new();
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        private_key_pkcs8_der,
        &rng,
    )
    .map_err(|e| Error::Internal(format!("failed to load ECDSA key pair: {e}")))?;

    // Sign the input
    let sig = key_pair
        .sign(&rng, signing_input.as_bytes())
        .map_err(|e| Error::Internal(format!("ECDSA signing failed: {e}")))?;

    let sig_b64 = URL_SAFE_NO_PAD.encode(sig.as_ref());

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Verify a JWS compact serialization (ES256) against a [`JsonWebKey`].
///
/// Extracts the public key from the JWK, decodes the JWS components,
/// and verifies the ECDSA-P256-SHA256 signature.
///
/// # Returns
///
/// The decoded payload bytes on success.
///
/// # Errors
///
/// Returns an error if the JWS format is invalid, the key type is wrong,
/// or the signature verification fails.
pub fn jws_verify_es256(jws: &str, public_key: &JsonWebKey) -> Result<Vec<u8>> {
    // Split the compact JWS into its three parts
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(Error::VerificationFailed(
            "JWS must have exactly 3 dot-separated parts".to_string(),
        ));
    }

    let [header_b64, payload_b64, sig_b64] = [parts[0], parts[1], parts[2]];

    // Validate the header contains ES256
    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| Error::VerificationFailed(format!("invalid base64url header: {e}")))?;
    let header_str = std::str::from_utf8(&header_bytes)
        .map_err(|e| Error::VerificationFailed(format!("header is not valid UTF-8: {e}")))?;
    if !header_str.contains("\"ES256\"") {
        return Err(Error::VerificationFailed(format!(
            "unsupported JWS algorithm: {header_str}"
        )));
    }

    // Reconstruct the public key from JWK coordinates
    if public_key.kty != "EC" || public_key.crv != "P-256" {
        return Err(Error::VerificationFailed(format!(
            "unsupported key type: kty={}, crv={}",
            public_key.kty, public_key.crv
        )));
    }

    let y = public_key.y.as_deref().ok_or_else(|| {
        Error::VerificationFailed("EC P-256 JWK missing y coordinate".to_string())
    })?;

    let x_bytes = URL_SAFE_NO_PAD
        .decode(&public_key.x)
        .map_err(|e| Error::VerificationFailed(format!("invalid base64url x coordinate: {e}")))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|e| Error::VerificationFailed(format!("invalid base64url y coordinate: {e}")))?;

    // Reconstruct the uncompressed EC point: 0x04 || x || y
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(&x_bytes);
    uncompressed.extend_from_slice(&y_bytes);

    // Decode the signature
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| Error::VerificationFailed(format!("invalid base64url signature: {e}")))?;

    // The message that was signed is: header_b64 || '.' || payload_b64
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Verify the signature
    let peer_public_key =
        signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &uncompressed);

    peer_public_key
        .verify(signing_input.as_bytes(), &sig_bytes)
        .map_err(|_| {
            Error::VerificationFailed("ECDSA signature verification failed".to_string())
        })?;

    // Decode and return the payload
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| Error::VerificationFailed(format!("invalid base64url payload: {e}")))?;

    Ok(payload)
}

/// Encode a certificate chain as base64url DER strings.
///
/// Useful for the `attestation_chain` field in [`SpiffeDidBinding`](crate::did_binding::SpiffeDidBinding).
/// Returns base64url-encoded DER bytes, leaf first.
pub fn chain_to_base64url(chain: &[Certificate]) -> Vec<String> {
    chain
        .iter()
        .map(|cert| URL_SAFE_NO_PAD.encode(cert.der()))
        .collect()
}

/// Decode base64url DER strings back to certificates.
///
/// Inverse of [`chain_to_base64url`].
pub fn chain_from_base64url(encoded: &[String]) -> Result<Vec<Certificate>> {
    encoded
        .iter()
        .map(|b64| {
            let der = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|e| Error::Certificate(format!("invalid base64url certificate: {e}")))?;
            Ok(Certificate::from_der(der))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::SelfSignedCa;
    use crate::identity::Identity;
    use crate::CsrOptions;
    use std::time::Duration;

    /// Helper: generate a self-signed P-256 workload certificate.
    async fn generate_test_cert() -> (crate::certificate::WorkloadCertificate, String) {
        let ca = SelfSignedCa::new("test.local").unwrap();
        let identity = Identity::new("test.local", "default", "test-svc");
        let csr = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let private_key_pem = csr.private_key().to_string();

        let cert = ca
            .sign_csr_with_key(
                csr.csr(),
                csr.private_key(),
                &identity,
                Duration::from_secs(3600),
            )
            .await
            .unwrap();

        (cert, private_key_pem)
    }

    #[tokio::test]
    async fn extract_ec_p256_jwk_from_cert() {
        let (cert, _) = generate_test_cert().await;
        let jwk = extract_ec_p256_jwk(cert.leaf()).unwrap();

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert!(!jwk.x.is_empty());
        assert!(jwk.y.is_some());

        // x and y should be 32 bytes each → 43 base64url chars (no padding)
        assert_eq!(jwk.x.len(), 43);
        assert_eq!(jwk.y.as_ref().unwrap().len(), 43);
    }

    #[tokio::test]
    async fn extract_ec_p256_jwk_deterministic() {
        let (cert, _) = generate_test_cert().await;
        let jwk1 = extract_ec_p256_jwk(cert.leaf()).unwrap();
        let jwk2 = extract_ec_p256_jwk(cert.leaf()).unwrap();
        assert_eq!(jwk1, jwk2);
    }

    #[tokio::test]
    async fn cert_fingerprint_deterministic() {
        let (cert, _) = generate_test_cert().await;
        let fp1 = cert_fingerprint(cert.leaf());
        let fp2 = cert_fingerprint(cert.leaf());
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("SHA256:"));
        // SHA-256 = 32 bytes → 43 base64url chars
        assert_eq!(fp1.len(), "SHA256:".len() + 43);
    }

    #[tokio::test]
    async fn cert_fingerprint_different_certs() {
        let (cert1, _) = generate_test_cert().await;
        let (cert2, _) = generate_test_cert().await;
        let fp1 = cert_fingerprint(cert1.leaf());
        let fp2 = cert_fingerprint(cert2.leaf());
        assert_ne!(fp1, fp2);
    }

    #[tokio::test]
    async fn jws_sign_verify_roundtrip() {
        let (cert, private_key_pem) = generate_test_cert().await;

        let payload = b"did:web:test-svc.test.local";
        let private_key_der = crate::certificate::PrivateKey::from_pem(&private_key_pem)
            .unwrap()
            .to_der()
            .unwrap();

        let jws = jws_sign_es256(payload, &private_key_der).unwrap();

        // Verify it has three parts
        assert_eq!(jws.split('.').count(), 3);

        // Verify against the public key extracted from the cert
        let jwk = extract_ec_p256_jwk(cert.leaf()).unwrap();
        let recovered = jws_verify_es256(&jws, &jwk).unwrap();
        assert_eq!(recovered, payload);
    }

    #[tokio::test]
    async fn jws_header_contains_es256() {
        let (_, private_key_pem) = generate_test_cert().await;
        let private_key_der = crate::certificate::PrivateKey::from_pem(&private_key_pem)
            .unwrap()
            .to_der()
            .unwrap();

        let jws = jws_sign_es256(b"test", &private_key_der).unwrap();

        // Decode the header
        let header_b64 = jws.split('.').next().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let header = std::str::from_utf8(&header_bytes).unwrap();
        assert_eq!(header, r#"{"alg":"ES256"}"#);
    }

    #[tokio::test]
    async fn jws_verification_fails_with_wrong_key() {
        let (_, private_key_pem) = generate_test_cert().await;
        let private_key_der = crate::certificate::PrivateKey::from_pem(&private_key_pem)
            .unwrap()
            .to_der()
            .unwrap();

        let jws = jws_sign_es256(b"payload", &private_key_der).unwrap();

        // Generate a different key pair's public key
        let (cert2, _) = generate_test_cert().await;
        let wrong_jwk = extract_ec_p256_jwk(cert2.leaf()).unwrap();

        let result = jws_verify_es256(&jws, &wrong_jwk);
        assert!(result.is_err());
        assert!(matches!(result, Err(Error::VerificationFailed(_))));
    }

    #[tokio::test]
    async fn jws_verification_fails_with_tampered_payload() {
        let (cert, private_key_pem) = generate_test_cert().await;
        let private_key_der = crate::certificate::PrivateKey::from_pem(&private_key_pem)
            .unwrap()
            .to_der()
            .unwrap();

        let jws = jws_sign_es256(b"original", &private_key_der).unwrap();
        let jwk = extract_ec_p256_jwk(cert.leaf()).unwrap();

        // Tamper with the payload part (replace middle section)
        let parts: Vec<&str> = jws.splitn(3, '.').collect();
        let tampered_payload = URL_SAFE_NO_PAD.encode(b"tampered");
        let tampered_jws = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

        let result = jws_verify_es256(&tampered_jws, &jwk);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn jws_rejects_malformed_input() {
        let jwk = JsonWebKey::ec_p256("x", "y");

        // Too few parts
        let result = jws_verify_es256("only.two", &jwk);
        assert!(result.is_err());

        // Empty string
        let result = jws_verify_es256("", &jwk);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn chain_to_base64url_roundtrip() {
        let (cert, _) = generate_test_cert().await;
        let chain = cert.chain();

        let encoded = chain_to_base64url(chain);
        assert_eq!(encoded.len(), chain.len());

        // Verify each element is valid base64url
        for b64 in &encoded {
            assert!(URL_SAFE_NO_PAD.decode(b64).is_ok());
        }

        // Roundtrip back to certificates
        let decoded = chain_from_base64url(&encoded).unwrap();
        assert_eq!(decoded.len(), chain.len());

        // Verify DER bytes match
        for (orig, dec) in chain.iter().zip(decoded.iter()) {
            assert_eq!(orig.der(), dec.der());
        }
    }

    #[tokio::test]
    async fn chain_to_base64url_preserves_order() {
        let (cert, _) = generate_test_cert().await;
        let chain = cert.chain();

        let encoded = chain_to_base64url(chain);

        // First element should be the leaf cert
        let leaf_b64 = URL_SAFE_NO_PAD.encode(chain[0].der());
        assert_eq!(encoded[0], leaf_b64);

        // Last element should be the root cert
        let root_b64 = URL_SAFE_NO_PAD.encode(chain[chain.len() - 1].der());
        assert_eq!(encoded[encoded.len() - 1], root_b64);
    }
}
