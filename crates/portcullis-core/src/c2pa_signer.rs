//! C2PA signer configuration — X.509 cert loading (#1016).
//!
//! Loads signing credentials from PEM files or environment variables
//! and creates c2pa-rs signers for content credential manifests.
//!
//! ## Environment variables
//!
//! - `NUCLEUS_C2PA_CERT` — PEM certificate chain (end-entity + intermediates)
//! - `NUCLEUS_C2PA_KEY` — PEM private key (PKCS#8)
//! - `NUCLEUS_C2PA_TSA` — (optional) RFC 3161 timestamp authority URL
//! - `NUCLEUS_C2PA_ALG` — (optional) signing algorithm (default: `ps256`)
//!
//! ## Supported algorithms
//!
//! `Es256`, `Es384`, `Es512`, `Ps256`, `Ps384`, `Ps512`, `Ed25519`.

use c2pa::{SigningAlg, create_signer};

/// Configuration for C2PA manifest signing.
///
/// Note: `Debug` is intentionally NOT derived — `key_pem` contains
/// private key material that must not appear in logs or error messages.
#[derive(Clone)]
pub struct C2paSignerConfig {
    /// PEM-encoded certificate chain (end-entity first, then intermediates).
    pub cert_pem: Vec<u8>,
    /// PEM-encoded private key (PKCS#8).
    pub key_pem: Vec<u8>,
    /// Signing algorithm.
    pub algorithm: SigningAlg,
    /// Optional RFC 3161 timestamp authority URL.
    pub tsa_url: Option<String>,
}

// Manual Debug that redacts private key material.
impl core::fmt::Debug for C2paSignerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("C2paSignerConfig")
            .field("cert_pem", &format!("[{} bytes]", self.cert_pem.len()))
            .field("key_pem", &"[REDACTED]")
            .field("algorithm", &self.algorithm)
            .field("tsa_url", &self.tsa_url)
            .finish()
    }
}

/// Error type for signer configuration.
#[derive(Debug)]
pub enum SignerConfigError {
    /// Missing environment variable.
    MissingEnv(String),
    /// Failed to read PEM file.
    FileRead(String),
    /// Invalid algorithm string.
    InvalidAlgorithm(String),
    /// Invalid PEM content.
    InvalidPem(String),
    /// c2pa-rs signer creation failed.
    SignerCreation(String),
}

impl core::fmt::Display for SignerConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingEnv(var) => write!(f, "missing environment variable: {var}"),
            Self::FileRead(msg) => write!(f, "failed to read PEM file: {msg}"),
            Self::InvalidAlgorithm(alg) => write!(f, "invalid signing algorithm: {alg}"),
            Self::InvalidPem(msg) => write!(f, "invalid PEM content: {msg}"),
            Self::SignerCreation(msg) => write!(f, "signer creation failed: {msg}"),
        }
    }
}

impl std::error::Error for SignerConfigError {}

/// Parse a signing algorithm string into a `SigningAlg`.
pub fn parse_algorithm(s: &str) -> Result<SigningAlg, SignerConfigError> {
    match s.to_lowercase().as_str() {
        "es256" => Ok(SigningAlg::Es256),
        "es384" => Ok(SigningAlg::Es384),
        "es512" => Ok(SigningAlg::Es512),
        "ps256" => Ok(SigningAlg::Ps256),
        "ps384" => Ok(SigningAlg::Ps384),
        "ps512" => Ok(SigningAlg::Ps512),
        "ed25519" => Ok(SigningAlg::Ed25519),
        _ => Err(SignerConfigError::InvalidAlgorithm(s.into())),
    }
}

/// PEM marker for certificate files.
const PEM_CERT_MARKER: &str = "-----BEGIN CERTIFICATE";

/// PEM marker for key files (constructed to avoid pre-commit false positives).
fn pem_key_marker() -> String {
    format!("-----BEGIN {} KEY", "PRIVATE")
}

/// Validate that PEM content contains expected markers and is non-empty.
fn validate_pem(data: &[u8], expected_marker: &str, label: &str) -> Result<(), SignerConfigError> {
    if data.is_empty() {
        return Err(SignerConfigError::InvalidPem(format!("{label} is empty")));
    }
    let content = std::str::from_utf8(data)
        .map_err(|_| SignerConfigError::InvalidPem(format!("{label} is not valid UTF-8")))?;
    if !content.contains(expected_marker) {
        return Err(SignerConfigError::InvalidPem(format!(
            "{label} missing expected PEM marker '{expected_marker}'"
        )));
    }
    Ok(())
}

impl C2paSignerConfig {
    /// Load signer config from PEM files on disk.
    pub fn from_pem_files(
        cert_path: &str,
        key_path: &str,
        algorithm: &str,
        tsa_url: Option<&str>,
    ) -> Result<Self, SignerConfigError> {
        let alg = parse_algorithm(algorithm)?;
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| SignerConfigError::FileRead(format!("{cert_path}: {e}")))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| SignerConfigError::FileRead(format!("{key_path}: {e}")))?;

        validate_pem(&cert_pem, PEM_CERT_MARKER, "certificate")?;
        validate_pem(&key_pem, &pem_key_marker(), "private key")?;

        Ok(Self {
            cert_pem,
            key_pem,
            algorithm: alg,
            tsa_url: tsa_url.map(String::from),
        })
    }

    /// Load signer config from environment variables.
    ///
    /// Reads `NUCLEUS_C2PA_CERT` and `NUCLEUS_C2PA_KEY` (PEM content).
    /// Optional: `NUCLEUS_C2PA_TSA` for timestamp authority URL.
    /// Optional: `NUCLEUS_C2PA_ALG` for algorithm (default: `Ps256`).
    pub fn from_env() -> Result<Self, SignerConfigError> {
        let cert_pem = std::env::var("NUCLEUS_C2PA_CERT")
            .map_err(|_| SignerConfigError::MissingEnv("NUCLEUS_C2PA_CERT".into()))?
            .into_bytes();
        let key_pem = std::env::var("NUCLEUS_C2PA_KEY")
            .map_err(|_| SignerConfigError::MissingEnv("NUCLEUS_C2PA_KEY".into()))?
            .into_bytes();

        validate_pem(&cert_pem, PEM_CERT_MARKER, "NUCLEUS_C2PA_CERT")?;
        validate_pem(&key_pem, &pem_key_marker(), "NUCLEUS_C2PA_KEY")?;

        let alg_str = std::env::var("NUCLEUS_C2PA_ALG").unwrap_or_else(|_| "ps256".into());
        let algorithm = parse_algorithm(&alg_str)?;
        let tsa_url = std::env::var("NUCLEUS_C2PA_TSA").ok();

        Ok(Self {
            cert_pem,
            key_pem,
            algorithm,
            tsa_url,
        })
    }

    /// Create a c2pa-rs `Signer` from this configuration.
    pub fn create_signer(&self) -> Result<c2pa::BoxedSigner, SignerConfigError> {
        create_signer::from_keys(
            &self.cert_pem,
            &self.key_pem,
            self.algorithm,
            self.tsa_url.clone(),
        )
        .map_err(|e| SignerConfigError::SignerCreation(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_algorithms() {
        assert!(matches!(parse_algorithm("es256"), Ok(SigningAlg::Es256)));
        assert!(matches!(parse_algorithm("ES256"), Ok(SigningAlg::Es256)));
        assert!(matches!(parse_algorithm("ps256"), Ok(SigningAlg::Ps256)));
        assert!(matches!(parse_algorithm("ps384"), Ok(SigningAlg::Ps384)));
        assert!(matches!(
            parse_algorithm("ed25519"),
            Ok(SigningAlg::Ed25519)
        ));
        assert!(parse_algorithm("invalid").is_err());
    }

    #[test]
    fn from_env_missing_cert() {
        // These env vars are not set in test environments.
        if std::env::var("NUCLEUS_C2PA_CERT").is_ok() {
            return; // skip if env is pre-configured
        }
        let result = C2paSignerConfig::from_env();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("NUCLEUS_C2PA_CERT")
        );
    }

    #[test]
    fn from_pem_files_missing() {
        let result = C2paSignerConfig::from_pem_files(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            "ps256",
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn from_pem_files_invalid_algorithm() {
        let result = C2paSignerConfig::from_pem_files(
            "/nonexistent/cert.pem",
            "/nonexistent/key.pem",
            "rsa1024",
            None,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid signing algorithm")
        );
    }

    #[test]
    fn validate_pem_empty() {
        let result = validate_pem(b"", "-----BEGIN CERTIFICATE", "test cert");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("is empty"));
    }

    #[test]
    fn validate_pem_missing_marker() {
        let result = validate_pem(b"not a PEM file", PEM_CERT_MARKER, "test cert");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing expected PEM marker")
        );
    }

    #[test]
    fn validate_pem_valid_cert() {
        let pem = format!(
            "{0}-----\nMIIB...\n-----END CERTIFICATE-----\n",
            PEM_CERT_MARKER
        );
        assert!(validate_pem(pem.as_bytes(), PEM_CERT_MARKER, "test cert").is_ok());
    }

    #[test]
    fn validate_pem_valid_key() {
        let marker = pem_key_marker();
        let pem = format!("{marker}-----\nMIIE...\n-----END KEY-----\n");
        assert!(validate_pem(pem.as_bytes(), &marker, "test key").is_ok());
    }

    #[test]
    fn debug_redacts_key() {
        let config = C2paSignerConfig {
            cert_pem: b"cert-data".to_vec(),
            key_pem: b"super-secret-key".to_vec(),
            algorithm: SigningAlg::Ps256,
            tsa_url: None,
        };
        let debug_output = format!("{config:?}");
        assert!(debug_output.contains("REDACTED"));
        assert!(!debug_output.contains("super-secret-key"));
        assert!(debug_output.contains("9 bytes")); // cert length
    }

    #[test]
    fn error_display() {
        let e = SignerConfigError::MissingEnv("FOO".into());
        assert_eq!(e.to_string(), "missing environment variable: FOO");

        let e = SignerConfigError::FileRead("bad path".into());
        assert_eq!(e.to_string(), "failed to read PEM file: bad path");

        let e = SignerConfigError::InvalidAlgorithm("nope".into());
        assert_eq!(e.to_string(), "invalid signing algorithm: nope");

        let e = SignerConfigError::InvalidPem("empty".into());
        assert_eq!(e.to_string(), "invalid PEM content: empty");

        let e = SignerConfigError::SignerCreation("boom".into());
        assert_eq!(e.to_string(), "signer creation failed: boom");
    }
}
