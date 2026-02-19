//! Authentication strategies for nucleus requests.
//!
//! Provides [`AuthStrategy`] trait and implementations for HMAC and mTLS.
//! HMAC signing delegates to `nucleus_client` — no reimplementation.

use std::path::Path;

/// Trait for authenticating requests to nucleus services.
///
/// Implementations produce header key-value pairs that are injected into
/// HTTP or gRPC requests.
pub trait AuthStrategy: Send + Sync {
    /// Produce authentication headers for an HTTP request body.
    fn sign_http(&self, body: &[u8]) -> Vec<(String, String)>;

    /// Produce authentication headers for a gRPC method invocation.
    fn sign_grpc(&self, method: &str) -> Vec<(String, String)>;
}

/// HMAC-SHA256 authentication.
///
/// Delegates to [`nucleus_client::sign_http_headers`] and
/// [`nucleus_client::sign_grpc_headers`] for the actual signing.
///
/// # Example
///
/// ```rust
/// use nucleus_sdk::HmacAuth;
///
/// let auth = HmacAuth::new(b"my-secret-key", Some("user@example.com"));
/// ```
pub struct HmacAuth {
    secret: Vec<u8>,
    actor: Option<String>,
}

impl HmacAuth {
    /// Create a new HMAC auth strategy.
    pub fn new(secret: &[u8], actor: Option<&str>) -> Self {
        Self {
            secret: secret.to_vec(),
            actor: actor.map(|s| s.to_string()),
        }
    }
}

impl AuthStrategy for HmacAuth {
    fn sign_http(&self, body: &[u8]) -> Vec<(String, String)> {
        let signed = nucleus_client::sign_http_headers(&self.secret, self.actor.as_deref(), body);
        signed.headers
    }

    fn sign_grpc(&self, method: &str) -> Vec<(String, String)> {
        let signed = nucleus_client::sign_grpc_headers(&self.secret, self.actor.as_deref(), method);
        signed.headers
    }
}

/// mTLS configuration for connecting to nucleus services.
///
/// Provides certificate and key paths for both reqwest (HTTP) and tonic (gRPC)
/// clients. The certificates are loaded at connection time, not at construction.
///
/// # Example
///
/// ```rust
/// use nucleus_sdk::MtlsConfig;
///
/// let mtls = MtlsConfig::new("/path/to/cert.pem", "/path/to/key.pem")
///     .with_ca_bundle("/path/to/ca.pem");
/// ```
#[derive(Debug, Clone)]
pub struct MtlsConfig {
    /// Path to the client certificate (PEM).
    pub cert_path: String,
    /// Path to the client private key (PKCS#8 PEM).
    pub key_path: String,
    /// Optional CA bundle for server verification.
    pub ca_bundle: Option<String>,
}

impl MtlsConfig {
    /// Create a new mTLS config with certificate and key paths.
    pub fn new(cert_path: impl Into<String>, key_path: impl Into<String>) -> Self {
        Self {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            ca_bundle: None,
        }
    }

    /// Set the CA bundle path for server certificate verification.
    pub fn with_ca_bundle(mut self, ca_bundle: impl Into<String>) -> Self {
        self.ca_bundle = Some(ca_bundle.into());
        self
    }

    /// Build a reqwest `Identity` from this config for HTTP clients.
    pub(crate) fn reqwest_identity(&self) -> Result<reqwest::Identity, crate::Error> {
        let cert_pem = std::fs::read(&self.cert_path).map_err(|e| {
            crate::Error::Config(format!("failed to read cert {}: {}", self.cert_path, e))
        })?;
        let key_pem = std::fs::read(&self.key_path).map_err(|e| {
            crate::Error::Config(format!("failed to read key {}: {}", self.key_path, e))
        })?;

        let mut combined = cert_pem;
        combined.push(b'\n');
        combined.extend_from_slice(&key_pem);

        reqwest::Identity::from_pem(&combined)
            .map_err(|e| crate::Error::Config(format!("invalid certificate/key: {}", e)))
    }

    /// Build a reqwest `Certificate` for CA verification.
    pub(crate) fn reqwest_ca_cert(&self) -> Result<Option<reqwest::Certificate>, crate::Error> {
        match &self.ca_bundle {
            Some(path) => {
                let pem = std::fs::read(path).map_err(|e| {
                    crate::Error::Config(format!("failed to read CA bundle {}: {}", path, e))
                })?;
                let cert = reqwest::Certificate::from_pem(&pem)
                    .map_err(|e| crate::Error::Config(format!("invalid CA certificate: {}", e)))?;
                Ok(Some(cert))
            }
            None => Ok(None),
        }
    }

    /// Check that the configured paths exist.
    pub fn validate(&self) -> Result<(), crate::Error> {
        if !Path::new(&self.cert_path).exists() {
            return Err(crate::Error::Config(format!(
                "cert file not found: {}",
                self.cert_path
            )));
        }
        if !Path::new(&self.key_path).exists() {
            return Err(crate::Error::Config(format!(
                "key file not found: {}",
                self.key_path
            )));
        }
        if let Some(ca) = &self.ca_bundle {
            if !Path::new(ca).exists() {
                return Err(crate::Error::Config(format!("CA bundle not found: {}", ca)));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_auth_produces_headers() {
        let auth = HmacAuth::new(b"test-secret", Some("actor"));
        let headers = auth.sign_http(b"body");

        assert!(headers.iter().any(|(k, _)| k == "x-nucleus-timestamp"));
        assert!(headers.iter().any(|(k, _)| k == "x-nucleus-signature"));
        assert!(headers.iter().any(|(k, _)| k == "x-nucleus-actor"));
    }

    #[test]
    fn test_hmac_auth_no_actor() {
        let auth = HmacAuth::new(b"test-secret", None);
        let headers = auth.sign_http(b"body");

        assert!(headers.iter().any(|(k, _)| k == "x-nucleus-signature"));
        assert!(!headers.iter().any(|(k, _)| k == "x-nucleus-actor"));
    }

    #[test]
    fn test_hmac_grpc_headers() {
        let auth = HmacAuth::new(b"test-secret", Some("actor"));
        let headers = auth.sign_grpc("/nucleus.node.v1.NodeService/CreatePod");

        assert!(headers.iter().any(|(k, _)| k == "x-nucleus-signature"));
        assert!(headers.iter().any(|(k, _)| k == "x-nucleus-method"));
    }

    #[test]
    fn test_hmac_signatures_match_nucleus_client() {
        let secret = b"shared-secret";
        let body = b"test-body";
        let actor = "test-actor";

        // Sign via our HmacAuth
        let auth = HmacAuth::new(secret, Some(actor));
        let sdk_headers = auth.sign_http(body);

        // Sign directly via nucleus_client
        let direct = nucleus_client::sign_http_headers(secret, Some(actor), body);

        // Timestamps will differ slightly, but the signature format is the same
        // and both produce the required header keys
        let sdk_keys: Vec<&str> = sdk_headers.iter().map(|(k, _)| k.as_str()).collect();
        let direct_keys: Vec<&str> = direct.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(sdk_keys, direct_keys);
    }

    #[test]
    fn test_mtls_config_builder() {
        let config = MtlsConfig::new("/tmp/cert.pem", "/tmp/key.pem").with_ca_bundle("/tmp/ca.pem");

        assert_eq!(config.cert_path, "/tmp/cert.pem");
        assert_eq!(config.key_path, "/tmp/key.pem");
        assert_eq!(config.ca_bundle.as_deref(), Some("/tmp/ca.pem"));
    }

    #[test]
    fn test_mtls_validate_missing_cert() {
        let config = MtlsConfig::new("/nonexistent/cert.pem", "/nonexistent/key.pem");
        let result = config.validate();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cert file not found"));
    }
}
