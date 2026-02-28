//! SPIFFE identity types and parsing.
//!
//! This module provides types for representing SPIFFE identities (SPIFFEIDs)
//! as defined in the [SPIFFE specification](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/).
//!
//! # SPIFFE URI Format
//!
//! A SPIFFE ID is a URI with the scheme `spiffe://` followed by a trust domain
//! and a workload path. For Kubernetes-style workloads, the path typically
//! contains namespace and service account information:
//!
//! ```text
//! spiffe://trust-domain/ns/namespace/sa/service-account
//! ```
//!
//! # Example
//!
//! ```
//! use nucleus_identity::Identity;
//!
//! let id = Identity::new("nucleus.local", "default", "my-service");
//! assert_eq!(id.to_spiffe_uri(), "spiffe://nucleus.local/ns/default/sa/my-service");
//!
//! let parsed = Identity::from_spiffe_uri("spiffe://nucleus.local/ns/default/sa/my-service").unwrap();
//! assert_eq!(parsed.trust_domain(), "nucleus.local");
//! ```

use crate::{Error, Result};
use std::fmt;

/// A SPIFFE identity representing a workload.
///
/// Contains the trust domain, namespace, and service account that uniquely
/// identify a workload within a SPIFFE trust domain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identity {
    trust_domain: String,
    namespace: String,
    service_account: String,
}

impl Identity {
    /// Creates a new identity with the given components.
    ///
    /// # Arguments
    ///
    /// * `trust_domain` - The SPIFFE trust domain (e.g., "nucleus.local")
    /// * `namespace` - The workload namespace (e.g., "default")
    /// * `service_account` - The service account name (e.g., "my-service")
    ///
    /// # Panics
    ///
    /// Panics if any component is empty or contains invalid characters.
    /// For fallible construction, use `Identity::try_new()` instead.
    pub fn new(
        trust_domain: impl Into<String>,
        namespace: impl Into<String>,
        service_account: impl Into<String>,
    ) -> Self {
        Self::try_new(trust_domain, namespace, service_account)
            .expect("invalid identity components")
    }

    /// Creates a new identity with validation, returning an error if invalid.
    ///
    /// # Arguments
    ///
    /// * `trust_domain` - The SPIFFE trust domain (e.g., "nucleus.local")
    /// * `namespace` - The workload namespace (e.g., "default")
    /// * `service_account` - The service account name (e.g., "my-service")
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any component is empty
    /// - Trust domain contains invalid characters (only alphanumeric, hyphen, dot allowed)
    /// - Namespace or service account contain path traversal sequences
    pub fn try_new(
        trust_domain: impl Into<String>,
        namespace: impl Into<String>,
        service_account: impl Into<String>,
    ) -> Result<Self> {
        let trust_domain = trust_domain.into();
        let namespace = namespace.into();
        let service_account = service_account.into();

        // Validate trust domain
        if trust_domain.is_empty() {
            return Err(Error::InvalidSpiffeUri("empty trust domain".to_string()));
        }
        if !trust_domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(Error::InvalidSpiffeUri(format!(
                "invalid trust domain characters: {trust_domain}"
            )));
        }

        // Validate namespace
        if namespace.is_empty() {
            return Err(Error::InvalidSpiffeUri("empty namespace".to_string()));
        }
        Self::validate_path_component(&namespace, "namespace")?;

        // Validate service account
        if service_account.is_empty() {
            return Err(Error::InvalidSpiffeUri("empty service account".to_string()));
        }
        Self::validate_path_component(&service_account, "service account")?;

        Ok(Self {
            trust_domain,
            namespace,
            service_account,
        })
    }

    /// Validates a path component per SPIFFE specification.
    ///
    /// Per https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md:
    /// - Path segments MUST contain only letters, numbers, dots, dashes, and underscores
    /// - No percent-encoded characters
    /// - No relative path modifiers (`.` or `..`)
    /// - No empty segments
    /// - Max 2048 bytes for entire SPIFFE ID
    fn validate_path_component(value: &str, name: &str) -> Result<()> {
        // Check maximum length (allow reasonable segment length)
        if value.len() > 253 {
            return Err(Error::InvalidSpiffeUri(format!(
                "{name} exceeds maximum length (253 bytes): {} bytes",
                value.len()
            )));
        }

        // Reject relative path modifiers (standalone `.` or `..`)
        // Per SPIFFE spec, these are not allowed as path segments
        // Note: `a..b` is valid (dots within segment), but `..` alone is not
        if value == "." || value == ".." {
            return Err(Error::InvalidSpiffeUri(format!(
                "{name} cannot be a relative path modifier: {value}"
            )));
        }

        // Reject absolute paths
        if value.starts_with('/') || value.ends_with('/') {
            return Err(Error::InvalidSpiffeUri(format!(
                "{name} cannot start or end with slash: {value}"
            )));
        }

        // Reject percent-encoded characters (URL encoding like %2e)
        if value.contains('%') {
            return Err(Error::InvalidSpiffeUri(format!(
                "{name} contains percent-encoded characters (not allowed): {value}"
            )));
        }

        // SPIFFE spec: path segments MUST contain only [a-zA-Z0-9.-_]
        // This naturally rejects:
        // - SQL injection characters (', ;, --, etc.)
        // - LDAP injection characters (*, |, &, etc.)
        // - Null bytes
        // - Control characters
        // - Unicode characters
        // - Slashes within segments
        for c in value.chars() {
            if !c.is_ascii_alphanumeric() && c != '.' && c != '-' && c != '_' {
                return Err(Error::InvalidSpiffeUri(format!(
                    "{name} contains invalid character '{}' (only a-zA-Z0-9.-_ allowed): {value}",
                    if c.is_control() {
                        format!("\\x{:02x}", c as u32)
                    } else {
                        c.to_string()
                    }
                )));
            }
        }

        // Additional check: cannot start with a dot (hidden file convention)
        if value.starts_with('.') {
            return Err(Error::InvalidSpiffeUri(format!(
                "{name} cannot start with dot: {value}"
            )));
        }

        Ok(())
    }

    /// Creates an identity for a pod using its UUID.
    ///
    /// This is useful when pods don't have a service account and need
    /// a unique identity based on their pod ID.
    ///
    /// # Panics
    ///
    /// Panics if the trust_domain or pod_id contain invalid characters.
    /// For fallible construction, use `Identity::try_new()` with "pods" as namespace.
    pub fn for_pod(trust_domain: impl Into<String>, pod_id: impl fmt::Display) -> Self {
        Self::try_new(trust_domain, "pods", pod_id.to_string())
            .expect("invalid pod identity components")
    }

    /// Parses a SPIFFE URI into an Identity.
    ///
    /// Expects the format: `spiffe://trust-domain/ns/namespace/sa/service-account`
    ///
    /// # Errors
    ///
    /// Returns an error if the URI is malformed or doesn't follow the expected format.
    pub fn from_spiffe_uri(uri: &str) -> Result<Self> {
        // Must start with spiffe://
        let path = uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| Error::InvalidSpiffeUri("must start with spiffe://".to_string()))?;

        // Split trust domain from path
        let (trust_domain, workload_path) = path
            .split_once('/')
            .ok_or_else(|| Error::InvalidSpiffeUri("missing workload path".to_string()))?;

        if trust_domain.is_empty() {
            return Err(Error::InvalidSpiffeUri("empty trust domain".to_string()));
        }

        // Validate trust domain (no special chars except hyphen and dot)
        if !trust_domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err(Error::InvalidSpiffeUri(format!(
                "invalid trust domain: {trust_domain}"
            )));
        }

        // Parse workload path: ns/<namespace>/sa/<service-account>
        let parts: Vec<&str> = workload_path.split('/').collect();

        if parts.len() >= 4 && parts[0] == "ns" && parts[2] == "sa" {
            let namespace = parts[1];
            let service_account = parts[3..].join("/"); // Allow slashes in SA name

            if namespace.is_empty() {
                return Err(Error::InvalidSpiffeUri("empty namespace".to_string()));
            }
            if service_account.is_empty() {
                return Err(Error::InvalidSpiffeUri("empty service account".to_string()));
            }

            Ok(Self {
                trust_domain: trust_domain.to_string(),
                namespace: namespace.to_string(),
                service_account,
            })
        } else {
            // Try alternative format: just a path identifier
            // spiffe://trust-domain/workload-id
            if parts.len() == 1 && !parts[0].is_empty() {
                Ok(Self {
                    trust_domain: trust_domain.to_string(),
                    namespace: "default".to_string(),
                    service_account: parts[0].to_string(),
                })
            } else {
                Err(Error::InvalidSpiffeUri(format!(
                    "unexpected path format: {workload_path}"
                )))
            }
        }
    }

    /// Returns the SPIFFE URI representation of this identity.
    pub fn to_spiffe_uri(&self) -> String {
        format!(
            "spiffe://{}/ns/{}/sa/{}",
            self.trust_domain, self.namespace, self.service_account
        )
    }

    /// Returns the trust domain.
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    /// Returns the namespace.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Returns the service account.
    pub fn service_account(&self) -> &str {
        &self.service_account
    }

    /// Checks if this identity belongs to the given trust domain.
    pub fn is_in_trust_domain(&self, trust_domain: &str) -> bool {
        self.trust_domain == trust_domain
    }

    /// Convert this SPIFFE identity to a `did:web` identifier.
    ///
    /// The mapping is deterministic and injective: the service account becomes
    /// the subdomain of the trust domain.
    ///
    /// ```text
    /// spiffe://groundtruth.dev/ns/apps/sa/music-app  →  did:web:music-app.groundtruth.dev
    /// ```
    ///
    /// # Example
    ///
    /// ```
    /// use nucleus_identity::Identity;
    ///
    /// let id = Identity::new("groundtruth.dev", "apps", "music-app");
    /// assert_eq!(id.to_did_web(), "did:web:music-app.groundtruth.dev");
    /// ```
    pub fn to_did_web(&self) -> String {
        format!("did:web:{}.{}", self.service_account, self.trust_domain)
    }

    /// Parse a `did:web` identifier back to a SPIFFE identity.
    ///
    /// The first subdomain label is the service account, the remainder
    /// is the trust domain.
    ///
    /// ```text
    /// did:web:music-app.groundtruth.dev  →  spiffe://groundtruth.dev/ns/{namespace}/sa/music-app
    /// ```
    ///
    /// # Arguments
    ///
    /// * `did` - The `did:web` identifier to parse.
    /// * `namespace` - The SPIFFE namespace (cannot be inferred from the DID).
    ///
    /// # Errors
    ///
    /// Returns an error if the DID doesn't start with `did:web:` or has
    /// no subdomain separator.
    pub fn from_did_web(did: &str, namespace: &str) -> Result<Self> {
        let method_specific = did
            .strip_prefix("did:web:")
            .ok_or_else(|| Error::InvalidSpiffeUri("DID must start with did:web:".into()))?;

        let dot_pos = method_specific.find('.').ok_or_else(|| {
            Error::InvalidSpiffeUri("did:web must have subdomain.domain format".into())
        })?;

        let app_name = &method_specific[..dot_pos];
        let trust_domain = &method_specific[dot_pos + 1..];

        if app_name.is_empty() {
            return Err(Error::InvalidSpiffeUri("empty subdomain in did:web".into()));
        }
        if trust_domain.is_empty() {
            return Err(Error::InvalidSpiffeUri("empty domain in did:web".into()));
        }

        Self::try_new(trust_domain, namespace, app_name)
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_spiffe_uri())
    }
}

impl std::str::FromStr for Identity {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_spiffe_uri(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_identity() {
        let id = Identity::new("nucleus.local", "default", "my-service");
        assert_eq!(id.trust_domain(), "nucleus.local");
        assert_eq!(id.namespace(), "default");
        assert_eq!(id.service_account(), "my-service");
    }

    #[test]
    fn test_for_pod() {
        let id = Identity::for_pod("nucleus.local", "abc-123");
        assert_eq!(id.trust_domain(), "nucleus.local");
        assert_eq!(id.namespace(), "pods");
        assert_eq!(id.service_account(), "abc-123");
    }

    #[test]
    fn test_to_spiffe_uri() {
        let id = Identity::new("nucleus.local", "production", "api-server");
        assert_eq!(
            id.to_spiffe_uri(),
            "spiffe://nucleus.local/ns/production/sa/api-server"
        );
    }

    #[test]
    fn test_from_spiffe_uri_valid() {
        let id =
            Identity::from_spiffe_uri("spiffe://nucleus.local/ns/default/sa/my-service").unwrap();
        assert_eq!(id.trust_domain(), "nucleus.local");
        assert_eq!(id.namespace(), "default");
        assert_eq!(id.service_account(), "my-service");
    }

    #[test]
    fn test_from_spiffe_uri_with_complex_trust_domain() {
        let id = Identity::from_spiffe_uri(
            "spiffe://cluster-1.nucleus.example.com/ns/kube-system/sa/coredns",
        )
        .unwrap();
        assert_eq!(id.trust_domain(), "cluster-1.nucleus.example.com");
        assert_eq!(id.namespace(), "kube-system");
        assert_eq!(id.service_account(), "coredns");
    }

    #[test]
    fn test_from_spiffe_uri_simple_path() {
        let id = Identity::from_spiffe_uri("spiffe://nucleus.local/my-workload").unwrap();
        assert_eq!(id.trust_domain(), "nucleus.local");
        assert_eq!(id.namespace(), "default");
        assert_eq!(id.service_account(), "my-workload");
    }

    #[test]
    fn test_from_spiffe_uri_missing_scheme() {
        let err = Identity::from_spiffe_uri("nucleus.local/ns/default/sa/my-service").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    #[test]
    fn test_from_spiffe_uri_empty_trust_domain() {
        let err = Identity::from_spiffe_uri("spiffe:///ns/default/sa/my-service").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    #[test]
    fn test_from_spiffe_uri_invalid_trust_domain() {
        let err = Identity::from_spiffe_uri("spiffe://invalid_domain/ns/default/sa/my-service")
            .unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    #[test]
    fn test_from_spiffe_uri_empty_namespace() {
        let err =
            Identity::from_spiffe_uri("spiffe://nucleus.local/ns//sa/my-service").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    #[test]
    fn test_from_spiffe_uri_empty_service_account() {
        let err = Identity::from_spiffe_uri("spiffe://nucleus.local/ns/default/sa/").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    #[test]
    fn test_roundtrip() {
        let original = Identity::new("nucleus.local", "default", "my-service");
        let uri = original.to_spiffe_uri();
        let parsed = Identity::from_spiffe_uri(&uri).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_display() {
        let id = Identity::new("nucleus.local", "default", "my-service");
        assert_eq!(
            format!("{id}"),
            "spiffe://nucleus.local/ns/default/sa/my-service"
        );
    }

    #[test]
    fn test_from_str() {
        let id: Identity = "spiffe://nucleus.local/ns/default/sa/my-service"
            .parse()
            .unwrap();
        assert_eq!(id.trust_domain(), "nucleus.local");
    }

    #[test]
    fn test_is_in_trust_domain() {
        let id = Identity::new("nucleus.local", "default", "my-service");
        assert!(id.is_in_trust_domain("nucleus.local"));
        assert!(!id.is_in_trust_domain("other.local"));
    }

    #[test]
    fn test_equality() {
        let id1 = Identity::new("nucleus.local", "default", "my-service");
        let id2 = Identity::new("nucleus.local", "default", "my-service");
        let id3 = Identity::new("nucleus.local", "default", "other-service");
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Identity::new("nucleus.local", "default", "my-service"));
        set.insert(Identity::new("nucleus.local", "default", "my-service"));
        assert_eq!(set.len(), 1);
    }

    // ── did:web mapping ─────────────────────────────────────────────────

    #[test]
    fn test_to_did_web() {
        let id = Identity::new("groundtruth.dev", "apps", "music-app");
        assert_eq!(id.to_did_web(), "did:web:music-app.groundtruth.dev");
    }

    #[test]
    fn test_to_did_web_complex_domain() {
        let id = Identity::new("cluster-1.nucleus.example.com", "prod", "api-server");
        assert_eq!(
            id.to_did_web(),
            "did:web:api-server.cluster-1.nucleus.example.com"
        );
    }

    #[test]
    fn test_from_did_web() {
        let id = Identity::from_did_web("did:web:music-app.groundtruth.dev", "apps").unwrap();
        assert_eq!(id.trust_domain(), "groundtruth.dev");
        assert_eq!(id.namespace(), "apps");
        assert_eq!(id.service_account(), "music-app");
    }

    #[test]
    fn test_from_did_web_complex_domain() {
        let id = Identity::from_did_web("did:web:api-server.cluster-1.nucleus.example.com", "prod")
            .unwrap();
        assert_eq!(id.trust_domain(), "cluster-1.nucleus.example.com");
        assert_eq!(id.service_account(), "api-server");
    }

    #[test]
    fn test_did_web_roundtrip() {
        let original = Identity::new("groundtruth.dev", "apps", "music-app");
        let did = original.to_did_web();
        let parsed = Identity::from_did_web(&did, "apps").unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_from_did_web_invalid_prefix() {
        let err = Identity::from_did_web("did:key:abc123", "default").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    #[test]
    fn test_from_did_web_no_subdomain() {
        let err = Identity::from_did_web("did:web:example", "default").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    #[test]
    fn test_from_did_web_empty_subdomain() {
        let err = Identity::from_did_web("did:web:.example.com", "default").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }
}
