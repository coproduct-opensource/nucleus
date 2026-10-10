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

/// The SPIFFE ID specification's bound on a whole ID, in bytes.
pub(crate) const MAX_SPIFFE_ID_LEN: usize = 2048;

/// The SPIFFE ID specification's bound on a trust domain, in bytes.
pub(crate) const MAX_TRUST_DOMAIN_LEN: usize = 255;

/// A trust domain as this taxonomy admits it: 1..=255 bytes of `[a-z0-9.-]`.
///
/// The SPIFFE grammar, lowercase only (an uppercase trust domain is refused,
/// not folded), less `_`: every trust domain nucleus issues for is also a DNS
/// name. No port, no userinfo, nothing else.
pub(crate) fn validate_trust_domain(trust_domain: &str) -> Result<()> {
    if trust_domain.is_empty() || trust_domain.len() > MAX_TRUST_DOMAIN_LEN {
        return Err(Error::InvalidSpiffeUri(format!(
            "trust domain must be 1..={MAX_TRUST_DOMAIN_LEN} bytes, got {}",
            trust_domain.len()
        )));
    }
    if !trust_domain
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return Err(Error::InvalidSpiffeUri(format!(
            "invalid trust domain characters (only a-z, 0-9, '.', '-'): {trust_domain}"
        )));
    }
    Ok(())
}

/// One SPIFFE path segment: non-empty `[A-Za-z0-9._-]`, never `.` or `..`.
pub(crate) fn validate_spiffe_segment(segment: &str) -> Result<()> {
    if segment.is_empty() {
        return Err(Error::InvalidSpiffeUri(
            "empty path segment (a doubled or trailing '/')".to_string(),
        ));
    }
    if segment == "." || segment == ".." {
        return Err(Error::InvalidSpiffeUri(format!(
            "dot segment {segment:?}: SPIFFE IDs never contain '.' or '..'"
        )));
    }
    if !segment
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return Err(Error::InvalidSpiffeUri(format!(
            "path segment {segment:?} has characters outside [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

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

    /// The identity a node's own certificate carries:
    /// `spiffe://<trust_domain>/ns/system/sa/node`.
    ///
    /// Stated once, here, because two parties need it: the node mints its
    /// certificate under it, and every client reaching the node accepts
    /// exactly it (`node_tls`).
    ///
    /// # Errors
    ///
    /// When `trust_domain` is not a valid trust domain.
    pub fn node(trust_domain: impl Into<String>) -> Result<Self> {
        Self::try_new(trust_domain, "system", "node")
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

        validate_trust_domain(&trust_domain)?;

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
        // The one SPIFFE ID grammar (`docs/spiffe-taxonomy.md`): every spelling
        // other than the canonical one is refused, never normalised, so no two
        // URIs can name one `Identity`.
        if uri.len() > MAX_SPIFFE_ID_LEN {
            return Err(Error::InvalidSpiffeUri(format!(
                "SPIFFE ID is {} bytes; at most {MAX_SPIFFE_ID_LEN} allowed",
                uri.len()
            )));
        }
        let path = uri
            .strip_prefix("spiffe://")
            .ok_or_else(|| Error::InvalidSpiffeUri("must start with spiffe://".to_string()))?;

        let (trust_domain, workload_path) = path
            .split_once('/')
            .ok_or_else(|| Error::InvalidSpiffeUri("missing workload path".to_string()))?;
        validate_trust_domain(trust_domain)?;

        let parts: Vec<&str> = workload_path.split('/').collect();
        for part in &parts {
            validate_spiffe_segment(part)?;
        }

        // `ns/<namespace>/sa/<account>[/<segment>...]`: segments below the
        // account belong to it (a CI identity's `owner/repo/refs/<ref>`, a
        // lineage `/call/...`). Any other shape is not a workload identity
        // here, and is refused rather than given a namespace: an `Identity`
        // is a function of exactly one URI.
        match parts.as_slice() {
            ["ns", namespace, "sa", account, below @ ..] => {
                let mut service_account = (*account).to_string();
                for segment in below {
                    service_account.push('/');
                    service_account.push_str(segment);
                }
                Ok(Self {
                    trust_domain: trust_domain.to_string(),
                    namespace: (*namespace).to_string(),
                    service_account,
                })
            }
            _ => Err(Error::InvalidSpiffeUri(format!(
                "not a workload identity: the path must be ns/<namespace>/sa/<account>, got {workload_path:?}"
            ))),
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

    /// Convert the complete SPIFFE identity to a path-based `did:web`.
    ///
    /// Namespace and every service-account segment remain distinct. Dots in
    /// an account are path characters, never trust-domain separators.
    ///
    /// ```
    /// use nucleus_identity::Identity;
    /// let id = Identity::new("groundtruth.dev", "apps", "music-app");
    /// assert_eq!(id.to_did_web(), "did:web:groundtruth.dev:ns:apps:sa:music-app");
    /// ```
    pub fn to_did_web(&self) -> String {
        format!(
            "did:web:{}:ns:{}:sa:{}",
            self.trust_domain,
            self.namespace,
            self.service_account.replace('/', ":")
        )
    }

    /// Parse the canonical path-based DID and require the expected namespace.
    ///
    /// The former subdomain mapping discarded the namespace and is refused:
    /// guessing it from caller input would retain the identity collision.
    /// This parses an identifier only; it does not authenticate a DID document.
    pub fn from_did_web(did: &str, namespace: &str) -> Result<Self> {
        let value = did
            .strip_prefix("did:web:")
            .ok_or_else(|| Error::InvalidSpiffeUri("DID must start with did:web:".into()))?;
        let parts: Vec<_> = value.split(':').collect();
        let [domain, "ns", embedded_namespace, "sa", account @ ..] = parts.as_slice() else {
            return Err(Error::InvalidSpiffeUri(
                "expected did:web:<domain>:ns:<namespace>:sa:<account>".into(),
            ));
        };
        if *embedded_namespace != namespace {
            return Err(Error::InvalidSpiffeUri(
                "DID namespace does not match expected namespace".into(),
            ));
        }
        let identity = Self::from_spiffe_uri(&format!(
            "spiffe://{domain}/ns/{embedded_namespace}/sa/{}",
            account.join("/")
        ))?;
        if identity.to_did_web() != did {
            return Err(Error::InvalidSpiffeUri(
                "noncanonical did:web identity".into(),
            ));
        }
        Ok(identity)
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
    fn a_path_that_is_not_ns_sa_is_refused() {
        // One Identity per URI: a path of another shape is not given a
        // namespace it does not spell.
        for uri in [
            "spiffe://nucleus.local/my-workload",
            "spiffe://nucleus.local/workload/my-service",
            "spiffe://nucleus.local/ns/default",
            "spiffe://nucleus.local/ns/default/sa",
        ] {
            assert!(Identity::from_spiffe_uri(uri).is_err(), "{uri}");
        }
    }

    #[test]
    fn non_canonical_spellings_are_refused() {
        for uri in [
            "spiffe://Nucleus.local/ns/default/sa/x",
            "SPIFFE://nucleus.local/ns/default/sa/x",
            "spiffe://nucleus.local:443/ns/default/sa/x",
            "spiffe://u@nucleus.local/ns/default/sa/x",
            "spiffe://nucleus.local/ns/default/sa/x/",
            "spiffe://nucleus.local/ns/default/sa//x",
            "spiffe://nucleus.local/ns/default/sa/x/../y",
            "spiffe://nucleus.local/ns/./sa/x",
            "spiffe://nucleus.local/ns/default/sa/x%2Fy",
            "spiffe://nucleus.local/ns/default/sa/x?q",
            "spiffe://nucleus.local/ns/default/sa/x#f",
            "spiffe://nucleus.local/ns/default/sa/x;p",
            "spiffe://nucleus.local/ns/default/sa/x\0",
            "spiffe://nucleus.local/ns/default/sa/\u{0445}",
        ] {
            assert!(Identity::from_spiffe_uri(uri).is_err(), "{uri:?}");
        }
        // Segments below the account are the account's.
        let id =
            Identity::from_spiffe_uri("spiffe://nucleus.local/ns/github/sa/o/r/refs/x").unwrap();
        assert_eq!(id.service_account(), "o/r/refs/x");
        assert_eq!(
            id.to_spiffe_uri(),
            "spiffe://nucleus.local/ns/github/sa/o/r/refs/x"
        );
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
        assert_eq!(
            id.to_did_web(),
            "did:web:groundtruth.dev:ns:apps:sa:music-app"
        );
    }

    #[test]
    fn test_to_did_web_complex_domain() {
        let id = Identity::new("cluster-1.nucleus.example.com", "prod", "api-server");
        assert_eq!(
            id.to_did_web(),
            "did:web:cluster-1.nucleus.example.com:ns:prod:sa:api-server"
        );
    }

    #[test]
    fn test_from_did_web() {
        let id =
            Identity::from_did_web("did:web:groundtruth.dev:ns:apps:sa:music-app", "apps").unwrap();
        assert_eq!(id.trust_domain(), "groundtruth.dev");
        assert_eq!(id.namespace(), "apps");
        assert_eq!(id.service_account(), "music-app");
    }

    #[test]
    fn test_from_did_web_complex_domain() {
        let id = Identity::from_did_web(
            "did:web:cluster-1.nucleus.example.com:ns:prod:sa:api-server",
            "prod",
        )
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
    fn did_web_preserves_namespace_and_account_segments() {
        let ids = [
            Identity::new("example.com", "a", "worker"),
            Identity::new("example.com", "b", "worker"),
            Identity::new("example.com", "a", "worker.team"),
            Identity::new("team.example.com", "a", "worker"),
            Identity::from_spiffe_uri("spiffe://example.com/ns/a/sa/owner/repo/refs/main").unwrap(),
        ];
        let dids: std::collections::HashSet<_> = ids.iter().map(Identity::to_did_web).collect();
        assert_eq!(dids.len(), ids.len());
        for id in ids {
            let did = id.to_did_web();
            assert!(!did.contains('/'));
            assert_eq!(Identity::from_did_web(&did, id.namespace()).unwrap(), id);
            assert!(Identity::from_did_web(&did, "other").is_err());
        }
        for invalid in [
            "did:web:worker.example.com",
            "did:web:example.com:ns:a:sa:",
            "did:web:example.com:ns:a:sa:owner::repo",
            "did:web:example.com:ns:a:sa:..",
            "did:web:example.com:ns:a:sa:owner%2Frepo",
            "did:web:example.com:ns:a:sa:owner/repo",
        ] {
            assert!(Identity::from_did_web(invalid, "a").is_err(), "{invalid}");
        }
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
