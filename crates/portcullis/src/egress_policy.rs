//! Egress policy — `.nucleus/egress.toml` config loader and host pattern matching.
//!
//! Implements a default-deny egress policy: when an `egress.toml` exists, only
//! hosts matching the allowlist (and not on the denylist) may be contacted.
//!
//! ## Host Pattern Types
//!
//! - **Exact**: `api.github.com` — matches only that host
//! - **Wildcard**: `*.github.com` — matches any subdomain of github.com
//! - **CIDR**: `10.0.0.0/8` — matches any IP in the network range
//!
//! ## Example `egress.toml`
//!
//! ```toml
//! # Maximum outbound payload size in bytes (optional, default: no limit)
//! max_payload_bytes = 1048576  # 1 MiB
//!
//! # Hosts that are allowed for egress (default-deny: unlisted = denied)
//! allowed_hosts = [
//!     "api.github.com",
//!     "*.crates.io",
//!     "registry.npmjs.org",
//! ]
//!
//! # Hosts that are always denied, even if they match an allow pattern
//! denied_hosts = [
//!     "evil.example.com",
//!     "*.malware.test",
//! ]
//! ```
//!
//! ## Evaluation Order
//!
//! 1. If the host matches any `denied_hosts` pattern → **Deny**
//! 2. If the host matches any `allowed_hosts` pattern → **Allow**
//! 3. Otherwise → **Deny** (default-deny)

use std::fmt;
use std::net::IpAddr;
#[cfg(feature = "spec")]
use std::path::Path;

/// Result of checking a host against the egress policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressVerdict {
    /// The host is allowed for egress.
    Allow,
    /// The host is denied for egress, with a reason.
    Deny {
        /// Human-readable reason for the denial.
        reason: String,
    },
}

impl EgressVerdict {
    /// Returns `true` if the verdict allows egress.
    pub fn is_allowed(&self) -> bool {
        matches!(self, EgressVerdict::Allow)
    }

    /// Returns `true` if the verdict denies egress.
    pub fn is_denied(&self) -> bool {
        matches!(self, EgressVerdict::Deny { .. })
    }
}

/// A host pattern that can match exact hostnames, wildcards, or CIDR ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "String", into = "String")
)]
pub enum HostPattern {
    /// Exact hostname match (e.g., `api.github.com`).
    Exact(String),
    /// Wildcard subdomain match (e.g., `*.github.com` matches `api.github.com`).
    Wildcard {
        /// The suffix after the `*.` prefix (e.g., `github.com`).
        suffix: String,
    },
    /// CIDR range match (e.g., `10.0.0.0/8`).
    Cidr {
        /// The network address.
        network: IpAddr,
        /// The prefix length in bits.
        prefix_len: u8,
        /// Original string representation for display.
        raw: String,
    },
}

impl HostPattern {
    /// Parse a host pattern from a string.
    ///
    /// Supports:
    /// - `*.example.com` → wildcard
    /// - `10.0.0.0/8` or `fd00::/8` → CIDR
    /// - anything else → exact match
    pub fn parse(s: &str) -> Result<Self, EgressPolicyError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(EgressPolicyError::EmptyPattern);
        }

        // Wildcard: *.suffix
        if let Some(suffix) = trimmed.strip_prefix("*.") {
            if suffix.is_empty() {
                return Err(EgressPolicyError::InvalidPattern(
                    "wildcard suffix is empty".into(),
                ));
            }
            return Ok(HostPattern::Wildcard {
                suffix: suffix.to_lowercase(),
            });
        }

        // CIDR: contains '/' and parses as IP/prefix
        if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let prefix_len: u8 = prefix_str.parse().map_err(|_| {
                    EgressPolicyError::InvalidCidr(format!("invalid prefix length: {prefix_str}"))
                })?;
                let max_prefix = match ip {
                    IpAddr::V4(_) => 32,
                    IpAddr::V6(_) => 128,
                };
                if prefix_len > max_prefix {
                    return Err(EgressPolicyError::InvalidCidr(format!(
                        "prefix length {prefix_len} exceeds maximum {max_prefix}"
                    )));
                }
                return Ok(HostPattern::Cidr {
                    network: ip,
                    prefix_len,
                    raw: trimmed.to_string(),
                });
            }
        }

        // Exact match
        Ok(HostPattern::Exact(trimmed.to_lowercase()))
    }

    /// Check if this pattern matches a given host string.
    ///
    /// The host can be a hostname or an IP address string.
    pub fn matches(&self, host: &str) -> bool {
        let host_lower = host.trim().to_lowercase();
        match self {
            HostPattern::Exact(exact) => host_lower == *exact,
            HostPattern::Wildcard { suffix } => {
                // Match: host is exactly the suffix, or host ends with .suffix
                host_lower == *suffix || host_lower.ends_with(&format!(".{suffix}"))
            }
            HostPattern::Cidr {
                network,
                prefix_len,
                ..
            } => {
                if let Ok(ip) = host_lower.parse::<IpAddr>() {
                    ip_in_cidr(ip, *network, *prefix_len)
                } else {
                    false
                }
            }
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Exact(s) => write!(f, "{s}"),
            HostPattern::Wildcard { suffix } => write!(f, "*.{suffix}"),
            HostPattern::Cidr { raw, .. } => write!(f, "{raw}"),
        }
    }
}

impl TryFrom<String> for HostPattern {
    type Error = EgressPolicyError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        HostPattern::parse(&s)
    }
}

impl From<HostPattern> for String {
    fn from(p: HostPattern) -> String {
        p.to_string()
    }
}

/// Check if an IP address falls within a CIDR range.
fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if prefix_len == 0 {
                return true;
            }
            let ip_bits = u32::from(ip);
            let net_bits = u32::from(net);
            let mask = u32::MAX.checked_shl(32 - prefix_len as u32).unwrap_or(0);
            (ip_bits & mask) == (net_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if prefix_len == 0 {
                return true;
            }
            let ip_bits = u128::from(ip);
            let net_bits = u128::from(net);
            let mask = u128::MAX.checked_shl(128 - prefix_len as u32).unwrap_or(0);
            (ip_bits & mask) == (net_bits & mask)
        }
        // IPv4 vs IPv6 mismatch
        _ => false,
    }
}

/// Raw TOML config file structure.
#[cfg(feature = "spec")]
#[derive(Debug, serde::Deserialize)]
struct EgressConfigFile {
    /// Hosts that are allowed for egress.
    #[serde(default)]
    allowed_hosts: Vec<String>,
    /// Hosts that are always denied, even if they match an allow pattern.
    #[serde(default)]
    denied_hosts: Vec<String>,
    /// Maximum outbound payload size in bytes.
    #[serde(default)]
    max_payload_bytes: Option<u64>,
}

/// A loaded and validated egress policy.
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    /// Allowed host patterns.
    pub allowed_hosts: Vec<HostPattern>,
    /// Denied host patterns (evaluated first — deny takes precedence).
    pub denied_hosts: Vec<HostPattern>,
    /// Maximum outbound payload size in bytes (None = no limit).
    pub max_payload_bytes: Option<u64>,
}

impl EgressPolicy {
    /// Check whether a host is allowed by this policy.
    ///
    /// Evaluation order:
    /// 1. If the host matches any `denied_hosts` → Deny
    /// 2. If the host matches any `allowed_hosts` → Allow
    /// 3. Otherwise → Deny (default-deny)
    pub fn check_host(&self, host: &str) -> EgressVerdict {
        // Step 1: check deny list first (deny takes precedence)
        for pattern in &self.denied_hosts {
            if pattern.matches(host) {
                return EgressVerdict::Deny {
                    reason: format!("host '{host}' matches denied pattern '{pattern}'"),
                };
            }
        }

        // Step 2: check allow list
        for pattern in &self.allowed_hosts {
            if pattern.matches(host) {
                return EgressVerdict::Allow;
            }
        }

        // Step 3: default deny
        EgressVerdict::Deny {
            reason: format!("host '{host}' not in allowlist (default-deny)"),
        }
    }

    /// Check whether a payload size is within the configured limit.
    ///
    /// Returns `Allow` if no limit is set or the size is within bounds.
    pub fn check_payload_size(&self, size_bytes: u64) -> EgressVerdict {
        match self.max_payload_bytes {
            Some(max) if size_bytes > max => EgressVerdict::Deny {
                reason: format!("payload size {size_bytes} bytes exceeds maximum {max} bytes"),
            },
            _ => EgressVerdict::Allow,
        }
    }
}

/// TOML loading methods — requires the `spec` feature (serde + toml).
#[cfg(feature = "spec")]
impl EgressPolicy {
    /// Load an egress policy from a directory containing `egress.toml`.
    ///
    /// Looks for `<dir>/egress.toml` and parses it.
    /// Returns `Ok(None)` if the file does not exist (no egress restrictions).
    /// Returns `Err` if the file exists but is malformed.
    pub fn load_from_dir(dir: &Path) -> Result<Option<Self>, EgressPolicyError> {
        let path = dir.join("egress.toml");
        if !path.exists() {
            return Ok(None);
        }
        let content = std::fs::read_to_string(&path).map_err(EgressPolicyError::Io)?;
        Self::from_toml(&content).map(Some)
    }

    /// Parse an egress policy from a TOML string.
    pub fn from_toml(toml_content: &str) -> Result<Self, EgressPolicyError> {
        let config: EgressConfigFile =
            toml::from_str(toml_content).map_err(EgressPolicyError::Toml)?;

        let allowed_hosts = config
            .allowed_hosts
            .into_iter()
            .map(|s| HostPattern::parse(&s))
            .collect::<Result<Vec<_>, _>>()?;

        let denied_hosts = config
            .denied_hosts
            .into_iter()
            .map(|s| HostPattern::parse(&s))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(EgressPolicy {
            allowed_hosts,
            denied_hosts,
            max_payload_bytes: config.max_payload_bytes,
        })
    }
}

/// Errors from egress policy loading and validation.
#[derive(Debug)]
pub enum EgressPolicyError {
    /// Failed to read the policy file.
    #[cfg(feature = "spec")]
    Io(std::io::Error),
    /// Failed to parse the TOML content.
    #[cfg(feature = "spec")]
    Toml(toml::de::Error),
    /// A host pattern is empty.
    EmptyPattern,
    /// A host pattern is invalid.
    InvalidPattern(String),
    /// A CIDR pattern is invalid.
    InvalidCidr(String),
}

impl fmt::Display for EgressPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "spec")]
            EgressPolicyError::Io(e) => write!(f, "failed to read egress policy: {e}"),
            #[cfg(feature = "spec")]
            EgressPolicyError::Toml(e) => write!(f, "failed to parse egress TOML: {e}"),
            EgressPolicyError::EmptyPattern => write!(f, "empty host pattern"),
            EgressPolicyError::InvalidPattern(s) => write!(f, "invalid host pattern: {s}"),
            EgressPolicyError::InvalidCidr(s) => write!(f, "invalid CIDR pattern: {s}"),
        }
    }
}

impl std::error::Error for EgressPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            #[cfg(feature = "spec")]
            EgressPolicyError::Io(e) => Some(e),
            #[cfg(feature = "spec")]
            EgressPolicyError::Toml(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── HostPattern parsing ──────────────────────────────────────────

    #[test]
    fn parse_exact_host() {
        let p = HostPattern::parse("api.github.com").unwrap();
        assert_eq!(p, HostPattern::Exact("api.github.com".into()));
    }

    #[test]
    fn parse_exact_host_case_insensitive() {
        let p = HostPattern::parse("API.GitHub.COM").unwrap();
        assert_eq!(p, HostPattern::Exact("api.github.com".into()));
    }

    #[test]
    fn parse_wildcard() {
        let p = HostPattern::parse("*.github.com").unwrap();
        assert_eq!(
            p,
            HostPattern::Wildcard {
                suffix: "github.com".into()
            }
        );
    }

    #[test]
    fn parse_cidr_v4() {
        let p = HostPattern::parse("10.0.0.0/8").unwrap();
        match p {
            HostPattern::Cidr {
                network,
                prefix_len,
                ..
            } => {
                assert_eq!(network, "10.0.0.0".parse::<IpAddr>().unwrap());
                assert_eq!(prefix_len, 8);
            }
            other => panic!("expected Cidr, got {other:?}"),
        }
    }

    #[test]
    fn parse_cidr_v6() {
        let p = HostPattern::parse("fd00::/8").unwrap();
        match p {
            HostPattern::Cidr {
                network,
                prefix_len,
                ..
            } => {
                assert_eq!(network, "fd00::".parse::<IpAddr>().unwrap());
                assert_eq!(prefix_len, 8);
            }
            other => panic!("expected Cidr, got {other:?}"),
        }
    }

    #[test]
    fn parse_empty_is_error() {
        assert!(HostPattern::parse("").is_err());
        assert!(HostPattern::parse("   ").is_err());
    }

    #[test]
    fn parse_wildcard_empty_suffix_is_error() {
        assert!(HostPattern::parse("*.").is_err());
    }

    #[test]
    fn parse_cidr_invalid_prefix_length() {
        assert!(HostPattern::parse("10.0.0.0/33").is_err());
        assert!(HostPattern::parse("fd00::/129").is_err());
    }

    #[test]
    fn parse_cidr_non_numeric_prefix() {
        assert!(HostPattern::parse("10.0.0.0/abc").is_err());
    }

    // ── HostPattern matching ─────────────────────────────────────────

    #[test]
    fn exact_match() {
        let p = HostPattern::parse("api.github.com").unwrap();
        assert!(p.matches("api.github.com"));
        assert!(p.matches("API.GitHub.COM")); // case-insensitive
        assert!(!p.matches("evil.github.com"));
        assert!(!p.matches("github.com"));
    }

    #[test]
    fn wildcard_match() {
        let p = HostPattern::parse("*.github.com").unwrap();
        assert!(p.matches("api.github.com"));
        assert!(p.matches("raw.github.com"));
        assert!(p.matches("a.b.github.com")); // deep subdomain
        assert!(p.matches("github.com")); // bare domain also matches
        assert!(!p.matches("evil.com"));
        assert!(!p.matches("notgithub.com"));
    }

    #[test]
    fn cidr_v4_match() {
        let p = HostPattern::parse("10.0.0.0/8").unwrap();
        assert!(p.matches("10.0.0.1"));
        assert!(p.matches("10.255.255.255"));
        assert!(!p.matches("11.0.0.1"));
        assert!(!p.matches("192.168.1.1"));
        assert!(!p.matches("api.github.com")); // hostname, not IP
    }

    #[test]
    fn cidr_v4_slash_32() {
        let p = HostPattern::parse("192.168.1.1/32").unwrap();
        assert!(p.matches("192.168.1.1"));
        assert!(!p.matches("192.168.1.2"));
    }

    #[test]
    fn cidr_v4_slash_0() {
        let p = HostPattern::parse("0.0.0.0/0").unwrap();
        assert!(p.matches("1.2.3.4"));
        assert!(p.matches("255.255.255.255"));
    }

    #[test]
    fn cidr_v6_match() {
        let p = HostPattern::parse("fd00::/8").unwrap();
        assert!(p.matches("fd00::1"));
        assert!(p.matches("fdff::1"));
        assert!(!p.matches("fe80::1"));
    }

    #[test]
    fn cidr_no_cross_family_match() {
        let p = HostPattern::parse("10.0.0.0/8").unwrap();
        assert!(!p.matches("fd00::1")); // IPv6 vs IPv4 pattern
    }

    // ── EgressPolicy::check_host (no TOML needed) ───────────────────

    /// Helper to build a policy directly without TOML parsing.
    fn make_policy(allowed: &[&str], denied: &[&str], max_payload: Option<u64>) -> EgressPolicy {
        EgressPolicy {
            allowed_hosts: allowed
                .iter()
                .map(|s| HostPattern::parse(s).unwrap())
                .collect(),
            denied_hosts: denied
                .iter()
                .map(|s| HostPattern::parse(s).unwrap())
                .collect(),
            max_payload_bytes: max_payload,
        }
    }

    #[test]
    fn allowed_host_passes() {
        let policy = make_policy(&["api.github.com", "*.crates.io"], &[], None);
        assert!(policy.check_host("api.github.com").is_allowed());
        assert!(policy.check_host("static.crates.io").is_allowed());
    }

    #[test]
    fn unlisted_host_denied_by_default() {
        let policy = make_policy(&["api.github.com"], &[], None);
        let verdict = policy.check_host("evil.com");
        assert!(verdict.is_denied());
        match verdict {
            EgressVerdict::Deny { reason } => {
                assert!(reason.contains("not in allowlist"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn denied_host_overrides_allowed() {
        let policy = make_policy(&["*.github.com"], &["evil.github.com"], None);
        // evil.github.com matches both allow and deny — deny wins
        assert!(policy.check_host("evil.github.com").is_denied());
        // good.github.com only matches allow — allowed
        assert!(policy.check_host("good.github.com").is_allowed());
    }

    #[test]
    fn cidr_allow_works() {
        let policy = make_policy(&["10.0.0.0/8"], &[], None);
        assert!(policy.check_host("10.1.2.3").is_allowed());
        assert!(policy.check_host("192.168.1.1").is_denied());
    }

    #[test]
    fn cidr_deny_overrides_allow() {
        let policy = make_policy(&["10.0.0.0/8"], &["10.0.0.1/32"], None);
        assert!(policy.check_host("10.0.0.1").is_denied());
        assert!(policy.check_host("10.0.0.2").is_allowed());
    }

    // ── Payload size check ──────────────────────────────────────────

    #[test]
    fn no_payload_limit_allows_all() {
        let policy = make_policy(&["example.com"], &[], None);
        assert!(policy.check_payload_size(u64::MAX).is_allowed());
    }

    #[test]
    fn payload_within_limit_allowed() {
        let policy = make_policy(&[], &[], Some(1024));
        assert!(policy.check_payload_size(1024).is_allowed());
        assert!(policy.check_payload_size(0).is_allowed());
    }

    #[test]
    fn payload_exceeds_limit_denied() {
        let policy = make_policy(&[], &[], Some(1024));
        let verdict = policy.check_payload_size(1025);
        assert!(verdict.is_denied());
        match verdict {
            EgressVerdict::Deny { reason } => {
                assert!(reason.contains("1025"));
                assert!(reason.contains("1024"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn empty_policy_denies_all() {
        let policy = make_policy(&[], &[], None);
        assert!(policy.check_host("anything.com").is_denied());
    }

    // ── TOML loading tests (require `spec` feature) ────────────────

    #[cfg(feature = "spec")]
    mod toml_tests {
        use super::*;

        #[test]
        fn load_minimal_policy() {
            let toml = r#"
allowed_hosts = ["api.github.com"]
"#;
            let policy = EgressPolicy::from_toml(toml).unwrap();
            assert_eq!(policy.allowed_hosts.len(), 1);
            assert!(policy.denied_hosts.is_empty());
            assert!(policy.max_payload_bytes.is_none());
        }

        #[test]
        fn load_full_policy() {
            let toml = r#"
max_payload_bytes = 1048576

allowed_hosts = [
    "api.github.com",
    "*.crates.io",
    "10.0.0.0/8",
]

denied_hosts = [
    "evil.example.com",
    "*.malware.test",
]
"#;
            let policy = EgressPolicy::from_toml(toml).unwrap();
            assert_eq!(policy.allowed_hosts.len(), 3);
            assert_eq!(policy.denied_hosts.len(), 2);
            assert_eq!(policy.max_payload_bytes, Some(1_048_576));
        }

        #[test]
        fn empty_config_denies_all() {
            let toml = "";
            let policy = EgressPolicy::from_toml(toml).unwrap();
            assert!(policy.allowed_hosts.is_empty());
            assert!(policy.denied_hosts.is_empty());
            assert!(policy.check_host("anything.com").is_denied());
        }

        #[test]
        fn malformed_toml_is_error() {
            let toml = "this is not valid toml [[[";
            assert!(EgressPolicy::from_toml(toml).is_err());
        }

        #[test]
        fn invalid_pattern_in_config_is_error() {
            let toml = r#"
allowed_hosts = ["*."]
"#;
            assert!(EgressPolicy::from_toml(toml).is_err());
        }

        // ── load_from_dir ───────────────────────────────────────────────

        #[test]
        fn load_from_dir_missing_file_returns_none() {
            let dir = tempfile::tempdir().unwrap();
            let result = EgressPolicy::load_from_dir(dir.path()).unwrap();
            assert!(result.is_none());
        }

        #[test]
        fn load_from_dir_with_valid_file() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("egress.toml"),
                r#"allowed_hosts = ["example.com"]"#,
            )
            .unwrap();
            let policy = EgressPolicy::load_from_dir(dir.path())
                .unwrap()
                .expect("policy should exist");
            assert_eq!(policy.allowed_hosts.len(), 1);
            assert!(policy.check_host("example.com").is_allowed());
        }

        #[test]
        fn load_from_dir_with_malformed_file_is_error() {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("egress.toml"), "not valid [[[").unwrap();
            assert!(EgressPolicy::load_from_dir(dir.path()).is_err());
        }
    }

    // ── Display ─────────────────────────────────────────────────────

    #[test]
    fn host_pattern_display() {
        assert_eq!(
            HostPattern::parse("api.github.com").unwrap().to_string(),
            "api.github.com"
        );
        assert_eq!(
            HostPattern::parse("*.github.com").unwrap().to_string(),
            "*.github.com"
        );
        assert_eq!(
            HostPattern::parse("10.0.0.0/8").unwrap().to_string(),
            "10.0.0.0/8"
        );
    }
}
