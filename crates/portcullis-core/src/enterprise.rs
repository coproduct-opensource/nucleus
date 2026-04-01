//! Enterprise managed allowlists — schema for organizational policy controls.
//!
//! Enterprises need explicit allowlists for what can run in an organization:
//! which MCP servers (by manifest hash), which hook binaries (by signing key),
//! which sink classes are permitted, and how deep delegation chains can go.
//!
//! This module defines the **schema only** — types, validation logic, and
//! TOML loading. Kernel integration (applying these as a ceiling on all
//! decisions) is separate work.
//!
//! ## Loading
//!
//! Enterprise allowlists are loaded from `.nucleus/enterprise.toml`:
//!
//! ```toml
//! required_receipt_signing = true
//! max_delegation_depth = 3
//! denied_sinks = ["email_send", "cloud_mutation"]
//! # None = all sinks allowed; explicit list = only these permitted
//! # allowed_sinks = ["workspace_write", "bash_exec", "git_commit"]
//!
//! [[allowed_mcp_servers]]
//! name = "filesystem"
//! sha256 = "a1b2c3..."
//!
//! [[allowed_hook_sources]]
//! path = "hooks/pre-commit.sh"
//! signing_key = "ed25519:..."
//! ```
//!
//! ## Deny-takes-precedence
//!
//! If a sink appears in both `allowed_sinks` and `denied_sinks`, the deny
//! list wins. This is a security invariant: explicit denials cannot be
//! overridden by allowlists.

use crate::SinkClass;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/// A reference to an MCP server identified by name and content hash.
///
/// The hash is the SHA-256 of the server's manifest content, providing
/// a tamper-evident identifier that changes when the server is modified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestHash {
    /// Human-readable server name (for diagnostics, not for matching).
    pub name: String,
    /// Hex-encoded SHA-256 hash of the manifest content.
    pub sha256: String,
}

/// A reference to a hook source identified by path and signing key.
///
/// Hook binaries must be signed by one of the allowed signing keys
/// to be loaded. The path is informational; the signing key is the
/// security-relevant field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedSource {
    /// Path to the hook binary (relative to workspace root).
    pub path: String,
    /// Public key that signed this hook (e.g., "ed25519:...").
    pub signing_key: String,
}

/// Enterprise-managed allowlist — the ceiling on what an organization permits.
///
/// When loaded, this policy acts as an upper bound: even if local config
/// would allow an action, the enterprise allowlist can deny it.
///
/// ## Security invariants
///
/// 1. `denied_sinks` takes precedence over `allowed_sinks` (deny wins).
/// 2. An empty `allowed_mcp_servers` list means NO MCP servers are allowed
///    (fail-closed for MCP).
/// 3. `allowed_sinks = None` means all sinks are allowed (backward compat);
///    `allowed_sinks = Some(vec![])` means NO sinks are allowed (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseAllowlist {
    /// MCP servers allowed by manifest hash. Empty = none allowed.
    #[serde(default)]
    pub allowed_mcp_servers: Vec<ManifestHash>,

    /// Hook sources allowed by signing key. Empty = none allowed.
    #[serde(default)]
    pub allowed_hook_sources: Vec<SignedSource>,

    /// Sink classes explicitly allowed. `None` = all allowed (default).
    /// `Some(vec![])` = no sinks allowed (fail-closed).
    #[serde(default)]
    pub allowed_sinks: Option<Vec<SinkClass>>,

    /// Sink classes explicitly denied. Always takes precedence over allowed.
    #[serde(default)]
    pub denied_sinks: Vec<SinkClass>,

    /// Maximum delegation depth for agent-to-agent delegation chains.
    /// `None` = no limit (backward compat).
    #[serde(default)]
    pub max_delegation_depth: Option<u32>,

    /// Whether all receipts must be cryptographically signed.
    /// When true, unsigned receipts are rejected.
    #[serde(default)]
    pub required_receipt_signing: bool,
}

// ═══════════════════════════════════════════════════════════════════════════
// Check methods
// ═══════════════════════════════════════════════════════════════════════════

impl EnterpriseAllowlist {
    /// Check whether an MCP server (identified by its manifest SHA-256 hash)
    /// is allowed by this enterprise policy.
    ///
    /// Returns `true` if the hash appears in `allowed_mcp_servers`.
    /// An empty allowlist means no servers are allowed (fail-closed).
    pub fn check_mcp_server(&self, hash: &str) -> bool {
        self.allowed_mcp_servers.iter().any(|m| m.sha256 == hash)
    }

    /// Check whether a sink class is allowed by this enterprise policy.
    ///
    /// **Deny-takes-precedence**: if a sink appears in `denied_sinks`,
    /// it is denied regardless of `allowed_sinks`.
    ///
    /// When `allowed_sinks` is `None`, all non-denied sinks are allowed.
    /// When `allowed_sinks` is `Some(list)`, only sinks in the list
    /// (and not in `denied_sinks`) are allowed.
    pub fn check_sink(&self, sink: SinkClass) -> bool {
        // Deny list always wins.
        if self.denied_sinks.contains(&sink) {
            return false;
        }

        // If no allowlist is set, all non-denied sinks pass.
        match &self.allowed_sinks {
            None => true,
            Some(allowed) => allowed.contains(&sink),
        }
    }

    /// Check whether a delegation depth is within the enterprise limit.
    ///
    /// Returns `true` if `depth <= max_delegation_depth` or if no limit is set.
    pub fn check_delegation_depth(&self, depth: u32) -> bool {
        match self.max_delegation_depth {
            None => true,
            Some(max) => depth <= max,
        }
    }

    /// Check whether a hook source is allowed by signing key.
    ///
    /// Returns `true` if the signing key appears in `allowed_hook_sources`.
    /// An empty allowlist means no hook sources are allowed (fail-closed).
    pub fn check_hook_source(&self, signing_key: &str) -> bool {
        self.allowed_hook_sources
            .iter()
            .any(|s| s.signing_key == signing_key)
    }

    /// Load an enterprise allowlist from a directory containing `enterprise.toml`.
    ///
    /// Looks for `<dir>/enterprise.toml` (typically `.nucleus/enterprise.toml`).
    /// Returns `Ok(None)` if the file does not exist (enterprise mode not configured).
    /// Returns `Err` if the file exists but cannot be parsed.
    pub fn load_from_dir(dir: &Path) -> Result<Option<Self>, EnterpriseLoadError> {
        let path = dir.join("enterprise.toml");
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(EnterpriseLoadError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        };

        let allowlist: Self =
            toml::from_str(&contents).map_err(|e| EnterpriseLoadError::Parse {
                path: path.display().to_string(),
                source: e,
            })?;

        Ok(Some(allowlist))
    }
}

impl Default for EnterpriseAllowlist {
    /// Default: no restrictions (backward compatible).
    ///
    /// - No MCP server allowlist (empty = none allowed if enterprise mode active,
    ///   but default is meant for "enterprise mode not configured" case).
    /// - No hook source restrictions.
    /// - All sinks allowed (`allowed_sinks = None`).
    /// - No delegation depth limit.
    /// - Receipt signing not required.
    fn default() -> Self {
        Self {
            allowed_mcp_servers: Vec::new(),
            allowed_hook_sources: Vec::new(),
            allowed_sinks: None,
            denied_sinks: Vec::new(),
            max_delegation_depth: None,
            required_receipt_signing: false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════════

/// Errors that can occur when loading an enterprise allowlist.
#[derive(Debug)]
pub enum EnterpriseLoadError {
    /// File exists but could not be read.
    Io {
        path: String,
        source: std::io::Error,
    },
    /// File exists but contains invalid TOML or schema mismatch.
    Parse {
        path: String,
        source: toml::de::Error,
    },
}

impl std::fmt::Display for EnterpriseLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read enterprise policy at {path}: {source}")
            }
            Self::Parse { path, source } => {
                write!(f, "failed to parse enterprise policy at {path}: {source}")
            }
        }
    }
}

impl std::error::Error for EnterpriseLoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── MCP server checks ────────────────────────────────────────────

    #[test]
    fn check_mcp_server_allows_known_hash() {
        let policy = EnterpriseAllowlist {
            allowed_mcp_servers: vec![ManifestHash {
                name: "filesystem".into(),
                sha256: "abc123".into(),
            }],
            ..Default::default()
        };
        assert!(policy.check_mcp_server("abc123"));
    }

    #[test]
    fn check_mcp_server_denies_unknown_hash() {
        let policy = EnterpriseAllowlist {
            allowed_mcp_servers: vec![ManifestHash {
                name: "filesystem".into(),
                sha256: "abc123".into(),
            }],
            ..Default::default()
        };
        assert!(!policy.check_mcp_server("unknown"));
    }

    #[test]
    fn check_mcp_server_empty_list_denies_all() {
        let policy = EnterpriseAllowlist::default();
        assert!(!policy.check_mcp_server("anything"));
    }

    // ── Sink checks ─────────────────────────────────────────────────

    #[test]
    fn check_sink_no_restrictions_allows_all() {
        let policy = EnterpriseAllowlist::default();
        for sink in SinkClass::ALL {
            assert!(
                policy.check_sink(sink),
                "default policy should allow {sink:?}"
            );
        }
    }

    #[test]
    fn check_sink_allowlist_permits_listed() {
        let policy = EnterpriseAllowlist {
            allowed_sinks: Some(vec![SinkClass::WorkspaceWrite, SinkClass::GitCommit]),
            ..Default::default()
        };
        assert!(policy.check_sink(SinkClass::WorkspaceWrite));
        assert!(policy.check_sink(SinkClass::GitCommit));
        assert!(!policy.check_sink(SinkClass::EmailSend));
        assert!(!policy.check_sink(SinkClass::HTTPEgress));
    }

    #[test]
    fn check_sink_deny_takes_precedence_over_allow() {
        let policy = EnterpriseAllowlist {
            allowed_sinks: Some(vec![SinkClass::WorkspaceWrite, SinkClass::EmailSend]),
            denied_sinks: vec![SinkClass::EmailSend],
            ..Default::default()
        };
        assert!(policy.check_sink(SinkClass::WorkspaceWrite));
        // EmailSend is in both allowed and denied -- deny wins.
        assert!(!policy.check_sink(SinkClass::EmailSend));
    }

    #[test]
    fn check_sink_deny_without_allowlist() {
        let policy = EnterpriseAllowlist {
            allowed_sinks: None, // all allowed by default
            denied_sinks: vec![SinkClass::CloudMutation],
            ..Default::default()
        };
        assert!(policy.check_sink(SinkClass::WorkspaceWrite));
        assert!(!policy.check_sink(SinkClass::CloudMutation));
    }

    #[test]
    fn check_sink_empty_allowlist_denies_all() {
        let policy = EnterpriseAllowlist {
            allowed_sinks: Some(vec![]), // explicit empty = nothing allowed
            ..Default::default()
        };
        for sink in SinkClass::ALL {
            assert!(
                !policy.check_sink(sink),
                "empty allowlist should deny {sink:?}"
            );
        }
    }

    // ── Delegation depth checks ─────────────────────────────────────

    #[test]
    fn check_delegation_depth_no_limit() {
        let policy = EnterpriseAllowlist::default();
        assert!(policy.check_delegation_depth(100));
        assert!(policy.check_delegation_depth(u32::MAX));
    }

    #[test]
    fn check_delegation_depth_within_limit() {
        let policy = EnterpriseAllowlist {
            max_delegation_depth: Some(3),
            ..Default::default()
        };
        assert!(policy.check_delegation_depth(0));
        assert!(policy.check_delegation_depth(3));
        assert!(!policy.check_delegation_depth(4));
    }

    // ── Hook source checks ──────────────────────────────────────────

    #[test]
    fn check_hook_source_allows_known_key() {
        let policy = EnterpriseAllowlist {
            allowed_hook_sources: vec![SignedSource {
                path: "hooks/lint.sh".into(),
                signing_key: "ed25519:abc".into(),
            }],
            ..Default::default()
        };
        assert!(policy.check_hook_source("ed25519:abc"));
    }

    #[test]
    fn check_hook_source_denies_unknown_key() {
        let policy = EnterpriseAllowlist {
            allowed_hook_sources: vec![SignedSource {
                path: "hooks/lint.sh".into(),
                signing_key: "ed25519:abc".into(),
            }],
            ..Default::default()
        };
        assert!(!policy.check_hook_source("ed25519:unknown"));
    }

    #[test]
    fn check_hook_source_empty_denies_all() {
        let policy = EnterpriseAllowlist::default();
        assert!(!policy.check_hook_source("ed25519:anything"));
    }

    // ── TOML parsing ────────────────────────────────────────────────

    #[test]
    fn parse_full_toml() {
        let toml_str = r#"
required_receipt_signing = true
max_delegation_depth = 3
allowed_sinks = ["workspace_write", "git_commit"]
denied_sinks = ["email_send", "cloud_mutation"]

[[allowed_mcp_servers]]
name = "filesystem"
sha256 = "deadbeef01"

[[allowed_mcp_servers]]
name = "github"
sha256 = "cafebabe02"

[[allowed_hook_sources]]
path = "hooks/pre-commit.sh"
signing_key = "ed25519:key1"
"#;

        let policy: EnterpriseAllowlist = toml::from_str(toml_str).unwrap();

        assert!(policy.required_receipt_signing);
        assert_eq!(policy.max_delegation_depth, Some(3));
        assert_eq!(policy.allowed_mcp_servers.len(), 2);
        assert_eq!(policy.allowed_mcp_servers[0].name, "filesystem");
        assert_eq!(policy.allowed_mcp_servers[0].sha256, "deadbeef01");
        assert_eq!(policy.allowed_mcp_servers[1].name, "github");
        assert_eq!(policy.allowed_hook_sources.len(), 1);
        assert_eq!(policy.allowed_hook_sources[0].signing_key, "ed25519:key1");

        let allowed = policy.allowed_sinks.as_ref().unwrap();
        assert_eq!(allowed.len(), 2);
        assert!(allowed.contains(&SinkClass::WorkspaceWrite));
        assert!(allowed.contains(&SinkClass::GitCommit));

        assert_eq!(policy.denied_sinks.len(), 2);
        assert!(policy.denied_sinks.contains(&SinkClass::EmailSend));
        assert!(policy.denied_sinks.contains(&SinkClass::CloudMutation));
    }

    #[test]
    fn parse_minimal_toml() {
        let toml_str = r#"
required_receipt_signing = false
"#;
        let policy: EnterpriseAllowlist = toml::from_str(toml_str).unwrap();
        assert!(!policy.required_receipt_signing);
        assert!(policy.allowed_mcp_servers.is_empty());
        assert!(policy.allowed_hook_sources.is_empty());
        assert!(policy.allowed_sinks.is_none());
        assert!(policy.denied_sinks.is_empty());
        assert!(policy.max_delegation_depth.is_none());
    }

    #[test]
    fn parse_empty_toml() {
        let policy: EnterpriseAllowlist = toml::from_str("").unwrap();
        assert_eq!(policy, EnterpriseAllowlist::default());
    }

    #[test]
    fn parse_deny_takes_precedence_from_toml() {
        let toml_str = r#"
allowed_sinks = ["workspace_write", "email_send"]
denied_sinks = ["email_send"]
"#;
        let policy: EnterpriseAllowlist = toml::from_str(toml_str).unwrap();
        assert!(policy.check_sink(SinkClass::WorkspaceWrite));
        assert!(!policy.check_sink(SinkClass::EmailSend));
    }

    // ── File loading ────────────────────────────────────────────────

    #[test]
    fn load_from_dir_missing_file_returns_none() {
        let dir = std::env::temp_dir().join("nucleus-test-enterprise-missing");
        let _ = std::fs::create_dir_all(&dir);
        // Ensure no enterprise.toml exists.
        let _ = std::fs::remove_file(dir.join("enterprise.toml"));

        let result = EnterpriseAllowlist::load_from_dir(&dir).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_from_dir_valid_file() {
        let dir = std::env::temp_dir().join("nucleus-test-enterprise-valid");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("enterprise.toml"),
            r#"
required_receipt_signing = true
max_delegation_depth = 5
denied_sinks = ["http_egress"]
"#,
        )
        .unwrap();

        let policy = EnterpriseAllowlist::load_from_dir(&dir)
            .unwrap()
            .expect("should load");
        assert!(policy.required_receipt_signing);
        assert_eq!(policy.max_delegation_depth, Some(5));
        assert!(!policy.check_sink(SinkClass::HTTPEgress));
        assert!(policy.check_sink(SinkClass::WorkspaceWrite));

        // Cleanup.
        let _ = std::fs::remove_file(dir.join("enterprise.toml"));
    }

    #[test]
    fn load_from_dir_invalid_toml_returns_error() {
        let dir = std::env::temp_dir().join("nucleus-test-enterprise-invalid");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("enterprise.toml"), "this is { not valid toml").unwrap();

        let result = EnterpriseAllowlist::load_from_dir(&dir);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("failed to parse"),
            "error should mention parsing: {err}"
        );

        // Cleanup.
        let _ = std::fs::remove_file(dir.join("enterprise.toml"));
    }
}
