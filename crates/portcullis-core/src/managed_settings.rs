//! Managed settings — enterprise policy distribution for agent runtimes.
//!
//! Organizations push policy artifacts to a central registry, and agent
//! runtimes pull and enforce them automatically. This is the MDM-style
//! profile mechanism for agent security.
//!
//! This module defines the **configuration and merge logic** — types for
//! describing where to find org policy, how to enforce it, and how to
//! merge org-level settings with local project-level policy. The actual
//! distribution infrastructure (registry fetch, caching, pinning) is
//! separate work.
//!
//! ## Loading
//!
//! Managed settings are loaded from `.nucleus/managed.toml`:
//!
//! ```toml
//! policy_artifact_ref = "ghcr.io/acme-corp/agent-policy:latest"
//! required_compartment_image = "ghcr.io/acme-corp/sandbox:v2"
//! enforcement_mode = "enforce"
//! update_interval_secs = 3600
//!
//! [org_policy]
//! denied_sinks = ["email_send", "cloud_mutation"]
//! allowed_sinks = ["workspace_write", "git_commit", "bash_exec"]
//! max_delegation_depth = 3
//! required_receipt_signing = true
//! ```
//!
//! ## Merge semantics
//!
//! When merging org-level and local project-level enterprise policies:
//!
//! - **Deny lists**: union (org denials + local denials both apply).
//! - **Allow lists**: intersection — local can only narrow the org allowlist,
//!   never widen it. If the org allows `[A, B, C]` and local allows `[B, C, D]`,
//!   the effective allowlist is `[B, C]`.
//! - **Scalars**: org takes precedence (e.g., `max_delegation_depth`,
//!   `required_receipt_signing`).
//!
//! This ensures org policy acts as an upper bound that local projects
//! cannot escape.

use crate::SinkClass;
use crate::enterprise::EnterpriseAllowlist;
use serde::{Deserialize, Serialize};
use std::path::Path;

// ═══════════════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════════════

/// How the runtime should handle policy violations.
///
/// Enforcement modes form a total order: `Audit < Warn < Enforce`.
/// Organizations typically roll out new policies starting at `Audit`,
/// promote to `Warn` for visibility, then `Enforce` once confident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Log violations but allow the action to proceed.
    /// Useful during initial policy rollout to gauge impact.
    Audit,
    /// Log violations and display a warning to the user,
    /// but still allow the action to proceed.
    Warn,
    /// Block the action entirely when it violates policy.
    /// This is the production-grade enforcement level.
    Enforce,
}

impl Default for EnforcementMode {
    /// Defaults to `Enforce` — fail-closed by default.
    fn default() -> Self {
        Self::Enforce
    }
}

impl std::fmt::Display for EnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Audit => write!(f, "audit"),
            Self::Warn => write!(f, "warn"),
            Self::Enforce => write!(f, "enforce"),
        }
    }
}

/// Enterprise managed settings — how an org distributes and enforces policy.
///
/// Loaded from `.nucleus/managed.toml`. This struct describes:
/// - Where to find the org's policy artifact (registry reference)
/// - What compartment image is required for execution
/// - How to enforce policy violations
/// - How often to check for policy updates
/// - The org-level enterprise policy itself (for merge with local)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedSettings {
    /// OCI/registry reference for the organization's policy artifact.
    /// Example: `"ghcr.io/acme-corp/agent-policy:latest"`
    ///
    /// When set, the runtime should pull this artifact on session start
    /// and apply it as the organizational ceiling.
    #[serde(default)]
    pub policy_artifact_ref: Option<String>,

    /// Required compartment (container) image for execution.
    /// When set, the runtime must use this image; local overrides are rejected.
    #[serde(default)]
    pub required_compartment_image: Option<String>,

    /// How to handle policy violations.
    #[serde(default)]
    pub enforcement_mode: EnforcementMode,

    /// How often (in seconds) to check for policy updates from the registry.
    /// Defaults to 3600 (1 hour).
    #[serde(default = "default_update_interval")]
    pub update_interval_secs: u64,

    /// Org-level enterprise policy embedded in managed settings.
    /// When present, this is merged with local project policy via
    /// [`ManagedSettings::merge_with_local`].
    #[serde(default)]
    pub org_policy: Option<EnterpriseAllowlist>,
}

fn default_update_interval() -> u64 {
    3600
}

// ═══════════════════════════════════════════════════════════════════════════
// Loading
// ═══════════════════════════════════════════════════════════════════════════

impl ManagedSettings {
    /// Load managed settings from a directory containing `managed.toml`.
    ///
    /// Looks for `<dir>/managed.toml` (typically `.nucleus/managed.toml`).
    /// Returns `Ok(None)` if the file does not exist (managed mode not configured).
    /// Returns `Err` if the file exists but cannot be parsed.
    pub fn load_from_dir(dir: &Path) -> Result<Option<Self>, ManagedSettingsError> {
        let path = dir.join("managed.toml");
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(ManagedSettingsError::Io {
                    path: path.display().to_string(),
                    source: e,
                });
            }
        };

        let settings: Self =
            toml::from_str(&contents).map_err(|e| ManagedSettingsError::Parse {
                path: path.display().to_string(),
                source: e,
            })?;

        Ok(Some(settings))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Merge logic
// ═══════════════════════════════════════════════════════════════════════════

impl ManagedSettings {
    /// Merge org policy with a local project-level enterprise policy.
    ///
    /// Returns the effective `EnterpriseAllowlist` after applying merge rules:
    ///
    /// - **Deny lists**: union of org + local (both apply).
    /// - **Allow lists**: intersection — local can narrow but not widen.
    ///   If either side has `None` (no restriction), the other side's list wins.
    ///   If both have explicit lists, only the intersection is allowed.
    /// - **Scalars**: org takes precedence when set (`max_delegation_depth`,
    ///   `required_receipt_signing`).
    /// - **MCP servers / hook sources**: intersection by hash/key — local can
    ///   only use servers/hooks the org also allows.
    ///
    /// If `self.org_policy` is `None`, returns `local` unchanged.
    pub fn merge_with_local(&self, local: &EnterpriseAllowlist) -> EnterpriseAllowlist {
        let org = match &self.org_policy {
            Some(org) => org,
            None => return local.clone(),
        };

        // Deny list: union (both org and local denials apply).
        let mut denied_sinks = org.denied_sinks.clone();
        for sink in &local.denied_sinks {
            if !denied_sinks.contains(sink) {
                denied_sinks.push(*sink);
            }
        }

        // Allow list: intersection.
        // None means "no restriction" (all allowed).
        // Some([]) means "nothing allowed" (fail-closed).
        let allowed_sinks = match (&org.allowed_sinks, &local.allowed_sinks) {
            // Both unrestricted → unrestricted.
            (None, None) => None,
            // One side restricts → use that side's list.
            (Some(org_list), None) => Some(org_list.clone()),
            (None, Some(local_list)) => Some(local_list.clone()),
            // Both restrict → intersection.
            (Some(org_list), Some(local_list)) => {
                let intersection: Vec<SinkClass> = org_list
                    .iter()
                    .filter(|s| local_list.contains(s))
                    .copied()
                    .collect();
                Some(intersection)
            }
        };

        // MCP servers: intersection by sha256 hash.
        let allowed_mcp_servers = org
            .allowed_mcp_servers
            .iter()
            .filter(|org_server| {
                local
                    .allowed_mcp_servers
                    .iter()
                    .any(|local_server| local_server.sha256 == org_server.sha256)
            })
            .cloned()
            .collect();

        // Hook sources: intersection by signing key.
        let allowed_hook_sources = org
            .allowed_hook_sources
            .iter()
            .filter(|org_hook| {
                local
                    .allowed_hook_sources
                    .iter()
                    .any(|local_hook| local_hook.signing_key == org_hook.signing_key)
            })
            .cloned()
            .collect();

        // Scalars: org takes precedence when set.
        let max_delegation_depth = org.max_delegation_depth.or(local.max_delegation_depth);
        let required_receipt_signing =
            org.required_receipt_signing || local.required_receipt_signing;

        EnterpriseAllowlist {
            allowed_mcp_servers,
            allowed_hook_sources,
            allowed_sinks,
            denied_sinks,
            max_delegation_depth,
            required_receipt_signing,
        }
    }

    /// Check whether a sink is allowed under the merged policy.
    ///
    /// Merges the org policy (from `self`) with the provided local policy,
    /// then checks the sink against the effective merged policy.
    ///
    /// This is a convenience method combining [`Self::merge_with_local`]
    /// with [`EnterpriseAllowlist::check_sink`].
    pub fn is_sink_allowed(&self, sink: SinkClass, local: &EnterpriseAllowlist) -> bool {
        let merged = self.merge_with_local(local);
        merged.check_sink(sink)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════════════════

/// Errors that can occur when loading managed settings.
#[derive(Debug)]
pub enum ManagedSettingsError {
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

impl std::fmt::Display for ManagedSettingsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "failed to read managed settings at {path}: {source}")
            }
            Self::Parse { path, source } => {
                write!(f, "failed to parse managed settings at {path}: {source}")
            }
        }
    }
}

impl std::error::Error for ManagedSettingsError {
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
    use crate::enterprise::{ManifestHash, SignedSource};

    // ── Loading ─────────────────────────────────────────────────────

    #[test]
    fn load_from_dir_missing_file_returns_none() {
        let dir = std::env::temp_dir().join("nucleus-test-managed-missing");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join("managed.toml"));

        let result = ManagedSettings::load_from_dir(&dir).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_from_dir_minimal_file() {
        let dir = std::env::temp_dir().join("nucleus-test-managed-minimal");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("managed.toml"),
            r#"
enforcement_mode = "audit"
"#,
        )
        .unwrap();

        let settings = ManagedSettings::load_from_dir(&dir)
            .unwrap()
            .expect("should load");
        assert_eq!(settings.enforcement_mode, EnforcementMode::Audit);
        assert!(settings.policy_artifact_ref.is_none());
        assert!(settings.required_compartment_image.is_none());
        assert_eq!(settings.update_interval_secs, 3600);
        assert!(settings.org_policy.is_none());

        let _ = std::fs::remove_file(dir.join("managed.toml"));
    }

    #[test]
    fn load_from_dir_full_file() {
        let dir = std::env::temp_dir().join("nucleus-test-managed-full");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("managed.toml"),
            r#"
policy_artifact_ref = "ghcr.io/acme/policy:v1"
required_compartment_image = "ghcr.io/acme/sandbox:v2"
enforcement_mode = "enforce"
update_interval_secs = 1800

[org_policy]
required_receipt_signing = true
max_delegation_depth = 2
denied_sinks = ["email_send"]
allowed_sinks = ["workspace_write", "bash_exec"]
"#,
        )
        .unwrap();

        let settings = ManagedSettings::load_from_dir(&dir)
            .unwrap()
            .expect("should load");
        assert_eq!(
            settings.policy_artifact_ref.as_deref(),
            Some("ghcr.io/acme/policy:v1")
        );
        assert_eq!(
            settings.required_compartment_image.as_deref(),
            Some("ghcr.io/acme/sandbox:v2")
        );
        assert_eq!(settings.enforcement_mode, EnforcementMode::Enforce);
        assert_eq!(settings.update_interval_secs, 1800);

        let org = settings.org_policy.as_ref().unwrap();
        assert!(org.required_receipt_signing);
        assert_eq!(org.max_delegation_depth, Some(2));
        assert!(org.denied_sinks.contains(&SinkClass::EmailSend));
        let allowed = org.allowed_sinks.as_ref().unwrap();
        assert!(allowed.contains(&SinkClass::WorkspaceWrite));
        assert!(allowed.contains(&SinkClass::BashExec));

        let _ = std::fs::remove_file(dir.join("managed.toml"));
    }

    #[test]
    fn load_from_dir_invalid_toml_returns_error() {
        let dir = std::env::temp_dir().join("nucleus-test-managed-invalid");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("managed.toml"), "not { valid toml").unwrap();

        let result = ManagedSettings::load_from_dir(&dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to parse"));

        let _ = std::fs::remove_file(dir.join("managed.toml"));
    }

    // ── Enforcement modes ───────────────────────────────────────────

    #[test]
    fn enforcement_mode_default_is_enforce() {
        assert_eq!(EnforcementMode::default(), EnforcementMode::Enforce);
    }

    #[test]
    fn enforcement_mode_ordering() {
        assert!(EnforcementMode::Audit < EnforcementMode::Warn);
        assert!(EnforcementMode::Warn < EnforcementMode::Enforce);
    }

    #[test]
    fn enforcement_mode_display() {
        assert_eq!(EnforcementMode::Audit.to_string(), "audit");
        assert_eq!(EnforcementMode::Warn.to_string(), "warn");
        assert_eq!(EnforcementMode::Enforce.to_string(), "enforce");
    }

    #[test]
    fn enforcement_mode_serde_roundtrip() {
        for mode in [
            EnforcementMode::Audit,
            EnforcementMode::Warn,
            EnforcementMode::Enforce,
        ] {
            let toml_str = format!("mode = \"{}\"", mode);
            #[derive(Deserialize)]
            struct Wrapper {
                mode: EnforcementMode,
            }
            let w: Wrapper = toml::from_str(&toml_str).unwrap();
            assert_eq!(w.mode, mode);
        }
    }

    // ── Merge: deny lists ───────────────────────────────────────────

    #[test]
    fn merge_deny_lists_are_unioned() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                denied_sinks: vec![SinkClass::EmailSend],
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            denied_sinks: vec![SinkClass::CloudMutation],
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        assert!(merged.denied_sinks.contains(&SinkClass::EmailSend));
        assert!(merged.denied_sinks.contains(&SinkClass::CloudMutation));
    }

    #[test]
    fn merge_deny_lists_no_duplicates() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                denied_sinks: vec![SinkClass::EmailSend],
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            denied_sinks: vec![SinkClass::EmailSend], // same as org
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        assert_eq!(
            merged
                .denied_sinks
                .iter()
                .filter(|s| **s == SinkClass::EmailSend)
                .count(),
            1
        );
    }

    // ── Merge: allow lists ──────────────────────────────────────────

    #[test]
    fn merge_allow_lists_intersection() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                allowed_sinks: Some(vec![
                    SinkClass::WorkspaceWrite,
                    SinkClass::BashExec,
                    SinkClass::GitCommit,
                ]),
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            allowed_sinks: Some(vec![
                SinkClass::BashExec,
                SinkClass::GitCommit,
                SinkClass::HTTPEgress, // not in org → filtered out
            ]),
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        let allowed = merged.allowed_sinks.unwrap();
        assert!(allowed.contains(&SinkClass::BashExec));
        assert!(allowed.contains(&SinkClass::GitCommit));
        // WorkspaceWrite is in org but not local → excluded.
        assert!(!allowed.contains(&SinkClass::WorkspaceWrite));
        // HTTPEgress is in local but not org → excluded.
        assert!(!allowed.contains(&SinkClass::HTTPEgress));
    }

    #[test]
    fn merge_allow_list_org_restricted_local_unrestricted() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                allowed_sinks: Some(vec![SinkClass::WorkspaceWrite]),
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            allowed_sinks: None, // local doesn't restrict
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        // Org restriction wins.
        let allowed = merged.allowed_sinks.unwrap();
        assert_eq!(allowed, vec![SinkClass::WorkspaceWrite]);
    }

    #[test]
    fn merge_allow_list_both_unrestricted() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                allowed_sinks: None,
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            allowed_sinks: None,
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        assert!(merged.allowed_sinks.is_none());
    }

    // ── Merge: scalars ──────────────────────────────────────────────

    #[test]
    fn merge_scalars_org_takes_precedence() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                max_delegation_depth: Some(2),
                required_receipt_signing: true,
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            max_delegation_depth: Some(10), // local wants more → org wins
            required_receipt_signing: false,
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        assert_eq!(merged.max_delegation_depth, Some(2));
        assert!(merged.required_receipt_signing);
    }

    #[test]
    fn merge_scalars_org_none_uses_local() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                max_delegation_depth: None, // org doesn't set
                required_receipt_signing: false,
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            max_delegation_depth: Some(5),
            required_receipt_signing: false,
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        assert_eq!(merged.max_delegation_depth, Some(5));
    }

    // ── Merge: MCP servers / hook sources ───────────────────────────

    #[test]
    fn merge_mcp_servers_intersection() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                allowed_mcp_servers: vec![
                    ManifestHash {
                        name: "fs".into(),
                        sha256: "aaa".into(),
                    },
                    ManifestHash {
                        name: "github".into(),
                        sha256: "bbb".into(),
                    },
                ],
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            allowed_mcp_servers: vec![
                ManifestHash {
                    name: "fs".into(),
                    sha256: "aaa".into(),
                },
                ManifestHash {
                    name: "custom".into(),
                    sha256: "ccc".into(),
                },
            ],
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        assert_eq!(merged.allowed_mcp_servers.len(), 1);
        assert_eq!(merged.allowed_mcp_servers[0].sha256, "aaa");
    }

    #[test]
    fn merge_hook_sources_intersection() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                allowed_hook_sources: vec![
                    SignedSource {
                        path: "a.sh".into(),
                        signing_key: "ed25519:k1".into(),
                    },
                    SignedSource {
                        path: "b.sh".into(),
                        signing_key: "ed25519:k2".into(),
                    },
                ],
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            allowed_hook_sources: vec![SignedSource {
                path: "a.sh".into(),
                signing_key: "ed25519:k1".into(),
            }],
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        assert_eq!(merged.allowed_hook_sources.len(), 1);
        assert_eq!(merged.allowed_hook_sources[0].signing_key, "ed25519:k1");
    }

    // ── Merge: no org policy ────────────────────────────────────────

    #[test]
    fn merge_no_org_policy_returns_local_unchanged() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: None,
        };

        let local = EnterpriseAllowlist {
            denied_sinks: vec![SinkClass::EmailSend],
            max_delegation_depth: Some(5),
            ..Default::default()
        };

        let merged = settings.merge_with_local(&local);
        assert_eq!(merged, local);
    }

    // ── is_sink_allowed ─────────────────────────────────────────────

    #[test]
    fn is_sink_allowed_checks_merged_policy() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                denied_sinks: vec![SinkClass::EmailSend],
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist::default();

        assert!(!settings.is_sink_allowed(SinkClass::EmailSend, &local));
        assert!(settings.is_sink_allowed(SinkClass::WorkspaceWrite, &local));
    }

    #[test]
    fn is_sink_allowed_local_deny_also_applies() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist::default()),
        };

        let local = EnterpriseAllowlist {
            denied_sinks: vec![SinkClass::CloudMutation],
            ..Default::default()
        };

        assert!(!settings.is_sink_allowed(SinkClass::CloudMutation, &local));
    }

    #[test]
    fn is_sink_allowed_local_cannot_widen_org_allowlist() {
        let settings = ManagedSettings {
            policy_artifact_ref: None,
            required_compartment_image: None,
            enforcement_mode: EnforcementMode::Enforce,
            update_interval_secs: 3600,
            org_policy: Some(EnterpriseAllowlist {
                allowed_sinks: Some(vec![SinkClass::WorkspaceWrite]),
                ..Default::default()
            }),
        };

        let local = EnterpriseAllowlist {
            // Local tries to add HTTPEgress — should be rejected.
            allowed_sinks: Some(vec![SinkClass::WorkspaceWrite, SinkClass::HTTPEgress]),
            ..Default::default()
        };

        assert!(settings.is_sink_allowed(SinkClass::WorkspaceWrite, &local));
        assert!(!settings.is_sink_allowed(SinkClass::HTTPEgress, &local));
    }
}
