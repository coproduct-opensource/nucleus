//! Identity-based policy enforcement for tool-proxy.
//!
//! This module integrates SPIFFE workload identity with the lattice-guard
//! policy system to enable zero-prompt authorization for AI agents.
//!
//! # Overview
//!
//! When a request comes in via mTLS with a SPIFFE identity, we:
//! 1. Extract the SPIFFE ID from the client certificate
//! 2. Look up the matching policy in the `IdentityPolicySet`
//! 3. Use the associated `PermissionLattice` to authorize operations
//!
//! This replaces the approval-based flow for pre-authorized operations,
//! enabling "zero prompt" execution for agents with matching policies.

use std::path::PathBuf;
use std::sync::Arc;

use lattice_guard::escalation::{EscalationPolicy, EscalationPolicySet};
use lattice_guard::identity::{IdentityPolicy, IdentityPolicySet};
use lattice_guard::PermissionLattice;
use serde::{Deserialize, Serialize};

/// Policy configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Version of the policy format.
    #[serde(default = "default_version")]
    pub version: String,

    /// List of identity-based policies.
    #[serde(default)]
    pub policies: Vec<PolicyRule>,

    /// List of escalation policies.
    #[serde(default)]
    pub escalation_policies: Vec<EscalationPolicyRule>,

    /// Default permissions for unmatched identities.
    #[serde(default)]
    pub default: Option<DefaultPolicy>,
}

fn default_version() -> String {
    "v1".to_string()
}

/// A single policy rule matching SPIFFE identities to permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Matcher for SPIFFE IDs (glob patterns supported).
    #[serde(rename = "match")]
    pub matcher: PolicyMatcher,

    /// Allowed operations.
    #[serde(default)]
    pub allow: Vec<PolicyOperation>,

    /// Denied operations (takes precedence over allow).
    #[serde(default)]
    pub deny: Vec<PolicyOperation>,

    /// Use a preset permission profile.
    #[serde(default)]
    pub preset: Option<String>,
}

/// Matcher for policy rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyMatcher {
    /// SPIFFE ID pattern (glob-style: * matches segment, ** matches any path).
    pub spiffe_id: String,
}

/// An operation specification in a policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOperation {
    /// The operation type.
    pub operation: String,

    /// Optional path patterns for filesystem operations.
    #[serde(default)]
    pub paths: Vec<String>,

    /// Optional command patterns for execute operations.
    #[serde(default)]
    pub commands: Vec<String>,

    /// Optional host patterns for web_fetch operations.
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// Default policy for unmatched identities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultPolicy {
    /// Use a preset permission profile.
    pub preset: String,
}

/// An escalation policy rule defining who can approve escalations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPolicyRule {
    /// SPIFFE ID pattern for requestors who can use this policy.
    pub requestor_pattern: String,

    /// SPIFFE ID pattern for approvers who can grant escalations.
    pub approver_pattern: String,

    /// Maximum permissions that can be granted via this policy (preset name).
    pub max_grant: String,

    /// Maximum TTL in seconds for grants under this policy.
    #[serde(default = "default_max_ttl")]
    pub max_ttl_seconds: u64,

    /// Whether this policy requires the approver to be in a different chain.
    #[serde(default = "default_require_distinct")]
    pub require_distinct_chains: bool,

    /// Whether this policy requires full attestation on both chains.
    /// Defaults to true for security - agents must prove their provenance.
    #[serde(default = "default_require_attestation")]
    pub require_attestation: bool,

    /// Human-readable description of this policy.
    #[serde(default)]
    pub description: String,
}

fn default_require_attestation() -> bool {
    true
}

fn default_max_ttl() -> u64 {
    3600 // 1 hour
}

fn default_require_distinct() -> bool {
    true
}

/// Runtime policy engine that evaluates requests against identity policies.
#[derive(Clone)]
pub struct PolicyEngine {
    policy_set: Arc<IdentityPolicySet>,
    escalation_policies: Arc<EscalationPolicySet>,
    zero_prompt_enabled: bool,
}

impl PolicyEngine {
    /// Create a new policy engine from configuration.
    pub fn from_config(config: &PolicyConfig) -> Self {
        let mut policy_set = IdentityPolicySet::new();

        for rule in &config.policies {
            let permissions = if let Some(preset) = &rule.preset {
                preset_to_permissions(preset)
            } else {
                // Build permissions from allow/deny rules
                build_permissions_from_rules(&rule.allow, &rule.deny)
            };

            policy_set.add_policy(IdentityPolicy::new(
                rule.matcher.spiffe_id.clone(),
                permissions,
            ));
        }

        // Set default permissions
        if let Some(default) = &config.default {
            let default_permissions = preset_to_permissions(&default.preset);
            policy_set = policy_set.with_default(default_permissions);
        }

        // Build escalation policies
        let mut escalation_policies = EscalationPolicySet::new();
        for rule in &config.escalation_policies {
            let max_grant = preset_to_permissions(&rule.max_grant);
            let policy =
                EscalationPolicy::new(&rule.requestor_pattern, &rule.approver_pattern, max_grant)
                    .with_max_ttl(rule.max_ttl_seconds)
                    .with_distinct_chains(rule.require_distinct_chains)
                    .with_attestation(rule.require_attestation)
                    .with_description(&rule.description);

            escalation_policies.add_policy(policy);
        }

        Self {
            policy_set: Arc::new(policy_set),
            escalation_policies: Arc::new(escalation_policies),
            zero_prompt_enabled: true,
        }
    }

    /// Create a policy engine with zero-prompt mode disabled.
    /// This means all operations still require explicit approval.
    pub fn disabled() -> Self {
        Self {
            policy_set: Arc::new(IdentityPolicySet::new()),
            escalation_policies: Arc::new(EscalationPolicySet::new()),
            zero_prompt_enabled: false,
        }
    }

    /// Check if zero-prompt mode is enabled.
    pub fn is_zero_prompt_enabled(&self) -> bool {
        self.zero_prompt_enabled
    }

    /// Get the permissions for a SPIFFE identity.
    ///
    /// Returns None if no matching policy and no default is set.
    pub fn permissions_for(&self, spiffe_id: &str) -> Option<&PermissionLattice> {
        if !self.zero_prompt_enabled {
            return None;
        }
        self.policy_set.permissions_for(spiffe_id)
    }

    /// Check if a SPIFFE identity has a matching policy.
    #[allow(dead_code)]
    pub fn has_policy_for(&self, spiffe_id: &str) -> bool {
        self.policy_set.has_policy_for(spiffe_id)
    }

    /// Get the matching policy for logging/debugging.
    pub fn matching_policy(&self, spiffe_id: &str) -> Option<&IdentityPolicy> {
        self.policy_set.matching_policy(spiffe_id)
    }

    /// Get the escalation policy set for processing escalation requests.
    pub fn escalation_policies(&self) -> &EscalationPolicySet {
        &self.escalation_policies
    }

    /// Check if any escalation policies are configured.
    pub fn has_escalation_policies(&self) -> bool {
        !self.escalation_policies.policies.is_empty()
    }
}

/// Load policy configuration from a YAML file.
pub async fn load_policy_file(path: &PathBuf) -> Result<PolicyConfig, PolicyError> {
    let contents = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| PolicyError::Io(e.to_string()))?;

    parse_policy_yaml(&contents)
}

/// Parse policy configuration from YAML string.
pub fn parse_policy_yaml(yaml: &str) -> Result<PolicyConfig, PolicyError> {
    serde_yaml::from_str(yaml).map_err(|e| PolicyError::Parse(e.to_string()))
}

/// Convert a preset name to a PermissionLattice.
fn preset_to_permissions(preset: &str) -> PermissionLattice {
    match preset.to_lowercase().as_str() {
        "codegen" => PermissionLattice::codegen(),
        "pr_review" | "pr-review" => PermissionLattice::pr_review(),
        "pr_approve" | "pr-approve" => PermissionLattice::pr_approve(),
        "code_review" | "code-review" => PermissionLattice::code_review(),
        "web_research" | "web-research" | "research" => PermissionLattice::web_research(),
        "restrictive" => PermissionLattice::restrictive(),
        "permissive" => PermissionLattice::permissive(),
        "network_only" | "network-only" => PermissionLattice::network_only(),
        "read_only" | "read-only" => PermissionLattice::read_only(),
        "filesystem_readonly" | "filesystem-readonly" => PermissionLattice::filesystem_readonly(),
        "edit_only" | "edit-only" => PermissionLattice::edit_only(),
        "local_dev" | "local-dev" => PermissionLattice::local_dev(),
        "fix_issue" | "fix-issue" => PermissionLattice::fix_issue(),
        "release" => PermissionLattice::release(),
        "database_client" | "database-client" => PermissionLattice::database_client(),
        "demo" => PermissionLattice::demo(),
        _ => {
            tracing::warn!(preset = %preset, "unknown preset, using restrictive");
            PermissionLattice::restrictive()
        }
    }
}

/// Build a PermissionLattice from allow/deny rules.
///
/// This is a simplified implementation - a full version would parse
/// the operation types and build appropriate capability levels.
fn build_permissions_from_rules(
    allow: &[PolicyOperation],
    deny: &[PolicyOperation],
) -> PermissionLattice {
    // For MVP, we use a base permissive lattice and restrict based on denies
    // A more complete implementation would build from scratch

    let mut base = if allow.is_empty() {
        PermissionLattice::restrictive()
    } else {
        // Start with codegen as a reasonable base for most agent workloads
        PermissionLattice::codegen()
    };

    // Check if any allow rules grant network access
    let has_network = allow
        .iter()
        .any(|op| op.operation == "web_fetch" || op.operation == "network" || !op.hosts.is_empty());

    if !has_network && !allow.is_empty() {
        // No network operations allowed, use read_only as a more restrictive base
        base = PermissionLattice::read_only();
    }

    // Check if any deny rules block filesystem writes
    let denies_write = deny
        .iter()
        .any(|op| op.operation == "filesystem_write" || op.operation == "write");

    if denies_write {
        base = base.meet(&PermissionLattice::read_only());
    }

    base
}

/// Policy-related errors.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("io error: {0}")]
    Io(String),

    #[error("parse error: {0}")]
    Parse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_policy_yaml() {
        let yaml = r#"
version: v1
policies:
  - match:
      spiffe_id: "spiffe://nucleus.local/ns/*/sa/coder-*"
    preset: codegen

  - match:
      spiffe_id: "spiffe://nucleus.local/ns/*/sa/reviewer-*"
    preset: pr_review

default:
  preset: restrictive
"#;

        let config = parse_policy_yaml(yaml).unwrap();
        assert_eq!(config.version, "v1");
        assert_eq!(config.policies.len(), 2);
        assert_eq!(
            config.policies[0].matcher.spiffe_id,
            "spiffe://nucleus.local/ns/*/sa/coder-*"
        );
        assert_eq!(config.policies[0].preset, Some("codegen".to_string()));
        assert!(config.default.is_some());
    }

    #[test]
    fn test_policy_engine_lookup() {
        let yaml = r#"
version: v1
policies:
  - match:
      spiffe_id: "spiffe://nucleus.local/ns/*/sa/coder-*"
    preset: codegen

  - match:
      spiffe_id: "spiffe://nucleus.local/ns/*/sa/reviewer-*"
    preset: pr_review

default:
  preset: restrictive
"#;

        let config = parse_policy_yaml(yaml).unwrap();
        let engine = PolicyEngine::from_config(&config);

        // Coder should match codegen
        let perms = engine
            .permissions_for("spiffe://nucleus.local/ns/default/sa/coder-001")
            .unwrap();
        assert_eq!(
            perms.description,
            "Code generation permissions (network-isolated)"
        );

        // Reviewer should match pr_review
        let perms = engine
            .permissions_for("spiffe://nucleus.local/ns/default/sa/reviewer-001")
            .unwrap();
        assert_eq!(perms.description, "PR review permissions");

        // Unknown should get default (restrictive)
        let perms = engine
            .permissions_for("spiffe://nucleus.local/ns/default/sa/unknown")
            .unwrap();
        assert_eq!(perms.description, "Restrictive permissions");
    }

    #[test]
    fn test_policy_engine_no_match() {
        let yaml = r#"
version: v1
policies:
  - match:
      spiffe_id: "spiffe://nucleus.local/ns/prod/sa/coder-*"
    preset: codegen
"#;

        let config = parse_policy_yaml(yaml).unwrap();
        let engine = PolicyEngine::from_config(&config);

        // No default set, so unmatched should return None
        assert!(engine
            .permissions_for("spiffe://nucleus.local/ns/dev/sa/coder-001")
            .is_none());
    }

    #[test]
    fn test_policy_engine_disabled() {
        let engine = PolicyEngine::disabled();

        // Should never return permissions when disabled
        assert!(engine
            .permissions_for("spiffe://nucleus.local/ns/default/sa/coder-001")
            .is_none());
        assert!(!engine.is_zero_prompt_enabled());
    }

    #[test]
    fn test_preset_mapping() {
        assert_eq!(
            preset_to_permissions("codegen").description,
            "Code generation permissions (network-isolated)"
        );
        assert_eq!(
            preset_to_permissions("pr_review").description,
            "PR review permissions"
        );
        assert_eq!(
            preset_to_permissions("pr-review").description,
            "PR review permissions"
        );
        assert_eq!(
            preset_to_permissions("restrictive").description,
            "Restrictive permissions"
        );
        // Unknown preset defaults to restrictive
        assert_eq!(
            preset_to_permissions("nonexistent").description,
            "Restrictive permissions"
        );
    }

    #[test]
    fn test_parse_allow_deny_rules() {
        let yaml = r#"
version: v1
policies:
  - match:
      spiffe_id: "spiffe://nucleus.local/ns/*/sa/agent-*"
    allow:
      - operation: filesystem_read
        paths: ["/workspace/**"]
      - operation: execute
        commands: ["npm *", "cargo *"]
    deny:
      - operation: filesystem_write
        paths: ["/workspace/.env*"]
"#;

        let config = parse_policy_yaml(yaml).unwrap();
        assert_eq!(config.policies.len(), 1);
        assert_eq!(config.policies[0].allow.len(), 2);
        assert_eq!(config.policies[0].deny.len(), 1);
        assert_eq!(config.policies[0].allow[0].operation, "filesystem_read");
        assert_eq!(config.policies[0].allow[0].paths, vec!["/workspace/**"]);
    }
}
