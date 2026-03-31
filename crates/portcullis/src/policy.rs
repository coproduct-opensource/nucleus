//! Policy compiler — `.nucleus/policy.toml` → runtime configuration.
//!
//! A policy file is the declarative source of truth for a session's
//! security configuration. It compiles deterministically to a
//! `PermissionLattice` + compartment rules.
//!
//! ## Example policy.toml
//!
//! ```toml
//! [profile]
//! name = "my-project"
//! description = "Security policy for my-project"
//!
//! [profile.capabilities]
//! read_files = "always"
//! write_files = "low_risk"
//! run_bash = "low_risk"
//! web_fetch = "low_risk"
//! git_push = "never"
//!
//! [profile.budget]
//! max_cost_usd = 5.0
//!
//! [compartments]
//! default = "draft"
//!
//! [compartments.overrides.research]
//! write_files = "never"
//! run_bash = "never"
//! web_fetch = "always"
//!
//! [compartments.overrides.execute]
//! run_bash = "always"
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::profile::ProfileSpec;
use portcullis_core::compartment::Compartment;
use portcullis_core::manifest::ManifestPolicy;
use portcullis_core::CapabilityLevel;

/// A compiled policy — the output of the policy compiler.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    /// The permission lattice compiled from the profile spec.
    pub profile: ProfileSpec,
    /// Default compartment (if any).
    pub default_compartment: Option<Compartment>,
    /// Per-compartment capability overrides.
    pub compartment_overrides: BTreeMap<Compartment, CapabilityOverrides>,
    /// SHA-256 hash of the canonical TOML input (for reproducibility).
    pub source_hash: [u8; 32],
    /// Policy for tools without manifests (#588).
    pub manifest_policy: ManifestPolicy,
}

/// Capability overrides for a specific compartment.
///
/// Only specified fields override the base profile. `None` means
/// "inherit from the profile's default for this compartment."
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[allow(missing_docs)]
pub struct CapabilityOverrides {
    #[serde(default)]
    pub read_files: Option<CapabilityLevel>,
    #[serde(default)]
    pub write_files: Option<CapabilityLevel>,
    #[serde(default)]
    pub edit_files: Option<CapabilityLevel>,
    #[serde(default)]
    pub run_bash: Option<CapabilityLevel>,
    #[serde(default)]
    pub glob_search: Option<CapabilityLevel>,
    #[serde(default)]
    pub grep_search: Option<CapabilityLevel>,
    #[serde(default)]
    pub web_search: Option<CapabilityLevel>,
    #[serde(default)]
    pub web_fetch: Option<CapabilityLevel>,
    #[serde(default)]
    pub git_commit: Option<CapabilityLevel>,
    #[serde(default)]
    pub git_push: Option<CapabilityLevel>,
    #[serde(default)]
    pub create_pr: Option<CapabilityLevel>,
    #[serde(default)]
    pub manage_pods: Option<CapabilityLevel>,
    #[serde(default)]
    pub spawn_agent: Option<CapabilityLevel>,
}

/// Raw TOML policy file structure (internal).
#[derive(Debug, Deserialize)]
struct PolicyFile {
    /// Profile specification.
    profile: ProfileSpec,
    /// Compartment configuration.
    #[serde(default)]
    compartments: Option<CompartmentsConfig>,
    /// Manifest policy: "default_deny" or "default_allow" (default).
    /// Controls whether tools without manifests are rejected (#588).
    #[serde(default)]
    manifest_policy: ManifestPolicyStr,
}

/// String representation for TOML deserialization.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ManifestPolicyStr {
    /// Tools without manifests are rejected.
    DefaultDeny,
    /// Tools without manifests are allowed (default for backward compat).
    #[default]
    DefaultAllow,
}

impl From<ManifestPolicyStr> for ManifestPolicy {
    fn from(s: ManifestPolicyStr) -> Self {
        match s {
            ManifestPolicyStr::DefaultDeny => ManifestPolicy::DefaultDeny,
            ManifestPolicyStr::DefaultAllow => ManifestPolicy::DefaultAllow,
        }
    }
}

/// Compartment configuration section.
#[derive(Debug, Deserialize)]
struct CompartmentsConfig {
    /// Default compartment name.
    #[serde(default)]
    default: Option<String>,
    /// Per-compartment capability overrides.
    #[serde(default)]
    overrides: BTreeMap<String, CapabilityOverrides>,
}

/// Policy compilation errors.
#[derive(Debug)]
pub enum PolicyError {
    /// Failed to read the policy file.
    Io(std::io::Error),
    /// Failed to parse the TOML content.
    Toml(toml::de::Error),
    /// A compartment name in the policy is not recognized.
    UnknownCompartment(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::Io(e) => write!(f, "failed to read policy file: {e}"),
            PolicyError::Toml(e) => write!(f, "failed to parse policy TOML: {e}"),
            PolicyError::UnknownCompartment(s) => write!(f, "unknown compartment: {s}"),
        }
    }
}

impl From<std::io::Error> for PolicyError {
    fn from(e: std::io::Error) -> Self {
        PolicyError::Io(e)
    }
}

impl From<toml::de::Error> for PolicyError {
    fn from(e: toml::de::Error) -> Self {
        PolicyError::Toml(e)
    }
}

/// Compile a policy from a TOML file.
///
/// The compilation is deterministic: identical TOML input always
/// produces an identical `CompiledPolicy` (including `source_hash`).
pub fn compile_policy(path: &Path) -> Result<CompiledPolicy, PolicyError> {
    let content = std::fs::read_to_string(path)?;
    compile_policy_str(&content)
}

/// Compile a policy from a TOML string.
pub fn compile_policy_str(toml_content: &str) -> Result<CompiledPolicy, PolicyError> {
    // Deterministic hash of the source
    let mut hasher = Sha256::new();
    hasher.update(toml_content.as_bytes());
    let hash = hasher.finalize();
    let mut source_hash = [0u8; 32];
    source_hash.copy_from_slice(&hash);

    let policy_file: PolicyFile = toml::from_str(toml_content)?;

    let mut default_compartment = None;
    let mut compartment_overrides = BTreeMap::new();

    if let Some(compartments) = policy_file.compartments {
        if let Some(default_name) = compartments.default {
            default_compartment = Some(
                Compartment::from_str_opt(&default_name)
                    .ok_or(PolicyError::UnknownCompartment(default_name))?,
            );
        }
        for (name, overrides) in compartments.overrides {
            let compartment =
                Compartment::from_str_opt(&name).ok_or(PolicyError::UnknownCompartment(name))?;
            compartment_overrides.insert(compartment, overrides);
        }
    }

    Ok(CompiledPolicy {
        profile: policy_file.profile,
        default_compartment,
        compartment_overrides,
        source_hash,
        manifest_policy: policy_file.manifest_policy.into(),
    })
}

impl CompiledPolicy {
    /// Hex-encoded source hash for display/comparison.
    pub fn source_hash_hex(&self) -> String {
        hex::encode(self.source_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL_POLICY: &str = r#"
[profile]
name = "test-policy"
description = "Minimal test policy"

[profile.capabilities]
read_files = "always"
write_files = "low_risk"
run_bash = "never"
"#;

    const FULL_POLICY: &str = r#"
[profile]
name = "full-policy"
description = "Full policy with compartments"

[profile.capabilities]
read_files = "always"
write_files = "low_risk"
run_bash = "low_risk"
web_fetch = "low_risk"
git_push = "never"

[profile.budget]
max_cost_usd = "5.0"

[compartments]
default = "draft"

[compartments.overrides.research]
write_files = "never"
run_bash = "never"
web_fetch = "always"

[compartments.overrides.execute]
run_bash = "always"
"#;

    #[test]
    fn compile_minimal_policy() {
        let policy = compile_policy_str(MINIMAL_POLICY).unwrap();
        assert_eq!(policy.profile.name, "test-policy");
        assert_eq!(
            policy.profile.capabilities.read_files,
            CapabilityLevel::Always
        );
        assert_eq!(policy.profile.capabilities.run_bash, CapabilityLevel::Never);
        assert!(policy.default_compartment.is_none());
        assert!(policy.compartment_overrides.is_empty());
    }

    #[test]
    fn compile_full_policy_with_compartments() {
        let policy = compile_policy_str(FULL_POLICY).unwrap();
        assert_eq!(policy.profile.name, "full-policy");
        assert_eq!(policy.default_compartment, Some(Compartment::Draft));
        assert_eq!(policy.compartment_overrides.len(), 2);

        // Research overrides
        let research = &policy.compartment_overrides[&Compartment::Research];
        assert_eq!(research.write_files, Some(CapabilityLevel::Never));
        assert_eq!(research.run_bash, Some(CapabilityLevel::Never));
        assert_eq!(research.web_fetch, Some(CapabilityLevel::Always));

        // Execute overrides
        let execute = &policy.compartment_overrides[&Compartment::Execute];
        assert_eq!(execute.run_bash, Some(CapabilityLevel::Always));
    }

    #[test]
    fn source_hash_is_deterministic() {
        let p1 = compile_policy_str(MINIMAL_POLICY).unwrap();
        let p2 = compile_policy_str(MINIMAL_POLICY).unwrap();
        assert_eq!(p1.source_hash, p2.source_hash);
        assert_eq!(p1.source_hash_hex(), p2.source_hash_hex());
    }

    #[test]
    fn source_hash_changes_with_content() {
        let p1 = compile_policy_str(MINIMAL_POLICY).unwrap();
        let p2 = compile_policy_str(FULL_POLICY).unwrap();
        assert_ne!(p1.source_hash, p2.source_hash);
    }

    #[test]
    fn unknown_compartment_is_error() {
        let bad = r#"
[profile]
name = "bad"

[compartments]
default = "nonexistent"
"#;
        let result = compile_policy_str(bad);
        assert!(matches!(result, Err(PolicyError::UnknownCompartment(_))));
    }

    #[test]
    fn default_manifest_policy_is_allow() {
        let policy = compile_policy_str(MINIMAL_POLICY).unwrap();
        assert_eq!(policy.manifest_policy, ManifestPolicy::DefaultAllow);
    }

    #[test]
    fn manifest_policy_default_deny() {
        let toml = r#"
manifest_policy = "default_deny"

[profile]
name = "strict"

[profile.capabilities]
read_files = "always"
"#;
        let policy = compile_policy_str(toml).unwrap();
        assert_eq!(policy.manifest_policy, ManifestPolicy::DefaultDeny);
    }

    #[test]
    fn unknown_compartment_override_is_error() {
        let bad = r#"
[profile]
name = "bad"

[compartments.overrides.invalid]
run_bash = "always"
"#;
        let result = compile_policy_str(bad);
        assert!(matches!(result, Err(PolicyError::UnknownCompartment(_))));
    }
}
