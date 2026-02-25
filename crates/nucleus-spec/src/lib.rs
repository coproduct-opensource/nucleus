//! PodSpec definitions shared by nucleus-node and nucleus-tool-proxy.

use std::collections::BTreeMap;
use std::path::PathBuf;

use lattice_guard::PermissionLattice;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level pod spec document (YAML/JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSpec {
    /// API version for the spec.
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    /// Kind of the spec (should be "Pod").
    pub kind: String,
    /// Metadata about the pod.
    #[serde(default)]
    pub metadata: Metadata,
    /// Pod specification.
    pub spec: PodSpecInner,
}

impl PodSpec {
    /// Create a new PodSpec with defaults for version and kind.
    pub fn new(spec: PodSpecInner) -> Self {
        Self {
            api_version: "nucleus/v1".to_string(),
            kind: "Pod".to_string(),
            metadata: Metadata::default(),
            spec,
        }
    }
}

/// Metadata for a pod.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Metadata {
    /// Optional pod name.
    pub name: Option<String>,
    /// Optional namespace for identity derivation.
    /// When set, this controls the SPIFFE namespace (e.g., "agents" for durable
    /// agent identities, "default" for ephemeral pods).
    /// Defaults to "default" when not specified.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Optional labels.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Inner spec fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodSpecInner {
    /// Working directory for the pod.
    #[serde(default = "default_work_dir")]
    pub work_dir: PathBuf,
    /// Timeout in seconds for pod execution.
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    /// Permission policy.
    #[serde(default)]
    pub policy: PolicySpec,
    /// Optional budget model overrides.
    #[serde(default)]
    pub budget_model: Option<BudgetModelSpec>,
    /// Optional resource hints.
    #[serde(default)]
    pub resources: Option<ResourceSpec>,
    /// Optional network hints.
    #[serde(default)]
    pub network: Option<NetworkSpec>,
    /// Optional VM image hints (Firecracker).
    #[serde(default)]
    pub image: Option<ImageSpec>,
    /// Optional vsock configuration for VM communication.
    #[serde(default)]
    pub vsock: Option<VsockSpec>,
    /// Optional seccomp policy for Firecracker.
    #[serde(default)]
    pub seccomp: Option<SeccompSpec>,
    /// Optional cgroup placement for Firecracker process.
    #[serde(default)]
    pub cgroup: Option<CgroupSpec>,
    /// Optional credentials to inject into the pod.
    /// These are passed as environment variables to the pod's workload.
    ///
    /// SECURITY NOTE: Credentials should never be logged. Implementations
    /// must redact credential values in any debug output or audit logs.
    #[serde(default)]
    pub credentials: Option<CredentialsSpec>,
    /// Additional repositories for multi-repo execution.
    ///
    /// When specified, these repos are made accessible alongside the primary `work_dir`.
    /// Each repo is identified by its name (or path basename if name is omitted)
    /// and can be targeted in tool operations (read, write, run) via the `repo` field.
    ///
    /// Use this for cross-repo tasks where an agent must work across multiple repositories.
    #[serde(default)]
    pub repos: Vec<RepoSpec>,
}

/// A repository specification for multi-repo execution.
///
/// Each `RepoSpec` defines an additional repository that will be sandboxed
/// alongside the pod's primary `work_dir`. Repos are addressed by name in
/// tool operations (read, write, run).
///
/// # Example (YAML)
/// ```yaml
/// spec:
///   work_dir: /path/to/primary-repo
///   repos:
///     - path: /path/to/secondary-repo
///       name: secondary
///     - path: /path/to/third-repo
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSpec {
    /// Path to the repository on the host.
    pub path: PathBuf,
    /// Optional name/identifier for the repo.
    ///
    /// Used to address this repo in tool operations. If not specified,
    /// defaults to the basename of the path (e.g., `/home/user/my-lib` → `my-lib`).
    #[serde(default)]
    pub name: Option<String>,
}

impl RepoSpec {
    /// Get the effective name of this repo.
    ///
    /// Returns the explicit name if set, otherwise the basename of the path.
    pub fn effective_name(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            self.path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "repo".to_string())
        })
    }
}

impl PodSpecInner {
    /// Resolve the policy spec to a concrete lattice.
    pub fn resolve_policy(&self) -> Result<PermissionLattice, PolicyError> {
        self.policy.resolve()
    }
}

fn default_work_dir() -> PathBuf {
    PathBuf::from(".")
}

fn default_timeout_seconds() -> u64 {
    3600
}

/// Policy spec for a pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicySpec {
    /// Use a named profile.
    Profile { name: String },
    /// Inline permission lattice.
    Inline { lattice: Box<PermissionLattice> },
}

impl Default for PolicySpec {
    fn default() -> Self {
        Self::Profile {
            name: "default".to_string(),
        }
    }
}

impl PolicySpec {
    /// Resolve a policy spec to a PermissionLattice.
    pub fn resolve(&self) -> Result<PermissionLattice, PolicyError> {
        match self {
            PolicySpec::Profile { name } => match name.as_str() {
                "default" => Ok(PermissionLattice::default()),
                "fix_issue" => Ok(PermissionLattice::fix_issue()),
                "demo" => Ok(PermissionLattice::demo()),
                // Workflow profiles for orchestrated agent tasks
                "pr_review" | "pr-review" => Ok(PermissionLattice::pr_review()),
                "codegen" => Ok(PermissionLattice::codegen()),
                "pr_approve" | "pr-approve" => Ok(PermissionLattice::pr_approve()),
                // Other profiles
                "read_only" | "read-only" => Ok(PermissionLattice::read_only()),
                "permissive" => Ok(PermissionLattice::permissive()),
                "restrictive" => Ok(PermissionLattice::restrictive()),
                "local_dev" | "local-dev" => Ok(PermissionLattice::local_dev()),
                "code_review" | "code-review" => Ok(PermissionLattice::code_review()),
                "web_research" | "web-research" => Ok(PermissionLattice::web_research()),
                "network_only" | "network-only" => Ok(PermissionLattice::network_only()),
                "edit_only" | "edit-only" => Ok(PermissionLattice::edit_only()),
                "release" => Ok(PermissionLattice::release()),
                "database_client" | "database-client" => Ok(PermissionLattice::database_client()),
                "orchestrator" => Ok(PermissionLattice::orchestrator()),
                "filesystem_readonly" | "filesystem-readonly" => {
                    Ok(PermissionLattice::filesystem_readonly())
                }
                other => Err(PolicyError::UnknownProfile(other.to_string())),
            },
            PolicySpec::Inline { lattice } => Ok(lattice.as_ref().clone().normalize()),
        }
    }
}

/// Budget model override spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetModelSpec {
    /// Base cost for any execution.
    pub base_cost_usd: f64,
    /// Cost per second of allowed execution time.
    pub cost_per_second_usd: f64,
}

/// Resource hints for the pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    /// CPU cores requested.
    pub cpu_cores: Option<u32>,
    /// Memory size in MiB.
    pub memory_mib: Option<u64>,
}

/// Network hints for the pod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSpec {
    /// Allowed egress destinations.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Denied egress destinations.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Allowed DNS hostnames (resolved and pinned at pod start).
    #[serde(default)]
    pub dns_allow: Vec<String>,
}

/// VM image configuration for Firecracker pods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSpec {
    /// Path to the kernel image.
    pub kernel_path: PathBuf,
    /// Path to the root filesystem image.
    pub rootfs_path: PathBuf,
    /// Optional kernel boot args.
    #[serde(default)]
    pub boot_args: Option<String>,
    /// Whether the root filesystem should be mounted read-only.
    #[serde(default)]
    pub read_only: bool,
    /// Optional scratch disk image for writable storage.
    #[serde(default)]
    pub scratch_path: Option<PathBuf>,
}

/// Vsock configuration for VM communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsockSpec {
    /// Guest CID for vsock.
    pub guest_cid: u32,
    /// Guest vsock port to listen on.
    pub port: u32,
}

/// Seccomp policy for Firecracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SeccompSpec {
    /// Use Firecracker defaults.
    Default,
    /// Disable seccomp entirely (not recommended).
    Disabled,
    /// Use a custom seccomp filter.
    Custom { filter_path: PathBuf },
}

/// Cgroup placement and settings for the Firecracker process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupSpec {
    /// Path to the cgroup directory.
    pub path: PathBuf,
    /// Settings to write before placing the process.
    #[serde(default)]
    pub settings: Vec<CgroupSetting>,
}

/// A single cgroup file + value to write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CgroupSetting {
    /// File name inside the cgroup directory (e.g. \"cpu.max\").
    pub file: String,
    /// Value to write to the file.
    pub value: String,
}

/// Credentials to inject into a pod.
///
/// Credentials are passed securely to the pod's workload as environment variables.
/// Values are stored in memory-mapped tmpfs and never written to persistent storage.
///
/// SECURITY NOTE: This struct implements a custom `Debug` that redacts secret values.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CredentialsSpec {
    /// Environment variables containing credentials.
    /// Keys are the variable names (e.g., `LLM_API_TOKEN`), values are the secrets.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl std::fmt::Debug for CredentialsSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact all credential values for safe debug output
        let redacted: BTreeMap<&str, &str> = self
            .env
            .keys()
            .map(|k| (k.as_str(), "[REDACTED]"))
            .collect();
        f.debug_struct("CredentialsSpec")
            .field("env", &redacted)
            .finish()
    }
}

impl CredentialsSpec {
    /// Create a new empty credentials spec.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an environment variable credential.
    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Check if credentials are empty.
    pub fn is_empty(&self) -> bool {
        self.env.is_empty()
    }

    /// Get a redacted representation for logging.
    pub fn redacted(&self) -> BTreeMap<&str, &str> {
        self.env
            .keys()
            .map(|k| (k.as_str(), "[REDACTED]"))
            .collect()
    }
}

/// Compute SHA-256 of a byte slice and return the hex string.
pub fn sha256_bytes_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

/// Exit report written by the tool-proxy before shutdown.
///
/// Contains a deterministic workspace content hash and the audit chain tail
/// so the host (nucleus-node) can build an `ExecutionReceipt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitReport {
    /// SHA-256 of workspace contents at exit.
    pub workspace_hash: String,
    /// Hash of the last audit log entry.
    pub audit_tail_hash: String,
    /// Total number of audit log entries.
    pub audit_entry_count: u64,
    /// Unix timestamp when the report was generated.
    pub timestamp_unix: u64,
}

/// Errors resolving policies.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The named profile was not found.
    #[error("unknown policy profile: {0}")]
    UnknownProfile(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_workflow_profile_resolution() {
        // Test workflow profile aliases
        let profiles = [
            ("pr_review", "PR review permissions"),
            ("pr-review", "PR review permissions"),
            ("codegen", "Code generation permissions (network-isolated)"),
            ("pr_approve", "PR approval permissions (CI-gated)"),
            ("pr-approve", "PR approval permissions (CI-gated)"),
            (
                "orchestrator",
                "Orchestrator permissions (pod management only)",
            ),
        ];

        for (name, expected_prefix) in profiles {
            let spec = PolicySpec::Profile {
                name: name.to_string(),
            };
            let result = spec.resolve();
            assert!(
                result.is_ok(),
                "Profile '{}' should resolve successfully",
                name
            );
            let lattice = result.unwrap();
            assert!(
                lattice.description.starts_with(expected_prefix),
                "Profile '{}' should have description starting with '{}', got '{}'",
                name,
                expected_prefix,
                lattice.description
            );
        }
    }

    #[test]
    fn test_all_profiles_resolve() {
        let profile_names = [
            "default",
            "fix_issue",
            "demo",
            "pr_review",
            "pr-review",
            "codegen",
            "pr_approve",
            "pr-approve",
            "orchestrator",
            "read_only",
            "read-only",
            "permissive",
            "restrictive",
            "local_dev",
            "local-dev",
            "code_review",
            "code-review",
            "web_research",
            "web-research",
            "network_only",
            "network-only",
            "edit_only",
            "edit-only",
            "release",
            "database_client",
            "database-client",
            "filesystem_readonly",
            "filesystem-readonly",
        ];

        for name in profile_names {
            let spec = PolicySpec::Profile {
                name: name.to_string(),
            };
            let result = spec.resolve();
            assert!(
                result.is_ok(),
                "Profile '{}' should resolve successfully, got: {:?}",
                name,
                result.err()
            );
        }
    }

    #[test]
    fn test_unknown_profile_error() {
        let spec = PolicySpec::Profile {
            name: "nonexistent".to_string(),
        };
        let result = spec.resolve();
        assert!(result.is_err());
        assert!(matches!(result, Err(PolicyError::UnknownProfile(_))));
    }

    #[test]
    fn test_credentials_spec_debug_redacts_values() {
        let creds = CredentialsSpec::new()
            .with_env("LLM_API_TOKEN", "super-secret-token-12345")
            .with_env("GITHUB_TOKEN", "ghp_abcdefghijklmnop");

        let debug_output = format!("{:?}", creds);

        // Debug output should NOT contain actual secret values
        assert!(
            !debug_output.contains("super-secret-token-12345"),
            "Debug output must not contain credential value: {}",
            debug_output
        );
        assert!(
            !debug_output.contains("ghp_abcdefghijklmnop"),
            "Debug output must not contain GitHub token: {}",
            debug_output
        );

        // Debug output should contain the key names (so we know what's configured)
        assert!(
            debug_output.contains("LLM_API_TOKEN"),
            "Debug output should show key names: {}",
            debug_output
        );
        assert!(
            debug_output.contains("GITHUB_TOKEN"),
            "Debug output should show key names: {}",
            debug_output
        );

        // Debug output should show [REDACTED]
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug output should show [REDACTED]: {}",
            debug_output
        );
    }

    #[test]
    fn test_credentials_spec_values_accessible() {
        let creds = CredentialsSpec::new().with_env("LLM_API_TOKEN", "super-secret-token-12345");

        // The actual value should still be accessible for runtime use
        assert_eq!(
            creds.env.get("LLM_API_TOKEN"),
            Some(&"super-secret-token-12345".to_string())
        );
    }

    #[test]
    fn test_credentials_spec_redacted_helper() {
        let creds = CredentialsSpec::new()
            .with_env("TOKEN_A", "secret1")
            .with_env("TOKEN_B", "secret2");

        let redacted = creds.redacted();

        // Keys should be present
        assert!(redacted.contains_key("TOKEN_A"));
        assert!(redacted.contains_key("TOKEN_B"));

        // Values should all be [REDACTED]
        assert_eq!(redacted.get("TOKEN_A"), Some(&"[REDACTED]"));
        assert_eq!(redacted.get("TOKEN_B"), Some(&"[REDACTED]"));
    }

    #[test]
    fn test_credentials_spec_is_empty() {
        let empty = CredentialsSpec::new();
        assert!(empty.is_empty());

        let with_env = CredentialsSpec::new().with_env("KEY", "value");
        assert!(!with_env.is_empty());
    }

    #[test]
    fn test_credentials_spec_yaml_serialization() {
        let creds = CredentialsSpec::new().with_env("LLM_API_TOKEN", "test-token");

        let yaml = serde_yaml::to_string(&creds).expect("should serialize");

        // YAML should contain the actual value (for transmission to nucleus-node)
        assert!(yaml.contains("test-token"));
        assert!(yaml.contains("LLM_API_TOKEN"));
    }

    #[test]
    fn test_pod_spec_with_credentials_parses() {
        let yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /tmp
  timeout_seconds: 300
  policy:
    type: profile
    name: default
  credentials:
    env:
      LLM_API_TOKEN: "secret-token-12345"
      GITHUB_TOKEN: "ghp_test"
"#;

        let spec: PodSpec = serde_yaml::from_str(yaml).expect("should parse");

        // Credentials should be parsed
        assert!(spec.spec.credentials.is_some());
        let creds = spec.spec.credentials.unwrap();
        assert_eq!(
            creds.env.get("LLM_API_TOKEN"),
            Some(&"secret-token-12345".to_string())
        );
        assert_eq!(creds.env.get("GITHUB_TOKEN"), Some(&"ghp_test".to_string()));
    }

    #[test]
    fn test_pod_spec_without_credentials_parses() {
        let yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /tmp
  policy:
    type: profile
    name: default
"#;

        let spec: PodSpec = serde_yaml::from_str(yaml).expect("should parse");

        // Credentials should be None when not specified
        assert!(spec.spec.credentials.is_none());
    }

    #[test]
    fn test_pod_spec_debug_redacts_credentials() {
        // Create a PodSpec with credentials
        let yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /tmp
  policy:
    type: profile
    name: default
  credentials:
    env:
      LLM_API_TOKEN: "sk-secret-12345-abcdef"
      GITHUB_TOKEN: "ghp_supersecret"
"#;

        let spec: PodSpec = serde_yaml::from_str(yaml).expect("should parse");

        // Debug format the entire PodSpec
        let debug_output = format!("{:?}", spec);

        // The debug output must NOT contain the actual secret values
        assert!(
            !debug_output.contains("sk-secret-12345-abcdef"),
            "PodSpec debug must not leak LLM_API_TOKEN: {}",
            debug_output
        );
        assert!(
            !debug_output.contains("ghp_supersecret"),
            "PodSpec debug must not leak GITHUB_TOKEN: {}",
            debug_output
        );

        // But it should show that credentials exist and show key names
        assert!(
            debug_output.contains("credentials"),
            "Debug should mention credentials field"
        );
        assert!(
            debug_output.contains("[REDACTED]"),
            "Debug should show redacted markers"
        );
    }

    #[test]
    fn test_metadata_namespace_backward_compat() {
        // YAML without namespace (existing PodSpecs) should parse fine
        let yaml_no_ns = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /tmp
  policy:
    type: profile
    name: default
"#;
        let spec: PodSpec =
            serde_yaml::from_str(yaml_no_ns).expect("should parse without namespace");
        assert!(spec.metadata.namespace.is_none());
        assert_eq!(spec.metadata.name.as_deref(), Some("test-pod"));

        // YAML with namespace should parse and preserve the value
        let yaml_with_ns = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: coder-alpha
  namespace: agents
spec:
  work_dir: /tmp
  policy:
    type: profile
    name: default
"#;
        let spec: PodSpec =
            serde_yaml::from_str(yaml_with_ns).expect("should parse with namespace");
        assert_eq!(spec.metadata.namespace.as_deref(), Some("agents"));
        assert_eq!(spec.metadata.name.as_deref(), Some("coder-alpha"));
    }

    #[test]
    fn test_metadata_namespace_roundtrip() {
        let metadata = Metadata {
            name: Some("test-agent".to_string()),
            namespace: Some("agents".to_string()),
            ..Default::default()
        };

        let yaml = serde_yaml::to_string(&metadata).expect("should serialize");
        assert!(yaml.contains("namespace: agents"));

        let parsed: Metadata = serde_yaml::from_str(&yaml).expect("should deserialize");
        assert_eq!(parsed.namespace.as_deref(), Some("agents"));
        assert_eq!(parsed.name.as_deref(), Some("test-agent"));
    }

    // ── RepoSpec tests ──────────────────────────────────────────────────────

    #[test]
    fn test_repo_spec_effective_name_with_explicit_name() {
        let repo = RepoSpec {
            path: PathBuf::from("/home/user/my-lib"),
            name: Some("explicit-name".to_string()),
        };
        assert_eq!(repo.effective_name(), "explicit-name");
    }

    #[test]
    fn test_repo_spec_effective_name_from_path_basename() {
        let repo = RepoSpec {
            path: PathBuf::from("/home/user/my-lib"),
            name: None,
        };
        assert_eq!(repo.effective_name(), "my-lib");
    }

    #[test]
    fn test_repo_spec_effective_name_relative_path() {
        let repo = RepoSpec {
            path: PathBuf::from("relative/path/to/repo"),
            name: None,
        };
        assert_eq!(repo.effective_name(), "repo");
    }

    #[test]
    fn test_repo_spec_effective_name_simple_name() {
        // A path that is just the repo name itself
        let repo = RepoSpec {
            path: PathBuf::from("nucleus"),
            name: None,
        };
        assert_eq!(repo.effective_name(), "nucleus");
    }

    #[test]
    fn test_repo_spec_effective_name_root_path_falls_back() {
        // "/" has no basename, so should fall back to "repo"
        let repo = RepoSpec {
            path: PathBuf::from("/"),
            name: None,
        };
        assert_eq!(repo.effective_name(), "repo");
    }

    #[test]
    fn test_repo_spec_effective_name_explicit_overrides_basename() {
        // Explicit name should win over whatever the basename would be
        let repo = RepoSpec {
            path: PathBuf::from("/workspace/boring-basename"),
            name: Some("friendly-name".to_string()),
        };
        assert_eq!(repo.effective_name(), "friendly-name");
        // The basename would have been "boring-basename"
        assert_ne!(repo.effective_name(), "boring-basename");
    }

    #[test]
    fn test_repo_spec_serialization_with_name() {
        let repo = RepoSpec {
            path: PathBuf::from("/path/to/secondary"),
            name: Some("secondary".to_string()),
        };
        let yaml = serde_yaml::to_string(&repo).expect("should serialize");
        assert!(yaml.contains("path:"), "yaml must include path: {}", yaml);
        assert!(yaml.contains("secondary"), "yaml must include name: {}", yaml);
    }

    #[test]
    fn test_repo_spec_serialization_without_name() {
        let repo = RepoSpec {
            path: PathBuf::from("/path/to/repo"),
            name: None,
        };
        let yaml = serde_yaml::to_string(&repo).expect("should serialize");
        assert!(yaml.contains("path:"), "yaml must include path: {}", yaml);
        // name: null or absent is acceptable; just verify path is present
        assert!(yaml.contains("/path/to/repo"), "yaml should contain path value: {}", yaml);
    }

    #[test]
    fn test_repo_spec_deserialization_with_name() {
        let yaml = r#"
path: /path/to/secondary
name: secondary
"#;
        let repo: RepoSpec = serde_yaml::from_str(yaml).expect("should deserialize");
        assert_eq!(repo.path, PathBuf::from("/path/to/secondary"));
        assert_eq!(repo.name.as_deref(), Some("secondary"));
        assert_eq!(repo.effective_name(), "secondary");
    }

    #[test]
    fn test_repo_spec_deserialization_without_name() {
        let yaml = r#"
path: /path/to/my-repo
"#;
        let repo: RepoSpec = serde_yaml::from_str(yaml).expect("should deserialize");
        assert_eq!(repo.path, PathBuf::from("/path/to/my-repo"));
        assert!(repo.name.is_none());
        // effective_name() should derive from path basename
        assert_eq!(repo.effective_name(), "my-repo");
    }

    #[test]
    fn test_repo_spec_roundtrip() {
        let original = RepoSpec {
            path: PathBuf::from("/workspace/secondary-repo"),
            name: Some("secondary".to_string()),
        };
        let yaml = serde_yaml::to_string(&original).expect("should serialize");
        let parsed: RepoSpec = serde_yaml::from_str(&yaml).expect("should deserialize");
        assert_eq!(parsed.path, original.path);
        assert_eq!(parsed.name, original.name);
        assert_eq!(parsed.effective_name(), original.effective_name());
    }

    // ── PodSpec with repos field tests ──────────────────────────────────────

    #[test]
    fn test_pod_spec_without_repos_defaults_empty() {
        let yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /tmp
  policy:
    type: profile
    name: default
"#;
        let spec: PodSpec = serde_yaml::from_str(yaml).expect("should parse");
        // repos should default to an empty Vec when not specified
        assert!(
            spec.spec.repos.is_empty(),
            "repos should default to empty vec, got: {:?}",
            spec.spec.repos
        );
    }

    #[test]
    fn test_pod_spec_with_single_repo_parses() {
        let yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /workspace/primary
  policy:
    type: profile
    name: default
  repos:
    - path: /workspace/secondary
      name: secondary
"#;
        let spec: PodSpec = serde_yaml::from_str(yaml).expect("should parse");
        assert_eq!(spec.spec.repos.len(), 1);
        assert_eq!(spec.spec.repos[0].path, PathBuf::from("/workspace/secondary"));
        assert_eq!(spec.spec.repos[0].name.as_deref(), Some("secondary"));
        assert_eq!(spec.spec.repos[0].effective_name(), "secondary");
    }

    #[test]
    fn test_pod_spec_with_multiple_repos_parses() {
        let yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /workspace/primary
  policy:
    type: profile
    name: default
  repos:
    - path: /workspace/secondary
      name: secondary
    - path: /workspace/third-repo
    - path: /workspace/lib
      name: shared-lib
"#;
        let spec: PodSpec = serde_yaml::from_str(yaml).expect("should parse");
        assert_eq!(spec.spec.repos.len(), 3);

        // First repo: explicit name
        assert_eq!(spec.spec.repos[0].effective_name(), "secondary");

        // Second repo: no name, should derive from basename
        assert_eq!(spec.spec.repos[1].effective_name(), "third-repo");
        assert!(spec.spec.repos[1].name.is_none());

        // Third repo: explicit name
        assert_eq!(spec.spec.repos[2].effective_name(), "shared-lib");
    }

    #[test]
    fn test_pod_spec_repos_all_have_names_derived() {
        // Verify effective_name() is always usable for every repo in the list
        let yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /workspace/primary
  policy:
    type: profile
    name: default
  repos:
    - path: /workspace/repo-a
    - path: /workspace/repo-b
    - path: /workspace/repo-c
"#;
        let spec: PodSpec = serde_yaml::from_str(yaml).expect("should parse");
        let names: Vec<String> = spec.spec.repos.iter().map(|r| r.effective_name()).collect();
        assert_eq!(names, vec!["repo-a", "repo-b", "repo-c"]);
    }

    #[test]
    fn test_pod_spec_repos_roundtrip() {
        let yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: multi-repo-pod
spec:
  work_dir: /workspace/primary
  timeout_seconds: 600
  policy:
    type: profile
    name: codegen
  repos:
    - path: /workspace/secondary
      name: secondary
    - path: /workspace/utils
"#;
        let spec: PodSpec = serde_yaml::from_str(yaml).expect("should parse");
        let serialized = serde_yaml::to_string(&spec).expect("should serialize");
        let reparsed: PodSpec = serde_yaml::from_str(&serialized).expect("should re-parse");

        assert_eq!(reparsed.spec.repos.len(), 2);
        assert_eq!(reparsed.spec.repos[0].effective_name(), "secondary");
        assert_eq!(reparsed.spec.repos[1].effective_name(), "utils");
        assert_eq!(reparsed.spec.work_dir, PathBuf::from("/workspace/primary"));
    }

    #[test]
    fn test_pod_spec_repos_backward_compat_existing_specs() {
        // Ensure existing PodSpecs (without repos) still parse correctly
        let legacy_yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: legacy-pod
spec:
  work_dir: /tmp/workspace
  timeout_seconds: 3600
  policy:
    type: profile
    name: default
  credentials:
    env:
      LLM_API_TOKEN: "test-token-123"
"#;
        let spec: PodSpec = serde_yaml::from_str(legacy_yaml).expect("legacy spec should parse");
        assert!(
            spec.spec.repos.is_empty(),
            "legacy spec should have no repos"
        );
        // Other fields must still be intact
        assert_eq!(spec.spec.work_dir, PathBuf::from("/tmp/workspace"));
        assert_eq!(spec.spec.timeout_seconds, 3600);
        let creds = spec.spec.credentials.expect("should have credentials");
        assert_eq!(
            creds.env.get("LLM_API_TOKEN").map(|s| s.as_str()),
            Some("test-token-123")
        );
    }

    #[test]
    fn test_pod_spec_empty_repos_list_explicit() {
        // Explicitly providing an empty repos list should work
        let yaml = r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test-pod
spec:
  work_dir: /tmp
  policy:
    type: profile
    name: default
  repos: []
"#;
        let spec: PodSpec = serde_yaml::from_str(yaml).expect("should parse");
        assert!(spec.spec.repos.is_empty());
    }

    #[test]
    fn test_repo_spec_names_uniqueness_by_effective_name() {
        // When using repos, callers need distinct effective names;
        // this test documents the behaviour when names would collide.
        let repos = vec![
            RepoSpec { path: PathBuf::from("/a/nucleus"), name: None },
            RepoSpec { path: PathBuf::from("/b/nucleus"), name: None },
        ];
        // Both would derive the same basename — effective_name is not guaranteed unique.
        // Document this: both return "nucleus", callers are responsible for disambiguation.
        assert_eq!(repos[0].effective_name(), "nucleus");
        assert_eq!(repos[1].effective_name(), "nucleus");
    }
}
