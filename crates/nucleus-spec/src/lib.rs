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

/// Errors resolving policies.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The named profile was not found.
    #[error("unknown policy profile: {0}")]
    UnknownProfile(String),
}
