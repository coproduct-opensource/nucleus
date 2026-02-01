//! Configuration handling

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Main configuration file
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    /// Default permission profile
    #[serde(default)]
    pub default_profile: String,

    /// Budget settings
    #[serde(default)]
    pub budget: BudgetConfig,

    /// Authentication settings
    #[serde(default)]
    pub auth: AuthConfig,

    /// Lima VM settings (macOS)
    #[serde(default)]
    pub vm: VmConfig,

    /// nucleus-node settings
    #[serde(default)]
    pub node: NodeConfig,

    /// Firecracker settings
    #[serde(default)]
    pub firecracker: FirecrackerConfig,

    /// Time settings
    #[serde(default)]
    pub time: TimeConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BudgetConfig {
    /// Maximum cost per task in USD
    #[serde(default = "default_max_cost")]
    pub max_cost_usd: f64,

    /// Maximum input tokens
    #[serde(default = "default_input_tokens")]
    pub max_input_tokens: u64,

    /// Maximum output tokens
    #[serde(default = "default_output_tokens")]
    pub max_output_tokens: u64,
}

impl Default for BudgetConfig {
    fn default() -> Self {
        Self {
            max_cost_usd: default_max_cost(),
            max_input_tokens: default_input_tokens(),
            max_output_tokens: default_output_tokens(),
        }
    }
}

fn default_max_cost() -> f64 {
    5.0
}
fn default_input_tokens() -> u64 {
    100_000
}
fn default_output_tokens() -> u64 {
    10_000
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AuthConfig {
    /// Use macOS Keychain for secrets
    #[serde(default)]
    pub use_keychain: bool,
}

/// Lima VM configuration (macOS only)
#[derive(Debug, Serialize, Deserialize)]
pub struct VmConfig {
    /// Lima VM name
    #[serde(default = "default_vm_name")]
    pub name: String,

    /// Auto-start VM when running nucleus commands
    #[serde(default = "default_true")]
    pub auto_start: bool,

    /// VM CPUs
    #[serde(default = "default_vm_cpus")]
    pub cpus: u32,

    /// VM memory in GiB
    #[serde(default = "default_vm_memory")]
    pub memory_gib: u32,

    /// VM disk in GiB
    #[serde(default = "default_vm_disk")]
    pub disk_gib: u32,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            name: default_vm_name(),
            auto_start: true,
            cpus: default_vm_cpus(),
            memory_gib: default_vm_memory(),
            disk_gib: default_vm_disk(),
        }
    }
}

fn default_vm_name() -> String {
    "nucleus".to_string()
}
fn default_vm_cpus() -> u32 {
    4
}
fn default_vm_memory() -> u32 {
    8
}
fn default_vm_disk() -> u32 {
    50
}
fn default_true() -> bool {
    true
}

/// nucleus-node configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    /// nucleus-node HTTP endpoint
    #[serde(default = "default_node_url")]
    pub url: String,

    /// nucleus-node gRPC endpoint (optional)
    #[serde(default)]
    pub grpc_url: Option<String>,

    /// Actor name for signed requests
    #[serde(default = "default_actor")]
    pub actor: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            url: default_node_url(),
            grpc_url: None,
            actor: default_actor(),
        }
    }
}

fn default_node_url() -> String {
    "http://127.0.0.1:8080".to_string()
}
fn default_actor() -> String {
    "nucleus-cli".to_string()
}

/// Firecracker configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct FirecrackerConfig {
    /// Path to kernel (relative to artifacts directory)
    #[serde(default = "default_kernel_path")]
    pub kernel_path: String,

    /// Path to rootfs (relative to artifacts directory)
    #[serde(default = "default_rootfs_path")]
    pub rootfs_path: String,

    /// Path to scratch disk (relative to artifacts directory)
    #[serde(default)]
    pub scratch_path: Option<String>,

    /// Vsock CID
    #[serde(default = "default_vsock_cid")]
    pub vsock_cid: u32,

    /// Vsock port
    #[serde(default = "default_vsock_port")]
    pub vsock_port: u32,

    /// Mount rootfs read-only
    #[serde(default = "default_true")]
    pub rootfs_read_only: bool,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            kernel_path: default_kernel_path(),
            rootfs_path: default_rootfs_path(),
            scratch_path: Some(default_scratch_path()),
            vsock_cid: default_vsock_cid(),
            vsock_port: default_vsock_port(),
            rootfs_read_only: true,
        }
    }
}

fn default_kernel_path() -> String {
    "vmlinux".to_string()
}
fn default_rootfs_path() -> String {
    "rootfs.ext4".to_string()
}
fn default_scratch_path() -> String {
    "scratch.ext4".to_string()
}
fn default_vsock_cid() -> u32 {
    3
}
fn default_vsock_port() -> u32 {
    5000
}

/// Time configuration
#[derive(Debug, Serialize, Deserialize)]
pub struct TimeConfig {
    /// Default session timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}

impl Default for TimeConfig {
    fn default() -> Self {
        Self {
            timeout_seconds: default_timeout(),
        }
    }
}

fn default_timeout() -> u64 {
    3600
}

impl Config {
    /// Load config from a file path
    pub fn load(path: &str) -> Result<Self> {
        let expanded = shellexpand::tilde(path).to_string();
        let path = Path::new(&expanded);

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// Get the artifacts directory path
    pub fn artifacts_dir() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?;
        Ok(config_dir.join("nucleus").join("artifacts"))
    }

    /// Get absolute path to kernel
    pub fn kernel_path(&self) -> Result<PathBuf> {
        Ok(Self::artifacts_dir()?.join(&self.firecracker.kernel_path))
    }

    /// Get absolute path to rootfs
    pub fn rootfs_path(&self) -> Result<PathBuf> {
        Ok(Self::artifacts_dir()?.join(&self.firecracker.rootfs_path))
    }

    /// Get absolute path to scratch disk
    #[allow(dead_code)]
    pub fn scratch_path(&self) -> Result<Option<PathBuf>> {
        match &self.firecracker.scratch_path {
            Some(p) => Ok(Some(Self::artifacts_dir()?.join(p))),
            None => Ok(None),
        }
    }
}

/// Show current configuration
pub fn show(config_path: &str) -> Result<()> {
    let config = Config::load(config_path)?;

    println!("Nucleus Configuration");
    println!("=====================");
    println!();
    println!("Config file: {}", config_path);
    println!();

    println!(
        "Default profile: {}",
        if config.default_profile.is_empty() {
            "restrictive"
        } else {
            &config.default_profile
        }
    );
    println!();

    println!("[auth]");
    println!("  use_keychain = {}", config.auth.use_keychain);
    println!();

    println!("[vm]");
    println!("  name = \"{}\"", config.vm.name);
    println!("  auto_start = {}", config.vm.auto_start);
    println!("  cpus = {}", config.vm.cpus);
    println!("  memory_gib = {}", config.vm.memory_gib);
    println!("  disk_gib = {}", config.vm.disk_gib);
    println!();

    println!("[node]");
    println!("  url = \"{}\"", config.node.url);
    if let Some(grpc) = &config.node.grpc_url {
        println!("  grpc_url = \"{}\"", grpc);
    }
    println!("  actor = \"{}\"", config.node.actor);
    println!();

    println!("[firecracker]");
    println!("  kernel_path = \"{}\"", config.firecracker.kernel_path);
    println!("  rootfs_path = \"{}\"", config.firecracker.rootfs_path);
    if let Some(scratch) = &config.firecracker.scratch_path {
        println!("  scratch_path = \"{}\"", scratch);
    }
    println!("  vsock_cid = {}", config.firecracker.vsock_cid);
    println!("  vsock_port = {}", config.firecracker.vsock_port);
    println!(
        "  rootfs_read_only = {}",
        config.firecracker.rootfs_read_only
    );
    println!();

    println!("[budget]");
    println!("  max_cost_usd = {}", config.budget.max_cost_usd);
    println!("  max_input_tokens = {}", config.budget.max_input_tokens);
    println!("  max_output_tokens = {}", config.budget.max_output_tokens);
    println!();

    println!("[time]");
    println!("  timeout_seconds = {}", config.time.timeout_seconds);

    Ok(())
}
