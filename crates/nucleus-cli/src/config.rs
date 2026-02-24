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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.default_profile.is_empty());
        assert_eq!(config.budget.max_cost_usd, 5.0);
        assert_eq!(config.budget.max_input_tokens, 100_000);
        assert_eq!(config.budget.max_output_tokens, 10_000);
        assert!(!config.auth.use_keychain);
        assert_eq!(config.vm.name, "nucleus");
        assert!(config.vm.auto_start);
        assert_eq!(config.vm.cpus, 4);
        assert_eq!(config.vm.memory_gib, 8);
        assert_eq!(config.vm.disk_gib, 50);
        assert_eq!(config.node.url, "http://127.0.0.1:8080");
        assert!(config.node.grpc_url.is_none());
        assert_eq!(config.node.actor, "nucleus-cli");
        assert_eq!(config.firecracker.kernel_path, "vmlinux");
        assert_eq!(config.firecracker.rootfs_path, "rootfs.ext4");
        assert!(config.firecracker.rootfs_read_only);
        assert_eq!(config.firecracker.vsock_cid, 3);
        assert_eq!(config.firecracker.vsock_port, 5000);
        assert_eq!(config.time.timeout_seconds, 3600);
    }

    #[test]
    fn test_load_nonexistent_file_returns_default() {
        let result = Config::load("/nonexistent/path/nucleus.toml");
        assert!(result.is_ok());
        let config = result.unwrap();
        // Should be default config
        assert!(config.default_profile.is_empty());
        assert_eq!(config.budget.max_cost_usd, 5.0);
    }

    #[test]
    fn test_load_valid_toml() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
default_profile = "fix-issue"

[budget]
max_cost_usd = 10.0
max_input_tokens = 50000
max_output_tokens = 5000

[auth]
use_keychain = true

[vm]
name = "my-nucleus"
auto_start = false
cpus = 8
memory_gib = 16
disk_gib = 100

[node]
url = "http://192.168.1.1:9090"
grpc_url = "http://192.168.1.1:9091"
actor = "my-agent"

[firecracker]
kernel_path = "my-vmlinux"
rootfs_path = "my-rootfs.ext4"
vsock_cid = 5
vsock_port = 6000
rootfs_read_only = false

[time]
timeout_seconds = 7200
"#
        )
        .unwrap();

        let config = Config::load(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.default_profile, "fix-issue");
        assert_eq!(config.budget.max_cost_usd, 10.0);
        assert_eq!(config.budget.max_input_tokens, 50000);
        assert_eq!(config.budget.max_output_tokens, 5000);
        assert!(config.auth.use_keychain);
        assert_eq!(config.vm.name, "my-nucleus");
        assert!(!config.vm.auto_start);
        assert_eq!(config.vm.cpus, 8);
        assert_eq!(config.vm.memory_gib, 16);
        assert_eq!(config.vm.disk_gib, 100);
        assert_eq!(config.node.url, "http://192.168.1.1:9090");
        assert_eq!(
            config.node.grpc_url,
            Some("http://192.168.1.1:9091".to_string())
        );
        assert_eq!(config.node.actor, "my-agent");
        assert_eq!(config.firecracker.kernel_path, "my-vmlinux");
        assert_eq!(config.firecracker.rootfs_path, "my-rootfs.ext4");
        assert!(!config.firecracker.rootfs_read_only);
        assert_eq!(config.firecracker.vsock_cid, 5);
        assert_eq!(config.firecracker.vsock_port, 6000);
        assert_eq!(config.time.timeout_seconds, 7200);
    }

    #[test]
    fn test_load_partial_toml_uses_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
default_profile = "review"
"#
        )
        .unwrap();

        let config = Config::load(file.path().to_str().unwrap()).unwrap();
        assert_eq!(config.default_profile, "review");
        // Other fields should be default
        assert_eq!(config.budget.max_cost_usd, 5.0);
        assert_eq!(config.vm.cpus, 4);
        assert_eq!(config.node.url, "http://127.0.0.1:8080");
    }

    #[test]
    fn test_load_invalid_toml_returns_error() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "[[[not valid toml").unwrap();

        let result = Config::load(file.path().to_str().unwrap());
        assert!(result.is_err());
    }

    #[test]
    fn test_kernel_path_under_artifacts() {
        let config = Config::default();
        let path = config.kernel_path().unwrap();
        assert!(path.ends_with("vmlinux"));
        assert!(path.to_string_lossy().contains("nucleus"));
    }

    #[test]
    fn test_rootfs_path_under_artifacts() {
        let config = Config::default();
        let path = config.rootfs_path().unwrap();
        assert!(path.ends_with("rootfs.ext4"));
        assert!(path.to_string_lossy().contains("nucleus"));
    }

    #[test]
    fn test_scratch_path_default_has_value() {
        let config = Config::default();
        let path = config.scratch_path().unwrap();
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.ends_with("scratch.ext4"));
    }

    #[test]
    fn test_scratch_path_none_when_not_set() {
        let mut config = Config::default();
        config.firecracker.scratch_path = None;
        let path = config.scratch_path().unwrap();
        assert!(path.is_none());
    }

    #[test]
    fn test_custom_kernel_path_reflected() {
        let mut config = Config::default();
        config.firecracker.kernel_path = "custom-kernel".to_string();
        let path = config.kernel_path().unwrap();
        assert!(path.ends_with("custom-kernel"));
    }

    #[test]
    fn test_budget_config_defaults() {
        let budget = BudgetConfig::default();
        assert_eq!(budget.max_cost_usd, 5.0);
        assert_eq!(budget.max_input_tokens, 100_000);
        assert_eq!(budget.max_output_tokens, 10_000);
    }

    #[test]
    fn test_vm_config_defaults() {
        let vm = VmConfig::default();
        assert_eq!(vm.name, "nucleus");
        assert!(vm.auto_start);
        assert_eq!(vm.cpus, 4);
        assert_eq!(vm.memory_gib, 8);
        assert_eq!(vm.disk_gib, 50);
    }

    #[test]
    fn test_node_config_defaults() {
        let node = NodeConfig::default();
        assert_eq!(node.url, "http://127.0.0.1:8080");
        assert!(node.grpc_url.is_none());
        assert_eq!(node.actor, "nucleus-cli");
    }

    #[test]
    fn test_firecracker_config_defaults() {
        let fc = FirecrackerConfig::default();
        assert_eq!(fc.kernel_path, "vmlinux");
        assert_eq!(fc.rootfs_path, "rootfs.ext4");
        assert_eq!(fc.scratch_path, Some("scratch.ext4".to_string()));
        assert_eq!(fc.vsock_cid, 3);
        assert_eq!(fc.vsock_port, 5000);
        assert!(fc.rootfs_read_only);
    }

    #[test]
    fn test_time_config_defaults() {
        let time = TimeConfig::default();
        assert_eq!(time.timeout_seconds, 3600);
    }

    #[test]
    fn test_show_nonexistent_path_succeeds() {
        // show() loads config (returns default if missing) and prints it
        let result = show("/nonexistent/config.toml");
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_valid_config() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"default_profile = "fix-issue""#).unwrap();

        let result = show(file.path().to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_show_config_empty_profile_shows_restrictive() {
        // show() should display "restrictive" when default_profile is empty
        // This is just a smoke test that it doesn't panic
        let result = show("/nonexistent/path.toml");
        assert!(result.is_ok());
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
