//! Setup command - one-line macOS setup for Nucleus
//!
//! Provisions a Lima VM with Firecracker, downloads artifacts, and generates secrets.

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use std::path::PathBuf;
use std::process::Command;
use tracing::{info, warn};

use crate::keychain::{self, SecretKind, SecretStore};

/// Version of Firecracker to download
const FIRECRACKER_VERSION: &str = "1.10.1";

/// Set up nucleus environment (Lima VM, artifacts, secrets)
#[derive(Args, Debug)]
pub struct SetupArgs {
    /// Force re-setup even if already configured
    #[arg(long)]
    pub force: bool,

    /// Skip Lima VM setup (for Linux hosts or manual VM management)
    #[arg(long)]
    pub skip_vm: bool,

    /// Lima VM name
    #[arg(long, default_value = "nucleus")]
    pub vm_name: String,

    /// Lima VM CPUs
    #[arg(long, default_value = "4")]
    pub vm_cpus: u32,

    /// Lima VM memory (GiB)
    #[arg(long, default_value = "8")]
    pub vm_memory_gib: u32,

    /// Lima VM disk (GiB)
    #[arg(long, default_value = "50")]
    pub vm_disk_gib: u32,

    /// Rotate existing secrets
    #[arg(long)]
    pub rotate_secrets: bool,

    /// Skip artifact download (for offline setup)
    #[arg(long)]
    pub skip_artifacts: bool,
}

/// Platform detection result
#[derive(Debug)]
pub enum Platform {
    MacOS {
        chip: AppleChip,
        version: MacOSVersion,
    },
    Linux,
    Other(String),
}

#[derive(Debug, Clone, Copy)]
pub enum AppleChip {
    M1,
    M2,
    M3,
    M4,
    Intel,
    Unknown,
}

impl AppleChip {
    pub fn supports_nested_virt(&self) -> bool {
        matches!(self, AppleChip::M3 | AppleChip::M4)
    }
}

#[derive(Debug, Clone)]
pub struct MacOSVersion {
    pub major: u32,
    pub minor: u32,
}

impl MacOSVersion {
    pub fn supports_nested_virt(&self) -> bool {
        self.major >= 15
    }
}

/// Execute the setup command
pub async fn execute(args: SetupArgs) -> Result<()> {
    println!("Nucleus Setup");
    println!("=============\n");

    // Step 1: Detect platform
    let platform = detect_platform()?;
    print_platform_info(&platform);

    match &platform {
        Platform::MacOS { chip, version } => {
            // Check nested virtualization support
            if !chip.supports_nested_virt() || !version.supports_nested_virt() {
                warn_nested_virt_limitations(chip, version);
            }

            // Step 2: Set up Lima VM
            if !args.skip_vm {
                setup_lima_vm(&args).await?;
            } else {
                println!("Skipping Lima VM setup (--skip-vm)");
            }
        }
        Platform::Linux => {
            println!("Linux detected - skipping Lima VM setup");
            verify_kvm_access()?;
        }
        Platform::Other(os) => {
            bail!(
                "Unsupported platform: {}. Nucleus requires macOS or Linux.",
                os
            );
        }
    }

    // Step 3: Generate and store secrets
    println!("\nSetting up secrets...");
    setup_secrets(&args)?;

    // Step 4: Download/build artifacts
    if !args.skip_artifacts {
        println!("\nSetting up artifacts...");
        setup_artifacts(&args, &platform).await?;
    } else {
        println!("\nSkipping artifact setup (--skip-artifacts)");
    }

    // Step 5: Write config file
    println!("\nWriting configuration...");
    write_config(&args)?;

    // Step 6: Print summary
    print_setup_summary(&args, &platform);

    Ok(())
}

fn detect_platform() -> Result<Platform> {
    let os = std::env::consts::OS;

    match os {
        "macos" => {
            let chip = detect_apple_chip()?;
            let version = detect_macos_version()?;
            Ok(Platform::MacOS { chip, version })
        }
        "linux" => Ok(Platform::Linux),
        other => Ok(Platform::Other(other.to_string())),
    }
}

fn detect_apple_chip() -> Result<AppleChip> {
    let output = Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .context("Failed to detect CPU")?;

    let brand = String::from_utf8_lossy(&output.stdout).to_lowercase();

    if brand.contains("m4") {
        Ok(AppleChip::M4)
    } else if brand.contains("m3") {
        Ok(AppleChip::M3)
    } else if brand.contains("m2") {
        Ok(AppleChip::M2)
    } else if brand.contains("m1") {
        Ok(AppleChip::M1)
    } else if brand.contains("intel") {
        Ok(AppleChip::Intel)
    } else {
        Ok(AppleChip::Unknown)
    }
}

fn detect_macos_version() -> Result<MacOSVersion> {
    let output = Command::new("sw_vers")
        .args(["-productVersion"])
        .output()
        .context("Failed to detect macOS version")?;

    let version_str = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = version_str.trim().split('.').collect();

    let major = parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    Ok(MacOSVersion { major, minor })
}

fn print_platform_info(platform: &Platform) {
    match platform {
        Platform::MacOS { chip, version } => {
            println!("Platform: macOS {}.{}", version.major, version.minor);
            println!("Chip: {:?}", chip);
            if chip.supports_nested_virt() && version.supports_nested_virt() {
                println!("Nested virtualization: Supported");
            } else {
                println!("Nested virtualization: Limited (see below)");
            }
        }
        Platform::Linux => {
            println!("Platform: Linux");
        }
        Platform::Other(os) => {
            println!("Platform: {}", os);
        }
    }
}

fn warn_nested_virt_limitations(chip: &AppleChip, version: &MacOSVersion) {
    println!();
    println!("WARNING: Limited nested virtualization support");
    println!("=========================================");

    if !chip.supports_nested_virt() {
        println!(
            "  Your chip ({:?}) does not support nested virtualization.",
            chip
        );
        println!("  Nested virt requires Apple M3 or newer.");
    }

    if !version.supports_nested_virt() {
        println!(
            "  Your macOS version ({}.{}) does not support nested virtualization.",
            version.major, version.minor
        );
        println!("  Nested virt requires macOS 15 (Sequoia) or newer.");
    }

    println!();
    println!("Options:");
    println!("  1. Use a cloud Linux VM with KVM support");
    println!("  2. Upgrade to Apple M3+ and macOS 15+");
    println!("  3. Continue anyway (Lima will use slower emulation)");
    println!();
}

fn verify_kvm_access() -> Result<()> {
    let kvm_path = std::path::Path::new("/dev/kvm");
    if !kvm_path.exists() {
        bail!(
            "/dev/kvm not found. Ensure KVM is enabled and you have access.\n\
             Try: sudo modprobe kvm && sudo chmod 666 /dev/kvm"
        );
    }

    // Check if we can access it
    match std::fs::metadata(kvm_path) {
        Ok(_) => {
            println!("KVM access: OK");
            Ok(())
        }
        Err(e) => {
            bail!(
                "/dev/kvm exists but is not accessible: {}\n\
                 Try: sudo usermod -aG kvm $USER && newgrp kvm",
                e
            );
        }
    }
}

async fn setup_lima_vm(args: &SetupArgs) -> Result<()> {
    println!("\nSetting up Lima VM...");

    // Check if Lima is installed
    if !is_lima_installed() {
        bail!(
            "Lima is not installed.\n\
             Install with: brew install lima\n\
             Then re-run: nucleus setup"
        );
    }

    // Check if VM already exists
    if lima_vm_exists(&args.vm_name)? {
        if args.force {
            println!("Removing existing VM '{}'...", args.vm_name);
            delete_lima_vm(&args.vm_name)?;
        } else {
            bail!(
                "Lima VM '{}' already exists.\n\
                 Use --force to recreate, or run: limactl delete {}",
                args.vm_name,
                args.vm_name
            );
        }
    }

    // Generate Lima config
    let lima_config = generate_lima_config(args)?;
    let config_path = get_lima_config_path()?;

    // Ensure parent directory exists
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write config
    std::fs::write(&config_path, &lima_config)?;
    println!("Wrote Lima config to: {}", config_path.display());

    // Create VM
    println!(
        "Creating Lima VM '{}' (this may take several minutes)...",
        args.vm_name
    );
    let status = Command::new("limactl")
        .args([
            "create",
            "--name",
            &args.vm_name,
            &config_path.to_string_lossy(),
        ])
        .status()
        .context("Failed to create Lima VM")?;

    if !status.success() {
        bail!("Lima VM creation failed. Check the output above for details.");
    }

    // Start VM
    println!("Starting Lima VM...");
    let status = Command::new("limactl")
        .args(["start", &args.vm_name])
        .status()
        .context("Failed to start Lima VM")?;

    if !status.success() {
        bail!("Lima VM failed to start. Check: limactl list");
    }

    println!("Lima VM '{}' is running", args.vm_name);
    Ok(())
}

fn is_lima_installed() -> bool {
    Command::new("limactl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn lima_vm_exists(name: &str) -> Result<bool> {
    let output = Command::new("limactl")
        .args(["list", "--format", "{{.Name}}"])
        .output()
        .context("Failed to list Lima VMs")?;

    let vms = String::from_utf8_lossy(&output.stdout);
    Ok(vms.lines().any(|line| line.trim() == name))
}

fn delete_lima_vm(name: &str) -> Result<()> {
    let status = Command::new("limactl")
        .args(["delete", name, "--force"])
        .status()
        .context("Failed to delete Lima VM")?;

    if !status.success() {
        bail!("Failed to delete Lima VM '{}'", name);
    }
    Ok(())
}

fn get_lima_config_path() -> Result<PathBuf> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
    Ok(config_dir.join("nucleus").join("lima.yaml"))
}

fn get_artifacts_dir() -> Result<PathBuf> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
    Ok(config_dir.join("nucleus").join("artifacts"))
}

fn generate_lima_config(args: &SetupArgs) -> Result<String> {
    let artifacts_dir = get_artifacts_dir()?;
    let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;

    let config = format!(
        r#"# Lima configuration for Nucleus
# Generated by: nucleus setup

vmType: vz
arch: aarch64

cpus: {cpus}
memory: "{memory}GiB"
disk: "{disk}GiB"

# Nested virtualization (requires M3+ and macOS 15+)
nestedVirtualization: true

images:
  - location: "https://cloud-images.ubuntu.com/releases/24.10/release/ubuntu-24.10-server-cloudimg-arm64.img"
    arch: "aarch64"

mounts:
  # Read-only mount of nucleus artifacts
  - location: "{artifacts}"
    mountPoint: "/nucleus/artifacts"
    writable: false

  # Read-write mount for work directories
  - location: "{home}"
    mountPoint: "/host"
    writable: true

# Port forwarding for nucleus-node
portForwards:
  - guestPort: 8080
    hostPort: 8080
    proto: tcp
  - guestPort: 9080
    hostPort: 9080
    proto: tcp

# Provisioning script
provision:
  - mode: system
    script: |
      #!/bin/bash
      set -eux

      # Install dependencies
      apt-get update
      apt-get install -y e2fsprogs docker.io curl

      # Verify KVM
      if [ ! -e /dev/kvm ]; then
        echo "WARNING: /dev/kvm not available. Nested virtualization may not be working."
      fi

      # Download Firecracker
      FC_VERSION="{fc_version}"
      FC_ARCH="aarch64"
      curl -fsSL -o /usr/local/bin/firecracker \
        "https://github.com/firecracker-microvm/firecracker/releases/download/v${{FC_VERSION}}/firecracker-v${{FC_VERSION}}-${{FC_ARCH}}"
      chmod +x /usr/local/bin/firecracker

      # Download kernel
      curl -fsSL -o /nucleus/artifacts/vmlinux \
        "https://github.com/firecracker-microvm/firecracker/releases/download/v${{FC_VERSION}}/vmlinux-v${{FC_VERSION}}-${{FC_ARCH}}.bin"

      echo "Firecracker setup complete"

containerd:
  system: false
  user: false

ssh:
  overVsock: true
"#,
        cpus = args.vm_cpus,
        memory = args.vm_memory_gib,
        disk = args.vm_disk_gib,
        artifacts = artifacts_dir.display(),
        home = home_dir.display(),
        fc_version = FIRECRACKER_VERSION,
    );

    Ok(config)
}

fn setup_secrets(args: &SetupArgs) -> Result<()> {
    for kind in SecretKind::all() {
        let exists = SecretStore::exists(*kind)?;

        if exists && args.rotate_secrets {
            keychain::rotate_secret(*kind)?;
            println!("  Rotated: {}", kind.description());
        } else if exists {
            println!("  Exists: {}", kind.description());
        } else {
            let (_, _) = SecretStore::get_or_create(*kind)?;
            keychain::MetadataStore::set(*kind, keychain::SecretMetadata::new())?;
            println!("  Created: {}", kind.description());
        }
    }

    // Check rotation warnings
    let warnings = keychain::check_rotation_status()?;
    for (kind, days) in warnings {
        if days <= 0 {
            warn!(
                "Secret '{}' is overdue for rotation! Run: nucleus setup --rotate-secrets",
                kind.description()
            );
        } else {
            info!(
                "Secret '{}' will need rotation in {} days",
                kind.description(),
                days
            );
        }
    }

    Ok(())
}

async fn setup_artifacts(args: &SetupArgs, platform: &Platform) -> Result<()> {
    let artifacts_dir = get_artifacts_dir()?;
    std::fs::create_dir_all(&artifacts_dir)?;

    println!("Artifacts directory: {}", artifacts_dir.display());

    match platform {
        Platform::MacOS { .. } => {
            if args.skip_vm {
                println!("  Skipping artifact setup (--skip-vm implies artifacts are managed externally)");
            } else {
                println!("  Artifacts will be downloaded by Lima VM provisioning script");
                println!("  Run 'limactl shell {}' to verify", args.vm_name);
            }
        }
        Platform::Linux => {
            // On Linux, download directly
            download_artifacts_linux(&artifacts_dir).await?;
        }
        Platform::Other(_) => {
            println!("  Skipping artifact setup for unsupported platform");
        }
    }

    Ok(())
}

async fn download_artifacts_linux(artifacts_dir: &std::path::Path) -> Result<()> {
    let arch = std::env::consts::ARCH;
    let fc_arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => bail!("Unsupported architecture: {}", arch),
    };

    // Download Firecracker binary
    let fc_url = format!(
        "https://github.com/firecracker-microvm/firecracker/releases/download/v{}/firecracker-v{}-{}",
        FIRECRACKER_VERSION, FIRECRACKER_VERSION, fc_arch
    );
    let fc_path = artifacts_dir.join("firecracker");

    println!("  Downloading Firecracker...");
    download_file(&fc_url, &fc_path).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fc_path, std::fs::Permissions::from_mode(0o755))?;
    }

    // Download kernel
    let kernel_url = format!(
        "https://github.com/firecracker-microvm/firecracker/releases/download/v{}/vmlinux-v{}-{}.bin",
        FIRECRACKER_VERSION, FIRECRACKER_VERSION, fc_arch
    );
    let kernel_path = artifacts_dir.join("vmlinux");

    println!("  Downloading kernel...");
    download_file(&kernel_url, &kernel_path).await?;

    println!("  Artifacts downloaded successfully");
    Ok(())
}

async fn download_file(url: &str, path: &PathBuf) -> Result<()> {
    let response = ureq::get(url)
        .call()
        .map_err(|e| anyhow!("Download failed: {}", e))?;

    let mut reader = response.into_reader();
    let mut file = std::fs::File::create(path)?;
    std::io::copy(&mut reader, &mut file)?;

    Ok(())
}

fn write_config(args: &SetupArgs) -> Result<()> {
    let config_dir =
        dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
    let config_path = config_dir.join("nucleus").join("config.toml");

    // Don't overwrite existing config unless forced
    if config_path.exists() && !args.force {
        println!("  Config already exists: {}", config_path.display());
        println!("  Use --force to overwrite");
        return Ok(());
    }

    let config = format!(
        r#"# Nucleus CLI Configuration
# Generated by: nucleus setup

[auth]
# Use macOS Keychain for secrets (recommended)
use_keychain = true

[vm]
# Lima VM name
name = "{vm_name}"
# Auto-start VM when running nucleus commands
auto_start = true
# VM resources
cpus = {cpus}
memory_gib = {memory}
disk_gib = {disk}

[node]
# nucleus-node endpoint (forwarded from Lima VM)
url = "http://127.0.0.1:8080"
# Actor name for signed requests
actor = "nucleus-cli"

[firecracker]
# Paths to artifacts (relative to artifacts directory)
kernel_path = "vmlinux"
rootfs_path = "rootfs.ext4"
scratch_path = "scratch.ext4"
# Vsock configuration
vsock_cid = 3
vsock_port = 5000
# Rootfs read-only (recommended)
rootfs_read_only = true

[budget]
# Default budget limits
max_cost_usd = 5.0
max_input_tokens = 100000
max_output_tokens = 10000

[time]
# Default session timeout (seconds)
timeout_seconds = 3600
"#,
        vm_name = args.vm_name,
        cpus = args.vm_cpus,
        memory = args.vm_memory_gib,
        disk = args.vm_disk_gib,
    );

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&config_path, config)?;
    println!("  Wrote config to: {}", config_path.display());

    Ok(())
}

fn print_setup_summary(args: &SetupArgs, platform: &Platform) {
    println!();
    println!("Setup Complete!");
    println!("===============");
    println!();

    match platform {
        Platform::MacOS { chip, version } => {
            if chip.supports_nested_virt() && version.supports_nested_virt() {
                println!(
                    "Lima VM '{}' is ready with nested virtualization.",
                    args.vm_name
                );
            } else {
                println!(
                    "Lima VM '{}' is ready (emulation mode - may be slower).",
                    args.vm_name
                );
            }
        }
        Platform::Linux => {
            println!("Linux environment is ready with native KVM.");
        }
        _ => {}
    }

    println!();
    println!("Next steps:");
    println!("  1. Build rootfs (requires Docker):");
    println!(
        "     limactl shell {} -- /nucleus/artifacts/build-rootfs.sh",
        args.vm_name
    );
    println!();
    println!("  2. Start nucleus-node in the VM:");
    println!("     limactl shell {} -- nucleus-node", args.vm_name);
    println!();
    println!("  3. Run a task:");
    println!("     nucleus run \"Your task here\"");
    println!();
    println!("For diagnostics, run: nucleus doctor");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lima_config_generation() {
        let args = SetupArgs {
            force: false,
            skip_vm: false,
            vm_name: "test".to_string(),
            vm_cpus: 2,
            vm_memory_gib: 4,
            vm_disk_gib: 20,
            rotate_secrets: false,
            skip_artifacts: false,
        };

        let config = generate_lima_config(&args).unwrap();
        assert!(config.contains("vmType: vz"));
        assert!(config.contains("cpus: 2"));
        assert!(config.contains("memory: \"4GiB\""));
        assert!(config.contains("nestedVirtualization: true"));
    }
}
