//! Setup command - one-line macOS setup for Nucleus
//!
//! Provisions a Lima VM with Firecracker, downloads artifacts, and generates secrets.

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use std::path::PathBuf;
use std::process::Command;
use tracing::{info, warn};

use crate::constants::FIRECRACKER_VERSION;
use crate::keychain::{self, SecretKind, SecretStore};

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

    /// Install missing host dependencies (currently Lima, via Homebrew).
    ///
    /// Off by default: installing software on someone's machine is not
    /// something a setup command should do unasked. Without it, a missing
    /// dependency prints the exact command to run.
    #[arg(long)]
    pub install_deps: bool,

    /// Skip the post-setup smoke test that boots a throwaway microVM.
    ///
    /// The smoke test is the only step that proves Tier 2 actually works
    /// rather than appears configured, so skipping it is opt-out, not opt-in.
    #[arg(long)]
    pub skip_smoke_test: bool,
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppleChip {
    M1,
    M2,
    M3,
    M4,
    /// M5 **or newer**. The detection below folds every generation from 5 up
    /// into this variant deliberately: enumerating chips means the check goes
    /// stale on every Apple release, and the failure mode is the bad one —
    /// an unrecognised chip fell through to `Unknown`, whose
    /// `supports_nested_virt()` is `false`, so `doctor` told an M5 owner their
    /// hardware could not do nested virtualisation. That is exactly backwards,
    /// and it discourages the Lima+`vz` path that Firecracker needs for KVM.
    M5OrNewer,
    Intel,
    Unknown,
}

/// The generation number in an Apple Silicon brand string, e.g.
/// `"apple m5 pro"` -> `Some(5)`.
///
/// Parses rather than enumerating, because enumerating goes stale on every
/// Apple release and the stale failure mode is the harmful one: an
/// unrecognised chip fell through to [`AppleChip::Unknown`], whose
/// `supports_nested_virt()` is `false`, so `doctor` told an M5 owner their
/// hardware could not do nested virtualisation. It can — and that is the
/// capability the Lima `vz` path needs to expose `/dev/kvm` for Firecracker.
///
/// Requires the `apple m` prefix so a stray `m1` elsewhere in the string
/// cannot be mistaken for a generation.
pub fn apple_silicon_generation(brand_lowercase: &str) -> Option<u32> {
    let rest = brand_lowercase.split("apple m").nth(1)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse().ok()
}

impl AppleChip {
    pub fn supports_nested_virt(&self) -> bool {
        matches!(self, AppleChip::M3 | AppleChip::M4 | AppleChip::M5OrNewer)
    }

    /// Returns the Linux architecture for this chip
    pub fn linux_arch(&self) -> &'static str {
        match self {
            AppleChip::Intel => "x86_64",
            _ => "aarch64",
        }
    }

    /// Returns the Rust target triple for musl builds
    #[allow(dead_code)] // Used by cross-build.sh documentation
    pub fn musl_target(&self) -> &'static str {
        match self {
            AppleChip::Intel => "x86_64-unknown-linux-musl",
            _ => "aarch64-unknown-linux-musl",
        }
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
                setup_lima_vm(&args, chip).await?;
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

    // Step 6: Prove it works, rather than reporting that it appears configured.
    //
    // Deliberately the LAST thing, and deliberately opt-out: every other step
    // above checks a precondition, and a machine can pass all of them and still
    // boot no microVM. If this fails the user learns it here, not the first
    // time they try to run a workload.
    // On macOS Firecracker lives in the Lima VM; on Linux it is right here.
    // Previously this only ran on macOS, so a Linux host — the case where Tier 2
    // is most likely to actually be used — got no verification at all.
    let smoke_target = match &platform {
        Platform::MacOS { .. } if !args.skip_vm => Some(SmokeTarget::LimaVm(&args.vm_name)),
        Platform::MacOS { .. } => None,
        Platform::Linux => Some(SmokeTarget::LocalHost),
        Platform::Other(_) => None,
    };
    if let (Some(target), false) = (smoke_target, args.skip_smoke_test) {
        if !run_smoke_test(target) {
            print_setup_summary(&args, &platform);
            bail!(
                "setup finished, but no microVM could boot — Tier 2 is not usable yet.\n\
                 Re-run `nucleus doctor` and check the /dev/kvm line.\n\
                 To skip this check: nucleus setup --skip-smoke-test"
            );
        }
    } else if smoke_target.is_some() {
        println!("\nSkipping smoke test (--skip-smoke-test) — Tier 2 is unverified.");
    }

    // Step 7: Print summary
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

    if brand.contains("intel") {
        return Ok(AppleChip::Intel);
    }
    // Parse the generation rather than enumerating chips, so a new Apple
    // Silicon release is not misreported as `Unknown` (and therefore as
    // lacking nested virtualisation).
    Ok(match apple_silicon_generation(&brand) {
        Some(1) => AppleChip::M1,
        Some(2) => AppleChip::M2,
        Some(3) => AppleChip::M3,
        Some(4) => AppleChip::M4,
        Some(_) => AppleChip::M5OrNewer,
        None => AppleChip::Unknown,
    })
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
            println!("Target architecture: {}", chip.linux_arch());
            if chip.supports_nested_virt() && version.supports_nested_virt() {
                println!("Nested virtualization: Supported (native KVM)");
            } else if *chip == AppleChip::Intel {
                println!("Nested virtualization: Emulated (QEMU)");
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

    if *chip == AppleChip::Intel {
        println!("  Intel Macs use QEMU emulation for the Lima VM.");
        println!("  Performance will be slower than Apple Silicon with native vz.");
    } else if !chip.supports_nested_virt() {
        println!(
            "  Your chip ({:?}) does not support nested virtualization.",
            chip
        );
        println!("  Nested virt requires Apple M3 or newer.");
    }

    if !version.supports_nested_virt() && *chip != AppleChip::Intel {
        println!(
            "  Your macOS version ({}.{}) does not support nested virtualization.",
            version.major, version.minor
        );
        println!("  Nested virt requires macOS 15 (Sequoia) or newer.");
    }

    println!();
    println!("Options:");
    println!("  1. Use a cloud Linux VM with KVM support");
    if *chip != AppleChip::Intel {
        println!("  2. Upgrade to Apple M3+ and macOS 15+");
    }
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

async fn setup_lima_vm(args: &SetupArgs, chip: &AppleChip) -> Result<()> {
    println!("\nSetting up Lima VM...");

    // Check if Lima is installed
    if !is_lima_installed() {
        if args.install_deps {
            install_lima()?;
        } else {
            bail!(
                "Lima is not installed (2.0+ required for nested virtualization).\n\
                 Install it for me:  nucleus setup --install-deps\n\
                 Or do it yourself:  brew install lima && nucleus setup"
            );
        }
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
    let lima_config = generate_lima_config(args, chip)?;
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

    // Verify KVM availability after VM starts
    verify_kvm_in_vm(&args.vm_name);

    Ok(())
}

/// Verify KVM is available inside the Lima VM
fn verify_kvm_in_vm(vm_name: &str) {
    let kvm_check = Command::new("limactl")
        .args(["shell", vm_name, "--", "test", "-c", "/dev/kvm"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if kvm_check {
        info!("KVM available in VM - native Firecracker performance enabled");
        println!("\nKVM Status: /dev/kvm available");
        println!("  Firecracker microVMs will run with native performance.");
    } else {
        warn!("KVM not available in VM - Firecracker will use emulation");
        println!("\nKVM Status: /dev/kvm NOT available");
        // Firecracker is a KVM-based VMM. There is no emulation fallback: it
        // refuses to start, and `nucleus-node` returns "firecracker requires
        // /dev/kvm". Saying "slower" here promised a mode that does not exist.
        println!("  Firecracker CANNOT START without KVM - this is not a slow mode.");
        println!("  Tier 2 (microVM isolation) will be unavailable. You need:");
        println!("    - Apple Silicon M3/M4 Mac");
        println!("    - macOS 15+ (Sequoia)");
        println!("    - Or: Use a Linux host with KVM support");
    }
}

/// Install Lima via Homebrew, on explicit request (`--install-deps`).
fn install_lima() -> Result<()> {
    if which("brew").is_none() {
        bail!(
            "--install-deps needs Homebrew, which is not on PATH.\n\
             Install Lima another way, then re-run: nucleus setup"
        );
    }
    println!("Installing Lima (brew install lima)...");
    let status = Command::new("brew")
        .args(["install", "lima"])
        .status()
        .context("failed to run brew")?;
    if !status.success() {
        bail!("brew install lima failed; install it manually and re-run: nucleus setup");
    }
    if !is_lima_installed() {
        bail!("Lima still not on PATH after install; open a new shell and re-run: nucleus setup");
    }
    println!("Lima installed.");
    Ok(())
}

fn which(bin: &str) -> Option<String> {
    Command::new("which")
        .arg(bin)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|p| !p.is_empty())
}

/// Where the smoke test should run.
#[derive(Debug, Clone, Copy)]
pub enum SmokeTarget<'a> {
    /// Through a Lima VM (macOS hosts).
    LimaVm(&'a str),
    /// Directly on this machine (Linux hosts with KVM).
    LocalHost,
}

/// Boot a throwaway microVM and report whether it reached userspace.
///
/// This is the only check in setup that RUNS the thing rather than inferring
/// from it. `test -c /dev/kvm` passing means the device node exists, not that
/// Firecracker can use it — so without this, setup can report success on a
/// machine where no microVM will ever boot.
fn run_smoke_test(target: SmokeTarget<'_>) -> bool {
    println!("\nSmoke test: booting a throwaway microVM...");
    let script = include_str!("../../../scripts/firecracker/smoke-test.sh");
    let mut cmd = match target {
        // macOS reaches Firecracker through the Lima VM.
        SmokeTarget::LimaVm(vm_name) => {
            let mut c = Command::new("limactl");
            c.args(["shell", vm_name, "--", "sudo", "sh", "-s"]);
            c
        }
        // A Linux host with KVM already has everything; there is no VM to
        // shell into, and pretending otherwise is why this check used to be
        // skipped entirely on Linux.
        SmokeTarget::LocalHost => {
            let mut c = Command::new("sudo");
            c.args(["sh", "-s"]);
            c
        }
    };
    let out = cmd
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(script.as_bytes());
            }
            child.wait_with_output()
        });
    match out {
        Ok(o) if o.status.success() => {
            println!("  PASS - a microVM booted to userspace. Tier 2 works on this host.");
            true
        }
        Ok(o) => {
            println!("  FAIL - Tier 2 is not usable on this host yet.");
            let err = String::from_utf8_lossy(&o.stderr);
            for line in err.lines().take(12) {
                println!("    {line}");
            }
            false
        }
        Err(e) => {
            println!("  FAIL - could not run the smoke test: {e}");
            false
        }
    }
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

fn generate_lima_config(args: &SetupArgs, chip: &AppleChip) -> Result<String> {
    let artifacts_dir = get_artifacts_dir()?;
    let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;

    let arch = chip.linux_arch();
    let is_intel = *chip == AppleChip::Intel;

    // Intel Macs require QEMU; Apple Silicon uses Virtualization.framework
    let vm_type = if is_intel { "qemu" } else { "vz" };

    // Image URL differs by architecture - use Ubuntu 24.04 LTS for stability
    let image_url = if is_intel {
        "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
    } else {
        "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
    };

    // Nested virtualization only works on Apple Silicon M3+ with macOS 15+
    // Intel Macs cannot do nested virt in Lima
    let nested_virt = if is_intel { "false" } else { "true" };

    let config = format!(
        r#"# Lima configuration for Nucleus
# Generated by: nucleus setup
# Architecture: {arch}

vmType: {vm_type}
arch: {arch}

cpus: {cpus}
memory: "{memory}GiB"
disk: "{disk}GiB"

# Nested virtualization (requires M3+ and macOS 15+, disabled for Intel)
nestedVirtualization: {nested_virt}

images:
  - location: "{image_url}"
    arch: "{arch}"

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
  # gRPC port (HTTP port + 1000)
  - guestPort: 9180
    hostPort: 9180
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
        echo "Firecracker microVMs will not work without KVM."
      else
        echo "KVM is available"
        # Ensure Lima user can access KVM
        chmod 666 /dev/kvm
      fi

      # Download Firecracker (v1.14+ uses tarball format)
      FC_VERSION="{fc_version}"
      FC_ARCH="{arch}"
      echo "Downloading Firecracker v${{FC_VERSION}} for ${{FC_ARCH}}..."
      curl -fsSL -o /tmp/firecracker.tgz \
        "https://github.com/firecracker-microvm/firecracker/releases/download/v${{FC_VERSION}}/firecracker-v${{FC_VERSION}}-${{FC_ARCH}}.tgz"
      tar xzf /tmp/firecracker.tgz -C /tmp
      mv /tmp/release-v${{FC_VERSION}}-${{FC_ARCH}}/firecracker-v${{FC_VERSION}}-${{FC_ARCH}} /usr/local/bin/firecracker
      mv /tmp/release-v${{FC_VERSION}}-${{FC_ARCH}}/jailer-v${{FC_VERSION}}-${{FC_ARCH}} /usr/local/bin/jailer
      chmod +x /usr/local/bin/firecracker /usr/local/bin/jailer
      rm -rf /tmp/firecracker.tgz /tmp/release-v${{FC_VERSION}}-${{FC_ARCH}}

      # Download kernel from AWS S3 (Firecracker no longer ships kernels)
      mkdir -p /var/lib/nucleus/artifacts
      curl -fsSL -o /var/lib/nucleus/artifacts/vmlinux \
        "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/${{FC_ARCH}}/kernels/vmlinux.bin"

      # Create nucleus-node systemd service (using printf to avoid YAML parsing issues)
      printf '%s\n' '[Unit]' \
        'Description=Nucleus Node - Firecracker orchestrator' \
        'After=network.target docker.service' \
        'Wants=docker.service' \
        '' \
        '[Service]' \
        'Type=simple' \
        'ExecStart=/usr/local/bin/nucleus-node' \
        'Restart=on-failure' \
        'RestartSec=5' \
        'Environment=NUCLEUS_NODE_LISTEN_ADDR=0.0.0.0:8080' \
        'Environment=NUCLEUS_NODE_METRICS_ADDR=0.0.0.0:9080' \
        'Environment=NUCLEUS_NODE_GRPC_ADDR=0.0.0.0:9180' \
        'Environment=NUCLEUS_NODE_ARTIFACTS_DIR=/var/lib/nucleus/artifacts' \
        'Environment=RUST_LOG=info' \
        '' \
        '[Install]' \
        'WantedBy=multi-user.target' \
        > /etc/systemd/system/nucleus-node.service

      systemctl daemon-reload
      # Don't enable/start yet - nucleus-node binary needs to be installed first

      echo "Firecracker setup complete"
      echo "Architecture: ${{FC_ARCH}}"
      echo "Firecracker: $(firecracker --version 2>/dev/null || echo 'installed')"

containerd:
  system: false
  user: false

ssh:
  overVsock: {ssh_vsock}
"#,
        arch = arch,
        vm_type = vm_type,
        cpus = args.vm_cpus,
        memory = args.vm_memory_gib,
        disk = args.vm_disk_gib,
        nested_virt = nested_virt,
        image_url = image_url,
        artifacts = artifacts_dir.display(),
        home = home_dir.display(),
        fc_version = FIRECRACKER_VERSION,
        // vsock is only available with vz (Apple Silicon)
        ssh_vsock = if is_intel { "false" } else { "true" },
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
        Platform::MacOS { chip, .. } => {
            if args.skip_vm {
                println!("  Skipping artifact setup (--skip-vm implies artifacts are managed externally)");
            } else {
                println!("  Artifacts will be downloaded by Lima VM provisioning script");
                println!("  Target architecture: {}", chip.linux_arch());
                println!();
                println!("  After VM starts, build rootfs with:");
                println!(
                    "    limactl shell {} -- /nucleus/artifacts/build-rootfs.sh --arch {}",
                    args.vm_name,
                    chip.linux_arch()
                );
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

    // Download jailer
    let jailer_url = format!(
        "https://github.com/firecracker-microvm/firecracker/releases/download/v{}/jailer-v{}-{}",
        FIRECRACKER_VERSION, FIRECRACKER_VERSION, fc_arch
    );
    let jailer_path = artifacts_dir.join("jailer");

    println!("  Downloading jailer...");
    download_file(&jailer_url, &jailer_path).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&jailer_path, std::fs::Permissions::from_mode(0o755))?;
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

    let mut reader = response.into_parts().1.into_reader();
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
# gRPC endpoint for internal communication
grpc_url = "http://127.0.0.1:9180"
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
            let arch = chip.linux_arch();
            if chip.supports_nested_virt() && version.supports_nested_virt() {
                println!(
                    "Lima VM '{}' is ready with nested virtualization ({}).",
                    args.vm_name, arch
                );
            } else if *chip == AppleChip::Intel {
                println!(
                    "Lima VM '{}' is ready with QEMU emulation ({}).",
                    args.vm_name, arch
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
    println!();
    println!("  1. Cross-compile binaries for rootfs:");
    println!("     scripts/cross-build.sh");
    println!();
    println!("  2. Build rootfs (in Lima VM with Docker):");
    println!(
        "     limactl shell {} -- /host/.../scripts/firecracker/build-rootfs.sh \\",
        args.vm_name
    );
    println!("       --auth-secret \"$AUTH\" --approval-secret \"$APPROVAL\"");
    println!();
    println!("  3. Start nucleus:");
    println!("     nucleus start");
    println!();
    println!("  4. Run a task:");
    println!("     nucleus run \"Your task here\"");
    println!();
    println!("For diagnostics, run: nucleus doctor");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lima_config_generation_aarch64() {
        let args = SetupArgs {
            force: false,
            skip_vm: false,
            vm_name: "test".to_string(),
            vm_cpus: 2,
            vm_memory_gib: 4,
            vm_disk_gib: 20,
            rotate_secrets: false,
            skip_artifacts: false,
            install_deps: false,
            skip_smoke_test: true,
        };

        let config = generate_lima_config(&args, &AppleChip::M3).unwrap();
        assert!(config.contains("vmType: vz"));
        assert!(config.contains("arch: aarch64"));
        assert!(config.contains("cpus: 2"));
        assert!(config.contains("memory: \"4GiB\""));
        assert!(config.contains("nestedVirtualization: true"));
        assert!(config.contains("arm64.img"));
    }

    #[test]
    fn test_lima_config_generation_x86_64() {
        let args = SetupArgs {
            force: false,
            skip_vm: false,
            vm_name: "test".to_string(),
            vm_cpus: 2,
            vm_memory_gib: 4,
            vm_disk_gib: 20,
            rotate_secrets: false,
            skip_artifacts: false,
            install_deps: false,
            skip_smoke_test: true,
        };

        let config = generate_lima_config(&args, &AppleChip::Intel).unwrap();
        assert!(config.contains("vmType: qemu"));
        assert!(config.contains("arch: x86_64"));
        assert!(config.contains("nestedVirtualization: false"));
        assert!(config.contains("amd64.img"));
    }

    #[test]
    fn test_apple_chip_arch() {
        assert_eq!(AppleChip::M1.linux_arch(), "aarch64");
        assert_eq!(AppleChip::M2.linux_arch(), "aarch64");
        assert_eq!(AppleChip::M3.linux_arch(), "aarch64");
        assert_eq!(AppleChip::M4.linux_arch(), "aarch64");
        assert_eq!(AppleChip::Intel.linux_arch(), "x86_64");
        assert_eq!(AppleChip::Unknown.linux_arch(), "aarch64");
    }

    #[test]
    fn test_apple_chip_musl_target() {
        assert_eq!(AppleChip::M3.musl_target(), "aarch64-unknown-linux-musl");
        assert_eq!(AppleChip::Intel.musl_target(), "x86_64-unknown-linux-musl");
    }
}

#[cfg(test)]
mod apple_chip_tests {
    use super::*;

    /// The bug: "Apple M5 Pro" matched none of the enumerated m1..m4 strings,
    /// fell through to `Unknown`, and `Unknown.supports_nested_virt()` is
    /// false — so `doctor` reported that an M5 cannot do nested virtualisation.
    /// It can, and that is precisely the capability needed to expose /dev/kvm
    /// to Firecracker under Lima's `vz` backend.
    #[test]
    fn m5_and_newer_are_recognised_and_support_nested_virt() {
        for (brand, gen) in [
            ("apple m5 pro", 5),
            ("apple m5 max", 5),
            ("apple m6", 6),
            ("apple m12 ultra", 12),
        ] {
            assert_eq!(apple_silicon_generation(brand), Some(gen), "{brand}");
        }
        assert!(AppleChip::M5OrNewer.supports_nested_virt());
    }

    #[test]
    fn the_known_generations_still_parse() {
        for (brand, gen) in [
            ("apple m1", 1),
            ("apple m2 pro", 2),
            ("apple m3 max", 3),
            ("apple m4", 4),
        ] {
            assert_eq!(apple_silicon_generation(brand), Some(gen), "{brand}");
        }
    }

    /// M1/M2 genuinely lack nested virt; the fix must not paper over that.
    #[test]
    fn older_silicon_still_reports_no_nested_virt() {
        assert!(!AppleChip::M1.supports_nested_virt());
        assert!(!AppleChip::M2.supports_nested_virt());
        assert!(AppleChip::M3.supports_nested_virt());
    }

    #[test]
    fn non_apple_silicon_yields_no_generation() {
        for brand in ["intel(r) core(tm) i9", "", "some other cpu"] {
            assert_eq!(apple_silicon_generation(brand), None, "{brand}");
        }
    }
}
