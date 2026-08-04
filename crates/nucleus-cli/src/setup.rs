//! Setup command - one-line macOS setup for Nucleus
//!
//! Provisions a Lima VM with Firecracker, downloads artifacts, and generates secrets.

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use std::path::PathBuf;
use std::process::Command;
use tracing::{info, warn};

use crate::config;
use crate::keychain::{self, SecretKind, SecretStore};
use crate::provision::{self, ArtifactSource, Tier2Host};

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

    /// Skip the post-setup verification that boots a real nucleus pod.
    ///
    /// The verification is the only step that proves Tier 2 actually works
    /// rather than appears configured, so skipping it is opt-out, not opt-in.
    #[arg(long, alias = "skip-smoke-test")]
    pub skip_verify: bool,

    /// Where the guest rootfs and nucleus-node binary come from.
    ///
    /// `auto` uses this working tree's build output when it is complete and the
    /// pinned release otherwise. `local` requires the build output. `release`
    /// ignores it.
    #[arg(long, value_enum, default_value = "auto")]
    pub artifacts: ArtifactSourceArg,
}

/// CLI spelling of [`provision::ArtifactSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ArtifactSourceArg {
    /// Prefer a complete local build, fall back to the pinned release.
    Auto,
    /// Require this working tree's build output.
    Local,
    /// Require the pinned release.
    Release,
}

impl From<ArtifactSourceArg> for ArtifactSource {
    fn from(a: ArtifactSourceArg) -> Self {
        match a {
            ArtifactSourceArg::Auto => ArtifactSource::Auto,
            ArtifactSourceArg::Local => ArtifactSource::Local,
            ArtifactSourceArg::Release => ArtifactSource::Release,
        }
    }
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

    // Step 4: Install everything the host needs to actually launch a pod.
    //
    // This step did not exist on macOS. It printed instructions naming a script
    // at a path nothing creates, and setup then reported success — so the VM had
    // Firecracker and a kernel and no way to run nucleus.
    if !args.skip_artifacts {
        println!("\nInstalling Tier 2 components...");
        provision_tier2_host(&args, &platform)?;
    } else {
        println!("\nSkipping component install (--skip-artifacts) — Tier 2 will not work.");
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
    //
    // The check is a REAL nucleus pod, not a stock rootfs. `smoke-test.sh` boots
    // an Ubuntu image from the Firecracker CI bucket, which proves Firecracker
    // works and says nothing about nucleus: it never runs `guest-init` or the
    // tool-proxy. That gap let setup report "Tier 2 works on this host" on a VM
    // with no nucleus-node and no nucleus rootfs — measured 2026-07-29.
    let host = tier2_host_for(&args, &platform);
    if let (Some(host), false) = (host, args.skip_verify) {
        if let Err(e) = crate::verify::verify_tier2(&host, &args.vm_name) {
            print_setup_summary(&args, &platform, false);
            bail!(
                "setup finished, but a nucleus pod could not boot — Tier 2 is not usable yet.\n\
                 {e}\n\
                 Re-run the check on its own with: nucleus verify --tier2\n\
                 To skip it: nucleus setup --skip-verify"
            );
        }
    } else if !args.skip_verify {
        println!("\nNo Tier 2 host to verify against on this platform.");
    } else {
        println!("\nSkipping verification (--skip-verify) — Tier 2 is unverified.");
    }

    // Step 7: Print summary
    print_setup_summary(&args, &platform, true);

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
                // NOT "emulated". QEMU's HVF accelerator virtualises the guest;
                // it does not expose KVM inside it. Firecracker is a KVM-based
                // VMM, so with no /dev/kvm there is no slow mode — there is no
                // mode. Calling this "emulated" promised a fallback that has
                // never existed.
                println!("Nested virtualization: UNAVAILABLE (Intel Mac) — Tier 2 will not run");
            } else {
                println!("Nested virtualization: UNAVAILABLE (see below) — Tier 2 will not run");
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
    println!("WARNING: no nested virtualization — Tier 2 is unavailable here");
    println!("=============================================================");

    if *chip == AppleChip::Intel {
        println!("  Intel Macs run the Lima VM under QEMU, which cannot expose");
        println!("  /dev/kvm inside the guest. Firecracker is a KVM-based VMM:");
        println!("  without /dev/kvm it does not run slowly, it does not run.");
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
    println!("  1. Use a Linux host with /dev/kvm (cloud or bare metal)");
    if *chip != AppleChip::Intel {
        println!("  2. Apple M3 or newer on macOS 15+");
    }
    println!("  3. Continue for Tier 0/1 only — setup will still configure them,");
    println!("     and `nucleus verify --tier2` will fail, which is the truth.");
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

    // Use the SAME template that ships in the repo and as a release asset,
    // rather than generating a rival config here. The generated one had drifted:
    // a different Firecracker version, a different kernel URL, a different gRPC
    // port and a home mount at a path that made every `limactl shell` open with
    // `cd: /Users/...: No such file or directory`.
    let config_path = get_lima_config_path()?;
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&config_path, lima_template(chip))?;
    println!("Wrote Lima config to: {}", config_path.display());

    // Resources are applied with Lima's own `--set` rather than by rewriting the
    // YAML, so the template stays a valid standalone file and there is no
    // string-substitution step to get subtly wrong.
    let overrides = format!(
        ".cpus = {} | .memory = \"{}GiB\" | .disk = \"{}GiB\"",
        args.vm_cpus, args.vm_memory_gib, args.vm_disk_gib
    );

    println!(
        "Creating Lima VM '{}' (this may take several minutes)...",
        args.vm_name
    );
    let status = Command::new("limactl")
        .args([
            "create",
            "--name",
            &args.vm_name,
            "--set",
            &overrides,
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

fn setup_secrets(args: &SetupArgs) -> Result<()> {
    // Say this BEFORE the first Keychain call. Reading an existing item from a
    // binary the Keychain has not authorised opens a GUI dialog, and until it is
    // answered the process simply stops — no output, no timeout, no hint. Hit
    // while testing this very command: a rebuilt `nucleus` hung here for minutes
    // looking like a network stall. The dialog is legitimate; the silence is not.
    #[cfg(target_os = "macos")]
    println!("  (macOS may ask to authorise Keychain access — a rebuilt or updated");
    #[cfg(target_os = "macos")]
    println!("   `nucleus` needs approving once. Setup waits here until you answer.)");

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

    for (kind, days) in keychain::check_rotation_status()? {
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

/// The machine that will actually run Firecracker, if there is one.
fn tier2_host_for(args: &SetupArgs, platform: &Platform) -> Option<Tier2Host> {
    match platform {
        Platform::MacOS { .. } if !args.skip_vm => Some(Tier2Host::Lima(args.vm_name.clone())),
        // Firecracker lives in the Lima VM on macOS; with --skip-vm there is no
        // VM and nothing to install into.
        Platform::MacOS { .. } => None,
        Platform::Linux => Some(Tier2Host::Local),
        Platform::Other(_) => None,
    }
}

/// The Linux architecture of the Tier 2 host.
fn tier2_arch(platform: &Platform) -> Result<&'static str> {
    match platform {
        Platform::MacOS { chip, .. } => Ok(chip.linux_arch()),
        Platform::Linux => match std::env::consts::ARCH {
            "aarch64" => Ok("aarch64"),
            "x86_64" => Ok("x86_64"),
            other => bail!("unsupported architecture for Tier 2: {other}"),
        },
        Platform::Other(os) => bail!("no Tier 2 host on {os}"),
    }
}

/// Install Firecracker, the kernel, the guest rootfs, `nucleus-node`, the Linux
/// CLI and the node's service onto whichever machine will run microVMs.
///
/// Everything installed here is named by `nucleus_spec::tier2_artifacts` or
/// `nucleus_spec::vmm_version`. Nothing is named by a literal in this file, and
/// nothing is named by the Lima template — which is how the three provisioners
/// came to disagree, one of them on a URL that 404s.
fn provision_tier2_host(args: &SetupArgs, platform: &Platform) -> Result<()> {
    let Some(host) = tier2_host_for(args, platform) else {
        println!("  No Tier 2 host on this platform — nothing to install.");
        return Ok(());
    };
    let arch = tier2_arch(platform)?;
    let cache_dir = config::Config::artifacts_dir()?;
    std::fs::create_dir_all(&cache_dir)?;
    println!("  Download cache: {}", cache_dir.display());

    provision::install_firecracker(&host, arch)?;
    provision::install_kernel(&host, arch, &cache_dir)?;
    provision::install_tier2_artifacts(&host, arch, &cache_dir, args.artifacts.into())?;

    // The secrets already exist — `setup_secrets` created them a step ago, and
    // on an existing install they predate this run. They were simply never
    // handed to the node, which is why its unit could not start it.
    let auth = secret_hex(SecretKind::NodeAuthSecret)?;
    let proxy = secret_hex(SecretKind::ProxyAuthSecret)?;
    let approval = secret_hex(SecretKind::ApprovalSecret)?;
    provision::install_node_service(&host, &provision::node_env_body(&auth, &proxy, &approval))?;

    Ok(())
}

/// A stored secret in the encoding the rest of the CLI signs with.
///
/// `run.rs` and `node.rs` both use `hex::encode`; the node must be started with
/// the same string or every signed request fails in a way that reads like clock
/// skew rather than an encoding mismatch.
fn secret_hex(kind: SecretKind) -> Result<String> {
    let raw = SecretStore::get(kind)?.ok_or_else(|| {
        anyhow!(
            "secret '{}' is missing; re-run nucleus setup",
            kind.description()
        )
    })?;
    Ok(hex::encode(raw))
}

fn get_lima_config_path() -> Result<PathBuf> {
    Ok(config::nucleus_dir()?.join("lima.yaml"))
}

/// The Lima template for this chip, compiled in from `scripts/lima/`.
///
/// `include_str!` rather than reading from disk: the binary must work when it is
/// not standing in a checkout, and embedding it means the template CI lints is
/// byte-for-byte the one a user gets.
fn lima_template(chip: &AppleChip) -> &'static str {
    match chip {
        AppleChip::Intel => include_str!("../../../scripts/lima/nucleus-x86_64.yaml"),
        _ => include_str!("../../../scripts/lima/nucleus-aarch64.yaml"),
    }
}

fn write_config(args: &SetupArgs) -> Result<()> {
    let config_path = config::default_config_path()?;

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

/// What the user has, and what to do next.
///
/// `succeeded` distinguishes the two callers: setup prints this on the way out
/// either way, and the previous version said "Setup Complete!" in both — including
/// immediately before bailing with "Tier 2 is not usable yet".
///
/// The old next-steps list told the user to cross-compile binaries and run
/// `build-rootfs.sh` at a path printed as a literal `/host/.../`. Those steps are
/// what `setup` now does; leaving them here would be instructions for the bug.
fn print_setup_summary(args: &SetupArgs, platform: &Platform, succeeded: bool) {
    println!();
    if succeeded {
        println!("Setup complete");
        println!("==============");
    } else {
        println!("Setup did not finish");
        println!("====================");
    }
    println!();

    match platform {
        Platform::MacOS { chip, version } => {
            let arch = chip.linux_arch();
            if chip.supports_nested_virt() && version.supports_nested_virt() {
                println!(
                    "Lima VM '{}' has nested virtualization ({arch}).",
                    args.vm_name
                );
            } else {
                // No "emulation mode" line. There is no emulation mode: without
                // /dev/kvm, Firecracker does not start.
                println!(
                    "Lima VM '{}' has NO nested virtualization, so no /dev/kvm and no Tier 2.",
                    args.vm_name
                );
            }
        }
        Platform::Linux => println!("This host has KVM."),
        _ => {}
    }

    println!();
    if succeeded {
        println!("A real nucleus pod booted, proved its identity to its own tool-proxy,");
        println!("served an allowed operation and refused a forbidden one. Tier 2 works here.");
        println!();
        println!("Next:");
        println!("  nucleus verify --tier2    re-run that proof any time");
        println!("  nucleus doctor            check the components are still installed");
        println!("  nucleus start             run the node as a service");
    } else {
        println!("Next:");
        println!("  nucleus doctor            which component is missing");
        println!("  nucleus verify --tier2    re-run the boot check on its own");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The template must carry the VM's SHAPE and name no artifact versions.
    ///
    /// This is the invariant that keeps the three provisioners from diverging
    /// again: if the template names a Firecracker version or a kernel URL, that
    /// is a second answer to a question `nucleus_spec::tier2_artifacts` already
    /// answers, and the two can drift — which is how the published template came
    /// to pin a kernel URL returning HTTP 404 while the code pinned another.
    #[test]
    fn the_lima_templates_name_no_artifact_versions_or_urls() {
        for (chip, template) in [
            (AppleChip::M3, lima_template(&AppleChip::M3)),
            (AppleChip::Intel, lima_template(&AppleChip::Intel)),
        ] {
            // Non-vacuity: assert we are looking at a real template first. An
            // empty string trivially "names no URLs".
            assert!(
                template.contains("provision:") && template.contains("images:"),
                "{chip:?} template does not look like a Lima config"
            );
            for forbidden in [
                "firecracker-microvm/firecracker/releases",
                "spec.ccfc.min",
                "vmlinux-6.1",
                "FIRECRACKER_VERSION=",
            ] {
                assert!(
                    !template.contains(forbidden),
                    "{chip:?} template names {forbidden:?}; artifact pins belong in \
                     nucleus_spec::tier2_artifacts, not here"
                );
            }
        }
    }

    /// A Firecracker host needs no container runtime, and Lima installs rootless
    /// containerd + BuildKit unless told not to. That is not merely wasteful: on
    /// a fresh VM it pushed first boot past `limactl start`'s timeout, and setup
    /// failed with "Lima VM failed to start" after ten minutes while the VM was
    /// running fine and still provisioning. The config these templates replaced
    /// disabled it; dropping the block was a regression this test exists to stop
    /// recurring.
    #[test]
    fn the_templates_disable_containerd() {
        for (chip, template) in [
            (AppleChip::M3, lima_template(&AppleChip::M3)),
            (AppleChip::Intel, lima_template(&AppleChip::Intel)),
        ] {
            assert!(
                template.contains("containerd:"),
                "{chip:?} template must declare containerd explicitly"
            );
            let after = template.split("containerd:").nth(1).unwrap_or("");
            let block = &after[..after.len().min(200)];
            assert!(
                block.contains("system: false") && block.contains("user: false"),
                "{chip:?} template must disable BOTH system and user containerd; got:{block}"
            );
        }
    }

    /// Each template must still describe the right machine.
    #[test]
    fn the_templates_describe_the_right_vm_shape() {
        let arm = lima_template(&AppleChip::M3);
        assert!(arm.contains("vmType: \"vz\""));
        assert!(arm.contains("nestedVirtualization: true"));
        assert!(arm.contains("arm64.img"));

        let intel = lima_template(&AppleChip::Intel);
        assert!(intel.contains("vmType: \"qemu\""));
        assert!(intel.contains("amd64.img"));
        // An Intel Mac cannot do nested virt, so the template must not claim it.
        assert!(!intel.contains("nestedVirtualization: true"));
    }

    /// Both templates forward the same ports the generated config used, and the
    /// gRPC port must match `config.toml`'s `grpc_url` — they disagreed before
    /// (4002 in the templates, 9180 in the config).
    #[test]
    fn the_templates_forward_the_grpc_port_the_config_points_at() {
        for template in [
            lima_template(&AppleChip::M3),
            lima_template(&AppleChip::Intel),
        ] {
            assert!(template.contains("guestPort: 8080"));
            assert!(
                template.contains("guestPort: 9180"),
                "gRPC port must match config.toml's grpc_url of 9180"
            );
        }
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
