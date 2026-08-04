//! Doctor command - diagnose nucleus environment issues

use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

use crate::keychain::{self, SecretKind, SecretStore};
use crate::provision;
#[cfg(target_os = "macos")]
use crate::setup::{AppleChip, MacOSVersion};

/// Check status indicator
#[derive(Debug, Clone, Copy)]
enum Status {
    Ok,
    Warning,
    Error,
}

impl Status {
    fn icon(&self) -> &'static str {
        match self {
            Status::Ok => "[OK]",
            Status::Warning => "[WARN]",
            Status::Error => "[ERR]",
        }
    }
}

/// Run all diagnostic checks
pub async fn diagnose() -> Result<()> {
    println!("Nucleus Environment Check");
    println!("=========================\n");

    let mut all_ok = true;

    // Platform checks
    all_ok &= check_platform();
    println!();

    // Lima checks (macOS only)
    if cfg!(target_os = "macos") {
        all_ok &= check_lima();
        println!();
    }

    // KVM checks (Linux only)
    if cfg!(target_os = "linux") {
        all_ok &= check_kvm();
        println!();
    }

    // Docker check (needed for rootfs building)
    all_ok &= check_docker();
    println!();

    // Secrets checks
    all_ok &= check_secrets();
    println!();

    // Tier 2 component checks, probed where they are actually used
    all_ok &= check_tier2_components();
    println!();

    // Config checks
    all_ok &= check_config();
    println!();

    // Network policy capability check
    all_ok &= check_network_policy_capability();
    println!();

    // Node connectivity (if configured)
    all_ok &= check_node_connectivity().await;
    println!();

    // Summary.
    //
    // The exit code has to agree with the text. It did not: `doctor` returned
    // `Ok(())` unconditionally, so it exited 0 while printing failures — and it
    // printed "All checks passed!" on a machine where `nucleus start` exited 1,
    // because every missing Tier 2 component was graded a warning and
    // `print_check` counts warnings as success. A green check that cannot go red
    // is not a check.
    if all_ok {
        println!("All checks passed.");
        println!("This says the components are installed. To prove Tier 2 actually");
        println!("works, boot a real pod: nucleus verify --tier2");
        Ok(())
    } else {
        println!("Some checks failed. Run 'nucleus setup' to fix them.");
        anyhow::bail!("environment check failed")
    }
}

fn print_check(name: &str, status: Status, message: &str) -> bool {
    println!("{} {}: {}", status.icon(), name, message);
    !matches!(status, Status::Error)
}

fn check_platform() -> bool {
    println!("Platform");
    println!("--------");

    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    let os_ok = print_check(
        "Operating System",
        if os == "macos" || os == "linux" {
            Status::Ok
        } else {
            Status::Error
        },
        &format!("{} ({})", os, arch),
    );

    #[cfg(target_os = "macos")]
    {
        let chip = check_chip();
        let chip_status = if chip.supports_nested_virt() {
            Status::Ok
        } else {
            Status::Warning
        };
        let chip_ok = print_check(
            "Apple Chip",
            chip_status,
            &format!(
                "{:?}{}",
                chip,
                if chip.supports_nested_virt() {
                    " (nested virt expected)"
                } else {
                    // An expectation derived from the chip name, not a
                    // capability test. The /dev/kvm probe in the Lima section
                    // is authoritative — inference from chip strings is what
                    // reported an M5 as incapable when it is not.
                    " (nested virt not expected - the /dev/kvm probe below decides)"
                }
            ),
        );

        let version = check_macos_version();
        let version_status = if version.supports_nested_virt() {
            Status::Ok
        } else {
            Status::Warning
        };
        let version_ok = print_check(
            "macOS Version",
            version_status,
            &format!(
                "{}.{}{}",
                version.major,
                version.minor,
                if version.supports_nested_virt() {
                    " (nested virt supported)"
                } else {
                    " (requires macOS 15+)"
                }
            ),
        );

        os_ok && chip_ok && version_ok
    }

    #[cfg(not(target_os = "macos"))]
    os_ok
}

/// Guard: mediates the `sysctl` subprocess spawn used to identify the Apple
/// chip. Named with the `check_` guard prefix so it belongs to
/// `check_platform`'s guard call-closure (capability confinement).
#[cfg(target_os = "macos")]
fn check_chip() -> AppleChip {
    let output = Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok();

    let brand = output
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
        .unwrap_or_default();

    if brand.contains("intel") {
        return AppleChip::Intel;
    }
    match crate::setup::apple_silicon_generation(&brand) {
        Some(1) => AppleChip::M1,
        Some(2) => AppleChip::M2,
        Some(3) => AppleChip::M3,
        Some(4) => AppleChip::M4,
        Some(_) => AppleChip::M5OrNewer,
        None => AppleChip::Unknown,
    }
}

/// Guard: mediates the `sw_vers` subprocess spawn used to read the macOS
/// version. Named with the `check_` guard prefix so it belongs to
/// `check_platform`'s guard call-closure (capability confinement).
#[cfg(target_os = "macos")]
fn check_macos_version() -> MacOSVersion {
    let output = Command::new("sw_vers")
        .args(["-productVersion"])
        .output()
        .ok();

    let version_str = output
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let parts: Vec<&str> = version_str.trim().split('.').collect();

    MacOSVersion {
        major: parts.first().and_then(|s| s.parse().ok()).unwrap_or(0),
        minor: parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0),
    }
}

/// The Lima VM to inspect.
///
/// `setup` takes `--vm-name`, so hardcoding "nucleus" here meant `doctor`
/// reported "VM not found" for any user who named theirs anything else — the
/// two commands disagreed about which machine they were talking about.
fn vm_name() -> String {
    std::env::var("NUCLEUS_VM_NAME").unwrap_or_else(|_| "nucleus".to_string())
}

fn check_lima() -> bool {
    println!("Lima VM");
    println!("-------");

    // Check if Lima is installed and get version
    let lima_output = Command::new("limactl").arg("--version").output().ok();

    let (lima_installed, lima_version) = match lima_output {
        Some(output) if output.status.success() => {
            let version_str = String::from_utf8_lossy(&output.stdout);
            // Parse "limactl version 2.0.3" -> "2.0.3"
            let version = version_str
                .trim()
                .strip_prefix("limactl version ")
                .unwrap_or("")
                .to_string();
            (true, version)
        }
        _ => (false, String::new()),
    };

    if !lima_installed {
        print_check(
            "Lima installed",
            Status::Error,
            "no (install with: brew install lima)",
        );
        return false;
    }

    // Check Lima version (2.0+ required for nested virt)
    let version_parts: Vec<u32> = lima_version
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();
    let major_version = version_parts.first().copied().unwrap_or(0);

    let version_ok = major_version >= 2;
    print_check(
        "Lima version",
        if version_ok {
            Status::Ok
        } else {
            Status::Warning
        },
        &format!(
            "{}{}",
            lima_version,
            if version_ok {
                " (nested virt supported)"
            } else {
                " (upgrade to 2.0+ for nested virt)"
            }
        ),
    );

    // Check for nucleus VM
    let vm_output = Command::new("limactl")
        .args(["list", "--format", "{{.Name}}:{{.Status}}"])
        .output()
        .ok();

    let vms = vm_output
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let nucleus_vm = vms
        .lines()
        .find(|line| line.starts_with(&format!("{}:", vm_name())))
        .map(|line| line.split(':').nth(1).unwrap_or("unknown"));

    let vm_ok = match nucleus_vm {
        Some("Running") => print_check("nucleus VM", Status::Ok, "running"),
        Some(status) => print_check(
            "nucleus VM",
            Status::Warning,
            &format!("{} (run: limactl start nucleus)", status),
        ),
        None => print_check(
            "nucleus VM",
            Status::Error,
            "not found (run: nucleus setup)",
        ),
    };

    // Check KVM inside VM (if running)
    if nucleus_vm == Some("Running") {
        let kvm_check = Command::new("limactl")
            .args(["shell", &vm_name(), "--", "test", "-e", "/dev/kvm"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        print_check(
            "KVM in VM",
            if kvm_check {
                Status::Ok
            } else {
                // NOT a warning. Firecracker is a KVM-based VMM: without
                // /dev/kvm it does not fall back to emulation, it refuses to
                // start (`nucleus-node` returns "firecracker requires
                // /dev/kvm"). Reporting this as a slow-but-working mode sent
                // users down a path that cannot work.
                Status::Error
            },
            if kvm_check {
                "/dev/kvm available (Tier 2 microVMs will run)"
            } else {
                "/dev/kvm MISSING - Firecracker cannot start at all (not emulation). \
                 Recreate the VM with nested virtualization: nucleus setup --force"
            },
        );

        // Check Firecracker version in VM
        let fc_output = Command::new("limactl")
            .args(["shell", &vm_name(), "--", "firecracker", "--version"])
            .output()
            .ok();

        if let Some(output) = fc_output {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                let version = version_str.lines().next().unwrap_or("").trim();

                // A FLOOR, NOT AN EQUALITY TEST. This used to be
                // `version.contains(FIRECRACKER_VERSION)`, which reported a
                // newer *patched* Firecracker as wrong exactly as loudly as an
                // older vulnerable one — so the natural fix for the warning was
                // to downgrade. `judge` refuses known-escape builds and accepts
                // anything at or above the floor that is not denylisted.
                let verdict = nucleus_spec::vmm_version::judge(version);
                print_check(
                    "Firecracker",
                    if verdict.is_acceptable() {
                        Status::Ok
                    } else {
                        Status::Error
                    },
                    &if verdict.is_acceptable() {
                        version.to_string()
                    } else {
                        verdict.to_string()
                    },
                );
            } else {
                print_check(
                    "Firecracker",
                    Status::Error,
                    "not installed in VM (run: nucleus setup)",
                );
            }
        }

        // Check Docker in VM (needed for rootfs building inside VM)
        let docker_check = Command::new("limactl")
            .args(["shell", &vm_name(), "--", "docker", "--version"])
            .output()
            .ok();

        if let Some(output) = docker_check {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                let version = version_str.lines().next().unwrap_or("").trim();
                print_check("Docker in VM", Status::Ok, version);
            } else {
                print_check(
                    "Docker in VM",
                    Status::Warning,
                    "not installed (needed for rootfs building)",
                );
            }
        }
    }

    vm_ok
}

fn check_kvm() -> bool {
    println!("KVM");
    println!("---");

    let kvm_exists = std::path::Path::new("/dev/kvm").exists();
    print_check(
        "/dev/kvm",
        if kvm_exists {
            Status::Ok
        } else {
            Status::Error
        },
        if kvm_exists {
            "exists"
        } else {
            "not found (enable KVM in BIOS)"
        },
    )
}

fn check_docker() -> bool {
    println!("Docker");
    println!("------");

    // Check if Docker is installed
    let docker_output = Command::new("docker").args(["--version"]).output().ok();

    match docker_output {
        Some(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let version_line = version.lines().next().unwrap_or("").trim();
            print_check("Docker CLI", Status::Ok, version_line);

            // Check if Docker daemon is running
            let daemon_check = Command::new("docker")
                .args(["info"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            print_check(
                "Docker daemon",
                if daemon_check {
                    Status::Ok
                } else {
                    Status::Warning
                },
                if daemon_check {
                    "running"
                } else {
                    "not running (start Docker Desktop)"
                },
            )
        }
        _ => print_check(
            "Docker CLI",
            Status::Warning,
            "not installed (optional, needed for cross-compilation)",
        ),
    }
}

fn check_secrets() -> bool {
    println!("Secrets");
    println!("-------");

    // Printed BEFORE the first Keychain read, for the same reason `setup` does
    // it: macOS opens an authorisation dialog when the calling binary is not the
    // one that stored the item, and the process blocks there with no output.
    // `doctor` hitting this is worse than `setup` hitting it — someone runs
    // `doctor` precisely when something is already wrong, and a silent hang is
    // the least useful possible answer.
    #[cfg(target_os = "macos")]
    println!("  (macOS may ask to authorise Keychain access; this waits for you)");

    let mut all_ok = true;

    for kind in SecretKind::all() {
        let exists = SecretStore::exists(*kind).unwrap_or(false);
        let status = if exists { Status::Ok } else { Status::Error };

        all_ok &= print_check(
            kind.account_name(),
            status,
            if exists { "configured" } else { "missing" },
        );

        // Check rotation status
        if exists {
            if let Ok(Some(metadata)) = keychain::MetadataStore::get(*kind) {
                let days = metadata.days_until_rotation();
                if days <= 0 {
                    print_check(
                        &format!("  {} rotation", kind.account_name()),
                        Status::Warning,
                        "overdue",
                    );
                } else if days <= 14 {
                    print_check(
                        &format!("  {} rotation", kind.account_name()),
                        Status::Warning,
                        &format!("due in {} days", days),
                    );
                }
            }
        }
    }

    all_ok
}

/// Do the Tier 2 components exist WHERE THEY ARE USED?
///
/// The previous version of this check looked for `vmlinux` and `rootfs.ext4` in
/// the workstation's own artifacts directory — the wrong side of the boundary.
/// On macOS the node runs inside the Lima VM and consumes paths in *its* filesystem,
/// so a perfectly working install reported "Kernel: missing" and a broken one
/// reported the same. Both findings were also graded `WARN`, which
/// `print_check` treats as success, so `doctor` printed "All checks passed!"
/// in the same minute `nucleus start` exited 1. Measured 2026-07-29.
///
/// Every component here is now probed on the Tier 2 host and graded `ERR`,
/// because each one is required for a pod to boot at all.
fn check_tier2_components() -> bool {
    println!("Tier 2 components (on the host that runs microVMs)");
    println!("-------------------------------------------------");

    let Some(host) = doctor_tier2_host() else {
        print_check(
            "Tier 2 host",
            Status::Warning,
            "none on this platform - Tier 0/1 only",
        );
        return true;
    };

    let checks: [(&str, String); 6] = [
        ("Firecracker", "command -v firecracker".to_string()),
        ("jailer", "command -v jailer".to_string()),
        (
            "Guest kernel",
            format!("test -s {}/vmlinux", provision::HOST_ARTIFACTS_DIR),
        ),
        (
            "Nucleus rootfs",
            format!("test -s {}/rootfs.ext4", provision::HOST_ARTIFACTS_DIR),
        ),
        (
            "nucleus-node",
            "test -x /usr/local/bin/nucleus-node".to_string(),
        ),
        (
            "Node secrets",
            format!(
                "test -s {} && grep -q NUCLEUS_NODE_AUTH_SECRET {}",
                provision::NODE_ENV_PATH,
                provision::NODE_ENV_PATH
            ),
        ),
    ];

    let mut all_ok = true;
    for (name, probe) in &checks {
        let present = host.test(probe);
        all_ok &= print_check(
            name,
            if present { Status::Ok } else { Status::Error },
            if present {
                "installed"
            } else {
                "missing - run: nucleus setup"
            },
        );
    }
    all_ok
}

/// The Tier 2 host `doctor` should probe, if there is one.
fn doctor_tier2_host() -> Option<provision::Tier2Host> {
    if cfg!(target_os = "linux") {
        return Some(provision::Tier2Host::Local);
    }
    let running = Command::new("limactl")
        .args(["list", "--format", "{{.Name}} {{.Status}}"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("nucleus Running"))
        .unwrap_or(false);
    running.then(|| provision::Tier2Host::Lima("nucleus".to_string()))
}

fn check_config() -> bool {
    println!("Configuration");
    println!("-------------");

    let config_path = dirs::config_dir()
        .map(|d| d.join("nucleus").join("config.toml"))
        .unwrap_or_else(|| PathBuf::from("~/.config/nucleus/config.toml"));

    let config_path_str = config_path.display().to_string();
    print_check(
        "Config file",
        if config_path.exists() {
            Status::Ok
        } else {
            Status::Warning
        },
        if config_path.exists() {
            &config_path_str
        } else {
            "not found (will use defaults)"
        },
    )
}

async fn check_node_connectivity() -> bool {
    println!("Node Connectivity");
    println!("-----------------");

    // Try to connect to default node URL
    let node_url = "http://127.0.0.1:8080/health";

    // Create agent with timeout
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(2)))
        .build();
    let agent: ureq::Agent = config.into();

    match agent.get(node_url).call() {
        Ok(resp) if resp.status().as_u16() == 200 => {
            print_check("nucleus-node", Status::Ok, "reachable")
        }
        Ok(resp) => print_check(
            "nucleus-node",
            Status::Warning,
            &format!("responded with status {}", resp.status().as_u16()),
        ),
        Err(_) => print_check(
            "nucleus-node",
            Status::Warning,
            "not reachable (start with: nucleus-node)",
        ),
    }
}

fn check_network_policy_capability() -> bool {
    println!("Network Security");
    println!("----------------");

    let os = std::env::consts::OS;

    if os == "linux" {
        // On Linux, check for iptables
        let iptables_ok = Command::new("iptables")
            .args(["--version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        print_check(
            "Network policy",
            if iptables_ok {
                Status::Ok
            } else {
                Status::Warning
            },
            if iptables_ok {
                "iptables available (full network isolation)"
            } else {
                "iptables not found (network policies may not be enforced)"
            },
        )
    } else {
        // On macOS, network policies run inside the Lima VM
        print_check(
            "Network policy",
            Status::Warning,
            "host-level iptables not available (network policy enforced inside Lima VM only)",
        );

        // Additional warning about the security model
        println!("  Note: On macOS, network security relies on the Lima VM's isolation.");
        println!("        For production workloads with strict network requirements, use Linux.");

        true // Don't fail the check, just warn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_icons() {
        assert_eq!(Status::Ok.icon(), "[OK]");
        assert_eq!(Status::Warning.icon(), "[WARN]");
        assert_eq!(Status::Error.icon(), "[ERR]");
    }

    // The platform helpers `check_chip` and `check_macos_version` each spawn a
    // subprocess, so they must be guards within `check_platform`'s call-closure
    // (capability confinement). This test exercises them to confirm the
    // guard-prefixed functions run without panicking and return usable values.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_platform_guards_are_callable() {
        let version = check_macos_version();
        // First component of `sw_vers`; on any supported macOS host it is >= 10,
        // and falls back to 0 when detection fails. Either is acceptable.
        assert!(version.major == 0 || version.major >= 10);

        // `check_chip` must return a chip whose nested-virt capability is
        // queryable, mirroring how `check_platform` consumes it.
        let chip = check_chip();
        let _ = chip.supports_nested_virt();
    }
}
