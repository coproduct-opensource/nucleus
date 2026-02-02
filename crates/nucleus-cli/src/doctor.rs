//! Doctor command - diagnose nucleus environment issues

use anyhow::Result;
use std::path::PathBuf;
use std::process::Command;

use crate::keychain::{self, SecretKind, SecretStore};
#[cfg(target_os = "macos")]
use crate::setup::{AppleChip, MacOSVersion};

/// Expected Firecracker version
const EXPECTED_FIRECRACKER_VERSION: &str = "1.14.1";

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

    // Artifacts checks
    all_ok &= check_artifacts();
    println!();

    // Config checks
    all_ok &= check_config();
    println!();

    // Node connectivity (if configured)
    all_ok &= check_node_connectivity().await;
    println!();

    // Summary
    if all_ok {
        println!("All checks passed! Nucleus is ready to use.");
    } else {
        println!("Some checks failed. Run 'nucleus setup' to fix issues.");
    }

    Ok(())
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
        let chip = detect_chip();
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
                    " (nested virt supported)"
                } else {
                    " (nested virt NOT supported)"
                }
            ),
        );

        let version = detect_macos_version();
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

#[cfg(target_os = "macos")]
fn detect_chip() -> AppleChip {
    let output = Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok();

    let brand = output
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
        .unwrap_or_default();

    if brand.contains("m4") {
        AppleChip::M4
    } else if brand.contains("m3") {
        AppleChip::M3
    } else if brand.contains("m2") {
        AppleChip::M2
    } else if brand.contains("m1") {
        AppleChip::M1
    } else if brand.contains("intel") {
        AppleChip::Intel
    } else {
        AppleChip::Unknown
    }
}

#[cfg(target_os = "macos")]
fn detect_macos_version() -> MacOSVersion {
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

fn check_lima() -> bool {
    println!("Lima VM");
    println!("-------");

    // Check if Lima is installed and get version
    let lima_output = Command::new("limactl")
        .arg("--version")
        .output()
        .ok();

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
        .find(|line| line.starts_with("nucleus:"))
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
            .args(["shell", "nucleus", "--", "test", "-e", "/dev/kvm"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        print_check(
            "KVM in VM",
            if kvm_check {
                Status::Ok
            } else {
                Status::Warning
            },
            if kvm_check {
                "/dev/kvm available (native Firecracker performance)"
            } else {
                "/dev/kvm not available (emulation mode - slower)"
            },
        );

        // Check Firecracker version in VM
        let fc_output = Command::new("limactl")
            .args(["shell", "nucleus", "--", "firecracker", "--version"])
            .output()
            .ok();

        if let Some(output) = fc_output {
            if output.status.success() {
                let version_str = String::from_utf8_lossy(&output.stdout);
                let version = version_str.lines().next().unwrap_or("").trim();

                let version_ok = version.contains(EXPECTED_FIRECRACKER_VERSION);
                print_check(
                    "Firecracker",
                    if version_ok {
                        Status::Ok
                    } else {
                        Status::Warning
                    },
                    version,
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
            .args(["shell", "nucleus", "--", "docker", "--version"])
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

fn check_artifacts() -> bool {
    println!("Artifacts");
    println!("---------");

    let artifacts_dir = dirs::config_dir()
        .map(|d| d.join("nucleus").join("artifacts"))
        .unwrap_or_else(|| PathBuf::from("~/.config/nucleus/artifacts"));

    let dir_exists = artifacts_dir.exists();
    print_check(
        "Artifacts directory",
        if dir_exists {
            Status::Ok
        } else {
            Status::Error
        },
        &artifacts_dir.display().to_string(),
    );

    if !dir_exists {
        return false;
    }

    let mut all_ok = true;

    // Check kernel
    let kernel_path = artifacts_dir.join("vmlinux");
    all_ok &= print_check(
        "Kernel",
        if kernel_path.exists() {
            Status::Ok
        } else {
            Status::Warning
        },
        if kernel_path.exists() {
            "present"
        } else {
            "missing (will be downloaded by VM)"
        },
    );

    // Check rootfs
    let rootfs_path = artifacts_dir.join("rootfs.ext4");
    all_ok &= print_check(
        "Rootfs",
        if rootfs_path.exists() {
            Status::Ok
        } else {
            Status::Warning
        },
        if rootfs_path.exists() {
            "present"
        } else {
            "missing (needs to be built)"
        },
    );

    // Check scratch
    let scratch_path = artifacts_dir.join("scratch.ext4");
    print_check(
        "Scratch disk",
        if scratch_path.exists() {
            Status::Ok
        } else {
            Status::Warning
        },
        if scratch_path.exists() {
            "present"
        } else {
            "missing (optional)"
        },
    );

    all_ok
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_icons() {
        assert_eq!(Status::Ok.icon(), "[OK]");
        assert_eq!(Status::Warning.icon(), "[WARN]");
        assert_eq!(Status::Error.icon(), "[ERR]");
    }
}
