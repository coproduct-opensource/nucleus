//! Integration tests for M3/M4 Mac with native nested virtualization
//!
//! These tests validate the full Firecracker stack on Apple Silicon with
//! hardware-accelerated KVM.
//!
//! Prerequisites:
//! - M3 or M4 Mac
//! - macOS 15+ (Sequoia)
//! - Lima VM "nucleus" running
//! - Firecracker installed in VM
//!
//! Run with: cargo test -p nucleus-cli --test macos_m3m4

use std::process::Command;

/// Information about the Lima VM
#[derive(Debug)]
struct LimaVmInfo {
    name: String,
    status: String,
    vm_type: String,
}

/// Check if running on macOS
fn is_macos() -> bool {
    std::env::consts::OS == "macos"
}

/// Check if running on Apple Silicon (ARM64)
fn is_apple_silicon() -> bool {
    std::env::consts::ARCH == "aarch64"
}

/// Detect Apple chip type
fn detect_apple_chip() -> String {
    let output = Command::new("sysctl")
        .args(["-n", "machdep.cpu.brand_string"])
        .output()
        .ok();

    output
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Detect macOS version
fn detect_macos_version() -> (u32, u32) {
    let output = Command::new("sw_vers")
        .args(["-productVersion"])
        .output()
        .ok();

    let version_str = output
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let parts: Vec<&str> = version_str.trim().split('.').collect();

    (
        parts.first().and_then(|s| s.parse().ok()).unwrap_or(0),
        parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0),
    )
}

/// Check if Lima is installed
fn is_lima_installed() -> bool {
    Command::new("limactl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get Lima VM info
fn get_lima_vm_info(vm_name: &str) -> Option<LimaVmInfo> {
    let output = Command::new("limactl")
        .args(["list", "--format", "{{.Name}}:{{.Status}}:{{.VMType}}"])
        .output()
        .ok()?;

    let vms = String::from_utf8_lossy(&output.stdout);

    for line in vms.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 && parts[0] == vm_name {
            return Some(LimaVmInfo {
                name: parts[0].to_string(),
                status: parts[1].to_string(),
                vm_type: parts[2].to_string(),
            });
        }
    }

    None
}

/// Check if KVM is available in the Lima VM
fn is_kvm_available_in_vm(vm_name: &str) -> bool {
    Command::new("limactl")
        .args(["shell", vm_name, "--", "test", "-c", "/dev/kvm"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Get Firecracker version in VM
fn get_firecracker_version_in_vm(vm_name: &str) -> Option<String> {
    let output = Command::new("limactl")
        .args(["shell", vm_name, "--", "firecracker", "--version"])
        .output()
        .ok()?;

    if output.status.success() {
        Some(
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string(),
        )
    } else {
        None
    }
}

/// Check if this is an M3 or M4 Mac
fn is_m3_or_m4() -> bool {
    let chip = detect_apple_chip().to_lowercase();
    chip.contains("m3") || chip.contains("m4")
}

/// Check if macOS version supports nested virtualization (15+)
fn macos_supports_nested_virt() -> bool {
    let (major, _) = detect_macos_version();
    major >= 15
}

#[test]
#[ignore = "requires M3/M4 Mac with macOS 15+ and Lima VM running"]
fn test_platform_detection() {
    assert!(is_macos(), "Must run on macOS");
    assert!(is_apple_silicon(), "Must run on Apple Silicon");

    let chip = detect_apple_chip();
    println!("Detected chip: {}", chip);

    let (major, minor) = detect_macos_version();
    println!("Detected macOS version: {}.{}", major, minor);

    assert!(
        is_m3_or_m4(),
        "Must run on M3 or M4 Mac (detected: {})",
        chip
    );
    assert!(
        macos_supports_nested_virt(),
        "macOS must be 15+ for nested virt (detected: {}.{})",
        major,
        minor
    );
}

#[test]
#[ignore = "requires M3/M4 Mac with macOS 15+ and Lima VM running"]
fn test_lima_vm_running() {
    assert!(is_lima_installed(), "Lima must be installed");

    let vm_info = get_lima_vm_info("nucleus").expect("nucleus VM should exist");

    println!("VM Name: {}", vm_info.name);
    println!("VM Status: {}", vm_info.status);
    println!("VM Type: {}", vm_info.vm_type);

    assert_eq!(vm_info.status, "Running", "VM must be running");
    assert_eq!(
        vm_info.vm_type, "vz",
        "VM must use Apple Virtualization.framework (vz)"
    );
}

#[test]
#[ignore = "requires M3/M4 Mac with macOS 15+ and Lima VM running"]
fn test_kvm_available_in_vm() {
    assert!(
        is_kvm_available_in_vm("nucleus"),
        "KVM must be available in nucleus VM for native Firecracker performance"
    );
}

#[test]
#[ignore = "requires M3/M4 Mac with macOS 15+ and Lima VM running"]
fn test_firecracker_installed_in_vm() {
    let version =
        get_firecracker_version_in_vm("nucleus").expect("Firecracker should be installed in VM");

    println!("Firecracker version: {}", version);

    assert!(
        version.contains("Firecracker"),
        "Should be valid Firecracker version"
    );
    assert!(
        version.contains("1.14"),
        "Should be Firecracker 1.14.x (got: {})",
        version
    );
}

#[test]
#[ignore = "requires M3/M4 Mac with macOS 15+ and Lima VM running"]
fn test_full_m3m4_stack() {
    // This test validates the complete M3/M4 testing environment

    // 1. Platform checks
    assert!(is_macos(), "Must run on macOS");
    assert!(is_apple_silicon(), "Must run on Apple Silicon");
    assert!(is_m3_or_m4(), "Must run on M3 or M4 Mac");
    assert!(macos_supports_nested_virt(), "macOS must be 15+");

    // 2. Lima checks
    assert!(is_lima_installed(), "Lima must be installed");
    let vm_info = get_lima_vm_info("nucleus").expect("nucleus VM should exist");
    assert_eq!(vm_info.status, "Running", "VM must be running");
    assert_eq!(vm_info.vm_type, "vz", "VM must use vz driver");

    // 3. KVM check
    assert!(
        is_kvm_available_in_vm("nucleus"),
        "KVM must be available for native performance"
    );

    // 4. Firecracker check
    let fc_version =
        get_firecracker_version_in_vm("nucleus").expect("Firecracker should be installed");
    assert!(fc_version.contains("1.14"), "Firecracker 1.14.x required");

    println!("\n=== M3/M4 Native Testing Stack Validated ===");
    println!(
        "Platform: {} macOS {}.{}",
        detect_apple_chip(),
        detect_macos_version().0,
        detect_macos_version().1
    );
    println!("Lima VM: {} ({})", vm_info.name, vm_info.vm_type);
    println!("KVM: Available (native performance)");
    println!("Firecracker: {}", fc_version);
    println!("=============================================\n");
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_is_macos() {
        // This should pass on any platform - it just returns true/false
        let _ = is_macos();
    }

    #[test]
    fn test_is_apple_silicon() {
        // This should pass on any platform - it just returns true/false
        let _ = is_apple_silicon();
    }
}
