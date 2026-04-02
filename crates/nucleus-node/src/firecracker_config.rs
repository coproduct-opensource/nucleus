// =============================================================================
// Firecracker VM configuration
// =============================================================================
//
// Extracted from main.rs to reduce file size. Builds the Firecracker JSON
// configuration from a PodSpec, including kernel arguments, networking,
// vsock, audit sinks, and sandbox proof tokens.

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use serde::Serialize;
#[cfg(target_os = "linux")]
use tokio::process::Command;

#[cfg(target_os = "linux")]
use nucleus_spec::PodSpec;

#[cfg(target_os = "linux")]
use crate::net;
#[cfg(target_os = "linux")]
use crate::ApiError;

// ---------------------------------------------------------------------------
// Config structs
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
pub(crate) struct FirecrackerConfig {
    #[serde(rename = "boot-source")]
    boot_source: BootSource,
    drives: Vec<DriveConfig>,
    #[serde(rename = "machine-config")]
    machine_config: MachineConfig,
    #[serde(rename = "network-interfaces", skip_serializing_if = "Vec::is_empty")]
    network_interfaces: Vec<NetworkInterface>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vsock: Option<VsockConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logger: Option<LoggerConfig>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct BootSource {
    kernel_image_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    boot_args: Option<String>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct DriveConfig {
    drive_id: String,
    path_on_host: String,
    is_root_device: bool,
    is_read_only: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct MachineConfig {
    vcpu_count: i64,
    mem_size_mib: i64,
    smt: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct NetworkInterface {
    iface_id: String,
    host_dev_name: String,
    guest_mac: String,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct LoggerConfig {
    log_path: String,
    level: String,
    show_level: bool,
    show_log_origin: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
struct VsockConfig {
    guest_cid: u32,
    uds_path: String,
}

// ---------------------------------------------------------------------------
// FirecrackerConfig construction
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
impl FirecrackerConfig {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_spec(
        spec: &PodSpec,
        log_path: &Path,
        vsock_path: &Path,
        image: &nucleus_spec::ImageSpec,
        net_plan: Option<&net::NetPlan>,
        auth_secret: &str,
        approval_secret: &str,
        workload_api_port: Option<u32>,
    ) -> Self {
        let vcpu_count = spec
            .spec
            .resources
            .as_ref()
            .and_then(|r| r.cpu_cores)
            .unwrap_or(1) as i64;
        let mem_size_mib = spec
            .spec
            .resources
            .as_ref()
            .and_then(|r| r.memory_mib)
            .unwrap_or(512) as i64;

        let default_args = "console=ttyS0 reboot=k panic=1 pci=off init=/init".to_string();
        let mut boot_args = match image.boot_args.clone() {
            Some(args) => {
                if args.contains("init=") {
                    Some(args)
                } else {
                    Some(format!("{args} init=/init"))
                }
            }
            None => Some(default_args),
        };

        if let Some(plan) = net_plan {
            let extra = plan.kernel_arg();
            boot_args = match boot_args.take() {
                Some(args) if args.contains("nucleus.net=") => Some(args),
                Some(args) => Some(format!("{args} {extra}")),
                None => Some(extra),
            };
        }

        boot_args = match boot_args.take() {
            Some(args) if args.contains("ipv6.disable=") => Some(args),
            Some(args) => Some(format!("{args} ipv6.disable=1")),
            None => Some("ipv6.disable=1".to_string()),
        };

        // Inject secrets via kernel command line (read by nucleus-guest-init)
        // This is more secure than baking secrets into the rootfs image
        boot_args = match boot_args.take() {
            Some(args) => Some(format!(
                "{args} nucleus.auth_secret={auth_secret} nucleus.approval_secret={approval_secret}"
            )),
            None => Some(format!(
                "nucleus.auth_secret={auth_secret} nucleus.approval_secret={approval_secret}"
            )),
        };

        // Inject workload API port if identity management is enabled
        if let Some(port) = workload_api_port {
            boot_args = match boot_args.take() {
                Some(args) => Some(format!("{args} nucleus.workload_api_port={port}")),
                None => Some(format!("nucleus.workload_api_port={port}")),
            };
        }

        // Inject audit S3 sink config and AWS credentials via kernel args
        if let Some(ref sink) = spec.spec.audit_sink {
            boot_args = match boot_args.take() {
                Some(args) => Some(format!("{args} nucleus.audit_s3_bucket={}", sink.s3_bucket)),
                None => Some(format!("nucleus.audit_s3_bucket={}", sink.s3_bucket)),
            };
            if let Some(ref prefix) = sink.s3_prefix {
                if let Some(ref mut args) = boot_args {
                    args.push_str(&format!(" nucleus.audit_s3_prefix={prefix}"));
                }
            }
            if let Some(ref region) = sink.s3_region {
                if let Some(ref mut args) = boot_args {
                    args.push_str(&format!(" nucleus.audit_s3_region={region}"));
                }
            }
            if let Some(ref endpoint) = sink.s3_endpoint {
                if let Some(ref mut args) = boot_args {
                    args.push_str(&format!(" nucleus.audit_s3_endpoint={endpoint}"));
                }
            }
            // Forward ambient AWS credentials for S3 audit sink
            for (env_key, arg_key) in [
                ("AWS_ACCESS_KEY_ID", "nucleus.aws_access_key_id"),
                ("AWS_SECRET_ACCESS_KEY", "nucleus.aws_secret_access_key"),
                ("AWS_SESSION_TOKEN", "nucleus.aws_session_token"),
                ("AWS_DEFAULT_REGION", "nucleus.aws_default_region"),
            ] {
                if let Ok(val) = std::env::var(env_key) {
                    if let Some(ref mut args) = boot_args {
                        args.push_str(&format!(" {arg_key}={val}"));
                    }
                }
            }
        }

        // Inject sandbox proof token so tool-proxy inside the VM can verify it's managed.
        // This is a fallback — tier 1 (SVID with attestation) is preferred in Firecracker.
        {
            use sha2::{Digest, Sha256};
            let spec_yaml = serde_yaml::to_string(spec).unwrap_or_default();
            let spec_hash = hex::encode(Sha256::digest(spec_yaml.as_bytes()));
            let sandbox_token = nucleus_client::generate_sandbox_token(
                auth_secret.as_bytes(),
                "firecracker",
                &spec_hash,
            );
            boot_args = match boot_args.take() {
                Some(args) => Some(format!("{args} nucleus.sandbox_token={sandbox_token}")),
                None => Some(format!("nucleus.sandbox_token={sandbox_token}")),
            };
        }

        let vsock = spec.spec.vsock.as_ref().map(|vsock| VsockConfig {
            guest_cid: vsock.guest_cid,
            uds_path: vsock_path.display().to_string(),
        });

        let network_interfaces = match net_plan {
            Some(plan) => vec![NetworkInterface {
                iface_id: "eth0".to_string(),
                host_dev_name: plan.tap_name.clone(),
                guest_mac: plan.guest_mac.clone(),
            }],
            None => Vec::new(),
        };

        Self {
            boot_source: BootSource {
                kernel_image_path: image.kernel_path.display().to_string(),
                boot_args,
            },
            drives: build_drive_config(image),
            machine_config: MachineConfig {
                vcpu_count,
                mem_size_mib,
                smt: false,
            },
            network_interfaces,
            vsock,
            logger: Some(LoggerConfig {
                log_path: log_path.display().to_string(),
                level: "Info".to_string(),
                show_level: true,
                show_log_origin: false,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn build_drive_config(image: &nucleus_spec::ImageSpec) -> Vec<DriveConfig> {
    let mut drives = vec![DriveConfig {
        drive_id: "rootfs".to_string(),
        path_on_host: image.rootfs_path.display().to_string(),
        is_root_device: true,
        is_read_only: image.read_only,
    }];

    if let Some(ref scratch) = image.scratch_path {
        drives.push(DriveConfig {
            drive_id: "scratch".to_string(),
            path_on_host: scratch.display().to_string(),
            is_root_device: false,
            is_read_only: false,
        });
    }

    drives
}

/// Verify that seccomp is active on a Firecracker process by reading /proc/{pid}/status.
/// Returns Ok(()) if seccomp mode is 2 (SECCOMP_MODE_FILTER).
#[cfg(target_os = "linux")]
pub(crate) fn verify_seccomp_active(pid: u32) -> Result<(), String> {
    let status_path = format!("/proc/{}/status", pid);
    let status = std::fs::read_to_string(&status_path)
        .map_err(|e| format!("cannot read {}: {}", status_path, e))?;
    let seccomp_line = status
        .lines()
        .find(|l| l.starts_with("Seccomp:"))
        .ok_or_else(|| format!("no Seccomp field in {}", status_path))?;
    let mode: u8 = seccomp_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if mode < 2 {
        return Err(format!("seccomp mode {} (expected 2 = filter)", mode));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub(crate) fn verify_seccomp_active(_pid: u32) -> Result<(), String> {
    // Seccomp is Linux-only; skip verification on other platforms.
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_seccomp_flags(command: &mut Command, spec: &PodSpec) -> Result<(), ApiError> {
    if let Some(ref seccomp) = spec.spec.seccomp {
        match seccomp {
            nucleus_spec::SeccompSpec::Default => {}
            nucleus_spec::SeccompSpec::Disabled => {
                command.arg("--no-seccomp");
            }
            nucleus_spec::SeccompSpec::Custom { filter_path } => {
                command.arg("--seccomp-filter").arg(filter_path);
            }
        }
    }
    Ok(())
}
