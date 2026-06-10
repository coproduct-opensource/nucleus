// =============================================================================
// Firecracker VM configuration
// =============================================================================
//
// Extracted from main.rs to reduce file size. Builds the Firecracker JSON
// configuration from a PodSpec, including kernel arguments, networking,
// vsock, audit sinks, and sandbox proof tokens.

#[cfg(target_os = "linux")]
use std::path::Path;

// NOTE: `serde`, `nucleus_spec::PodSpec` and `crate::net` are intentionally NOT
// gated behind `target_os = "linux"`. The pure lowering seams below
// (`lower_drives`, `lower_vsock`, `lower_network_interfaces`, `seccomp_args`)
// are platform-independent so the isolation invariants they enforce can be
// property-tested on any host (see `mod tests`). Only the side-effecting
// `from_spec` / `apply_seccomp_flags` (which spawn Firecracker via `Command`)
// remain Linux-only.
use serde::Serialize;
#[cfg(target_os = "linux")]
use tokio::process::Command;

use nucleus_spec::PodSpec;

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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

        // Pure lowering seams (property-tested in `mod tests`): the money/boot
        // path uses the exact same functions the invariant tests assert over.
        let vsock = lower_vsock(spec, &vsock_path.display().to_string());
        let network_interfaces = lower_network_interfaces(net_plan);

        Self {
            boot_source: BootSource {
                kernel_image_path: image.kernel_path.display().to_string(),
                boot_args,
            },
            drives: lower_drives(image),
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

// ---------------------------------------------------------------------------
// Pure lowering seams
// ---------------------------------------------------------------------------
//
// These functions are the policy -> VM-config lowering. They are deliberately
// pure and platform-independent (no `Command`, no filesystem, no Firecracker)
// so that the security-critical isolation invariants can be property-tested in
// isolation. `from_spec` / `apply_seccomp_flags` delegate to them, so the
// proven invariants hold on the real boot path — not just in the tests.

/// ISOLATION INVARIANT (1) — read-only rootfs.
///
/// The rootfs drive's `is_read_only` is a pure function of `image.read_only`:
/// an RO policy lowers to `is_read_only = true` and an RW policy lowers to
/// `false` (no silent flip in either direction). The optional scratch drive is
/// always writable and never the root device.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lower_drives(image: &nucleus_spec::ImageSpec) -> Vec<DriveConfig> {
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

/// ISOLATION INVARIANT (2) — distinct guest CIDs never collapse.
///
/// `guest_cid` is copied verbatim from the spec, so lowering is injective on the
/// CID: two specs with distinct CIDs always lower to configs with distinct
/// CIDs. A lowering bug that hard-coded, truncated, or otherwise collided CIDs
/// would break the `lowering_preserves_distinct_cids` proptest.
///
/// TODO(vkvm): there is NO host-side CID allocator in nucleus-node today —
/// `VsockSpec.guest_cid` is supplied by the caller (the `--vsock-cid` CLI arg in
/// nucleus-cli). Cross-pod uniqueness must therefore be guaranteed by the
/// caller/scheduler. This lowering only guarantees it never *introduces* a
/// collision; allocating provably-unique CIDs host-side is tracked for the
/// verified-KVM work.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lower_vsock(spec: &PodSpec, uds_path: &str) -> Option<VsockConfig> {
    spec.spec.vsock.as_ref().map(|vsock| VsockConfig {
        guest_cid: vsock.guest_cid,
        uds_path: uds_path.to_string(),
    })
}

/// ISOLATION INVARIANT (3) — no host NIC into the guest unless networking is
/// explicitly provisioned.
///
/// When `net_plan` is `None` (no network policy / network denied) the lowered
/// config exposes ZERO network interfaces, so the guest has no tap device and
/// therefore no host bridge/route reachable from inside the VM. When a plan is
/// present, exactly one `eth0` tap is attached, bound to the plan's host tap
/// device. (Network-namespace creation + default-deny is a separate
/// orchestration concern enforced by `net::NetnsPlan`; see net.rs.)
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn lower_network_interfaces(net_plan: Option<&net::NetPlan>) -> Vec<NetworkInterface> {
    match net_plan {
        Some(plan) => vec![NetworkInterface {
            iface_id: "eth0".to_string(),
            host_dev_name: plan.tap_name.clone(),
            guest_mac: plan.guest_mac.clone(),
        }],
        None => Vec::new(),
    }
}

/// ISOLATION INVARIANT (4) — seccomp is only ever disabled on explicit request.
///
/// Pure derivation of the seccomp CLI flags Firecracker is launched with:
/// * `Default` / absent  -> no flag (Firecracker's built-in filter stays active)
/// * `Disabled`          -> `--no-seccomp` (the ONLY way to turn the filter off)
/// * `Custom { path }`   -> `--seccomp-filter <path>`
///
/// A lowering bug that emitted `--no-seccomp` for any policy other than
/// `Disabled` would silently strip the sandbox and is caught by the
/// `seccomp_never_silently_disabled` proptest.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn seccomp_args(spec: &PodSpec) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    match spec.spec.seccomp.as_ref() {
        None | Some(nucleus_spec::SeccompSpec::Default) => Vec::new(),
        Some(nucleus_spec::SeccompSpec::Disabled) => vec![OsString::from("--no-seccomp")],
        Some(nucleus_spec::SeccompSpec::Custom { filter_path }) => vec![
            OsString::from("--seccomp-filter"),
            filter_path.clone().into_os_string(),
        ],
    }
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
    // Delegate to the pure `seccomp_args` seam so the launched command carries
    // exactly the flags the invariant tests assert over.
    for arg in seccomp_args(spec) {
        command.arg(arg);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy -> VM-config lowering: isolation-invariant property tests
// ---------------------------------------------------------------------------
//
// These guard the security-critical lowering. Each test is written to FAIL if
// the invariant it protects is broken (RO->RW flip, colliding CIDs, a host NIC
// leaking into a network-denied guest, or seccomp silently disabled). The
// lowering seams are pure + platform-independent, so these run on every host.
#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_spec::{ImageSpec, PodSpec, SeccompSpec, VsockSpec};
    use proptest::prelude::*;
    use std::collections::HashSet;
    use std::ffi::OsString;
    use std::path::PathBuf;

    /// Minimal valid PodSpec with all optional sections defaulted to absent.
    /// Built by deserialization so it exercises the real spec defaults rather
    /// than hand-constructing every field.
    fn base_spec() -> PodSpec {
        serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
            .expect("base PodSpec must deserialize")
    }

    fn image(read_only: bool, scratch: bool) -> ImageSpec {
        ImageSpec {
            kernel_path: PathBuf::from("/var/lib/nucleus/vmlinux"),
            rootfs_path: PathBuf::from("/var/lib/nucleus/rootfs.ext4"),
            boot_args: None,
            read_only,
            scratch_path: scratch.then(|| PathBuf::from("/var/lib/nucleus/scratch.ext4")),
        }
    }

    // ----- Invariant (1): read-only rootfs ---------------------------------

    proptest! {
        #[test]
        fn readonly_policy_lowers_to_readonly_rootfs(ro in any::<bool>(), scratch in any::<bool>()) {
            let drives = lower_drives(&image(ro, scratch));

            // rootfs is always present, first, and the root device.
            prop_assert_eq!(&drives[0].drive_id, "rootfs");
            prop_assert!(drives[0].is_root_device);

            // The invariant: RO policy <=> RO rootfs, with no silent flip in
            // either direction.
            prop_assert_eq!(drives[0].is_read_only, ro);

            // A scratch disk, when present, is always writable and never root.
            if scratch {
                prop_assert_eq!(drives.len(), 2);
                prop_assert_eq!(&drives[1].drive_id, "scratch");
                prop_assert!(!drives[1].is_root_device);
                prop_assert!(!drives[1].is_read_only);
            } else {
                prop_assert_eq!(drives.len(), 1);
            }
        }
    }

    // ----- Invariant (2): distinct vsock CIDs never collide ----------------

    fn lower_cid(cid: u32) -> u32 {
        let mut spec = base_spec();
        spec.spec.vsock = Some(VsockSpec {
            guest_cid: cid,
            port: 1024,
        });
        lower_vsock(&spec, "/run/nucleus/vsock.sock")
            .expect("vsock present")
            .guest_cid
    }

    proptest! {
        #[test]
        fn lowering_preserves_distinct_cids(
            cids in prop::collection::hash_set(any::<u32>(), 1..64)
        ) {
            // N specs, each with a DISTINCT guest_cid (hash_set guarantees it).
            let lowered: Vec<u32> = cids.iter().copied().map(lower_cid).collect();

            // The invariant: lowering is injective on guest_cid — it never
            // collapses two distinct agents' CIDs into one. A bug that
            // hard-coded / truncated the CID would shrink this set and FAIL.
            let unique: HashSet<u32> = lowered.iter().copied().collect();
            prop_assert_eq!(unique.len(), cids.len());

            // ...and each CID is preserved verbatim (no remapping).
            for cid in cids {
                prop_assert_eq!(lower_cid(cid), cid);
            }
        }
    }

    #[test]
    fn absent_vsock_lowers_to_no_vsock() {
        let spec = base_spec();
        assert!(spec.spec.vsock.is_none());
        assert!(lower_vsock(&spec, "/run/nucleus/vsock.sock").is_none());
    }

    // ----- Invariant (3): no host NIC into a network-denied guest ----------

    #[test]
    fn no_net_plan_lowers_to_zero_network_interfaces() {
        // No NetPlan == network denied / absent => the guest has no tap device
        // and therefore no host bridge/route reachable from inside the VM.
        let ifaces = lower_network_interfaces(None);
        assert!(
            ifaces.is_empty(),
            "network-denied guest must have NO network interface, got {ifaces:?}"
        );
    }

    #[test]
    fn net_plan_lowers_to_exactly_one_bound_tap() {
        // A real NetPlan from the allocator (pure computation, no OS calls).
        let plan = net::NetworkAllocator::new()
            .allocate(uuid::Uuid::new_v4(), "nuc-test".to_string())
            .expect("allocate net plan");
        let ifaces = lower_network_interfaces(Some(&plan));

        assert_eq!(ifaces.len(), 1, "expected exactly one NIC");
        assert_eq!(ifaces[0].iface_id, "eth0");
        // The single NIC must be bound to the plan's host tap device — not some
        // other host bridge/interface.
        assert_eq!(ifaces[0].host_dev_name, plan.tap_name);
        assert_eq!(ifaces[0].guest_mac, plan.guest_mac);
    }

    // ----- Invariant (4): seccomp only disabled on explicit request --------

    #[test]
    fn seccomp_default_and_absent_keep_filter_active() {
        let mut spec = base_spec();
        // Absent policy => no flag => Firecracker's built-in filter stays on.
        assert!(seccomp_args(&spec).is_empty());
        // Explicit Default => same.
        spec.spec.seccomp = Some(SeccompSpec::Default);
        assert!(seccomp_args(&spec).is_empty());
    }

    #[test]
    fn seccomp_disabled_emits_no_seccomp_flag() {
        let mut spec = base_spec();
        spec.spec.seccomp = Some(SeccompSpec::Disabled);
        assert_eq!(seccomp_args(&spec), vec![OsString::from("--no-seccomp")]);
    }

    #[test]
    fn seccomp_custom_pins_filter_path() {
        let mut spec = base_spec();
        spec.spec.seccomp = Some(SeccompSpec::Custom {
            filter_path: PathBuf::from("/etc/nucleus/seccomp.bpf"),
        });
        assert_eq!(
            seccomp_args(&spec),
            vec![
                OsString::from("--seccomp-filter"),
                OsString::from("/etc/nucleus/seccomp.bpf"),
            ]
        );
    }

    proptest! {
        #[test]
        fn seccomp_never_silently_disabled(disable in any::<bool>()) {
            let mut spec = base_spec();
            spec.spec.seccomp = Some(if disable {
                SeccompSpec::Disabled
            } else {
                SeccompSpec::Default
            });
            let has_disable = seccomp_args(&spec)
                .iter()
                .any(|a| a.to_string_lossy() == "--no-seccomp");
            // The invariant: `--no-seccomp` appears IFF the policy is explicitly
            // Disabled. A bug that disabled seccomp for a Default policy would
            // FAIL here.
            prop_assert_eq!(has_disable, disable);
        }
    }
}
