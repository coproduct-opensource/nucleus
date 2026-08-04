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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

/// Where the jailer puts things, and what those things are called INSIDE the jail.
///
/// The jailer chroots to `<chroot_base>/<exec_file_name>/<id>/root`, so every
/// path Firecracker reads must be expressed relative to that root, while the
/// host must still know the outside path to hard-link resources in and to reach
/// the vsock socket. This type holds both halves so no caller has to reconstruct
/// either by string surgery.
#[derive(Debug, Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct JailLayout {
    /// Host path of the jail root — `<chroot_base>/<exec>/<id>/root`.
    pub jail_root: std::path::PathBuf,
}

/// In-jail names. Fixed, not derived from the host path: a jailed Firecracker
/// sees `/kernel`, never `/var/lib/nucleus/images/<sha>/vmlinux`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) mod in_jail {
    pub const KERNEL: &str = "/kernel";
    pub const ROOTFS: &str = "/rootfs.ext4";
    pub const SCRATCH: &str = "/scratch.ext4";
    pub const VSOCK: &str = "/vsock.sock";
    pub const LOG: &str = "/firecracker.log";
    pub const CONFIG: &str = "/config.json";
    pub const SECCOMP: &str = "/seccomp.bpf";
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl JailLayout {
    /// Derive the layout the jailer will create. Pure — no filesystem access —
    /// so the path arithmetic is testable on any host.
    pub fn new(
        chroot_base: &std::path::Path,
        firecracker_path: &std::path::Path,
        pod_id: &str,
    ) -> Self {
        let exec_name = firecracker_path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "firecracker".to_string());
        JailLayout {
            jail_root: chroot_base.join(exec_name).join(pod_id).join("root"),
        }
    }

    /// Host path of an in-jail file. `in_jail::*` names are absolute-in-jail, so
    /// the leading slash is stripped before joining — `jail_root.join("/kernel")`
    /// would silently yield `/kernel` on the HOST, which is how a jail escape
    /// gets written by accident.
    pub fn host_path(&self, in_jail_name: &str) -> std::path::PathBuf {
        self.jail_root.join(in_jail_name.trim_start_matches('/'))
    }
}

/// How a resource may legitimately be placed inside the jail.
///
/// THIS DISTINCTION IS LOAD-BEARING AND IT IS ABOUT DATA, NOT ISOLATION. Today a
/// non-jailed Firecracker is handed the caller's path directly, so when the guest
/// writes to an RW rootfs those writes land in the caller's file. Under a jail the
/// resource has to be brought inside, and a hard link preserves exactly that
/// semantics while a copy silently does not.
///
/// So a cross-device jail — where `hard_link` fails with `EXDEV` — must be a
/// LAUNCH FAILURE for anything writable, never a quiet fallback to copy. The
/// failure mode a copy would create is the worst kind: every pod appears to work,
/// and the guest's writes are discarded at teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Placement {
    /// The guest only reads this. A copy is an acceptable cross-device fallback.
    CopyableIfCrossDevice,
    /// The guest WRITES here. Hard link or fail — a copy would change semantics.
    HardLinkOnly,
}

/// One resource that must exist inside the jail before Firecracker execs.
#[derive(Debug, Clone)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct JailResource {
    /// Where it lives on the host now.
    pub host_source: std::path::PathBuf,
    /// The name Firecracker will open it by, after `chroot`.
    pub in_jail: &'static str,
    pub placement: Placement,
}

/// Everything that must be inside the jail, derived from the spec.
///
/// Pure — no filesystem access — so the placement policy is testable on any host,
/// which matters because the whole launch path below it is Linux-only and cannot
/// be exercised where this is being developed.
///
/// The config file and the log file are NOT here: they are produced rather than
/// relocated, so `prepare_jail` writes them directly.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn jail_resources(image: &nucleus_spec::ImageSpec, spec: &PodSpec) -> Vec<JailResource> {
    let mut resources = vec![
        JailResource {
            host_source: image.kernel_path.clone(),
            in_jail: in_jail::KERNEL,
            // The kernel image is never written by the guest.
            placement: Placement::CopyableIfCrossDevice,
        },
        JailResource {
            host_source: image.rootfs_path.clone(),
            in_jail: in_jail::ROOTFS,
            // Mirrors `lower_drives`' `is_read_only: image.read_only` exactly. If
            // these two ever disagree, a writable rootfs gets copied and the
            // guest's writes vanish — hence the `rw_rootfs_is_hard_link_only` pin.
            placement: if image.read_only {
                Placement::CopyableIfCrossDevice
            } else {
                Placement::HardLinkOnly
            },
        },
    ];

    if let Some(ref scratch) = image.scratch_path {
        resources.push(JailResource {
            host_source: scratch.clone(),
            in_jail: in_jail::SCRATCH,
            // `lower_drives` gives scratch `is_read_only: false` unconditionally.
            placement: Placement::HardLinkOnly,
        });
    }

    // A custom seccomp filter is opened by Firecracker AFTER the chroot, so the
    // BPF file has to come inside too. Missing this does not fail open — the VMM
    // cannot find its filter and dies — but it dies opaquely, which is its own
    // kind of bad.
    if let Some(nucleus_spec::SeccompSpec::Custom { filter_path }) = spec.spec.seccomp.as_ref() {
        resources.push(JailResource {
            host_source: filter_path.clone(),
            in_jail: in_jail::SECCOMP,
            placement: Placement::CopyableIfCrossDevice,
        });
    }

    resources
}

/// Bring one resource inside the jail, honouring its `Placement`.
///
/// Hard link first, always: it is cheap, it shares no page cache across jails
/// that the resource did not already share, and — critically — it keeps writes
/// visible at the caller's path exactly as the non-jailed path does today.
#[cfg(target_os = "linux")]
fn place_resource(resource: &JailResource, dest: &Path) -> Result<(), String> {
    // A relaunch under the same pod id finds the previous link still there.
    // `hard_link` fails with AlreadyExists rather than replacing.
    if dest.exists() {
        std::fs::remove_file(dest)
            .map_err(|e| format!("cannot clear stale {}: {e}", dest.display()))?;
    }
    match std::fs::hard_link(&resource.host_source, dest) {
        Ok(()) => Ok(()),
        Err(err) => match resource.placement {
            Placement::HardLinkOnly => Err(format!(
                "cannot hard-link {} into the jail at {}: {err}. This resource is \
                 WRITABLE by the guest, so falling back to a copy would silently \
                 discard the guest's writes instead of landing them at the source \
                 path — which is what the non-jailed path does. Put the jail \
                 (--jailer-chroot-base) on the same filesystem as the image, or \
                 pass an image whose writable drives already live there.",
                resource.host_source.display(),
                dest.display()
            )),
            Placement::CopyableIfCrossDevice => std::fs::copy(&resource.host_source, dest)
                .map(|_| ())
                .map_err(|copy_err| {
                    format!(
                        "cannot bring {} into the jail: hard link failed ({err}) and \
                         copy failed ({copy_err})",
                        resource.host_source.display()
                    )
                }),
        },
    }
}

/// Build the jail's contents so the jailer has something to chroot into.
///
/// ORDERING. This runs BEFORE the jailer is spawned, which is safe because the
/// jailer's documented behaviour on an existing `<chroot_base>/<exec>/<id>/root`
/// is "nothing is done if the path already exists" — it does not refuse, and it
/// does not clear what is there. It does `chown` the root directory to
/// `<uid>:<gid>`, but that is the directory only, so every file placed here is
/// chowned explicitly below. Firecracker runs unprivileged after the drop; a
/// root-owned scratch image would leave it unable to write its own disk.
///
/// The vsock socket is deliberately absent: Firecracker CREATES it at `uds_path`
/// inside the jail, and the host reaches it through `layout.host_path(VSOCK)`.
#[cfg(target_os = "linux")]
#[tracing::instrument(skip_all, fields(boot.stage = "prepare_jail"))]
pub(crate) fn prepare_jail(
    layout: &JailLayout,
    image: &nucleus_spec::ImageSpec,
    spec: &PodSpec,
    config_json: &[u8],
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    use std::os::unix::fs::chown;

    std::fs::create_dir_all(&layout.jail_root).map_err(|e| {
        format!(
            "cannot create jail root {}: {e}",
            layout.jail_root.display()
        )
    })?;

    let mut placed: Vec<std::path::PathBuf> = Vec::new();

    for resource in jail_resources(image, spec) {
        let dest = layout.host_path(resource.in_jail);
        place_resource(&resource, &dest)?;
        placed.push(dest);
    }

    // The VM config, written where the jailed Firecracker will read it.
    let config_dest = layout.host_path(in_jail::CONFIG);
    std::fs::write(&config_dest, config_json)
        .map_err(|e| format!("cannot write jailed config {}: {e}", config_dest.display()))?;
    placed.push(config_dest);

    // Firecracker's logger opens this path after dropping privileges, so it must
    // exist and be writable by the unprivileged uid — it will not create it.
    let log_dest = layout.host_path(in_jail::LOG);
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_dest)
        .map_err(|e| format!("cannot create jailed log {}: {e}", log_dest.display()))?;
    placed.push(log_dest);

    // The jail root itself must be writable by the dropped uid: Firecracker
    // creates the vsock socket inside it.
    chown(&layout.jail_root, Some(uid), Some(gid))
        .map_err(|e| format!("cannot chown jail root to {uid}:{gid}: {e}"))?;
    for path in &placed {
        chown(path, Some(uid), Some(gid))
            .map_err(|e| format!("cannot chown {} to {uid}:{gid}: {e}", path.display()))?;
    }

    Ok(())
}

/// Remove a pod's jail directory.
///
/// Best-effort by design, and it takes the pod directory (`<...>/<id>`) rather
/// than the `root` beneath it so a teardown does not leave an empty shell behind.
/// A failure here leaks disk, not isolation, so it is logged rather than fatal —
/// but note what it means for WRITABLE resources: those are hard links, so
/// unlinking them here drops only this jail's reference and the caller's file
/// keeps every byte the guest wrote.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn cleanup_jail(layout: &JailLayout) {
    let pod_dir = layout.jail_root.parent().unwrap_or(&layout.jail_root);
    if let Err(err) = std::fs::remove_dir_all(pod_dir) {
        if err.kind() != std::io::ErrorKind::NotFound {
            tracing::warn!(
                path = %pod_dir.display(),
                error = %err,
                "failed to remove pod jail directory; leaking disk, not isolation"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Jailer lowering (pure seam — see the module note on why this is not gated)
// ---------------------------------------------------------------------------

/// Build the `jailer` argv that launches Firecracker under cgroups, a chroot and
/// a dropped uid/gid.
///
/// WHY THE JAILER AT ALL. Today Firecracker is spawned directly with
/// `--config-file`, which boots the VM IMMEDIATELY, and `apply_cgroup` then runs
/// against the resulting pid. The guest therefore executes for a window before
/// its cpu/memory limits exist. The jailer closes that by construction: it
/// creates the cgroup, writes its own pid into it, sets up the chroot and mount
/// namespace, drops privileges, and only THEN `exec()`s Firecracker. Cgroups
/// cannot be late if they are established before the VMM exists.
///
/// It also buys three things we do not have: a chroot with `pivot_root` into a
/// fresh mount namespace, an unprivileged VMM process, and — because the jailer
/// copies the exec-file into the jail — no shared memory between Firecracker
/// processes.
///
/// THIS FUNCTION IS THE ARGV ONLY, AND THAT IS DELIBERATE. The cutover is a
/// launch-path change for every pod and cannot be exercised without a Linux host
/// running real Firecracker, which is not available where this was written. The
/// argv is the part that is easy to get subtly wrong and easy to test, so it
/// lands first with its invariants pinned; flipping the spawn to use it is a
/// separate, reviewable change that needs an integration test behind it.
///
/// STILL OWED BY THAT CUTOVER, listed so the remaining work is not a surprise:
/// every path in `FirecrackerConfig` is a HOST absolute path — `kernel_image_path`,
/// each drive's `path_on_host`, the vsock `uds_path` — and under a chroot they
/// must be relative to the jail, with the kernel and rootfs hard-linked or
/// bind-mounted in and the vsock socket created inside. `--netns` also replaces
/// the current `ip netns exec` wrapper, so the netns plumbing moves too.
/// Everything the jailer needs, as one value. A struct rather than eight
/// parameters because the ordering of eight strings is exactly the kind of thing
/// a caller gets wrong silently.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct JailerPlan<'a> {
    /// The Firecracker binary the jailer copies into the jail and execs.
    pub firecracker_path: &'a str,
    /// Pod id — becomes the jail directory and the cgroup leaf.
    pub pod_id: &'a str,
    /// Base under which the jailer builds `<base>/<exec>/<id>/root`.
    pub chroot_base: &'a str,
    /// Unprivileged uid the VMM drops to.
    pub uid: u32,
    /// Unprivileged gid the VMM drops to.
    pub gid: u32,
    /// Network namespace path, replacing the `ip netns exec` wrapper.
    pub netns: Option<&'a str>,
    /// Limits applied BEFORE exec — the whole reason for the jailer.
    pub cgroup: Option<&'a nucleus_spec::CgroupSpec>,
    /// Which cgroup hierarchy the host uses. See `detect_cgroup_version`.
    pub cgroup_version: u8,
    /// Config path as seen from INSIDE the jail.
    pub config_file_in_jail: &'a str,
}

/// Which cgroup hierarchy this host presents: `2` for the unified v2 tree, else `1`.
///
/// `/sys/fs/cgroup/cgroup.controllers` exists if and only if the unified v2
/// hierarchy is mounted there — it is the file the kernel documents for exactly
/// this test, and it is cheaper and more direct than parsing `/proc/mounts`.
///
/// Defaults to 2 when the path cannot be read at all. That is the deliberate
/// direction: v2 is the modern default, and being wrong toward v2 fails loudly
/// at launch (the jailer refuses) rather than silently placing a workload in a
/// hierarchy nobody is enforcing.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn detect_cgroup_version() -> u8 {
    if std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return 2;
    }
    // A v1 host has per-controller directories and no unified controllers file.
    if std::path::Path::new("/sys/fs/cgroup/cpu").is_dir() {
        return 1;
    }
    2
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn jailer_args(plan: &JailerPlan<'_>) -> Vec<String> {
    let JailerPlan {
        firecracker_path,
        pod_id,
        chroot_base,
        uid,
        gid,
        netns,
        cgroup,
        cgroup_version,
        config_file_in_jail,
    } = *plan;
    let mut args: Vec<String> = vec![
        "--id".to_string(),
        pod_id.to_string(),
        "--exec-file".to_string(),
        firecracker_path.to_string(),
        "--chroot-base-dir".to_string(),
        chroot_base.to_string(),
        "--uid".to_string(),
        uid.to_string(),
        "--gid".to_string(),
        gid.to_string(),
    ];

    if let Some(ns) = netns {
        args.push("--netns".to_string());
        args.push(ns.to_string());
    }

    // THE JAILER DEFAULTS TO CGROUP V1, AND MODERN LINUX IS V2-ONLY.
    //
    // Found by driving the real jailer (v1.16.1) with this exact argv against a
    // `cgroup2fs` host: it refuses outright with
    //
    //     Error: CgroupHierarchyMissing("No hierarchy found for this cgroup version.")
    //
    // and no VM is launched. `--cgroup-version` is documented as
    // `[default: "1"]`, the unified v2 hierarchy has been the distro default
    // since ~2021, and nothing in the cutover passed this flag — so every pod
    // carrying a cgroup spec would have failed to start on any current host.
    //
    // Emitted only alongside `--cgroup`, because that is the only path the
    // jailer needs a hierarchy for: with no cgroup settings it launches fine on
    // a v2 host regardless (verified the same way).
    if cgroup.is_some() {
        args.push("--cgroup-version".to_string());
        args.push(cgroup_version.to_string());
    }

    // Each setting becomes a `--cgroup file=value`, which the jailer applies
    // BEFORE exec. This is the whole point: the limit exists before the guest.
    if let Some(spec) = cgroup {
        for setting in &spec.settings {
            args.push("--cgroup".to_string());
            args.push(format!("{}={}", setting.file, setting.value));
        }
    }

    // Everything after the separator is Firecracker's own argv.
    args.push("--".to_string());
    args.push("--config-file".to_string());
    args.push(config_file_in_jail.to_string());
    args
}

// ---------------------------------------------------------------------------
// FirecrackerConfig construction
// ---------------------------------------------------------------------------

/// Force `pci=off` onto a guest kernel command line.
///
/// # Why this is a floor rather than a default
///
/// `pci=off` used to live only in the `default_args` literal, which is
/// **discarded wholesale** when a `PodSpec` supplies `image.boot_args`. So any
/// spec with a custom command line silently lost it, while `ipv6.disable=1`
/// three lines below was correctly enforced by appending. The right idiom was
/// already in the file, applied to one hardening flag and not the other.
///
/// It matters because nucleus's PCI posture is the guest half of its defence
/// against the virtio-PCI transport (CVE-2026-5747, escape-class). The host half
/// is that nucleus never passes `--enable-pci`, which
/// `jailer_argv_never_enables_the_pci_transport` pins. Neither half should be
/// reachable from spec input.
///
/// A spec-supplied `pci=` is **stripped**, not honoured and not an error:
/// `from_spec` returns `Self` with no error channel, and silently keeping a
/// weaker value would be the worst of the three options. In nucleus's model no
/// PodSpec has a legitimate reason to want guest PCI — the VMM is not started
/// with the PCI transport at all.
/// Ungated although its only caller is Linux-only, so the logic is compiled and
/// unit-tested on a macOS dev host rather than only in CI.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn enforce_pci_off(args: &str) -> String {
    let mut out: Vec<&str> = args
        .split_whitespace()
        .filter(|tok| !tok.starts_with("pci="))
        .collect();
    out.push("pci=off");
    out.join(" ")
}

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
        task_token: Option<&crate::session_mint::MintedTaskToken>,
        // When jailed, every path emitted below is IN-JAIL, not host.
        jail: Option<&JailLayout>,
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

        // Applied AFTER every branch that can build a command line, so no path
        // — default, spec-supplied, or net-augmented — can reach the guest
        // without it. See `enforce_pci_off`.
        boot_args = boot_args.map(|args| enforce_pci_off(&args));

        // `nucleus.auth_secret` is NO LONGER EMITTED.
        //
        // The kernel command line is world-readable inside the guest
        // (`/proc/cmdline`), so every process there — including the agent the
        // sandbox exists to contain — could read the HMAC key and sign requests
        // as the host. That is a trust boundary drawn inside a single trust
        // domain, and it cannot hold.
        //
        // It is not relocated, it is deleted: the tool-proxy is bound to a vsock
        // listener that accepts only `VMADDR_CID_HOST`, and the guest kernel
        // sets that CID. Origin is now established by something no guest process
        // can forge. Firecracker pods always have vsock (`spawn_firecracker_pod`
        // requires `spec.vsock`), so the HMAC tier is unreachable on this path.
        //
        // `nucleus.approval_secret` REMAINS for now: the approval endpoint is
        // still drand-anchored HMAC, and dropping its key needs a drand-only
        // tier first. Freshness is not origin, so the transport cannot replace
        // it on its own.
        let _ = auth_secret;
        boot_args = match boot_args.take() {
            Some(args) => Some(format!("{args} nucleus.approval_secret={approval_secret}")),
            None => Some(format!("nucleus.approval_secret={approval_secret}")),
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

        // Sandbox proof token — the tool-proxy refuses to start without SOME
        // proof it is running inside a managed sandbox.
        //
        // # Emitted only when the pod will have no SVID
        //
        // This is Tier 3 of `sandbox_proof`: the fallback for a workload with no
        // SPIFFE identity. A pod that gets an identity reaches Tier 1 or Tier 2
        // from its SVID and never consults this token — so emitting it there put
        // a per-pod secret on the world-readable kernel command line to be
        // ignored.
        //
        // `workload_api_port` is exactly the right condition and not a proxy for
        // it: `net::workload_api_port_for` and `net::identity_registration` are
        // the same predicate — identity enabled AND the egress grant granted —
        // stated on the advertising and serving sides. So `Some` here means the
        // pod will be registered and will have an SVID to prove itself with.
        //
        // Deleting it unconditionally would be wrong, and that is why this is a
        // condition rather than a removal: a node with identity management off,
        // or a pod whose grant was denied, has Tier 3 as its ONLY proof, and the
        // tool-proxy exits fatally when no tier succeeds.
        //
        // # This deadlocked every launch once, and what changed
        //
        // The condition shipped while `spawn_firecracker_pod` started the
        // workload API bridge AFTER `wait_for_proxy_health`. An identity-bearing
        // pod then had no proof at the only moment that mattered: the SVID
        // source did not exist yet, Tier 3 was gone, the guest exited as PID 1,
        // and every launch failed with "proxy health check timed out". Observed
        // on real hardware and invisible to every unit test, because the
        // omission is correct in isolation and wrong only in composition with
        // that ordering.
        //
        // The bridge now starts BEFORE the health check, which is what makes
        // this safe — not any improvement in the reasoning above.
        // `the_workload_api_bridge_starts_before_the_health_check` pins that
        // precondition, so if the bridge moves back this fails rather than
        // deadlocking a fleet.
        if workload_api_port.is_none() {
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

        // Inject the live-path session capability token via the kernel cmdline,
        // for nucleus-guest-init to forward to the in-VM tool-proxy as
        // NUCLEUS_TASK_TOKEN{,_NONCE,_ISSUER}.
        //
        // The token JSON is **hex-encoded** here (`nucleus.task_token_hex`)
        // because the kernel cmdline is whitespace-delimited and quote-sensitive;
        // raw JSON (braces/quotes) is unsafe to embed. guest-init hex-decodes it
        // back to the exact JSON the tool-proxy verify half expects. Nonce and
        // issuer are already hex. This is a scoped capability + PUBLIC issuer key
        // — NOT a secret — so riding the world-readable cmdline (M-4 caveat,
        // same channel as nucleus.auth_secret) is acceptable; the anti-replay /
        // anti-truncation defense rests on the host-pinned nonce, not secrecy.
        if let Some(tok) = task_token {
            let token_hex = hex::encode(tok.token_json.as_bytes());
            boot_args = match boot_args.take() {
                Some(args) => Some(format!(
                    "{args} nucleus.task_token_hex={token_hex} \
                     nucleus.task_token_nonce={} nucleus.task_token_issuer={}",
                    tok.nonce_hex, tok.issuer_hex
                )),
                None => Some(format!(
                    "nucleus.task_token_hex={token_hex} \
                     nucleus.task_token_nonce={} nucleus.task_token_issuer={}",
                    tok.nonce_hex, tok.issuer_hex
                )),
            };
        }

        // Pure lowering seams (property-tested in `mod tests`): the money/boot
        // path uses the exact same functions the invariant tests assert over.
        // Under the jailer every path below is resolved AFTER chroot, so it must
        // be the in-jail name; unjailed it stays the host path it always was.
        let jailed = jail.is_some();
        let vsock_for_config = if jailed {
            in_jail::VSOCK.to_string()
        } else {
            vsock_path.display().to_string()
        };
        let vsock = lower_vsock(spec, &vsock_for_config);
        let network_interfaces = lower_network_interfaces(net_plan);

        Self {
            boot_source: BootSource {
                kernel_image_path: if jailed {
                    in_jail::KERNEL.to_string()
                } else {
                    image.kernel_path.display().to_string()
                },
                boot_args,
            },
            drives: lower_drives(image, jailed),
            machine_config: MachineConfig {
                vcpu_count,
                mem_size_mib,
                smt: false,
            },
            network_interfaces,
            vsock,
            logger: Some(LoggerConfig {
                log_path: if jailed {
                    in_jail::LOG.to_string()
                } else {
                    log_path.display().to_string()
                },
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
/// ISOLATION INVARIANT: under the jailer, `path_on_host` is a path in the JAIL.
/// Firecracker resolves it after `chroot`, so a host path here would simply not
/// exist for it — and the kernel/rootfs are hard-linked in under these names.
fn lower_drives(image: &nucleus_spec::ImageSpec, jailed: bool) -> Vec<DriveConfig> {
    let mut drives = vec![DriveConfig {
        drive_id: "rootfs".to_string(),
        path_on_host: if jailed {
            in_jail::ROOTFS.to_string()
        } else {
            image.rootfs_path.display().to_string()
        },
        is_root_device: true,
        is_read_only: image.read_only,
    }];

    if let Some(ref scratch) = image.scratch_path {
        drives.push(DriveConfig {
            drive_id: "scratch".to_string(),
            path_on_host: if jailed {
                in_jail::SCRATCH.to_string()
            } else {
                scratch.display().to_string()
            },
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
fn seccomp_args(spec: &PodSpec, jailed: bool) -> Vec<std::ffi::OsString> {
    use std::ffi::OsString;
    match spec.spec.seccomp.as_ref() {
        None | Some(nucleus_spec::SeccompSpec::Default) => Vec::new(),
        Some(nucleus_spec::SeccompSpec::Disabled) => vec![OsString::from("--no-seccomp")],
        Some(nucleus_spec::SeccompSpec::Custom { filter_path }) => vec![
            OsString::from("--seccomp-filter"),
            // Under the jailer Firecracker opens this after `chroot`, so the host
            // path would simply not resolve. `jail_resources` puts the BPF file at
            // this name inside the jail.
            if jailed {
                OsString::from(in_jail::SECCOMP)
            } else {
                filter_path.clone().into_os_string()
            },
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

// FAIL-CLOSED, corrected 2026-07-26. This returned `Ok(())` — "seccomp is
// Linux-only; skip verification on other platforms" — which made a VERIFIER
// report success on a platform where it cannot verify anything.
//
// That silently defeated its own caller. main.rs kills the process and aborts
// the launch when seccomp cannot be confirmed, and its comment says so
// explicitly: "The previous behavior only logged a warning and continued
// (fail-open)." The cfg stub reintroduced precisely that, for any non-Linux
// build, one layer down.
//
// THE RULE, worth stating because it generalises: an ENFORCER may refuse when it
// cannot act, but a VERIFIER may never SUCCEED when it cannot check. "I was
// unable to look" and "I looked and it was fine" are different answers, and only
// one of them is safe to return from a function whose caller kills a process on
// Err.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub(crate) fn verify_seccomp_active(_pid: u32) -> Result<(), String> {
    Err("seccomp verification requires Linux; cannot confirm a filter is active".to_string())
}

/// Wait, bounded, for the filter to become active — then fail closed.
///
/// WHY A POLL AND NOT A SINGLE READ. `verify_seccomp_active` is a snapshot, and a
/// freshly spawned pid has not installed its filter yet: Firecracker applies its
/// own BPF during startup, after `exec`. Reading `/proc/<pid>/status` immediately
/// therefore observes mode 0 and, under a fail-closed caller, aborts a launch that
/// was about to be perfectly confined.
///
/// The jailer makes this decisive rather than merely likely. Without it the pid is
/// Firecracker from the first instant; with it the pid is the JAILER, which builds
/// the cgroup, chroots, drops privileges and only then `exec()`s — and holds mode 0
/// for all of that. A single read against a jailed launch is close to guaranteed to
/// see 0, which would mean no pod ever starts.
///
/// FAIL-CLOSED IS PRESERVED, and that is the point of the bound: this returns Err
/// if the deadline passes without mode >= 2. Waiting longer is not the same as
/// deciding it is fine — see the rule in `check-failclosed-verifiers.sh`. A
/// verifier may never SUCCEED when it cannot check; it may take a moment to look.
#[cfg(target_os = "linux")]
#[tracing::instrument(skip_all, fields(boot.stage = "seccomp.wait"))]
pub(crate) async fn verify_seccomp_active_within(
    pid: u32,
    timeout: std::time::Duration,
) -> Result<(), String> {
    const POLL: std::time::Duration = std::time::Duration::from_millis(20);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match verify_seccomp_active(pid) {
            Ok(()) => return Ok(()),
            Err(err) => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "{err} (waited {}ms for the filter to become active)",
                        timeout.as_millis()
                    ));
                }
            }
        }
        tokio::time::sleep(POLL).await;
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn apply_seccomp_flags(
    command: &mut Command,
    spec: &PodSpec,
    jailed: bool,
) -> Result<(), ApiError> {
    // Delegate to the pure `seccomp_args` seam so the launched command carries
    // exactly the flags the invariant tests assert over.
    for arg in seccomp_args(spec, jailed) {
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

    /// Build a cmdline for a pod that either will or will not receive an SVID.
    ///
    /// Linux-gated because `from_spec` is: the cmdline builder only compiles on
    /// the platform that can run a microVM. These therefore run in CI and in
    /// OrbStack, never on a macOS dev machine — the same trap that once hid the
    /// vsock accept path behind a `cfg` nobody compiled.
    #[cfg(target_os = "linux")]
    fn boot_args_with_identity(will_have_identity: bool) -> String {
        let config = FirecrackerConfig::from_spec(
            &base_spec(),
            std::path::Path::new("/unused/firecracker.log"),
            std::path::Path::new("/unused/vsock.sock"),
            &image(true, false),
            None,
            "auth-secret",
            "approval-secret",
            will_have_identity.then_some(15012),
            None,
            None,
        );
        config.boot_source.boot_args.unwrap_or_default()
    }

    /// **A pod that will hold an SVID gets no Tier 3 token.**
    ///
    /// `sandbox_token` is the fallback proof for a workload with no SPIFFE
    /// identity. A pod that gets one proves itself from the SVID and never reads
    /// the token — so emitting it there put a per-pod secret on the
    /// world-readable kernel command line to be ignored.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_identity_bearing_pod_carries_no_sandbox_token() {
        let args = boot_args_with_identity(true);
        assert!(
            !args.contains("nucleus.sandbox_token"),
            "a pod with a workload identity reaches Tier 1/2 from its SVID and does \
             not need the Tier 3 token: {args}"
        );
    }

    /// **The precondition that makes the omission above safe**, pinned against
    /// the source rather than trusted.
    ///
    /// The first attempt at that omission deadlocked every launch: the guest's
    /// SVID source started after the health check that needed it, so an
    /// identity-bearing pod had no proof at all. Nothing caught it, because each
    /// half is correct alone.
    ///
    /// Not gated on Linux: the ordering is a property of the source text, and
    /// gating it would mean the guard does not run on the machine where the
    /// change is usually made.
    #[test]
    fn the_workload_api_bridge_starts_before_the_health_check() {
        let src = include_str!("main.rs");
        let bridge = src
            .find("WorkloadApiVsockBridge::start")
            .expect("the bridge start site");
        let health = src
            .find("wait_for_proxy_health(health_addr)")
            .expect("the health check site");
        assert!(
            bridge < health,
            "the workload API bridge must start BEFORE the proxy health check — the guest \
             needs its SVID in order to become healthy, so producing it afterwards is the \
             wrong order. An identity-bearing pod has no Tier 3 fallback, so this ordering \
             is the only thing letting it prove itself at all."
        );
    }

    /// **Non-vacuity, and the reason this is a condition rather than a removal.**
    ///
    /// A node with identity management off, or a pod whose egress grant was
    /// denied, has Tier 3 as its ONLY proof — and `sandbox_proof` exits fatally
    /// when no tier succeeds. Deleting the token outright would turn those pods
    /// from working into dead.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_pod_without_an_identity_keeps_its_only_proof() {
        let args = boot_args_with_identity(false);
        assert!(
            args.contains("nucleus.sandbox_token="),
            "a pod with no SVID has Tier 3 as its only sandbox proof and must keep it: {args}"
        );
    }

    /// The condition must track the identity predicate rather than merely
    /// correlating with it: `workload_api_port_for` and `identity_registration`
    /// are the same rule stated on the advertising and serving sides, so the
    /// port being present is exactly "this pod will be registered".
    #[cfg(target_os = "linux")]
    #[test]
    fn the_token_condition_matches_the_identity_predicate() {
        for (enabled, granted) in [(true, true), (true, false), (false, true), (false, false)] {
            let grant = if granted {
                net::IdentityGrant::Granted
            } else {
                net::IdentityGrant::Denied {
                    offending: "0.0.0.0/0".to_string(),
                }
            };
            let port = net::workload_api_port_for(enabled, &grant, 15012);
            let args = boot_args_with_identity(port.is_some());
            assert_eq!(
                args.contains("nucleus.sandbox_token="),
                port.is_none(),
                "identity_enabled={enabled} granted={granted}: the Tier 3 token must be \
                 present exactly when the pod will have no SVID"
            );
        }
    }

    // ----- Invariant (1): read-only rootfs ---------------------------------

    proptest! {
        #[test]
        fn readonly_policy_lowers_to_readonly_rootfs(ro in any::<bool>(), scratch in any::<bool>()) {
            let drives = lower_drives(&image(ro, scratch), false);

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
        assert!(seccomp_args(&spec, false).is_empty());
        // Explicit Default => same.
        spec.spec.seccomp = Some(SeccompSpec::Default);
        assert!(seccomp_args(&spec, false).is_empty());
    }

    #[test]
    fn seccomp_disabled_emits_no_seccomp_flag() {
        let mut spec = base_spec();
        spec.spec.seccomp = Some(SeccompSpec::Disabled);
        assert_eq!(
            seccomp_args(&spec, false),
            vec![OsString::from("--no-seccomp")]
        );
    }

    #[test]
    fn seccomp_custom_pins_filter_path() {
        let mut spec = base_spec();
        spec.spec.seccomp = Some(SeccompSpec::Custom {
            filter_path: PathBuf::from("/etc/nucleus/seccomp.bpf"),
        });
        assert_eq!(
            seccomp_args(&spec, false),
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
            let has_disable = seccomp_args(&spec, false)
                .iter()
                .any(|a| a.to_string_lossy() == "--no-seccomp");
            // The invariant: `--no-seccomp` appears IFF the policy is explicitly
            // Disabled. A bug that disabled seccomp for a Default policy would
            // FAIL here.
            prop_assert_eq!(has_disable, disable);
        }
    }

    // ── the fail-closed verifier rule ───────────────────────────────────────
    //
    // Runs only off Linux, which is exactly where the bug lived: on Linux the
    // real implementation reads /proc and this stub does not exist. A dev
    // machine is where a vacuously-successful verifier would have been trusted.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn seccomp_verifier_fails_closed_when_it_cannot_verify() {
        let r = super::verify_seccomp_active(1);
        assert!(
            r.is_err(),
            "a verifier that cannot check must not report success — its caller \
             kills the process on Err and continues on Ok"
        );
    }

    // ── THE GUEST-VISIBLE DEVICE SURFACE ────────────────────────────────────
    //
    // Firecracker deliberately emulates only five devices — virtio-net,
    // virtio-block, virtio-vsock, a serial console and a minimal keyboard
    // controller — on the principle that every feature not implemented is
    // attack surface that does not exist. This test pins which of them WE
    // attach, because that is the guest-to-host boundary of a nucleus pod.
    //
    // Nothing asserted it before. Firecracker's 2026 releases added developer-
    // preview hotplug for PCI virtio block/pmem/net devices; a future config
    // field enabling any of those would widen the guest's reach into the host
    // and, without this test, would land as an ordinary struct change.
    //
    // Pinned on the SERIALIZED form — that is what Firecracker actually
    // consumes — so a field renamed or newly serialized is caught, and a field
    // that exists in Rust but is never serialized correctly is not counted.
    // ── Jail path arithmetic ─────────────────────────────────────────────────

    #[test]
    fn jail_layout_matches_the_jailers_own_convention() {
        let l = JailLayout::new(
            std::path::Path::new("/srv/jail"),
            std::path::Path::new("/usr/bin/firecracker"),
            "pod-1",
        );
        // The jailer builds <chroot_base>/<exec_file_name>/<id>/root. Getting
        // this wrong means hard-linking the kernel somewhere the jailed VMM
        // cannot see, and the failure would look like a boot problem.
        assert_eq!(
            l.jail_root,
            std::path::Path::new("/srv/jail/firecracker/pod-1/root")
        );
    }

    /// `place_resource` must produce a LINK, not a copy, for writable resources —
    /// asserted on the inode, because a copy is indistinguishable from a link by
    /// content and that is exactly what makes the bug silent.
    ///
    /// Linux-only because `place_resource` is; that is not a coverage gap, it is
    /// where the code runs. The current uid/gid are read off a file this test just
    /// created rather than hardcoded, so it passes as root in a container and as an
    /// unprivileged user in CI.
    #[cfg(target_os = "linux")]
    #[test]
    fn placing_a_writable_resource_links_rather_than_copies() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path();
        let src = dir.join("scratch.ext4");
        std::fs::write(&src, b"guest writes land here").expect("write source");
        let dest = dir.join("in-jail-scratch");

        let resource = JailResource {
            host_source: src.clone(),
            in_jail: in_jail::SCRATCH,
            placement: Placement::HardLinkOnly,
        };
        place_resource(&resource, &dest).expect("same-filesystem hard link must succeed");

        let src_ino = std::fs::metadata(&src).expect("src meta").ino();
        let dest_ino = std::fs::metadata(&dest).expect("dest meta").ino();
        assert_eq!(
            src_ino,
            dest_ino,
            "writable resource was COPIED into the jail (distinct inodes), so the \
             guest's writes would never reach {}",
            src.display()
        );

        // A relaunch under the same pod id must not trip over the previous link.
        place_resource(&resource, &dest).expect("re-placing over a stale link must succeed");
        assert_eq!(std::fs::metadata(&dest).expect("dest meta").ino(), src_ino);
    }

    /// When a writable resource cannot be linked, the launch FAILS and the message
    /// says why it is not silently copying instead. The distinction between the two
    /// placements is only worth having if the strict side actually refuses.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unlinkable_writable_resource_refuses_rather_than_copying() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path();
        let dest = dir.join("dest");

        let writable = JailResource {
            host_source: dir.join("does-not-exist.ext4"),
            in_jail: in_jail::SCRATCH,
            placement: Placement::HardLinkOnly,
        };
        let err = place_resource(&writable, &dest)
            .expect_err("an unlinkable WRITABLE resource must fail the launch");
        assert!(
            err.contains("WRITABLE") && err.contains("discard"),
            "the error must explain why a copy is not an acceptable fallback: {err}"
        );
        assert!(
            !dest.exists(),
            "nothing may be left at the destination after a refused placement"
        );

        // The read-only side is allowed to fall back — but only to something that
        // actually works, so an absent source still fails, naming both attempts.
        let readable = JailResource {
            placement: Placement::CopyableIfCrossDevice,
            ..writable.clone()
        };
        let err = place_resource(&readable, &dest).expect_err("absent source cannot be placed");
        assert!(
            err.contains("hard link failed") && err.contains("copy failed"),
            "a failed fallback must report both attempts: {err}"
        );
    }

    /// End-to-end on the real filesystem: after `prepare_jail`, every path the
    /// jailed config names exists inside the jail.
    ///
    /// This is the check that the cutover's two halves agree. `from_spec` decides
    /// what names the VMM will open; `prepare_jail` decides what exists. Nothing
    /// else relates them, and if they diverge the VMM fails to open its own kernel.
    #[cfg(target_os = "linux")]
    #[test]
    fn prepare_jail_creates_every_path_the_jailed_config_names() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().expect("temp dir");
        let base = tmp.path();
        let src = base.join("images");
        std::fs::create_dir_all(&src).expect("image dir");
        for name in ["vmlinux", "rootfs.ext4", "scratch.ext4", "filter.bpf"] {
            std::fs::write(src.join(name), b"x").expect("write image");
        }
        // Own uid/gid, read off a file we just made: chowning to ourselves is always
        // permitted, so this works unprivileged in CI and as root in a container.
        let meta = std::fs::metadata(src.join("vmlinux")).expect("meta");
        let (uid, gid) = (meta.uid(), meta.gid());

        let img = nucleus_spec::ImageSpec {
            kernel_path: src.join("vmlinux"),
            rootfs_path: src.join("rootfs.ext4"),
            boot_args: None,
            read_only: false,
            scratch_path: Some(src.join("scratch.ext4")),
        };
        let mut spec = base_spec();
        spec.spec.vsock = Some(VsockSpec {
            guest_cid: 3,
            port: 1024,
        });
        spec.spec.seccomp = Some(SeccompSpec::Custom {
            filter_path: src.join("filter.bpf"),
        });

        let layout = JailLayout::new(
            &base.join("jail"),
            Path::new("/usr/bin/firecracker"),
            "pod-e2e",
        );
        let config = FirecrackerConfig::from_spec(
            &spec,
            Path::new("/unused/host/firecracker.log"),
            Path::new("/unused/host/vsock.sock"),
            &img,
            None,
            "auth",
            "approval",
            None,
            None,
            Some(&layout),
        );
        let config_json = serde_json::to_vec_pretty(&config).expect("serialize");

        prepare_jail(&layout, &img, &spec, &config_json, uid, gid).expect("prepare_jail");

        // Every path the config names, except the vsock socket, which Firecracker
        // creates itself at boot — so what must exist for it is the writable jail
        // root it gets created in.
        let mut named = vec![config.boot_source.kernel_image_path.clone()];
        named.extend(config.drives.iter().map(|d| d.path_on_host.clone()));
        named.push(config.logger.as_ref().expect("logger").log_path.clone());
        named.push(in_jail::CONFIG.to_string());
        for arg in seccomp_args(&spec, true) {
            let arg = arg.to_string_lossy().to_string();
            if arg.starts_with('/') {
                named.push(arg);
            }
        }

        for name in named {
            let host = layout.host_path(&name);
            assert!(
                host.exists(),
                "the jailed config names {name}, which prepare_jail did not create at \
                 {} — after chroot the VMM would find nothing there",
                host.display()
            );
        }
        assert!(
            layout.jail_root.is_dir(),
            "the jail root must exist and be a directory for Firecracker to create \
             its vsock socket in"
        );

        // Re-running must be idempotent: pods get relaunched.
        prepare_jail(&layout, &img, &spec, &config_json, uid, gid)
            .expect("prepare_jail must be idempotent");

        cleanup_jail(&layout);
        assert!(
            !layout.jail_root.exists(),
            "cleanup_jail must remove the jail"
        );
        // Cleanup unlinks hard links, so the caller's writable image survives.
        assert!(
            img.rootfs_path.exists(),
            "teardown must not destroy the caller's rootfs — those are hard links, \
             and the guest's writes live at the source path"
        );
    }

    /// A bounded WAIT must not become a bounded SUCCESS.
    ///
    /// `verify_seccomp_active_within` was added because the jailer holds the pid
    /// through its whole pre-exec sequence, so a single read sees mode 0 and would
    /// abort every jailed launch. The risk in that fix is obvious and worth pinning:
    /// the easy way to stop a verifier from failing is to stop it from checking. A
    /// pid that will never have a filter must still end in Err.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn waiting_for_seccomp_still_fails_closed() {
        // A pid that cannot be verified: /proc/<pid>/status will not be readable.
        // u32::MAX is above any pid_max, so this never races a real process.
        let err = verify_seccomp_active_within(u32::MAX, std::time::Duration::from_millis(60))
            .await
            .expect_err(
                "a pid whose seccomp filter can never be confirmed must FAIL, not be \
                 waited into success",
            );
        assert!(
            err.contains("waited"),
            "the error should say it gave the filter time to appear: {err}"
        );
    }

    /// ISOLATION/DATA INVARIANT: a drive the guest can WRITE is hard-link-only.
    ///
    /// This test exists because the two facts it relates live in different
    /// functions and nothing but this pins them together: `lower_drives` decides
    /// `is_read_only`, and `jail_resources` decides whether a cross-device jail
    /// may fall back to `fs::copy`. If they drift so that a writable drive
    /// becomes copyable, every pod still boots and every guest write is thrown
    /// away at teardown — a silent data-loss bug wearing a green build.
    #[test]
    fn a_drive_the_guest_can_write_is_never_copyable() {
        for (read_only, scratch) in [(true, true), (true, false), (false, true), (false, false)] {
            let img = image(read_only, scratch);
            let spec = base_spec();
            let resources = jail_resources(&img, &spec);
            let drives = lower_drives(&img, true);

            for drive in &drives {
                if drive.is_read_only {
                    continue;
                }
                let placed = resources
                    .iter()
                    .find(|r| r.in_jail == drive.path_on_host)
                    .unwrap_or_else(|| {
                        panic!(
                            "writable drive {} is in the config but nothing brings it \
                             into the jail — Firecracker would open a path that does \
                             not exist after chroot",
                            drive.path_on_host
                        )
                    });
                assert_eq!(
                    placed.placement,
                    Placement::HardLinkOnly,
                    "drive {} is writable (is_read_only=false) but may be COPIED into \
                     the jail; the guest's writes would not reach {}",
                    drive.path_on_host,
                    placed.host_source.display()
                );
            }
        }
    }

    /// Every path a jailed Firecracker opens is either produced by `prepare_jail`
    /// or listed in `jail_resources`. Nothing may be left as a host path.
    ///
    /// The failure this catches is the cutover's central risk: the config is built
    /// from host absolute paths, and any one of them left unconverted resolves to
    /// nothing after `chroot`.
    ///
    /// Linux-gated because it exercises `from_spec`, which is. The PURE half of the
    /// same invariant — that a writable drive is never merely copied — is checked
    /// on every host by `a_drive_the_guest_can_write_is_never_copyable`.
    #[cfg(target_os = "linux")]
    #[test]
    fn every_jailed_config_path_is_brought_into_the_jail() {
        let img = image(false, true);
        let mut spec = base_spec();
        spec.spec.vsock = Some(VsockSpec {
            guest_cid: 7,
            port: 1024,
        });
        spec.spec.seccomp = Some(SeccompSpec::Custom {
            filter_path: PathBuf::from("/etc/nucleus/filter.bpf"),
        });

        let config = FirecrackerConfig::from_spec(
            &spec,
            Path::new("/host/pod/firecracker.log"),
            Path::new("/host/pod/vsock.sock"),
            &img,
            None,
            "auth",
            "approval",
            None,
            None,
            Some(&JailLayout::new(
                Path::new("/srv/jail"),
                Path::new("/usr/bin/firecracker"),
                "pod-x",
            )),
        );

        let resources = jail_resources(&img, &spec);
        // Produced inside the jail rather than relocated into it.
        let produced = [in_jail::CONFIG, in_jail::LOG, in_jail::VSOCK];
        let mut known: Vec<&str> = resources.iter().map(|r| r.in_jail).collect();
        known.extend_from_slice(&produced);

        let mut config_paths = vec![config.boot_source.kernel_image_path.clone()];
        config_paths.extend(config.drives.iter().map(|d| d.path_on_host.clone()));
        if let Some(ref v) = config.vsock {
            config_paths.push(v.uds_path.clone());
        }
        if let Some(ref l) = config.logger {
            config_paths.push(l.log_path.clone());
        }
        for arg in seccomp_args(&spec, true) {
            let arg = arg.to_string_lossy().to_string();
            if arg.starts_with('/') {
                config_paths.push(arg);
            }
        }

        for path in config_paths {
            assert!(
                known.contains(&path.as_str()),
                "jailed config references {path}, which nothing puts inside the jail. \
                 After chroot that path does not exist. Known: {known:?}"
            );
            assert!(
                !path.contains("/host/"),
                "jailed config leaked a HOST path: {path}"
            );
        }
    }

    #[test]
    fn host_path_never_escapes_the_jail_root() {
        let l = JailLayout::new(
            std::path::Path::new("/srv/jail"),
            std::path::Path::new("/usr/bin/firecracker"),
            "pod-1",
        );
        // `in_jail::*` names are absolute-IN-JAIL. `PathBuf::join` with an
        // absolute argument REPLACES the whole path, so a naive join would
        // return /kernel on the host — writing the kernel outside the jail and
        // pointing a jailed VMM at a path it cannot read. Every mapping must
        // stay under jail_root.
        for name in [
            in_jail::KERNEL,
            in_jail::ROOTFS,
            in_jail::SCRATCH,
            in_jail::VSOCK,
            in_jail::LOG,
            in_jail::CONFIG,
            in_jail::SECCOMP,
        ] {
            let host = l.host_path(name);
            assert!(
                host.starts_with(&l.jail_root),
                "{name} mapped to {host:?}, which is outside {:?}",
                l.jail_root
            );
        }
        assert_eq!(
            l.host_path(in_jail::KERNEL),
            std::path::Path::new("/srv/jail/firecracker/pod-1/root/kernel")
        );
    }

    // ── Jailer argv invariants ───────────────────────────────────────────────
    //
    // The reason the jailer is worth adopting is an ORDERING property: cgroups
    // are established before the VMM exists, so the guest cannot run unlimited.
    // These pin the argv that delivers it.

    fn sample_cgroup() -> nucleus_spec::CgroupSpec {
        nucleus_spec::CgroupSpec {
            path: std::path::PathBuf::from("/sys/fs/cgroup/nucleus/pod-1"),
            settings: vec![
                nucleus_spec::CgroupSetting {
                    file: "cpu.max".to_string(),
                    value: "50000 100000".to_string(),
                },
                nucleus_spec::CgroupSetting {
                    file: "memory.max".to_string(),
                    value: "268435456".to_string(),
                },
            ],
        }
    }

    /// THE FLAG THAT WAS MISSING, and what it cost.
    ///
    /// The jailer's `--cgroup-version` is documented `[default: "1"]`, and the
    /// unified v2 hierarchy has been the Linux default since ~2021. The cutover
    /// never passed it. Driving the REAL jailer (v1.16.1) with the argv this
    /// function emits, against a `cgroup2fs` host, produced:
    ///
    ///     Error: CgroupHierarchyMissing("No hierarchy found for this cgroup version.")
    ///
    /// and no VM launched. Every pod carrying a cgroup spec would have failed to
    /// start on any current host — the exact "untested launch path" risk the
    /// cutover was shipped with. Adding `--cgroup-version 2` made the same run
    /// succeed, with the pod cgroup created and populated before exec.
    #[test]
    fn the_cgroup_version_is_declared_whenever_cgroups_are_requested() {
        let spec: nucleus_spec::CgroupSpec = serde_json::from_str(
            r#"{"path":"/sys/fs/cgroup/nucleus","settings":[{"file":"cpu.weight","value":"42"}]}"#,
        )
        .expect("cgroup spec");
        let args = jailer_args(&JailerPlan {
            firecracker_path: "/usr/bin/firecracker",
            pod_id: "pod-1",
            chroot_base: "/srv/jailer",
            uid: 123,
            gid: 100,
            netns: None,
            cgroup: Some(&spec),
            cgroup_version: 2,
            config_file_in_jail: "/config.json",
        });
        let vpos = args.iter().position(|a| a == "--cgroup-version").expect(
            "a cgroup request must declare the hierarchy version; the \
                     jailer defaults to v1 and refuses on a v2 host",
        );
        assert_eq!(args[vpos + 1], "2");
        let cpos = args.iter().position(|a| a == "--cgroup").expect("--cgroup");
        assert!(
            vpos < cpos,
            "the version must be declared before the settings it applies to"
        );
        let sep = args.iter().position(|a| a == "--").expect("separator");
        assert!(cpos < sep, "cgroup args belong to the JAILER, before `--`");
    }

    /// With no cgroup spec there is no hierarchy to find, and the jailer launches
    /// on a v2 host without the flag — verified against the real binary. So the
    /// flag is emitted only where it is needed, and its absence here is a
    /// decision rather than an oversight.
    #[test]
    fn no_cgroup_request_means_no_version_flag() {
        let args = jailer_args(&JailerPlan {
            firecracker_path: "/usr/bin/firecracker",
            pod_id: "pod-1",
            chroot_base: "/srv/jailer",
            uid: 123,
            gid: 100,
            netns: None,
            cgroup: None,
            cgroup_version: 2,
            config_file_in_jail: "/config.json",
        });
        assert!(!args.iter().any(|a| a == "--cgroup-version"));
    }

    #[test]
    fn jailer_applies_every_cgroup_limit_before_exec() {
        let cg = sample_cgroup();
        let args = jailer_args(&JailerPlan {
            firecracker_path: "/usr/bin/firecracker",
            pod_id: "pod-1",
            chroot_base: "/srv/jail",
            uid: 1000,
            gid: 1000,
            netns: Some("/var/run/netns/ns-pod-1"),
            cgroup: Some(&cg),
            cgroup_version: 2,
            config_file_in_jail: "/config.json",
        });

        // Every declared limit reaches the jailer as a --cgroup pair.
        for setting in &cg.settings {
            let expected = format!("{}={}", setting.file, setting.value);
            assert!(
                args.contains(&expected),
                "cgroup limit {expected} missing from jailer argv: {args:?}"
            );
        }

        // And every --cgroup appears BEFORE the `--` separator, which is what
        // makes it apply prior to exec rather than after boot.
        let sep = args
            .iter()
            .position(|a| a == "--")
            .expect("separator present");
        for (i, a) in args.iter().enumerate() {
            if a == "--cgroup" {
                assert!(i < sep, "a --cgroup landed after the separator: {args:?}");
            }
        }
    }

    #[test]
    fn jailer_drops_privileges_and_passes_the_netns() {
        let args = jailer_args(&JailerPlan {
            firecracker_path: "/usr/bin/firecracker",
            pod_id: "pod-1",
            chroot_base: "/srv/jail",
            uid: 1000,
            gid: 1000,
            netns: Some("/var/run/netns/ns-pod-1"),
            cgroup: None,
            cgroup_version: 2,
            config_file_in_jail: "/config.json",
        });
        let pair = |flag: &str| -> Option<String> {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1).cloned())
        };
        assert_eq!(pair("--exec-file").as_deref(), Some("/usr/bin/firecracker"));
        assert_eq!(pair("--id").as_deref(), Some("pod-1"));
        assert_eq!(pair("--netns").as_deref(), Some("/var/run/netns/ns-pod-1"));

        // A jailed VMM must not run as root. Asserted rather than assumed: the
        // privilege drop is one of the three things the jailer buys us.
        assert_eq!(pair("--uid").as_deref(), Some("1000"));
        assert_eq!(pair("--gid").as_deref(), Some("1000"));
        assert_ne!(
            pair("--uid").as_deref(),
            Some("0"),
            "the VMM must not run as root"
        );
    }

    #[test]
    fn firecracker_argv_stays_behind_the_separator() {
        let args = jailer_args(&JailerPlan {
            firecracker_path: "/usr/bin/firecracker",
            pod_id: "pod-1",
            chroot_base: "/srv/jail",
            uid: 1000,
            gid: 1000,
            netns: None,
            cgroup: Some(&sample_cgroup()),
            cgroup_version: 2,
            config_file_in_jail: "/config.json",
        });
        let sep = args
            .iter()
            .position(|a| a == "--")
            .expect("separator present");
        // The config file is Firecracker's argument, not the jailer's — passing
        // it before the separator would make the jailer reject it.
        let cfg = args
            .iter()
            .position(|a| a == "--config-file")
            .expect("config-file present");
        assert!(
            cfg > sep,
            "--config-file must follow the separator: {args:?}"
        );
    }

    #[test]
    fn firecracker_device_surface_is_exactly_pinned() {
        // A maximal pod: every optional device present, so nothing is missed by
        // being skip_serializing_if'd away.
        let cfg = FirecrackerConfig {
            boot_source: BootSource {
                kernel_image_path: "/k".to_string(),
                boot_args: Some("console=ttyS0".to_string()),
            },
            drives: vec![DriveConfig {
                drive_id: "rootfs".to_string(),
                path_on_host: "/rootfs.ext4".to_string(),
                is_root_device: true,
                is_read_only: true,
            }],
            machine_config: MachineConfig {
                vcpu_count: 1,
                mem_size_mib: 128,
                smt: false,
            },
            network_interfaces: vec![NetworkInterface {
                iface_id: "eth0".to_string(),
                host_dev_name: "tap0".to_string(),
                guest_mac: "AA:BB:CC:DD:EE:01".to_string(),
            }],
            vsock: Some(VsockConfig {
                guest_cid: 3,
                uds_path: "/v.sock".to_string(),
            }),
            logger: Some(LoggerConfig {
                log_path: "/log".to_string(),
                level: "Info".to_string(),
                show_level: false,
                show_log_origin: false,
            }),
        };

        let value = serde_json::to_value(&cfg).expect("serialize");
        let got: std::collections::BTreeSet<String> = value
            .as_object()
            .expect("config is a JSON object")
            .keys()
            .cloned()
            .collect();
        let want: std::collections::BTreeSet<String> = [
            "boot-source",
            "drives",
            "logger",
            "machine-config",
            "network-interfaces",
            "vsock",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        assert_eq!(
            got, want,
            "the guest-visible device surface changed — a device class was \
             added to or removed from what Firecracker is told to attach"
        );
    }

    // ── PCI posture: both halves of the CVE-2026-5747 defence ─────────────

    /// THE HOST HALF. Firecracker's virtio-PCI transport is opt-in via
    /// `--enable-pci`; the default MMIO transport is unaffected by
    /// CVE-2026-5747 (OOB write, CVSS v4 8.7, guest root -> potential host code
    /// execution). Nucleus has never passed the flag, so the vulnerable code was
    /// unreachable — but that was an unstated accident, and nothing would have
    /// noticed it changing.
    #[test]
    fn jailer_argv_never_enables_the_pci_transport() {
        let spec: nucleus_spec::CgroupSpec = serde_json::from_str(
            r#"{"path":"/sys/fs/cgroup/nucleus","settings":[{"file":"cpu.weight","value":"42"}]}"#,
        )
        .expect("cgroup spec");
        for cgroup in [None, Some(&spec)] {
            for netns in [None, Some("/var/run/netns/pod-1")] {
                let args = jailer_args(&JailerPlan {
                    firecracker_path: "/usr/bin/firecracker",
                    pod_id: "pod-1",
                    chroot_base: "/srv/jailer",
                    uid: 123,
                    gid: 100,
                    netns,
                    cgroup,
                    cgroup_version: 2,
                    config_file_in_jail: in_jail::CONFIG,
                });
                assert!(
                    !args.iter().any(|a| a.contains("enable-pci")),
                    "jailer argv must never enable the virtio-PCI transport: {args:?}"
                );
            }
        }
    }

    /// THE GUEST HALF, and the bug it fixes. `pci=off` used to live only in the
    /// `default_args` literal, which is discarded whenever a PodSpec supplies
    /// `image.boot_args` — so any spec with a custom command line silently lost
    /// the hardening flag. Spec input must not be able to weaken it.
    #[test]
    fn a_spec_supplied_cmdline_cannot_drop_pci_off() {
        // The pre-fix path: a custom cmdline with no mention of pci.
        let hardened = enforce_pci_off("console=ttyS0 reboot=k panic=1 init=/init");
        assert!(
            hardened.split_whitespace().any(|t| t == "pci=off"),
            "a spec-supplied cmdline must still get pci=off: {hardened}"
        );
    }

    /// An explicit weakening is stripped rather than honoured — and the result
    /// names `pci=off` exactly once, so the kernel is not handed two values.
    #[test]
    fn an_explicit_pci_on_is_overridden_not_honoured() {
        let hardened = enforce_pci_off("console=ttyS0 pci=on init=/init");
        assert!(
            !hardened.split_whitespace().any(|t| t == "pci=on"),
            "pci=on must not survive: {hardened}"
        );
        assert_eq!(
            hardened
                .split_whitespace()
                .filter(|t| *t == "pci=off")
                .count(),
            1,
            "exactly one pci= token: {hardened}"
        );
        // Everything else is preserved.
        assert!(hardened.contains("console=ttyS0") && hardened.contains("init=/init"));
    }

    /// Idempotent: applying the floor to an already-hardened cmdline is a no-op,
    /// so the default path does not end up with a duplicate.
    #[test]
    fn enforcing_pci_off_is_idempotent() {
        let once = enforce_pci_off("console=ttyS0 pci=off init=/init");
        assert_eq!(once, enforce_pci_off(&once));
        assert_eq!(
            once.split_whitespace().filter(|t| *t == "pci=off").count(),
            1
        );
    }
}
