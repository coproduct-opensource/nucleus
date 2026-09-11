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

#[cfg(target_os = "linux")]
use crate::ApiError;
use crate::net;

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
    /// The read-only data image. Fixed like the rest, and here the fixity is what makes a base
    /// restorable: Firecracker has no `drive_overrides` on `/snapshot/load`, so a restored VM
    /// reopens its drives at the paths inside the snapshot.
    pub const DATA: &str = "/data.img";
    pub const VSOCK: &str = "/vsock.sock";
    pub const LOG: &str = "/firecracker.log";
    pub const CONFIG: &str = "/config.json";
    pub const SECCOMP: &str = "/seccomp.bpf";
    /// A base snapshot placed for restore. Fixed names like the rest — and here the fixity is
    /// load-bearing rather than tidy, because the vsock path inside a snapshot is fixed too.
    pub const SNAPSHOT_VMSTATE: &str = "/snapshot.vmstate";
    pub const SNAPSHOT_MEM: &str = "/snapshot.mem";
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
            // guest's writes vanish — hence the `rw_rootfs_is_hard_link_only`
            // pin, which until #2784 was named here and never written.
            //
            // The agreement is necessary and NOT sufficient. A hard link means
            // the guest writes through to `image.rootfs_path` itself, so
            // `read_only: false` against the shared installed artifact gives
            // every later pod the previous pod's writes and lets concurrent
            // pods share one writable block device. That is why
            // `ImageSpec::read_only` now defaults to TRUE: the placement below
            // is correct for a private image and unsafe for a shared one, and
            // nothing here can tell which it was handed.
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

    if let Some(ref data) = image.data_path {
        resources.push(JailResource {
            host_source: data.clone(),
            in_jail: in_jail::DATA,
            // COPYABLE, unlike scratch, and the difference is exactly `is_read_only`. The reason
            // scratch must be hard-linked is that a copy would silently discard the guest's
            // writes; a read-only image has no writes to discard, so a cross-device copy is
            // correct — merely slower, and the same trade the kernel and rootfs already make.
            placement: Placement::CopyableIfCrossDevice,
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
    if let Err(err) = std::fs::remove_dir_all(pod_dir)
        && err.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            path = %pod_dir.display(),
            error = %err,
            "failed to remove pod jail directory; leaking disk, not isolation"
        );
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
    pub uid: crate::production_confinement::NonRootUid,
    /// Unprivileged gid the VMM drops to.
    pub gid: u32,
    /// Network namespace path, replacing the `ip netns exec` wrapper.
    pub netns: Option<&'a str>,
    /// Limits applied BEFORE exec — the whole reason for the jailer.
    pub cgroup: Option<&'a nucleus_spec::CgroupSpec>,
    /// Which cgroup hierarchy the host uses. See `detect_cgroup_version`.
    pub cgroup_version: u8,
    /// Config path as seen from INSIDE the jail.
    /// The in-jail config file to boot from, or `None` to leave the VMM idle in its API loop.
    ///
    /// `Some` is the historical path: Firecracker parses the file and boots immediately, which is
    /// why it can never be snapshotted — there is no moment at which to ask it to pause. `None`
    /// means the caller will build the machine over the API socket instead.
    pub config_file_in_jail: Option<&'a str>,
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

/// One call on Firecracker's HTTP API: what to send, where, and with what body.
///
/// Held as data rather than issued directly so the LOWERING is separable from the transport.
/// The mapping from a [`FirecrackerConfig`] to a request sequence is the part that can be wrong
/// in ways nothing notices until a guest misbehaves; the part that opens a Unix socket is not.
/// Keeping them apart means the first can be tested on a machine with no KVM, which is the same
/// discipline this module already applies to `lower_drives` and `seccomp_args`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiRequest {
    /// `PUT` for configuration, `PATCH` for state transitions.
    pub method: &'static str,
    /// The API path, e.g. `/boot-source` or `/drives/rootfs`.
    pub path: String,
    /// The JSON body.
    pub body: String,
}

/// Lower a boot configuration into the ordered API calls that build the same VM.
///
/// This is the API-socket twin of writing the config file. Firecracker accepts either; the file
/// form boots the machine the moment it is parsed, which is exactly why it cannot be snapshotted
/// — `/snapshot/create` needs a VMM that is configured, running, and then PAUSED, and a
/// `--config-file` launch gives no window in which to ask.
///
/// **`InstanceStart` is deliberately not here.** The caller issues it, because the gap between
/// "configured" and "running" is where the seccomp filter is verified: today
/// `verify_seccomp_active_within` races a guest that is already booting, and in API mode the VMM
/// sits idle in its API loop with its filter installed, so the check can happen BEFORE the vCPUs
/// run. Returning the boot action here would hand that window back.
///
/// Order is a property, not an accident, and is asserted in the tests: the logger goes first so
/// that a fault configuring anything after it is written down, and everything the machine is
/// made of precedes the action that would run it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn config_to_requests(cfg: &FirecrackerConfig) -> Vec<ApiRequest> {
    // Every sub-struct here is the API's own body shape — that correspondence is why this
    // function is a re-serialization rather than a translation.
    fn put(path: impl Into<String>, body: &impl Serialize) -> ApiRequest {
        ApiRequest {
            method: "PUT",
            path: path.into(),
            body: serde_json::to_string(body).expect("config sub-structs serialize"),
        }
    }

    let mut out = Vec::new();
    if let Some(logger) = &cfg.logger {
        out.push(put("/logger", logger));
    }
    out.push(put("/boot-source", &cfg.boot_source));
    for drive in &cfg.drives {
        out.push(put(format!("/drives/{}", drive.drive_id), drive));
    }
    out.push(put("/machine-config", &cfg.machine_config));
    for nic in &cfg.network_interfaces {
        out.push(put(format!("/network-interfaces/{}", nic.iface_id), nic));
    }
    if let Some(vsock) = &cfg.vsock {
        out.push(put("/vsock", vsock));
    }
    out
}

/// The action that starts the vCPUs, issued only after the sandbox has been verified.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn instance_start_request() -> ApiRequest {
    ApiRequest {
        method: "PUT",
        path: "/actions".into(),
        body: r#"{"action_type":"InstanceStart"}"#.into(),
    }
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
    // Nothing after the separator in API mode: an argv that names a config file is an argv that
    // boots, and the point of API mode is to be configured while still stopped.
    if let Some(cfg) = config_file_in_jail {
        args.push("--config-file".to_string());
        args.push(cfg.to_string());
    }
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
    /// A device-less configuration, for tests exercising the parts of the restore path that read
    /// a config rather than a machine. Deliberately minimal: anything a restore actually needs
    /// comes out of the SNAPSHOT, which is the property under test.
    #[cfg(test)]
    pub(crate) fn without_devices() -> Self {
        Self {
            boot_source: BootSource {
                kernel_image_path: String::new(),
                boot_args: None,
            },
            drives: Vec::new(),
            machine_config: MachineConfig {
                vcpu_count: 1,
                mem_size_mib: 256,
                smt: false,
            },
            network_interfaces: Vec::new(),
            vsock: None,
            logger: None,
        }
    }

    /// The `(iface_id, host_dev_name)` pairs this pod's network interfaces use.
    ///
    /// For `network_overrides` on snapshot restore: the base was frozen holding another pod's tap,
    /// and this is the only thing `/snapshot/load` lets a caller change.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn interface_names(&self) -> Vec<(String, String)> {
        self.network_interfaces
            .iter()
            .map(|n| (n.iface_id.clone(), n.host_dev_name.clone()))
            .collect()
    }

    /// What a snapshot of this machine would have to name, read off the config that booted it.
    ///
    /// Here rather than in `main.rs` for two reasons: the fields are private to this module, and
    /// `main.rs` sits on its line ceiling — so the assembly belongs on the side of the seam that
    /// can afford it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn snapshot_inputs(
        &self,
        vmm_version: nucleus_spec::vmm_version::VmmVersion,
    ) -> crate::snapshot_store::SnapshotInputs {
        crate::snapshot_store::SnapshotInputs {
            boot_args: self.boot_source.boot_args.clone().unwrap_or_default(),
            // Rendered here rather than by the caller: `main.rs` should hand over the version it
            // observed, not a formatting of it.
            vmm_version: vmm_version.to_string(),
            // The API takes these as unsigned; they are `i64` here only because that is what the
            // config file wants. `max(0)` covers the low end and `try_from` the high end: `as`
            // truncates rather than saturates, so a value above `u32::MAX` would arrive as a
            // small plausible one — an absurd memory size silently becoming a bootable one is
            // the failure this path least wants to hand a VMM.
            vcpu_count: u32::try_from(self.machine_config.vcpu_count.max(0)).unwrap_or(u32::MAX),
            mem_size_mib: u32::try_from(self.machine_config.mem_size_mib.max(0))
                .unwrap_or(u32::MAX),
            smt: self.machine_config.smt,
            // A scratch drive is the writable, non-root one. `is_read_only` is the property that
            // matters, not the drive's name, because a name is a convention and this is not.
            writable_scratch: self
                .drives
                .iter()
                .any(|d| !d.is_root_device && !d.is_read_only),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_spec(
        spec: &PodSpec,
        log_path: &Path,
        vsock_path: &Path,
        image: &nucleus_spec::ImageSpec,
        net_plan: Option<&net::NetPlan>,
        approval_pubkeys: &str,
        workload_api_port: Option<u32>,
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

        // OS assumption: KB-VSOCK-PEER-CID; docs/assumptions/kernel-behaviour.md.
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
        // `nucleus.approval_secret` is NO LONGER EMITTED either.
        //
        // It was the last real secret on this command line: an HMAC key is
        // symmetric, so the guest's VERIFICATION key was also a signing key,
        // and any workload that read `/proc/cmdline` could forge approvals
        // for its own operations — an authority bypass, not just a leak.
        //
        // What rides here instead is `nucleus.approval_pubkeys`: the Ed25519
        // PUBLIC half of the node's approval signing key. The guest verifies
        // an approver's signature (drand-anchored, `verify_strict`) and can do
        // nothing else with the key — reading it grants no forging power, so
        // it is safe on a world-readable channel, and it is per-node config,
        // so it does not block a snapshot base (see `SHARED_CONFIG_KEYS`).
        boot_args = match boot_args.take() {
            Some(args) => Some(format!(
                "{args} nucleus.approval_pubkeys={approval_pubkeys}"
            )),
            None => Some(format!("nucleus.approval_pubkeys={approval_pubkeys}")),
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
            // The AWS credentials are NO LONGER EMITTED here.
            //
            // They were forwarded as `nucleus.aws_access_key_id` /
            // `_secret_access_key` / `_session_token`, which put long-lived
            // cloud credentials on the world-readable `/proc/cmdline` — the C1
            // exposure, and the sharpest instance of it: these keys write the
            // audit trail, so the workload they were readable by could erase
            // its own record. They now ride the workload API
            // (`FETCH_AUDIT_CREDENTIALS`, served once, before any workload
            // exists) — see `handle_fetch_audit_credentials`. Only the REGION
            // stays: it is per-fleet configuration, not a secret, and the
            // snapshot guard classifies it as shared.
            if let Ok(region) = std::env::var("AWS_DEFAULT_REGION") {
                if let Some(ref mut args) = boot_args {
                    args.push_str(&format!(" nucleus.aws_default_region={region}"));
                }
            }
        }

        // NO per-pod material is written to the kernel command line.
        //
        // The Tier-3 `nucleus.sandbox_token` fallback and the identity-less
        // task-token copy (`nucleus.task_token_hex` and siblings) have both been
        // RETIRED (2026-08-08). This
        // is the deletion that lets C1's `Cmdline` channel theorem be proved
        // GREEN over EVERY pod rather than only identity-bearing ones, and it
        // is a deletion rather than a relocation because the fallback was
        // already dead on every rootfs nucleus ships:
        //
        //   * The Tier-3 token is verified with the tool-proxy's auth secret
        //     (`try_orchestrator_token`). The guest gets that secret only from
        //     `nucleus.auth_secret` (DELETED from the cmdline in Phase 1) or
        //     `/etc/nucleus/auth.secret` (written ONLY under
        //     `build-rootfs.sh --legacy-secrets`, which no build path — CI
        //     boot, release, quickstart, Makefile — passes). So on a shipped
        //     rootfs the guest's auth secret is empty, while the NODE signs the
        //     token with its required-non-empty `proxy_auth_secret`. The HMAC
        //     never matches: the token could not be verified, so it proved
        //     nothing and only sat on the world-readable cmdline as a Secret.
        //
        // An identity-BEARING pod reaches Tier 1/2 from its SVID and fetches
        // its task token over the workload API (`FETCH_TASK_TOKEN`), so it is
        // fully served without either cmdline value. An identity-LESS
        // Firecracker pod has no Tier 1/2 SVID and, now, no Tier 3 either — it
        // fails closed with `SandboxProofError::NakedProcess`, which on a
        // shipped rootfs is the outcome it already had. Retiring the dead
        // fallback makes that failure honest instead of routing it through an
        // unverifiable secret on `/proc/cmdline`.
        //
        // If a Tier-3 fallback is ever wanted again, its verification key must
        // arrive over a channel that is not the cmdline (the workload API is
        // the established shape) — not by re-baking a fleet-shared secret.

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

    if let Some(ref data) = image.data_path {
        drives.push(DriveConfig {
            drive_id: "data".to_string(),
            path_on_host: if jailed {
                in_jail::DATA.to_string()
            } else {
                data.display().to_string()
            },
            is_root_device: false,
            // The property the whole design rests on, and it is unconditional: there is no spec
            // field that can make this writable. A guest that could write here would corrupt an
            // image other pods are reading, and would make the pod unsnapshottable into the
            // bargain — `snapshot_inputs` counts any writable non-root drive as scratch.
            is_read_only: true,
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

/// OS assumption: KB-PROCFS-STATUS (docs/assumptions/kernel-behaviour.md).
///
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
#[path = "firecracker_config_tests.rs"]
mod tests;
