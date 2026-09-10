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

/// A read-only data image lowers to a non-root, read-only drive at the fixed in-jail name.
///
/// Three properties, each load-bearing for a different reason:
/// * `is_read_only` — a guest that could write here would corrupt an image other pods read;
/// * `is_root_device: false` — it is a corpus beside the system, not the system;
/// * the fixed in-jail name — Firecracker has no `drive_overrides` on `/snapshot/load`, so a
///   restored VM reopens drives at the paths inside the snapshot. Identical inside each
///   chroot, distinct outside, exactly as the vsock path must be.
#[test]
fn a_data_image_lowers_to_a_read_only_non_root_drive() {
    let mut img = image(true, false);
    img.data_path = Some(PathBuf::from("/var/lib/nucleus/corpus.img"));
    let drives = lower_drives(&img, true);
    let data = drives
        .iter()
        .find(|d| d.drive_id == "data")
        .expect("the data image becomes a drive");
    assert!(data.is_read_only, "a shared corpus is never writable");
    assert!(!data.is_root_device);
    assert_eq!(data.path_on_host, in_jail::DATA);

    // Unjailed it keeps the host path, like every other artifact on that path.
    let unjailed = lower_drives(&img, false);
    let data = unjailed.iter().find(|d| d.drive_id == "data").unwrap();
    assert_eq!(data.path_on_host, "/var/lib/nucleus/corpus.img");

    // And no data image means no drive at all — absence is a no-op, so every spec written
    // before this field is unaffected.
    assert!(
        lower_drives(&image(true, false), true)
            .iter()
            .all(|d| d.drive_id != "data")
    );
}

/// A data image does NOT make a pod unsnapshottable; a scratch disk does.
///
/// This is the property that lets a gate pod still be a base. `snapshot_inputs` counts any
/// writable non-root drive as scratch, and refuses to snapshot such a pod — clones would
/// either share one writable file or inherit stale cached filesystem state. A read-only
/// corpus has neither problem, and if this test ever fails the whole design collapses:
/// delivering a corpus would cost the ability to reuse the pod that reads it.
///
/// Linux-gated because `snapshot_inputs` is: asserting on `lower_drives`'s output instead
/// would restate the predicate rather than exercise it.
#[cfg(target_os = "linux")]
#[test]
fn a_read_only_data_image_does_not_count_as_writable_scratch() {
    let mut with_data = image(true, false);
    with_data.data_path = Some(PathBuf::from("/corpus.img"));
    let cfg = |img: &ImageSpec| FirecrackerConfig {
        boot_source: BootSource {
            kernel_image_path: String::new(),
            boot_args: None,
        },
        drives: lower_drives(img, true),
        machine_config: MachineConfig {
            vcpu_count: 1,
            mem_size_mib: 256,
            smt: false,
        },
        network_interfaces: Vec::new(),
        vsock: None,
        logger: None,
    };
    assert!(
        !cfg(&with_data)
            .snapshot_inputs(nucleus_spec::vmm_version::PINNED)
            .writable_scratch,
        "a read-only corpus must not read as writable scratch, or attaching one would make \
             the pod unsnapshottable"
    );
    assert!(
        cfg(&image(true, true))
            .snapshot_inputs(nucleus_spec::vmm_version::PINNED)
            .writable_scratch,
        "...while a real scratch disk still does"
    );
}

fn image(read_only: bool, scratch: bool) -> ImageSpec {
    ImageSpec {
        kernel_path: PathBuf::from("/var/lib/nucleus/vmlinux"),
        rootfs_path: PathBuf::from("/var/lib/nucleus/rootfs.ext4"),
        boot_args: None,
        read_only,
        scratch_path: scratch.then(|| PathBuf::from("/var/lib/nucleus/scratch.ext4")),
        kernel_digest: None,
        rootfs_digest: None,
        scratch_digest: None,
        data_path: None,
        data_digest: None,
    }
}

/// A config with every optional section present, built directly rather than through
/// `from_spec` — which is Linux-only, and the point of a pure lowering is that it can be
/// checked on a machine with no KVM.
fn full_config() -> FirecrackerConfig {
    FirecrackerConfig {
        boot_source: BootSource {
            kernel_image_path: "/kernel".into(),
            boot_args: Some("console=ttyS0 reboot=k panic=1 pci=off".into()),
        },
        drives: vec![
            DriveConfig {
                drive_id: "rootfs".into(),
                path_on_host: "/rootfs.ext4".into(),
                is_root_device: true,
                is_read_only: true,
            },
            DriveConfig {
                drive_id: "scratch".into(),
                path_on_host: "/scratch.ext4".into(),
                is_root_device: false,
                is_read_only: false,
            },
        ],
        machine_config: MachineConfig {
            vcpu_count: 2,
            mem_size_mib: 512,
            smt: false,
        },
        network_interfaces: vec![NetworkInterface {
            iface_id: "eth0".into(),
            host_dev_name: "tap0".into(),
            guest_mac: "AA:BB:CC:DD:EE:FF".into(),
        }],
        vsock: Some(VsockConfig {
            guest_cid: 3,
            uds_path: "/vsock.sock".into(),
        }),
        logger: Some(LoggerConfig {
            log_path: "/firecracker.log".into(),
            level: "Info".into(),
            show_level: false,
            show_log_origin: false,
        }),
    }
}

/// The lowering emits the machine before anything that could run it, and never the boot.
///
/// Order is the property that matters. The logger is first so a failure configuring
/// anything after it is written down rather than lost; `InstanceStart` is absent because the
/// caller issues it after verifying the seccomp filter — which is the whole reason for
/// driving the API instead of handing Firecracker a config file that boots on parse.
#[test]
fn the_lowering_configures_the_machine_and_never_starts_it() {
    let reqs = config_to_requests(&full_config());
    let paths: Vec<&str> = reqs.iter().map(|r| r.path.as_str()).collect();

    assert_eq!(
        paths,
        vec![
            "/logger",
            "/boot-source",
            "/drives/rootfs",
            "/drives/scratch",
            "/machine-config",
            "/network-interfaces/eth0",
            "/vsock",
        ]
    );
    assert!(
        reqs.iter().all(|r| r.method == "PUT"),
        "configuration is all PUT; state transitions are the caller's PATCH"
    );
    assert!(
        !reqs.iter().any(|r| r.path == "/actions"),
        "the lowering must not start the vCPUs: that window is where seccomp is verified"
    );
    assert_eq!(instance_start_request().path, "/actions");
}

/// The bodies are the shapes a real Firecracker accepted.
///
/// Verified against firecracker v1.16.1 on KVM (`vmm_version::PINNED`): each of these paths
/// and body shapes returned 204, then `/snapshot/create` and `/snapshot/load` round-tripped.
/// Pinning them here means a serde rename or a field drop is caught on any machine, instead
/// of at the next real boot.
#[test]
fn each_body_is_the_shape_firecracker_accepts() {
    let reqs = config_to_requests(&full_config());
    let body = |p: &str| {
        reqs.iter()
            .find(|r| r.path == p)
            .unwrap_or_else(|| panic!("no request for {p}"))
            .body
            .clone()
    };
    let json = |p: &str| -> serde_json::Value { serde_json::from_str(&body(p)).unwrap() };

    assert_eq!(json("/boot-source")["kernel_image_path"], "/kernel");
    assert!(json("/boot-source")["boot_args"].is_string());
    let root = json("/drives/rootfs");
    assert_eq!(root["drive_id"], "rootfs");
    assert_eq!(root["is_root_device"], true);
    assert_eq!(root["path_on_host"], "/rootfs.ext4");
    assert_eq!(json("/machine-config")["vcpu_count"], 2);
    assert_eq!(json("/machine-config")["mem_size_mib"], 512);
    assert_eq!(json("/network-interfaces/eth0")["host_dev_name"], "tap0");
    assert_eq!(json("/vsock")["guest_cid"], 3);
}

/// An absent section emits no call at all — not an empty one.
#[test]
fn optional_sections_are_omitted_rather_than_sent_empty() {
    let mut cfg = full_config();
    cfg.logger = None;
    cfg.vsock = None;
    cfg.network_interfaces.clear();
    let paths: Vec<String> = config_to_requests(&cfg)
        .into_iter()
        .map(|r| r.path)
        .collect();
    assert_eq!(
        paths,
        vec![
            "/boot-source",
            "/drives/rootfs",
            "/drives/scratch",
            "/machine-config"
        ]
    );
}

/// Build a cmdline for a pod that either will or will not receive an SVID.
///
/// Linux-gated because `from_spec` is: the cmdline builder only compiles on
/// the platform that can run a microVM. These therefore run in CI and in
/// OrbStack, never on a macOS dev machine — the same trap that once hid the
/// vsock accept path behind a `cfg` nobody compiled.
//
// GATED, not merely `allow(dead_code)`: `from_spec` does not EXIST off
// Linux, so the old attribute silenced the wrong diagnostic and the helper
// still failed to compile. `cargo test -p nucleus-node` was therefore
// broken on macOS — every test in this crate, not just these — while CI
// stayed green because CI is Linux. A Mac developer could not run the
// node's tests at all.
#[cfg(target_os = "linux")]
fn boot_args_with_identity(will_have_identity: bool) -> String {
    let config = FirecrackerConfig::from_spec(
        &base_spec(),
        std::path::Path::new("/unused/firecracker.log"),
        std::path::Path::new("/unused/vsock.sock"),
        &image(true, false),
        None,
        "aa00bb11-approval-pubkeys",
        will_have_identity.then_some(15012),
        None,
    );
    config.boot_source.boot_args.unwrap_or_default()
}

/// **No pod carries a Tier-3 `sandbox_token` on its cmdline — RETIRED.**
/// The fallback was verified with an auth secret the guest no longer has on
/// any shipped rootfs (`/etc/nucleus/auth.secret` is written only under
/// `--legacy-secrets`, and `nucleus.auth_secret` left the cmdline in
/// Phase 1), so the token could never verify: it was a dead Secret on a
/// world-readable channel. Gone for BOTH identity states now.
#[cfg(target_os = "linux")]
#[test]
fn no_pod_carries_a_sandbox_token_on_the_cmdline() {
    for identity in [true, false] {
        let args = boot_args_with_identity(identity);
        assert!(
            !args.contains("nucleus.sandbox_token"),
            "identity={identity}: the retired Tier-3 token must not be emitted: {args}"
        );
    }
}

/// **No pod carries a task token on its cmdline — RETIRED.** Identity-bearing
/// pods fetch it over the workload API (`FETCH_TASK_TOKEN`); identity-less
/// pods have no verifiable proof at all now and fail closed. Either way the
/// cmdline copy is gone.
#[cfg(target_os = "linux")]
#[test]
fn no_pod_carries_a_task_token_on_the_cmdline() {
    for identity in [true, false] {
        let args = boot_args_with_identity(identity);
        assert!(
            !args.contains("nucleus.task_token_hex"),
            "identity={identity}: the task-token cmdline copy must be gone: {args}"
        );
        assert!(!args.contains("nucleus.task_token_nonce"), "{args}");
        assert!(!args.contains("nucleus.task_token_issuer"), "{args}");
    }
}

/// **THE CATEGORICAL GATE, and the Rust half of the Lean `Cmdline` theorem.**
/// Over ANY pod's actual boot args — identity-bearing OR identity-less — NO
/// key classified per-pod-secret may appear. The whole
/// [`snapshot::PER_POD_SECRET_KEYS`] set at once, so a per-pod secret nobody
/// has invented yet is caught the moment it is emitted. Now UNCONDITIONAL
/// (was identity-bearing only) — the retirement is what makes the future
/// Lean channel theorem provable over every pod. Reuses the snapshot key
/// parser so the two cannot disagree on what a key is.
#[cfg(target_os = "linux")]
#[test]
fn no_pod_cmdline_carries_any_per_pod_secret() {
    for identity in [true, false] {
        let args = boot_args_with_identity(identity);
        let emitted: Vec<&str> = args
            .split_whitespace()
            .map(|t| t.split('=').next().unwrap_or(t))
            .collect();
        let leaked: Vec<&str> = crate::snapshot::PER_POD_SECRET_KEYS
            .iter()
            .copied()
            .filter(|k| emitted.contains(k))
            .collect();
        assert!(
            leaked.is_empty(),
            "identity={identity}: /proc/cmdline carries per-pod secret material \
                 {leaked:?} — the C1 exposure. Deliver it over the workload API instead. \
                 Full args: {args}"
        );
    }
}

/// A MAXIMAL spec's boot args: every optional emission triggered — an audit
/// sink with all four S3 fields (→ the `audit_s3_*` keys), identity (→
/// `nucleus.workload_api_port`), and the always-emitted `nucleus.approval_pubkeys`
/// — so the completeness check below sees the emitter's full `nucleus.*`
/// vocabulary, not the thin slice `base_spec` produces.
#[cfg(target_os = "linux")]
fn boot_args_maximal() -> String {
    let spec: PodSpec = serde_json::from_str(
            r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"audit_sink":{"s3_bucket":"b","s3_prefix":"p/","s3_region":"us-west-2","s3_endpoint":"https://e.example"}}}"#,
        )
        .expect("maximal spec must deserialize");
    let config = FirecrackerConfig::from_spec(
        &spec,
        std::path::Path::new("/unused/firecracker.log"),
        std::path::Path::new("/unused/vsock.sock"),
        &image(true, false),
        None,
        "aa00bb11-approval-pubkeys",
        Some(15012),
        None,
    );
    config.boot_source.boot_args.unwrap_or_default()
}

/// **Behavioral completeness — the robust replacement for the source-scrape.**
/// Over the REAL generated boot args of a maximal spec, EVERY `nucleus.*` key
/// present must be classified (per-pod-secret or shared-config). The old
/// `snapshot::every_cmdline_key_is_classified` scraped THIS file's SOURCE for
/// `nucleus.` substrings — which its own docstring distrusts: it counts key
/// names quoted in tests and comments (false positives) and would miss a key
/// built by `format!` / concatenation (false negative). Running the emitter and
/// reading its ACTUAL output removes both failure modes: a new key can only
/// reach a snapshot base by being emitted, and if it is emitted, it is caught
/// here unless someone classified it. The partition into per-pod vs shared then
/// decides whether the base is `SafeToClone` — so an unclassified key fails
/// LOUDLY rather than defaulting to clonable.
#[cfg(target_os = "linux")]
#[test]
fn every_emitted_cmdline_key_is_classified() {
    let args = boot_args_maximal();
    let emitted: Vec<&str> = args
        .split_whitespace()
        .map(|t| t.split('=').next().unwrap_or(t))
        .filter(|k| k.starts_with("nucleus."))
        .collect();
    // Non-vacuity: the maximal spec must actually exercise the emitter. If it
    // emitted nothing, the loop below would pass while checking nothing.
    assert!(
        emitted.len() >= 5,
        "the maximal spec emitted only {} nucleus.* keys — it has stopped \
             exercising the emitter, so this completeness check proves nothing. \
             Args: {args}",
        emitted.len()
    );
    for k in &emitted {
        assert!(
            crate::snapshot::PER_POD_SECRET_KEYS.contains(k)
                || crate::snapshot::SHARED_CONFIG_KEYS.contains(k),
            "{k} is emitted onto the guest command line but classified NEITHER \
                 per-pod-secret nor shared-config. Classify it in snapshot.rs: getting \
                 it wrong in the 'shared' direction leaks it to every clone restored \
                 from a snapshot base."
        );
    }
}

/// **The precondition that makes the identity-bearing path work**, pinned
/// against the source rather than trusted, and now load-bearing: with the
/// Tier-3 fallback retired, an identity-bearing pod's SVID is its ONLY proof,
/// and it needs the SVID source running before the health check that depends
/// on it. The first attempt at deferring the token deadlocked every launch
/// because the bridge started after the health check.
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
        // The health wait now sits inside `net::confinement::gate`, which
        // also requires the guest's egress attestation. The ordering this
        // guards is unchanged — the bridge must still come first — so the
        // needle follows the call site rather than the function name.
        .find("confinement::gate(health_addr")
        .expect("the health/attestation gate site");
    assert!(
        bridge < health,
        "the workload API bridge must start BEFORE the proxy health check — the guest \
             needs its SVID in order to become healthy, so producing it afterwards is the \
             wrong order. An identity-bearing pod has no Tier 3 fallback, so this ordering \
             is the only thing letting it prove itself at all."
    );
}

/// **The retirement holds under every identity outcome.** Whatever the
/// `(identity_enabled, egress_granted)` combination resolves to — and hence
/// whether `workload_api_port` is `Some` — NEITHER the sandbox token nor the
/// task-token copy is ever written. There is no longer a condition to track,
/// which is the point: the previous version of this test pinned the copies
/// as present exactly when the port was absent; now they are absent always.
#[cfg(target_os = "linux")]
#[test]
fn no_identity_outcome_reintroduces_a_cmdline_token() {
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
        assert!(
            !args.contains("nucleus.sandbox_token="),
            "identity_enabled={enabled} granted={granted}: the retired Tier-3 token \
                 must never reappear: {args}"
        );
        assert!(
            !args.contains("nucleus.task_token_hex="),
            "identity_enabled={enabled} granted={granted}: the retired task-token copy \
                 must never reappear: {args}"
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
        kernel_digest: None,
        rootfs_digest: None,
        scratch_digest: None,
        data_path: None,
        data_digest: None,
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
        "aa00bb11-approval-pubkeys",
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
        "aa00bb11-approval-pubkeys",
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
        uid: crate::production_confinement::NonRootUid::new(123).unwrap(),
        gid: 100,
        netns: None,
        cgroup: Some(&spec),
        cgroup_version: 2,
        config_file_in_jail: Some("/config.json"),
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
        uid: crate::production_confinement::NonRootUid::new(123).unwrap(),
        gid: 100,
        netns: None,
        cgroup: None,
        cgroup_version: 2,
        config_file_in_jail: Some("/config.json"),
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
        uid: crate::production_confinement::NonRootUid::new(1000).unwrap(),
        gid: 1000,
        netns: Some("/var/run/netns/ns-pod-1"),
        cgroup: Some(&cg),
        cgroup_version: 2,
        config_file_in_jail: Some("/config.json"),
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
        uid: crate::production_confinement::NonRootUid::new(1000).unwrap(),
        gid: 1000,
        netns: Some("/var/run/netns/ns-pod-1"),
        cgroup: None,
        cgroup_version: 2,
        config_file_in_jail: Some("/config.json"),
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
        uid: crate::production_confinement::NonRootUid::new(1000).unwrap(),
        gid: 1000,
        netns: None,
        cgroup: Some(&sample_cgroup()),
        cgroup_version: 2,
        config_file_in_jail: Some("/config.json"),
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

// ── #2603: the shipped String function agrees with the Lean token model ──
//
// `crates/portcullis-core/lean/GuestDeviceSurfaceProofs.lean` proves
// idempotence, `pci=off ∈ enforce x`, `pci=on ∉ enforce x` and
// `count pci=off = 1` over a TOKENISED command line (`Cmdline.enforce`).
// Aeneas cannot extract the `String` code, so the bridge is this parity
// test: a transcription of the Lean model runs beside the real function
// on arbitrary token lists, and the two must agree token for token. The
// theorems then transfer to `enforce_pci_off` through the equality.

/// `GuestDeviceSurface.Tok`, transcribed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ModelTok {
    Pci(bool), // `true` = `pci=off`, `false` = any other value (`pci=on`)
    Other(String),
}

impl ModelTok {
    /// The Rust token this model token stands for.
    fn render(&self) -> String {
        match self {
            ModelTok::Pci(true) => "pci=off".to_string(),
            ModelTok::Pci(false) => "pci=on".to_string(),
            ModelTok::Other(s) => s.clone(),
        }
    }
}

/// `GuestDeviceSurface.Cmdline.enforce`, transcribed: keep the non-`pci`
/// tokens in order, append one `pci=off`.
fn model_enforce(args: &[ModelTok]) -> Vec<ModelTok> {
    let mut out: Vec<ModelTok> = args
        .iter()
        .filter(|t| !matches!(t, ModelTok::Pci(_)))
        .cloned()
        .collect();
    out.push(ModelTok::Pci(true));
    out
}

fn model_tok_strategy() -> impl proptest::strategy::Strategy<Value = ModelTok> {
    use proptest::prelude::*;
    prop_oneof![
        2 => Just(ModelTok::Pci(true)),
        2 => Just(ModelTok::Pci(false)),
        // Opaque tokens never start with `pci=` and never contain
        // whitespace — the two facts the tokeniser (split_whitespace)
        // and `Tok.other` rely on.
        5 => "[a-z0-9._/=-]{1,12}"
            .prop_filter("not a pci= token", |s| !s.starts_with("pci="))
            .prop_map(ModelTok::Other),
    ]
}

proptest::proptest! {
    /// `enforce_pci_off(join tokens) = join (model_enforce tokens)`.
    #[test]
    fn enforce_pci_off_agrees_with_the_token_model(
        toks in proptest::collection::vec(model_tok_strategy(), 0..12)
    ) {
        let line = toks.iter().map(ModelTok::render).collect::<Vec<_>>().join(" ");
        let expected = model_enforce(&toks)
            .iter()
            .map(ModelTok::render)
            .collect::<Vec<_>>()
            .join(" ");
        proptest::prop_assert_eq!(enforce_pci_off(&line), expected);
        // The Lean theorems, observed on the shipped function.
        let once = enforce_pci_off(&line);
        proptest::prop_assert_eq!(enforce_pci_off(&once), once.clone()); // enforce_idem
        let pci: Vec<&str> = once
            .split_whitespace()
            .filter(|t| t.starts_with("pci="))
            .collect();
        proptest::prop_assert_eq!(pci, vec!["pci=off"]); // enforce_pci_tokens + count = 1
    }
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
                uid: crate::production_confinement::NonRootUid::new(123).unwrap(),
                gid: 100,
                netns,
                cgroup,
                cgroup_version: 2,
                config_file_in_jail: Some(in_jail::CONFIG),
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
