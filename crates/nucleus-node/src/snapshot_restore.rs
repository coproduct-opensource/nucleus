//! Booting a pod from a base snapshot instead of from its kernel.
//!
//! [`crate::snapshot_store`] names bases and [`crate::snapshot_vmm`] moves them; this decides
//! whether *this* launch may use one, and brings the VMM up either way. It is the reader that
//! `snapshot_store` was missing — a store nothing restores from is a cache with no hit.
//!
//! # Measured on Firecracker v1.16.1, aarch64/KVM, 2026-09-09
//!
//! Four facts decide this module's shape. All were measured against a real VMM, because three of
//! them are the kind of thing that is silently wrong when assumed:
//!
//! | fact | consequence |
//! |---|---|
//! | The vsock UDS path is **baked into the snapshot** and re-bound at load. It cannot be overridden, and `PUT /vsock` never gets a chance — load fails first and the VMM exits | **restore is jailed-only** |
//! | Firecracker does **not** unlink the socket when it exits | a stale socket must be removed or load fails `EADDRINUSE` |
//! | `network_overrides` on `/snapshot/load` **does** retarget `host_dev_name` | per-pod taps work |
//! | A restored guest ran for 4 s and the base memory file was **byte-identical** afterwards | the File backend maps `MAP_PRIVATE`, so one base safely backs many clones |
//!
//! Restore + resume measured **17 ms** with vsock and a network interface attached (10 ms load,
//! 6 ms resume), against ~79 ms for a cold boot.
//!
//! # Why jailed-only is not a limitation to fix later
//!
//! Because the UDS path is part of the snapshot, a base is restorable exactly where that path is
//! free. Unjailed, every pod's socket is `<pod_dir>/vsock.sock` — different per pod, so a base
//! taken by one pod can never be restored by another. Under the jailer every pod sees
//! [`in_jail::VSOCK`] inside its own chroot: **identical inside, distinct outside**, which is the
//! one arrangement that makes a shared base coherent. The jail was adopted for isolation and
//! happens to be what makes reuse possible at all.
//!
//! # Hard link or nothing
//!
//! The base has to be inside the chroot for the VMM to open it. Placement is a hard link and
//! **never** a copy: the memory image is `mem_size_mib`, so copying 256 MiB would cost far more
//! than the ~79 ms cold boot it is trying to avoid. A cross-device store is therefore refused
//! with an explanation rather than silently made slower than doing nothing.
//!
//! Nothing is chowned. A hard link shares the inode, so chowning the link would change the shared
//! base's ownership for every later pod — and it is unnecessary, because the measurement above
//! says the guest never writes the file. Read permission is the whole requirement.

#[cfg(any(target_os = "linux", test))]
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", test))]
use crate::firecracker_config::{FirecrackerConfig, JailLayout, in_jail};
use crate::snapshot_store::HostIdentity;
#[cfg(any(target_os = "linux", test))]
use crate::snapshot_store::{Derivation, Lookup, SnapshotStore};
#[cfg(any(target_os = "linux", test))]
use crate::snapshot_vmm::SnapshotArtifacts;

/// Why this launch is cold-booting.
///
/// Every arm is an ordinary outcome, not a failure — a cold boot is always correct. They are
/// distinguished because "there is no base yet" and "there is one and this node may not touch it"
/// are different operational facts, and an `Option` could not tell them apart.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug)]
pub(crate) enum NoBase {
    /// Not launched under the jailer, so no base could be restorable. See the module docs.
    NotJailed,
    /// The pod pins no image digests, so it has no program identity to look a base up by.
    NoProgramIdentity(String),
    /// The VMM's version was never established, so a base could not be named safely.
    NoVmmVersion,
    /// Nothing published for this derivation.
    Absent,
    /// Published by a different machine; restoring would run a guest on a CPU it was not frozen on.
    ForeignHost {
        taken_on: HostIdentity,
        running_on: HostIdentity,
    },
    /// Present but unreadable.
    Damaged(String),
    /// The store and the jail are on different filesystems, so placing the base would mean copying
    /// a whole memory image — slower than the cold boot it replaces.
    CrossDevice(String),
}

impl std::fmt::Display for NoBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJailed => write!(
                f,
                "not jailed, and a snapshot's vsock path is fixed at the path it was taken on"
            ),
            Self::NoProgramIdentity(why) => write!(f, "no program identity: {why}"),
            Self::NoVmmVersion => write!(f, "the VMM version was never established"),
            Self::Absent => write!(f, "no base published for this derivation"),
            Self::ForeignHost {
                taken_on,
                running_on,
            } => write!(
                f,
                "the base was taken on {}/{} and this node is {}/{}",
                taken_on.arch, taken_on.cpu_model, running_on.arch, running_on.cpu_model
            ),
            Self::Damaged(why) => write!(f, "the published base is unreadable: {why}"),
            Self::CrossDevice(why) => write!(
                f,
                "the snapshot store is not on the jail's filesystem, so using it would mean \
                 copying a whole memory image — slower than booting cold: {why}"
            ),
        }
    }
}

/// The derivation this launch would restore, and where a base for it would live.
///
/// Linux-gated because `FirecrackerConfig`'s inherent methods are: the whole launch path is.
#[cfg(target_os = "linux")]
pub(crate) fn derivation_for(
    cfg: &FirecrackerConfig,
    spec: &nucleus_spec::PodSpec,
    verdict: &nucleus_spec::vmm_version::VmmVerdict,
) -> Result<Derivation, NoBase> {
    let found = verdict.found().ok_or(NoBase::NoVmmVersion)?;
    let program = nucleus_spec::identity::program_digest(spec)
        .map_err(|e| NoBase::NoProgramIdentity(e.to_string()))?;
    Ok(cfg.snapshot_inputs(found).derivation(program))
}

/// Find a base for this launch and place it inside the jail.
///
/// Returns the artifacts by their **in-jail** names, which is what the VMM will open them by
/// after `chroot` — the same discipline `prepare_jail` already applies to the kernel and rootfs.
#[cfg(target_os = "linux")]
pub(crate) fn place_base(
    store_root: &Path,
    derivation: &Derivation,
    jail: Option<&JailLayout>,
) -> Result<SnapshotArtifacts, NoBase> {
    let jail = jail.ok_or(NoBase::NotJailed)?;
    let store = SnapshotStore::new(store_root.to_path_buf(), HostIdentity::detect());
    match store.lookup(derivation) {
        Lookup::Absent => return Err(NoBase::Absent),
        Lookup::Damaged(why) => return Err(NoBase::Damaged(why)),
        Lookup::ForeignHost {
            taken_on,
            running_on,
        } => {
            return Err(NoBase::ForeignHost {
                taken_on,
                running_on,
            });
        }
        Lookup::Present(_) => {}
    }
    let dir = store.published_dir(&derivation.name());
    for (src, name) in [
        (dir.join("vmstate"), in_jail::SNAPSHOT_VMSTATE),
        (dir.join("mem"), in_jail::SNAPSHOT_MEM),
    ] {
        let dest = jail.host_path(name);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| NoBase::CrossDevice(e.to_string()))?;
        }
        // A relaunch under the same pod id finds the previous link; `hard_link` would fail
        // `AlreadyExists` rather than replace, exactly as `place_resource` documents.
        let _ = std::fs::remove_file(&dest);
        std::fs::hard_link(&src, &dest).map_err(|e| {
            NoBase::CrossDevice(format!("{} -> {}: {e}", src.display(), dest.display()))
        })?;
    }
    Ok(SnapshotArtifacts {
        vmstate: PathBuf::from(in_jail::SNAPSHOT_VMSTATE),
        mem: PathBuf::from(in_jail::SNAPSHOT_MEM),
    })
}

/// The whole decision, as one call the launch path can make in one line.
///
/// Never returns an error: a cold boot is always a correct outcome, so every reason to skip a
/// base is *logged* and swallowed here rather than propagated. The launch path has enough ways to
/// fail without a cache miss becoming one of them — and the reason is on the record either way.
#[cfg(target_os = "linux")]
pub(crate) fn base_for(
    state: &crate::NodeState,
    cfg: &FirecrackerConfig,
    spec: &nucleus_spec::PodSpec,
    verdict: &nucleus_spec::vmm_version::VmmVerdict,
    jail: Option<&JailLayout>,
) -> Option<SnapshotArtifacts> {
    let root = state.state_dir.join("snapshots");
    match derivation_for(cfg, spec, verdict).and_then(|d| place_base(&root, &d, jail)) {
        Ok(base) => {
            tracing::info!("restoring this pod from a published base instead of booting cold");
            Some(base)
        }
        Err(why) => {
            tracing::debug!(%why, "cold boot");
            None
        }
    }
}

/// The tap retargeting a restored VM needs.
///
/// The base was frozen holding one pod's tap device; this pod has its own. `network_overrides` is
/// the only thing `/snapshot/load` lets us change, and it changes exactly the right thing.
///
/// Note what it does NOT change: the guest MAC, which comes from the snapshot. Every clone of a
/// base therefore presents the same MAC — harmless here because each pod has a private tap in its
/// own netns and nothing bridges them, and a real problem the moment anything does.
#[cfg(target_os = "linux")]
pub(crate) fn network_overrides(cfg: &FirecrackerConfig) -> Vec<serde_json::Value> {
    cfg.interface_names()
        .into_iter()
        .map(|(iface_id, host_dev_name)| {
            serde_json::json!({ "iface_id": iface_id, "host_dev_name": host_dev_name })
        })
        .collect()
}

/// Bring a freshly-spawned VMM to a running state — from a base if one was placed, else from the
/// configuration.
///
/// One function for both so the launch path has a single call and cannot drift into two shapes
/// that disagree about error handling or ordering.
#[cfg(target_os = "linux")]
pub(crate) async fn bring_up(
    sock: &Path,
    cfg: &FirecrackerConfig,
    base: Option<&SnapshotArtifacts>,
    jail: Option<&JailLayout>,
) -> Result<(), String> {
    let Some(base) = base else {
        crate::firecracker_api::configure(sock, cfg).await?;
        return crate::firecracker_api::start(sock).await;
    };

    // Firecracker re-binds the snapshot's own vsock path at load and does NOT unlink it on exit,
    // so a previous VMM's socket file is still sitting there and load fails `EADDRINUSE`. Removing
    // it is not tidying — it is a precondition, and the failure it prevents reads as an unrelated
    // "Address in use" from deep inside device restore.
    if let Some(jail) = jail {
        let stale = jail.host_path(in_jail::VSOCK);
        if stale.exists() {
            std::fs::remove_file(&stale)
                .map_err(|e| format!("cannot clear the stale vsock socket for restore: {e}"))?;
        }
    }

    crate::firecracker_api::wait_for_api_socket(sock).await?;
    crate::firecracker_api::send(
        sock,
        &crate::firecracker_api::put_json(
            "/snapshot/load",
            &serde_json::json!({
                "snapshot_path": base.vmstate,
                "mem_backend": { "backend_path": base.mem, "backend_type": "File" },
                "resume_vm": false,
                "network_overrides": network_overrides(cfg),
            }),
        ),
    )
    .await?;
    crate::snapshot_vmm::resume(sock).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal renders something a human can act on, and none of them is the empty string.
    ///
    /// Cheap, and it is the one property that makes `NoBase` worth being an enum: the whole
    /// argument for distinguishing these cases is that the operator can tell them apart.
    #[test]
    fn every_reason_for_cold_booting_explains_itself() {
        let here = HostIdentity {
            arch: "aarch64".into(),
            cpu_model: "this".into(),
        };
        let there = HostIdentity {
            arch: "x86_64".into(),
            cpu_model: "that".into(),
        };
        for reason in [
            NoBase::NotJailed,
            NoBase::NoProgramIdentity("unpinned".into()),
            NoBase::NoVmmVersion,
            NoBase::Absent,
            NoBase::ForeignHost {
                taken_on: there,
                running_on: here,
            },
            NoBase::Damaged("truncated".into()),
            NoBase::CrossDevice("EXDEV".into()),
        ] {
            let rendered = reason.to_string();
            assert!(
                rendered.len() > 20,
                "a cold-boot reason must say something: {reason:?} -> {rendered:?}"
            );
        }
        // The two that are most often confused must not read alike.
        assert_ne!(
            NoBase::Absent.to_string(),
            NoBase::Damaged("x".into()).to_string()
        );
    }

    /// Placement is a hard LINK, not a copy — asserted by inode identity.
    ///
    /// The distinction is the whole performance argument: a copy of a 256 MiB memory image costs
    /// far more than the ~79 ms cold boot it replaces, so a store that silently copied would be a
    /// cache that makes every launch slower. Comparing `st_ino` is the only assertion that can
    /// tell the two apart — file contents are identical either way.
    #[cfg(target_os = "linux")]
    #[test]
    fn placing_a_base_hard_links_it_rather_than_copying_it() {
        use crate::snapshot_store::{BARRIER_PROTOCOL, SnapshotStore};
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("store");
        let host = HostIdentity::detect();
        let store = SnapshotStore::new(root.clone(), host);
        let d = Derivation {
            program: "c".repeat(64),
            vmm_version: "1.16.1".into(),
            arch: std::env::consts::ARCH.to_string(),
            vcpu_count: 1,
            mem_size_mib: 256,
            smt: false,
            cpu_template: None,
            barrier_protocol: BARRIER_PROTOCOL,
        };

        // A base with recognisable contents.
        let inc = store.begin().unwrap();
        std::fs::write(&inc.artifacts.vmstate, b"vmstate").unwrap();
        std::fs::write(&inc.artifacts.mem, vec![7u8; 8192]).unwrap();
        let published = store.publish(inc, &d).unwrap();

        let jail = JailLayout {
            jail_root: tmp.path().join("jail/root"),
        };
        std::fs::create_dir_all(&jail.jail_root).unwrap();

        let placed = place_base(&root, &d, Some(&jail)).expect("a published base is placeable");
        assert_eq!(placed.mem, PathBuf::from(in_jail::SNAPSHOT_MEM));
        assert_eq!(placed.vmstate, PathBuf::from(in_jail::SNAPSHOT_VMSTATE));

        let src = std::fs::metadata(published.join("mem")).unwrap();
        let dst = std::fs::metadata(jail.host_path(in_jail::SNAPSHOT_MEM)).unwrap();
        assert_eq!(
            (src.dev(), src.ino()),
            (dst.dev(), dst.ino()),
            "the base must be hard-linked into the jail; a copy would cost more than a cold boot"
        );
        assert_eq!(src.nlink(), 2, "one link in the store, one in the jail");

        // And the second placement, as a relaunch under the same pod id would do.
        place_base(&root, &d, Some(&jail)).expect("placing twice must not fail on AlreadyExists");
    }

    /// Unjailed never restores, however good the base is.
    #[cfg(target_os = "linux")]
    #[test]
    fn an_unjailed_launch_is_refused_a_base() {
        let tmp = tempfile::tempdir().unwrap();
        let d = Derivation {
            program: "d".repeat(64),
            vmm_version: "1.16.1".into(),
            arch: std::env::consts::ARCH.to_string(),
            vcpu_count: 1,
            mem_size_mib: 256,
            smt: false,
            cpu_template: None,
            barrier_protocol: crate::snapshot_store::BARRIER_PROTOCOL,
        };
        assert!(
            matches!(place_base(tmp.path(), &d, None), Err(NoBase::NotJailed)),
            "a snapshot's vsock path is fixed at the path it was taken on, so an unjailed pod \
             could never rebind it"
        );
    }

    /// The real thing: publish a base this code took, then restore from it through `bring_up`.
    ///
    /// Everything above tests a piece. This tests the composition on a live VMM, which is the only
    /// way to know — the sequence is Firecracker accepting or refusing in an order no type
    /// enforces, and three of its rules were discovered by measurement rather than documentation
    /// (see the module header).
    ///
    /// Skips unless a KVM host with the pinned artifacts is present. `NUCLEUS_TEST_ARTIFACTS`
    /// should hold `vmlinux` and `rootfs.ext4`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_base_this_code_published_is_one_this_code_restores() {
        use crate::firecracker_api;
        use crate::snapshot_store::{BARRIER_PROTOCOL, SnapshotStore};

        let Some(art) = std::env::var_os("NUCLEUS_TEST_ARTIFACTS").map(PathBuf::from) else {
            eprintln!("skipping: NUCLEUS_TEST_ARTIFACTS is not set");
            return;
        };
        let (kernel, rootfs) = (art.join("vmlinux"), art.join("rootfs.ext4"));
        let kvm_usable = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok();
        if !kernel.is_file() || !rootfs.is_file() || !kvm_usable {
            eprintln!("skipping: no artifacts, or /dev/kvm is not openable by this user");
            return;
        }
        let Some(fc) = std::env::var_os("PATH").and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join("firecracker"))
                .find(|c| c.is_file())
        }) else {
            eprintln!("skipping: no firecracker on PATH");
            return;
        };

        let tmp = tempfile::tempdir().unwrap();
        // The vsock path is the one thing a snapshot fixes, so BOTH VMMs must use this exact
        // path — which is what the jail's fixed in-jail names buy in production.
        let jail = JailLayout {
            jail_root: tmp.path().join("root"),
        };
        std::fs::create_dir_all(&jail.jail_root).unwrap();
        let vsock = jail.host_path(in_jail::VSOCK);

        // ── take a base ─────────────────────────────────────────────────────────────────
        let sock1 = tmp.path().join("fc1.socket");
        let mut vm1 = tokio::process::Command::new(&fc)
            .arg("--api-sock")
            .arg(&sock1)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("firecracker spawns");
        let staged = {
            let store = SnapshotStore::new(tmp.path().join("store"), HostIdentity::detect());
            store.begin().expect("staging")
        };
        let took = async {
            firecracker_api::wait_for_api_socket(&sock1).await?;
            for (path, body) in [
                (
                    "/boot-source",
                    serde_json::json!({"kernel_image_path": kernel,
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"}),
                ),
                (
                    "/drives/rootfs",
                    serde_json::json!({"drive_id": "rootfs", "path_on_host": rootfs,
                        "is_root_device": true, "is_read_only": true}),
                ),
                (
                    "/machine-config",
                    serde_json::json!({"vcpu_count": 1, "mem_size_mib": 256}),
                ),
                (
                    "/vsock",
                    serde_json::json!({"guest_cid": 3, "uds_path": vsock}),
                ),
            ] {
                firecracker_api::send(&sock1, &firecracker_api::put_json(path, &body)).await?;
            }
            firecracker_api::send(&sock1, &crate::firecracker_config::instance_start_request())
                .await?;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            crate::snapshot_vmm::create(
                &sock1,
                &crate::snapshot::SnapshotSafety::SafeToClone,
                &staged.artifacts,
            )
            .await
        }
        .await;
        let _ = vm1.kill().await;
        took.expect("taking a base must succeed");

        // ── publish it ──────────────────────────────────────────────────────────────────
        let store = SnapshotStore::new(tmp.path().join("store"), HostIdentity::detect());
        let d = Derivation {
            program: "e".repeat(64),
            vmm_version: "1.16.1".into(),
            arch: std::env::consts::ARCH.to_string(),
            vcpu_count: 1,
            mem_size_mib: 256,
            smt: false,
            cpu_template: None,
            barrier_protocol: BARRIER_PROTOCOL,
        };
        let published = store.publish(staged, &d).expect("publish");

        // ── restore from it, through the launch path's own function ─────────────────────
        // Host paths rather than in-jail names because this VMM is not chrooted; `place_base`
        // covers the naming and is tested separately.
        let base = SnapshotArtifacts {
            vmstate: published.join("vmstate"),
            mem: published.join("mem"),
        };
        let before = std::fs::read(&base.mem).expect("base mem readable");

        let sock2 = tmp.path().join("fc2.socket");
        let mut vm2 = tokio::process::Command::new(&fc)
            .arg("--api-sock")
            .arg(&sock2)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("second firecracker spawns");
        assert!(
            vsock.exists(),
            "the first VMM's socket must still be there — Firecracker does not unlink it, which \
             is precisely why bring_up has to"
        );
        let cfg = crate::firecracker_config::FirecrackerConfig::without_devices();
        let restored = bring_up(&sock2, &cfg, Some(&base), Some(&jail)).await;
        // Let the restored guest run and dirty its memory before checking the base.
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let after = std::fs::read(&base.mem).expect("base mem still readable");
        let alive = vm2.try_wait().expect("try_wait").is_none();
        let _ = vm2.kill().await;

        restored.expect("a base this code published must be one this code restores");
        assert!(alive, "the restored VMM must still be running");
        assert_eq!(
            before, after,
            "a restored guest must not write through to the shared base — every later clone \
             depends on it being unchanged"
        );
    }

    /// A foreign-host refusal names BOTH machines.
    ///
    /// The entire reason cross-host is a refusal rather than a cache miss is that somebody can
    /// read it and see which two hosts disagree. A message naming one of them is a miss with
    /// extra steps.
    #[test]
    fn a_foreign_host_refusal_names_both_machines() {
        let rendered = NoBase::ForeignHost {
            taken_on: HostIdentity {
                arch: "x86_64".into(),
                cpu_model: "some other silicon".into(),
            },
            running_on: HostIdentity {
                arch: "aarch64".into(),
                cpu_model: "this silicon".into(),
            },
        }
        .to_string();
        assert!(rendered.contains("some other silicon"), "{rendered}");
        assert!(rendered.contains("this silicon"), "{rendered}");
    }
}
