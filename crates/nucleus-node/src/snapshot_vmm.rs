//! Taking and restoring Firecracker snapshots, behind the safety verdict.
//!
//! [`crate::snapshot`] decides WHETHER a microVM may be a base; this does the taking. They are
//! apart because the decision is pure and heavily tested, and the taking is four HTTP calls on a
//! Unix socket — and because a snapshot routine that also decided its own admissibility would be
//! the natural place for someone to add "just this once".
//!
//! # Measured, not assumed
//!
//! On the pinned Firecracker (v1.16.1, aarch64/KVM), a 256 MiB guest:
//!
//! | step | measured |
//! |---|---|
//! | `PATCH /vm {Paused}` + `PUT /snapshot/create` | ~480 ms |
//! | `PUT /snapshot/load` (File backend) | ~5 ms |
//! | `PATCH /vm {Resumed}` | ~4 ms |
//!
//! Restore is ~10 ms against a cold boot, which is the entire case for doing this. Create costs
//! ~480 ms because it writes the whole guest memory to disk — roughly 3× what
//! `snapshot.rs`'s docs estimated, and the reason create belongs on a base-building path rather
//! than on every pod.
//!
//! # Why the File backend
//!
//! UFFD would let many clones share one memory image and page in lazily. It also adds a
//! privileged process inside the chroot whose *crash is a hang* — every guest fault blocks
//! forever — and none of the 10 ms above needs it. So: File now, UFFD when there is a density
//! problem to point at.

use std::path::Path;

use crate::firecracker_api;
use crate::snapshot::SnapshotSafety;

/// Where a snapshot's two files live.
///
/// Two, because Firecracker separates them: `vmstate` is small (kilobytes — device and vCPU
/// state) while `mem` is the whole guest memory. Restore maps the second rather than reading it,
/// which is why restore is milliseconds and create is not.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) struct SnapshotArtifacts {
    /// Device and vCPU state.
    pub vmstate: std::path::PathBuf,
    /// The guest memory image.
    pub mem: std::path::PathBuf,
}

/// Pause a running microVM and write a full snapshot, if it is safe to clone from.
///
/// The verdict is taken as an argument rather than computed here, so that the caller has to have
/// obtained one — there is no path through this function that skips it.
///
/// # Errors
///
/// The verdict, rendered, when it is not `SafeToClone`; otherwise whatever the VMM refused.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) async fn create(
    sock: &Path,
    safety: &SnapshotSafety,
    out: &SnapshotArtifacts,
) -> Result<(), String> {
    if !safety.is_safe_to_clone() {
        return Err(format!("refusing to snapshot this microVM: {safety}"));
    }
    // Paused first, and this is not merely tidy: `/snapshot/create` on a running VM is refused
    // by Firecracker, and a config-file launch never offers a moment to ask — which is the whole
    // reason the API path exists.
    firecracker_api::send(sock, &firecracker_api::patch_vm("Paused")).await?;
    firecracker_api::send(
        sock,
        &firecracker_api::put_json(
            "/snapshot/create",
            &serde_json::json!({
                "snapshot_type": "Full",
                "snapshot_path": out.vmstate,
                "mem_file_path": out.mem,
            }),
        ),
    )
    .await
}

/// Load a snapshot into a VMM that has been started with an API socket and nothing else.
///
/// Deliberately does NOT resume: whatever is per-pod about this clone — its tap device, its
/// vsock path — has to be patched between load and resume, and a function that did both would
/// leave no seam to do it in.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) async fn load(sock: &Path, artifacts: &SnapshotArtifacts) -> Result<(), String> {
    firecracker_api::send(
        sock,
        &firecracker_api::put_json(
            "/snapshot/load",
            &serde_json::json!({
                "snapshot_path": artifacts.vmstate,
                "mem_backend": { "backend_path": artifacts.mem, "backend_type": "File" },
                "resume_vm": false,
            }),
        ),
    )
    .await
}

/// Resume a loaded snapshot's vCPUs.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) async fn resume(sock: &Path) -> Result<(), String> {
    firecracker_api::send(sock, &firecracker_api::patch_vm("Resumed")).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifacts() -> SnapshotArtifacts {
        SnapshotArtifacts {
            vmstate: "/unused/vmstate".into(),
            mem: "/unused/mem".into(),
        }
    }

    /// Every refusal reaches the caller, and none of them touches the socket.
    ///
    /// The path here does not exist, which is the assertion: a verdict that let execution reach
    /// the VMM would fail with a connection error instead of the reason, and the reason is the
    /// thing worth reporting.
    #[tokio::test]
    async fn an_unsafe_verdict_refuses_without_talking_to_the_vmm() {
        for verdict in [
            SnapshotSafety::PersonalizedSince,
            SnapshotSafety::NotAtBarrier,
            SnapshotSafety::WritableScratchAttached,
            SnapshotSafety::WouldDuplicateSecret {
                key: "nucleus.auth_secret".into(),
            },
        ] {
            let err = create(
                Path::new("/nonexistent/nucleus-test/fc.socket"),
                &verdict,
                &artifacts(),
            )
            .await
            .expect_err("an unsafe verdict must refuse");
            assert!(
                err.starts_with("refusing to snapshot this microVM"),
                "the refusal must carry the verdict, not a socket error: {err}"
            );
            assert!(
                !err.contains("cannot connect"),
                "the verdict must be checked BEFORE the socket: {err}"
            );
        }
    }

    /// The real thing: boot, snapshot, restore into a second VMM, resume.
    ///
    /// Everything above tests the guard. This tests the protocol — and it is the only way to
    /// know, because the whole sequence is Firecracker refusing or not refusing in an order that
    /// no type can enforce (`create` on a running VM is rejected; `load` into a configured one
    /// is rejected; `resume` before `load` is rejected).
    ///
    /// Skips unless a KVM host with the pinned artifacts is present, so it is a no-op everywhere
    /// except where it can mean something. Point `NUCLEUS_TEST_ARTIFACTS` at a directory holding
    /// `vmlinux` and `rootfs.ext4`.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_real_microvm_snapshots_and_restores() {
        let Some(art) = std::env::var_os("NUCLEUS_TEST_ARTIFACTS").map(std::path::PathBuf::from)
        else {
            eprintln!("skipping: NUCLEUS_TEST_ARTIFACTS is not set");
            return;
        };
        let (kernel, rootfs) = (art.join("vmlinux"), art.join("rootfs.ext4"));
        // Openable, not merely present. `/dev/kvm` exists on any Linux with the module loaded,
        // while using it needs group membership or an ACL — and a VM restart resets a `chmod`.
        // Testing for existence alone turns "this host cannot run the test" into a failure that
        // reads like a code defect, which cost a debugging cycle to learn.
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

        let dir = tempfile::tempdir().expect("tempdir");
        let out = SnapshotArtifacts {
            vmstate: dir.path().join("vmstate"),
            mem: dir.path().join("mem"),
        };

        // ── boot ────────────────────────────────────────────────────────────────────────
        let sock1 = dir.path().join("fc1.socket");
        let mut vm1 = tokio::process::Command::new(&fc)
            .arg("--api-sock")
            .arg(&sock1)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("firecracker spawns");

        let booted = async {
            firecracker_api::wait_for_api_socket(&sock1).await?;
            firecracker_api::send(
                &sock1,
                &firecracker_api::put_json(
                    "/boot-source",
                    &serde_json::json!({
                        "kernel_image_path": kernel,
                        "boot_args": "console=ttyS0 reboot=k panic=1 pci=off",
                    }),
                ),
            )
            .await?;
            firecracker_api::send(
                &sock1,
                &firecracker_api::put_json(
                    "/drives/rootfs",
                    &serde_json::json!({
                        "drive_id": "rootfs", "path_on_host": rootfs,
                        "is_root_device": true, "is_read_only": true,
                    }),
                ),
            )
            .await?;
            firecracker_api::send(
                &sock1,
                &firecracker_api::put_json(
                    "/machine-config",
                    &serde_json::json!({"vcpu_count": 1, "mem_size_mib": 256}),
                ),
            )
            .await?;
            firecracker_api::send(&sock1, &crate::firecracker_config::instance_start_request())
                .await?;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            // The verdict a base has to carry. Passed in, never computed here.
            create(&sock1, &SnapshotSafety::SafeToClone, &out).await
        }
        .await;
        let _ = vm1.kill().await;
        booted.expect("boot and snapshot must succeed");

        let vmstate_len = std::fs::metadata(&out.vmstate)
            .expect("vmstate written")
            .len();
        let mem_len = std::fs::metadata(&out.mem).expect("mem written").len();
        assert!(vmstate_len > 0, "device state must not be empty");
        assert_eq!(
            mem_len,
            256 * 1024 * 1024,
            "the memory image is the whole guest memory, which is why create is the slow half"
        );

        // ── restore into a fresh VMM ────────────────────────────────────────────────────
        let sock2 = dir.path().join("fc2.socket");
        let mut vm2 = tokio::process::Command::new(&fc)
            .arg("--api-sock")
            .arg(&sock2)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("second firecracker spawns");

        let restored = async {
            firecracker_api::wait_for_api_socket(&sock2).await?;
            load(&sock2, &out).await?;
            resume(&sock2).await
        }
        .await;
        let _ = vm2.kill().await;
        restored.expect("a snapshot this code took must be one this code can restore");
    }

    /// A safe verdict does proceed to the VMM — otherwise the guard above proves nothing.
    #[tokio::test]
    async fn a_safe_verdict_proceeds_to_the_socket() {
        let err = create(
            Path::new("/nonexistent/nucleus-test/fc.socket"),
            &SnapshotSafety::SafeToClone,
            &artifacts(),
        )
        .await
        .expect_err("there is no VMM at that path");
        assert!(
            err.contains("cannot connect"),
            "a safe verdict must get as far as the socket: {err}"
        );
    }
}
