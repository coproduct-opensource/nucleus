//! Holding a pod's boot artifacts to the digests its spec pinned.
//!
//! # Why this measures the jail, not the source
//!
//! `admit_posture` already measures a rootfs, ~1300 lines before `prepare_jail` places it. That
//! gap is a window: anything that swaps the file in between is measured as one thing and booted
//! as another. Verifying the **placed** artifact closes it without needing `linkat`,
//! `CAP_DAC_READ_SEARCH`, or holding an fd across the whole launch — `place_resource` hard-links
//! the host file into the jail, so the in-jail path is the same inode, and where it has to fall
//! back to a copy, the copy is what boots. Either way, the bytes measured here are the bytes the
//! VM gets.
//!
//! Unjailed there is nothing to place: the host path IS what boots, so it is measured directly.
//! That leaves the pre-existing window between measurement and `exec` — the same one `posture.rs`
//! lives with, and named here rather than papered over.
//!
//! # Absent is not a failure
//!
//! A spec that pins nothing is every spec written before these fields existed, so absence cannot
//! refuse without breaking all of them. What absence costs is the check itself: the node has no
//! statement to hold the bytes to. A pin that is PRESENT is always enforced.

use std::path::{Path, PathBuf};

use nucleus_spec::{ArtifactDigest, ImageSpec};

use crate::firecracker_config::{JailLayout, in_jail};

/// One artifact to check: what it is called, where it now lives, and what it should hash to.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Pinned<'a> {
    what: &'static str,
    path: PathBuf,
    expected: &'a ArtifactDigest,
}

/// Resolve the pins to the paths that will actually boot.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn pins<'a>(image: &'a ImageSpec, jail: Option<&JailLayout>) -> Vec<Pinned<'a>> {
    // In the jail every artifact has a fixed name; unjailed, the spec's own path is used.
    let at = |in_jail_name: &str, host: &Path| -> PathBuf {
        match jail {
            Some(j) => j.jail_root.join(in_jail_name.trim_start_matches('/')),
            None => host.to_path_buf(),
        }
    };
    let mut out = Vec::new();
    if let Some(d) = &image.kernel_digest {
        out.push(Pinned {
            what: "kernel",
            path: at(in_jail::KERNEL, &image.kernel_path),
            expected: d,
        });
    }
    if let Some(d) = &image.rootfs_digest {
        out.push(Pinned {
            what: "rootfs",
            path: at(in_jail::ROOTFS, &image.rootfs_path),
            expected: d,
        });
    }
    if let (Some(d), Some(scratch)) = (&image.scratch_digest, &image.scratch_path) {
        out.push(Pinned {
            what: "scratch",
            path: at(in_jail::SCRATCH, scratch),
            expected: d,
        });
    }
    // The data image matters most of the three to check AFTER placement: it is the one artifact a
    // pod may share with other pods, and its digest is in the program identity, so bytes that do
    // not match the pin would give this pod another pod's identity.
    if let (Some(d), Some(data)) = (&image.data_digest, &image.data_path) {
        out.push(Pinned {
            what: "data",
            path: at(in_jail::DATA, data),
            expected: d,
        });
    }
    out
}

/// Measure every pinned artifact and refuse on any mismatch.
///
/// Uses the same `measure_artifact` the launch attestation uses, so the digest a spec pins, the
/// digest an attestation reports, and the digest a posture claim is admitted against are one
/// function's output and cannot drift apart.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) async fn verify(image: &ImageSpec, jail: Option<&JailLayout>) -> Result<(), String> {
    for p in pins(image, jail) {
        let measured = nucleus_identity::attestation::measure_artifact(&p.path)
            .await
            .map_err(|e| format!("cannot measure the {} at {}: {e}", p.what, p.path.display()))?;
        let measured_hex = hex::encode(measured);
        if measured_hex != p.expected.hex() {
            return Err(format!(
                "the {} that would boot does not match the digest this pod pinned: \
                 {} says sha-256:{measured_hex}, the spec pinned {}",
                p.what,
                p.path.display(),
                p.expected.as_str()
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(kernel: &Path, kd: Option<&str>) -> ImageSpec {
        ImageSpec {
            kernel_path: kernel.to_path_buf(),
            rootfs_path: PathBuf::from("/unused/rootfs.ext4"),
            boot_args: None,
            read_only: false,
            scratch_path: None,
            kernel_digest: kd.map(|d| ArtifactDigest::parse(d).expect("test digest parses")),
            rootfs_digest: None,
            scratch_digest: None,
            data_path: None,
            data_digest: None,
        }
    }

    /// A spec that pins nothing is checked against nothing — and must not fail for it.
    ///
    /// This is every spec written before the fields existed. Note the paths here do not exist:
    /// that is the point, since nothing should be opened when nothing is pinned.
    #[tokio::test]
    async fn an_unpinned_image_is_not_a_failure() {
        let img = image(Path::new("/nonexistent/vmlinux"), None);
        assert!(verify(&img, None).await.is_ok());
    }

    /// A pin that matches passes, measured with the same function the attestation uses.
    #[tokio::test]
    async fn a_matching_pin_passes() {
        let dir = tempfile::tempdir().unwrap();
        let k = dir.path().join("vmlinux");
        std::fs::write(&k, b"kernel bytes").unwrap();
        let digest = hex::encode(
            nucleus_identity::attestation::measure_artifact(&k)
                .await
                .unwrap(),
        );
        let img = image(&k, Some(&format!("sha-256:{digest}")));
        verify(&img, None).await.expect("a matching pin must pass");
    }

    /// A pin that does not match refuses, and the message names both digests.
    ///
    /// Both, because "digest mismatch" alone sends an operator to compare two things they cannot
    /// see; the whole value of a pin is being able to say which artifact turned up.
    #[tokio::test]
    async fn a_mismatched_pin_refuses_and_names_both_digests() {
        let dir = tempfile::tempdir().unwrap();
        let k = dir.path().join("vmlinux");
        std::fs::write(&k, b"not the kernel you pinned").unwrap();
        let wrong = format!("sha-256:{}", "ab".repeat(32));
        let img = image(&k, Some(&wrong));

        let err = verify(&img, None)
            .await
            .expect_err("a wrong digest must refuse the launch");
        assert!(err.contains("kernel"), "{err}");
        assert!(err.contains(&"ab".repeat(32)), "the pinned digest: {err}");
        assert!(
            err.contains("sha-256:")
                && !err.contains(&format!("sha-256:{}", "ab".repeat(32) + "x")),
            "the measured digest: {err}"
        );
    }

    /// A pinned artifact that is not there is a refusal, not a pass.
    #[tokio::test]
    async fn a_pinned_artifact_that_is_missing_refuses() {
        let img = image(
            Path::new("/nonexistent/vmlinux"),
            Some(&format!("sha-256:{}", "cd".repeat(32))),
        );
        let err = verify(&img, None).await.expect_err("missing must refuse");
        assert!(err.contains("cannot measure"), "{err}");
    }
}
