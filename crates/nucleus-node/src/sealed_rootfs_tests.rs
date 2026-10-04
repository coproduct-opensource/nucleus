use super::*;

fn sealed() -> Seal {
    Seal {
        dev: 2049,
        ino: 131,
        ctime_sec: 1_790_957_349,
        ctime_nsec: 178_714_780,
        immutable: true,
    }
}

/// The reuse condition, field by field. Each row is a way the bytes could have changed since
/// the measurement, and each must refuse reuse.
#[test]
fn a_seal_is_reused_only_while_every_field_holds() {
    let s = sealed();
    assert!(still_sealed(&s, &s), "an untouched seal is reused");

    let cases: [(&str, Seal); 5] = [
        // `chattr -i`, write, and NOT re-sealed.
        (
            "flag cleared",
            Seal {
                immutable: false,
                ..s
            },
        ),
        // `chattr -i`, write, `chattr +i`: the flag is back, the ctime is not.
        (
            "ctime moved",
            Seal {
                ctime_nsec: s.ctime_nsec + 1,
                ..s
            },
        ),
        (
            "ctime moved by seconds",
            Seal {
                ctime_sec: s.ctime_sec + 1,
                ..s
            },
        ),
        (
            "another inode",
            Seal {
                ino: s.ino + 1,
                ..s
            },
        ),
        (
            "another device",
            Seal {
                dev: s.dev + 1,
                ..s
            },
        ),
    ];
    for (why, now) in cases {
        assert!(!still_sealed(&s, &now), "{why}: must not be reused");
    }

    let never = Seal {
        immutable: false,
        ..s
    };
    assert!(
        !still_sealed(&never, &never),
        "a record that was never immutable proves nothing, however well it matches"
    );
}

/// The tests below need a real kernel, root (for `CAP_LINUX_IMMUTABLE` and `chown`) and a
/// filesystem with reflink, which is what production runs on and no CI runner has. They are
/// run on a throwaway machine with
/// `NUCLEUS_SEALED_ROOTFS_TEST_DIR=/srv/x cargo test -p nucleus-node sealed_rootfs -- --ignored`.
#[cfg(target_os = "linux")]
mod on_a_reflink_filesystem {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;

    const NEEDS: &str = "needs root and NUCLEUS_SEALED_ROOTFS_TEST_DIR on a reflink filesystem";

    fn base() -> tempfile::TempDir {
        let dir = std::env::var_os("NUCLEUS_SEALED_ROOTFS_TEST_DIR").expect(NEEDS);
        tempfile::tempdir_in(dir).expect("a scratch dir on the reflink filesystem")
    }

    fn write(p: &Path, bytes: &[u8]) {
        let mut f = std::fs::File::create(p).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
    }

    fn pin_of(bytes: &[u8]) -> nucleus_spec::ArtifactDigest {
        let d = nucleus_identity::attestation::hash_bytes(bytes);
        nucleus_spec::ArtifactDigest::parse(&format!("sha-256:{}", hex::encode(d))).unwrap()
    }

    fn me() -> (u32, u32) {
        let m = std::fs::metadata("/proc/self").unwrap();
        (m.uid(), m.gid())
    }

    /// A jail rootfs as `prepare_jail` leaves it: a hard link of the source.
    fn hard_linked(source: &Path, jail: &Path) -> PathBuf {
        std::fs::create_dir_all(jail).unwrap();
        let dest = jail.join("rootfs.ext4");
        std::fs::hard_link(source, &dest).unwrap();
        dest
    }

    /// Rewrite in place keeping size and mtime: gatehouse F-161, and what a stat cache misses.
    fn rewrite_preserving_mtime(p: &Path, bytes: &[u8]) {
        let before = std::fs::metadata(p).unwrap();
        let mut f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
        f.set_times(std::fs::FileTimes::new().set_modified(before.modified().unwrap()))
            .unwrap();
        let after = std::fs::metadata(p).unwrap();
        assert_eq!(
            (
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec()
            ),
            (after.ino(), after.len(), after.mtime(), after.mtime_nsec())
        );
    }

    /// The saving, and what it rests on. The second pod is served from the sealed copy, and
    /// the source being rewritten in place afterwards -- stat preserved -- cannot reach it:
    /// every pod still boots the PINNED bytes.
    #[tokio::test]
    #[ignore = "needs root and NUCLEUS_SEALED_ROOTFS_TEST_DIR on a reflink filesystem"]
    async fn later_pods_boot_the_pinned_bytes_without_another_read() {
        let b = base();
        let source = b.path().join("catalog-rootfs.ext4");
        write(&source, b"the pinned rootfs");
        let pin = pin_of(b"the pinned rootfs");
        let store = SealedRootfs::open(&b.path().join("sealed")).unwrap();

        for pod in ["a", "b"] {
            let dest = hard_linked(&source, &b.path().join(pod));
            let m = store
                .place(&source, &pin, &dest, me())
                .await
                .expect("sealed");
            assert_eq!(hex::encode(m.measured), pin.hex());
            assert_eq!(std::fs::read(&dest).unwrap(), b"the pinned rootfs");
            assert_ne!(
                std::fs::metadata(&dest).unwrap().ino(),
                std::fs::metadata(&source).unwrap().ino(),
                "the jail holds its own inode, not the shared one"
            );
        }
        assert_eq!(store.entries.lock().await.len(), 1, "sealed once");

        rewrite_preserving_mtime(&source, b"poisoned  rootfs!");
        let dest = hard_linked(&source, &b.path().join("c"));
        let m = store
            .place(&source, &pin, &dest, me())
            .await
            .expect("sealed");
        assert_eq!(hex::encode(m.measured), pin.hex());
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"the pinned rootfs",
            "a pod is placed from the sealed copy, never from the source again"
        );
    }

    /// The seal itself: the kernel refuses every way of changing the sealed copy.
    #[tokio::test]
    #[ignore = "needs root and NUCLEUS_SEALED_ROOTFS_TEST_DIR on a reflink filesystem"]
    async fn the_sealed_copy_refuses_writes_links_and_unlinks_even_from_root() {
        let b = base();
        let source = b.path().join("rootfs.ext4");
        write(&source, b"bytes");
        let store = SealedRootfs::open(&b.path().join("sealed")).unwrap();
        let dest = hard_linked(&source, &b.path().join("a"));
        store
            .place(&source, &pin_of(b"bytes"), &dest, me())
            .await
            .expect("sealed");
        let path = store.entries.lock().await[0].path.clone();

        let denied = |r: std::io::Result<()>, what: &str| {
            let e = r.expect_err(what);
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied,
                "{what}: {e}"
            );
        };
        denied(
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .map(drop),
            "open for write",
        );
        denied(
            std::fs::hard_link(&path, b.path().join("again")),
            "hard link",
        );
        denied(std::fs::remove_file(&path), "unlink");
        denied(std::fs::rename(&path, b.path().join("moved")), "rename");
    }

    /// THE PERTURBATION. Someone with `CAP_LINUX_IMMUTABLE` lifts the seal, rewrites the
    /// sealed copy keeping size and mtime, and puts the seal back. The next pod must not get
    /// the old measurement: it is sealed afresh from the source, and boots the source's bytes.
    /// Drop `ctime` from `still_sealed` and this goes red.
    #[tokio::test]
    #[ignore = "needs root and NUCLEUS_SEALED_ROOTFS_TEST_DIR on a reflink filesystem"]
    async fn a_seal_lifted_and_restored_is_not_reused() {
        let b = base();
        let source = b.path().join("rootfs.ext4");
        write(&source, b"good rootfs");
        let pin = pin_of(b"good rootfs");
        let store = SealedRootfs::open(&b.path().join("sealed")).unwrap();
        let dest = hard_linked(&source, &b.path().join("a"));
        store
            .place(&source, &pin, &dest, me())
            .await
            .expect("sealed");

        let (path, ino) = {
            let e = &store.entries.lock().await[0];
            sys::set_immutable(&e.file, false).unwrap();
            rewrite_preserving_mtime(&e.path, b"evil rootfs");
            sys::set_immutable(&e.file, true).unwrap();
            (e.path.clone(), e.seal.ino)
        };
        assert_eq!(std::fs::read(&path).unwrap(), b"evil rootfs");

        let dest = hard_linked(&source, &b.path().join("b"));
        let m = store
            .place(&source, &pin, &dest, me())
            .await
            .expect("sealed again");
        assert_eq!(hex::encode(m.measured), pin.hex());
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"good rootfs",
            "the tampered copy must never be cloned into a jail"
        );
        assert_ne!(
            store.entries.lock().await[0].seal.ino,
            ino,
            "a fresh seal, not the old one"
        );
        assert!(!path.exists(), "the tampered copy is discarded");
    }

    /// A pod that writes its rootfs writes its own clone, and nothing any other pod boots.
    #[tokio::test]
    #[ignore = "needs root and NUCLEUS_SEALED_ROOTFS_TEST_DIR on a reflink filesystem"]
    async fn a_pod_writing_its_rootfs_reaches_no_other_pod() {
        let b = base();
        let source = b.path().join("rootfs.ext4");
        write(&source, b"shared bytes");
        let pin = pin_of(b"shared bytes");
        let store = SealedRootfs::open(&b.path().join("sealed")).unwrap();
        let first = hard_linked(&source, &b.path().join("a"));
        store
            .place(&source, &pin, &first, me())
            .await
            .expect("sealed");
        let second = hard_linked(&source, &b.path().join("b"));
        store
            .place(&source, &pin, &second, me())
            .await
            .expect("sealed");

        // As a compromised VMM would: it owns its clone, so it can make it writable.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o600)).unwrap();
        write(&first, b"VMM was here");

        assert_eq!(std::fs::read(&second).unwrap(), b"shared bytes");
        assert_eq!(std::fs::read(&source).unwrap(), b"shared bytes");
        let e = &store.entries.lock().await[0];
        assert_eq!(std::fs::read(&e.path).unwrap(), b"shared bytes");
        assert!(still_sealed(&e.seal, &seal_of(&e.file).unwrap()));
    }

    /// A source that is not what its pin says is measured and reported, never placed or kept.
    #[tokio::test]
    #[ignore = "needs root and NUCLEUS_SEALED_ROOTFS_TEST_DIR on a reflink filesystem"]
    async fn a_source_that_does_not_match_its_pin_is_measured_not_placed() {
        let b = base();
        let source = b.path().join("rootfs.ext4");
        write(&source, b"not what was pinned");
        let store = SealedRootfs::open(&b.path().join("sealed")).unwrap();
        let dest = hard_linked(&source, &b.path().join("a"));
        let before = std::fs::metadata(&dest).unwrap().ino();

        let m = store
            .place(&source, &pin_of(b"what was pinned"), &dest, me())
            .await;
        assert_eq!(
            m.map(|e| e.measured),
            Some(nucleus_identity::attestation::hash_bytes(
                b"not what was pinned"
            ))
        );
        assert_eq!(
            std::fs::metadata(&dest).unwrap().ino(),
            before,
            "dest untouched"
        );
        assert!(
            store.entries.lock().await.is_empty(),
            "a mismatch is never kept"
        );
        assert_eq!(
            std::fs::read_dir(b.path().join("sealed")).unwrap().count(),
            0
        );
    }

    /// Without reflink between source and store nothing changes: `None`, and the jail keeps
    /// the hard link for `verify` to read as before.
    #[tokio::test]
    #[ignore = "needs root and NUCLEUS_SEALED_ROOTFS_TEST_DIR on a reflink filesystem"]
    async fn a_source_on_another_filesystem_falls_back_to_reading_it() {
        let b = base();
        let elsewhere = tempfile::tempdir().unwrap(); // the default temp dir, not the reflink fs
        let source = elsewhere.path().join("rootfs.ext4");
        write(&source, b"bytes");
        let store = SealedRootfs::open(&b.path().join("sealed")).unwrap();
        let jail = elsewhere.path().join("jail");
        let dest = hard_linked(&source, &jail);
        assert_eq!(
            store.place(&source, &pin_of(b"bytes"), &dest, me()).await,
            None
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"bytes");
        assert!(store.entries.lock().await.is_empty());
    }

    /// Nothing from a previous node life is trusted, or left behind.
    #[test]
    #[ignore = "needs root and NUCLEUS_SEALED_ROOTFS_TEST_DIR on a reflink filesystem"]
    fn open_discards_what_a_previous_life_sealed() {
        let b = base();
        let dir = b.path().join("sealed");
        std::fs::create_dir_all(&dir).unwrap();
        let stale = dir.join(format!("{}.0", "ab".repeat(32)));
        write(&stale, b"from before the restart");
        sys::set_immutable(&std::fs::File::open(&stale).unwrap(), true).unwrap();

        let _store = SealedRootfs::open(&dir).unwrap();
        assert!(!stale.exists());
    }

    /// The per-boot cost on a real-sized image, before and after: `prepare_jail`'s hard link
    /// plus `verify`'s full read, against `place` plus `verify` with the sealed measurement.
    /// Prints, asserts only that the answers agree. Run on the throwaway machine with
    /// `NUCLEUS_SEALED_ROOTFS_BENCH_IMAGE=/srv/x/rootfs.ext4` (same filesystem as the dir).
    #[tokio::test]
    #[ignore = "needs root, a reflink filesystem and NUCLEUS_SEALED_ROOTFS_BENCH_IMAGE"]
    async fn per_boot_cost_on_a_real_sized_image() {
        use crate::firecracker_config::JailLayout;
        let image =
            PathBuf::from(std::env::var_os("NUCLEUS_SEALED_ROOTFS_BENCH_IMAGE").expect(NEEDS));
        let pin_hash = nucleus_identity::attestation::measure_artifact(&image)
            .await
            .unwrap();
        let pin = format!("sha-256:{}", hex::encode(pin_hash));
        let host = crate::rootfs_source::HostImage::resolve(&nucleus_spec::ImageSpec {
            kernel_path: PathBuf::from("/unused/vmlinux"),
            rootfs: nucleus_spec::RootfsSource::Path(image.clone()),
            boot_args: None,
            read_only: true,
            scratch_path: None,
            kernel_digest: None,
            rootfs_digest: Some(nucleus_spec::ArtifactDigest::parse(&pin).unwrap()),
            scratch_digest: None,
            data_path: None,
            data_digest: None,
        })
        .unwrap();
        let b = base();
        let store = SealedRootfs::open(&b.path().join("sealed")).unwrap();
        let us = |t: std::time::Instant| t.elapsed().as_micros();

        for (i, sealed) in [false, false, false, true, true, true, true]
            .into_iter()
            .enumerate()
        {
            let jail = JailLayout {
                jail_root: b.path().join(format!("jail{i}")),
            };
            let dest = hard_linked(&image, &jail.jail_root);
            let t = std::time::Instant::now();
            let m = if sealed {
                store
                    .place(&image, host.rootfs_digest.as_ref().unwrap(), &dest, me())
                    .await
            } else {
                None
            };
            let placed = us(t);
            let v = crate::image_identity::verify(&host, Some(&jail), m)
                .await
                .expect("verifies");
            assert_eq!(v.rootfs, Some(pin_hash));
            eprintln!(
                "BENCH boot={i} sealed={sealed} place_us={placed} place+verify_us={}",
                us(t)
            );
        }
    }
}
