//! A workspace goes into a microVM as an ext4 image and comes back out as a tree.
//!
//! A microVM has no host-directory mount, so the only way a tree reaches the
//! guest's `/work` is as the block device behind it: the pod's scratch disk.
//! [`seed`] builds that disk from a directory and returns the digest a spec pins
//! as `image.scratch_digest`; [`harvest`] reads the guest's result back out.
//!
//! # One measurement
//!
//! The digest comes from `nucleus_identity::attestation::measure_artifact`, the
//! function the node holds `scratch_digest` to after placing the image in the
//! jail. A second hash here would be a second decider for the same fact, free to
//! drift from the one the node enforces.
//!
//! # Owned by the workload
//!
//! The workload runs unprivileged, so a tree seeded with the host's ownership
//! can be read in the guest and not edited. [`seed`] therefore does not hand
//! mke2fs the directory: it writes the tree as a normalized tar with every
//! entry owned by `owner` (see [`crate::ext4`]'s `tree_tar`), and builds the
//! image from that. The same step makes the image a function of the tree's
//! content and modes alone, not of when or where it was checked out.
//!
//! # Where the image must live
//!
//! The node admits a caller-supplied scratch image only from inside its
//! `--scratch-root`, so [`seed`]'s `image` belongs there. The staging tar is
//! written beside it and removed.

use std::path::Path;

use nucleus_spec::ArtifactDigest;

use crate::ext4::{self, Ext4Error, Ext4Input, Ext4Spec, RootOwner, tree_tar};
use crate::scratch_readback::{self, ReadbackError};

/// Free inodes per free MiB: ext4's default ratio of one per 16 KiB, so the
/// workload can create files as well as grow them.
const INODES_PER_FREE_MIB: u32 = 64;

/// Build an ext4 image at `image` holding `tree`, every entry owned by `owner`
/// (the workload's uid:gid), with `free_mib` MiB of room beyond the content,
/// and return its digest in the form `image.scratch_digest` takes.
///
/// The image's UUID is derived from the staging tar's digest, so the same tree
/// seeded twice is the same image, and the digest can be computed ahead of
/// the pod. `image` must not already exist: overwriting a file is never what
/// seeding means, and it may be a scratch disk a running pod still has.
pub async fn seed(
    tree: &Path,
    image: &Path,
    owner: RootOwner,
    free_mib: u32,
) -> Result<ArtifactDigest, Ext4Error> {
    if !tree.is_dir() {
        return Err(Ext4Error::Refused(format!(
            "{} is not a directory",
            tree.display()
        )));
    }
    if image.exists() {
        return Err(Ext4Error::Refused(format!("{} exists", image.display())));
    }
    let entries = tree_tar::walk(tree)?;
    let beside = match image.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tar = tempfile::Builder::new()
        .prefix(".nucleus-seed-")
        .suffix(".tar")
        .tempfile_in(beside)
        .map_err(|e| Ext4Error::Io(format!("staging tar in {}: {e}", beside.display())))?;
    let digest = tree_tar::emit(
        tree,
        &entries,
        owner,
        std::io::BufWriter::new(tar.as_file()),
    )?;
    let spec = Ext4Spec {
        seed: digest,
        owner,
        extra_mib: free_mib,
        extra_inodes: free_mib.saturating_mul(INODES_PER_FREE_MIB),
    };
    ext4::build(Ext4Input::Tar(tar.path()), image, spec).await
}

/// Read the whole filesystem in `image` back out into `out`, replaying the
/// journal first.
///
/// A microVM is ended by being killed, so what the guest last wrote can sit
/// committed in the journal and not yet in the filesystem; reading without the
/// replay would return the tree as it was before those writes. `out` is created
/// and must be empty, so a harvest never merges into something already there.
///
/// Precondition: no VMM has the image open (see [`scratch_readback::read_file`]).
pub fn harvest(image: &Path, out: &Path) -> Result<(), ReadbackError> {
    std::fs::create_dir_all(out)
        .map_err(|e| ReadbackError::Failed(format!("creating {}: {e}", out.display())))?;
    let empty = std::fs::read_dir(out)
        .map_err(|e| ReadbackError::Failed(format!("reading {}: {e}", out.display())))?
        .next()
        .is_none();
    if !empty {
        return Err(ReadbackError::Failed(format!(
            "{} is not empty; a harvest does not merge",
            out.display()
        )));
    }
    scratch_readback::dump_tree(image, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    /// The workload uid:gid the guest runs as by default.
    const WORKLOAD: RootOwner = RootOwner {
        uid: 65534,
        gid: 65534,
    };

    /// A seed builds from a tar, so these need what `ext4` needs for one.
    fn have_e2fsprogs() -> bool {
        crate::ext4::tests::tar_capable()
    }

    /// Every regular file under `root`, by relative path, with its bytes.
    fn snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("readable") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    let rel = path.strip_prefix(root).expect("under root").to_path_buf();
                    out.insert(rel, std::fs::read(&path).expect("file"));
                }
            }
        }
        out
    }

    fn tree(dir: &Path) -> PathBuf {
        let t = dir.join("tree");
        std::fs::create_dir_all(t.join("src/nested")).expect("dirs");
        std::fs::write(t.join("README"), b"a workspace\n").expect("file");
        std::fs::write(t.join("src/lib.rs"), b"pub fn f() {}\n").expect("file");
        std::fs::write(t.join("src/nested/data.bin"), vec![0xA5u8; 10_000]).expect("file");
        t
    }

    #[tokio::test]
    async fn seed_then_harvest_returns_the_same_tree() {
        if !have_e2fsprogs() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let t = tree(dir.path());
        let image = dir.path().join("ws.ext4");
        let digest = seed(&t, &image, WORKLOAD, 16).await.expect("seed");

        // The digest is the node's own measurement of the file.
        let measured = nucleus_identity::attestation::measure_artifact(&image)
            .await
            .expect("measure");
        assert_eq!(digest.hex(), hex::encode(measured));

        let out = dir.path().join("out");
        harvest(&image, &out).expect("harvest");
        assert_eq!(snapshot(&out), snapshot(&t));
        assert!(
            !snapshot(&t).is_empty(),
            "an empty tree would prove nothing"
        );
        assert!(
            !out.join("lost+found").exists(),
            "mkfs noise is not workspace"
        );
    }

    #[tokio::test]
    async fn seed_refuses_to_overwrite_and_to_seed_a_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let t = tree(dir.path());
        let image = dir.path().join("exists.ext4");
        std::fs::write(&image, b"a running pod's disk").expect("file");
        assert!(matches!(
            seed(&t, &image, WORKLOAD, 16).await,
            Err(Ext4Error::Refused(_))
        ));
        assert_eq!(
            std::fs::read(&image).expect("kept"),
            b"a running pod's disk"
        );
        assert!(matches!(
            seed(&image, &dir.path().join("new.ext4"), WORKLOAD, 16).await,
            Err(Ext4Error::Refused(_))
        ));
    }

    /// The spike's finding: a seed owned by the host's uid can be read by the
    /// workload and not edited. Every entry, not just the root, must be the
    /// workload's.
    #[tokio::test]
    async fn every_seeded_entry_is_owned_by_the_workload() {
        if !have_e2fsprogs() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let t = tree(dir.path());
        let image = dir.path().join("ws.ext4");
        seed(&t, &image, WORKLOAD, 16).await.expect("seed");
        let paths = [
            "/",
            "/README",
            "/src",
            "/src/lib.rs",
            "/src/nested",
            "/src/nested/data.bin",
        ];
        for guest in paths {
            let out = std::process::Command::new("debugfs")
                .args(["-R", &format!("stat {guest}")])
                .arg(&image)
                .output()
                .expect("debugfs");
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(
                text.contains("User: 65534   Group: 65534"),
                "{guest} is not the workload's: {text}"
            );
        }
        // The staging tar is gone; only the image and its record remain.
        let mut left: Vec<_> = std::fs::read_dir(dir.path())
            .expect("dir")
            .map(|e| e.expect("entry").file_name().into_string().expect("utf8"))
            .collect();
        left.sort();
        assert_eq!(left, ["tree", "ws.ext4", "ws.ext4.provenance.json"]);
    }

    #[test]
    fn harvest_does_not_merge_into_a_populated_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("already"), b"x").expect("file");
        let err = harvest(&dir.path().join("none.ext4"), dir.path()).expect_err("refused");
        assert!(err.to_string().contains("not empty"), "{err}");
    }

    /// A guest killed after committing a write leaves it in the journal only.
    /// The harvest must return the NEW bytes; without the replay it returns the
    /// old ones, so this is red if the replay is skipped.
    ///
    /// The dirty journal is made with debugfs' own journal commands (`jo`, `jw`,
    /// `jc`), which write a committed transaction without checkpointing it — the
    /// state an unclean kill leaves.
    #[tokio::test]
    async fn a_dirty_journal_harvests_the_committed_bytes() {
        if !have_e2fsprogs() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let t = dir.path().join("tree");
        std::fs::create_dir_all(&t).expect("tree");
        std::fs::write(t.join("f"), vec![b'A'; 4096]).expect("old bytes");
        let image = dir.path().join("ws.ext4");
        seed(&t, &image, WORKLOAD, 16).await.expect("seed");

        // Where `f`'s first block lives.
        let bmap = std::process::Command::new("debugfs")
            .args(["-R", "bmap /f 0"])
            .arg(&image)
            .output()
            .expect("debugfs bmap");
        let block: u64 = String::from_utf8_lossy(&bmap.stdout)
            .trim()
            .parse()
            .expect("a block number");

        // Commit a transaction rewriting that block to 'B', and do not checkpoint.
        let newer = dir.path().join("newer");
        std::fs::write(&newer, vec![b'B'; 4096]).expect("new bytes");
        let script = dir.path().join("cmds");
        std::fs::write(
            &script,
            format!("jo\njw -b {block} {}\njc\n", newer.display()),
        )
        .expect("script");
        let jw = std::process::Command::new("debugfs")
            .arg("-w")
            .arg("-f")
            .arg(&script)
            .arg(&image)
            .output()
            .expect("debugfs journal write");
        assert!(
            jw.status.success(),
            "{}",
            String::from_utf8_lossy(&jw.stderr)
        );

        // Non-vacuity: before replay the filesystem still reads the OLD bytes.
        let dumped = dir.path().join("before");
        let pre = std::process::Command::new("debugfs")
            .args(["-R", &format!("dump /f {}", dumped.display())])
            .arg(&image)
            .output()
            .expect("debugfs dump");
        assert!(pre.status.success());
        assert_eq!(
            std::fs::read(&dumped).expect("dumped"),
            vec![b'A'; 4096],
            "the write must be in the journal only, or this proves nothing"
        );

        let out = dir.path().join("out");
        harvest(&image, &out).expect("harvest");
        assert_eq!(
            std::fs::read(out.join("f")).expect("harvested"),
            vec![b'B'; 4096]
        );
    }
}
