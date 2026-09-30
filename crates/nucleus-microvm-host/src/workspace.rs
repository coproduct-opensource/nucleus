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
//! # Where the image must live
//!
//! The node admits a caller-supplied scratch image only from inside its
//! `--scratch-root`, so [`seed`]'s `image` belongs there.

use std::path::Path;

use nucleus_spec::ArtifactDigest;

use crate::scratch_readback::{self, ReadbackError};

/// A mebibyte, in bytes.
const MIB: u64 = 1024 * 1024;

/// Why a seed did not produce an image.
#[derive(Debug)]
pub enum SeedError {
    /// `mkfs.ext4` is not installed.
    ToolMissing(String),
    /// The tree is not a directory, or the image already exists.
    Refused(String),
    /// `size_mib` does not fit in bytes.
    TooLarge(u64),
    /// I/O around `mkfs.ext4`.
    Io(String),
    /// `mkfs.ext4` ran and failed (the tree may not fit, for one).
    Failed(String),
}

impl std::fmt::Display for SeedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeedError::ToolMissing(e) => write!(
                f,
                "mkfs.ext4 is not available ({e}); install e2fsprogs to seed a workspace image"
            ),
            SeedError::Refused(why) => write!(f, "refusing to seed: {why}"),
            SeedError::TooLarge(mib) => write!(f, "{mib} MiB does not fit in a u64 byte count"),
            SeedError::Io(e) => write!(f, "seeding the workspace image: {e}"),
            SeedError::Failed(e) => write!(f, "mkfs.ext4 failed: {e}"),
        }
    }
}

impl std::error::Error for SeedError {}

/// Build an ext4 image of `size_mib` MiB at `image` holding `tree`, and return its
/// digest in the form `image.scratch_digest` takes.
///
/// `image` must not already exist: overwriting a file is never what seeding means,
/// and it may be a scratch disk a running pod still has.
pub async fn seed(tree: &Path, image: &Path, size_mib: u64) -> Result<ArtifactDigest, SeedError> {
    if !tree.is_dir() {
        return Err(SeedError::Refused(format!(
            "{} is not a directory",
            tree.display()
        )));
    }
    let bytes = size_mib
        .checked_mul(MIB)
        .ok_or(SeedError::TooLarge(size_mib))?;
    let file = std::fs::File::create_new(image)
        .map_err(|e| SeedError::Refused(format!("cannot create {} ({e})", image.display())))?;
    file.set_len(bytes)
        .map_err(|e| SeedError::Io(format!("sizing {}: {e}", image.display())))?;
    drop(file);

    let out = std::process::Command::new("mkfs.ext4")
        .args(["-q", "-F", "-d"])
        .arg(tree)
        .arg(image)
        .output();
    let failed = match out {
        Err(e) => Some(SeedError::ToolMissing(e.to_string())),
        Ok(o) if !o.status.success() => Some(SeedError::Failed(
            String::from_utf8_lossy(&o.stderr).trim().to_string(),
        )),
        Ok(_) => None,
    };
    if let Some(err) = failed {
        // A half-made image left behind would be refused by `create_new` on retry.
        let _ = std::fs::remove_file(image);
        return Err(err);
    }

    let digest = nucleus_identity::attestation::measure_artifact(image)
        .await
        .map_err(|e| SeedError::Io(format!("measuring {}: {e}", image.display())))?;
    ArtifactDigest::parse(&format!("sha-256:{}", hex::encode(digest))).map_err(SeedError::Io)
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

    fn have_e2fsprogs() -> bool {
        ["mkfs.ext4", "e2fsck", "debugfs"]
            .iter()
            .all(|t| std::process::Command::new(t).arg("-V").output().is_ok())
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
            eprintln!("skipping: e2fsprogs not installed");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let t = tree(dir.path());
        let image = dir.path().join("ws.ext4");
        let digest = seed(&t, &image, 16).await.expect("seed");

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
            seed(&t, &image, 16).await,
            Err(SeedError::Refused(_))
        ));
        assert_eq!(
            std::fs::read(&image).expect("kept"),
            b"a running pod's disk"
        );
        assert!(matches!(
            seed(&image, &dir.path().join("new.ext4"), 16).await,
            Err(SeedError::Refused(_))
        ));
        assert!(matches!(
            seed(&t, &dir.path().join("huge.ext4"), u64::MAX).await,
            Err(SeedError::TooLarge(_))
        ));
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
            eprintln!("skipping: e2fsprogs not installed");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let t = dir.path().join("tree");
        std::fs::create_dir_all(&t).expect("tree");
        std::fs::write(t.join("f"), vec![b'A'; 4096]).expect("old bytes");
        let image = dir.path().join("ws.ext4");
        seed(&t, &image, 16).await.expect("seed");

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
