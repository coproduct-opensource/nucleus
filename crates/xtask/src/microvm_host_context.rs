//! Stage the build contexts for the Apple Container host images.
//!
//! Both contexts are flat directories of explicitly named files, because Apple
//! Container 1.4.1 drops nested files from a directory `COPY` (#3206):
//!
//! - [`run`] stages the local recipe's prebuilt inputs and their manifest.
//! - [`run_release`] stages the release recipe (`microvm_host::IMAGE_SOURCE`)
//!   with the tracked workspace sources as one tarball its `ADD` unpacks.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use nucleus_spec::microvm_host::{self as pins, ArtifactSource, HostInput, HostInputManifest};
use nucleus_spec::tier2_artifacts;
use sha2::{Digest, Sha256};

use crate::guest_layer::{Arch, check_static_elf};

fn copy_input(source: &Path, target: &Path, mode: u32) -> Result<HostInput> {
    use std::os::unix::fs::PermissionsExt;
    let mut input = File::open(source).with_context(|| format!("reading {}", source.display()))?;
    ensure!(
        input.metadata()?.is_file(),
        "{} is not a regular file",
        source.display()
    );
    let mut output = File::create_new(target)?;
    let mut hash = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0u8; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        // Ext4 images are commonly sparse. Preserve zero extents so staging a
        // mostly empty multi-GiB image does not consume its full logical size.
        if buffer[..count].iter().all(|byte| *byte == 0) {
            output.seek(SeekFrom::Current(count as i64))?;
        } else {
            output.write_all(&buffer[..count])?;
        }
        hash.update(&buffer[..count]);
        bytes += count as u64;
    }
    output.set_len(bytes)?;
    output.set_permissions(fs::Permissions::from_mode(mode))?;
    output.sync_all()?;
    Ok(HostInput {
        sha256: hex::encode(hash.finalize()),
        bytes,
    })
}

/// A new staging directory beside `out`, which must not exist yet. Published
/// with [`publish`] only once everything is in it.
fn stage_beside(out: &Path) -> Result<tempfile::TempDir> {
    ensure!(
        !out.exists(),
        "output {} already exists; choose a new directory",
        out.display()
    );
    let parent = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    Ok(tempfile::Builder::new()
        .prefix(".nucleus-host-context-")
        .tempdir_in(parent)?)
}

fn publish(stage: tempfile::TempDir, out: &Path) -> Result<()> {
    fs::rename(stage.path(), out).with_context(|| format!("publishing {}", out.display()))?;
    println!("{}", out.display());
    Ok(())
}

pub(crate) fn run(bin_dir: &Path, kernel: &Path, rootfs: &Path, out: &Path) -> Result<()> {
    let stage = stage_beside(out)?;
    let mut inputs = BTreeMap::new();
    for name in pins::LOCAL_HOST_BINARIES {
        let destination = (*name).to_string();
        let path = stage.path().join(&destination);
        let input = copy_input(&bin_dir.join(name), &path, 0o755)?;
        check_static_elf(&fs::read(&path)?, Arch::Aarch64)
            .with_context(|| format!("host executable {name}"))?;
        inputs.insert(destination, input);
    }
    let kernel_input = copy_input(kernel, &stage.path().join("vmlinux"), 0o444)?;
    ensure!(
        kernel_input.sha256 == tier2_artifacts::KERNEL_AARCH64.sha256,
        "guest kernel digest differs from the pinned ARM64 kernel"
    );
    inputs.insert("vmlinux".into(), kernel_input);
    let rootfs_path = stage.path().join("rootfs.ext4");
    let rootfs_input = copy_input(rootfs, &rootfs_path, 0o444)?;
    let mut file = File::open(rootfs_path)?;
    file.seek(SeekFrom::Start(1024 + 56))?;
    let mut magic = [0u8; 2];
    file.read_exact(&mut magic)
        .context("guest rootfs has no ext superblock")?;
    ensure!(
        magic == [0x53, 0xef],
        "guest rootfs has no ext filesystem magic"
    );
    inputs.insert("rootfs.ext4".into(), rootfs_input);
    fs::write(
        stage.path().join("Containerfile"),
        pins::LOCAL_HOST_CONTAINERFILE,
    )?;
    fs::write(
        stage.path().join("manifest.json"),
        serde_json::to_vec_pretty(&HostInputManifest::new("aarch64", inputs))?,
    )?;
    publish(stage, out)
}

// ── the release recipe's context ─────────────────────────────────────

/// The tracked paths the release recipe's `cargo build` stages read: the
/// workspace manifest, lock, toolchain, cargo config and every member.
const RELEASE_SOURCE_PATHS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo",
    "crates",
];

/// The probe source the release recipe compiles, staged flat as its file name.
const KVM_PROBE_SOURCE: &str = "docker/kvm-probe.c";

/// Stage `microvm_host::IMAGE_SOURCE` and its inputs from `root` into `out`.
pub(crate) fn run_release(root: &Path, out: &Path) -> Result<()> {
    let files = tracked_files(root, RELEASE_SOURCE_PATHS)?;
    stage_release(root, &files, out)
}

/// The files git tracks under `paths`, relative to `root`.
fn tracked_files(root: &Path, paths: &[&str]) -> Result<Vec<PathBuf>> {
    let listed = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z", "--"])
        .args(paths)
        .output()
        .context("running git ls-files")?;
    ensure!(
        listed.status.success(),
        "git ls-files failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let text = String::from_utf8(listed.stdout).context("git ls-files output")?;
    Ok(text
        .split('\0')
        .filter(|f| !f.is_empty())
        .map(PathBuf::from)
        .collect())
}

fn stage_release(root: &Path, files: &[PathBuf], out: &Path) -> Result<()> {
    let ArtifactSource::LocalBuild { containerfile } = pins::IMAGE_SOURCE else {
        bail!("the release image is pinned by digest; there is no recipe to stage");
    };
    // A path with nothing tracked under it is a staging that matches nothing:
    // the build would fail later, far from the cause.
    for path in RELEASE_SOURCE_PATHS {
        ensure!(
            files.iter().any(|f| f.starts_with(path)),
            "nothing to stage under {path}"
        );
    }
    let stage = stage_beside(out)?;
    fs::copy(root.join(containerfile), stage.path().join("Containerfile"))
        .with_context(|| format!("staging {containerfile}"))?;
    let probe = Path::new(KVM_PROBE_SOURCE);
    fs::copy(
        root.join(probe),
        stage
            .path()
            .join(probe.file_name().context("probe file name")?),
    )
    .with_context(|| format!("staging {KVM_PROBE_SOURCE}"))?;
    write_source_archive(
        root,
        files,
        &stage.path().join(pins::RELEASE_SOURCE_ARCHIVE),
    )?;
    publish(stage, out)
}

/// A tar of `files` (relative to `root`), owned by root, keeping each file's
/// mode and modification time: the build's cargo cache compares mtimes, so
/// flattening them could let a cached artifact outlive a changed source.
fn write_source_archive(root: &Path, files: &[PathBuf], archive: &Path) -> Result<()> {
    let mut tar = tar::Builder::new(File::create_new(archive)?);
    for rel in files {
        let path = root.join(rel);
        let file = File::open(&path).with_context(|| format!("reading {}", path.display()))?;
        let meta = file.metadata()?;
        ensure!(meta.is_file(), "{} is not a regular file", path.display());
        let mut header = tar::Header::new_gnu();
        header.set_metadata_in_mode(&meta, tar::HeaderMode::Complete);
        header.set_uid(0);
        header.set_gid(0);
        header.set_username("root")?;
        header.set_groupname("root")?;
        tar.append_data(&mut header, rel, file)
            .with_context(|| format!("archiving {}", rel.display()))?;
    }
    tar.into_inner()?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_copy_preserves_bytes_length_digest_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let target = dir.path().join("target");
        let mut bytes = vec![0; 3 * 65536];
        bytes[65536..65540].copy_from_slice(b"data");
        fs::write(&source, &bytes).unwrap();
        let copied = copy_input(&source, &target, 0o444).unwrap();
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(copied.bytes, bytes.len() as u64);
        assert_eq!(copied.sha256, hex::encode(Sha256::digest(&bytes)));
        assert_eq!(
            fs::metadata(target).unwrap().permissions().mode() & 0o777,
            0o444
        );
    }

    #[test]
    fn missing_executables_leave_no_output_or_partial_context() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("context");
        assert!(
            run(
                dir.path(),
                Path::new("missing-kernel"),
                Path::new("missing-rootfs"),
                &out
            )
            .is_err()
        );
        assert!(!out.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// A fake tree with one file under each release source path and the
    /// recipe and probe the staging copies.
    fn release_tree() -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempfile::tempdir().unwrap();
        let ArtifactSource::LocalBuild { containerfile } = pins::IMAGE_SOURCE else {
            panic!("pinned image");
        };
        let mut files = Vec::new();
        for rel in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            ".cargo/config.toml",
            "crates/a/src/deep/lib.rs",
            containerfile,
            KVM_PROBE_SOURCE,
        ] {
            let path = dir.path().join(rel);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, rel).unwrap();
            if !rel.starts_with("docker/") {
                files.push(PathBuf::from(rel));
            }
        }
        (dir, files)
    }

    #[test]
    fn the_release_context_is_flat_and_carries_nested_sources_in_the_archive() {
        let (tree, files) = release_tree();
        let out = tree.path().join("ctx/out");
        stage_release(tree.path(), &files, &out).unwrap();
        let mut staged: Vec<String> = fs::read_dir(&out)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                assert!(
                    e.file_type().unwrap().is_file(),
                    "{:?} is not flat",
                    e.path()
                );
                e.file_name().to_string_lossy().into_owned()
            })
            .collect();
        staged.sort();
        assert_eq!(
            staged,
            ["Containerfile", "kvm-probe.c", pins::RELEASE_SOURCE_ARCHIVE]
        );
        let mut archive =
            tar::Archive::new(File::open(out.join(pins::RELEASE_SOURCE_ARCHIVE)).unwrap());
        let mut entries: Vec<(String, u64, String)> = archive
            .entries()
            .unwrap()
            .map(|e| {
                let mut e = e.unwrap();
                let path = e.path().unwrap().to_string_lossy().into_owned();
                let uid = e.header().uid().unwrap();
                let mut body = String::new();
                e.read_to_string(&mut body).unwrap();
                (path, uid, body)
            })
            .collect();
        entries.sort();
        assert_eq!(entries.len(), files.len());
        for (path, uid, body) in entries {
            assert_eq!(uid, 0, "{path}");
            assert_eq!(path, body, "{path} carried the wrong bytes");
        }
    }

    #[test]
    fn a_release_source_path_with_nothing_tracked_is_refused() {
        let (tree, files) = release_tree();
        let without_crates: Vec<PathBuf> = files
            .into_iter()
            .filter(|f| !f.starts_with("crates"))
            .collect();
        let out = tree.path().join("out");
        let err = stage_release(tree.path(), &without_crates, &out).unwrap_err();
        assert!(err.to_string().contains("crates"), "{err}");
        assert!(!out.exists());
    }

    #[test]
    fn existing_output_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("keep"), b"operator context").unwrap();
        assert!(
            run(
                Path::new("missing"),
                Path::new("missing"),
                Path::new("missing"),
                dir.path()
            )
            .is_err()
        );
        assert_eq!(
            fs::read(dir.path().join("keep")).unwrap(),
            b"operator context"
        );
    }
}
