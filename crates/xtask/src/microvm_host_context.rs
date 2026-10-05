//! Stage explicit local inputs for the Apple Container host image.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, ensure};
use nucleus_spec::{microvm_host as pins, tier2_artifacts};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::guest_layer::{Arch, check_static_elf};

#[derive(Serialize)]
struct Input {
    sha256: String,
    bytes: u64,
}

fn copy_input(source: &Path, target: &Path, mode: u32) -> Result<Input> {
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
    Ok(Input {
        sha256: hex::encode(hash.finalize()),
        bytes,
    })
}

pub(crate) fn run(bin_dir: &Path, kernel: &Path, rootfs: &Path, out: &Path) -> Result<()> {
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
    let stage = tempfile::Builder::new()
        .prefix(".nucleus-host-context-")
        .tempdir_in(parent)?;
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
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema":"nucleus.microvm-host-inputs.v1", "architecture":"aarch64", "files":inputs,
        }))?,
    )?;
    fs::rename(stage.path(), out).with_context(|| format!("publishing {}", out.display()))?;
    println!("{}", out.display());
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
