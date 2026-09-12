//! Exact-tree compiler cache seeds. A seed is never attached writable to a VM.
//! Linux FICLONE and macOS clonefile share extents with private writes; other hosts use
//! an explicitly reported sparse copy. Neither outcome is a receipt cache hit.

use super::{Context, Path, PathBuf, Result, ensure, fs, sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::Instant;

#[derive(clap::Args)]
pub(crate) struct ProbeArgs {
    /// Existing immutable image. This measures copying; it grants no cache trust.
    #[arg(long)]
    source: PathBuf,
    /// New directory; the source is never modified.
    #[arg(long)]
    output: PathBuf,
}

pub(crate) fn probe(args: ProbeArgs) -> Result<()> {
    let ProbeArgs { source, output } = args;
    ensure!(
        fs::symlink_metadata(&source)?.is_file(),
        "probe source must be a regular file"
    );
    fs::create_dir(&output).context("probe output must be a new directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    }
    let started = Instant::now();
    let digest = sha256(&source)?;
    let source_hash_seconds = started.elapsed().as_secs_f64();
    let report = clone_verified(&source, &output.join("clone.img"), &digest)?;
    let report = serde_json::to_string_pretty(&serde_json::json!({
        "schema": "nucleus.cache-probe.v1", "source_sha256": digest,
        "source_hash_seconds": source_hash_seconds, "clone": report,
        "total_seconds": started.elapsed().as_secs_f64(),
        "scope": "host image cloning only; no VM build or receipt reuse"
    }))?;
    fs::write(output.join("report.json"), &report)?;
    println!("{report}");
    Ok(())
}

pub(super) struct FrozenScratch {
    path: PathBuf,
    digest: String,
}

impl FrozenScratch {
    pub(super) fn seal(completed: super::execute::CompletedBuild) -> Result<Self> {
        let path = completed.into_scratch();
        // The VM is stopped, but termination is not a guest filesystem flush.
        // Replay its journal and refuse anything needing operator repair. This
        // makes a crash-consistent cache; it does not promise every dirty guest
        // page persisted or authenticate intermediate compiler outputs.
        let status = std::process::Command::new("e2fsck")
            .arg("-p")
            .arg(&path)
            .status()
            .context("check stopped build scratch before cache promotion")?;
        ensure!(
            matches!(status.code(), Some(0 | 1)),
            "scratch repair failed: {status}"
        );
        fs::File::open(&path)?.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o400))?;
        }
        let digest = sha256(&path)?;
        Ok(Self { path, digest })
    }

    pub(super) fn fork(&self, destination: &Path) -> Result<(String, serde_json::Value)> {
        let started = Instant::now();
        let report = clone_verified(&self.path, destination, &self.digest)?;
        Ok((
            self.digest.clone(),
            serde_json::json!({
                "scope": "exact_tree", "parent_scratch_sha256": self.digest,
                "clone": report, "clone_and_verify_seconds": started.elapsed().as_secs_f64(),
                "trust": "compiler cache input; the new execution and artifact still require verification"
            }),
        ))
    }
}

#[derive(serde::Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
enum CloneMode {
    #[cfg(target_os = "linux")]
    Reflink,
    #[cfg(target_os = "macos")]
    ApfsClone,
    SparseCopy {
        reason: String,
    },
}

#[derive(serde::Serialize)]
struct CloneReport {
    #[serde(flatten)]
    mode: CloneMode,
    logical_bytes: u64,
    copy_seconds: f64,
    verification_seconds: f64,
}

fn clone_verified(source: &Path, destination: &Path, digest: &str) -> Result<CloneReport> {
    ensure!(
        fs::symlink_metadata(source)?.is_file(),
        "cache seed must be a regular file"
    );
    let parent = destination
        .parent()
        .context("scratch destination has no parent")?;
    let staging = tempfile::tempdir_in(parent)?;
    let staged = staging.path().join("image");
    let mut input = fs::File::open(source)?;
    let logical_bytes = input.metadata()?.len();
    let started = Instant::now();
    let mode = clone_or_copy(&mut input, &staged)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
    }
    fs::File::open(&staged)?.sync_all()?;
    let copy_seconds = started.elapsed().as_secs_f64();
    let verifying = Instant::now();
    ensure!(
        sha256(&staged)? == digest,
        "cache seed changed or clone is corrupt"
    );
    let verification_seconds = verifying.elapsed().as_secs_f64();
    // No partially copied file, replaced destination, shared writable inode, or
    // unchecked bytes can become the path passed to the node.
    // The temporary file is already a private clone, never the seed inode.
    // Link it into place without replacement, then drop its staging directory.
    fs::hard_link(&staged, destination)?;
    Ok(CloneReport {
        mode,
        logical_bytes,
        copy_seconds,
        verification_seconds,
    })
}

fn clone_or_copy(input: &mut fs::File, path: &Path) -> Result<CloneMode> {
    #[cfg(target_os = "macos")]
    let reason = {
        let parent = fs::File::open(path.parent().context("clone parent missing")?)?;
        match rustix::fs::fclonefileat(
            &*input,
            parent,
            path.file_name().context("clone filename missing")?,
            rustix::fs::CloneFlags::NOOWNERCOPY,
        ) {
            Ok(()) => return Ok(CloneMode::ApfsClone),
            Err(error)
                if matches!(
                    error,
                    rustix::io::Errno::OPNOTSUPP | rustix::io::Errno::XDEV
                ) =>
            {
                error.to_string()
            }
            Err(error) => return Err(error).context("clone APFS cache extents"),
        }
    };
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    #[cfg(target_os = "linux")]
    let reason = match rustix::fs::ioctl_ficlone(&output, &*input) {
        Ok(()) => return Ok(CloneMode::Reflink),
        Err(error)
            if matches!(
                error,
                rustix::io::Errno::OPNOTSUPP
                    | rustix::io::Errno::XDEV
                    | rustix::io::Errno::INVAL
                    | rustix::io::Errno::NOTTY
            ) =>
        {
            error.to_string()
        }
        Err(error) => return Err(error).context("clone cache extents"),
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let reason = "native cloning is not implemented on this platform".to_owned();
    sparse_copy(input, &mut output)?;
    Ok(CloneMode::SparseCopy { reason })
}

fn sparse_copy(input: &mut fs::File, output: &mut fs::File) -> Result<()> {
    output.set_len(0)?;
    let length = input.metadata()?.len();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut offset = 0;
        while offset < length {
            let start = match rustix::fs::seek(&*input, rustix::fs::SeekFrom::Data(offset)) {
                Ok(start) => start,
                Err(rustix::io::Errno::NXIO) => break,
                Err(rustix::io::Errno::INVAL | rustix::io::Errno::OPNOTSUPP) => {
                    return scan_sparse(input, output, length);
                }
                Err(error) => return Err(error).context("find cache data extent"),
            };
            let end = rustix::fs::seek(&*input, rustix::fs::SeekFrom::Hole(start))?.min(length);
            ensure!(start < end, "cache extent did not advance");
            input.seek(SeekFrom::Start(start))?;
            output.seek(SeekFrom::Start(start))?;
            ensure!(
                std::io::copy(&mut input.take(end - start), output)? == end - start,
                "cache seed truncated during copy"
            );
            offset = end;
        }
        output.set_len(length)?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    scan_sparse(input, output, length)
}

fn scan_sparse(input: &mut fs::File, output: &mut fs::File, length: u64) -> Result<()> {
    input.rewind()?;
    output.set_len(0)?;
    output.rewind()?;
    let mut buffer = [0u8; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let bytes = buffer.get(..count).context("cache read exceeded buffer")?;
        if bytes.iter().all(|byte| *byte == 0) {
            output.seek(SeekFrom::Current(i64::try_from(count)?))?;
        } else {
            output.write_all(bytes)?;
        }
    }
    ensure!(
        output.stream_position()? == length,
        "cache seed changed length during copy"
    );
    output.set_len(length)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clones_are_independent_and_cannot_replace_existing_files() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("seed");
        fs::write(&seed, b"compiler cache")?;
        let digest = sha256(&seed)?;
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        clone_verified(&seed, &first, &digest)?;
        clone_verified(&seed, &second, &digest)?;
        fs::write(&first, b"private changes")?;
        assert_eq!(sha256(&seed)?, digest);
        assert_eq!(sha256(&second)?, digest);
        assert!(clone_verified(&seed, &first, &digest).is_err());
        assert_eq!(fs::read(first)?, b"private changes");
        Ok(())
    }

    #[test]
    fn corrupt_seed_is_not_published() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("seed");
        fs::write(&seed, b"compiler cache")?;
        let digest = sha256(&seed)?;
        fs::write(&seed, b"tampered cache")?;
        let destination = temp.path().join("clone");
        assert!(clone_verified(&seed, &destination, &digest).is_err());
        assert!(!destination.try_exists()?);
        assert_eq!(fs::read_dir(temp.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn sparse_fallback_preserves_holes_data_and_trailing_length() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let seed = temp.path().join("seed");
        let mut input = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&seed)?;
        input.set_len(16 * 1024 * 1024)?;
        input.seek(SeekFrom::Start(1024 * 1024))?;
        input.write_all(b"extent contents")?;
        let digest = sha256(&seed)?;
        for (name, copier) in [
            (
                "extents",
                sparse_copy as fn(&mut fs::File, &mut fs::File) -> Result<()>,
            ),
            ("scan", |i: &mut fs::File, o: &mut fs::File| {
                scan_sparse(i, o, 16 * 1024 * 1024)
            }),
        ] {
            let path = temp.path().join(name);
            let mut output = fs::File::create(&path)?;
            copier(&mut input, &mut output)?;
            assert_eq!(sha256(&path)?, digest);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert!(output.metadata()?.blocks() * 512 < output.metadata()?.len() / 2);
            }
        }
        Ok(())
    }
}
