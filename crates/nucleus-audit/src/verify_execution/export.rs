//! Materialize bytes only after consuming the shared verifier's witness.
use std::ffi::OsStr;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use nucleus_ci_verdict::execution::{ExecutionClaim, VerifiedArtifacts};

pub(super) fn save(
    verified: VerifiedArtifacts,
    directory: &Path,
    now_micros: u64,
) -> Result<ExecutionClaim> {
    let (claim, bytes) = verified.into_parts(now_micros)?;
    for name in bytes.keys() {
        filename(name)?;
    }
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(directory).with_context(|| {
        format!(
            "creating artifact directory {} (must not exist)",
            directory.display()
        )
    })?;
    let write = || -> Result<()> {
        for (name, bytes) in bytes {
            let path = directory.join(name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&path)
                .with_context(|| format!("creating {}", path.display()))?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        #[cfg(unix)]
        File::open(directory)?.sync_all()?;
        Ok(())
    };
    write().with_context(|| {
        format!(
            "artifact export failed; partial files may remain in {}",
            directory.display()
        )
    })?;
    Ok(claim)
}

/// Artifact names are filenames here; guest workspace paths never select a
/// host destination. Reject path-like names before creating any output.
fn filename(name: &str) -> Result<()> {
    let path = Path::new(name);
    let mut components = path.components();
    ensure!(
        matches!(components.next(), Some(Component::Normal(_)))
            && components.next().is_none()
            && path.file_name() == Some(OsStr::new(name))
            && !name.contains(['\\', '\0']),
        "artifact name {name:?} is not a single filename"
    );
    Ok(())
}
