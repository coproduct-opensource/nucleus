//! An eval cell's results, returned by the node at pod exit (ADR 0013 rule 7).
//!
//! An eval cell boots a node-owned COPY of the caller's scratch disk
//! (`jail_placement::Placement::NodeCopyGuestWrites`). The caller's file is never linked into
//! the jail, so a write to it after the boot check cannot reach the guest. The cost is that the
//! guest's writes no longer land in the caller's file as it runs. This module returns them: once
//! the VMM has stopped, and before the jail is removed, the node copies its disk over the
//! caller's `image.scratch_path`. It measures what it exported with `measure_artifact`, the
//! function that pins disks (G-1), and records that digest. The signed receipt then carries it
//! (`Receipt::scratch_export`).
//!
//! This is the same teardown point `pod_receipt::preserve_exit_report` uses to bring the exit
//! report out of the same disk. A standard pod's scratch is still linked and is never exported.

use std::path::{Path, PathBuf};

use nucleus_spec::PodSpec;
use nucleus_spec::isolation_profile::IsolationProfile;

/// Where teardown records the export, in the host-owned pod dir.
pub(crate) const RECORD: &str = "scratch-export";

/// Where an eval cell's scratch disk is exported at exit: the caller's own `image.scratch_path`.
///
/// `None` for a standard pod, whose scratch is linked and needs no export, and for a pod with no
/// caller scratch, whose node-made disk the caller never named. A profile label that does not
/// parse exports too, matching `firecracker_config::jail_resources`, which copies for it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn target(spec: &PodSpec) -> Option<PathBuf> {
    let scratch = spec.spec.image.as_ref()?.scratch_path.clone()?;
    match IsolationProfile::of(spec) {
        Ok(IsolationProfile::Standard) => None,
        Ok(IsolationProfile::EvalCell) | Err(_) => Some(scratch),
    }
}

/// Copy the stopped pod's `disk` over the caller's existing file `to`, and return the digest of
/// what was exported, in the `sha-256:<hex>` form a spec pins.
///
/// `to` must already be a regular file, must not be a symlink, and is opened with neither
/// create nor truncate-on-open. The node runs as root and `to` is the caller's path, so the export
/// never creates a file and never writes through a link. The inode, owner and mode are the
/// caller's own, as they were before the pod ran.
pub(crate) async fn export(disk: &Path, to: &Path) -> Result<String, String> {
    let measured = nucleus_identity::attestation::measure_artifact(disk)
        .await
        .map_err(|e| format!("measuring {}: {e}", disk.display()))?;
    let (from, dest) = (disk.to_path_buf(), to.to_path_buf());
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        let mut source = std::fs::File::open(&from)?;
        // lstat, open, fstat: the inode opened must be the regular file the path named without
        // following a link, so a path swapped for a symlink in between is refused.
        let named = std::fs::symlink_metadata(&dest)?;
        if !named.is_file() {
            return Err(std::io::Error::other("not a regular file"));
        }
        let mut out = std::fs::OpenOptions::new().write(true).open(&dest)?;
        let opened = out.metadata()?;
        if (opened.dev(), opened.ino()) != (named.dev(), named.ino()) {
            return Err(std::io::Error::other("the path changed while it was opened"));
        }
        out.set_len(0)?;
        std::io::copy(&mut source, &mut out)?;
        out.sync_all()
    })
    .await
    .map_err(|e| format!("exporting to {}: {e}", to.display()))?
    .map_err(|e| format!("exporting to {}: {e}", to.display()))?;
    Ok(format!("sha-256:{}", hex::encode(measured)))
}

/// Export and record the outcome in `pod_dir`, for the receipt. Teardown continues either way.
/// A failed export is recorded as `not exported: <why>`, never as an empty field, so a receipt
/// cannot read as "nothing to export" when an export was owed.
pub(crate) async fn export_and_record(disk: &Path, to: &Path, pod_dir: &Path) {
    let record = match export(disk, to).await {
        Ok(digest) => digest,
        Err(why) => {
            tracing::warn!(error = %why, "eval-cell scratch export failed");
            format!("not exported: {why}")
        }
    };
    if let Err(e) = std::fs::write(pod_dir.join(RECORD), record) {
        tracing::warn!(error = %e, "could not record the eval-cell scratch export");
    }
}

/// What the receipt says was exported. Empty only when nothing was owed (a standard pod, or no
/// caller scratch); an owed export with no record says so rather than reading as empty.
pub(crate) fn recorded(spec: &PodSpec, pod_dir: &Path) -> String {
    match target(spec) {
        None => String::new(),
        Some(_) => std::fs::read_to_string(pod_dir.join(RECORD)).unwrap_or_else(|e| {
            format!("not exported: no export recorded at teardown ({e})")
        }),
    }
}

#[cfg(test)]
#[path = "scratch_export_tests.rs"]
mod tests;
