//! The record `nucleus setup` writes beside the guest rootfs it installs, so
//! the node can report which guest it boots (#3223,
//! `nucleus_spec::guest_release`).

use std::path::Path;

use anyhow::{Result, anyhow};
use nucleus_spec::guest_release::{GUEST_RELEASE_RECORD_FILE, GuestOrigin, GuestReleaseRecord};
use nucleus_spec::tier2_artifacts::GUEST_ROOTFS_FILE;

use super::{HOST_ARTIFACTS_DIR, SHARED_ARTIFACT_MODE, Tier2Host};

/// Write, beside the rootfs just installed, which guest it is and the digest
/// of its installed bytes, so the node can report it (#3223). The digest is
/// measured on the host, of the file the node will boot, after it landed.
pub(super) fn record_guest_release(
    host: &Tier2Host,
    cache_dir: &Path,
    origin: GuestOrigin,
) -> Result<()> {
    let rootfs = format!("{HOST_ARTIFACTS_DIR}/{GUEST_ROOTFS_FILE}");
    let out = host.sh(&format!("sha256sum {rootfs}"))?;
    let record = guest_release_record(origin, &out)?;
    std::fs::create_dir_all(cache_dir)?;
    let local = cache_dir.join(GUEST_RELEASE_RECORD_FILE);
    std::fs::write(&local, serde_json::to_vec_pretty(&record)?)?;
    host.put(
        &local,
        &format!("{HOST_ARTIFACTS_DIR}/{GUEST_RELEASE_RECORD_FILE}"),
        SHARED_ARTIFACT_MODE,
    )
}

/// The record for `origin`, from `sha256sum`'s output for the installed rootfs.
pub(super) fn guest_release_record(
    origin: GuestOrigin,
    sha256sum: &str,
) -> Result<GuestReleaseRecord> {
    let digest = sha256sum.split_whitespace().next().unwrap_or_default();
    GuestReleaseRecord::new(origin, digest)
        .map_err(|e| anyhow!("recording the installed guest rootfs: {e}"))
}
