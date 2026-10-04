//! Cgroup placement on the direct-spawn path (development builds only: production requires the
//! jailer, which applies the same [`NodeCgroup`] before `exec`).

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

use crate::ApiError;
use crate::pod_resources::NodeCgroup;

/// The only hierarchy the node writes under. `host_paths` holds a spec's `cgroup.path` to it.
#[cfg(target_os = "linux")]
const CGROUP_FS: &str = "/sys/fs/cgroup";

/// Where a pod whose spec names no cgroup directory is placed.
#[cfg(target_os = "linux")]
pub fn node_dir(pod_id: &str) -> PathBuf {
    Path::new(CGROUP_FS).join("nucleus").join(pod_id)
}

/// Place `pid` in `dir` under the node's limits.
///
/// Late by construction: the VMM is already running. That window is why production uses the
/// jailer. Cgroup v2 only; a v1 host is refused rather than left unlimited.
#[cfg(target_os = "linux")]
pub async fn apply_cgroup(pid: u32, dir: &Path, cgroup: &NodeCgroup) -> Result<(), ApiError> {
    use crate::pod_resources::CgroupVersion;
    match cgroup.version() {
        CgroupVersion::V2 => {}
        CgroupVersion::V1 => {
            return Err(ApiError::Driver(
                "direct-spawn cgroup placement needs cgroup v2; use --firecracker-jailer on a \
                 v1 host"
                    .to_string(),
            ));
        }
    }
    tokio::fs::create_dir_all(dir).await?;

    // A v2 controller's files exist in a child only once every ancestor delegates it, which the
    // jailer does for itself and this path must do too, or every limit write fails.
    let enable = cgroup
        .controllers()
        .iter()
        .map(|c| format!("+{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    let mut ancestors: Vec<&Path> = dir
        .ancestors()
        .skip(1)
        .take_while(|a| a.starts_with(CGROUP_FS))
        .collect();
    ancestors.reverse();
    for ancestor in ancestors {
        tokio::fs::write(ancestor.join("cgroup.subtree_control"), &enable).await?;
    }

    for setting in cgroup.settings() {
        tokio::fs::write(dir.join(&setting.file), setting.value.as_bytes()).await?;
    }
    tokio::fs::write(dir.join("cgroup.procs"), format!("{pid}"))
        .await
        .map_err(ApiError::Io)?;
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(not(target_os = "linux"))]
pub async fn apply_cgroup(
    _pid: u32,
    _dir: &std::path::Path,
    _cgroup: &NodeCgroup,
) -> Result<(), ApiError> {
    Err(ApiError::Driver(
        "cgroup placement requires Linux".to_string(),
    ))
}
