#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

use crate::ApiError;
use nucleus_spec::CgroupSpec;

#[cfg(target_os = "linux")]
pub async fn apply_cgroup(pid: u32, spec: &CgroupSpec) -> Result<(), ApiError> {
    ensure_dir(&spec.path).await?;

    for setting in &spec.settings {
        let path = spec.path.join(&setting.file);
        tokio::fs::write(&path, setting.value.as_bytes()).await?;
    }

    let procs = select_tasks_file(&spec.path);
    tokio::fs::write(procs, format!("{pid}"))
        .await
        .map_err(ApiError::Io)?;
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[cfg(not(target_os = "linux"))]
pub async fn apply_cgroup(_pid: u32, _spec: &CgroupSpec) -> Result<(), ApiError> {
    Err(ApiError::Driver(
        "cgroup placement requires Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
async fn ensure_dir(path: &Path) -> Result<(), ApiError> {
    tokio::fs::create_dir_all(path).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn select_tasks_file(path: &Path) -> PathBuf {
    let procs = path.join("cgroup.procs");
    if procs.exists() {
        return procs;
    }
    path.join("tasks")
}
