//! Node-side pod-lifecycle audit entries.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::error;

/// A pod's directory under the node's state directory: where its
/// `lifecycle.log`, logs and artifacts live. One function, so the launch path
/// and anything that records into the directory later cannot disagree on it.
pub(crate) fn pod_dir(state_dir: &Path, id: uuid::Uuid) -> std::path::PathBuf {
    state_dir.join("pods").join(id.to_string())
}

/// Append a node-side pod-lifecycle event to `<pod_dir>/lifecycle.log`.
///
/// Ensures every pod — including direct-task pods that never run a tool-proxy —
/// has at least start/stop entries.
///
/// **Deliberately NOT `audit.log`.** These entries are unsigned and unchained;
/// `audit.log` is the tool-proxy's HMAC-chained log, and interleaving unsigned
/// lines into it made every local- and container-driver log fail
/// `nucleus-audit verify` (its `ToolProxyEntry` requires
/// `prev_hash`/`hash`/`signature`). Keeping the two files separate preserves a
/// verifiable chain; the lifecycle file is folded into an evidence bundle as
/// explicitly-unsigned context. The filename lives here, in one place, so the
/// two cannot drift back together.
pub(crate) async fn write_lifecycle_audit(pod_dir: &Path, event: &str, pod_id: &str, detail: &str) {
    let audit_path = pod_dir.join("lifecycle.log");
    let audit_path = audit_path.as_path();
    let entry = serde_json::json!({
        "timestamp_unix": now_unix(),
        "actor": "nucleus-node",
        "event": event,
        "subject": format!("pod:{}", pod_id),
        "result": detail,
    });
    let line = match serde_json::to_string(&entry) {
        Ok(l) => l,
        Err(e) => {
            error!("failed to serialize lifecycle audit entry: {e}");
            return;
        }
    };
    // One O_APPEND write per entry: see `nucleus_jsonl` for the tearing this
    // replaced. A failed write is logged — it used to be dropped silently.
    if let Err(e) = nucleus_jsonl::append_line_unsynced_async(audit_path.to_path_buf(), line).await
    {
        error!(
            "failed to write lifecycle audit to {}: {e}",
            audit_path.display()
        );
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

use crate::{ApiError, DriverState, PodHandle, PodInfo, PodState, Stop};

impl PodHandle {
    pub(crate) async fn info(&self) -> PodInfo {
        let state = self.status().await;
        let proxy_addr = self.proxy_addr.lock().await.clone();
        PodInfo {
            id: self.id,
            name: self.spec.metadata.name.clone(),
            created_at_unix: self.created_at,
            state,
            proxy_addr,
            labels: self.spec.metadata.labels.clone(),
            parent_pod_id: self.parent_pod_id,
            posture: self.posture_stamp.clone(),
        }
    }

    pub(crate) async fn status(&self) -> PodState {
        match &self.driver_state {
            #[cfg(feature = "local-driver")]
            DriverState::Local(local) => local.status().await,
            DriverState::Firecracker(firecracker) => firecracker.status().await,
            DriverState::Container(container) => container.status().await,
        }
    }

    pub(crate) async fn cancel(&self) -> Result<(), ApiError> {
        self.teardown(Stop::Kill).await
    }

    pub(crate) async fn cleanup_after_exit(&self) {
        // Nothing to kill, so nothing can fail: the error arm is the kill's.
        let _ = self.teardown(Stop::AlreadyExited).await;
    }

    async fn teardown(&self, stop: Stop) -> Result<(), ApiError> {
        let result = match &self.driver_state {
            #[cfg(feature = "local-driver")]
            DriverState::Local(local) => local.teardown(stop).await,
            DriverState::Firecracker(firecracker) => firecracker.teardown(stop).await,
            DriverState::Container(container) => container.teardown(stop).await,
        };
        if result.is_ok() {
            self.capacity.lock().await.take();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lifecycle events for one pod are written from more than one task (create,
    /// cancel, the reaper); each must land as one whole line.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_lifecycle_entries_never_tear_a_line() {
        let dir = tempfile::tempdir().unwrap();
        let detail = "x".repeat(4096);
        let mut tasks = Vec::new();
        for t in 0..64 {
            let d = dir.path().to_path_buf();
            let detail = detail.clone();
            tasks.push(tokio::spawn(async move {
                write_lifecycle_audit(&d, &format!("event-{t}"), "pod", &detail).await;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let raw = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        let events: Vec<String> = raw
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .unwrap_or_else(|_| panic!("a torn line: {}", &l[..l.len().min(60)]))["event"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(events.len(), 64, "every entry exactly once");
    }
}
