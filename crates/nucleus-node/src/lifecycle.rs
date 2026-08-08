//! Node-side pod-lifecycle audit entries.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::AsyncWriteExt;
use tracing::error;

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
    match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)
        .await
    {
        Ok(mut file) => {
            let _ = file.write_all(line.as_bytes()).await;
            let _ = file.write_all(b"\n").await;
        }
        Err(e) => {
            error!(
                "failed to write lifecycle audit to {}: {e}",
                audit_path.display()
            );
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
