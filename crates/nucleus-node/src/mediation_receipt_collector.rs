//! Host-side collection of signed `MediationReceipt`s streamed from pods over vsock.
//!
//! # Why the host holds a copy
//!
//! A Firecracker guest cannot reach the node over HTTP, and its `/run` receipt
//! file dies with the microVM — so `nucleus-tool-proxy` streams each receipt to
//! the node over the workload-API vsock as it is produced (the `SHIP_RECEIPT`
//! command). This is the collector half: the copy the pod cannot retract, so a
//! host attestation over the receipt set binds what it OBSERVED rather than what
//! the pod later chose to report. It is the completeness-bounding the console
//! mirror (the boot lane's channel today) cannot give — the guest shipper is
//! fail-closed, so a pod whose receipts stop reaching the host stops deciding.
//!
//! # What authenticates a shipped receipt
//!
//! Two independent things, so this layer stays small:
//!
//! * **the connection** — the workload-API vsock connection is already bound to
//!   ONE pod (the node serves this pod's SVID and secrets over it), so a receipt
//!   arriving here can only be filed under THAT pod. The collector keys the file
//!   by the node's own `pod_id`, never anything the guest sends, so there is no
//!   cross-pod injection to guard against (and no session id to sanitize).
//! * **the receipt** — its content is an Ed25519 signature over its own fields,
//!   verified later by `nucleus-audit verify-mediation-receipts` over the
//!   assembled file. The node does not re-verify here: one implementation of that
//!   logic, not two that must agree.
//!
//! A note on trust granularity: the connection authenticates the *pod*, not the
//! tool-proxy vs. the workload inside it. A workload that reached this channel
//! could append receipts it did not sign — but it cannot forge the mediator
//! Ed25519 signature (the key lives in the tool-proxy, not the workload), so any
//! such line surfaces as a verification FAILURE in the scoreboard rather than a
//! trusted receipt. Distinguishing the two senders with a tool-proxy-held secret
//! is a later hardening, noted rather than pretended.

use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

/// The collected-receipts log inside a pod's node-side directory.
///
/// `pod_dir` is `<state>/pods/<pod_id>` — already per-pod and host-private (the
/// guest has no path to the node's state dir), and where the node keeps this
/// pod's other host-side records (`mediator-pubkey.hex`, `firecracker.log`). No
/// pod-id subkeying and nothing guest-supplied enters the path.
#[must_use]
pub fn receipt_log_path(pod_dir: &Path) -> PathBuf {
    pod_dir.join("collected-receipts.jsonl")
}

/// Append one shipped receipt line to the pod's collected log.
///
/// Flushed AND synced before the caller acks the pod: an accepted receipt that is
/// only in the page cache is lost by a host crash, and the pod would have been
/// told it was witnessed.
///
/// # Errors
/// If the directory cannot be created or the append fails — the caller must NOT
/// ack the pod on error.
pub async fn append_receipt(pod_dir: &Path, line: &str) -> Result<(), std::io::Error> {
    let path = receipt_log_path(pod_dir);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await?;
    f.write_all(line.trim_end().as_bytes()).await?;
    f.write_all(b"\n").await?;
    f.flush().await?;
    f.sync_data().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shipped_receipts_accumulate_one_per_line_in_order() {
        let pod_dir = tempfile::tempdir().unwrap();
        let r1 = r#"{"schema_version":1,"verdict":"allow"}"#;
        let r2 = r#"{"schema_version":1,"verdict":"deny"}"#;
        append_receipt(pod_dir.path(), r1).await.unwrap();
        append_receipt(pod_dir.path(), r2).await.unwrap();

        let stored = std::fs::read_to_string(receipt_log_path(pod_dir.path())).unwrap();
        let lines: Vec<&str> = stored.lines().collect();
        assert_eq!(
            lines,
            vec![r1, r2],
            "each receipt is its own JSON line, in order"
        );
    }

    #[tokio::test]
    async fn a_trailing_newline_in_the_shipped_line_is_normalized() {
        let pod_dir = tempfile::tempdir().unwrap();
        append_receipt(pod_dir.path(), "{\"verdict\":\"allow\"}\n")
            .await
            .unwrap();
        let stored = std::fs::read_to_string(receipt_log_path(pod_dir.path())).unwrap();
        assert_eq!(
            stored, "{\"verdict\":\"allow\"}\n",
            "exactly one terminating newline"
        );
    }

    #[tokio::test]
    async fn different_pods_collect_into_their_own_dirs() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        append_receipt(a.path(), "{\"a\":1}").await.unwrap();
        append_receipt(b.path(), "{\"b\":1}").await.unwrap();
        assert!(receipt_log_path(a.path()).exists());
        assert!(receipt_log_path(b.path()).exists());
        assert_ne!(
            std::fs::read_to_string(receipt_log_path(a.path())).unwrap(),
            std::fs::read_to_string(receipt_log_path(b.path())).unwrap()
        );
    }
}
