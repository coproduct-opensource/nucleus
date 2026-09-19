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
pub async fn append_receipt(
    pod_dir: &Path,
    line: &str,
) -> Result<nucleus_jsonl::Durable, std::io::Error> {
    // One O_APPEND write per receipt, synced: see `nucleus_jsonl` for the tearing
    // this replaced.
    nucleus_jsonl::append_line_synced_async(receipt_log_path(pod_dir), line.to_owned()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Receipts shipped on different connections are appended concurrently. Each
    /// must land as one whole line: a receipt log with a torn line is one the audit
    /// verifier cannot read past, produced by the node itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_appends_never_tear_a_line() {
        let pod_dir = tempfile::tempdir().unwrap();
        let mut tasks = Vec::new();
        for t in 0..64 {
            let dir = pod_dir.path().to_path_buf();
            tasks.push(tokio::spawn(async move {
                let line = format!(
                    r#"{{"schema_version":1,"tag":{t},"pad":"{}"}}"#,
                    "x".repeat(4096)
                );
                append_receipt(&dir, &line).await.unwrap();
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let stored = std::fs::read_to_string(receipt_log_path(pod_dir.path())).unwrap();
        let mut tags: Vec<u64> = stored
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l)
                    .unwrap_or_else(|_| panic!("a torn line: {}", &l[..l.len().min(60)]))["tag"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        tags.sort_unstable();
        assert_eq!(
            tags,
            (0..64).collect::<Vec<u64>>(),
            "every receipt exactly once"
        );
    }

    #[tokio::test]
    async fn shipped_receipts_accumulate_one_per_line_in_order() {
        let pod_dir = tempfile::tempdir().unwrap();
        let r1 = r#"{"schema_version":1,"verdict":"allow"}"#;
        let r2 = r#"{"schema_version":1,"verdict":"deny"}"#;
        let _kept = append_receipt(pod_dir.path(), r1).await.unwrap();
        let _kept = append_receipt(pod_dir.path(), r2).await.unwrap();

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
        let _kept = append_receipt(pod_dir.path(), "{\"verdict\":\"allow\"}\n")
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
        let _kept = append_receipt(a.path(), "{\"a\":1}").await.unwrap();
        let _kept = append_receipt(b.path(), "{\"b\":1}").await.unwrap();
        assert!(receipt_log_path(a.path()).exists());
        assert!(receipt_log_path(b.path()).exists());
        assert_ne!(
            std::fs::read_to_string(receipt_log_path(a.path())).unwrap(),
            std::fs::read_to_string(receipt_log_path(b.path())).unwrap()
        );
    }
}
