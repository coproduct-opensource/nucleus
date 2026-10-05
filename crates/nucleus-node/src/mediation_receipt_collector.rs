//! Durable collection of guest-reported mediation claims, including legacy
//! `MediationReceipt` envelopes. These are NOT host authorization evidence.
//!
//! The connection identifies the pod, not a trusted process inside it. A
//! compromised guest may choose every field and signature. Keeping its bytes
//! supports diagnostics but neither authenticates their truth nor proves a host
//! decision. The guest-claim log is separate from the host-only, signed
//! `host-effect-authorizations.jsonl` journal; SHIP_RECEIPT cannot append there.

use std::path::{Path, PathBuf};

/// The guest-claim log inside a pod's node-side directory.
///
/// `pod_dir` is `<state>/pods/<pod_id>` — already per-pod and host-private (the
/// guest has no path to the node's state dir), and where the node keeps this
/// pod's other host-side records. No
/// pod-id subkeying and nothing guest-supplied enters the path.
#[must_use]
pub fn receipt_log_path(pod_dir: &Path) -> PathBuf {
    pod_dir.join("guest-mediation-claims.jsonl")
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
                // The `Durable` is the proof the line reached the disk, which is exactly what
                // this test is about — so it is asserted rather than dropped. Dropping it would
                // have the test claim durability it never checked, which is what `#[must_use]`
                // on `Durable` exists to prevent.
                let durable = append_receipt(&dir, &line).await.unwrap();
                assert!(
                    durable.proves(&receipt_log_path(&dir), &line),
                    "the acknowledgement must prove THIS line reached THIS log"
                );
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
