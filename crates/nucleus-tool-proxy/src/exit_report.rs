#![allow(clippy::disallowed_types)] // #1216 exempt: exit report collection is post-decision infrastructure
//! Exit report generation for execution receipts.
//!
//! Before shutdown, the tool-proxy computes a workspace content hash and
//! captures the audit chain tail, writing this as the final audit log entry.
//! The host (nucleus-node) reads this to build an `ExecutionReceipt`.

use nucleus_spec::{sha256_bytes_hex, ExitReport};
use portcullis::trace_monitor::TraceMonitor;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Compute a deterministic SHA-256 hash of a directory's contents.
///
/// Walks the directory recursively, computes SHA-256 of each file's contents,
/// then hashes the sorted list of `(relative_path, file_hash)` pairs.
/// This produces a reproducible hash regardless of filesystem ordering.
///
/// Skips:
/// - Hidden files/directories (starting with `.`)
/// - The `.nucleus-exit-report.json` file itself
pub async fn hash_workspace(root: &Path) -> Result<String, std::io::Error> {
    let mut entries: Vec<(String, String)> = Vec::new();
    collect_file_hashes(root, root, &mut entries).await?;
    entries.sort();

    let mut hasher = Sha256::new();
    for (path, hash) in &entries {
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Recursively collect (relative_path, sha256_hex) for all files.
async fn collect_file_hashes(
    root: &Path,
    dir: &Path,
    entries: &mut Vec<(String, String)>,
) -> Result<(), std::io::Error> {
    let mut read_dir = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden files and the exit report itself
        if name_str.starts_with('.') {
            continue;
        }

        let path = entry.path();
        let file_type = entry.file_type().await?;

        if file_type.is_dir() {
            Box::pin(collect_file_hashes(root, &path, entries)).await?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let contents = tokio::fs::read(&path).await?;
            let hash = sha256_bytes_hex(&contents);
            entries.push((relative, hash));
        }
    }
    Ok(())
}

/// Token usage statistics collected during execution.
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    /// Input tokens consumed.
    pub input_tokens: u64,
    /// Output tokens generated.
    pub output_tokens: u64,
    /// Cache read tokens (prompt caching hits).
    pub cache_read_tokens: u64,
    /// Estimated cost in USD.
    pub cost_usd: f64,
}

/// Build an exit report from the current state.
///
/// `monitor` is a required argument, not an optional enrichment applied by the
/// caller afterwards. A report is the session's account of itself, and a session
/// that recorded effects nothing authorised must not be able to produce a clean
/// account by way of a caller forgetting a line. There is no signature here that
/// omits the monitor.
pub fn build_exit_report(
    workspace_hash: String,
    audit_tail_hash: String,
    audit_entry_count: u64,
    token_usage: Option<TokenUsage>,
    monitor: &TraceMonitor,
) -> ExitReport {
    let timestamp_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let usage = token_usage.unwrap_or_default();

    ExitReport {
        workspace_hash,
        audit_tail_hash,
        audit_entry_count,
        timestamp_unix,
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        cache_read_tokens: usage.cache_read_tokens,
        cost_usd: usage.cost_usd,
        // Exposure populated by write_exit_report() after guard extraction
        observed_exposure_labels: Vec::new(),
        observed_risk_tier: String::new(),
        uninhabitable_reached: false,
        // Class labels only — the detail stays in-process (Violation::label).
        monitor_violations: monitor
            .violations()
            .iter()
            .map(|v| v.label().to_string())
            .collect(),
        monitor_violations_dropped: monitor.violations_dropped(),
        // Populated by `apply_art12` — the log is not available here, and a
        // default of "" reads correctly as "no Article 12 log was kept".
        art12_chain_head: String::new(),
        art12_records: 0,
        art12_dropped: 0,
    }
}

/// Fold the Article 12 log's chain head into the report, for the host to sign.
///
/// `None` leaves the fields empty, which is the truthful rendering of a session
/// that kept no Article 12 log — distinct from a log with zero records, which
/// reports a genesis-derived head and `art12_records: 0`.
pub fn apply_art12(report: &mut ExitReport, log: Option<&std::sync::Arc<crate::art12::Art12Log>>) {
    let Some(log) = log else {
        return;
    };
    let (head, records) = log.head().unwrap_or_else(|_| (String::new(), 0));
    report.art12_chain_head = head;
    report.art12_records = records;
    report.art12_dropped = log.dropped();
}

/// Fold the session's verified exposure into the report.
///
/// Extracted from `write_exit_report` so the mapping from `ExposureLabel` to the
/// strings the trust gate scores on is testable, and so main.rs stays under its
/// line ratchet. The guard is read here rather than passed pre-extracted: the
/// point of the field is what the guard actually held at shutdown.
pub fn apply_exposure(
    report: &mut ExitReport,
    exposure_guard: &std::sync::RwLock<Option<std::sync::Arc<portcullis::GradedExposureGuard>>>,
) {
    let Ok(guard_opt) = exposure_guard.read() else {
        return;
    };
    let Some(guard) = guard_opt.as_ref() else {
        return;
    };
    let exposure = guard.exposure();
    for (label, name) in [
        (portcullis::guard::ExposureLabel::PrivateData, "PrivateData"),
        (
            portcullis::guard::ExposureLabel::UntrustedContent,
            "UntrustedContent",
        ),
        (portcullis::guard::ExposureLabel::ExfilVector, "ExfilVector"),
    ] {
        if exposure.contains(label) {
            report.observed_exposure_labels.push(name.to_string());
        }
    }
    report.uninhabitable_reached = exposure.is_uninhabitable();
    report.observed_risk_tier = match exposure.to_risk() {
        portcullis::StateRisk::Safe => "safe",
        portcullis::StateRisk::Low => "low",
        portcullis::StateRisk::Medium => "medium",
        portcullis::StateRisk::Uninhabitable => "critical",
    }
    .to_string();

    tracing::info!(
        exposure = ?report.observed_exposure_labels,
        risk = %report.observed_risk_tier,
        uninhabitable = report.uninhabitable_reached,
        "exit report: verified exposure captured"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_hash_workspace_empty() {
        let dir = TempDir::new().unwrap();
        let hash = hash_workspace(dir.path()).await.unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[tokio::test]
    async fn test_hash_workspace_deterministic() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"world").unwrap();

        let hash1 = hash_workspace(dir.path()).await.unwrap();
        let hash2 = hash_workspace(dir.path()).await.unwrap();
        assert_eq!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_hash_workspace_content_sensitive() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"version1").unwrap();
        let hash1 = hash_workspace(dir.path()).await.unwrap();

        std::fs::write(dir.path().join("file.txt"), b"version2").unwrap();
        let hash2 = hash_workspace(dir.path()).await.unwrap();

        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_hash_workspace_skips_hidden() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("visible.txt"), b"data").unwrap();
        std::fs::write(dir.path().join(".hidden"), b"secret").unwrap();

        let hash_with_hidden = hash_workspace(dir.path()).await.unwrap();

        // Remove hidden file — hash should be the same
        std::fs::remove_file(dir.path().join(".hidden")).unwrap();
        let hash_without_hidden = hash_workspace(dir.path()).await.unwrap();

        assert_eq!(hash_with_hidden, hash_without_hidden);
    }

    #[tokio::test]
    async fn test_hash_workspace_recursive() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("sub/dir")).unwrap();
        std::fs::write(dir.path().join("sub/dir/deep.txt"), b"nested").unwrap();

        let hash = hash_workspace(dir.path()).await.unwrap();
        assert_eq!(hash.len(), 64);
    }

    /// A monitor that has observed nothing.
    fn clean_monitor() -> TraceMonitor {
        struct NullSink;
        impl portcullis::verdict_sink::VerdictSink for NullSink {
            fn record(
                &self,
                _c: portcullis::verdict_sink::VerdictContext,
            ) -> Result<(), portcullis::verdict_sink::SinkError> {
                Ok(())
            }
            fn preflight(
                &self,
                _o: portcullis::Operation,
            ) -> Result<(), portcullis::verdict_sink::SinkError> {
                Ok(())
            }
        }
        TraceMonitor::new(std::sync::Arc::new(NullSink))
    }

    /// A monitor that has seen `n` unmediated effects: a terminal Allow with no
    /// preceding kernel decision.
    fn monitor_with_violations(n: usize) -> TraceMonitor {
        use portcullis::verdict_sink::{
            ActorIdentity, VerdictContext, VerdictOutcome, VerdictSink,
        };
        let m = clean_monitor();
        for _ in 0..n {
            m.record(VerdictContext {
                operation: portcullis::Operation::RunBash,
                subject: "unmediated".to_string(),
                outcome: VerdictOutcome::Allow,
                actor: ActorIdentity::Unknown,
                policy_rule: None,
                extensions: std::collections::BTreeMap::new(),
            })
            .unwrap();
        }
        assert_eq!(
            m.violations().len(),
            n,
            "fixture did not produce violations"
        );
        m
    }

    /// **The acceptance test for the exit-report half.** The report is the
    /// session's account of itself; a session whose mediation invariants broke
    /// must not be able to file a clean one.
    ///
    /// Perturbation: drop the `monitor_violations` population in
    /// `build_exit_report` and this REDs — and because `build_exit_report` is
    /// the function the live shutdown path calls, the test and the live path
    /// cannot disagree.
    #[test]
    fn the_report_carries_what_the_monitor_observed() {
        let clean = build_exit_report("w".into(), "t".into(), 1, None, &clean_monitor());
        assert!(
            clean.monitor_violations.is_empty(),
            "a clean session must file a clean report, or the assertion below proves nothing"
        );

        let dirty = build_exit_report("w".into(), "t".into(), 1, None, &monitor_with_violations(2));
        assert_eq!(
            dirty.monitor_violations,
            vec!["OutcomeWithoutDecision", "OutcomeWithoutDecision"],
            "the report must carry the violations the monitor observed"
        );
    }

    /// The report carries the violation CLASS and not the session state behind
    /// it. Everything in this vector leaves the process.
    #[test]
    fn the_report_does_not_export_violation_detail() {
        let report =
            build_exit_report("w".into(), "t".into(), 1, None, &monitor_with_violations(1));
        // Without this the loop below is vacuous on an empty vector — which is
        // exactly what an unwired report produces.
        assert_eq!(report.monitor_violations.len(), 1);
        for label in &report.monitor_violations {
            assert!(
                !label.contains("unmediated"),
                "the subject of the violating record escaped into the report: {label}"
            );
        }
    }

    #[test]
    fn test_build_exit_report() {
        let report = build_exit_report(
            "workspace_hash".to_string(),
            "audit_hash".to_string(),
            10,
            None,
            &clean_monitor(),
        );
        assert_eq!(report.workspace_hash, "workspace_hash");
        assert_eq!(report.audit_tail_hash, "audit_hash");
        assert_eq!(report.audit_entry_count, 10);
        assert!(report.timestamp_unix > 0);
        assert_eq!(report.input_tokens, 0);
        assert_eq!(report.cost_usd, 0.0);
    }

    #[test]
    fn test_build_exit_report_with_usage() {
        let usage = TokenUsage {
            input_tokens: 1500,
            output_tokens: 500,
            cache_read_tokens: 200,
            cost_usd: 0.42,
        };
        let report = build_exit_report(
            "hash".to_string(),
            "tail".to_string(),
            5,
            Some(usage),
            &clean_monitor(),
        );
        assert_eq!(report.input_tokens, 1500);
        assert_eq!(report.output_tokens, 500);
        assert_eq!(report.cache_read_tokens, 200);
        assert!((report.cost_usd - 0.42).abs() < f64::EPSILON);
    }
}
