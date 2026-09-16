#![allow(clippy::disallowed_types)] // #1216 exempt: exit report collection is post-decision infrastructure
//! Exit report generation for execution receipts.
//!
//! Before shutdown, the tool-proxy computes a workspace content hash and
//! captures the audit chain tail, writing this as the final audit log entry.
//! The host (nucleus-node) reads this to build an `ExecutionReceipt`.

use nucleus::portcullis::kernel::Kernel;
use nucleus_spec::{ExitReport, sha256_bytes_hex};
use portcullis::trace_monitor::TraceMonitor;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

use crate::AuditLog;

/// Compute a deterministic SHA-256 hash of a directory's contents.
///
/// Walks the directory recursively, computes SHA-256 of each file's contents,
/// then hashes the sorted list of `(relative_path, file_hash)` pairs.
/// This produces a reproducible hash regardless of filesystem ordering.
///
/// Skips:
/// - Hidden files/directories (starting with `.`)
/// - The `.nucleus-exit-report.json` file itself
#[cfg(test)]
pub async fn hash_workspace(root: &Path) -> Result<String, std::io::Error> {
    hash_workspace_excluding(root, &[]).await
}

/// [`hash_workspace`], leaving out the files at `exclude`.
///
/// The supervisor's own audit log lives in the work dir on a microVM (the rootfs
/// is read-only), so it was hashed as if it were the workload's output. It is
/// timestamped and keyed per launch, which made `workspace_hash` differ on every
/// run of one program — measured by the A6 walk — and it is attested separately
/// by `audit_tail_hash`. The workload cannot write it (its directory is the
/// supervisor's), so excluding it hides nothing the workload produced.
pub async fn hash_workspace_excluding(
    root: &Path,
    exclude: &[&Path],
) -> Result<String, std::io::Error> {
    let mut entries: Vec<(String, String)> = Vec::new();
    collect_file_hashes(root, root, exclude, &mut entries).await?;
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
    exclude: &[&Path],
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
        if exclude.contains(&path.as_path()) {
            continue;
        }
        let file_type = entry.file_type().await?;

        if file_type.is_dir() {
            Box::pin(collect_file_hashes(root, &path, exclude, entries)).await?;
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
        // Populated by `apply_authority` from the kernel at shutdown.
        authority: None,
    }
}

/// Fold what the kernel granted and what the session used into the report:
/// ρ and the decision counts (ADR 0004). `task_grant_id` is the grant the
/// pod's spec named, if any.
pub fn apply_authority(report: &mut ExitReport, kernel: &Kernel, task_grant_id: Option<String>) {
    let mut summary = portcullis::summarise_authority(kernel.effective(), kernel.trace());
    summary.task_grant_id = task_grant_id;
    info!(
        granted = summary.granted_dimensions.len(),
        used = summary.used_dimensions.len(),
        overhead = ?summary.overhead,
        allowed = summary.allowed,
        denied = summary.denied,
        approvals = summary.approvals_requested,
        "exit report: authority summary captured"
    );
    report.authority = Some(summary);
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
/// `kernel_exposure` is the fallback, and on an HTTP pod it is the ONLY source.
/// `exposure_guard` is written by `NucleusMcpServer::new` alone, and the two
/// transports are mutually exclusive, so an HTTP pod reached both `return`s
/// below and shipped an exit report with `observed_exposure_labels` empty — for
/// its entire life, and indistinguishable from a session that was never exposed
/// to anything. The kernel is what actually accumulates exposure and gates on
/// it, so its set is the honest answer when the MCP guard is absent.
pub fn apply_exposure(
    report: &mut ExitReport,
    exposure_guard: &std::sync::RwLock<Option<std::sync::Arc<portcullis::GradedExposureGuard>>>,
    kernel_exposure: &portcullis::guard::ExposureSet,
) {
    let exposure = match exposure_guard.read() {
        Ok(guard_opt) => match guard_opt.as_ref() {
            Some(guard) => guard.exposure(),
            None => kernel_exposure.clone(),
        },
        // A poisoned lock is not "clean": fall back to the kernel rather than
        // returning, which would report no exposure at all.
        Err(_) => kernel_exposure.clone(),
    };
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

/// Write the exit report on shutdown (including verified exposure data and
/// the authority summary). Lives here rather than in main.rs so the report's
/// inputs are all in one place and main.rs stays under its line ratchet.
pub async fn write_exit_report(
    audit: &AuditLog,
    work_dir_path: &Path,
    exposure_guard: &std::sync::RwLock<Option<Arc<portcullis::GradedExposureGuard>>>,
    monitor: &portcullis::trace_monitor::TraceMonitor,
    art12_log: Option<&Arc<crate::art12::Art12Log>>,
    kernel: &Arc<tokio::sync::Mutex<Kernel>>,
    task_grant_id: Option<String>,
) {
    let workspace_hash =
        match hash_workspace_excluding(work_dir_path, &[audit.path.as_path()]).await {
            Ok(h) => h,
            Err(e) => {
                warn!("failed to hash workspace for exit report: {e}");
                crate::console_line(&format!(
                    "[exit-report] not written: hashing the workspace failed: {e}"
                ));
                return;
            }
        };

    let (tail_hash, count) = audit.tail_hash_and_count();
    let mut report = build_exit_report(workspace_hash, tail_hash, count, None, monitor);
    if !report.monitor_violations.is_empty() || report.monitor_violations_dropped > 0 {
        warn!(
            violations = ?report.monitor_violations,
            dropped = report.monitor_violations_dropped,
            "exit report: decision-stream properties were violated during this session"
        );
    }

    apply_art12(&mut report, art12_log);
    {
        let kernel = kernel.lock().await;
        apply_authority(&mut report, &kernel, task_grant_id);
        // Moved inside this block so the kernel's own exposure is available as
        // the fallback. It is read at shutdown either way, which is the point of
        // the field.
        apply_exposure(&mut report, exposure_guard, kernel.exposure());
    }

    let report_path = work_dir_path.join(nucleus_spec::exit_report_auth::EXIT_REPORT_FILE);
    let signed = crate::art12_sink::mediation_seed_from_env().map(|seed| {
        sign(
            report.clone(),
            &ed25519_dalek::SigningKey::from_bytes(&seed),
        )
    });
    let is_signed = signed.is_some();
    let json = match signed {
        // Signed whenever the pod has a mediation key — every node-launched
        // microVM does. See `nucleus_spec::exit_report_auth` for why the node
        // refuses an unsigned report on that path.
        Some(Ok(signed)) => serde_json::to_string_pretty(&signed),
        Some(Err(e)) => {
            warn!("failed to sign exit report: {e}");
            crate::console_line("[exit-report] not written: signing failed");
            return;
        }
        None => serde_json::to_string_pretty(&report),
    };
    let json = match json {
        Ok(json) => json,
        Err(e) => {
            warn!("failed to serialize exit report: {e}");
            return;
        }
    };
    match write_replacing(work_dir_path, &report_path, json.as_bytes()).await {
        Ok(()) => {
            // On the guest console, which the host keeps: tracing does not reach it,
            // and a missing receipt was invisible until this line existed.
            crate::console_line(&format!(
                "[exit-report] written (signed={is_signed}, entries={count})"
            ));
            info!(
                path = %report_path.display(),
                entries = count,
                event = "exit_report_written",
                "exit report written"
            )
        }
        Err(e) => {
            crate::console_line(&format!("[exit-report] not written: {e}"));
            warn!(
                "failed to write exit report to {}: {e}",
                report_path.display()
            )
        }
    }
}

/// Write the exit report as soon as the workload exits.
///
/// On a microVM the report used to be written only after the proxy stopped
/// serving, and nothing stops it: the VM outlives its workload, and the node ends
/// a pod by killing it. So the report — and the pod receipt built from it — was
/// never produced for a Firecracker pod. The workload's exit is the point after
/// which nothing it does is mediated, which makes it the right moment. The
/// shutdown write stays, and overwrites this one where shutdown is reached.
#[allow(clippy::too_many_arguments)]
pub(crate) fn on_workload_exit(
    audit: Arc<AuditLog>,
    work_dir: std::path::PathBuf,
    exposure_guard: Arc<std::sync::RwLock<Option<Arc<portcullis::GradedExposureGuard>>>>,
    monitor: Arc<TraceMonitor>,
    art12_log: Option<Arc<crate::art12::Art12Log>>,
    kernel: Arc<tokio::sync::Mutex<Kernel>>,
    task_grant_id: Option<String>,
) -> crate::workload_supervisor::ExitHook {
    Box::new(move || {
        Box::pin(async move {
            write_exit_report(
                &audit,
                &work_dir,
                &exposure_guard,
                &monitor,
                art12_log.as_ref(),
                &kernel,
                task_grant_id,
            )
            .await;
        })
    })
}

/// Sign `report` for the node, which verifies against its own record of the key.
pub(crate) fn sign(
    report: ExitReport,
    key: &ed25519_dalek::SigningKey,
) -> Result<nucleus_spec::exit_report_auth::SignedExitReport, serde_json::Error> {
    use ed25519_dalek::Signer;
    let bytes = nucleus_spec::exit_report_auth::signing_bytes(&report)?;
    Ok(nucleus_spec::exit_report_auth::SignedExitReport {
        signature: hex::encode(key.sign(&bytes).to_bytes()),
        signer_pubkey: hex::encode(key.verifying_key().to_bytes()),
        report,
    })
}

/// Write `path` without following anything the workload planted there.
///
/// The work dir belongs to the workload's uid and this process is the
/// supervisor, so a plain write would follow a symlink the workload placed at
/// `path` and write, with the supervisor's authority, wherever it points. The
/// bytes go to a fresh temp file opened `O_CREAT|O_EXCL|O_NOFOLLOW` (an existing
/// file or link at that name fails the open), then are renamed over `path`;
/// rename replaces a link rather than following it.
async fn write_replacing(dir: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let tmp = dir.join(format!(
        ".nucleus-exit-report.{}.{nanos}.tmp",
        std::process::id()
    ));
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&tmp).await?;
    let written = async {
        use tokio::io::AsyncWriteExt;
        file.write_all(bytes).await?;
        file.sync_all().await
    }
    .await;
    if let Err(e) = written {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    tokio::fs::rename(&tmp, path).await?;
    // The rename is a directory entry; without syncing the directory it can be
    // lost if the VM is killed before the journal commits, and a microVM is
    // ended by being killed.
    tokio::fs::File::open(dir).await?.sync_all().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// The report says what the kernel granted and what the session used,
    /// and names the grant the spec named.
    #[test]
    #[allow(deprecated)] // `decide` is the shortest way to a real trace
    fn the_authority_summary_comes_from_the_kernel_and_names_the_grant() {
        use portcullis::{Operation, PermissionLattice};
        let mut kernel = Kernel::new(PermissionLattice::restrictive());
        kernel.decide(Operation::ReadFiles, "src/main.rs");
        kernel.decide(Operation::GitPush, "origin main");
        let mut report = ExitReport {
            workspace_hash: "w".into(),
            audit_tail_hash: "t".into(),
            audit_entry_count: 2,
            timestamp_unix: 1,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cost_usd: 0.0,
            observed_exposure_labels: Vec::new(),
            observed_risk_tier: String::new(),
            uninhabitable_reached: false,
            monitor_violations: Vec::new(),
            monitor_violations_dropped: 0,
            art12_chain_head: String::new(),
            art12_records: 0,
            art12_dropped: 0,
            authority: None,
        };
        apply_authority(&mut report, &kernel, Some("grant-1".into()));
        let a = report.authority.expect("summary");
        assert_eq!(a.task_grant_id.as_deref(), Some("grant-1"));
        assert_eq!(a.allowed, 1);
        assert_eq!(a.denied, 1);
        assert_eq!(a.used_dimensions, vec!["read_files"]);
        assert!(a.overhead.is_some());
    }

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

    /// **An HTTP pod's exit report records the exposure it actually accumulated.**
    ///
    /// `exposure_guard` is written by `NucleusMcpServer::new` alone, and the two
    /// transports are mutually exclusive (`main.rs`: `if args.mcp { return … }`),
    /// so on an HTTP pod the slot is `None` for the pod's whole life. Before this,
    /// `apply_exposure` returned early on that `None` and the report shipped with
    /// `observed_exposure_labels` empty — indistinguishable from a session that
    /// touched nothing, for every HTTP pod ever run.
    ///
    /// The kernel is what accumulates exposure and gates on it, so it is the
    /// honest source when the MCP guard is absent.
    #[test]
    fn an_http_pod_reports_the_kernels_exposure_not_an_empty_set() {
        use portcullis::guard::{ExposureLabel, ExposureSet};

        let no_mcp_guard = std::sync::RwLock::new(None);

        // The control: nothing accumulated anywhere is still an empty report, so
        // the assertion below is about the SOURCE and not about the mapping.
        let mut clean = build_exit_report("w".into(), "t".into(), 1, None, &clean_monitor());
        apply_exposure(&mut clean, &no_mcp_guard, &ExposureSet::empty());
        assert!(
            clean.observed_exposure_labels.is_empty(),
            "an unexposed session must file an empty report, or the assertion below proves nothing"
        );

        // The kernel saw private data and untrusted content. With no MCP guard,
        // that is what the report must carry.
        let kernel_exposure = ExposureSet::singleton(ExposureLabel::PrivateData)
            .union(&ExposureSet::singleton(ExposureLabel::UntrustedContent));
        let mut report = build_exit_report("w".into(), "t".into(), 1, None, &clean_monitor());
        apply_exposure(&mut report, &no_mcp_guard, &kernel_exposure);

        assert!(
            report
                .observed_exposure_labels
                .contains(&"PrivateData".to_string()),
            "the kernel's PrivateData exposure must reach the exit report: {:?}",
            report.observed_exposure_labels
        );
        assert!(
            report
                .observed_exposure_labels
                .contains(&"UntrustedContent".to_string()),
            "the kernel's UntrustedContent exposure must reach the exit report: {:?}",
            report.observed_exposure_labels
        );
        assert!(
            !report
                .observed_exposure_labels
                .contains(&"ExfilVector".to_string()),
            "a leg the kernel did not record must not appear: {:?}",
            report.observed_exposure_labels
        );
    }

    /// A poisoned guard lock is not "clean" either.
    ///
    /// The early `return` on a failed read had the same shape as the `None` arm:
    /// it filed a report saying no exposure was observed. Under-reporting taint
    /// is the direction that makes a session look safer than it was.
    #[test]
    fn a_poisoned_guard_still_reports_the_kernels_exposure() {
        use portcullis::guard::{ExposureLabel, ExposureSet};

        let poisoned = std::sync::RwLock::new(None);
        let _ = std::panic::catch_unwind(|| {
            let _g = poisoned.write().expect("lock");
            panic!("poison it");
        });
        assert!(
            poisoned.read().is_err(),
            "the lock must actually be poisoned"
        );

        let kernel_exposure = ExposureSet::singleton(ExposureLabel::ExfilVector);
        let mut report = build_exit_report("w".into(), "t".into(), 1, None, &clean_monitor());
        apply_exposure(&mut report, &poisoned, &kernel_exposure);

        assert!(
            report
                .observed_exposure_labels
                .contains(&"ExfilVector".to_string()),
            "a poisoned MCP guard must fall back to the kernel, not to silence: {:?}",
            report.observed_exposure_labels
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

#[cfg(test)]
mod signed_report_tests {
    use super::*;

    /// What the supervisor writes is what the node's verifier accepts: the same
    /// preimage, the same key.
    #[test]
    fn a_signed_report_verifies_against_the_signing_key() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let report: ExitReport = serde_json::from_str(
            r#"{"workspace_hash":"w","audit_tail_hash":"t","audit_entry_count":1,"timestamp_unix":2}"#,
        )
        .unwrap();
        let signed = sign(report, &key).unwrap();
        assert_eq!(
            signed.signer_pubkey,
            hex::encode(key.verifying_key().to_bytes())
        );
        let sig: [u8; 64] = hex::decode(&signed.signature).unwrap().try_into().unwrap();
        let bytes = nucleus_spec::exit_report_auth::signing_bytes(&signed.report).unwrap();
        key.verifying_key()
            .verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&sig))
            .expect("verifies");
    }

    /// The workload owns the work dir and plants a symlink where the report goes.
    /// The supervisor's write must replace the link, never write through it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_symlink_planted_at_the_report_path_is_replaced_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let path = dir
            .path()
            .join(nucleus_spec::exit_report_auth::EXIT_REPORT_FILE);
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        write_replacing(dir.path(), &path, b"{\"report\":1}")
            .await
            .unwrap();

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"untouched",
            "the link was followed"
        );
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(
            meta.file_type().is_file(),
            "the link must be replaced by a file"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"report\":1}");
    }
}
