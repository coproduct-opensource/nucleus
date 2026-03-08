mod discover;
mod finding;
mod report;
mod scan_claude_settings;
mod scan_mcp_config;
mod scan_podspec;
mod tool_pattern;

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use finding::{Finding, ScanReport, Severity};

#[derive(Parser, Debug)]
#[command(name = "nucleus-audit")]
#[command(about = "Verify, inspect, and scan nucleus audit logs and agent configurations")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify a tool-proxy JSONL audit log (HMAC signatures + hash chain).
    Verify {
        /// Audit log path to verify.
        #[arg(long, env = "NUCLEUS_AUDIT_LOG")]
        log: PathBuf,
        /// Audit log signing secret.
        #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_SECRET")]
        secret: Option<String>,
        /// Read the audit secret from a file.
        #[arg(long)]
        secret_file: Option<PathBuf>,
        /// Fallback to tool-proxy auth secret if audit secret is omitted.
        #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUTH_SECRET")]
        auth_secret: Option<String>,
    },
    /// Verify a portcullis permission audit log (hash chain only).
    VerifyChain {
        /// Audit log path (JSONL, each line is a portcullis AuditEntry).
        #[arg(long)]
        log: PathBuf,
        /// HMAC secret (required if entries were written with FileAuditBackend).
        #[arg(long, env = "NUCLEUS_AUDIT_SECRET")]
        secret: Option<String>,
    },
    /// Print a summary of audit events grouped by identity.
    Summary {
        /// Audit log path (tool-proxy JSONL format).
        #[arg(long, env = "NUCLEUS_AUDIT_LOG")]
        log: PathBuf,
    },
    /// Export audit log entries as formatted JSON.
    Export {
        /// Audit log path (tool-proxy JSONL format).
        #[arg(long, env = "NUCLEUS_AUDIT_LOG")]
        log: PathBuf,
        /// Output format.
        #[arg(long, default_value = "json")]
        format: ExportFormat,
    },
    /// Scan agent configurations for security posture and vulnerabilities.
    ///
    /// Supports PodSpec YAML, Claude Code settings.json, and MCP config files.
    /// Use --auto to discover configs in the current directory, or provide paths explicitly.
    Scan {
        /// Auto-discover config files in the current directory tree.
        #[arg(long)]
        auto: bool,
        /// Directory to scan when using --auto (defaults to current directory).
        #[arg(long, default_value = ".")]
        dir: PathBuf,
        /// Path to a PodSpec YAML/JSON file.
        #[arg(long)]
        pod_spec: Option<PathBuf>,
        /// Path to a Claude Code settings.json file.
        #[arg(long)]
        claude_settings: Option<PathBuf>,
        /// Path to an MCP config file (.mcp.json).
        #[arg(long)]
        mcp_config: Option<PathBuf>,
        /// Optional audit log to analyze runtime behavior against declared policy.
        #[arg(long)]
        audit_log: Option<PathBuf>,
        /// Output format (text or json).
        #[arg(long, default_value = "text")]
        format: ScanOutputFormat,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum ExportFormat {
    Json,
    Jsonl,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ScanOutputFormat {
    Text,
    Json,
}

#[derive(Debug, Deserialize)]
struct ToolProxyEntry {
    timestamp_unix: u64,
    actor: Option<String>,
    event: String,
    subject: String,
    result: String,
    prev_hash: String,
    hash: String,
    signature: String,
}

/// Signed line from FileAuditBackend.
#[derive(Debug, Deserialize)]
struct SignedLine {
    entry: serde_json::Value,
    hmac: String,
}

#[derive(thiserror::Error, Debug)]
pub enum AuditError {
    #[error("missing audit secret (use --secret, --secret-file, or env)")]
    MissingSecret,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse entry at line {line}: {source}")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    #[error("invalid audit log at line {line}: {message}")]
    Invalid { line: usize, message: String },
    #[error("error: {0}")]
    Backend(String),
}

fn main() -> Result<(), AuditError> {
    let cli = Cli::parse();

    match cli.command {
        Command::Verify {
            log,
            secret,
            secret_file,
            auth_secret,
        } => {
            let resolved = resolve_secret(
                secret.as_deref(),
                secret_file.as_deref(),
                auth_secret.as_deref(),
            )?;
            let count = verify_tool_proxy_log(&log, resolved.as_bytes())?;
            println!("ok: verified {} tool-proxy entries", count);
        }
        Command::VerifyChain { log, secret } => {
            let count = verify_portcullis_chain(&log, secret.as_deref())?;
            println!("ok: verified {} portcullis entries", count);
        }
        Command::Summary { log } => {
            print_summary(&log)?;
        }
        Command::Export { log, format } => {
            export_log(&log, &format)?;
        }
        Command::Scan {
            auto,
            dir,
            pod_spec,
            claude_settings,
            mcp_config,
            audit_log,
            format,
        } => {
            // Collect all config paths to scan
            let mut pod_specs: Vec<PathBuf> = pod_spec.into_iter().collect();
            let mut claude_settings_paths: Vec<PathBuf> = claude_settings.into_iter().collect();
            let mut mcp_configs: Vec<PathBuf> = mcp_config.into_iter().collect();

            if auto {
                let discovered = discover::discover_configs(&dir, 3);
                if discovered.is_empty()
                    && pod_specs.is_empty()
                    && claude_settings_paths.is_empty()
                    && mcp_configs.is_empty()
                {
                    eprintln!("No agent config files found in {}", dir.display());
                    eprintln!(
                        "Looked for: .claude/settings.json, .mcp.json, \
                         and PodSpec YAML in examples/podspecs/"
                    );
                    std::process::exit(2);
                }

                // Print discovery results
                if !discovered.is_empty() {
                    eprintln!(
                        "Discovered {} config file{}:",
                        discovered.total(),
                        if discovered.total() == 1 { "" } else { "s" }
                    );
                    for p in &discovered.claude_settings {
                        eprintln!("  Claude settings: {}", p.display());
                    }
                    for p in &discovered.mcp_configs {
                        eprintln!("  MCP config:      {}", p.display());
                    }
                    for p in &discovered.pod_specs {
                        eprintln!("  PodSpec:         {}", p.display());
                    }
                    eprintln!();
                }

                pod_specs.extend(discovered.pod_specs);
                claude_settings_paths.extend(discovered.claude_settings);
                mcp_configs.extend(discovered.mcp_configs);
            }

            if pod_specs.is_empty() && claude_settings_paths.is_empty() && mcp_configs.is_empty() {
                eprintln!(
                    "Error: at least one of --pod-spec, --claude-settings, \
                     --mcp-config, or --auto is required"
                );
                std::process::exit(2);
            }

            let total_sources = pod_specs.len() + claude_settings_paths.len() + mcp_configs.len();
            let include_source_in_finding = total_sources > 1;
            let single_pod_only =
                pod_specs.len() == 1 && claude_settings_paths.is_empty() && mcp_configs.is_empty();

            let mut report = ScanReport::default();
            let mut aggregate_trifecta_rank = 0u8;
            let mut aggregate_has_pod = false;
            let mut aggregate_network_posture: Option<String> = None;
            let mut aggregate_isolation_level: Option<String> = None;

            // Scan PodSpecs
            for ps_path in &pod_specs {
                let ps_report = scan_podspec::scan_pod_spec(ps_path, audit_log.as_deref())?;
                report.scanned_sources.push(ps_path.display().to_string());

                aggregate_has_pod = true;
                aggregate_trifecta_rank =
                    aggregate_trifecta_rank.max(trifecta_rank_from_str(&ps_report.trifecta_risk));
                merge_dimension(&mut aggregate_network_posture, &ps_report.network_posture);
                merge_dimension(&mut aggregate_isolation_level, &ps_report.isolation_level);
                report.has_credentials |= ps_report.has_credentials;

                if single_pod_only {
                    report.pod_name = ps_report.pod_name.clone();
                    report.policy_profile = ps_report.policy_profile.clone();
                    report.trifecta_risk = ps_report.trifecta_risk.clone();
                    report.trifecta_enforced = ps_report.trifecta_enforced;
                    report.permission_surface = ps_report.permission_surface.clone();
                    report.network_posture = ps_report.network_posture.clone();
                    report.isolation_level = ps_report.isolation_level.clone();
                    report.runtime_metrics = ps_report.runtime_metrics.clone();
                }

                report.findings.extend(attach_source_to_findings(
                    ps_report.findings,
                    ps_path,
                    include_source_in_finding,
                ));
            }

            // Scan Claude settings
            for cs_path in &claude_settings_paths {
                let (findings, summary) = scan_claude_settings::scan_claude_settings(cs_path)?;
                report.scanned_sources.push(cs_path.display().to_string());

                let has_critical_trifecta = findings
                    .iter()
                    .any(|f| f.category == "trifecta" && f.severity == Severity::Critical);
                let has_partial_trifecta = findings.iter().any(|f| f.category == "trifecta");
                let claude_rank = if has_critical_trifecta {
                    2
                } else if has_partial_trifecta {
                    1
                } else {
                    0
                };
                aggregate_trifecta_rank = aggregate_trifecta_rank.max(claude_rank);
                report.has_credentials |= findings.iter().any(|f| f.category == "credentials");

                if claude_settings_paths.len() == 1 {
                    report.claude_settings_summary = Some(summary);
                }

                report.findings.extend(attach_source_to_findings(
                    findings,
                    cs_path,
                    include_source_in_finding,
                ));
            }

            // Scan MCP configs
            for mc_path in &mcp_configs {
                let (findings, summary) = scan_mcp_config::scan_mcp_config(mc_path)?;
                report.scanned_sources.push(mc_path.display().to_string());

                if findings.iter().any(|f| f.category == "credentials") {
                    report.has_credentials = true;
                }
                if mcp_configs.len() == 1 {
                    report.mcp_config_summary = Some(summary);
                }

                report.findings.extend(attach_source_to_findings(
                    findings,
                    mc_path,
                    include_source_in_finding,
                ));
            }

            if !single_pod_only {
                report.pod_name = None;
                report.policy_profile = None;
                report.trifecta_risk = trifecta_label_from_rank(aggregate_trifecta_rank);
                report.trifecta_enforced = false;
                report.permission_surface = Default::default();
                report.network_posture = if aggregate_has_pod {
                    aggregate_network_posture.unwrap_or_else(|| "multiple".to_string())
                } else {
                    "unspecified".to_string()
                };
                report.isolation_level = if aggregate_has_pod {
                    aggregate_isolation_level.unwrap_or_else(|| "multiple".to_string())
                } else {
                    "none".to_string()
                };
                report.runtime_metrics = None;
            }

            dedupe_findings(&mut report.findings);
            report.scanned_sources.sort();

            // Sort all findings by severity then title
            report.findings.sort_by(|a, b| a.severity.cmp(&b.severity));

            match format {
                ScanOutputFormat::Text => report::print_scan_report(&report),
                ScanOutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&report).unwrap());
                }
            }

            // Exit with non-zero status if critical or high findings exist
            let worst = report
                .findings
                .iter()
                .map(|f| &f.severity)
                .min()
                .cloned()
                .unwrap_or(Severity::Info);
            if worst <= Severity::High {
                std::process::exit(1);
            }
        }
    }

    Ok(())
}

fn attach_source_to_findings(
    findings: Vec<Finding>,
    source: &Path,
    include_source: bool,
) -> Vec<Finding> {
    if !include_source {
        return findings;
    }
    let source = source.display().to_string();
    findings
        .into_iter()
        .map(|mut finding| {
            finding.title = format!("[{}] {}", source, finding.title);
            finding
        })
        .collect()
}

fn dedupe_findings(findings: &mut Vec<Finding>) {
    let mut seen: HashSet<(Severity, String, String, String)> = HashSet::new();
    findings.retain(|f| {
        seen.insert((
            f.severity.clone(),
            f.category.clone(),
            f.title.clone(),
            f.description.clone(),
        ))
    });
}

fn trifecta_rank_from_str(risk: &str) -> u8 {
    match risk {
        "Complete" => 2,
        "Medium" | "Low" => 1,
        _ => 0,
    }
}

fn trifecta_label_from_rank(rank: u8) -> String {
    match rank {
        2 => "Complete".to_string(),
        1 => "Medium".to_string(),
        _ => "None".to_string(),
    }
}

fn merge_dimension(current: &mut Option<String>, next: &str) {
    match current {
        None => *current = Some(next.to_string()),
        Some(value) if value == "multiple" => {}
        Some(value) if value == next => {}
        Some(value) => *value = "multiple".to_string(),
    }
}

// --- verify (tool-proxy) ---

fn resolve_secret(
    secret: Option<&str>,
    secret_file: Option<&Path>,
    auth_secret: Option<&str>,
) -> Result<String, AuditError> {
    if let Some(s) = secret {
        return Ok(s.to_string());
    }
    if let Some(path) = secret_file {
        let s = std::fs::read_to_string(path)?.trim().to_string();
        if s.is_empty() {
            return Err(AuditError::MissingSecret);
        }
        return Ok(s);
    }
    if let Some(s) = auth_secret {
        return Ok(s.to_string());
    }
    Err(AuditError::MissingSecret)
}

fn verify_tool_proxy_log(path: &Path, secret: &[u8]) -> Result<usize, AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut prev_hash = String::new();
    let mut count = 0usize;

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = idx + 1;
        let entry: ToolProxyEntry =
            serde_json::from_str(line).map_err(|source| AuditError::Json {
                line: line_no,
                source,
            })?;
        if entry.prev_hash != prev_hash {
            return Err(AuditError::Invalid {
                line: line_no,
                message: format!(
                    "prev_hash mismatch (expected {}, got {})",
                    prev_hash, entry.prev_hash
                ),
            });
        }
        let actor = entry.actor.clone().unwrap_or_default();
        let message = format!(
            "{}|{}|{}|{}|{}|{}",
            entry.timestamp_unix, actor, entry.event, entry.subject, entry.result, prev_hash
        );
        let signature = sign_message(secret, message.as_bytes());
        if signature != entry.signature {
            return Err(AuditError::Invalid {
                line: line_no,
                message: "signature mismatch".to_string(),
            });
        }
        let hash = sha256_hex(&format!("{}|{}", message, signature));
        if hash != entry.hash {
            return Err(AuditError::Invalid {
                line: line_no,
                message: "hash mismatch".to_string(),
            });
        }
        prev_hash = entry.hash.clone();
        count += 1;
    }

    Ok(count)
}

// --- verify-chain (portcullis) ---

fn verify_portcullis_chain(path: &Path, secret: Option<&str>) -> Result<usize, AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries: Vec<portcullis::AuditEntry> = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = idx + 1;

        let entry: portcullis::AuditEntry =
            if let Ok(signed) = serde_json::from_str::<SignedLine>(line) {
                if let Some(secret) = secret {
                    let entry_str = serde_json::to_string(&signed.entry)
                        .map_err(|e| AuditError::Backend(e.to_string()))?;
                    let expected = hmac_hex(secret.as_bytes(), entry_str.as_bytes());
                    if expected != signed.hmac {
                        return Err(AuditError::Invalid {
                            line: line_no,
                            message: "HMAC verification failed".to_string(),
                        });
                    }
                }
                serde_json::from_value(signed.entry).map_err(|source| AuditError::Json {
                    line: line_no,
                    source,
                })?
            } else {
                serde_json::from_str(line).map_err(|source| AuditError::Json {
                    line: line_no,
                    source,
                })?
            };

        entries.push(entry);
    }

    if !entries.is_empty() {
        if entries[0].prev_hash.is_some() {
            return Err(AuditError::Invalid {
                line: 1,
                message: "genesis entry has non-None prev_hash".to_string(),
            });
        }

        for i in 1..entries.len() {
            let expected = entries[i - 1].content_hash();
            match &entries[i].prev_hash {
                Some(actual) if *actual == expected => {}
                Some(actual) => {
                    return Err(AuditError::Invalid {
                        line: i + 1,
                        message: format!(
                            "hash chain broken: expected {}, got {}",
                            expected, actual
                        ),
                    });
                }
                None => {
                    return Err(AuditError::Invalid {
                        line: i + 1,
                        message: "missing prev_hash on non-genesis entry".to_string(),
                    });
                }
            }
        }
    }

    Ok(entries.len())
}

// --- summary ---

fn print_summary(path: &Path) -> Result<(), AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut by_event: HashMap<String, usize> = HashMap::new();
    let mut by_actor: HashMap<String, usize> = HashMap::new();
    let mut by_result: HashMap<String, usize> = HashMap::new();
    let mut total = 0usize;

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: ToolProxyEntry =
            serde_json::from_str(line).map_err(|source| AuditError::Json {
                line: idx + 1,
                source,
            })?;

        *by_event.entry(entry.event).or_insert(0) += 1;
        let actor = entry.actor.unwrap_or_else(|| "<none>".to_string());
        *by_actor.entry(actor).or_insert(0) += 1;
        let result_key = if entry.result.starts_with("denied") {
            "denied".to_string()
        } else {
            entry.result
        };
        *by_result.entry(result_key).or_insert(0) += 1;
        total += 1;
    }

    println!("=== Audit Log Summary ===");
    println!("Total entries: {}", total);
    println!();

    println!("By event type:");
    let mut events: Vec<_> = by_event.into_iter().collect();
    events.sort_by(|a, b| b.1.cmp(&a.1));
    for (event, count) in &events {
        println!("  {:<30} {}", event, count);
    }
    println!();

    println!("By actor:");
    let mut actors: Vec<_> = by_actor.into_iter().collect();
    actors.sort_by(|a, b| b.1.cmp(&a.1));
    for (actor, count) in &actors {
        println!("  {:<30} {}", actor, count);
    }
    println!();

    println!("By result:");
    let mut results: Vec<_> = by_result.into_iter().collect();
    results.sort_by(|a, b| b.1.cmp(&a.1));
    for (result, count) in &results {
        println!("  {:<30} {}", result, count);
    }

    Ok(())
}

// --- export ---

fn export_log(path: &Path, format: &ExportFormat) -> Result<(), AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries: Vec<serde_json::Value> = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let entry: serde_json::Value =
            serde_json::from_str(line).map_err(|source| AuditError::Json {
                line: idx + 1,
                source,
            })?;
        entries.push(entry);
    }

    match format {
        ExportFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&entries).unwrap());
        }
        ExportFormat::Jsonl => {
            for entry in &entries {
                println!("{}", serde_json::to_string(entry).unwrap());
            }
        }
    }

    Ok(())
}

// --- crypto helpers ---

fn sign_message(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

fn hmac_hex(secret: &[u8], message: &[u8]) -> String {
    sign_message(secret, message)
}

fn sha256_hex(message: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_pod_spec(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
        use std::io::Write;
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn test_scan_restrictive_pod_clean() {
        let dir = tempfile::tempdir().unwrap();
        let spec = write_pod_spec(
            dir.path(),
            "pod.yaml",
            r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: safe-agent
spec:
  work_dir: /workspace
  timeout_seconds: 300
  policy:
    type: profile
    name: read_only
  network:
    deny:
      - "0.0.0.0/0"
  image:
    kernel_path: /var/lib/vmlinux
    rootfs_path: /var/lib/rootfs.ext4
    read_only: true
"#,
        );

        let report = scan_podspec::scan_pod_spec(&spec, None).unwrap();
        assert_eq!(report.policy_profile.as_deref(), Some("read_only"));
        assert_eq!(report.network_posture, "airgapped");
        assert_eq!(report.isolation_level, "firecracker");
        assert!(!report.has_credentials);
        assert!(
            report.findings.is_empty(),
            "Expected no findings, got: {:?}",
            report.findings
        );
    }

    #[test]
    fn test_scan_permissive_flags_issues() {
        let dir = tempfile::tempdir().unwrap();
        let spec = write_pod_spec(
            dir.path(),
            "pod.yaml",
            r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: danger-agent
spec:
  work_dir: /workspace
  timeout_seconds: 86400
  policy:
    type: profile
    name: permissive
  credentials:
    env:
      ROOT_PASSWORD: "hunter2"
      AWS_SECRET_ACCESS_KEY: "AKIA..."
"#,
        );

        let report = scan_podspec::scan_pod_spec(&spec, None).unwrap();
        assert_eq!(report.trifecta_risk, "Complete");
        assert!(report.trifecta_enforced);
        assert_eq!(report.network_posture, "unspecified");
        assert_eq!(report.isolation_level, "none");
        assert!(report.has_credentials);

        let severities: Vec<&Severity> = report.findings.iter().map(|f| &f.severity).collect();
        assert!(
            severities.contains(&&Severity::High),
            "Should have HIGH findings"
        );
        assert!(
            severities.contains(&&Severity::Medium),
            "Should have MEDIUM findings"
        );

        let cred_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.category == "credentials")
            .collect();
        assert!(
            cred_findings.len() >= 2,
            "Should flag ROOT_PASSWORD and AWS_SECRET_ACCESS_KEY"
        );
    }

    #[test]
    fn test_scan_json_output_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let spec = write_pod_spec(
            dir.path(),
            "pod.yaml",
            r#"
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: test
spec:
  work_dir: /workspace
  policy:
    type: profile
    name: fix_issue
"#,
        );

        let report = scan_podspec::scan_pod_spec(&spec, None).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["policy_profile"], "fix_issue");
        assert_eq!(parsed["trifecta_enforced"], true);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical < Severity::High);
        assert!(Severity::High < Severity::Medium);
        assert!(Severity::Medium < Severity::Low);
        assert!(Severity::Low < Severity::Info);
    }

    #[test]
    fn test_attach_source_to_findings_prefixes_title() {
        let findings = vec![Finding {
            severity: Severity::Medium,
            category: "test".to_string(),
            title: "Sample finding".to_string(),
            description: "desc".to_string(),
        }];
        let out = attach_source_to_findings(findings, Path::new("foo.yaml"), true);
        assert_eq!(out.len(), 1);
        assert!(out[0].title.starts_with("[foo.yaml] "));
    }

    #[test]
    fn test_dedupe_findings_removes_exact_duplicates() {
        let mut findings = vec![
            Finding {
                severity: Severity::High,
                category: "network".to_string(),
                title: "A".to_string(),
                description: "D".to_string(),
            },
            Finding {
                severity: Severity::High,
                category: "network".to_string(),
                title: "A".to_string(),
                description: "D".to_string(),
            },
        ];
        dedupe_findings(&mut findings);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_merge_dimension_marks_multiple() {
        let mut dim = None;
        merge_dimension(&mut dim, "airgapped");
        merge_dimension(&mut dim, "filtered");
        assert_eq!(dim.as_deref(), Some("multiple"));
    }
}
