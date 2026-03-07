mod finding;
mod report;
mod scan_claude_settings;
mod scan_mcp_config;
mod scan_podspec;
mod tool_pattern;

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use finding::{ScanReport, Severity};

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
    /// At least one input source must be provided.
    Scan {
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
            pod_spec,
            claude_settings,
            mcp_config,
            audit_log,
            format,
        } => {
            if pod_spec.is_none() && claude_settings.is_none() && mcp_config.is_none() {
                eprintln!(
                    "Error: at least one of --pod-spec, --claude-settings, \
                     or --mcp-config is required"
                );
                std::process::exit(2);
            }

            let mut report = ScanReport::default();

            // Scan PodSpec if provided
            if let Some(ps_path) = &pod_spec {
                report = scan_podspec::scan_pod_spec(ps_path, audit_log.as_deref())?;
            }

            // Scan Claude settings if provided
            if let Some(cs_path) = &claude_settings {
                let (findings, summary) = scan_claude_settings::scan_claude_settings(cs_path)?;
                // If no PodSpec, derive trifecta info from settings findings
                if pod_spec.is_none() {
                    let has_trifecta = findings
                        .iter()
                        .any(|f| f.category == "trifecta" && f.severity == Severity::Critical);
                    report.trifecta_risk = if has_trifecta {
                        "Complete".to_string()
                    } else if findings.iter().any(|f| f.category == "trifecta") {
                        "Medium".to_string()
                    } else {
                        "None".to_string()
                    };
                    report.trifecta_enforced = false; // settings.json has no enforcement
                    report.has_credentials = findings.iter().any(|f| f.category == "credentials");
                }
                report.findings.extend(findings);
                report.claude_settings_summary = Some(summary);
            }

            // Scan MCP config if provided
            if let Some(mc_path) = &mcp_config {
                let (findings, summary) = scan_mcp_config::scan_mcp_config(mc_path)?;
                if findings.iter().any(|f| f.category == "credentials") {
                    report.has_credentials = true;
                }
                report.findings.extend(findings);
                report.mcp_config_summary = Some(summary);
            }

            // Sort all findings by severity
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
}
