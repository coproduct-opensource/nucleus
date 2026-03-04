use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use hmac::{Hmac, Mac};
use lattice_guard::CapabilityLevel;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "nucleus-audit")]
#[command(about = "Verify, inspect, and scan nucleus audit logs and pod specifications")]
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
    /// Verify a lattice-guard permission audit log (hash chain only).
    VerifyChain {
        /// Audit log path (JSONL, each line is a lattice-guard AuditEntry).
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
    /// Scan a PodSpec for security posture and potential vulnerabilities.
    ///
    /// Analyzes permission policies, network configuration, credential handling,
    /// and isolation settings. Optionally cross-references against an audit log
    /// to detect runtime deviations from declared policy.
    Scan {
        /// Path to a PodSpec YAML/JSON file.
        #[arg(long)]
        pod_spec: PathBuf,
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
enum ScanOutputFormat {
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
enum AuditError {
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
    #[error("lattice-guard backend error: {0}")]
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
            let count = verify_lattice_guard_chain(&log, secret.as_deref())?;
            println!("ok: verified {} lattice-guard entries", count);
        }
        Command::Summary { log } => {
            print_summary(&log)?;
        }
        Command::Export { log, format } => {
            export_log(&log, &format)?;
        }
        Command::Scan {
            pod_spec,
            audit_log,
            format,
        } => {
            let report = scan_pod_spec(&pod_spec, audit_log.as_deref())?;
            match format {
                ScanOutputFormat::Text => print_scan_report(&report),
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

// --- verify-chain (lattice-guard) ---

fn verify_lattice_guard_chain(path: &Path, secret: Option<&str>) -> Result<usize, AuditError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut entries: Vec<lattice_guard::AuditEntry> = Vec::new();

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = idx + 1;

        // Try signed format first (FileAuditBackend), then raw entry
        let entry: lattice_guard::AuditEntry =
            if let Ok(signed) = serde_json::from_str::<SignedLine>(line) {
                // Verify HMAC if secret provided
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

    // Verify hash chain linkage
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

// --- scan ---

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum Severity {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
    Info = 4,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct Finding {
    severity: Severity,
    category: String,
    title: String,
    description: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct ScanReport {
    pod_name: Option<String>,
    policy_profile: String,
    trifecta_risk: String,
    trifecta_enforced: bool,
    permission_surface: PermissionSurface,
    network_posture: String,
    isolation_level: String,
    has_credentials: bool,
    findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_metrics: Option<RuntimeMetrics>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct PermissionSurface {
    total_capabilities: usize,
    always_allowed: Vec<String>,
    low_risk: Vec<String>,
    never: Vec<String>,
    approval_required: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct RuntimeMetrics {
    total_entries: usize,
    chain_valid: bool,
    deviations: usize,
    trifecta_completions: usize,
    blocks: usize,
    identities: usize,
}

fn scan_pod_spec(
    pod_spec_path: &Path,
    audit_log_path: Option<&Path>,
) -> Result<ScanReport, AuditError> {
    let yaml = std::fs::read_to_string(pod_spec_path)?;
    let spec: nucleus_spec::PodSpec = serde_yaml::from_str(&yaml)
        .map_err(|e| AuditError::Backend(format!("failed to parse PodSpec: {}", e)))?;

    let lattice = spec
        .spec
        .resolve_policy()
        .map_err(|e| AuditError::Backend(format!("failed to resolve policy: {}", e)))?;

    let mut findings = Vec::new();

    // --- Policy analysis ---

    let policy_profile = match &spec.spec.policy {
        nucleus_spec::PolicySpec::Profile { name } => name.clone(),
        nucleus_spec::PolicySpec::Inline { .. } => "inline".to_string(),
    };

    let trifecta_config = lattice_guard::IncompatibilityConstraint::enforcing();
    let trifecta_risk = trifecta_config.trifecta_risk(&lattice.capabilities);
    let trifecta_enforced = lattice.trifecta_constraint;

    if !trifecta_enforced {
        findings.push(Finding {
            severity: Severity::Critical,
            category: "trifecta".to_string(),
            title: "Trifecta enforcement disabled".to_string(),
            description: "The lethal trifecta constraint is disabled. An agent with \
                private data access + untrusted content + external communication can \
                exfiltrate data without approval gates."
                .to_string(),
        });
    }

    let trifecta_str = format!("{:?}", trifecta_risk);
    if trifecta_risk == lattice_guard::TrifectaRisk::Complete && trifecta_enforced {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "trifecta".to_string(),
            title: "Complete trifecta with enforcement".to_string(),
            description: "All three trifecta components are present. Enforcement is \
                enabled so exfiltration operations will require approval, but the \
                attack surface is maximal."
                .to_string(),
        });
    } else if trifecta_risk == lattice_guard::TrifectaRisk::Complete && !trifecta_enforced {
        findings.push(Finding {
            severity: Severity::Critical,
            category: "trifecta".to_string(),
            title: "Complete trifecta WITHOUT enforcement".to_string(),
            description: "All three trifecta components are present and enforcement \
                is disabled. This agent can read private data, fetch untrusted content, \
                and push to external systems without any approval gate."
                .to_string(),
        });
    }

    // --- Capability surface analysis ---

    let caps = &lattice.capabilities;
    let cap_fields: Vec<(&str, CapabilityLevel)> = vec![
        ("read_files", caps.read_files),
        ("write_files", caps.write_files),
        ("edit_files", caps.edit_files),
        ("run_bash", caps.run_bash),
        ("glob_search", caps.glob_search),
        ("grep_search", caps.grep_search),
        ("web_search", caps.web_search),
        ("web_fetch", caps.web_fetch),
        ("git_commit", caps.git_commit),
        ("git_push", caps.git_push),
        ("create_pr", caps.create_pr),
        ("manage_pods", caps.manage_pods),
    ];

    let always_allowed: Vec<String> = cap_fields
        .iter()
        .filter(|(_, l)| *l == CapabilityLevel::Always)
        .map(|(n, _)| n.to_string())
        .collect();
    let low_risk: Vec<String> = cap_fields
        .iter()
        .filter(|(_, l)| *l == CapabilityLevel::LowRisk)
        .map(|(n, _)| n.to_string())
        .collect();
    let never: Vec<String> = cap_fields
        .iter()
        .filter(|(_, l)| *l == CapabilityLevel::Never)
        .map(|(n, _)| n.to_string())
        .collect();

    let approval_required: Vec<String> = lattice
        .obligations
        .approvals
        .iter()
        .map(|op| format!("{:?}", op).to_lowercase())
        .collect();

    // High-risk capabilities without approval obligations
    let dangerous_ops = ["run_bash", "git_push", "create_pr", "manage_pods"];
    for (name, level) in &cap_fields {
        if dangerous_ops.contains(name) && *level >= CapabilityLevel::Always {
            let op_name = format!(
                "{:?}",
                match *name {
                    "run_bash" => lattice_guard::Operation::RunBash,
                    "git_push" => lattice_guard::Operation::GitPush,
                    "create_pr" => lattice_guard::Operation::CreatePr,
                    "manage_pods" => lattice_guard::Operation::ManagePods,
                    _ => continue,
                }
            );
            let has_approval = approval_required
                .iter()
                .any(|a| a == &op_name.to_lowercase());
            if !has_approval {
                findings.push(Finding {
                    severity: Severity::High,
                    category: "permissions".to_string(),
                    title: format!("{} is always-allowed without approval", name),
                    description: format!(
                        "The capability '{}' is set to Always with no approval \
                         obligation. Consider requiring human approval for this \
                         high-risk operation.",
                        name
                    ),
                });
            }
        }
    }

    if policy_profile == "permissive" {
        findings.push(Finding {
            severity: Severity::High,
            category: "policy".to_string(),
            title: "Permissive policy profile".to_string(),
            description: "The 'permissive' profile enables most capabilities. \
                Use a more restrictive profile like 'fix_issue' or 'code_review' \
                to enforce least privilege."
                .to_string(),
        });
    }

    // --- Network analysis ---

    let network_posture = match &spec.spec.network {
        Some(net) if !net.deny.is_empty() && net.dns_allow.is_empty() => "airgapped",
        Some(net) if !net.dns_allow.is_empty() => "filtered",
        Some(_) => "permissive",
        None => "unspecified",
    };

    if network_posture == "unspecified" {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "network".to_string(),
            title: "No network policy specified".to_string(),
            description: "The PodSpec has no network configuration. The agent's \
                network access depends on the executor's defaults. Specify an \
                explicit NetworkSpec (deny_all, package_registries, or permissive)."
                .to_string(),
        });
    } else if network_posture == "permissive" {
        findings.push(Finding {
            severity: Severity::High,
            category: "network".to_string(),
            title: "Unrestricted network egress".to_string(),
            description: "The agent has unrestricted outbound network access. \
                This enables data exfiltration to arbitrary destinations. Use \
                NetworkSpec::package_registries() or deny_all() to restrict egress."
                .to_string(),
        });
    }

    // --- Isolation analysis ---

    let isolation_level = if spec.spec.image.is_some() {
        "firecracker"
    } else if spec.spec.seccomp.is_some() || spec.spec.cgroup.is_some() {
        "container"
    } else {
        "none"
    };

    if isolation_level == "none" {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "isolation".to_string(),
            title: "No VM/container isolation configured".to_string(),
            description: "The PodSpec has no image, seccomp, or cgroup configuration. \
                The agent will run with host-level access unless the executor provides \
                isolation. Configure ImageSpec for Firecracker VM isolation."
                .to_string(),
        });
    }

    if let Some(nucleus_spec::SeccompSpec::Disabled) = &spec.spec.seccomp {
        findings.push(Finding {
            severity: Severity::High,
            category: "isolation".to_string(),
            title: "Seccomp disabled".to_string(),
            description: "Seccomp filtering is explicitly disabled. The agent process \
                can invoke any system call. Use Default or a custom filter."
                .to_string(),
        });
    }

    // --- Credential analysis ---

    let has_credentials = spec
        .spec
        .credentials
        .as_ref()
        .is_some_and(|c| !c.is_empty());
    if has_credentials {
        let creds = spec.spec.credentials.as_ref().unwrap();
        let dangerous_patterns = [
            "ROOT",
            "ADMIN",
            "MASTER",
            "PRIVATE_KEY",
            "AWS_SECRET",
            "DATABASE_URL",
        ];
        for key in creds.env.keys() {
            let upper = key.to_uppercase();
            for pattern in &dangerous_patterns {
                if upper.contains(pattern) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: "credentials".to_string(),
                        title: format!("High-privilege credential: {}", key),
                        description: format!(
                            "Credential '{}' matches pattern '{}'. Ensure this \
                             agent requires this level of access and that the \
                             credential is scoped to minimum privileges.",
                            key, pattern
                        ),
                    });
                }
            }
        }

        if creds.env.len() > 5 {
            findings.push(Finding {
                severity: Severity::Medium,
                category: "credentials".to_string(),
                title: format!("{} credentials injected", creds.env.len()),
                description: "A large number of credentials are injected. Each \
                    credential increases the blast radius of a compromised agent. \
                    Review whether all credentials are necessary."
                    .to_string(),
            });
        }
    }

    // --- Timeout analysis ---

    if spec.spec.timeout_seconds > 7200 {
        findings.push(Finding {
            severity: Severity::Low,
            category: "timeout".to_string(),
            title: format!("Long timeout: {}s", spec.spec.timeout_seconds),
            description: "Execution timeout exceeds 2 hours. Long-running agents \
                have more time to perform unauthorized actions if compromised. \
                Consider a shorter timeout with resume capability."
                .to_string(),
        });
    }

    // --- Runtime audit log analysis ---

    let runtime_metrics = if let Some(log_path) = audit_log_path {
        Some(analyze_audit_log(log_path, &mut findings)?)
    } else {
        None
    };

    // Sort findings by severity
    findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    Ok(ScanReport {
        pod_name: spec.metadata.name,
        policy_profile,
        trifecta_risk: trifecta_str,
        trifecta_enforced,
        permission_surface: PermissionSurface {
            total_capabilities: cap_fields.len(),
            always_allowed,
            low_risk,
            never,
            approval_required,
        },
        network_posture: network_posture.to_string(),
        isolation_level: isolation_level.to_string(),
        has_credentials,
        findings,
        runtime_metrics,
    })
}

fn analyze_audit_log(
    log_path: &Path,
    findings: &mut Vec<Finding>,
) -> Result<RuntimeMetrics, AuditError> {
    let file = File::open(log_path)?;
    let reader = BufReader::new(file);

    let log = lattice_guard::audit::AuditLog::in_memory();
    let mut identities: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut deviations = 0usize;
    let mut trifecta_completions = 0usize;
    let mut blocks = 0usize;
    let mut total = 0usize;

    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Try lattice-guard AuditEntry format
        let entry: lattice_guard::AuditEntry =
            if let Ok(signed) = serde_json::from_str::<SignedLine>(line) {
                serde_json::from_value(signed.entry).map_err(|source| AuditError::Json {
                    line: idx + 1,
                    source,
                })?
            } else {
                serde_json::from_str(line).map_err(|source| AuditError::Json {
                    line: idx + 1,
                    source,
                })?
            };

        identities.insert(entry.identity.clone());

        if entry.is_deviation() {
            deviations += 1;
        }
        if let Some(lattice_guard::TrifectaRisk::Complete) = entry.trifecta_impact() {
            trifecta_completions += 1;
        }
        if matches!(
            &entry.event,
            lattice_guard::audit::PermissionEvent::ExecutionBlocked { .. }
        ) {
            blocks += 1;
        }

        log.record(entry);
        total += 1;
    }

    let chain_valid = log.verify_chain().is_ok();

    if !chain_valid {
        findings.push(Finding {
            severity: Severity::Critical,
            category: "audit_integrity".to_string(),
            title: "Audit log hash chain broken".to_string(),
            description: "The audit log's cryptographic hash chain is invalid. \
                This indicates tampering or corruption. The audit trail cannot \
                be trusted."
                .to_string(),
        });
    }

    if trifecta_completions > 0 {
        findings.push(Finding {
            severity: Severity::High,
            category: "runtime".to_string(),
            title: format!(
                "{} trifecta completion{} detected",
                trifecta_completions,
                if trifecta_completions == 1 { "" } else { "s" }
            ),
            description: format!(
                "The audit log contains {} events where all three lethal trifecta \
                 components were active simultaneously. Review these events for \
                 potential data exfiltration.",
                trifecta_completions
            ),
        });
    }

    let deviation_rate = if total > 0 {
        deviations as f64 / total as f64
    } else {
        0.0
    };

    if deviation_rate > 0.1 {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "runtime".to_string(),
            title: format!("High deviation rate: {:.1}%", deviation_rate * 100.0),
            description: format!(
                "{} of {} audit events ({:.1}%) are deviations from declared \
                 permissions. This suggests the declared policy is too restrictive \
                 (agents constantly escalating) or the agent is misbehaving.",
                deviations,
                total,
                deviation_rate * 100.0
            ),
        });
    }

    Ok(RuntimeMetrics {
        total_entries: total,
        chain_valid,
        deviations,
        trifecta_completions,
        blocks,
        identities: identities.len(),
    })
}

fn print_scan_report(report: &ScanReport) {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║               NUCLEUS SECURITY SCAN REPORT                 ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // --- Overview ---
    if let Some(name) = &report.pod_name {
        println!("  Pod:            {}", name);
    }
    println!("  Policy:         {}", report.policy_profile);
    println!("  Trifecta risk:  {}", report.trifecta_risk);
    println!(
        "  Trifecta guard: {}",
        if report.trifecta_enforced {
            "ENFORCED"
        } else {
            "DISABLED"
        }
    );
    println!("  Network:        {}", report.network_posture);
    println!("  Isolation:      {}", report.isolation_level);
    println!(
        "  Credentials:    {}",
        if report.has_credentials {
            "present"
        } else {
            "none"
        }
    );
    println!();

    // --- Permission surface ---
    println!("── Permission Surface ──────────────────────────────────────────");
    if !report.permission_surface.always_allowed.is_empty() {
        println!(
            "  Always allowed:    {}",
            report.permission_surface.always_allowed.join(", ")
        );
    }
    if !report.permission_surface.low_risk.is_empty() {
        println!(
            "  Low-risk auto:     {}",
            report.permission_surface.low_risk.join(", ")
        );
    }
    if !report.permission_surface.never.is_empty() {
        println!(
            "  Never allowed:     {}",
            report.permission_surface.never.join(", ")
        );
    }
    if !report.permission_surface.approval_required.is_empty() {
        println!(
            "  Approval required: {}",
            report.permission_surface.approval_required.join(", ")
        );
    }
    println!();

    // --- Runtime metrics ---
    if let Some(metrics) = &report.runtime_metrics {
        println!("── Runtime Analysis ────────────────────────────────────────────");
        println!("  Audit entries:     {}", metrics.total_entries);
        println!(
            "  Chain integrity:   {}",
            if metrics.chain_valid {
                "VALID"
            } else {
                "BROKEN"
            }
        );
        println!("  Identities:        {}", metrics.identities);
        println!("  Deviations:        {}", metrics.deviations);
        println!("  Trifecta events:   {}", metrics.trifecta_completions);
        println!("  Blocked:           {}", metrics.blocks);
        println!();
    }

    // --- Findings ---
    let critical_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium_count = report
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low_count = report
        .findings
        .iter()
        .filter(|f| f.severity <= Severity::Low)
        .count();

    println!(
        "── Findings ({} critical, {} high, {} medium, {} low) ──────────",
        critical_count, high_count, medium_count, low_count
    );
    println!();

    for finding in &report.findings {
        let marker = match finding.severity {
            Severity::Critical => "!!",
            Severity::High => "! ",
            Severity::Medium => "~ ",
            Severity::Low => "- ",
            Severity::Info => "  ",
        };
        println!("  {} [{}] {}", marker, finding.severity, finding.title);
        // Wrap description at ~70 chars
        for line in textwrap(&finding.description, 58) {
            println!("       {}", line);
        }
        println!();
    }

    if report.findings.is_empty() {
        println!("  No findings. This PodSpec follows security best practices.");
        println!();
    }

    // --- Verdict ---
    let verdict = if critical_count > 0 {
        "FAIL — critical issues must be resolved"
    } else if high_count > 0 {
        "WARN — high-severity issues should be addressed"
    } else if medium_count > 0 {
        "PASS with advisories"
    } else {
        "PASS"
    };
    println!("══ Verdict: {} ══", verdict);
}

fn textwrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in s.split_whitespace() {
        if current.len() + word.len() + 1 > width && !current.is_empty() {
            lines.push(current.clone());
            current.clear();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
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
    use std::io::Write;

    fn write_pod_spec(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = File::create(&path).unwrap();
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

        let report = scan_pod_spec(&spec, None).unwrap();
        assert_eq!(report.policy_profile, "read_only");
        assert_eq!(report.network_posture, "airgapped");
        assert_eq!(report.isolation_level, "firecracker");
        assert!(!report.has_credentials);
        // read_only + airgapped + firecracker = no findings
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

        let report = scan_pod_spec(&spec, None).unwrap();
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

        // Should flag credential patterns
        let cred_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.category == "credentials")
            .collect();
        assert!(
            cred_findings.len() >= 2,
            "Should flag ROOT_PASSWORD and AWS_SECRET_ACCESS_KEY"
        );

        // Should flag timeout
        let timeout_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.category == "timeout")
            .collect();
        assert_eq!(timeout_findings.len(), 1);

        // Should flag permissive profile
        let policy_findings: Vec<&Finding> = report
            .findings
            .iter()
            .filter(|f| f.category == "policy")
            .collect();
        assert_eq!(policy_findings.len(), 1);
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

        let report = scan_pod_spec(&spec, None).unwrap();
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
