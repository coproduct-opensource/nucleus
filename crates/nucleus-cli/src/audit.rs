//! `nucleus audit` — scan agent configurations for security risks.
//!
//! Tier 0 entry point: fast value, no runtime required.
//!
//! Scans the current directory (or a specified path) for:
//! - MCP server configurations with unmediated tool access
//! - Sensitive files that shouldn't be accessible to agents
//! - PodSpec files with overly permissive policies
//!
//! Outputs findings as text (default) or SARIF (for CI), and suggests a
//! minimal safe profile based on the tools discovered.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use serde::Serialize;

use portcullis::profile::{ProfileRegistry, ProfileSpec};

// ── CLI args ─────────────────────────────────────────────────────────

/// Audit agent configurations for security risks.
///
/// Scans the current directory for MCP configs, sensitive files, and
/// PodSpec files. Generates findings and suggests a minimal safe profile.
#[derive(Args)]
pub struct AuditArgs {
    /// Directory to scan (defaults to current directory).
    #[arg(short, long)]
    pub path: Option<PathBuf>,

    /// Output format: text (default) or sarif (for CI).
    #[arg(short, long, default_value = "text")]
    pub format: OutputFormat,

    /// Write SARIF output to this file (implies --format sarif).
    #[arg(long)]
    pub sarif_output: Option<PathBuf>,

    /// Suggest a profile name from the canonical registry.
    #[arg(long, default_value_t = true)]
    pub suggest_profile: bool,
}

#[derive(Clone, Debug, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Sarif,
}

// ── Finding model ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Severity: critical, warning, info.
    pub severity: Severity,
    /// Short identifier (e.g. "unmediated-mcp-tools").
    pub rule_id: String,
    /// Human-readable message.
    pub message: String,
    /// File where the issue was found.
    pub file: PathBuf,
    /// Suggested fix or action.
    pub recommendation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

// ── MCP config scanning ─────────────────────────────────────────────

/// Known MCP config file locations to scan.
const MCP_CONFIG_LOCATIONS: &[&str] = &[
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    ".vscode/mcp.json",
    ".cursor/mcp.json",
    ".claude/mcp.json",
    "claude_desktop_config.json",
];

/// Tool names that indicate filesystem access.
const FS_TOOL_PATTERNS: &[&str] = &[
    "read_file",
    "write_file",
    "edit_file",
    "list_files",
    "search_files",
    "create_file",
    "delete_file",
    "directory_tree",
    "file_search",
    "read",
    "write",
    "edit",
];

/// Tool names that indicate network access.
const NET_TOOL_PATTERNS: &[&str] = &[
    "fetch",
    "fetch_url",
    "http_request",
    "web_search",
    "browser",
    "curl",
    "wget",
    "request",
];

/// Tool names that indicate code execution.
const EXEC_TOOL_PATTERNS: &[&str] = &[
    "run_command",
    "execute",
    "bash",
    "shell",
    "terminal",
    "exec",
    "run_terminal_command",
    "run",
];

/// Tool names that indicate git/publish operations.
const GIT_TOOL_PATTERNS: &[&str] = &[
    "git",
    "git_push",
    "git_commit",
    "create_pull_request",
    "create_pr",
    "push",
    "publish",
];

/// Sensitive file patterns that agents shouldn't access.
const SENSITIVE_FILE_PATTERNS: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "credentials.json",
    "credentials.yaml",
    "service-account.json",
    ".aws/credentials",
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
];

fn scan_mcp_configs(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for location in MCP_CONFIG_LOCATIONS {
        let config_path = root.join(location);
        if !config_path.exists() {
            continue;
        }

        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let parsed: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => {
                findings.push(Finding {
                    severity: Severity::Warning,
                    rule_id: "invalid-mcp-config".to_string(),
                    message: format!("MCP config is not valid JSON: {}", location),
                    file: config_path,
                    recommendation: "Fix JSON syntax errors in the MCP configuration.".to_string(),
                });
                continue;
            }
        };

        // Look for mcpServers key
        let servers = parsed
            .get("mcpServers")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        if servers.is_empty() {
            continue;
        }

        // Check if nucleus is configured as the mediator
        let has_nucleus = servers.keys().any(|k| k.contains("nucleus"));

        if !has_nucleus {
            findings.push(Finding {
                severity: Severity::Warning,
                rule_id: "no-nucleus-mediator".to_string(),
                message: format!(
                    "MCP config has {} server(s) but no nucleus mediator — \
                     tool calls are not policy-enforced.",
                    servers.len()
                ),
                file: config_path.clone(),
                recommendation:
                    "Add nucleus as an MCP mediator to enforce policy on all tool calls. \
                     Run `nucleus run --local` to mediate agent tool access."
                        .to_string(),
            });
        }

        // Analyze each server's tools for risk classification
        for (name, server) in &servers {
            if name.contains("nucleus") {
                continue; // Skip nucleus itself
            }

            let command = server.get("command").and_then(|c| c.as_str()).unwrap_or("");

            // Check for known tool patterns
            let args: Vec<String> = server
                .get("args")
                .and_then(|a| a.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            let all_text = format!("{} {} {}", name, command, args.join(" ")).to_lowercase();

            let has_fs = FS_TOOL_PATTERNS.iter().any(|p| all_text.contains(p));
            let has_net = NET_TOOL_PATTERNS.iter().any(|p| all_text.contains(p));
            let has_exec = EXEC_TOOL_PATTERNS.iter().any(|p| all_text.contains(p));
            let has_git = GIT_TOOL_PATTERNS.iter().any(|p| all_text.contains(p));

            // Trifecta check: if server has all three legs of risk
            let taint_legs = [has_fs, has_net || has_exec, has_git || has_exec]
                .iter()
                .filter(|&&b| b)
                .count();

            if taint_legs >= 3 {
                findings.push(Finding {
                    severity: Severity::Critical,
                    rule_id: "trifecta-capable-server".to_string(),
                    message: format!(
                        "MCP server '{}' has filesystem, network/exec, and git/publish \
                         capabilities — trifecta-capable without policy enforcement.",
                        name
                    ),
                    file: config_path.clone(),
                    recommendation: format!(
                        "Mediate '{}' through nucleus to enforce trifecta gating. \
                         This prevents data exfiltration via the read→fetch→push chain.",
                        name
                    ),
                });
            } else if taint_legs == 2 {
                findings.push(Finding {
                    severity: Severity::Warning,
                    rule_id: "dual-risk-server".to_string(),
                    message: format!(
                        "MCP server '{}' has 2 of 3 trifecta legs — \
                         one additional capability could enable exfiltration.",
                        name
                    ),
                    file: config_path.clone(),
                    recommendation: format!(
                        "Consider mediating '{}' through nucleus for taint tracking.",
                        name
                    ),
                });
            }

            // Check for env vars that might contain secrets
            if let Some(env) = server.get("env").and_then(|e| e.as_object()) {
                for key in env.keys() {
                    let key_lower = key.to_lowercase();
                    if key_lower.contains("secret")
                        || key_lower.contains("password")
                        || key_lower.contains("token")
                        || key_lower.contains("api_key")
                        || key_lower.contains("apikey")
                    {
                        findings.push(Finding {
                            severity: Severity::Warning,
                            rule_id: "inline-secret".to_string(),
                            message: format!(
                                "MCP server '{}' has inline credential '{}' — \
                                 secrets in config files risk exposure to agents.",
                                name, key
                            ),
                            file: config_path.clone(),
                            recommendation:
                                "Use environment variable references or a secret manager \
                                 instead of inline credentials."
                                    .to_string(),
                        });
                    }
                }
            }
        }
    }

    findings
}

// ── Sensitive file scanning ──────────────────────────────────────────

fn scan_sensitive_files(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for pattern in SENSITIVE_FILE_PATTERNS {
        let file_path = root.join(pattern);
        if file_path.exists() {
            // Check if file is gitignored
            let is_gitignored = std::process::Command::new("git")
                .args(["check-ignore", "-q", pattern])
                .current_dir(root)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if !is_gitignored {
                findings.push(Finding {
                    severity: Severity::Critical,
                    rule_id: "sensitive-file-exposed".to_string(),
                    message: format!(
                        "Sensitive file '{}' exists and is not gitignored — \
                         agents with read access can see credentials.",
                        pattern
                    ),
                    file: file_path,
                    recommendation: format!(
                        "Add '{}' to .gitignore and use the `paths.blocked` \
                         section in your nucleus profile to prevent agent access.",
                        pattern
                    ),
                });
            } else {
                findings.push(Finding {
                    severity: Severity::Info,
                    rule_id: "sensitive-file-gitignored".to_string(),
                    message: format!(
                        "Sensitive file '{}' exists but is gitignored. \
                         Consider also blocking it in nucleus path policy.",
                        pattern
                    ),
                    file: file_path,
                    recommendation: format!(
                        "Add '{}' to `paths.blocked` in your nucleus profile \
                         for defense-in-depth.",
                        pattern
                    ),
                });
            }
        }
    }

    findings
}

// ── PodSpec scanning ─────────────────────────────────────────────────

fn scan_podspecs(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Collect candidate PodSpec files from the root directory
    let candidates: Vec<PathBuf> = std::fs::read_dir(root)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name == "pod.yaml"
                || name == "podspec.yaml"
                || name.ends_with(".pod.yaml")
                || name.ends_with(".podspec.yaml")
        })
        .collect();

    for entry in candidates {
        let content = match std::fs::read_to_string(&entry) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Try to parse as PodSpec YAML
        let parsed: serde_json::Value = match serde_yaml::from_str(&content) {
            Ok(v) => v,
            Err(_) => {
                findings.push(Finding {
                    severity: Severity::Warning,
                    rule_id: "invalid-podspec".to_string(),
                    message: format!("PodSpec file is not valid YAML: {}", entry.display()),
                    file: entry,
                    recommendation: "Fix YAML syntax errors in the PodSpec.".to_string(),
                });
                continue;
            }
        };

        // Check for overly permissive capabilities
        if let Some(caps) = parsed.get("capabilities") {
            let always_caps: Vec<&str> = [
                "write_files",
                "run_bash",
                "web_fetch",
                "git_push",
                "create_pr",
                "manage_pods",
            ]
            .iter()
            .filter(|cap| {
                caps.get(**cap)
                    .and_then(|v| v.as_str())
                    .map(|v| v == "always")
                    .unwrap_or(false)
            })
            .copied()
            .collect();

            if !always_caps.is_empty() {
                findings.push(Finding {
                    severity: Severity::Warning,
                    rule_id: "overly-permissive-caps".to_string(),
                    message: format!(
                        "PodSpec has `always` level for risky capabilities: {}",
                        always_caps.join(", ")
                    ),
                    file: entry.clone(),
                    recommendation: "Use `low_risk` instead of `always` for capabilities that \
                         involve side effects. Reserve `always` for read-only operations."
                        .to_string(),
                });
            }
        }

        // Check for missing budget
        if parsed.get("budget").is_none() {
            findings.push(Finding {
                severity: Severity::Info,
                rule_id: "no-budget-limit".to_string(),
                message: format!("PodSpec has no budget limit: {}", entry.display()),
                file: entry.clone(),
                recommendation: "Add a `budget` section with `max_cost_usd` to prevent \
                     unbounded spending."
                    .to_string(),
            });
        }

        // Check for missing time limit
        if parsed.get("time").is_none() {
            findings.push(Finding {
                severity: Severity::Info,
                rule_id: "no-time-limit".to_string(),
                message: format!("PodSpec has no time limit: {}", entry.display()),
                file: entry,
                recommendation: "Add a `time` section with `duration_hours` to prevent \
                     unbounded execution."
                    .to_string(),
            });
        }
    }

    findings
}

// ── Profile suggestion ───────────────────────────────────────────────

/// Suggest a canonical profile based on discovered MCP tools.
fn suggest_profile(root: &Path) -> Option<ProfileSuggestion> {
    // Gather all MCP tool indicators
    let mut has_fs = false;
    let mut has_net = false;
    let mut has_exec = false;
    let mut has_git_write = false;
    let mut has_git_read = false;

    for location in MCP_CONFIG_LOCATIONS {
        let config_path = root.join(location);
        let content = match std::fs::read_to_string(&config_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let parsed: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let servers = parsed
            .get("mcpServers")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        for (name, server) in &servers {
            let command = server.get("command").and_then(|c| c.as_str()).unwrap_or("");
            let all_text = format!("{} {}", name, command).to_lowercase();

            if FS_TOOL_PATTERNS.iter().any(|p| all_text.contains(p)) {
                has_fs = true;
            }
            if NET_TOOL_PATTERNS.iter().any(|p| all_text.contains(p)) {
                has_net = true;
            }
            if EXEC_TOOL_PATTERNS.iter().any(|p| all_text.contains(p)) {
                has_exec = true;
            }
            if all_text.contains("push") || all_text.contains("publish") {
                has_git_write = true;
            }
            if all_text.contains("git") || all_text.contains("commit") {
                has_git_read = true;
            }
        }
    }

    // Match to canonical profile based on observed capabilities
    let registry = ProfileRegistry::canonical().ok()?;

    let suggested_name = if !has_fs && !has_net && !has_exec && !has_git_read {
        return None; // No MCP configs found
    } else if has_fs && !has_net && !has_exec && !has_git_read {
        "read-only"
    } else if has_fs && has_exec && !has_net && has_git_read && !has_git_write {
        "local-dev"
    } else if has_fs && has_exec && has_net && has_git_write {
        "codegen" // full capabilities — suggest codegen with its built-in limits
    } else if has_fs && !has_net && has_git_read {
        "safe-pr-fixer"
    } else if has_fs && has_net && !has_exec {
        "research-web"
    } else if has_fs && has_exec && !has_net {
        "test-runner"
    } else {
        "local-dev" // conservative default
    };

    let profile = registry.get(suggested_name)?;

    Some(ProfileSuggestion {
        name: suggested_name.to_string(),
        reason: match suggested_name {
            "read-only" => {
                "Only filesystem read access detected. Read-only profile is sufficient.".to_string()
            }
            "local-dev" => {
                "Filesystem + execution detected but no network. Local-dev profile is safe."
                    .to_string()
            }
            "codegen" => "Full capabilities detected — codegen profile provides guardrails \
                 with budget and time limits."
                .to_string(),
            "safe-pr-fixer" => {
                "Filesystem + git detected without network. Safe-pr-fixer is a good fit."
                    .to_string()
            }
            "research-web" => {
                "Filesystem + network but no execution. Research-web profile is appropriate."
                    .to_string()
            }
            "test-runner" => {
                "Filesystem + execution but no network. Test-runner profile fits.".to_string()
            }
            _ => format!(
                "Based on detected capabilities, '{}' is suggested.",
                suggested_name
            ),
        },
        profile: profile.clone(),
    })
}

#[derive(Debug)]
struct ProfileSuggestion {
    name: String,
    reason: String,
    profile: ProfileSpec,
}

// ── Output formatters ────────────────────────────────────────────────

fn format_text(findings: &[Finding], suggestion: Option<&ProfileSuggestion>) -> String {
    let mut out = String::new();

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let warnings = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    out.push_str("nucleus audit\n");
    out.push_str(&"=".repeat(60));
    out.push('\n');

    if findings.is_empty() {
        out.push_str("\nNo findings. Your configuration looks clean.\n");
    } else {
        out.push_str(&format!(
            "\n{} finding(s): {} critical, {} warning, {} info\n\n",
            findings.len(),
            critical,
            warnings,
            info,
        ));

        // Sort by severity (critical first)
        let mut sorted: Vec<&Finding> = findings.iter().collect();
        sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

        for (i, finding) in sorted.iter().enumerate() {
            let marker = match finding.severity {
                Severity::Critical => "[CRITICAL]",
                Severity::Warning => "[WARNING] ",
                Severity::Info => "[INFO]    ",
            };
            out.push_str(&format!("  {}  {} {}\n", i + 1, marker, finding.rule_id,));
            out.push_str(&format!("     {}\n", finding.message));
            out.push_str(&format!("     File: {}\n", finding.file.display()));
            out.push_str(&format!("     Fix:  {}\n\n", finding.recommendation));
        }
    }

    // Profile suggestion
    if let Some(suggestion) = suggestion {
        out.push_str(&"-".repeat(60));
        out.push_str("\nSuggested profile\n\n");
        out.push_str(&format!("  Name:   {}\n", suggestion.name));
        out.push_str(&format!("  Reason: {}\n\n", suggestion.reason));
        out.push_str("  Usage:\n");
        out.push_str(&format!(
            "    nucleus run --local --profile {} \"your task\"\n\n",
            suggestion.name
        ));
        if let Ok(yaml) = suggestion.profile.to_yaml() {
            out.push_str("  Profile YAML:\n");
            for line in yaml.lines() {
                out.push_str(&format!("    {}\n", line));
            }
        }
        out.push('\n');
    }

    // Exit status hint
    if critical > 0 {
        out.push_str(&format!("Exit: FAIL ({} critical finding(s))\n", critical));
    } else if warnings > 0 {
        out.push_str(&format!(
            "Exit: WARN ({} warning(s), review recommended)\n",
            warnings
        ));
    } else {
        out.push_str("Exit: PASS\n");
    }

    out
}

/// Minimal SARIF 2.1.0 output for CI integration (GitHub Code Scanning, etc.).
fn format_sarif(findings: &[Finding]) -> serde_json::Value {
    let rules: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| &f.rule_id)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|id| {
            serde_json::json!({
                "id": id,
                "shortDescription": { "text": id },
            })
        })
        .collect();

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                Severity::Critical => "error",
                Severity::Warning => "warning",
                Severity::Info => "note",
            };
            serde_json::json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file.to_string_lossy(),
                        },
                    },
                }],
                "fixes": [{
                    "description": { "text": f.recommendation },
                }],
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "nucleus-audit",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/coproduct-opensource/nucleus",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    })
}

// ── Main execute ─────────────────────────────────────────────────────

pub fn execute(args: AuditArgs) -> Result<()> {
    let root = args
        .path
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let root = root.canonicalize().unwrap_or_else(|_| root.clone());

    // Run all scanners
    let mut findings = Vec::new();
    findings.extend(scan_mcp_configs(&root));
    findings.extend(scan_sensitive_files(&root));
    findings.extend(scan_podspecs(&root));

    // Profile suggestion
    let suggestion = if args.suggest_profile {
        suggest_profile(&root)
    } else {
        None
    };

    // Determine output format
    let format = if args.sarif_output.is_some() {
        OutputFormat::Sarif
    } else {
        args.format
    };

    match format {
        OutputFormat::Text => {
            let report = format_text(&findings, suggestion.as_ref());
            print!("{}", report);
        }
        OutputFormat::Sarif => {
            let sarif = format_sarif(&findings);
            let json = serde_json::to_string_pretty(&sarif).context("Failed to serialize SARIF")?;

            if let Some(output_path) = &args.sarif_output {
                std::fs::write(output_path, &json)
                    .with_context(|| format!("Failed to write {}", output_path.display()))?;
                eprintln!("SARIF written to {}", output_path.display());
            } else {
                println!("{}", json);
            }
        }
    }

    // Exit with non-zero status if critical findings
    let critical_count = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    if critical_count > 0 {
        std::process::exit(1);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn setup_dir() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn test_empty_directory_no_findings() {
        let dir = setup_dir();
        let findings = scan_mcp_configs(dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_mcp_config_no_nucleus_mediator() {
        let dir = setup_dir();
        let config = serde_json::json!({
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem"]
                }
            }
        });
        fs::write(dir.path().join(".mcp.json"), config.to_string()).unwrap();

        let findings = scan_mcp_configs(dir.path());
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.rule_id == "no-nucleus-mediator"));
    }

    #[test]
    fn test_mcp_config_with_nucleus_no_warning() {
        let dir = setup_dir();
        let config = serde_json::json!({
            "mcpServers": {
                "nucleus": {
                    "command": "nucleus-mcp",
                    "args": ["--proxy-url", "http://localhost:9999"]
                }
            }
        });
        fs::write(dir.path().join(".mcp.json"), config.to_string()).unwrap();

        let findings = scan_mcp_configs(dir.path());
        // Should not have "no-nucleus-mediator" since nucleus is present
        assert!(!findings.iter().any(|f| f.rule_id == "no-nucleus-mediator"));
    }

    #[test]
    fn test_trifecta_capable_server() {
        let dir = setup_dir();
        let config = serde_json::json!({
            "mcpServers": {
                "all-in-one": {
                    "command": "server-with-read_file-and-fetch_url-and-bash-and-git_push",
                    "args": []
                }
            }
        });
        fs::write(dir.path().join(".mcp.json"), config.to_string()).unwrap();

        let findings = scan_mcp_configs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "trifecta-capable-server"));
    }

    #[test]
    fn test_inline_secret_detected() {
        let dir = setup_dir();
        let config = serde_json::json!({
            "mcpServers": {
                "my-server": {
                    "command": "my-mcp-server",
                    "args": [],
                    "env": {
                        "API_KEY": "sk-12345",
                        "DATABASE_URL": "postgres://localhost"
                    }
                }
            }
        });
        fs::write(dir.path().join(".mcp.json"), config.to_string()).unwrap();

        let findings = scan_mcp_configs(dir.path());
        // API_KEY should trigger but DATABASE_URL should not (no secret-like keyword)
        assert!(findings.iter().any(|f| f.rule_id == "inline-secret"));
    }

    #[test]
    fn test_sensitive_file_detected() {
        let dir = setup_dir();
        // Create a .env file
        fs::write(dir.path().join(".env"), "SECRET=value").unwrap();

        let findings = scan_sensitive_files(dir.path());
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "sensitive-file-exposed"
                || f.rule_id == "sensitive-file-gitignored"));
    }

    #[test]
    fn test_podspec_overly_permissive() {
        let dir = setup_dir();
        let podspec = r#"
name: my-agent
capabilities:
  read_files: always
  write_files: always
  run_bash: always
  git_push: always
"#;
        fs::write(dir.path().join("pod.yaml"), podspec).unwrap();

        let findings = scan_podspecs(dir.path());
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "overly-permissive-caps"));
    }

    #[test]
    fn test_podspec_missing_budget_and_time() {
        let dir = setup_dir();
        let podspec = r#"
name: my-agent
capabilities:
  read_files: low_risk
"#;
        fs::write(dir.path().join("pod.yaml"), podspec).unwrap();

        let findings = scan_podspecs(dir.path());
        assert!(findings.iter().any(|f| f.rule_id == "no-budget-limit"));
        assert!(findings.iter().any(|f| f.rule_id == "no-time-limit"));
    }

    #[test]
    fn test_format_text_empty() {
        let report = format_text(&[], None);
        assert!(report.contains("No findings"));
        assert!(report.contains("PASS"));
    }

    #[test]
    fn test_format_text_with_findings() {
        let findings = vec![Finding {
            severity: Severity::Critical,
            rule_id: "test-rule".to_string(),
            message: "Test message".to_string(),
            file: PathBuf::from("test.json"),
            recommendation: "Fix it".to_string(),
        }];
        let report = format_text(&findings, None);
        assert!(report.contains("[CRITICAL]"));
        assert!(report.contains("test-rule"));
        assert!(report.contains("FAIL"));
    }

    #[test]
    fn test_format_sarif_valid() {
        let findings = vec![Finding {
            severity: Severity::Warning,
            rule_id: "test-rule".to_string(),
            message: "Test message".to_string(),
            file: PathBuf::from("test.json"),
            recommendation: "Fix it".to_string(),
        }];
        let sarif = format_sarif(&findings);
        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"][0]["ruleId"], "test-rule");
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "warning");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Critical > Severity::Warning);
        assert!(Severity::Warning > Severity::Info);
    }

    #[test]
    fn test_invalid_json_mcp_config() {
        let dir = setup_dir();
        fs::write(dir.path().join(".mcp.json"), "not json {{{").unwrap();

        let findings = scan_mcp_configs(dir.path());
        assert!(findings.iter().any(|f| f.rule_id == "invalid-mcp-config"));
    }

    #[test]
    fn test_multiple_mcp_locations() {
        let dir = setup_dir();

        // Create two MCP configs in different locations
        let config = serde_json::json!({
            "mcpServers": {
                "server-a": { "command": "read_file_server", "args": [] }
            }
        });
        fs::write(dir.path().join(".mcp.json"), config.to_string()).unwrap();

        fs::create_dir_all(dir.path().join(".vscode")).unwrap();
        fs::write(dir.path().join(".vscode/mcp.json"), config.to_string()).unwrap();

        let findings = scan_mcp_configs(dir.path());
        // Should find issues in both configs
        let mediator_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "no-nucleus-mediator")
            .collect();
        assert_eq!(mediator_findings.len(), 2);
    }

    #[test]
    fn test_env_key_detection_case_insensitive() {
        let dir = setup_dir();
        let config = serde_json::json!({
            "mcpServers": {
                "my-server": {
                    "command": "server",
                    "env": {
                        "MY_SECRET_VALUE": "hidden",
                        "my_token": "tok",
                        "MY_PASSWORD": "pass"
                    }
                }
            }
        });
        fs::write(dir.path().join(".mcp.json"), config.to_string()).unwrap();

        let findings = scan_mcp_configs(dir.path());
        let secret_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "inline-secret")
            .collect();
        assert_eq!(secret_findings.len(), 3);
    }
}
