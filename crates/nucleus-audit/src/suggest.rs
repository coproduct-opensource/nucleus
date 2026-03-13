//! Profile suggestion engine for nucleus-audit scan results.
//!
//! Analyzes scan findings and generates a minimal safe [`ProfileSpec`] YAML
//! that preserves needed capabilities while breaking the uninhabitable_state.
//!
//! Philosophy: **gate, don't block.** When the uninhabitable_state is detected, add
//! approval obligations on exfiltration operations rather than removing
//! capabilities entirely. This matches the nucleus approach — the agent can
//! still do useful work, but dangerous paths require explicit approval.

use portcullis::profile::{
    BudgetSpec, CapabilitiesSpec, ObligationSpec, PathsSpec, ProfileSpec, TimeSpec,
};
use portcullis::CapabilityLevel;

use crate::finding::{Finding, ScanReport, Severity};

/// Sensitive paths that should always be blocked.
const BLOCKED_PATHS: &[&str] = &[
    "**/.env",
    "**/.env.*",
    "**/.ssh/**",
    "**/.aws/**",
    "**/.gnupg/**",
    "**/credentials*",
    "**/secrets*",
    "**/*private_key*",
    "**/*id_rsa*",
];

/// Generate a suggested [`ProfileSpec`] from scan findings.
///
/// The suggestion:
/// - Preserves capabilities that were observed in the scanned config
/// - Adds approval obligations when the uninhabitable_state would otherwise be complete
/// - Blocks sensitive paths
/// - Sets sensible budget and time limits
/// - Names the profile based on the uninhabitable_state risk level
pub fn suggest_profile(report: &ScanReport) -> ProfileSpec {
    let has_uninhabitable = report.state_risk == "Complete"
        || report
            .findings
            .iter()
            .any(|f| f.category == "uninhabitable_state" && f.severity == Severity::Critical);

    let has_credentials = report.has_credentials;
    let has_exfil_findings = report.findings.iter().any(|f| f.category == "exfiltration");

    // Determine which capabilities are in use from the permission surface
    let caps = capabilities_from_surface(&report.permission_surface);

    // Build obligations: gate exfiltration operations when uninhabitable_state is present
    let mut obligations = Vec::new();
    if has_uninhabitable || has_exfil_findings {
        // Gate exfiltration operations with approval
        if caps.git_push != CapabilityLevel::Never {
            obligations.push(ObligationSpec::GitPush);
        }
        if caps.create_pr != CapabilityLevel::Never {
            obligations.push(ObligationSpec::CreatePr);
        }
        if caps.run_bash != CapabilityLevel::Never {
            obligations.push(ObligationSpec::RunBash);
        }
    }

    // Build blocked paths
    let mut blocked: Vec<String> = BLOCKED_PATHS.iter().map(|s| (*s).to_string()).collect();

    // Add credential-related path blocks if credentials were found
    if has_credentials {
        for finding in &report.findings {
            if finding.category == "credentials" {
                // Extract env var names from credential findings and block common locations
                if finding.title.contains("DATABASE_URL") {
                    blocked.push("**/.pgpass".to_string());
                }
            }
        }
    }

    blocked.sort();
    blocked.dedup();

    let paths = PathsSpec {
        allowed: Vec::new(), // empty = all allowed
        blocked,
    };

    // Profile name based on risk
    let name = if has_uninhabitable {
        "suggested-safe".to_string()
    } else {
        "suggested-minimal".to_string()
    };

    let description = if has_uninhabitable {
        "Auto-generated profile that breaks the uninhabitable_state by adding \
         approval obligations on exfiltration operations."
            .to_string()
    } else {
        "Auto-generated minimal profile matching observed capabilities.".to_string()
    };

    ProfileSpec {
        name,
        description: Some(description),
        capabilities: caps,
        obligations,
        paths: Some(paths),
        budget: Some(BudgetSpec::default()),
        time: Some(TimeSpec {
            duration_hours: Some(2),
            duration_minutes: None,
        }),
    }
}

/// Derive capability levels from the scan report's permission surface.
fn capabilities_from_surface(surface: &crate::finding::PermissionSurface) -> CapabilitiesSpec {
    // Start restrictive, then raise based on observed usage
    let mut caps = CapabilitiesSpec {
        read_files: CapabilityLevel::Never,
        write_files: CapabilityLevel::Never,
        edit_files: CapabilityLevel::Never,
        run_bash: CapabilityLevel::Never,
        glob_search: CapabilityLevel::Never,
        grep_search: CapabilityLevel::Never,
        web_search: CapabilityLevel::Never,
        web_fetch: CapabilityLevel::Never,
        git_commit: CapabilityLevel::Never,
        git_push: CapabilityLevel::Never,
        create_pr: CapabilityLevel::Never,
        manage_pods: CapabilityLevel::Never,
    };

    // Raise capabilities based on what's observed in the permission surface
    for op_name in &surface.always_allowed {
        set_capability(&mut caps, op_name, CapabilityLevel::Always);
    }
    for op_name in &surface.low_risk {
        set_capability(&mut caps, op_name, CapabilityLevel::LowRisk);
    }
    for op_name in &surface.approval_required {
        // Operations requiring approval → LowRisk (the obligation handles gating)
        set_capability(&mut caps, op_name, CapabilityLevel::LowRisk);
    }
    // `never` operations stay Never

    // If the surface is empty (e.g., Claude settings scan), use safe defaults
    if surface.total_capabilities == 0
        && surface.always_allowed.is_empty()
        && surface.low_risk.is_empty()
    {
        caps = CapabilitiesSpec::default(); // use profile defaults
    }

    caps
}

/// Set a capability level by operation name string.
fn set_capability(caps: &mut CapabilitiesSpec, name: &str, level: CapabilityLevel) {
    match name.to_lowercase().replace(' ', "_").as_str() {
        "read_files" | "readfiles" | "read" => caps.read_files = level,
        "write_files" | "writefiles" | "write" => caps.write_files = level,
        "edit_files" | "editfiles" | "edit" => caps.edit_files = level,
        "run_bash" | "runbash" | "bash" => caps.run_bash = level,
        "glob_search" | "globsearch" | "glob" => caps.glob_search = level,
        "grep_search" | "grepsearch" | "grep" => caps.grep_search = level,
        "web_search" | "websearch" => caps.web_search = level,
        "web_fetch" | "webfetch" => caps.web_fetch = level,
        "git_commit" | "gitcommit" => caps.git_commit = level,
        "git_push" | "gitpush" => caps.git_push = level,
        "create_pr" | "createpr" => caps.create_pr = level,
        "manage_pods" | "managepods" => caps.manage_pods = level,
        _ => {} // Unknown operation, skip
    }
}

/// Format a suggested profile as YAML with a descriptive header comment.
pub fn format_suggestion(profile: &ProfileSpec, findings: &[Finding]) -> String {
    let mut out = String::new();

    // Header
    out.push_str("# Nucleus suggested profile\n");
    out.push_str("#\n");
    out.push_str("# Generated by: nucleus-audit scan --suggest-profile\n");

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();

    if critical > 0 || high > 0 {
        out.push_str(&format!(
            "# Remediates: {} critical, {} high findings\n",
            critical, high
        ));
    }

    if profile.obligations.is_empty() {
        out.push_str("# Strategy: minimal capabilities matching observed usage\n");
    } else {
        out.push_str("# Strategy: gate exfiltration with approval obligations (breaks uninhabitable_state)\n");
    }

    out.push_str("#\n");
    out.push_str("# To use:\n");
    out.push_str("#   1. Save as nucleus-profile.yaml\n");
    out.push_str("#   2. nucleus run --profile nucleus-profile.yaml <command>\n");
    out.push_str("#\n\n");

    // Serialize the profile
    let yaml = serde_yaml::to_string(profile).unwrap_or_else(|_| "# error serializing".into());
    out.push_str(&yaml);
    out
}

/// Generate a Claude Code MCP allowlist snippet from scan findings.
///
/// When MCP servers are scanned, this produces a suggested `permissions.deny`
/// block for Claude Code settings.json that blocks dangerous MCP tool patterns.
pub fn mcp_allowlist_snippet(report: &ScanReport) -> Option<String> {
    let mcp_findings: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| {
            f.category.starts_with("mcp_")
                || (f.category == "credentials" && f.title.contains("MCP"))
                || f.category == "supply_chain"
                || (f.category == "execution" && f.title.contains("MCP"))
        })
        .collect();

    if mcp_findings.is_empty() && report.mcp_config_summary.is_none() {
        return None;
    }

    let mut out = String::new();
    out.push_str("// Suggested Claude Code deny rules for MCP servers\n");
    out.push_str("// Add to .claude/settings.json under permissions.deny\n");
    out.push_str("{\n");
    out.push_str("  \"permissions\": {\n");
    out.push_str("    \"deny\": [\n");

    let mut deny_rules: Vec<String> = Vec::new();

    // Always deny sensitive tool patterns for MCP servers with exfil capability
    for finding in &mcp_findings {
        if finding.description.contains("exfiltration") || finding.category == "mcp_vcs" {
            // Extract server name from finding title
            if let Some(server_name) = extract_mcp_server_name(&finding.title) {
                deny_rules.push(format!("mcp__{}__push", server_name));
                deny_rules.push(format!("mcp__{}__create_pull_request", server_name));
            }
        }
        if finding.category == "mcp_communication" {
            if let Some(server_name) = extract_mcp_server_name(&finding.title) {
                deny_rules.push(format!("mcp__{}__send_message", server_name));
                deny_rules.push(format!("mcp__{}__post_message", server_name));
            }
        }
    }

    deny_rules.sort();
    deny_rules.dedup();

    for (i, rule) in deny_rules.iter().enumerate() {
        let comma = if i < deny_rules.len() - 1 { "," } else { "" };
        out.push_str(&format!("      \"{}\"{}\n", rule, comma));
    }

    if deny_rules.is_empty() {
        out.push_str("      // No specific deny rules needed — review MCP server access\n");
    }

    out.push_str("    ]\n");
    out.push_str("  }\n");
    out.push_str("}\n");

    Some(out)
}

/// Extract MCP server name from a finding title like "Vcs access via MCP server 'github'"
fn extract_mcp_server_name(title: &str) -> Option<String> {
    // Pattern: ... MCP server '<name>'
    if let Some(start) = title.find("MCP server '") {
        let after = &title[start + "MCP server '".len()..];
        if let Some(end) = after.find('\'') {
            return Some(after[..end].to_string());
        }
    }
    // Pattern: ... MCP server "<name>"
    if let Some(start) = title.find("MCP server \"") {
        let after = &title[start + "MCP server \"".len()..];
        if let Some(end) = after.find('"') {
            return Some(after[..end].to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{McpConfigSummary, PermissionSurface, ScanReport, Severity};

    fn report_with_uninhabitable() -> ScanReport {
        ScanReport {
            state_risk: "Complete".to_string(),
            uninhabitable_state_enforced: true,
            permission_surface: PermissionSurface {
                total_capabilities: 12,
                always_allowed: vec!["read_files".into(), "glob_search".into()],
                low_risk: vec!["write_files".into(), "web_fetch".into(), "run_bash".into()],
                never: vec!["manage_pods".into()],
                approval_required: vec!["git_push".into()],
            },
            findings: vec![
                Finding {
                    severity: Severity::Critical,
                    category: "uninhabitable_state".to_string(),
                    title: "Lethal uninhabitable_state detected".to_string(),
                    description: "desc".to_string(),
                },
                Finding {
                    severity: Severity::High,
                    category: "credentials".to_string(),
                    title: "Plaintext secret".to_string(),
                    description: "desc".to_string(),
                },
            ],
            has_credentials: true,
            ..ScanReport::default()
        }
    }

    fn clean_report() -> ScanReport {
        ScanReport {
            state_risk: "None".to_string(),
            permission_surface: PermissionSurface {
                total_capabilities: 5,
                always_allowed: vec!["read_files".into(), "glob_search".into()],
                low_risk: vec!["write_files".into(), "edit_files".into()],
                never: vec!["git_push".into(), "manage_pods".into()],
                approval_required: vec![],
            },
            findings: vec![],
            ..ScanReport::default()
        }
    }

    #[test]
    fn test_uninhabitable_adds_obligations() {
        let report = report_with_uninhabitable();
        let profile = suggest_profile(&report);

        assert_eq!(profile.name, "suggested-safe");
        assert!(!profile.obligations.is_empty(), "Should add obligations");
        assert!(
            profile
                .obligations
                .iter()
                .any(|o| matches!(o, ObligationSpec::GitPush)),
            "Should require approval for git_push"
        );
        assert!(
            profile
                .obligations
                .iter()
                .any(|o| matches!(o, ObligationSpec::RunBash)),
            "Should require approval for run_bash"
        );
    }

    #[test]
    fn test_clean_report_no_obligations() {
        let report = clean_report();
        let profile = suggest_profile(&report);

        assert_eq!(profile.name, "suggested-minimal");
        assert!(
            profile.obligations.is_empty(),
            "No uninhabitable_state = no obligations"
        );
    }

    #[test]
    fn test_capabilities_preserved() {
        let report = report_with_uninhabitable();
        let profile = suggest_profile(&report);

        assert_eq!(profile.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(profile.capabilities.web_fetch, CapabilityLevel::LowRisk);
        assert_eq!(profile.capabilities.manage_pods, CapabilityLevel::Never);
    }

    #[test]
    fn test_sensitive_paths_blocked() {
        let report = clean_report();
        let profile = suggest_profile(&report);

        let paths = profile.paths.as_ref().unwrap();
        assert!(paths.blocked.iter().any(|p| p.contains(".env")));
        assert!(paths.blocked.iter().any(|p| p.contains(".ssh")));
        assert!(paths.blocked.iter().any(|p| p.contains(".aws")));
    }

    #[test]
    fn test_budget_and_time_defaults() {
        let report = clean_report();
        let profile = suggest_profile(&report);

        assert!(profile.budget.is_some());
        assert_eq!(profile.budget.as_ref().unwrap().max_cost_usd, "5.00");
        assert!(profile.time.is_some());
        assert_eq!(profile.time.as_ref().unwrap().duration_hours, Some(2));
    }

    #[test]
    fn test_format_suggestion_yaml() {
        let report = report_with_uninhabitable();
        let profile = suggest_profile(&report);
        let yaml = format_suggestion(&profile, &report.findings);

        assert!(yaml.contains("# Nucleus suggested profile"));
        assert!(yaml.contains("Remediates: 1 critical, 1 high"));
        assert!(yaml.contains("gate exfiltration"));
        assert!(yaml.contains("suggested-safe"));
        assert!(yaml.contains("nucleus-profile.yaml"));
    }

    #[test]
    fn test_format_clean_suggestion() {
        let report = clean_report();
        let profile = suggest_profile(&report);
        let yaml = format_suggestion(&profile, &report.findings);

        assert!(yaml.contains("minimal capabilities"));
        assert!(yaml.contains("suggested-minimal"));
    }

    #[test]
    fn test_extract_mcp_server_name() {
        assert_eq!(
            extract_mcp_server_name("Vcs access via MCP server 'github'"),
            Some("github".to_string())
        );
        assert_eq!(extract_mcp_server_name("No server here"), None);
    }

    #[test]
    fn test_mcp_allowlist_snippet() {
        let report = ScanReport {
            mcp_config_summary: Some(McpConfigSummary {
                server_count: 2,
                command_servers: 2,
                http_servers: 0,
                servers_with_credentials: 1,
            }),
            findings: vec![Finding {
                severity: Severity::Medium,
                category: "mcp_vcs".to_string(),
                title: "Vcs access via MCP server 'github'".to_string(),
                description: "exfiltration capable".to_string(),
            }],
            ..ScanReport::default()
        };

        let snippet = mcp_allowlist_snippet(&report);
        assert!(snippet.is_some());
        let s = snippet.unwrap();
        assert!(s.contains("mcp__github__push"));
        assert!(s.contains("mcp__github__create_pull_request"));
    }

    #[test]
    fn test_mcp_allowlist_none_when_no_mcp() {
        let report = ScanReport::default();
        assert!(mcp_allowlist_snippet(&report).is_none());
    }

    #[test]
    fn test_profile_validates() {
        let report = report_with_uninhabitable();
        let profile = suggest_profile(&report);
        assert!(
            profile.validate().is_ok(),
            "Suggested profile must validate"
        );
    }

    #[test]
    fn test_empty_surface_uses_defaults() {
        let report = ScanReport {
            findings: vec![Finding {
                severity: Severity::Medium,
                category: "uninhabitable_state".to_string(),
                title: "Partial uninhabitable_state".to_string(),
                description: "desc".to_string(),
            }],
            ..ScanReport::default()
        };
        let profile = suggest_profile(&report);

        // Empty surface → defaults (not all-Never)
        assert_eq!(profile.capabilities.read_files, CapabilityLevel::Always);
        assert_eq!(profile.capabilities.run_bash, CapabilityLevel::Never);
    }
}
