//! Claude Code settings.json security scanner.
//!
//! Parses Claude Code's `settings.json` format and projects permission rules
//! onto the portcullis CapabilityLattice for uninhabitable_state analysis.

use std::collections::HashMap;
use std::path::Path;

use portcullis::{CapabilityLattice, CapabilityLevel, IncompatibilityConstraint};
use serde::Deserialize;

use crate::finding::{ClaudeSettingsSummary, Finding, Severity};
use crate::tool_pattern::{
    bash_implied_capabilities, is_exfil_bash_pattern, is_sensitive_path_pattern,
    is_unrestricted_pattern, mcp_implied_capabilities, parse_tool_permission, ToolKind,
};
use crate::AuditError;

// --- Serde structs for Claude Code settings.json ---

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ClaudeSettings {
    #[serde(default)]
    pub permissions: Option<PermissionRules>,
    #[serde(default)]
    pub mcp_servers: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub sandbox: Option<SandboxConfig>,
    #[serde(default)]
    pub hooks: Option<serde_json::Value>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(default)]
    pub skip_dangerous_mode_permission_prompt: Option<bool>,
    #[serde(default)]
    pub api_key_helper: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub ask: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)] // Fields used for deserialization tolerance
pub struct SandboxConfig {
    pub enabled: Option<bool>,
    #[serde(default)]
    pub filesystem: Option<serde_json::Value>,
    #[serde(default)]
    pub network: Option<serde_json::Value>,
}

/// Scan a Claude Code settings.json file for security issues.
pub fn scan_claude_settings(
    path: &Path,
) -> Result<(Vec<Finding>, ClaudeSettingsSummary), AuditError> {
    let content = std::fs::read_to_string(path)?;
    let settings: ClaudeSettings = serde_json::from_str(&content)
        .map_err(|e| AuditError::Backend(format!("failed to parse settings.json: {}", e)))?;

    let mut findings = Vec::new();
    let mut safety_bypasses = Vec::new();

    let perms = settings.permissions.as_ref();
    let allow_rules = perms.map_or(0, |p| p.allow.len());
    let deny_rules = perms.map_or(0, |p| p.deny.len());
    let ask_rules = perms.map_or(0, |p| p.ask.len());
    let mcp_server_count = settings.mcp_servers.as_ref().map_or(0, |m| m.len());

    // ---  UninhabitableState analysis via CapabilityLattice projection ---

    if let Some(perms) = perms {
        let caps = project_to_capability_lattice(perms);
        let uninhabitable_state_config = IncompatibilityConstraint::enforcing();
        let state_risk = uninhabitable_state_config.state_risk(&caps);

        if state_risk == portcullis::StateRisk::Uninhabitable {
            findings.push(Finding {
                severity: Severity::Critical,
                category: "uninhabitable_state".to_string(),
                title: "Lethal uninhabitable_state in Claude Code settings".to_string(),
                description: "The allow rules grant private data access (Read/Glob/Grep) + \
                    untrusted content (WebFetch/WebSearch) + exfiltration (Bash) without \
                    sufficient deny rules to break the uninhabitable_state. A prompt injection attack \
                    could exfiltrate sensitive data."
                    .to_string(),
            });
        } else if state_risk == portcullis::StateRisk::Medium {
            findings.push(Finding {
                severity: Severity::Medium,
                category: "uninhabitable_state".to_string(),
                title: "Partial uninhabitable_state in Claude Code settings".to_string(),
                description:
                    "Two of three uninhabitable_state components are present in allow rules. \
                    Adding the third would enable data exfiltration. Review deny rules."
                        .to_string(),
            });
        }

        // --- Unrestricted bash ---
        for rule in &perms.allow {
            let parsed = parse_tool_permission(rule);
            if parsed.tool == ToolKind::Bash && is_unrestricted_pattern(parsed.pattern.as_deref()) {
                // Check if deny rules mitigate this
                let has_bash_deny = perms.deny.iter().any(|d| {
                    let dp = parse_tool_permission(d);
                    dp.tool == ToolKind::Bash
                });
                if !has_bash_deny {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: "permissions".to_string(),
                        title: "Unrestricted Bash access".to_string(),
                        description: "Bash is allowed without pattern restrictions and no \
                            deny rules limit it. The agent can execute any shell command \
                            including data exfiltration via curl, wget, etc."
                            .to_string(),
                    });
                }
            }

            // Exfiltration patterns in bash allow rules
            if parsed.tool == ToolKind::Bash {
                if let Some(pattern) = &parsed.pattern {
                    if is_exfil_bash_pattern(pattern) {
                        findings.push(Finding {
                            severity: Severity::High,
                            category: "exfiltration".to_string(),
                            title: format!("Exfiltration command allowed: {}", rule),
                            description: format!(
                                "The allow rule '{}' permits a known exfiltration command. \
                                 If this is intentional, add it to the 'ask' list instead \
                                 so it requires approval.",
                                rule
                            ),
                        });
                    }
                }
            }

            // Sensitive path access
            if parsed.tool == ToolKind::Read {
                if let Some(pattern) = &parsed.pattern {
                    if is_sensitive_path_pattern(pattern) {
                        findings.push(Finding {
                            severity: Severity::Medium,
                            category: "permissions".to_string(),
                            title: format!("Sensitive path readable: {}", rule),
                            description: format!(
                                "The allow rule '{}' grants read access to a sensitive path \
                                 (credentials, secrets, SSH keys). Consider adding a deny rule.",
                                rule
                            ),
                        });
                    }
                }
            }
        }

        // --- No deny rules ---
        if perms.deny.is_empty() && !perms.allow.is_empty() {
            findings.push(Finding {
                severity: Severity::Medium,
                category: "permissions".to_string(),
                title: "No deny rules configured".to_string(),
                description: "Allow rules are present but no deny rules. Without deny rules, \
                    all allowed tools have unrestricted access. Add deny rules for sensitive \
                    operations (e.g., Bash(curl *), Read(.env))."
                    .to_string(),
            });
        }
    }

    // --- Safety bypass flags ---

    if settings.skip_dangerous_mode_permission_prompt == Some(true) {
        safety_bypasses.push("skipDangerousModePermissionPrompt".to_string());
        findings.push(Finding {
            severity: Severity::High,
            category: "safety_bypass".to_string(),
            title: "Dangerous mode prompt skipped".to_string(),
            description: "skipDangerousModePermissionPrompt is true. This suppresses the \
                safety confirmation when entering dangerous mode, making it easier to \
                accidentally grant full permissions."
                .to_string(),
        });
    }

    if settings.api_key_helper.is_some() {
        findings.push(Finding {
            severity: Severity::Medium,
            category: "credentials".to_string(),
            title: "API key helper script configured".to_string(),
            description: "An apiKeyHelper script is configured. This script runs to generate \
                API credentials and has access to the environment. Ensure it is trusted and \
                not subject to injection."
                .to_string(),
        });
    }

    // --- Sandbox configuration ---

    let sandbox_enabled = settings.sandbox.as_ref().and_then(|s| s.enabled);
    if sandbox_enabled == Some(false) {
        safety_bypasses.push("sandbox.enabled=false".to_string());
        findings.push(Finding {
            severity: Severity::Medium,
            category: "isolation".to_string(),
            title: "Sandbox explicitly disabled".to_string(),
            description: "The sandbox is explicitly disabled. The agent runs without \
                filesystem or network isolation boundaries."
                .to_string(),
        });
    }

    // --- Hooks ---

    if let Some(hooks) = &settings.hooks {
        if hooks.is_object() && !hooks.as_object().unwrap().is_empty() {
            let hook_count = hooks.as_object().unwrap().len();
            findings.push(Finding {
                severity: Severity::Medium,
                category: "hooks".to_string(),
                title: format!(
                    "{} hook{} configured",
                    hook_count,
                    if hook_count == 1 { "" } else { "s" }
                ),
                description: "Hooks can execute arbitrary commands or make HTTP requests in \
                    response to tool events. Each hook is a potential execution and \
                    exfiltration vector. Review hook configurations."
                    .to_string(),
            });
        }
    }

    // --- Inline credentials in env ---

    if let Some(env) = &settings.env {
        check_credential_env(env, &mut findings, "settings.env");
    }

    // --- MCP servers embedded in settings ---

    if let Some(servers) = &settings.mcp_servers {
        for (name, server) in servers {
            if let Some(env) = server.get("env").and_then(|e| e.as_object()) {
                let env_map: HashMap<String, String> = env
                    .iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect();
                check_credential_env(&env_map, &mut findings, &format!("mcpServers.{}", name));
            }
        }
    }

    let summary = ClaudeSettingsSummary {
        total_allow_rules: allow_rules,
        total_deny_rules: deny_rules,
        total_ask_rules: ask_rules,
        mcp_server_count,
        sandbox_enabled,
        safety_bypasses,
    };

    Ok((findings, summary))
}

/// Project Claude Code allow/deny rules to a CapabilityLattice for uninhabitable_state analysis.
fn project_to_capability_lattice(perms: &PermissionRules) -> CapabilityLattice {
    // Start from all-Never (not default, which is permissive)
    let mut caps = CapabilityLattice {
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
        ..CapabilityLattice::default()
    };

    // Allow rules raise capabilities to LowRisk
    for rule in &perms.allow {
        let parsed = parse_tool_permission(rule);
        match parsed.tool {
            ToolKind::Read | ToolKind::Glob | ToolKind::Grep => {
                caps.read_files = CapabilityLevel::LowRisk;
                if matches!(parsed.tool, ToolKind::Glob) {
                    caps.glob_search = CapabilityLevel::LowRisk;
                }
                if matches!(parsed.tool, ToolKind::Grep) {
                    caps.grep_search = CapabilityLevel::LowRisk;
                }
            }
            ToolKind::Write | ToolKind::Edit => {
                caps.write_files = CapabilityLevel::LowRisk;
                caps.edit_files = CapabilityLevel::LowRisk;
            }
            ToolKind::Bash => {
                caps.run_bash = CapabilityLevel::LowRisk;
                // Bash implies additional capabilities based on pattern
                let implied = bash_implied_capabilities(parsed.pattern.as_deref());
                if implied.read_files {
                    caps.read_files = CapabilityLevel::LowRisk;
                }
                if implied.glob_search {
                    caps.glob_search = CapabilityLevel::LowRisk;
                }
                if implied.grep_search {
                    caps.grep_search = CapabilityLevel::LowRisk;
                }
                if implied.web_fetch {
                    caps.web_fetch = CapabilityLevel::LowRisk;
                }
                if implied.web_search {
                    caps.web_search = CapabilityLevel::LowRisk;
                }
                if implied.git_push {
                    caps.git_push = CapabilityLevel::LowRisk;
                }
                if implied.git_commit {
                    caps.git_commit = CapabilityLevel::LowRisk;
                }
            }
            ToolKind::WebSearch => {
                caps.web_search = CapabilityLevel::LowRisk;
            }
            ToolKind::WebFetch => {
                caps.web_fetch = CapabilityLevel::LowRisk;
            }
            ToolKind::McpTool { server, tool } => {
                let implied = mcp_implied_capabilities(&server, &tool);
                if implied.private_data {
                    caps.read_files = CapabilityLevel::LowRisk;
                }
                if implied.untrusted_content {
                    caps.web_fetch = CapabilityLevel::LowRisk;
                }
                if implied.exfiltration {
                    caps.run_bash = CapabilityLevel::LowRisk;
                }
                if implied.git_push {
                    caps.git_push = CapabilityLevel::LowRisk;
                }
                if implied.create_pr {
                    caps.create_pr = CapabilityLevel::LowRisk;
                }
            }
            ToolKind::Unknown(_) => {}
        }
    }

    // Deny rules demote capabilities back to Never (if they fully block the tool)
    for rule in &perms.deny {
        let parsed = parse_tool_permission(rule);
        // Only demote if the deny is unrestricted (blocks all uses of the tool)
        if is_unrestricted_pattern(parsed.pattern.as_deref()) {
            match parsed.tool {
                ToolKind::Read => caps.read_files = CapabilityLevel::Never,
                ToolKind::Glob => caps.glob_search = CapabilityLevel::Never,
                ToolKind::Grep => caps.grep_search = CapabilityLevel::Never,
                ToolKind::Write => caps.write_files = CapabilityLevel::Never,
                ToolKind::Edit => caps.edit_files = CapabilityLevel::Never,
                ToolKind::Bash => caps.run_bash = CapabilityLevel::Never,
                ToolKind::WebSearch => caps.web_search = CapabilityLevel::Never,
                ToolKind::WebFetch => caps.web_fetch = CapabilityLevel::Never,
                _ => {}
            }
        }
    }

    caps
}

/// Check a map of env vars for credential patterns.
fn check_credential_env(env: &HashMap<String, String>, findings: &mut Vec<Finding>, source: &str) {
    let credential_patterns = [
        "API_KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PRIVATE_KEY",
        "AWS_SECRET",
        "DATABASE_URL",
    ];

    for key in env.keys() {
        let upper = key.to_uppercase();
        for pattern in &credential_patterns {
            if upper.contains(pattern) {
                findings.push(Finding {
                    severity: Severity::High,
                    category: "credentials".to_string(),
                    title: format!("Credential in {}: {}", source, key),
                    description: format!(
                        "Environment variable '{}' in {} matches credential pattern '{}'. \
                         Use a secret manager or environment variable reference (${{VAR}}) \
                         instead of plaintext values in config files.",
                        key, source, pattern
                    ),
                });
                break; // One finding per key
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_json(perms: &str) -> String {
        format!(r#"{{ "permissions": {} }}"#, perms)
    }

    #[test]
    fn test_full_uninhabitable_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            settings_json(r#"{ "allow": ["Read", "WebFetch", "Bash"], "deny": [], "ask": [] }"#),
        )
        .unwrap();

        let (findings, summary) = scan_claude_settings(&path).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.category == "uninhabitable_state" && f.severity == Severity::Critical),
            "Should detect uninhabitable_state. Findings: {:?}",
            findings
        );
        assert_eq!(summary.total_allow_rules, 3);
        assert_eq!(summary.total_deny_rules, 0);
    }

    #[test]
    fn test_uninhabitable_mitigated_by_deny() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // Deny bash entirely → breaks uninhabitable_state exfil leg
        std::fs::write(
            &path,
            settings_json(
                r#"{ "allow": ["Read", "WebFetch", "Bash(cargo *)"], "deny": ["Bash"], "ask": [] }"#,
            ),
        )
        .unwrap();

        let (findings, _) = scan_claude_settings(&path).unwrap();
        let uninhabitable_state_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "uninhabitable_state" && f.severity == Severity::Critical)
            .collect();
        assert!(
            uninhabitable_state_findings.is_empty(),
            " UninhabitableState should be mitigated by deny rule. Got: {:?}",
            uninhabitable_state_findings
        );
    }

    #[test]
    fn test_safety_bypass_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{ "skipDangerousModePermissionPrompt": true }"#).unwrap();

        let (findings, summary) = scan_claude_settings(&path).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.category == "safety_bypass" && f.severity == Severity::High),);
        assert!(summary
            .safety_bypasses
            .contains(&"skipDangerousModePermissionPrompt".to_string()));
    }

    #[test]
    fn test_clean_restrictive_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            settings_json(
                r#"{
                    "allow": ["Read", "Bash(cargo *)"],
                    "deny": ["Bash(curl *)", "Bash(wget *)", "Read(.env)"],
                    "ask": ["Bash(git push *)"]
                }"#,
            ),
        )
        .unwrap();

        let (findings, summary) = scan_claude_settings(&path).unwrap();
        // No uninhabitable_state (no WebFetch), has deny rules
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(
            critical.is_empty(),
            "Should have no critical findings: {:?}",
            critical
        );
        assert_eq!(summary.total_deny_rules, 3);
        assert_eq!(summary.total_ask_rules, 1);
    }

    #[test]
    fn test_credential_detection_in_env() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{ "env": { "MY_API_KEY": "sk-secret-123" } }"#).unwrap();

        let (findings, _) = scan_claude_settings(&path).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.category == "credentials" && f.severity == Severity::High),
            "Should flag credential in env"
        );
    }

    #[test]
    fn test_edit_write_bash_triggers_uninhabitable() {
        // This is the real-world case from thaqi-renovation.json:
        // ["Edit", "Write", "Bash"] — unrestricted Bash implies ALL capabilities
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            settings_json(r#"{ "allow": ["Edit", "Write", "Bash"], "deny": [], "ask": [] }"#),
        )
        .unwrap();

        let (findings, _) = scan_claude_settings(&path).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.category == "uninhabitable_state" && f.severity == Severity::Critical),
            "Edit+Write+Bash should trigger CRITICAL uninhabitable_state because unrestricted \
             Bash implies read (cat), web (curl), and exfil. Findings: {:?}",
            findings
        );
    }

    #[test]
    fn test_mcp_tool_exfil_can_complete_uninhabitable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            settings_json(
                r#"{ "allow": ["Read", "WebFetch", "mcp__github__create_pr"], "deny": [], "ask": [] }"#,
            ),
        )
        .unwrap();

        let (findings, _) = scan_claude_settings(&path).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.category == "uninhabitable_state" && f.severity == Severity::Critical),
            "MCP create_pr should count as exfiltration in uninhabitable_state analysis: {:?}",
            findings
        );
    }

    #[test]
    fn test_unrestricted_bash_propagation() {
        // Bare "Bash" should propagate to ALL capability lattice legs
        let perms = PermissionRules {
            allow: vec!["Bash".to_string()],
            deny: vec![],
            ask: vec![],
        };
        let caps = project_to_capability_lattice(&perms);
        assert_eq!(caps.run_bash, CapabilityLevel::LowRisk);
        assert_eq!(caps.read_files, CapabilityLevel::LowRisk, "cat/head/less");
        assert_eq!(caps.glob_search, CapabilityLevel::LowRisk, "find/ls");
        assert_eq!(caps.grep_search, CapabilityLevel::LowRisk, "grep/rg");
        assert_eq!(caps.web_fetch, CapabilityLevel::LowRisk, "curl/wget");
        assert_eq!(caps.web_search, CapabilityLevel::LowRisk, "curl+APIs");
        assert_eq!(caps.git_push, CapabilityLevel::LowRisk, "git push");
        assert_eq!(caps.git_commit, CapabilityLevel::LowRisk, "git commit");
    }

    #[test]
    fn test_patterned_bash_partial_propagation() {
        // Bash(curl *) should raise web_fetch but NOT read_files
        let perms = PermissionRules {
            allow: vec!["Bash(curl *)".to_string()],
            deny: vec![],
            ask: vec![],
        };
        let caps = project_to_capability_lattice(&perms);
        assert_eq!(caps.run_bash, CapabilityLevel::LowRisk);
        assert_eq!(
            caps.web_fetch,
            CapabilityLevel::LowRisk,
            "curl implies web_fetch"
        );
        assert_eq!(
            caps.read_files,
            CapabilityLevel::Never,
            "curl does NOT imply read_files"
        );
        assert_eq!(
            caps.grep_search,
            CapabilityLevel::Never,
            "curl does NOT imply grep"
        );

        // Bash(cat *) should raise read_files but NOT web_fetch
        let perms2 = PermissionRules {
            allow: vec!["Bash(cat *)".to_string()],
            deny: vec![],
            ask: vec![],
        };
        let caps2 = project_to_capability_lattice(&perms2);
        assert_eq!(
            caps2.read_files,
            CapabilityLevel::LowRisk,
            "cat implies read_files"
        );
        assert_eq!(
            caps2.web_fetch,
            CapabilityLevel::Never,
            "cat does NOT imply web_fetch"
        );

        // Bash(git push *) should raise git_push
        let perms3 = PermissionRules {
            allow: vec!["Bash(git push *)".to_string()],
            deny: vec![],
            ask: vec![],
        };
        let caps3 = project_to_capability_lattice(&perms3);
        assert_eq!(
            caps3.git_push,
            CapabilityLevel::LowRisk,
            "git push implies git_push"
        );
        assert_eq!(
            caps3.git_commit,
            CapabilityLevel::Never,
            "git push does NOT imply git_commit"
        );
    }

    #[test]
    fn test_exfil_bash_pattern() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            settings_json(r#"{ "allow": ["Bash(curl *)"], "deny": [], "ask": [] }"#),
        )
        .unwrap();

        let (findings, _) = scan_claude_settings(&path).unwrap();
        assert!(
            findings.iter().any(|f| f.category == "exfiltration"),
            "Should flag curl as exfiltration: {:?}",
            findings
        );
    }
}
