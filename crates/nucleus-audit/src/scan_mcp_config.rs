//! MCP server configuration security scanner.
//!
//! Parses `.mcp.json` or the `mcpServers` section of Claude Code settings
//! and flags credential exposure, dangerous commands, and attack surface.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::finding::{Finding, McpConfigSummary, Severity};
use crate::AuditError;

// --- Serde structs for MCP config ---

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpConfig {
    #[serde(default)]
    pub mcp_servers: HashMap<String, McpServerEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct McpServerEntry {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Option<Vec<String>>,
    #[serde(default)]
    pub env: Option<HashMap<String, String>>,
    #[serde(default, rename = "type")]
    pub type_: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

/// Scan an MCP config file for security issues.
pub fn scan_mcp_config(path: &Path) -> Result<(Vec<Finding>, McpConfigSummary), AuditError> {
    let content = std::fs::read_to_string(path)?;
    let config: McpConfig = serde_json::from_str(&content)
        .map_err(|e| AuditError::Backend(format!("failed to parse MCP config: {}", e)))?;

    let mut findings = Vec::new();
    let mut command_servers = 0;
    let mut http_servers = 0;
    let mut servers_with_credentials = 0;

    for (name, server) in &config.mcp_servers {
        let is_http = server.type_.as_deref() == Some("http") || server.url.is_some();
        if is_http {
            http_servers += 1;
        } else {
            command_servers += 1;
        }

        let mut has_creds = false;

        // --- HTTP server analysis ---
        if is_http {
            if let Some(url) = &server.url {
                if !url.starts_with("http://localhost")
                    && !url.starts_with("http://127.0.0.1")
                    && !url.starts_with("http://[::1]")
                {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        category: "network".to_string(),
                        title: format!("External MCP server '{}': {}", name, url),
                        description: format!(
                            "MCP server '{}' connects to an external URL. This exposes \
                             tool calls and context to a remote endpoint. Ensure the \
                             server is trusted and the connection is encrypted.",
                            name
                        ),
                    });
                }
            }
        }

        // --- Credential analysis in env ---
        if let Some(env) = &server.env {
            let credential_patterns = ["API_KEY", "TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY"];
            for (key, value) in env {
                let upper = key.to_uppercase();
                let is_variable_ref = value.starts_with("${") || value.starts_with("$");
                for pattern in &credential_patterns {
                    if upper.contains(pattern) {
                        has_creds = true;
                        if !is_variable_ref {
                            findings.push(Finding {
                                severity: Severity::High,
                                category: "credentials".to_string(),
                                title: format!(
                                    "Plaintext credential in MCP server '{}': {}",
                                    name, key
                                ),
                                description: format!(
                                    "MCP server '{}' has env var '{}' containing a credential \
                                     value. Use an environment variable reference (${{VAR}}) \
                                     instead of a plaintext value in the config file.",
                                    name, key
                                ),
                            });
                        }
                        break;
                    }
                }
            }
        }

        // --- Auth headers ---
        if let Some(headers) = &server.headers {
            for key in headers.keys() {
                let lower = key.to_lowercase();
                if lower == "authorization"
                    || lower.contains("token")
                    || lower.contains("api-key")
                    || lower.contains("x-api-key")
                {
                    has_creds = true;
                    findings.push(Finding {
                        severity: Severity::High,
                        category: "credentials".to_string(),
                        title: format!("Auth header in MCP server '{}': {}", name, key),
                        description: format!(
                            "MCP server '{}' includes authentication header '{}'. \
                             Hardcoded auth headers in config files are a security risk. \
                             Use environment variable references instead.",
                            name, key
                        ),
                    });
                }
            }
        }

        if has_creds {
            servers_with_credentials += 1;
        }

        // --- Dangerous commands ---
        if let Some(cmd) = &server.command {
            let dangerous_commands = ["sudo", "sh -c", "bash -c", "eval"];
            for dangerous in &dangerous_commands {
                if cmd.contains(dangerous) {
                    findings.push(Finding {
                        severity: Severity::High,
                        category: "execution".to_string(),
                        title: format!("Dangerous command in MCP server '{}': {}", name, cmd),
                        description: format!(
                            "MCP server '{}' uses '{}' which enables arbitrary \
                             code execution. Prefer specific, scoped commands.",
                            name, dangerous
                        ),
                    });
                }
            }
        }

        // --- Suspicious args ---
        if let Some(args) = &server.args {
            for arg in args {
                if arg.contains("eval") || arg.contains("exec(") {
                    findings.push(Finding {
                        severity: Severity::Medium,
                        category: "execution".to_string(),
                        title: format!("Suspicious arg in MCP server '{}': {}", name, arg),
                        description: format!(
                            "MCP server '{}' has argument '{}' that may enable \
                             dynamic code execution.",
                            name, arg
                        ),
                    });
                }
            }
        }
    }

    // --- Overall surface area ---
    if config.mcp_servers.len() > 5 {
        findings.push(Finding {
            severity: Severity::Low,
            category: "surface_area".to_string(),
            title: format!("{} MCP servers configured", config.mcp_servers.len()),
            description: "A large number of MCP servers increases the attack \
                surface. Each server can execute code and access credentials. \
                Review whether all servers are necessary."
                .to_string(),
        });
    }

    let summary = McpConfigSummary {
        server_count: config.mcp_servers.len(),
        command_servers,
        http_servers,
        servers_with_credentials,
    };

    Ok((findings, summary))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plaintext_credential_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        std::fs::write(
            &path,
            r#"{
                "mcpServers": {
                    "myserver": {
                        "command": "npx",
                        "args": ["-y", "my-mcp"],
                        "env": {
                            "API_KEY": "sk-secret-123"
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let (findings, summary) = scan_mcp_config(&path).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.category == "credentials" && f.severity == Severity::High),
            "Should flag plaintext API_KEY: {:?}",
            findings
        );
        assert_eq!(summary.servers_with_credentials, 1);
    }

    #[test]
    fn test_variable_ref_credential_no_flag() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        std::fs::write(
            &path,
            r#"{
                "mcpServers": {
                    "github": {
                        "command": "npx",
                        "args": ["-y", "gh-actions-mcp"],
                        "env": {
                            "GITHUB_TOKEN": "${GITHUB_TOKEN}"
                        }
                    }
                }
            }"#,
        )
        .unwrap();

        let (findings, summary) = scan_mcp_config(&path).unwrap();
        // Variable refs should NOT be flagged as plaintext credentials
        let plaintext_creds: Vec<_> = findings
            .iter()
            .filter(|f| f.category == "credentials" && f.title.contains("Plaintext"))
            .collect();
        assert!(
            plaintext_creds.is_empty(),
            "Variable ref should not be flagged as plaintext: {:?}",
            plaintext_creds
        );
        // But it should still count as having credentials
        assert_eq!(summary.servers_with_credentials, 1);
    }

    #[test]
    fn test_http_server_detection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        std::fs::write(
            &path,
            r#"{
                "mcpServers": {
                    "remote": {
                        "type": "http",
                        "url": "https://api.evil.com/mcp",
                        "headers": { "Authorization": "Bearer token" }
                    }
                }
            }"#,
        )
        .unwrap();

        let (findings, summary) = scan_mcp_config(&path).unwrap();
        assert_eq!(summary.http_servers, 1);
        assert!(findings.iter().any(|f| f.category == "network"));
        assert!(findings.iter().any(|f| f.category == "credentials"));
    }

    #[test]
    fn test_dangerous_command() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        std::fs::write(
            &path,
            r#"{
                "mcpServers": {
                    "danger": {
                        "command": "sudo npx",
                        "args": ["-y", "my-mcp"]
                    }
                }
            }"#,
        )
        .unwrap();

        let (findings, _) = scan_mcp_config(&path).unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.category == "execution" && f.severity == Severity::High),
            "Should flag sudo: {:?}",
            findings
        );
    }

    #[test]
    fn test_clean_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");
        std::fs::write(
            &path,
            r#"{
                "mcpServers": {
                    "local": {
                        "command": "/usr/local/bin/my-tool",
                        "args": ["--mode", "safe"]
                    }
                }
            }"#,
        )
        .unwrap();

        let (findings, summary) = scan_mcp_config(&path).unwrap();
        assert!(
            findings.is_empty(),
            "Clean config should have no findings: {:?}",
            findings
        );
        assert_eq!(summary.server_count, 1);
        assert_eq!(summary.command_servers, 1);
        assert_eq!(summary.servers_with_credentials, 0);
    }
}
