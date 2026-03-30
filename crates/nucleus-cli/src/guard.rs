//! `nucleus guard` — MCP security in one command.
//!
//! ```bash
//! nucleus guard audit    # scan MCP configs for vulnerabilities
//! nucleus guard init     # generate Cedar policies from scan
//! nucleus guard enable   # install hook enforcement
//! nucleus guard status   # show active sessions and exposure
//! ```

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};

/// Secure your MCP servers in one command.
#[derive(Args, Debug)]
pub struct GuardArgs {
    #[command(subcommand)]
    pub command: GuardCommand,
}

#[derive(Subcommand, Debug)]
pub enum GuardCommand {
    /// Scan MCP configurations for security risks
    Audit {
        /// Directory to scan (default: current directory)
        #[arg(default_value = ".")]
        dir: String,
    },
    /// Generate Cedar policies from scan results
    Init {
        /// Directory to initialize (default: current directory)
        #[arg(default_value = ".")]
        dir: String,
    },
    /// Install nucleus-claude-hook for enforcement
    Enable,
    /// Show active guard sessions and exposure state
    Status,
}

pub fn execute(args: GuardArgs) -> Result<()> {
    match args.command {
        GuardCommand::Audit { dir } => audit(&dir),
        GuardCommand::Init { dir } => init(&dir),
        GuardCommand::Enable => enable(),
        GuardCommand::Status => status(),
    }
}

// ─────────────────────────────────────────────────────────────
// guard audit — scan MCP configs
// ─────────────────────────────────────────────────────────────

fn audit(dir: &str) -> Result<()> {
    let dir = PathBuf::from(shellexpand::tilde(dir).as_ref());

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  NUCLEUS GUARD — MCP Security Audit                        ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // Find MCP configs
    let configs = find_mcp_configs(&dir);
    if configs.is_empty() {
        println!("No MCP configurations found in {}", dir.display());
        println!();
        println!("Looked for:");
        println!("  .claude/settings.json");
        println!("  .mcp.json");
        println!("  mcp.json");
        println!("  .vscode/mcp.json");
        println!("  .cursor/mcp.json");
        return Ok(());
    }

    let mut total_servers = 0u32;
    let mut critical = 0u32;
    let mut high = 0u32;
    let mut unknown = 0u32;
    let mut ok = 0u32;

    for config_path in &configs {
        println!("Scanning: {}", config_path.display());
        let content = fs::read_to_string(config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;

        let servers = extract_mcp_servers(&content);
        for (name, server_config) in &servers {
            total_servers += 1;
            let risk = assess_server_risk(name, server_config);
            match risk {
                Risk::Critical(reason) => {
                    critical += 1;
                    println!("  \u{2717} {} — CRITICAL: {}", name, reason);
                    println!("    → fix: nucleus guard init");
                }
                Risk::High(reason) => {
                    high += 1;
                    println!("  \u{2717} {} — HIGH: {}", name, reason);
                }
                Risk::Unknown => {
                    unknown += 1;
                    println!("  \u{26A0} {} — UNKNOWN: no manifest declared", name);
                    println!("    → defaulting to most restrictive");
                }
                Risk::Ok(note) => {
                    ok += 1;
                    println!("  \u{2713} {} — OK: {}", name, note);
                }
            }
        }
    }

    println!();
    println!(
        "Summary: {} servers ({} critical, {} high, {} unknown, {} ok)",
        total_servers, critical, high, unknown, ok
    );

    if critical > 0 || high > 0 {
        println!();
        println!("Run `nucleus guard init` to generate Cedar policies.");
        println!("Run `nucleus guard enable` to enforce them.");
    }

    if critical > 0 {
        std::process::exit(1);
    }

    Ok(())
}

#[derive(Debug)]
enum Risk {
    Critical(String),
    High(String),
    Unknown,
    Ok(String),
}

fn find_mcp_configs(dir: &Path) -> Vec<PathBuf> {
    let candidates = [
        ".claude/settings.json",
        ".mcp.json",
        "mcp.json",
        ".vscode/mcp.json",
        ".cursor/mcp.json",
        "claude_desktop_config.json",
    ];

    candidates
        .iter()
        .map(|c| dir.join(c))
        .filter(|p| p.exists())
        .collect()
}

fn extract_mcp_servers(content: &str) -> Vec<(String, serde_json::Value)> {
    let mut servers = Vec::new();

    let Ok(json) = serde_json::from_str::<serde_json::Value>(content) else {
        return servers;
    };

    // Check mcpServers (Claude Code / MCP config format)
    if let Some(mcp) = json.get("mcpServers").and_then(|v| v.as_object()) {
        for (name, config) in mcp {
            servers.push((name.clone(), config.clone()));
        }
    }

    // Check hooks.mcpServers (settings.json format)
    if let Some(mcp) = json
        .get("hooks")
        .and_then(|h| h.get("mcpServers"))
        .and_then(|v| v.as_object())
    {
        for (name, config) in mcp {
            servers.push((name.clone(), config.clone()));
        }
    }

    servers
}

fn assess_server_risk(name: &str, config: &serde_json::Value) -> Risk {
    let command = config.get("command").and_then(|v| v.as_str()).unwrap_or("");
    let args: Vec<&str> = config
        .get("args")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    // npx -y with unknown packages = supply chain risk
    if command == "npx" && args.iter().any(|a| *a == "-y" || *a == "--yes") {
        let pkg = args
            .iter()
            .find(|a| !a.starts_with('-'))
            .unwrap_or(&"unknown");
        if !is_known_safe_package(pkg) {
            return Risk::Critical(format!(
                "npx -y with unvetted package '{pkg}' — supply chain risk"
            ));
        }
    }

    // Commands with shell access
    if command.contains("bash")
        || command.contains("sh")
        || args.iter().any(|a| a.contains("&&") || a.contains("|"))
    {
        return Risk::Critical("shell command with injection vectors".to_string());
    }

    // Docker/container — generally safer
    if command == "docker" || command == "podman" {
        return Risk::Ok("containerized execution".to_string());
    }

    // Known safe MCP servers
    if is_known_safe_server(name, command) {
        return Risk::Ok(classify_safe_server(name, command));
    }

    // HTTP URLs — remote server
    if command.starts_with("http://") || command.starts_with("https://") {
        return Risk::High("remote MCP server — no local control".to_string());
    }

    // Unknown server
    Risk::Unknown
}

fn is_known_safe_package(pkg: &str) -> bool {
    let safe = [
        "@anthropic-ai/",
        "@modelcontextprotocol/",
        "@playwright/",
        "playwright-mcp",
    ];
    safe.iter().any(|s| pkg.contains(s))
}

fn is_known_safe_server(name: &str, command: &str) -> bool {
    let safe_names = ["fetch", "memory", "filesystem", "git", "github", "sqlite"];
    let safe_commands = ["node", "npx", "uvx", "python", "deno"];

    safe_names.iter().any(|s| name.contains(s))
        || safe_commands.iter().any(|s| command.starts_with(s))
}

fn classify_safe_server(name: &str, _command: &str) -> String {
    if name.contains("fetch") {
        "HTTP fetch — read-only network".to_string()
    } else if name.contains("memory") {
        "local memory — no network".to_string()
    } else if name.contains("filesystem") || name.contains("fs") {
        "filesystem access — local only".to_string()
    } else if name.contains("git") || name.contains("github") {
        "version control — review permissions".to_string()
    } else {
        "recognized server".to_string()
    }
}

// ─────────────────────────────────────────────────────────────
// guard init — generate Cedar policies
// ─────────────────────────────────────────────────────────────

fn init(dir: &str) -> Result<()> {
    let dir = PathBuf::from(shellexpand::tilde(dir).as_ref());
    let guard_dir = dir.join(".nucleus");
    fs::create_dir_all(&guard_dir)?;

    let policy_path = guard_dir.join("guard.cedar");

    let policy = generate_default_cedar_policy(&dir);
    fs::write(&policy_path, &policy)?;

    println!("Generated: {}", policy_path.display());
    println!();
    println!("Review the policy, then run:");
    println!("  nucleus guard enable");
    println!();
    println!("Policy preview:");
    for line in policy.lines().take(20) {
        println!("  {line}");
    }
    if policy.lines().count() > 20 {
        println!("  ... ({} more lines)", policy.lines().count() - 20);
    }

    Ok(())
}

fn generate_default_cedar_policy(dir: &Path) -> String {
    let mut policy = String::new();

    policy.push_str("// Nucleus Guard — Cedar policy for MCP security\n");
    policy.push_str("// Generated by `nucleus guard init`\n");
    policy.push_str("// Review and customize before enabling enforcement.\n\n");

    // Default: allow reads
    policy.push_str("// Allow all read operations (safe — no side effects)\n");
    policy.push_str("permit(\n");
    policy.push_str("    principal,\n");
    policy.push_str("    action == Action::\"read_files\",\n");
    policy.push_str("    resource\n");
    policy.push_str(");\n\n");

    policy.push_str("permit(\n");
    policy.push_str("    principal,\n");
    policy.push_str("    action == Action::\"glob_search\",\n");
    policy.push_str("    resource\n");
    policy.push_str(");\n\n");

    policy.push_str("permit(\n");
    policy.push_str("    principal,\n");
    policy.push_str("    action == Action::\"grep_search\",\n");
    policy.push_str("    resource\n");
    policy.push_str(");\n\n");

    // Block writes from adversarial sources
    policy.push_str("// Block writes when source data is adversarial\n");
    policy.push_str("forbid(\n");
    policy.push_str("    principal,\n");
    policy.push_str("    action == Action::\"write_files\",\n");
    policy.push_str("    resource\n");
    policy.push_str(") when {\n");
    policy.push_str("    context.integrity == \"adversarial\"\n");
    policy.push_str("};\n\n");

    // Allow writes from trusted sources
    policy.push_str("// Allow writes from trusted sources\n");
    policy.push_str("permit(\n");
    policy.push_str("    principal,\n");
    policy.push_str("    action == Action::\"write_files\",\n");
    policy.push_str("    resource\n");
    policy.push_str(") when {\n");
    policy.push_str("    context.integrity == \"trusted\" ||\n");
    policy.push_str("    context.integrity == \"untrusted\"\n");
    policy.push_str("};\n\n");

    // Block git push from web-tainted sessions
    policy.push_str("// Block git push when web content has tainted the session\n");
    policy.push_str("forbid(\n");
    policy.push_str("    principal,\n");
    policy.push_str("    action == Action::\"git_push\",\n");
    policy.push_str("    resource\n");
    policy.push_str(") when {\n");
    policy.push_str("    context.authority == \"noauthority\"\n");
    policy.push_str("};\n\n");

    // Block PR creation from untrusted sources
    policy.push_str("// Block PR creation from untrusted sources\n");
    policy.push_str("forbid(\n");
    policy.push_str("    principal,\n");
    policy.push_str("    action == Action::\"create_pr\",\n");
    policy.push_str("    resource\n");
    policy.push_str(") when {\n");
    policy.push_str("    context.integrity == \"adversarial\"\n");
    policy.push_str("};\n\n");

    // Check for specific MCP servers and add tailored policies
    let configs = find_mcp_configs(dir);
    for config_path in &configs {
        if let Ok(content) = fs::read_to_string(config_path) {
            let servers = extract_mcp_servers(&content);
            for (name, _) in &servers {
                policy.push_str(&format!("// Policy for MCP server: {name}\n"));
                policy.push_str(&format!(
                    "// Customize permissions for mcp__{name}__* tools\n\n"
                ));
            }
        }
    }

    policy
}

// ─────────────────────────────────────────────────────────────
// guard enable — install hook enforcement
// ─────────────────────────────────────────────────────────────

fn enable() -> Result<()> {
    // Find the hook binary
    let hook_bin = which_hook()?;

    println!("Installing nucleus guard enforcement...");
    println!("  Hook binary: {}", hook_bin.display());

    // Run the hook's --setup command
    let output = std::process::Command::new(&hook_bin)
        .arg("--setup")
        .output()
        .context("failed to run nucleus-claude-hook --setup")?;

    if output.status.success() {
        println!("  Status: enabled");
        println!();
        println!("Nucleus guard is now enforcing MCP security.");
        println!("Every tool call is gated through the portcullis kernel.");
        println!();
        println!("  Flow labels: enabled (IFC 5-dimensional)");
        println!("  Exposure tracking: enabled (uninhabitable state detection)");
        println!("  MCP tool gating: enabled (fail-closed)");
        println!();
        println!("View session state: nucleus guard status");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("Setup failed: {stderr}");
        std::process::exit(1);
    }

    Ok(())
}

fn which_hook() -> Result<PathBuf> {
    // Check same directory as nucleus binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join("nucleus-claude-hook");
            if sibling.exists() {
                return Ok(sibling);
            }
        }
    }

    // Check PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("nucleus-claude-hook")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(PathBuf::from(path));
            }
        }
    }

    anyhow::bail!(
        "nucleus-claude-hook not found. Install with:\n  \
         cargo install --path crates/nucleus-claude-hook"
    )
}

// ─────────────────────────────────────────────────────────────
// guard status — show active sessions
// ─────────────────────────────────────────────────────────────

fn status() -> Result<()> {
    let session_dir = std::env::temp_dir().join("nucleus-hook");

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  NUCLEUS GUARD — Status                                    ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    if !session_dir.is_dir() {
        println!("No active sessions.");
        return Ok(());
    }

    let entries: Vec<_> = fs::read_dir(&session_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();

    if entries.is_empty() {
        println!("No active sessions.");
        return Ok(());
    }

    println!("Active sessions:");
    for entry in &entries {
        let path = entry.path();
        let session_id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown");

        if let Ok(content) = fs::read_to_string(&path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                let ops = json
                    .get("allowed_ops")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let flow_obs = json
                    .get("flow_observations")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                let profile = json
                    .get("profile")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");

                println!(
                    "  {} — profile: {}, ops: {}, flow nodes: {}",
                    &session_id[..8.min(session_id.len())],
                    profile,
                    ops,
                    flow_obs
                );
            }
        }
    }

    println!();
    println!("Session data: {}", session_dir.display());

    Ok(())
}
