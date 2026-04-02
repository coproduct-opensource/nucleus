//! `nucleus-claude-hook --init` — scaffold a `.nucleus/` project directory
//! and `.claude/` Claude Code integration files.
//!
//! Creates the full directory structure with default Compartmentfile,
//! policy.toml, egress.toml, and placeholder directories for profiles
//! and tool manifests. Also scaffolds `.claude/settings.json` (with
//! merge support for existing files) and compartment slash commands.
//! Existing files are never overwritten.

use portcullis_core::compartmentfile::default_compartmentfile;
use std::fs;
use std::path::Path;

/// Default policy.toml content — a safe starting point that compiles
/// with `compile_policy()`.
fn default_policy_toml() -> &'static str {
    r#"# Security policy — compiled to a PermissionLattice at session start.
# See: https://github.com/coproduct-opensource/nucleus

[profile]
name = "my-project"
description = "Default security policy"

[profile.capabilities]
read_files = "always"
write_files = "low_risk"
edit_files = "low_risk"
run_bash = "low_risk"
glob_search = "always"
grep_search = "always"
web_search = "low_risk"
web_fetch = "low_risk"
git_commit = "low_risk"
git_push = "never"
create_pr = "never"

[profile.budget]
max_cost_usd = 5.0

# Default compartment — agents start here.
[compartments]
default = "draft"

# Per-compartment capability overrides.
[compartments.overrides.research]
write_files = "never"
run_bash = "never"
web_fetch = "always"

[compartments.overrides.execute]
run_bash = "always"
git_commit = "always"

# Manifest policy: "default_allow" (permissive) or "default_deny" (strict).
# manifest_policy = "default_allow"
"#
}

/// Default egress.toml content — network allowlist.
fn default_egress_toml() -> &'static str {
    r#"# Egress policy — controls which hosts an agent may contact.
#
# When this file is present, all outbound connections are default-deny:
# only hosts matching `allowed_hosts` are permitted, and `denied_hosts`
# always takes precedence over `allowed_hosts`.
#
# See: https://github.com/coproduct-opensource/nucleus

# Maximum outbound payload size in bytes (optional, default: no limit).
# Prevents large-scale data exfiltration even to allowed hosts.
# max_payload_bytes = 1048576  # 1 MiB

# Hosts the agent may contact. Supports three pattern types:
#
#   Exact:    "api.github.com"      — matches only that hostname
#   Wildcard: "*.crates.io"         — matches any subdomain (and the bare domain)
#   CIDR:     "10.0.0.0/8"          — matches any IP in the range
#
allowed_hosts = [
    "api.github.com",
    "*.crates.io",
    "registry.npmjs.org",
]

# Hosts that are always denied, even if they match an allow pattern.
denied_hosts = [
    # "evil.example.com",
]
"#
}

/// Default config.toml content — hook-level settings.
fn default_config_toml() -> &'static str {
    r#"# Nucleus security configuration
# See: nucleus-claude-hook --help

# Permission profile (run --show-profile <name> to preview)
profile = "safe_pr_fixer"

# Compartment (research/draft/execute/breakglass)
# compartment = "research"

# Deny MCP tools without manifests in .nucleus/manifests/
require_manifests = false

# Block all tool calls on hook infrastructure errors
fail_closed = false
"#
}

/// Write a file only if it doesn't already exist. Returns true if created.
fn write_if_absent(path: &Path, content: &str) -> bool {
    if path.exists() {
        println!(
            "  \x1b[33m!\x1b[0m {} already exists, skipping",
            path.display()
        );
        return false;
    }
    match fs::write(path, content) {
        Ok(()) => {
            println!("  \x1b[32m\u{2713}\x1b[0m Created {}", path.display());
            true
        }
        Err(e) => {
            println!(
                "  \x1b[31m\u{2717}\x1b[0m Failed to create {}: {e}",
                path.display()
            );
            false
        }
    }
}

/// Create a directory if it doesn't already exist. Returns true if created.
fn mkdir_if_absent(path: &Path) -> bool {
    if path.exists() {
        println!(
            "  \x1b[33m!\x1b[0m {}/ already exists, skipping",
            path.display()
        );
        return false;
    }
    match fs::create_dir_all(path) {
        Ok(()) => {
            println!("  \x1b[32m\u{2713}\x1b[0m Created {}/", path.display());
            true
        }
        Err(e) => {
            println!(
                "  \x1b[31m\u{2717}\x1b[0m Failed to create {}/: {e}",
                path.display()
            );
            false
        }
    }
}

/// Default `.claude/settings.json` nucleus entries.
///
/// Returns the JSON object that should be merged into `.claude/settings.json`.
fn default_claude_settings() -> serde_json::Value {
    serde_json::json!({
        "env": {
            "NUCLEUS_PROFILE": "safe_pr_fixer",
            "NUCLEUS_COMPARTMENT": "research"
        },
        "hooks": {
            "PreToolUse": [{"command": "nucleus-claude-hook"}],
            "PostToolUse": [{"command": "nucleus-claude-hook"}],
            "SessionStart": [{"command": "nucleus-claude-hook --session-init"}],
            "SessionEnd": [{"command": "nucleus-claude-hook --session-end"}]
        },
        "statusLine": "nucleus-claude-hook --statusline"
    })
}

/// Merge `source` into `target` without overwriting existing keys.
///
/// For objects: recursively merge, adding only missing keys.
/// For arrays (like hook lists): append entries from `source` that are not
/// already present in `target` (compared by JSON equality).
/// Scalar keys in `target` are never overwritten.
fn merge_json(target: &mut serde_json::Value, source: &serde_json::Value) {
    match (target, source) {
        (serde_json::Value::Object(t), serde_json::Value::Object(s)) => {
            for (key, src_val) in s {
                if let Some(existing) = t.get_mut(key) {
                    // Recurse into nested objects / arrays.
                    merge_json(existing, src_val);
                } else {
                    t.insert(key.clone(), src_val.clone());
                }
            }
        }
        (serde_json::Value::Array(t), serde_json::Value::Array(s)) => {
            for entry in s {
                if !t.contains(entry) {
                    t.push(entry.clone());
                }
            }
        }
        // Scalars: don't overwrite existing values.
        _ => {}
    }
}

/// Slash-command markdown for compartment switching.
fn compartment_command(name: &str, description: &str) -> String {
    format!(
        "Switch to the **{name}** compartment.\n\n\
         Run:\n```\n\
         echo {name} > $(nucleus-claude-hook --compartment-path)\n\
         ```\n\n\
         {description}\n"
    )
}

/// Scaffold `.claude/settings.json` — merge nucleus config into any existing file.
///
/// Returns `(created, skipped)` counts.
fn scaffold_claude_settings(claude_dir: &Path) -> (u32, u32) {
    let settings_path = claude_dir.join("settings.json");
    let nucleus_settings = default_claude_settings();

    if settings_path.exists() {
        // Read, merge, write back.
        match fs::read_to_string(&settings_path) {
            Ok(contents) => match serde_json::from_str::<serde_json::Value>(&contents) {
                Ok(mut existing) => {
                    merge_json(&mut existing, &nucleus_settings);
                    match serde_json::to_string_pretty(&existing) {
                        Ok(merged) => {
                            if let Err(e) = fs::write(&settings_path, merged) {
                                println!(
                                    "  \x1b[31m\u{2717}\x1b[0m Failed to update {}: {e}",
                                    settings_path.display()
                                );
                                return (0, 1);
                            }
                            println!(
                                "  \x1b[32m\u{2713}\x1b[0m Merged nucleus config into {}",
                                settings_path.display()
                            );
                            (1, 0)
                        }
                        Err(e) => {
                            println!(
                                "  \x1b[31m\u{2717}\x1b[0m Failed to serialize merged settings: {e}"
                            );
                            (0, 1)
                        }
                    }
                }
                Err(e) => {
                    println!(
                        "  \x1b[33m!\x1b[0m {} exists but is not valid JSON ({e}), skipping",
                        settings_path.display()
                    );
                    (0, 1)
                }
            },
            Err(e) => {
                println!(
                    "  \x1b[31m\u{2717}\x1b[0m Failed to read {}: {e}",
                    settings_path.display()
                );
                (0, 1)
            }
        }
    } else {
        // Create fresh.
        let pretty =
            serde_json::to_string_pretty(&nucleus_settings).expect("default settings serialize");
        if write_if_absent(&settings_path, &pretty) {
            (1, 0)
        } else {
            (0, 1)
        }
    }
}

/// Scaffold `.claude/commands/` with compartment slash commands.
///
/// Returns `(created, skipped)` counts.
fn scaffold_claude_commands(claude_dir: &Path) -> (u32, u32) {
    let commands_dir = claude_dir.join("commands");
    fs::create_dir_all(&commands_dir).ok();

    let mut created = 0u32;
    let mut skipped = 0u32;

    let commands: &[(&str, &str, &str)] = &[
        (
            "compartment-research.md",
            "research",
            "Read-only exploration. Web search and file reading allowed, \
             but no writes or shell commands.",
        ),
        (
            "compartment-draft.md",
            "draft",
            "Low-risk editing. File writes and edits allowed, \
             but no shell commands or git push.",
        ),
        (
            "compartment-execute.md",
            "execute",
            "Full execution. Shell commands and git operations allowed. \
             Use when you need to build, test, or deploy.",
        ),
        (
            "compartment-breakglass.md",
            "breakglass",
            "Emergency override. All capabilities unlocked. \
             Requires justification: provide the reason as $ARGUMENTS.",
        ),
    ];

    for (filename, name, description) in commands {
        let path = commands_dir.join(filename);
        let content = compartment_command(name, description);
        if write_if_absent(&path, &content) {
            created += 1;
        } else {
            skipped += 1;
        }
    }

    (created, skipped)
}

/// Skill template content: (directory_name, SKILL.md content).
const SKILL_TEMPLATES: &[(&str, &str)] = &[
    (
        "nucleus-research",
        "---\n\
         name: nucleus-research\n\
         description: Switch to the research compartment (read-only exploration)\n\
         ---\n\
         \n\
         # Switch to Research Compartment\n\
         \n\
         Switch the active Nucleus compartment to **research**.\n\
         \n\
         Research compartment allows read-only exploration: file reading, glob/grep search, \
         and web fetch are permitted. File writes, shell commands, and git operations are blocked.\n\
         \n\
         ## Usage\n\
         \n\
         Run this command to switch:\n\
         \n\
         ```bash\n\
         nucleus-claude-hook --compartment research\n\
         ```\n\
         \n\
         After switching, your capabilities will be restricted to read-only operations \
         until you switch to a different compartment.\n",
    ),
    (
        "nucleus-draft",
        "---\n\
         name: nucleus-draft\n\
         description: Switch to the draft compartment (read + write, no execution)\n\
         ---\n\
         \n\
         # Switch to Draft Compartment\n\
         \n\
         Switch the active Nucleus compartment to **draft**.\n\
         \n\
         Draft compartment allows file reads and writes (low-risk edits) but blocks shell \
         command execution, git push, and web access. Use this when writing or editing code.\n\
         \n\
         ## Usage\n\
         \n\
         Run this command to switch:\n\
         \n\
         ```bash\n\
         nucleus-claude-hook --compartment draft\n\
         ```\n\
         \n\
         After switching, you can read and write files but cannot run bash commands \
         or access the web.\n",
    ),
    (
        "nucleus-execute",
        "---\n\
         name: nucleus-execute\n\
         description: Switch to the execute compartment (full execution access)\n\
         ---\n\
         \n\
         # Switch to Execute Compartment\n\
         \n\
         Switch the active Nucleus compartment to **execute**.\n\
         \n\
         Execute compartment enables shell commands, git commit, and full build/test/deploy \
         capabilities. Use this when you need to run commands, build, or test.\n\
         \n\
         ## Usage\n\
         \n\
         Run this command to switch:\n\
         \n\
         ```bash\n\
         nucleus-claude-hook --compartment execute\n\
         ```\n\
         \n\
         After switching, you can run bash commands, git operations, and other execution tasks. \
         Note: escalation from research directly to execute is blocked -- you must go through \
         draft first.\n",
    ),
    (
        "nucleus-breakglass",
        "---\n\
         name: nucleus-breakglass\n\
         description: Emergency breakglass -- unlock all capabilities with a reason\n\
         ---\n\
         \n\
         # Emergency Breakglass\n\
         \n\
         Switch to **breakglass** compartment, unlocking all capabilities. \
         Requires a justification reason.\n\
         \n\
         Breakglass is for emergencies only (e.g., production outage). All actions are audited. \
         You must provide a reason -- bare breakglass without justification is denied.\n\
         \n\
         ## Usage\n\
         \n\
         Run this command with your reason as $ARGUMENTS:\n\
         \n\
         ```bash\n\
         nucleus-claude-hook --compartment \"breakglass:$ARGUMENTS\"\n\
         ```\n\
         \n\
         The reason is recorded in the audit trail. Escalation rules still apply -- \
         you must be in the execute compartment to escalate to breakglass.\n",
    ),
    (
        "nucleus-status",
        "---\n\
         name: nucleus-status\n\
         description: Show current Nucleus security status and active compartment\n\
         ---\n\
         \n\
         # Nucleus Security Status\n\
         \n\
         Display the current Nucleus security posture: active compartment, profile, \
         session info, and any taint state.\n\
         \n\
         ## Usage\n\
         \n\
         Run this command to see the current status:\n\
         \n\
         ```bash\n\
         nucleus-claude-hook --status\n\
         ```\n\
         \n\
         For machine-readable JSON output:\n\
         \n\
         ```bash\n\
         nucleus-claude-hook --status --json\n\
         ```\n\
         \n\
         This shows:\n\
         - Active compartment (research/draft/execute/breakglass)\n\
         - Security profile in effect\n\
         - Session taint state\n\
         - Operation counts\n",
    ),
    (
        "nucleus-promote",
        "---\n\
         name: nucleus-promote\n\
         description: Promote AI-generated content to human-verified status\n\
         ---\n\
         \n\
         # Promote Content\n\
         \n\
         Mark AI-generated content as human-verified. This updates the provenance metadata \
         so downstream consumers know a human has reviewed and approved the output.\n\
         \n\
         ## Usage\n\
         \n\
         After reviewing AI-generated content, run:\n\
         \n\
         ```bash\n\
         nucleus-claude-hook --reset-session \"$ARGUMENTS\"\n\
         ```\n\
         \n\
         This clears the taint flag on the specified session, indicating human review is complete. \
         The receipt chain is preserved for audit -- only the taint state is cleared.\n\
         \n\
         Provide the session ID as $ARGUMENTS. To find the current session ID, \
         use `/nucleus-status`.\n",
    ),
];

/// Scaffold `.claude/skills/` with Nucleus compartment management skills.
///
/// Returns `(created, skipped)` counts.
fn scaffold_claude_skills(claude_dir: &Path) -> (u32, u32) {
    let skills_dir = claude_dir.join("skills");
    fs::create_dir_all(&skills_dir).ok();

    let mut created = 0u32;
    let mut skipped = 0u32;

    for (dir_name, content) in SKILL_TEMPLATES {
        let skill_dir = skills_dir.join(dir_name);
        fs::create_dir_all(&skill_dir).ok();
        let path = skill_dir.join("SKILL.md");
        if write_if_absent(&path, content) {
            created += 1;
        } else {
            skipped += 1;
        }
    }

    (created, skipped)
}

/// Run the `--init` scaffold: create `.nucleus/` with all default files,
/// then scaffold `.claude/` integration (settings.json + slash commands).
pub fn run_init() {
    println!("Scaffolding .nucleus/ project directory...\n");

    let root = Path::new(".nucleus");
    fs::create_dir_all(root).ok();

    let mut created = 0u32;
    let mut skipped = 0u32;

    let files: &[(&str, &str)] = &[
        ("config.toml", default_config_toml()),
        ("Compartmentfile", default_compartmentfile()),
        ("policy.toml", default_policy_toml()),
        ("egress.toml", default_egress_toml()),
    ];

    for (name, content) in files {
        if write_if_absent(&root.join(name), content) {
            created += 1;
        } else {
            skipped += 1;
        }
    }

    let dirs: &[&str] = &["manifests", "profiles"];
    for name in dirs {
        if mkdir_if_absent(&root.join(name)) {
            created += 1;
        } else {
            skipped += 1;
        }
    }

    // --- Claude Code integration ---
    println!();
    println!("Scaffolding .claude/ integration...\n");

    let claude_dir = Path::new(".claude");
    fs::create_dir_all(claude_dir).ok();

    let (c, s) = scaffold_claude_settings(claude_dir);
    created += c;
    skipped += s;

    let (c, s) = scaffold_claude_commands(claude_dir);
    created += c;
    skipped += s;

    let (c, s) = scaffold_claude_skills(claude_dir);
    created += c;
    skipped += s;

    println!();
    if created > 0 {
        println!("Created {created} file(s)/dir(s).");
    }
    if skipped > 0 {
        println!("Skipped {skipped} (already exist).");
    }

    println!();
    println!("Directory structure:");
    println!("  .nucleus/");
    println!("  \u{251c}\u{2500}\u{2500} config.toml         # Hook-level settings");
    println!("  \u{251c}\u{2500}\u{2500} Compartmentfile     # Compartment definitions");
    println!("  \u{251c}\u{2500}\u{2500} policy.toml         # Security policy");
    println!("  \u{251c}\u{2500}\u{2500} egress.toml         # Network allowlist");
    println!("  \u{251c}\u{2500}\u{2500} manifests/          # Tool manifests");
    println!("  \u{2514}\u{2500}\u{2500} profiles/           # Custom profiles");
    println!();
    println!("  .claude/");
    println!("  \u{251c}\u{2500}\u{2500} settings.json       # Env vars + hooks + status line");
    println!("  \u{251c}\u{2500}\u{2500} commands/");
    println!("  \u{2502}   \u{251c}\u{2500}\u{2500} compartment-research.md");
    println!("  \u{2502}   \u{251c}\u{2500}\u{2500} compartment-draft.md");
    println!("  \u{2502}   \u{251c}\u{2500}\u{2500} compartment-execute.md");
    println!("  \u{2502}   \u{2514}\u{2500}\u{2500} compartment-breakglass.md");
    println!("  \u{2514}\u{2500}\u{2500} skills/");
    println!("      \u{251c}\u{2500}\u{2500} nucleus-research/SKILL.md");
    println!("      \u{251c}\u{2500}\u{2500} nucleus-draft/SKILL.md");
    println!("      \u{251c}\u{2500}\u{2500} nucleus-execute/SKILL.md");
    println!("      \u{251c}\u{2500}\u{2500} nucleus-breakglass/SKILL.md");
    println!("      \u{251c}\u{2500}\u{2500} nucleus-status/SKILL.md");
    println!("      \u{2514}\u{2500}\u{2500} nucleus-promote/SKILL.md");

    println!();
    println!("Next steps:");
    println!("  1. Edit .nucleus/policy.toml to customize capabilities");
    println!("  2. Run nucleus-claude-hook --doctor to verify");
    println!("  3. Restart Claude Code — hooks activate automatically");
    println!("  4. Use /nucleus-execute to switch compartments (skills)");
    println!("  5. Or use: nucleus-claude-hook --compartment draft");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Helper to create a unique temp dir for each test.
    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nucleus-init-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn default_compartmentfile_parses() {
        // Verify our default content is valid TOML that portcullis can parse.
        let cf =
            portcullis_core::compartmentfile::Compartmentfile::parse(default_compartmentfile());
        assert!(cf.is_ok(), "default Compartmentfile should parse");
    }

    #[test]
    fn default_policy_toml_parses() {
        // Verify the policy TOML is valid TOML (structural parse).
        let parsed: Result<toml::Value, _> = toml::from_str(default_policy_toml());
        assert!(parsed.is_ok(), "default policy.toml should be valid TOML");
    }

    #[test]
    fn default_egress_toml_parses() {
        let parsed: Result<toml::Value, _> = toml::from_str(default_egress_toml());
        assert!(parsed.is_ok(), "default egress.toml should be valid TOML");
    }

    #[test]
    fn write_if_absent_creates_file() {
        let dir = temp_dir();
        let path = dir.join("test.txt");
        assert!(write_if_absent(&path, "hello"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_if_absent_skips_existing() {
        let dir = temp_dir();
        let path = dir.join("test.txt");
        fs::write(&path, "original").unwrap();
        assert!(!write_if_absent(&path, "new content"));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mkdir_if_absent_creates_dir() {
        let dir = temp_dir();
        let sub = dir.join("subdir");
        assert!(mkdir_if_absent(&sub));
        assert!(sub.is_dir());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mkdir_if_absent_skips_existing() {
        let dir = temp_dir();
        let sub = dir.join("subdir");
        fs::create_dir_all(&sub).unwrap();
        assert!(!mkdir_if_absent(&sub));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn default_claude_settings_is_valid_json() {
        let v = default_claude_settings();
        assert!(v.is_object());
        assert!(v["env"]["NUCLEUS_PROFILE"].is_string());
        assert!(v["hooks"]["PreToolUse"].is_array());
        assert!(v["hooks"]["SessionStart"].is_array());
        assert!(v["statusLine"].is_string());
    }

    #[test]
    fn merge_json_adds_missing_keys() {
        let mut target = serde_json::json!({"a": 1});
        let source = serde_json::json!({"b": 2});
        merge_json(&mut target, &source);
        assert_eq!(target["a"], 1);
        assert_eq!(target["b"], 2);
    }

    #[test]
    fn merge_json_does_not_overwrite_existing_scalar() {
        let mut target = serde_json::json!({"a": 1});
        let source = serde_json::json!({"a": 99});
        merge_json(&mut target, &source);
        assert_eq!(target["a"], 1);
    }

    #[test]
    fn merge_json_recurses_into_objects() {
        let mut target = serde_json::json!({"env": {"MY_VAR": "keep"}});
        let source = serde_json::json!({"env": {"NUCLEUS_PROFILE": "safe_pr_fixer"}});
        merge_json(&mut target, &source);
        assert_eq!(target["env"]["MY_VAR"], "keep");
        assert_eq!(target["env"]["NUCLEUS_PROFILE"], "safe_pr_fixer");
    }

    #[test]
    fn merge_json_appends_to_arrays_without_duplicates() {
        let mut target = serde_json::json!([{"command": "my-hook"}]);
        let source = serde_json::json!([
            {"command": "my-hook"},
            {"command": "nucleus-claude-hook"}
        ]);
        merge_json(&mut target, &source);
        // my-hook should not be duplicated, nucleus-claude-hook appended.
        assert_eq!(target.as_array().unwrap().len(), 2);
    }

    #[test]
    fn merge_json_full_settings_scenario() {
        // Simulates a user who already has custom hooks and env vars.
        let mut target = serde_json::json!({
            "env": {"MY_TOKEN": "secret"},
            "hooks": {
                "PreToolUse": [{"command": "my-linter"}]
            }
        });
        let source = default_claude_settings();
        merge_json(&mut target, &source);

        // User's env var preserved, nucleus vars added.
        assert_eq!(target["env"]["MY_TOKEN"], "secret");
        assert_eq!(target["env"]["NUCLEUS_PROFILE"], "safe_pr_fixer");

        // User's hook preserved, nucleus hook appended.
        let pre = target["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 2);
        assert_eq!(pre[0]["command"], "my-linter");
        assert_eq!(pre[1]["command"], "nucleus-claude-hook");

        // New hook types added.
        assert!(target["hooks"]["SessionStart"].is_array());
        assert!(target["statusLine"].is_string());
    }

    #[test]
    fn scaffold_claude_settings_creates_fresh() {
        let dir = temp_dir();
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let (created, skipped) = scaffold_claude_settings(&claude_dir);
        assert_eq!(created, 1);
        assert_eq!(skipped, 0);

        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["env"]["NUCLEUS_PROFILE"], "safe_pr_fixer");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scaffold_claude_settings_merges_existing() {
        let dir = temp_dir();
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let existing = serde_json::json!({"env": {"MY_VAR": "keep"}, "custom": true});
        fs::write(
            claude_dir.join("settings.json"),
            serde_json::to_string_pretty(&existing).unwrap(),
        )
        .unwrap();

        let (created, skipped) = scaffold_claude_settings(&claude_dir);
        assert_eq!(created, 1);
        assert_eq!(skipped, 0);

        let content = fs::read_to_string(claude_dir.join("settings.json")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["env"]["MY_VAR"], "keep");
        assert_eq!(v["env"]["NUCLEUS_PROFILE"], "safe_pr_fixer");
        assert_eq!(v["custom"], true);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scaffold_claude_commands_creates_all() {
        let dir = temp_dir();
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let (created, skipped) = scaffold_claude_commands(&claude_dir);
        assert_eq!(created, 4);
        assert_eq!(skipped, 0);

        assert!(claude_dir.join("commands/compartment-research.md").exists());
        assert!(claude_dir.join("commands/compartment-draft.md").exists());
        assert!(claude_dir.join("commands/compartment-execute.md").exists());
        assert!(claude_dir
            .join("commands/compartment-breakglass.md")
            .exists());

        // Verify content structure.
        let content =
            fs::read_to_string(claude_dir.join("commands/compartment-research.md")).unwrap();
        assert!(content.contains("research"));
        assert!(content.contains("nucleus-claude-hook --compartment-path"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scaffold_claude_commands_skips_existing() {
        let dir = temp_dir();
        let claude_dir = dir.join(".claude");
        let commands_dir = claude_dir.join("commands");
        fs::create_dir_all(&commands_dir).unwrap();
        fs::write(commands_dir.join("compartment-research.md"), "custom").unwrap();

        let (created, skipped) = scaffold_claude_commands(&claude_dir);
        assert_eq!(created, 3);
        assert_eq!(skipped, 1);

        // Original content preserved.
        let content = fs::read_to_string(commands_dir.join("compartment-research.md")).unwrap();
        assert_eq!(content, "custom");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scaffold_claude_skills_creates_all() {
        let dir = temp_dir();
        let claude_dir = dir.join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let (created, skipped) = scaffold_claude_skills(&claude_dir);
        assert_eq!(created, 6);
        assert_eq!(skipped, 0);

        // All skill directories and SKILL.md files exist.
        for (name, _) in SKILL_TEMPLATES {
            let skill_file = claude_dir.join("skills").join(name).join("SKILL.md");
            assert!(skill_file.exists(), "missing: {}", skill_file.display());
        }

        // Verify content structure — YAML frontmatter present.
        let content =
            fs::read_to_string(claude_dir.join("skills/nucleus-research/SKILL.md")).unwrap();
        assert!(
            content.starts_with("---\n"),
            "should start with YAML frontmatter"
        );
        assert!(content.contains("name: nucleus-research"));
        assert!(content.contains("nucleus-claude-hook --compartment research"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scaffold_claude_skills_skips_existing() {
        let dir = temp_dir();
        let claude_dir = dir.join(".claude");
        let skill_dir = claude_dir.join("skills/nucleus-draft");
        fs::create_dir_all(&skill_dir).unwrap();
        fs::write(skill_dir.join("SKILL.md"), "custom skill").unwrap();

        let (created, skipped) = scaffold_claude_skills(&claude_dir);
        assert_eq!(created, 5);
        assert_eq!(skipped, 1);

        // Original content preserved.
        let content = fs::read_to_string(skill_dir.join("SKILL.md")).unwrap();
        assert_eq!(content, "custom skill");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn skill_templates_have_valid_frontmatter() {
        for (name, content) in SKILL_TEMPLATES {
            assert!(
                content.starts_with("---\n"),
                "skill {name} must start with YAML frontmatter"
            );
            assert!(
                content.contains(&format!("name: {name}")),
                "skill {name} frontmatter must contain name field"
            );
            assert!(
                content.contains("description:"),
                "skill {name} frontmatter must contain description field"
            );
        }
    }
}
