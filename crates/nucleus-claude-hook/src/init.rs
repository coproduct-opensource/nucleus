//! `nucleus-claude-hook --init` — scaffold a `.nucleus/` project directory.
//!
//! Creates the full directory structure with default Compartmentfile,
//! policy.toml, egress.toml, and placeholder directories for profiles
//! and tool manifests. Existing files are never overwritten.

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

/// Run the `--init` scaffold: create `.nucleus/` with all default files.
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
    println!("Next steps:");
    println!("  1. Edit .nucleus/policy.toml to customize capabilities");
    println!("  2. Run nucleus-claude-hook --doctor to verify");
    println!("  3. Restart Claude Code");
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
}
