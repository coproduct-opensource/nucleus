//! Auto-discovery of agent configuration files.
//!
//! Walks the directory tree to find Claude Code settings, MCP configs,
//! and PodSpec files. Zero-config entry point for `nucleus-audit scan --auto`.

use std::path::{Path, PathBuf};

/// Known config file patterns to discover.
const CLAUDE_SETTINGS_NAMES: &[&str] = &[".claude/settings.json", ".claude/settings.local.json"];

const MCP_CONFIG_NAMES: &[&str] = &[".mcp.json", "mcp.json", ".cursor/mcp.json"];

/// Result of auto-discovery scan.
#[derive(Debug, Default)]
pub struct DiscoveredConfigs {
    pub claude_settings: Vec<PathBuf>,
    pub mcp_configs: Vec<PathBuf>,
    pub pod_specs: Vec<PathBuf>,
}

impl DiscoveredConfigs {
    pub fn is_empty(&self) -> bool {
        self.claude_settings.is_empty() && self.mcp_configs.is_empty() && self.pod_specs.is_empty()
    }

    pub fn total(&self) -> usize {
        self.claude_settings.len() + self.mcp_configs.len() + self.pod_specs.len()
    }
}

/// Discover agent config files starting from `root`.
///
/// Walks the directory tree up to `max_depth` levels deep, skipping
/// hidden directories (except `.claude` and `.cursor`), `node_modules`,
/// `target`, and `.git`.
pub fn discover_configs(root: &Path, max_depth: usize) -> DiscoveredConfigs {
    let mut result = DiscoveredConfigs::default();
    walk_dir(root, 0, max_depth, &mut result);
    // Sort for deterministic output
    result.claude_settings.sort();
    result.mcp_configs.sort();
    result.pod_specs.sort();
    result
}

fn walk_dir(dir: &Path, depth: usize, max_depth: usize, result: &mut DiscoveredConfigs) {
    if depth > max_depth {
        return;
    }

    // Check for known config files at this level
    for name in CLAUDE_SETTINGS_NAMES {
        let path = dir.join(name);
        if path.is_file() {
            result.claude_settings.push(path);
        }
    }

    for name in MCP_CONFIG_NAMES {
        let path = dir.join(name);
        if path.is_file() {
            result.mcp_configs.push(path);
        }
    }

    // Check for PodSpec YAML files in known locations
    if depth == 0 {
        // Only scan specific dirs for podspecs to avoid false positives
        for podspec_dir in &["examples/podspecs", "podspecs", "deploy", "k8s", ".nucleus"] {
            let ps_dir = dir.join(podspec_dir);
            if ps_dir.is_dir() {
                scan_podspec_dir(&ps_dir, result);
            }
        }
    }

    // Recurse into subdirectories
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };

        // Skip irrelevant directories
        if should_skip_dir(name) {
            continue;
        }

        walk_dir(&path, depth + 1, max_depth, result);
    }
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "__pycache__"
            | ".venv"
            | "venv"
            | ".tox"
            | "dist"
            | "build"
    ) || (name.starts_with('.') && name != ".claude" && name != ".cursor" && name != ".nucleus")
}

fn scan_podspec_dir(dir: &Path, result: &mut DiscoveredConfigs) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext == "yaml" || ext == "yml" {
                // Quick check: does it look like a nucleus PodSpec?
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if content.contains("nucleus") && content.contains("Pod") {
                        result.pod_specs.push(path);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discover_claude_settings() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(claude_dir.join("settings.json"), "{}").unwrap();

        let result = discover_configs(dir.path(), 3);
        assert_eq!(result.claude_settings.len(), 1);
        assert!(result.claude_settings[0].ends_with(".claude/settings.json"));
    }

    #[test]
    fn test_discover_mcp_config() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".mcp.json"), "{}").unwrap();

        let result = discover_configs(dir.path(), 3);
        assert_eq!(result.mcp_configs.len(), 1);
    }

    #[test]
    fn test_discover_podspec() {
        let dir = tempfile::tempdir().unwrap();
        let ps_dir = dir.path().join("examples/podspecs");
        std::fs::create_dir_all(&ps_dir).unwrap();
        std::fs::write(
            ps_dir.join("agent.yaml"),
            "apiVersion: nucleus/v1\nkind: Pod\n",
        )
        .unwrap();

        let result = discover_configs(dir.path(), 3);
        assert_eq!(result.pod_specs.len(), 1);
    }

    #[test]
    fn test_discover_empty() {
        let dir = tempfile::tempdir().unwrap();
        let result = discover_configs(dir.path(), 3);
        assert!(result.is_empty());
    }

    #[test]
    fn test_skip_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        let nm_dir = dir.path().join("node_modules/.claude");
        std::fs::create_dir_all(&nm_dir).unwrap();
        std::fs::write(nm_dir.join("settings.json"), "{}").unwrap();

        let result = discover_configs(dir.path(), 3);
        assert!(result.claude_settings.is_empty());
    }
}
