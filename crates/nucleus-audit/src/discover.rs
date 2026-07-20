//! Auto-discovery of agent configuration files.
//!
//! Walks the directory tree to find agent tool settings, MCP configs,
//! and PodSpec files. Zero-config entry point for `nucleus-audit scan --auto`.

use std::path::{Path, PathBuf};

/// Filenames that agent tools conventionally use to store tool-permission
/// settings, placed inside a per-tool hidden config directory (`.<tool>/`).
///
/// Detection keys off these filenames inside *any* hidden config directory
/// rather than a single vendor's directory name, so coverage is a superset
/// of any one tool's layout (`.<tool>/settings.json`, `.<tool>/settings.local.json`).
const AGENT_SETTINGS_FILENAMES: &[&str] = &["settings.json", "settings.local.json"];

const MCP_CONFIG_NAMES: &[&str] = &[".mcp.json", "mcp.json", ".cursor/mcp.json"];

/// Result of auto-discovery scan.
#[derive(Debug, Default)]
pub struct DiscoveredConfigs {
    pub agent_settings: Vec<PathBuf>,
    pub mcp_configs: Vec<PathBuf>,
    pub pod_specs: Vec<PathBuf>,
}

impl DiscoveredConfigs {
    pub fn is_empty(&self) -> bool {
        self.agent_settings.is_empty() && self.mcp_configs.is_empty() && self.pod_specs.is_empty()
    }

    pub fn total(&self) -> usize {
        self.agent_settings.len() + self.mcp_configs.len() + self.pod_specs.len()
    }
}

/// Discover agent config files starting from `root`.
///
/// Walks the directory tree up to `max_depth` levels deep, skipping
/// build/VCS noise directories (`node_modules`, `target`, `.git`, ...).
/// Any hidden per-tool config directory is probed for conventional
/// settings files.
pub fn discover_configs(root: &Path, max_depth: usize) -> DiscoveredConfigs {
    let mut result = DiscoveredConfigs::default();
    walk_dir(root, 0, max_depth, &mut result);
    // Sort for deterministic output
    result.agent_settings.sort();
    result.mcp_configs.sort();
    result.pod_specs.sort();
    result
}

fn walk_dir(dir: &Path, depth: usize, max_depth: usize, result: &mut DiscoveredConfigs) {
    if depth > max_depth {
        return;
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

        // Skip build/VCS noise directories.
        if should_skip_dir(name) {
            continue;
        }

        // Any hidden directory may be an agent tool's per-tool config dir
        // (`.<tool>/`). Probe it for conventional settings files regardless
        // of whether we recurse further, so coverage is a superset across
        // tools rather than pinned to one vendor's directory name.
        if name.starts_with('.') {
            for fname in AGENT_SETTINGS_FILENAMES {
                let settings_path = path.join(fname);
                if settings_path.is_file() {
                    result.agent_settings.push(settings_path);
                }
            }
        }

        walk_dir(&path, depth + 1, max_depth, result);
    }
}

fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | "node_modules"
            | "target"
            | "__pycache__"
            | ".venv"
            | "venv"
            | ".tox"
            | "dist"
            | "build"
    )
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
    fn test_discover_agent_settings() {
        // A per-tool hidden config dir with a conventional settings file is
        // detected generically — this covers any `.<tool>/settings.json`
        // (the common `.<agent>/settings.json` layout), not one vendor.
        let dir = tempfile::tempdir().unwrap();
        let tool_dir = dir.path().join(".acme");
        std::fs::create_dir_all(&tool_dir).unwrap();
        std::fs::write(tool_dir.join("settings.json"), "{}").unwrap();

        let result = discover_configs(dir.path(), 3);
        assert_eq!(result.agent_settings.len(), 1);
        assert!(result.agent_settings[0].ends_with(".acme/settings.json"));
    }

    #[test]
    fn test_discover_agent_settings_local() {
        let dir = tempfile::tempdir().unwrap();
        let tool_dir = dir.path().join(".acme");
        std::fs::create_dir_all(&tool_dir).unwrap();
        std::fs::write(tool_dir.join("settings.local.json"), "{}").unwrap();

        let result = discover_configs(dir.path(), 3);
        assert_eq!(result.agent_settings.len(), 1);
        assert!(result.agent_settings[0].ends_with(".acme/settings.local.json"));
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
        let nm_dir = dir.path().join("node_modules/.acme");
        std::fs::create_dir_all(&nm_dir).unwrap();
        std::fs::write(nm_dir.join("settings.json"), "{}").unwrap();

        let result = discover_configs(dir.path(), 3);
        assert!(result.agent_settings.is_empty());
    }
}
