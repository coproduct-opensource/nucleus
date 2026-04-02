//! Profile resolution and config loading.
//!
//! Extracted from main.rs to stay under the line ratchet ceiling.

use portcullis::PermissionLattice;

/// Known profiles and their constructors.
pub(crate) fn resolve_profile(name: &str) -> Option<PermissionLattice> {
    match name {
        "read_only" => Some(PermissionLattice::read_only()),
        "code_review" => Some(PermissionLattice::code_review()),
        "edit_only" => Some(PermissionLattice::edit_only()),
        "fix_issue" => Some(PermissionLattice::fix_issue()),
        "safe_pr_fixer" => Some(PermissionLattice::safe_pr_fixer()),
        "release" => Some(PermissionLattice::release()),
        "permissive" => Some(PermissionLattice::permissive()),
        _ => None,
    }
}

/// Load config from `.nucleus/config.toml` (#550).
///
/// Priority: env var > config file > default.
pub(crate) fn load_config_file() -> std::collections::HashMap<String, String> {
    let mut config = std::collections::HashMap::new();

    let config_paths = [
        std::env::current_dir()
            .ok()
            .map(|d| d.join(".nucleus").join("config.toml")),
        dirs_next::home_dir().map(|d| d.join(".nucleus").join("config.toml")),
    ];

    for path in config_paths.iter().flatten() {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(table) = content.parse::<toml::Table>() {
                for (key, value) in &table {
                    if let Some(s) = value.as_str() {
                        config.insert(key.clone(), s.to_string());
                    } else if let Some(b) = value.as_bool() {
                        config.insert(key.clone(), if b { "1" } else { "0" }.to_string());
                    }
                }
            }
            break;
        }
    }

    config
}

pub(crate) fn default_profile_name() -> String {
    if let Ok(p) = std::env::var("NUCLEUS_PROFILE") {
        return p;
    }
    let config = load_config_file();
    if let Some(p) = config.get("profile") {
        return p.clone();
    }
    "safe_pr_fixer".to_string()
}

pub(crate) const PROFILES: &[&str] = &[
    "read_only",
    "code_review",
    "edit_only",
    "fix_issue",
    "safe_pr_fixer",
    "release",
    "permissive",
];

/// Load a provenance schema from the working directory (#952).
/// Checks for `.provenance.json` (primary) or `.provenance.toml` (fallback).
pub(crate) fn load_provenance_schema(
    cwd: &std::path::Path,
) -> Option<portcullis_core::provenance_schema::ProvenanceSchema> {
    let json_path = cwd.join(".provenance.json");
    if json_path.is_file() {
        let contents = std::fs::read_to_string(&json_path).ok()?;
        return serde_json::from_str(&contents).ok();
    }
    let toml_path = cwd.join(".provenance.toml");
    if toml_path.is_file() {
        let contents = std::fs::read_to_string(&toml_path).ok()?;
        return toml::from_str(&contents).ok();
    }
    None
}
