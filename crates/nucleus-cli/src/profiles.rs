//! Permission profile resolution.
//!
//! Profiles are resolved in priority order:
//! 1. **Canonical YAML profiles** from [`portcullis::profile::ProfileRegistry`]
//!    (10 profiles with uninhabitable_state analysis, descriptions, budgets, and time limits)
//! 2. **Short aliases** that map to canonical names (e.g., "review" → "code-review")
//! 3. **Legacy profiles** built into [`PermissionLattice`] (for profiles not yet
//!    migrated to YAML)

use anyhow::Result;
use portcullis::profile::ProfileRegistry;
use portcullis::PermissionLattice;

/// Resolve a profile name to a [`PermissionLattice`].
///
/// Returns `None` if the name is not recognized by any source.
pub fn resolve(name: &str) -> Option<PermissionLattice> {
    let registry = ProfileRegistry::default();

    // 1. Try canonical YAML profiles (handles hyphen/underscore normalization)
    if let Ok(lattice) = registry.resolve(name) {
        return Some(lattice);
    }

    // 2. Try short aliases → canonical names
    if let Some(canonical) = resolve_alias(name) {
        if let Ok(lattice) = registry.resolve(canonical) {
            return Some(lattice);
        }
    }

    // 3. Legacy profiles not (yet) in the registry
    resolve_legacy(name)
}

/// Map short aliases to canonical profile names.
fn resolve_alias(name: &str) -> Option<&'static str> {
    match name.to_lowercase().as_str() {
        // Aliases for canonical profiles
        "review" | "codereview" => Some("code-review"),
        "research" => Some("research-web"),
        "local" => Some("local-dev"),
        "readonly" => Some("read-only"),
        "safe-pr" | "safe_pr_fixer" => Some("safe-pr-fixer"),
        "publish" => Some("release"),
        _ => None,
    }
}

/// Legacy profiles not in ProfileRegistry.
fn resolve_legacy(name: &str) -> Option<PermissionLattice> {
    match name.to_lowercase().as_str() {
        "filesystem-readonly" | "fs-readonly" | "filesystem" => {
            Some(PermissionLattice::filesystem_readonly())
        }
        "network-only" | "network" => Some(PermissionLattice::network_only()),
        "edit-only" | "edit" => Some(PermissionLattice::edit_only()),
        "fix-issue" | "fixissue" | "fix" => Some(PermissionLattice::fix_issue()),
        "database-client" | "db-client" | "database" => Some(PermissionLattice::database_client()),
        "demo" => Some(PermissionLattice::demo()),
        "full" | "permissive" => Some(PermissionLattice::permissive()),
        "restrictive" | "minimal" => Some(PermissionLattice::restrictive()),
        _ => None,
    }
}

/// List available profiles to stdout.
///
/// Canonical profiles are listed first with descriptions from their YAML specs,
/// followed by legacy profiles.
pub fn list() -> Result<()> {
    let registry = ProfileRegistry::default();

    println!("Available Permission Profiles");
    println!("=============================");
    println!();

    // Canonical profiles (from YAML with descriptions)
    println!("Canonical profiles (declarative YAML with uninhabitable_state analysis):");
    println!();
    for name in registry.names() {
        if let Some(spec) = registry.get(name) {
            let desc = spec.description.as_deref().unwrap_or("(no description)");
            println!("  {:<18} {}", name, desc);
        }
    }

    // Legacy profiles
    let legacy: &[(&str, &str)] = &[
        (
            "filesystem-readonly",
            "Read + search; blocks sensitive paths",
        ),
        ("network-only", "Web access only (no filesystem/exec)"),
        ("edit-only", "Write + edit without exec or web"),
        ("fix-issue", "Write + bash + git commit (no push/PR)"),
        ("database-client", "DB CLI only (psql/mysql/redis)"),
        ("demo", "Demo-friendly permissions with approvals"),
        (
            "full",
            "Everything enabled (uninhabitable_state still enforced!)",
        ),
        ("restrictive", "Minimal permissions (default)"),
    ];
    println!();
    println!("Legacy profiles:");
    println!();
    for (name, desc) in legacy {
        println!("  {:<18} {}", name, desc);
    }

    println!();
    println!("Usage:");
    println!("  nucleus run --profile codegen \"Generate the feature\"");
    println!();
    println!("Note: Even 'full' profile enforces the uninhabitable_state constraint.");
    println!("      Exfiltration is blocked when private data + untrusted content");
    println!("      are both accessible.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_profiles_resolve() {
        // All 10 canonical profiles should resolve
        let canonical = [
            "safe-pr-fixer",
            "doc-editor",
            "test-runner",
            "triage-bot",
            "code-review",
            "codegen",
            "release",
            "research-web",
            "read-only",
            "local-dev",
        ];
        for name in &canonical {
            assert!(
                resolve(name).is_some(),
                "canonical profile '{}' should resolve",
                name
            );
        }
    }

    #[test]
    fn test_canonical_underscore_normalization() {
        // Underscores should resolve the same as hyphens
        assert!(resolve("safe_pr_fixer").is_some());
        assert!(resolve("doc_editor").is_some());
        assert!(resolve("test_runner").is_some());
        assert!(resolve("triage_bot").is_some());
        assert!(resolve("code_review").is_some());
        assert!(resolve("research_web").is_some());
        assert!(resolve("read_only").is_some());
        assert!(resolve("local_dev").is_some());
    }

    #[test]
    fn test_aliases_resolve() {
        assert!(
            resolve("review").is_some(),
            "'review' should alias code-review"
        );
        assert!(
            resolve("research").is_some(),
            "'research' should alias research-web"
        );
        assert!(resolve("local").is_some(), "'local' should alias local-dev");
        assert!(
            resolve("readonly").is_some(),
            "'readonly' should alias read-only"
        );
        assert!(
            resolve("publish").is_some(),
            "'publish' should alias release"
        );
        assert!(
            resolve("safe-pr").is_some(),
            "'safe-pr' should alias safe-pr-fixer"
        );
    }

    #[test]
    fn test_legacy_profiles_resolve() {
        let legacy = [
            "filesystem-readonly",
            "network-only",
            "edit-only",
            "fix-issue",
            "database-client",
            "demo",
            "full",
            "restrictive",
        ];
        for name in &legacy {
            assert!(
                resolve(name).is_some(),
                "legacy profile '{}' should resolve",
                name
            );
        }
    }

    #[test]
    fn test_legacy_aliases_resolve() {
        assert!(resolve("fs-readonly").is_some());
        assert!(resolve("filesystem").is_some());
        assert!(resolve("network").is_some());
        assert!(resolve("edit").is_some());
        assert!(resolve("fix").is_some());
        assert!(resolve("db-client").is_some());
        assert!(resolve("permissive").is_some());
        assert!(resolve("minimal").is_some());
    }

    #[test]
    fn test_unknown_profile_returns_none() {
        assert!(resolve("nonexistent").is_none());
        assert!(resolve("").is_none());
    }

    #[test]
    fn test_canonical_takes_priority_over_legacy() {
        // Profiles that exist in both canonical and legacy should use canonical
        // (which has YAML-defined descriptions, budgets, time limits)
        let registry = ProfileRegistry::default();
        let overlapping = ["code-review", "release", "read-only", "local-dev"];
        for name in &overlapping {
            let from_registry = registry.resolve(name).unwrap();
            let from_resolve = resolve(name).unwrap();
            // Both should produce the same result (canonical source)
            assert_eq!(
                from_registry.description, from_resolve.description,
                "profile '{}' should come from canonical registry",
                name
            );
        }
    }
}
