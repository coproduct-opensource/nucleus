//! Permission profile resolution.
//!
//! Profiles are resolved in priority order:
//! 1. **Canonical YAML profiles** from [`portcullis::profile::ProfileRegistry`]
//!    (10 profiles with uninhabitable_state analysis, descriptions, budgets, and time limits)
//! 2. **Short aliases** that map to canonical names (e.g., "review" → "code-review")
//! 3. **User profiles** under `~/.config/nucleus/profiles/*.yaml` — what
//!    `nucleus observe --grant … --narrow NAME --save` and the post-run
//!    "save a narrower profile?" prompt write (ADR 0004, milestone 3)
//! 4. **Legacy profiles** built into [`PermissionLattice`] (for profiles not yet
//!    migrated to YAML)
//!
//! A user profile may carry a canonical name only if it is **not wider**
//! than the canonical one (`leq`): learning from a run narrows, and a file
//! on disk cannot quietly widen what `--ceiling codegen` means. A wider
//! shadow is ignored with a warning.

use std::path::PathBuf;

use anyhow::Result;
use portcullis::PermissionLattice;
use portcullis::profile::ProfileRegistry;

use crate::config::nucleus_dir;

/// What a profile name may look like.
pub const PROFILE_NAME_HELP: &str = "a profile name is lowercase letters, digits and hyphens";

/// `[a-z0-9-]+`, so a name is a file name and a CLI argument and nothing else.
pub fn is_valid_profile_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Where user profiles live.
pub fn user_profiles_dir() -> Result<PathBuf> {
    Ok(nucleus_dir()?.join("profiles"))
}

/// Resolve a profile name to a [`PermissionLattice`].
///
/// Returns `None` if the name is not recognized by any source.
pub fn resolve(name: &str) -> Option<PermissionLattice> {
    let registry = ProfileRegistry::default();

    // 1. Try canonical YAML profiles (handles hyphen/underscore normalization)
    let canonical = registry.resolve(name).ok().or_else(|| {
        // 2. Try short aliases → canonical names
        resolve_alias(name).and_then(|c| registry.resolve(c).ok())
    });

    // 3. A user profile: on its own, or as a narrower shadow of a canonical one.
    if let Some(user) = resolve_user(name) {
        return match canonical {
            Some(c) if !user.leq(&c) => {
                eprintln!(
                    "nucleus: ignoring user profile '{name}': it is wider than the canonical \
                     profile of the same name (a user profile may only narrow it)"
                );
                Some(c)
            }
            _ => Some(user),
        };
    }
    if canonical.is_some() {
        return canonical;
    }

    // 4. Legacy profiles not (yet) in the registry
    resolve_legacy(name)
}

/// The user's profile directory, if it exists and parses. A directory that
/// fails to parse is reported once and treated as empty: a broken file must
/// not make `--profile codegen` fail.
pub fn user_registry() -> Option<ProfileRegistry> {
    let dir = user_profiles_dir().ok()?;
    match ProfileRegistry::load_from_dir(&dir) {
        Ok(r) if !r.is_empty() => Some(r),
        Ok(_) => None,
        Err(e) => {
            eprintln!("nucleus: user profiles in {} ignored: {e}", dir.display());
            None
        }
    }
}

fn resolve_user(name: &str) -> Option<PermissionLattice> {
    user_registry()?.resolve(name).ok()
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
/// then the user's own, then legacy profiles.
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

    if let Some(user) = user_registry() {
        println!();
        println!(
            "Your profiles ({}):",
            user_profiles_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        );
        println!();
        for name in user.names() {
            if let Some(spec) = user.get(name) {
                let desc = spec.description.as_deref().unwrap_or("(no description)");
                println!("  {:<18} {}", name, desc);
            }
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

    #[test]
    fn profile_names_are_file_and_flag_safe() {
        assert!(is_valid_profile_name("ci-tests"));
        assert!(is_valid_profile_name("x1"));
        assert!(!is_valid_profile_name(""));
        assert!(!is_valid_profile_name("CI Tests"));
        assert!(!is_valid_profile_name("../codegen"));
    }
}
