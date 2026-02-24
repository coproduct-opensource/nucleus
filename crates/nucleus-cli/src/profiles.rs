//! Built-in permission profiles

use anyhow::Result;
use lattice_guard::PermissionLattice;

/// Built-in permission profiles
pub enum Profile {
    /// Filesystem read-only: read + search with sensitive paths blocked
    FilesystemReadonly,
    /// Read-only: file reading and search only
    ReadOnly,
    /// Network-only: web access only, no filesystem or exec
    NetworkOnly,
    /// Web research: read + web search/fetch
    WebResearch,
    /// Code review: read + limited web search
    CodeReview,
    /// Edit-only: write + edit without exec or web
    EditOnly,
    /// Local dev: write + shell without web
    LocalDev,
    /// Fix issue: write + bash + git commit (no push/PR)
    FixIssue,
    /// Release: full dev + git push/PR with approvals
    Release,
    /// Database client: limited CLI access for DB tools
    DatabaseClient,
    /// Demo: broader commands with approvals
    Demo,
    /// Full access: everything enabled (trifecta still enforced)
    Full,
    /// Restrictive: minimal permissions
    Restrictive,
}

impl Profile {
    /// Get profile by name
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "filesystem-readonly" | "fs-readonly" | "filesystem" => Some(Self::FilesystemReadonly),
            "read-only" | "readonly" => Some(Self::ReadOnly),
            "network-only" | "network" => Some(Self::NetworkOnly),
            "web-research" | "research" => Some(Self::WebResearch),
            "code-review" | "codereview" | "review" => Some(Self::CodeReview),
            "edit-only" | "edit" => Some(Self::EditOnly),
            "local-dev" | "local" => Some(Self::LocalDev),
            "fix-issue" | "fixissue" | "fix" => Some(Self::FixIssue),
            "release" | "publish" => Some(Self::Release),
            "database-client" | "db-client" | "database" => Some(Self::DatabaseClient),
            "demo" => Some(Self::Demo),
            "full" | "permissive" => Some(Self::Full),
            "restrictive" | "minimal" => Some(Self::Restrictive),
            _ => None,
        }
    }

    /// Convert to a PermissionLattice
    pub fn to_lattice(&self) -> PermissionLattice {
        match self {
            Self::FilesystemReadonly => PermissionLattice::filesystem_readonly(),
            Self::ReadOnly => PermissionLattice::read_only(),
            Self::NetworkOnly => PermissionLattice::network_only(),
            Self::WebResearch => PermissionLattice::web_research(),
            Self::CodeReview => PermissionLattice::code_review(),
            Self::EditOnly => PermissionLattice::edit_only(),
            Self::LocalDev => PermissionLattice::local_dev(),
            Self::FixIssue => PermissionLattice::fix_issue(),
            Self::Release => PermissionLattice::release(),
            Self::DatabaseClient => PermissionLattice::database_client(),
            Self::Demo => PermissionLattice::demo(),
            Self::Full => PermissionLattice::permissive(),
            Self::Restrictive => PermissionLattice::restrictive(),
        }
    }

    /// Get all profile names
    #[allow(dead_code)]
    pub fn all_names() -> &'static [&'static str] {
        &[
            "filesystem-readonly",
            "read-only",
            "network-only",
            "web-research",
            "code-review",
            "edit-only",
            "local-dev",
            "fix-issue",
            "release",
            "database-client",
            "demo",
            "full",
            "restrictive",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_name_primary_names() {
        assert!(matches!(
            Profile::from_name("filesystem-readonly"),
            Some(Profile::FilesystemReadonly)
        ));
        assert!(matches!(
            Profile::from_name("read-only"),
            Some(Profile::ReadOnly)
        ));
        assert!(matches!(
            Profile::from_name("network-only"),
            Some(Profile::NetworkOnly)
        ));
        assert!(matches!(
            Profile::from_name("web-research"),
            Some(Profile::WebResearch)
        ));
        assert!(matches!(
            Profile::from_name("code-review"),
            Some(Profile::CodeReview)
        ));
        assert!(matches!(
            Profile::from_name("edit-only"),
            Some(Profile::EditOnly)
        ));
        assert!(matches!(
            Profile::from_name("local-dev"),
            Some(Profile::LocalDev)
        ));
        assert!(matches!(
            Profile::from_name("fix-issue"),
            Some(Profile::FixIssue)
        ));
        assert!(matches!(
            Profile::from_name("release"),
            Some(Profile::Release)
        ));
        assert!(matches!(
            Profile::from_name("database-client"),
            Some(Profile::DatabaseClient)
        ));
        assert!(matches!(
            Profile::from_name("demo"),
            Some(Profile::Demo)
        ));
        assert!(matches!(
            Profile::from_name("full"),
            Some(Profile::Full)
        ));
        assert!(matches!(
            Profile::from_name("restrictive"),
            Some(Profile::Restrictive)
        ));
    }

    #[test]
    fn test_from_name_aliases() {
        // FilesystemReadonly aliases
        assert!(matches!(
            Profile::from_name("fs-readonly"),
            Some(Profile::FilesystemReadonly)
        ));
        assert!(matches!(
            Profile::from_name("filesystem"),
            Some(Profile::FilesystemReadonly)
        ));
        // ReadOnly alias
        assert!(matches!(
            Profile::from_name("readonly"),
            Some(Profile::ReadOnly)
        ));
        // NetworkOnly alias
        assert!(matches!(
            Profile::from_name("network"),
            Some(Profile::NetworkOnly)
        ));
        // WebResearch alias
        assert!(matches!(
            Profile::from_name("research"),
            Some(Profile::WebResearch)
        ));
        // CodeReview aliases
        assert!(matches!(
            Profile::from_name("codereview"),
            Some(Profile::CodeReview)
        ));
        assert!(matches!(
            Profile::from_name("review"),
            Some(Profile::CodeReview)
        ));
        // EditOnly alias
        assert!(matches!(
            Profile::from_name("edit"),
            Some(Profile::EditOnly)
        ));
        // LocalDev alias
        assert!(matches!(
            Profile::from_name("local"),
            Some(Profile::LocalDev)
        ));
        // FixIssue aliases
        assert!(matches!(
            Profile::from_name("fixissue"),
            Some(Profile::FixIssue)
        ));
        assert!(matches!(
            Profile::from_name("fix"),
            Some(Profile::FixIssue)
        ));
        // Release alias
        assert!(matches!(
            Profile::from_name("publish"),
            Some(Profile::Release)
        ));
        // DatabaseClient aliases
        assert!(matches!(
            Profile::from_name("db-client"),
            Some(Profile::DatabaseClient)
        ));
        assert!(matches!(
            Profile::from_name("database"),
            Some(Profile::DatabaseClient)
        ));
        // Full alias
        assert!(matches!(
            Profile::from_name("permissive"),
            Some(Profile::Full)
        ));
        // Restrictive alias
        assert!(matches!(
            Profile::from_name("minimal"),
            Some(Profile::Restrictive)
        ));
    }

    #[test]
    fn test_from_name_case_insensitive() {
        assert!(Profile::from_name("FULL").is_some());
        assert!(Profile::from_name("Full").is_some());
        assert!(Profile::from_name("FIX-ISSUE").is_some());
        assert!(Profile::from_name("READ-ONLY").is_some());
        assert!(Profile::from_name("RESTRICTIVE").is_some());
    }

    #[test]
    fn test_from_name_unknown_returns_none() {
        assert!(Profile::from_name("unknown-profile").is_none());
        assert!(Profile::from_name("").is_none());
        assert!(Profile::from_name("super-admin").is_none());
        assert!(Profile::from_name("full-access").is_none());
    }

    #[test]
    fn test_all_names_are_resolvable() {
        for name in Profile::all_names() {
            assert!(
                Profile::from_name(name).is_some(),
                "Profile name '{}' should resolve",
                name
            );
        }
    }

    #[test]
    fn test_all_names_count() {
        let names = Profile::all_names();
        assert_eq!(names.len(), 13, "Should have 13 built-in profiles");
    }

    #[test]
    fn test_to_lattice_does_not_panic() {
        // Just verify each profile converts without panic
        let _ = Profile::FilesystemReadonly.to_lattice();
        let _ = Profile::ReadOnly.to_lattice();
        let _ = Profile::NetworkOnly.to_lattice();
        let _ = Profile::WebResearch.to_lattice();
        let _ = Profile::CodeReview.to_lattice();
        let _ = Profile::EditOnly.to_lattice();
        let _ = Profile::LocalDev.to_lattice();
        let _ = Profile::FixIssue.to_lattice();
        let _ = Profile::Release.to_lattice();
        let _ = Profile::DatabaseClient.to_lattice();
        let _ = Profile::Demo.to_lattice();
        let _ = Profile::Full.to_lattice();
        let _ = Profile::Restrictive.to_lattice();
    }

    #[test]
    fn test_list_succeeds() {
        // list() only prints to stdout, verify it returns Ok
        let result = list();
        assert!(result.is_ok());
    }
}

/// List available profiles
pub fn list() -> Result<()> {
    println!("Available Permission Profiles");
    println!("=============================");
    println!();
    println!("  filesystem-readonly  Read + search; blocks sensitive paths");
    println!("  read-only      File reading and search only");
    println!("  network-only   Web access only (no filesystem/exec)");
    println!("  web-research   Read + web search/fetch");
    println!("  code-review    Read + limited web search");
    println!("  edit-only      Write + edit without exec or web");
    println!("  local-dev      Write + shell without web");
    println!("  fix-issue      Write + bash + git commit (no push/PR)");
    println!("  release        Full dev + git push/PR with approvals");
    println!("  database-client  DB CLI only (psql/mysql/redis)");
    println!("  demo           Demo-friendly permissions with approvals");
    println!("  full           Everything enabled (trifecta still enforced!)");
    println!("  restrictive    Minimal permissions (default)");
    println!();
    println!("Usage:");
    println!("  nucleus run --profile fix-issue \"Fix the bug\"");
    println!();
    println!("Note: Even 'full' profile enforces the trifecta constraint.");
    println!("      Exfiltration is blocked when private data + untrusted content");
    println!("      are both accessible.");

    Ok(())
}
