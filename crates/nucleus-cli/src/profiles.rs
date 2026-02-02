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
