//! Built-in permission profiles

use anyhow::Result;
use lattice_guard::PermissionLattice;

/// Built-in permission profiles
pub enum Profile {
    /// Read-only: file reading and search only
    ReadOnly,
    /// Code review: read + limited web search
    CodeReview,
    /// Fix issue: write + bash + git commit (no push/PR)
    FixIssue,
    /// Full access: everything enabled (trifecta still enforced)
    Full,
    /// Restrictive: minimal permissions
    Restrictive,
}

impl Profile {
    /// Get profile by name
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "read-only" | "readonly" => Some(Self::ReadOnly),
            "code-review" | "codereview" | "review" => Some(Self::CodeReview),
            "fix-issue" | "fixissue" | "fix" => Some(Self::FixIssue),
            "full" | "permissive" => Some(Self::Full),
            "restrictive" | "minimal" => Some(Self::Restrictive),
            _ => None,
        }
    }

    /// Convert to a PermissionLattice
    pub fn to_lattice(&self) -> PermissionLattice {
        match self {
            Self::ReadOnly => PermissionLattice::read_only(),
            Self::CodeReview => PermissionLattice::code_review(),
            Self::FixIssue => PermissionLattice::fix_issue(),
            Self::Full => PermissionLattice::permissive(),
            Self::Restrictive => PermissionLattice::restrictive(),
        }
    }

    /// Get all profile names
    #[allow(dead_code)]
    pub fn all_names() -> &'static [&'static str] {
        &[
            "read-only",
            "code-review",
            "fix-issue",
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
    println!("  read-only      File reading and search only");
    println!("  code-review    Read + limited web search");
    println!("  fix-issue      Write + bash + git commit (no push/PR)");
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
