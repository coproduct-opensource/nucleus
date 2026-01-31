//! Path access lattice with allowed/blocked semantics.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Path access lattice with allowed/blocked semantics.
///
/// - `allowed`: Glob patterns for allowed paths. Empty means "all allowed".
/// - `blocked`: Glob patterns for blocked paths. Checked first (takes priority).
/// - `work_dir`: Optional sandbox root. All paths are resolved relative to this.
///
/// # Security
///
/// - All paths are canonicalized to prevent `../../../.env` traversal attacks
/// - Symlinks are resolved and checked against the work_dir sandbox
/// - Paths outside the work_dir are blocked when sandbox is enabled
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PathLattice {
    /// Allowed paths (glob patterns). Empty means "all allowed".
    pub allowed: HashSet<String>,
    /// Blocked paths (glob patterns). Union in meet operation.
    pub blocked: HashSet<String>,
    /// Optional sandbox root directory. When set, all paths must be within this directory.
    #[cfg_attr(feature = "serde", serde(default))]
    pub work_dir: Option<PathBuf>,
}

impl PathLattice {
    /// Create a new path lattice with a sandbox root directory.
    ///
    /// All path operations will be constrained to this directory.
    pub fn with_work_dir(work_dir: impl Into<PathBuf>) -> Self {
        Self {
            work_dir: Some(work_dir.into()),
            ..Default::default()
        }
    }

    /// Meet operation: intersection of allowed, union of blocked.
    ///
    /// The work_dir is taken from the first lattice if set, otherwise from the second.
    /// If both have work_dirs, the more restrictive (shorter prefix) is used.
    pub fn meet(&self, other: &Self) -> Self {
        let allowed = if self.allowed.is_empty() && other.allowed.is_empty() {
            HashSet::new()
        } else if self.allowed.is_empty() {
            other.allowed.clone()
        } else if other.allowed.is_empty() {
            self.allowed.clone()
        } else {
            self.allowed.intersection(&other.allowed).cloned().collect()
        };

        let blocked: HashSet<String> = self.blocked.union(&other.blocked).cloned().collect();

        // For work_dir, use the more restrictive one (if both are set, keep the one
        // that is NOT a parent of the other, or the shorter path)
        let work_dir = match (&self.work_dir, &other.work_dir) {
            (Some(a), Some(b)) => {
                // Use the one that's not a parent of the other, or shorter
                if a.starts_with(b) {
                    Some(a.clone())
                } else {
                    Some(b.clone())
                }
            }
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };

        Self {
            allowed,
            blocked,
            work_dir,
        }
    }

    /// Join operation: union of allowed, intersection of blocked.
    pub fn join(&self, other: &Self) -> Self {
        let allowed: HashSet<String> = self.allowed.union(&other.allowed).cloned().collect();

        let blocked = if self.blocked.is_empty() || other.blocked.is_empty() {
            HashSet::new()
        } else {
            self.blocked.intersection(&other.blocked).cloned().collect()
        };

        // For work_dir, use the less restrictive one (the parent)
        let work_dir = match (&self.work_dir, &other.work_dir) {
            (Some(a), Some(b)) => {
                if a.starts_with(b) {
                    Some(b.clone())
                } else if b.starts_with(a) {
                    Some(a.clone())
                } else {
                    // If neither is a parent, keep the first (arbitrary but deterministic)
                    Some(a.clone())
                }
            }
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };

        Self {
            allowed,
            blocked,
            work_dir,
        }
    }

    /// Normalize a path for security checking.
    ///
    /// This method:
    /// 1. Resolves the path relative to work_dir if set
    /// 2. Canonicalizes to resolve symlinks and `..` components
    /// 3. Verifies the result is within the sandbox (if work_dir is set)
    ///
    /// Returns None if the path escapes the sandbox or cannot be resolved.
    fn normalize_path(&self, path: &Path) -> Option<PathBuf> {
        // Start with the raw path
        let resolved = if path.is_absolute() {
            path.to_path_buf()
        } else if let Some(ref work_dir) = self.work_dir {
            work_dir.join(path)
        } else {
            path.to_path_buf()
        };

        // Try to canonicalize (resolves symlinks and ..)
        // If the file doesn't exist, we fall back to manual normalization
        let canonical = resolved.canonicalize().unwrap_or_else(|_| {
            // Manual normalization for non-existent paths
            normalize_path_components(&resolved)
        });

        // If we have a work_dir, verify the canonical path is within it
        if let Some(ref work_dir) = self.work_dir {
            // First, try to canonicalize the work_dir
            let canonical_work_dir = work_dir
                .canonicalize()
                .unwrap_or_else(|_| normalize_path_components(work_dir));

            // Check if the path starts with the work_dir
            // We need to handle the case where both are normalized but may differ
            // in trailing slashes or path separator normalization
            let canonical_str = canonical.to_string_lossy();
            let work_dir_str = canonical_work_dir.to_string_lossy();

            // Ensure we're checking for a proper directory prefix
            let is_inside = if canonical_str == work_dir_str {
                true
            } else if canonical_str.starts_with(&*work_dir_str) {
                // Make sure it's not just a prefix match (e.g., /tmp/foo vs /tmp/foobar)
                let suffix = &canonical_str[work_dir_str.len()..];
                suffix.starts_with('/') || suffix.starts_with(std::path::MAIN_SEPARATOR)
            } else {
                false
            };

            if !is_inside {
                // Path escapes sandbox
                return None;
            }
        }

        Some(canonical)
    }

    /// Check if a path is accessible according to this lattice.
    ///
    /// # Security
    ///
    /// This method:
    /// 1. Canonicalizes the path to prevent traversal attacks
    /// 2. Checks if the path is within the sandbox (if work_dir is set)
    /// 3. Checks blocked patterns (takes priority)
    /// 4. Checks allowed patterns (if any are set)
    pub fn can_access(&self, path: &Path) -> bool {
        // First, normalize and sandbox-check the path
        let canonical = match self.normalize_path(path) {
            Some(p) => p,
            None => {
                // Path escapes sandbox or cannot be normalized - deny
                return false;
            }
        };

        let path_str = canonical.to_string_lossy();

        // Also check the original path string for patterns like ".env"
        // This catches cases where the pattern is just a filename
        let original_str = path.to_string_lossy();

        // Check blocked patterns first (takes priority)
        for pattern in &self.blocked {
            if glob_match(pattern, &path_str) || glob_match(pattern, &original_str) {
                return false;
            }

            // Also check if any path component matches the pattern
            // This catches ".env" in "foo/.env/bar"
            if path_component_matches(path, pattern) || path_component_matches(&canonical, pattern)
            {
                return false;
            }
        }

        // If allowed is empty, all paths are allowed (that aren't blocked)
        if self.allowed.is_empty() {
            return true;
        }

        // Check if path matches any allowed pattern
        for pattern in &self.allowed {
            if glob_match(pattern, &path_str) || glob_match(pattern, &original_str) {
                return true;
            }
        }

        false
    }

    /// Check if this lattice is less than or equal to another.
    pub fn leq(&self, other: &Self) -> bool {
        let allowed_ok = other.allowed.is_empty() || self.allowed.is_subset(&other.allowed);
        let blocked_ok = other.blocked.is_subset(&self.blocked);
        allowed_ok && blocked_ok
    }

    /// Create a path lattice that blocks sensitive files.
    pub fn block_sensitive() -> Self {
        Self {
            allowed: HashSet::new(),
            blocked: [
                ".env*",
                "*.pem",
                "*.key",
                "**/secrets/**",
                "**/.ssh/**",
                "**/credentials*",
                "**/.aws/**",
                "**/.git/config",
                "**/id_rsa*",
                "**/id_ed25519*",
                "**/.npmrc",
                "**/.pypirc",
                "**/token*",
                "**/password*",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            work_dir: None,
        }
    }

    /// Create a path lattice that blocks sensitive files and sandboxes to a directory.
    pub fn sandboxed_sensitive(work_dir: impl Into<PathBuf>) -> Self {
        let mut lattice = Self::block_sensitive();
        lattice.work_dir = Some(work_dir.into());
        lattice
    }
}

/// Normalize path components without filesystem access.
///
/// Handles `.` and `..` components lexically.
fn normalize_path_components(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();

    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {
                // Skip "."
            }
            _ => {
                result.push(component);
            }
        }
    }

    result
}

/// Check if any path component matches a simple pattern.
///
/// This is a quick check for patterns like ".env" that should match
/// ".env", "foo/.env", ".env.local", etc.
fn path_component_matches(path: &Path, pattern: &str) -> bool {
    // Remove wildcards for component matching
    let base_pattern = pattern
        .trim_start_matches("**/")
        .trim_end_matches("/**")
        .trim_start_matches("*");

    if base_pattern.is_empty() {
        return false;
    }

    // Check each component
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            let name_str = name.to_string_lossy();
            if name_str.starts_with(base_pattern.trim_end_matches('*')) {
                return true;
            }
        }
    }

    false
}

/// Simple glob matching (supports * and ** patterns).
///
/// Pattern syntax:
/// - `*` matches any characters except `/`
/// - `**` matches any characters including `/`
/// - `**/` at the start matches any prefix including empty
/// - `/**` at the end matches any suffix
pub fn glob_match(pattern: &str, path: &str) -> bool {
    if pattern == "**/*" || pattern == "**" {
        return true;
    }

    // Convert glob to regex
    let regex_pattern = glob_to_regex(pattern);

    // Use regex for matching
    regex::Regex::new(&regex_pattern)
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

/// Convert a glob pattern to a regex pattern.
fn glob_to_regex(pattern: &str) -> String {
    let mut regex = String::with_capacity(pattern.len() * 2);
    regex.push('^');

    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next(); // consume second *
                    if chars.peek() == Some(&'/') {
                        chars.next(); // consume /
                                      // **/ matches any prefix including empty
                        regex.push_str("(.*?/)?");
                    } else {
                        // ** at end or before non-/ matches anything
                        regex.push_str(".*");
                    }
                } else {
                    // Single * matches anything except /
                    regex.push_str("[^/]*");
                }
            }
            '?' => regex.push_str("[^/]"),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(c);
            }
            _ => regex.push(c),
        }
    }

    regex.push('$');
    regex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_matching() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(!glob_match("*.rs", "src/main.rs"));
        assert!(glob_match("**/*.rs", "src/main.rs"));
        assert!(glob_match("src/**", "src/foo/bar/baz.rs"));
        assert!(glob_match(".env*", ".env"));
        assert!(glob_match(".env*", ".env.local"));
    }

    #[test]
    fn test_path_lattice_meet() {
        let a = PathLattice {
            allowed: HashSet::new(),
            blocked: ["*.env"].iter().map(|s| s.to_string()).collect(),
            work_dir: None,
        };
        let b = PathLattice {
            allowed: HashSet::new(),
            blocked: ["*.key"].iter().map(|s| s.to_string()).collect(),
            work_dir: None,
        };

        let result = a.meet(&b);
        assert!(result.blocked.contains("*.env"));
        assert!(result.blocked.contains("*.key"));
    }

    #[test]
    fn test_can_access() {
        let lattice = PathLattice::block_sensitive();
        assert!(!lattice.can_access(Path::new(".env")));
        assert!(!lattice.can_access(Path::new("secrets/api.key")));
        assert!(lattice.can_access(Path::new("src/main.rs")));
    }

    // Security: Path traversal tests
    #[test]
    fn test_path_traversal_blocked() {
        let lattice = PathLattice::block_sensitive();

        // These should all be blocked despite traversal attempts
        assert!(!lattice.can_access(Path::new("../../../.env")));
        assert!(!lattice.can_access(Path::new("src/../.env")));
        assert!(!lattice.can_access(Path::new("./subdir/../.env")));
    }

    #[test]
    fn test_sandbox_blocks_escape() {
        // Use a known temp directory that exists and can be canonicalized
        let temp_dir = std::env::temp_dir()
            .canonicalize()
            .expect("temp_dir should exist");
        let lattice = PathLattice::with_work_dir(&temp_dir);

        // Paths within the sandbox should work
        let inside = temp_dir.join("test.txt");
        assert!(
            lattice.can_access(&inside),
            "Path {:?} should be accessible within sandbox {:?}",
            inside,
            temp_dir
        );

        // Paths outside the sandbox should be blocked
        assert!(!lattice.can_access(Path::new("/etc/passwd")));
        assert!(!lattice.can_access(Path::new("/")));
    }

    #[test]
    fn test_sandbox_blocks_traversal_escape() {
        let temp_dir = std::env::temp_dir();
        let lattice = PathLattice::with_work_dir(temp_dir.join("subdir"));

        // Trying to escape via .. should be blocked
        assert!(!lattice.can_access(Path::new("../../etc/passwd")));
        assert!(!lattice.can_access(Path::new("../sibling/file.txt")));
    }

    #[test]
    fn test_path_component_matches() {
        assert!(path_component_matches(Path::new("foo/.env/bar"), ".env"));
        assert!(path_component_matches(Path::new(".env.local"), ".env"));
        assert!(!path_component_matches(Path::new("src/main.rs"), ".env"));
    }

    #[test]
    fn test_join_operation() {
        let a = PathLattice {
            allowed: ["src/**"].iter().map(|s| s.to_string()).collect(),
            blocked: [".env*", "*.key"].iter().map(|s| s.to_string()).collect(),
            work_dir: None,
        };
        let b = PathLattice {
            allowed: ["tests/**"].iter().map(|s| s.to_string()).collect(),
            blocked: [".env*", "*.pem"].iter().map(|s| s.to_string()).collect(),
            work_dir: None,
        };

        let result = a.join(&b);

        // Join: union of allowed
        assert!(result.allowed.contains("src/**"));
        assert!(result.allowed.contains("tests/**"));

        // Join: intersection of blocked
        assert!(result.blocked.contains(".env*"));
        assert!(!result.blocked.contains("*.key"));
        assert!(!result.blocked.contains("*.pem"));
    }

    #[test]
    fn test_normalize_path_components() {
        assert_eq!(
            normalize_path_components(Path::new("/a/b/../c")),
            PathBuf::from("/a/c")
        );
        assert_eq!(
            normalize_path_components(Path::new("/a/./b/c")),
            PathBuf::from("/a/b/c")
        );
        assert_eq!(
            normalize_path_components(Path::new("../a/b")),
            PathBuf::from("a/b")
        );
    }
}
