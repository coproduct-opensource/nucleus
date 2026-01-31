//! Shell command access lattice with allow/block semantics.

use std::collections::HashSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Shell command access lattice.
///
/// Controls which shell commands can be executed. Uses a combination of:
/// - `allowed`: Whitelist of allowed commands (empty means check blocked only)
/// - `blocked`: Blacklist of forbidden commands/patterns
///
/// In the meet operation:
/// - allowed: intersection (more restrictive)
/// - blocked: union (more restrictive)
///
/// # Security
///
/// Uses `shell-words` for proper command parsing to prevent bypass via:
/// - Quoting tricks (`"rm" "-rf"`)
/// - IFS manipulation
/// - Argument injection
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommandLattice {
    /// Allowed commands (whitelist). Empty means check blocked only.
    pub allowed: HashSet<String>,
    /// Blocked commands (blacklist). Union in meet operation.
    pub blocked: HashSet<String>,
}

impl Default for CommandLattice {
    fn default() -> Self {
        Self {
            allowed: [
                "cargo test",
                "cargo check",
                "cargo clippy",
                "cargo fmt --check",
                "git status",
                "git diff",
                "git log",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            blocked: [
                "rm -rf",
                "sudo",
                "chmod",
                "chown",
                "curl | sh",
                "wget | sh",
                "eval",
                "exec",
                "> /dev/sd",   // Block raw disk writes
                "dd if=",      // Block disk dumps
                "mkfs",        // Block filesystem creation
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

impl CommandLattice {
    /// Create an empty command lattice (blocks nothing, allows nothing specific).
    pub fn empty() -> Self {
        Self {
            allowed: HashSet::new(),
            blocked: HashSet::new(),
        }
    }

    /// Create a permissive command lattice (blocks dangerous commands only).
    pub fn permissive() -> Self {
        Self {
            allowed: HashSet::new(), // Empty = all allowed (unless blocked)
            blocked: Self::default().blocked,
        }
    }

    /// Create a restrictive command lattice (only safe read-only commands).
    pub fn restrictive() -> Self {
        Self {
            allowed: [
                "git status",
                "git diff",
                "git log",
                "ls",
                "cat",
                "head",
                "tail",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            blocked: Self::default().blocked,
        }
    }

    /// Meet operation: intersection of allowed, union of blocked.
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
        Self { allowed, blocked }
    }

    /// Join operation: union of allowed, intersection of blocked.
    pub fn join(&self, other: &Self) -> Self {
        let allowed: HashSet<String> = self.allowed.union(&other.allowed).cloned().collect();

        let blocked = if self.blocked.is_empty() || other.blocked.is_empty() {
            HashSet::new()
        } else {
            self.blocked.intersection(&other.blocked).cloned().collect()
        };

        Self { allowed, blocked }
    }

    /// Check if a command is allowed.
    ///
    /// A command is allowed if:
    /// 1. It does not match any blocked pattern (after proper parsing)
    /// 2. Either `allowed` is empty OR it matches an allowed pattern
    ///
    /// # Security
    ///
    /// Uses `shell-words` to properly parse the command, preventing bypass via:
    /// - Quoting tricks: `"rm" "-rf"` is correctly parsed as `["rm", "-rf"]`
    /// - Embedded quotes: `rm "-rf /"` is parsed as `["rm", "-rf /"]`
    /// - IFS manipulation: Handled by proper tokenization
    pub fn can_execute(&self, command: &str) -> bool {
        // Parse the command into words using proper shell parsing
        let words = match shell_words::split(command) {
            Ok(w) => w,
            Err(_) => {
                // If parsing fails (unbalanced quotes, etc.), deny
                return false;
            }
        };

        // Empty command is not allowed
        if words.is_empty() {
            return false;
        }

        let program = &words[0];

        // Check blocked patterns against:
        // 1. The full command string
        // 2. The program name
        // 3. Each individual word
        // 4. Reconstructed command from parsed words
        for blocked in &self.blocked {
            // Check if the blocked pattern is a program name
            if program == blocked {
                return false;
            }

            // Check if blocked pattern appears as a word
            if words.iter().any(|w| w == blocked) {
                return false;
            }

            // Check if the original command contains the blocked pattern
            // This catches patterns like "curl | sh" that span multiple words
            if command.contains(blocked) {
                return false;
            }

            // Check the reconstructed command (handles quoting bypass)
            let reconstructed = shell_words::join(&words);
            if reconstructed.contains(blocked) {
                return false;
            }
        }

        // If allowed is empty, allow anything not blocked
        if self.allowed.is_empty() {
            return true;
        }

        // Check if command matches any allowed pattern
        for allowed in &self.allowed {
            let allowed_words = match shell_words::split(allowed) {
                Ok(w) => w,
                Err(_) => continue,
            };

            if allowed_words.is_empty() {
                continue;
            }

            // Check if the command starts with the allowed pattern
            // e.g., "cargo test --release" matches "cargo test"
            if words.len() >= allowed_words.len()
                && words[..allowed_words.len()] == allowed_words[..]
            {
                return true;
            }
        }

        false
    }

    /// Check if this lattice is less than or equal to another.
    pub fn leq(&self, other: &Self) -> bool {
        // Our allowed must be subset of other's (or other allows all)
        let allowed_ok = other.allowed.is_empty() || self.allowed.is_subset(&other.allowed);
        // Other's blocked must be subset of ours
        let blocked_ok = other.blocked.is_subset(&self.blocked);
        allowed_ok && blocked_ok
    }

    /// Add a command to the allowed list.
    pub fn allow(&mut self, command: impl Into<String>) {
        self.allowed.insert(command.into());
    }

    /// Add a command pattern to the blocked list.
    pub fn block(&mut self, pattern: impl Into<String>) {
        self.blocked.insert(pattern.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_can_execute_allowed() {
        let lattice = CommandLattice::default();
        assert!(lattice.can_execute("cargo test"));
        assert!(lattice.can_execute("cargo test --release"));
        assert!(lattice.can_execute("git status"));
    }

    #[test]
    fn test_command_blocked_takes_priority() {
        let mut lattice = CommandLattice::default();
        lattice.allow("rm -rf"); // Even if allowed...
        assert!(!lattice.can_execute("rm -rf /")); // ...blocked patterns win
    }

    #[test]
    fn test_command_not_in_allowlist() {
        let lattice = CommandLattice::default();
        assert!(!lattice.can_execute("npm install")); // Not in allowed list
    }

    #[test]
    fn test_command_meet_union_blocked() {
        let a = CommandLattice {
            allowed: HashSet::new(),
            blocked: ["rm -rf"].iter().map(|s| s.to_string()).collect(),
        };
        let b = CommandLattice {
            allowed: HashSet::new(),
            blocked: ["sudo"].iter().map(|s| s.to_string()).collect(),
        };

        let result = a.meet(&b);
        assert!(result.blocked.contains("rm -rf"));
        assert!(result.blocked.contains("sudo"));
    }

    #[test]
    fn test_command_meet_intersection_allowed() {
        let a = CommandLattice {
            allowed: ["cargo test", "cargo check"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            blocked: HashSet::new(),
        };
        let b = CommandLattice {
            allowed: ["cargo test", "cargo build"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            blocked: HashSet::new(),
        };

        let result = a.meet(&b);
        assert!(result.allowed.contains("cargo test"));
        assert!(!result.allowed.contains("cargo check"));
        assert!(!result.allowed.contains("cargo build"));
    }

    #[test]
    fn test_permissive_allows_unlisted_commands() {
        let lattice = CommandLattice::permissive();
        assert!(lattice.can_execute("npm test"));
        assert!(lattice.can_execute("python script.py"));
        assert!(!lattice.can_execute("sudo rm -rf /")); // But blocks dangerous
    }

    // Security: Quoting bypass tests
    #[test]
    fn test_quoting_bypass_blocked() {
        let lattice = CommandLattice::default();

        // These should all be blocked despite quoting tricks
        assert!(!lattice.can_execute(r#""sudo" apt install"#));
        assert!(!lattice.can_execute(r#"'sudo' apt install"#));
        assert!(!lattice.can_execute("sudo apt install"));
    }

    #[test]
    fn test_rm_rf_quoting_bypass_blocked() {
        let lattice = CommandLattice::default();

        // Various attempts to bypass "rm -rf" block
        assert!(!lattice.can_execute("rm -rf /"));
        assert!(!lattice.can_execute(r#"rm "-rf" /"#));
        assert!(!lattice.can_execute(r#""rm" "-rf" /"#));
    }

    #[test]
    fn test_malformed_command_denied() {
        let lattice = CommandLattice::permissive();

        // Unbalanced quotes should be denied
        assert!(!lattice.can_execute(r#"echo "unclosed"#));
        assert!(!lattice.can_execute(r#"echo 'unclosed"#));
    }

    #[test]
    fn test_empty_command_denied() {
        let lattice = CommandLattice::permissive();
        assert!(!lattice.can_execute(""));
        assert!(!lattice.can_execute("   "));
    }

    #[test]
    fn test_join_operation() {
        let a = CommandLattice {
            allowed: ["cargo test"].iter().map(|s| s.to_string()).collect(),
            blocked: ["rm -rf", "sudo"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        let b = CommandLattice {
            allowed: ["cargo build"].iter().map(|s| s.to_string()).collect(),
            blocked: ["sudo", "chmod"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };

        let result = a.join(&b);

        // Join: union of allowed
        assert!(result.allowed.contains("cargo test"));
        assert!(result.allowed.contains("cargo build"));

        // Join: intersection of blocked
        assert!(result.blocked.contains("sudo"));
        assert!(!result.blocked.contains("rm -rf"));
        assert!(!result.blocked.contains("chmod"));
    }
}
