//! Shell command access lattice with allow/block semantics.

use std::collections::HashSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Shell command access lattice.
///
/// Controls which shell commands can be executed. Uses a combination of:
/// - `allowed`: Whitelist of allowed command strings (empty means check blocked only)
/// - `blocked`: Blacklist of forbidden command strings/patterns
/// - `allowed_rules`: Structured allowlist (program + args)
/// - `blocked_rules`: Structured blocklist (program + args)
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
    /// Structured allowlist rules (program + args).
    #[cfg_attr(feature = "serde", serde(default))]
    pub allowed_rules: Vec<CommandPattern>,
    /// Structured blocklist rules (program + args).
    #[cfg_attr(feature = "serde", serde(default))]
    pub blocked_rules: Vec<CommandPattern>,
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
                "> /dev/sd", // Block raw disk writes
                "dd if=",    // Block disk dumps
                "mkfs",      // Block filesystem creation
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            allowed_rules: Vec::new(),
            blocked_rules: default_blocked_rules(),
        }
    }
}

impl CommandLattice {
    /// Create an empty command lattice (blocks nothing, allows nothing specific).
    pub fn empty() -> Self {
        Self {
            allowed: HashSet::new(),
            blocked: HashSet::new(),
            allowed_rules: Vec::new(),
            blocked_rules: Vec::new(),
        }
    }

    /// Create a permissive command lattice (blocks dangerous commands only).
    pub fn permissive() -> Self {
        Self {
            allowed: HashSet::new(), // Empty = all allowed (unless blocked)
            blocked: Self::default().blocked,
            allowed_rules: Vec::new(),
            blocked_rules: default_blocked_rules(),
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
            allowed_rules: Vec::new(),
            blocked_rules: default_blocked_rules(),
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
        let allowed_rules = meet_allowed_rules(&self.allowed_rules, &other.allowed_rules);
        let blocked_rules = meet_blocked_rules(&self.blocked_rules, &other.blocked_rules);
        Self {
            allowed,
            blocked,
            allowed_rules,
            blocked_rules,
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

        let allowed_rules = join_allowed_rules(&self.allowed_rules, &other.allowed_rules);
        let blocked_rules = join_blocked_rules(&self.blocked_rules, &other.blocked_rules);
        Self {
            allowed,
            blocked,
            allowed_rules,
            blocked_rules,
        }
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

        // Block shell metacharacters unless explicitly allowlisted
        if self.allowed.is_empty()
            && self.allowed_rules.is_empty()
            && contains_shell_metacharacters(&words)
        {
            return false;
        }

        let program = &words[0];

        // Structured blocked rules take precedence
        if self
            .blocked_rules
            .iter()
            .any(|rule| rule_matches(rule, &words))
        {
            return false;
        }

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

            // Check if blocked pattern appears as an in-order subsequence
            if let Ok(blocked_words) = shell_words::split(blocked) {
                if !blocked_words.is_empty() && is_subsequence(&blocked_words, &words) {
                    return false;
                }
            }
        }

        // Structured allowlist rules
        if !self.allowed_rules.is_empty()
            && self
                .allowed_rules
                .iter()
                .any(|rule| rule_matches(rule, &words))
        {
            return true;
        }

        // If allowed is empty, allow anything not blocked
        if self.allowed.is_empty() && self.allowed_rules.is_empty() {
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
        let allowed_rules_ok = other.allowed_rules.is_empty()
            || self
                .allowed_rules
                .iter()
                .all(|rule| other.allowed_rules.contains(rule));
        let blocked_rules_ok = other
            .blocked_rules
            .iter()
            .all(|rule| self.blocked_rules.contains(rule));
        allowed_ok && blocked_ok && allowed_rules_ok && blocked_rules_ok
    }

    /// Add a command to the allowed list.
    pub fn allow(&mut self, command: impl Into<String>) {
        self.allowed.insert(command.into());
    }

    /// Add a command pattern to the blocked list.
    pub fn block(&mut self, pattern: impl Into<String>) {
        self.blocked.insert(pattern.into());
    }

    /// Add a structured rule to the allowlist.
    pub fn allow_rule(&mut self, rule: CommandPattern) {
        self.allowed_rules.push(rule);
    }

    /// Add a structured rule to the blocklist.
    pub fn block_rule(&mut self, rule: CommandPattern) {
        self.blocked_rules.push(rule);
    }
}

/// Structured command rule (program + args).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommandPattern {
    /// Program name (argv[0]).
    pub program: String,
    /// Argument patterns.
    #[cfg_attr(feature = "serde", serde(default))]
    pub args: Vec<ArgPattern>,
}

impl CommandPattern {
    /// Build a command pattern from an exact program and argument sequence.
    pub fn exact(program: impl Into<String>, args: &[impl AsRef<str>]) -> Self {
        Self {
            program: program.into(),
            args: args
                .iter()
                .map(|arg| ArgPattern::Exact(arg.as_ref().to_string()))
                .collect(),
        }
    }
}

/// Structured argument rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ArgPattern {
    /// Exact argument match.
    Exact(String),
    /// Any single argument.
    Any,
    /// Any remaining arguments (zero or more).
    AnyRemaining,
}

fn contains_shell_metacharacters(words: &[String]) -> bool {
    let metachars: HashSet<&str> = ["|", ";", "&&", "||", ">", ">>", "<", "2>", "&>"]
        .into_iter()
        .collect();

    words.iter().any(|w| metachars.contains(w.as_str()))
}

fn default_blocked_rules() -> Vec<CommandPattern> {
    let mut rules = Vec::new();
    for program in ["bash", "sh", "zsh", "fish"] {
        rules.push(CommandPattern {
            program: program.to_string(),
            args: vec![
                ArgPattern::Exact("-c".to_string()),
                ArgPattern::AnyRemaining,
            ],
        });
    }
    for program in ["pwsh", "powershell"] {
        rules.push(CommandPattern {
            program: program.to_string(),
            args: vec![
                ArgPattern::Exact("-Command".to_string()),
                ArgPattern::AnyRemaining,
            ],
        });
    }
    for program in ["python", "python3"] {
        rules.push(CommandPattern {
            program: program.to_string(),
            args: vec![
                ArgPattern::Exact("-c".to_string()),
                ArgPattern::AnyRemaining,
            ],
        });
    }
    rules.push(CommandPattern {
        program: "node".to_string(),
        args: vec![
            ArgPattern::Exact("-e".to_string()),
            ArgPattern::AnyRemaining,
        ],
    });
    rules.push(CommandPattern {
        program: "ruby".to_string(),
        args: vec![
            ArgPattern::Exact("-e".to_string()),
            ArgPattern::AnyRemaining,
        ],
    });
    rules.push(CommandPattern {
        program: "perl".to_string(),
        args: vec![
            ArgPattern::Exact("-e".to_string()),
            ArgPattern::AnyRemaining,
        ],
    });
    rules.push(CommandPattern {
        program: "php".to_string(),
        args: vec![
            ArgPattern::Exact("-r".to_string()),
            ArgPattern::AnyRemaining,
        ],
    });
    // Block gh CLI credential manipulation commands
    rules.push(CommandPattern {
        program: "gh".to_string(),
        args: vec![
            ArgPattern::Exact("auth".to_string()),
            ArgPattern::AnyRemaining,
        ],
    });
    rules.push(CommandPattern {
        program: "gh".to_string(),
        args: vec![
            ArgPattern::Exact("config".to_string()),
            ArgPattern::AnyRemaining,
        ],
    });
    rules
}

fn rule_matches(rule: &CommandPattern, words: &[String]) -> bool {
    if words.is_empty() {
        return false;
    }
    if words[0] != rule.program {
        return false;
    }
    let args = &words[1..];
    let mut idx = 0;
    for pattern in &rule.args {
        match pattern {
            ArgPattern::Exact(expected) => {
                if args.get(idx) != Some(expected) {
                    return false;
                }
                idx += 1;
            }
            ArgPattern::Any => {
                if args.get(idx).is_none() {
                    return false;
                }
                idx += 1;
            }
            ArgPattern::AnyRemaining => {
                return true;
            }
        }
    }
    true
}

fn meet_allowed_rules(a: &[CommandPattern], b: &[CommandPattern]) -> Vec<CommandPattern> {
    if a.is_empty() && b.is_empty() {
        return Vec::new();
    }
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    a.iter().filter(|rule| b.contains(rule)).cloned().collect()
}

fn join_allowed_rules(a: &[CommandPattern], b: &[CommandPattern]) -> Vec<CommandPattern> {
    if a.is_empty() && b.is_empty() {
        return Vec::new();
    }
    if a.is_empty() {
        return b.to_vec();
    }
    if b.is_empty() {
        return a.to_vec();
    }
    let mut rules = a.to_vec();
    for rule in b {
        if !rules.contains(rule) {
            rules.push(rule.clone());
        }
    }
    rules
}

fn meet_blocked_rules(a: &[CommandPattern], b: &[CommandPattern]) -> Vec<CommandPattern> {
    if a.is_empty() && b.is_empty() {
        return Vec::new();
    }
    let mut rules = a.to_vec();
    for rule in b {
        if !rules.contains(rule) {
            rules.push(rule.clone());
        }
    }
    rules
}

fn join_blocked_rules(a: &[CommandPattern], b: &[CommandPattern]) -> Vec<CommandPattern> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    a.iter().filter(|rule| b.contains(rule)).cloned().collect()
}

fn is_subsequence(needle: &[String], haystack: &[String]) -> bool {
    let mut i = 0;
    for word in haystack {
        if i < needle.len() && word == &needle[i] {
            i += 1;
        }
        if i == needle.len() {
            return true;
        }
    }
    false
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
            allowed_rules: Vec::new(),
            blocked_rules: Vec::new(),
        };
        let b = CommandLattice {
            allowed: HashSet::new(),
            blocked: ["sudo"].iter().map(|s| s.to_string()).collect(),
            allowed_rules: Vec::new(),
            blocked_rules: Vec::new(),
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
            allowed_rules: Vec::new(),
            blocked_rules: Vec::new(),
        };
        let b = CommandLattice {
            allowed: ["cargo test", "cargo build"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            blocked: HashSet::new(),
            allowed_rules: Vec::new(),
            blocked_rules: Vec::new(),
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

    #[test]
    fn test_permissive_blocks_shell_metacharacters() {
        let lattice = CommandLattice::permissive();
        assert!(!lattice.can_execute("echo hi | cat"));
        assert!(!lattice.can_execute("echo hi > out.txt"));
        assert!(!lattice.can_execute("echo hi && whoami"));
    }

    #[test]
    fn test_default_blocks_interpreter_flags() {
        let lattice = CommandLattice::default();
        assert!(!lattice.can_execute("bash -c 'echo hi'"));
        assert!(!lattice.can_execute("sh -c 'echo hi'"));
        assert!(!lattice.can_execute("python -c 'print(1)'"));
        assert!(!lattice.can_execute("node -e \"console.log('x')\""));
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
            blocked: ["rm -rf", "sudo"].iter().map(|s| s.to_string()).collect(),
            allowed_rules: Vec::new(),
            blocked_rules: Vec::new(),
        };
        let b = CommandLattice {
            allowed: ["cargo build"].iter().map(|s| s.to_string()).collect(),
            blocked: ["sudo", "chmod"].iter().map(|s| s.to_string()).collect(),
            allowed_rules: Vec::new(),
            blocked_rules: Vec::new(),
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

    #[test]
    fn test_structured_allowlist_rule() {
        let mut lattice = CommandLattice::empty();
        lattice.allow_rule(CommandPattern::exact("cargo", &["test"]));
        assert!(lattice.can_execute("cargo test --release"));
        assert!(!lattice.can_execute("cargo build"));
    }

    #[test]
    fn test_structured_blocklist_rule() {
        let mut lattice = CommandLattice::permissive();
        lattice.block_rule(CommandPattern {
            program: "bash".to_string(),
            args: vec![ArgPattern::AnyRemaining],
        });
        assert!(!lattice.can_execute("bash -c 'echo hi'"));
    }

    #[test]
    fn test_gh_auth_blocked() {
        let lattice = CommandLattice::default();
        // gh auth commands should be blocked (credential manipulation)
        assert!(!lattice.can_execute("gh auth login"));
        assert!(!lattice.can_execute("gh auth logout"));
        assert!(!lattice.can_execute("gh auth status"));
        assert!(!lattice.can_execute("gh auth token"));
    }

    #[test]
    fn test_gh_config_blocked() {
        let lattice = CommandLattice::default();
        // gh config commands should be blocked (credential manipulation)
        assert!(!lattice.can_execute("gh config set git_protocol ssh"));
        assert!(!lattice.can_execute("gh config get git_protocol"));
    }

    #[test]
    fn test_gh_regular_commands_allowed_in_permissive() {
        let lattice = CommandLattice::permissive();
        // Regular gh commands should be allowed in permissive mode
        assert!(lattice.can_execute("gh pr list"));
        assert!(lattice.can_execute("gh issue view 123"));
        assert!(lattice.can_execute("gh pr create --fill"));
        // But auth/config still blocked
        assert!(!lattice.can_execute("gh auth login"));
        assert!(!lattice.can_execute("gh config set editor vim"));
    }
}
