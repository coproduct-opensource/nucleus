//! Parser for Claude Code tool permission patterns like `Bash(curl *)` or `mcp__server__tool`.

/// A parsed tool permission from Claude Code settings.json.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolPermission {
    pub tool: ToolKind,
    pub pattern: Option<String>,
    pub raw: String,
}

/// Known tool categories that map to lattice operations.
#[derive(Debug, Clone, PartialEq)]
pub enum ToolKind {
    Bash,
    Read,
    Write,
    Edit,
    Glob,
    Grep,
    WebSearch,
    WebFetch,
    /// MCP tool: `mcp__<server>__<tool>`
    McpTool {
        server: String,
        tool: String,
    },
    /// Unknown tool name
    Unknown(String),
}

#[allow(dead_code)] // Public API for uninhabitable_state classification
impl ToolKind {
    /// Does this tool provide private data access (exposure leg 1)?
    pub fn is_private_data_access(&self) -> bool {
        matches!(self, ToolKind::Read | ToolKind::Glob | ToolKind::Grep)
    }

    /// Does this tool provide untrusted content exposure (exposure leg 2)?
    pub fn is_untrusted_content(&self) -> bool {
        matches!(self, ToolKind::WebFetch | ToolKind::WebSearch)
    }

    /// Does this tool provide an exfiltration vector (exposure leg 3)?
    pub fn is_exfil_vector(&self) -> bool {
        matches!(self, ToolKind::Bash)
    }
}

/// Parse a tool permission string like `Bash(curl *)` or `mcp__server__tool`.
pub fn parse_tool_permission(s: &str) -> ToolPermission {
    let s = s.trim();

    // Try MCP tool format: mcp__server__tool
    if s.starts_with("mcp__") {
        let parts: Vec<&str> = s.splitn(3, "__").collect();
        if parts.len() >= 3 {
            return ToolPermission {
                tool: ToolKind::McpTool {
                    server: parts[1].to_string(),
                    tool: parts[2].to_string(),
                },
                pattern: None,
                raw: s.to_string(),
            };
        }
    }

    // Try ToolName(pattern) format
    if let Some(paren_pos) = s.find('(') {
        if s.ends_with(')') {
            let tool_name = &s[..paren_pos];
            let pattern = &s[paren_pos + 1..s.len() - 1];
            let tool = match_tool_name(tool_name);
            return ToolPermission {
                tool,
                pattern: if pattern.is_empty() {
                    None
                } else {
                    Some(pattern.to_string())
                },
                raw: s.to_string(),
            };
        }
    }

    // Bare tool name (e.g., just "Bash" or "Read")
    let tool = match_tool_name(s);
    ToolPermission {
        tool,
        pattern: None,
        raw: s.to_string(),
    }
}

fn match_tool_name(name: &str) -> ToolKind {
    match name {
        "Bash" => ToolKind::Bash,
        "Read" => ToolKind::Read,
        "Write" => ToolKind::Write,
        "Edit" | "MultiEdit" => ToolKind::Edit,
        "Glob" | "LS" => ToolKind::Glob,
        "Grep" => ToolKind::Grep,
        "WebSearch" => ToolKind::WebSearch,
        "WebFetch" => ToolKind::WebFetch,
        other => ToolKind::Unknown(other.to_string()),
    }
}

/// Check if a bash pattern is unrestricted (matches everything).
pub fn is_unrestricted_pattern(pattern: Option<&str>) -> bool {
    match pattern {
        None => true, // bare `Bash` with no pattern = unrestricted
        Some("*") => true,
        _ => false,
    }
}

/// Check if a bash pattern targets known exfiltration commands.
pub fn is_exfil_bash_pattern(pattern: &str) -> bool {
    let exfil_commands = [
        "curl",
        "wget",
        "ncat",
        "ssh",
        "scp",
        "rsync",
        "git push",
        "git remote",
    ];
    let lower = pattern.to_lowercase();
    exfil_commands.iter().any(|cmd| {
        // Word-boundary match: the command must appear as a standalone word,
        // not as a substring of another word (e.g. "nc" in "branch")
        if let Some(pos) = lower.find(cmd) {
            let before_ok = pos == 0 || !lower.as_bytes()[pos - 1].is_ascii_alphanumeric();
            let after_pos = pos + cmd.len();
            let after_ok =
                after_pos >= lower.len() || !lower.as_bytes()[after_pos].is_ascii_alphanumeric();
            before_ok && after_ok
        } else {
            false
        }
    })
    // Special case: standalone "nc" (netcat) — must be first token or after whitespace
    || lower.split_whitespace().any(|word| word == "nc")
}

/// Capabilities implied by a bash pattern.
///
/// Unrestricted Bash can do everything — `cat` reads files, `curl` fetches web,
/// `grep` searches, `git push` exfiltrates. Patterned Bash implies a subset.
#[derive(Debug, Clone, Default)]
pub struct BashImpliedCapabilities {
    pub read_files: bool,
    pub glob_search: bool,
    pub grep_search: bool,
    pub web_fetch: bool,
    pub web_search: bool,
    pub git_push: bool,
    pub git_commit: bool,
}

/// Capabilities implied by an MCP tool permission.
#[derive(Debug, Clone, Default)]
pub struct McpImpliedCapabilities {
    pub private_data: bool,
    pub untrusted_content: bool,
    pub exfiltration: bool,
    pub git_push: bool,
    pub create_pr: bool,
}

impl BashImpliedCapabilities {
    /// All capabilities (unrestricted bash).
    pub fn all() -> Self {
        Self {
            read_files: true,
            glob_search: true,
            grep_search: true,
            web_fetch: true,
            web_search: true,
            git_push: true,
            git_commit: true,
        }
    }
}

/// Determine what capabilities a bash permission pattern implies.
///
/// - Unrestricted (bare `Bash` or `Bash(*)`) → all capabilities
/// - `Bash(curl *)` / `Bash(wget *)` → web_fetch
/// - `Bash(cat *)` / `Bash(head *)` / `Bash(tail *)` / `Bash(less *)` → read_files
/// - `Bash(grep *)` / `Bash(rg *)` → grep_search, read_files
/// - `Bash(find *)` / `Bash(ls *)` → glob_search
/// - `Bash(git push *)` → git_push
/// - `Bash(git commit *)` → git_commit
pub fn bash_implied_capabilities(pattern: Option<&str>) -> BashImpliedCapabilities {
    if is_unrestricted_pattern(pattern) {
        return BashImpliedCapabilities::all();
    }

    let mut caps = BashImpliedCapabilities::default();

    if let Some(pat) = pattern {
        let lower = pat.to_lowercase();
        // Extract the first word (command name)
        let first_word = lower.split_whitespace().next().unwrap_or("");

        match first_word {
            "curl" | "wget" | "http" | "fetch" => {
                caps.web_fetch = true;
            }
            "cat" | "head" | "tail" | "less" | "more" | "bat" | "open" => {
                caps.read_files = true;
            }
            "grep" | "rg" | "ag" | "ack" => {
                caps.grep_search = true;
                caps.read_files = true;
            }
            "find" | "ls" | "fd" | "tree" | "exa" | "eza" => {
                caps.glob_search = true;
            }
            "git" => {
                // Check subcommand
                let second = lower.split_whitespace().nth(1).unwrap_or("");
                match second {
                    "push" => caps.git_push = true,
                    "commit" => caps.git_commit = true,
                    _ => {}
                }
            }
            "ssh" | "scp" | "rsync" | "nc" | "ncat" => {
                // Network exfil tools — imply web_fetch (network access)
                caps.web_fetch = true;
            }
            _ => {}
        }
    }

    caps
}

/// Determine what capabilities an MCP tool permission implies.
///
/// This is a conservative heuristic over `mcp__<server>__<tool>` names.
pub fn mcp_implied_capabilities(server: &str, tool: &str) -> McpImpliedCapabilities {
    let server = server.to_lowercase();
    let tool = tool.to_lowercase();

    let server_has = |patterns: &[&str]| patterns.iter().any(|p| server.contains(p));
    let tool_has = |patterns: &[&str]| patterns.iter().any(|p| tool.contains(p));

    let private_server = server_has(&[
        "filesystem",
        "file",
        "fs",
        "git",
        "github",
        "gitlab",
        "bitbucket",
        "postgres",
        "mysql",
        "sqlite",
        "mongodb",
        "database",
        "db",
        "s3",
        "aws",
        "gcp",
        "azure",
        "memory",
    ]);
    let untrusted_server = server_has(&[
        "browser",
        "playwright",
        "puppeteer",
        "web",
        "search",
        "fetch",
        "crawl",
        "scrape",
        "http",
    ]);
    let exfil_server = server_has(&[
        "github",
        "gitlab",
        "bitbucket",
        "slack",
        "discord",
        "teams",
        "smtp",
        "mail",
        "http",
        "webhook",
    ]);

    let private_tool = tool_has(&["read", "list", "query", "search", "get", "fetch"]);
    let untrusted_tool = tool_has(&["search", "fetch", "crawl", "scrape", "navigate"]);
    let exfil_tool = tool_has(&[
        "create_pr",
        "pull_request",
        "push",
        "publish",
        "upload",
        "send",
        "post",
        "comment",
        "message",
        "webhook",
        "write_remote",
    ]);

    McpImpliedCapabilities {
        private_data: private_server || private_tool,
        untrusted_content: untrusted_server || untrusted_tool,
        exfiltration: exfil_server || exfil_tool,
        git_push: tool_has(&["git_push", "push"]),
        create_pr: tool_has(&["create_pr", "pull_request"]),
    }
}

/// Check if a read pattern targets known sensitive paths.
pub fn is_sensitive_path_pattern(pattern: &str) -> bool {
    let sensitive = [
        ".env",
        ".aws",
        ".ssh",
        ".gnupg",
        "credentials",
        "secret",
        "private_key",
        "id_rsa",
        ".claude",
    ];
    let lower = pattern.to_lowercase();
    sensitive.iter().any(|s| lower.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bash_with_pattern() {
        let p = parse_tool_permission("Bash(curl *)");
        assert_eq!(p.tool, ToolKind::Bash);
        assert_eq!(p.pattern.as_deref(), Some("curl *"));
    }

    #[test]
    fn test_parse_bare_tool() {
        let p = parse_tool_permission("Read");
        assert_eq!(p.tool, ToolKind::Read);
        assert_eq!(p.pattern, None);
    }

    #[test]
    fn test_parse_mcp_tool() {
        let p = parse_tool_permission("mcp__github__create_pr");
        assert_eq!(
            p.tool,
            ToolKind::McpTool {
                server: "github".to_string(),
                tool: "create_pr".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_tool_with_path_pattern() {
        let p = parse_tool_permission("Write(/workspaces/**)");
        assert_eq!(p.tool, ToolKind::Write);
        assert_eq!(p.pattern.as_deref(), Some("/workspaces/**"));
    }

    #[test]
    fn test_parse_unknown_tool() {
        let p = parse_tool_permission("Agent");
        assert_eq!(p.tool, ToolKind::Unknown("Agent".to_string()));
    }

    #[test]
    fn test_unrestricted_pattern() {
        assert!(is_unrestricted_pattern(None));
        assert!(is_unrestricted_pattern(Some("*")));
        assert!(!is_unrestricted_pattern(Some("curl *")));
    }

    #[test]
    fn test_exfil_detection() {
        assert!(is_exfil_bash_pattern("curl *"));
        assert!(is_exfil_bash_pattern("wget https://evil.com"));
        assert!(is_exfil_bash_pattern("git push *"));
        assert!(is_exfil_bash_pattern("nc 10.0.0.1 4444"));
        assert!(is_exfil_bash_pattern("ssh user@host"));
        assert!(!is_exfil_bash_pattern("cargo test"));
        assert!(!is_exfil_bash_pattern("npm run *"));
        // "nc" must not match as substring of "branch", "sync", etc.
        assert!(!is_exfil_bash_pattern("git branch *"));
        assert!(!is_exfil_bash_pattern("sync data"));
    }

    #[test]
    fn test_sensitive_path() {
        assert!(is_sensitive_path_pattern(".env"));
        assert!(is_sensitive_path_pattern("~/.aws/**"));
        assert!(is_sensitive_path_pattern("~/.ssh/id_rsa"));
        assert!(!is_sensitive_path_pattern("/workspaces/**"));
    }

    #[test]
    fn test_bash_implied_capabilities_unrestricted() {
        let caps = bash_implied_capabilities(None);
        assert!(caps.read_files);
        assert!(caps.glob_search);
        assert!(caps.grep_search);
        assert!(caps.web_fetch);
        assert!(caps.web_search);
        assert!(caps.git_push);
        assert!(caps.git_commit);

        // Same for wildcard
        let caps2 = bash_implied_capabilities(Some("*"));
        assert!(caps2.read_files);
        assert!(caps2.web_fetch);
    }

    #[test]
    fn test_bash_implied_capabilities_patterned() {
        // curl → web_fetch only
        let caps = bash_implied_capabilities(Some("curl *"));
        assert!(caps.web_fetch);
        assert!(!caps.read_files);
        assert!(!caps.grep_search);

        // cat → read_files only
        let caps = bash_implied_capabilities(Some("cat /tmp/foo"));
        assert!(caps.read_files);
        assert!(!caps.web_fetch);

        // grep → grep_search + read_files
        let caps = bash_implied_capabilities(Some("grep pattern *"));
        assert!(caps.grep_search);
        assert!(caps.read_files);
        assert!(!caps.web_fetch);

        // find → glob_search only
        let caps = bash_implied_capabilities(Some("find . -name '*.rs'"));
        assert!(caps.glob_search);
        assert!(!caps.read_files);

        // git push → git_push only
        let caps = bash_implied_capabilities(Some("git push origin main"));
        assert!(caps.git_push);
        assert!(!caps.git_commit);

        // git commit → git_commit only
        let caps = bash_implied_capabilities(Some("git commit -m 'msg'"));
        assert!(caps.git_commit);
        assert!(!caps.git_push);

        // cargo test → nothing extra
        let caps = bash_implied_capabilities(Some("cargo test"));
        assert!(!caps.read_files);
        assert!(!caps.web_fetch);
        assert!(!caps.git_push);
    }

    #[test]
    fn test_uninhabitable_classification() {
        assert!(ToolKind::Read.is_private_data_access());
        assert!(ToolKind::Grep.is_private_data_access());
        assert!(!ToolKind::Bash.is_private_data_access());

        assert!(ToolKind::WebFetch.is_untrusted_content());
        assert!(ToolKind::WebSearch.is_untrusted_content());
        assert!(!ToolKind::Read.is_untrusted_content());

        assert!(ToolKind::Bash.is_exfil_vector());
        assert!(!ToolKind::Read.is_exfil_vector());
    }

    #[test]
    fn test_mcp_implied_capabilities_github_create_pr() {
        let caps = mcp_implied_capabilities("github", "create_pr");
        assert!(caps.private_data);
        assert!(caps.exfiltration);
        assert!(caps.create_pr);
    }

    #[test]
    fn test_mcp_implied_capabilities_browser_navigation() {
        let caps = mcp_implied_capabilities("playwright", "navigate");
        assert!(caps.untrusted_content);
        assert!(!caps.create_pr);
    }
}
