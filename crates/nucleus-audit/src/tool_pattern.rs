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

#[allow(dead_code)] // Public API for trifecta classification
impl ToolKind {
    /// Does this tool provide private data access (trifecta leg 1)?
    pub fn is_private_data_access(&self) -> bool {
        matches!(self, ToolKind::Read | ToolKind::Glob | ToolKind::Grep)
    }

    /// Does this tool provide untrusted content exposure (trifecta leg 2)?
    pub fn is_untrusted_content(&self) -> bool {
        matches!(self, ToolKind::WebFetch | ToolKind::WebSearch)
    }

    /// Does this tool provide an exfiltration vector (trifecta leg 3)?
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
        "nc",
        "ncat",
        "ssh",
        "scp",
        "rsync",
        "git push",
        "git remote",
    ];
    let lower = pattern.to_lowercase();
    exfil_commands.iter().any(|cmd| lower.contains(cmd))
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
        assert!(!is_exfil_bash_pattern("cargo test"));
        assert!(!is_exfil_bash_pattern("npm run *"));
    }

    #[test]
    fn test_sensitive_path() {
        assert!(is_sensitive_path_pattern(".env"));
        assert!(is_sensitive_path_pattern("~/.aws/**"));
        assert!(is_sensitive_path_pattern("~/.ssh/id_rsa"));
        assert!(!is_sensitive_path_pattern("/workspaces/**"));
    }

    #[test]
    fn test_trifecta_classification() {
        assert!(ToolKind::Read.is_private_data_access());
        assert!(ToolKind::Grep.is_private_data_access());
        assert!(!ToolKind::Bash.is_private_data_access());

        assert!(ToolKind::WebFetch.is_untrusted_content());
        assert!(ToolKind::WebSearch.is_untrusted_content());
        assert!(!ToolKind::Read.is_untrusted_content());

        assert!(ToolKind::Bash.is_exfil_vector());
        assert!(!ToolKind::Read.is_exfil_vector());
    }
}
