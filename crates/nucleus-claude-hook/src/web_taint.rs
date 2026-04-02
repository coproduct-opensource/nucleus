//! Web content taint detection and warning (#838).
//!
//! When a PostToolUse result comes from a web-fetching tool (WebFetch,
//! WebSearch, or MCP tools classified as web-fetching), this module:
//!
//! 1. Detects the taint via `detect_web_taint()`
//! 2. Generates a stderr warning via `web_taint_warning()`
//! 3. Sets `web_tainted` in session state so the NEXT PreToolUse can
//!    inject `additionalContext` informing the model about untrusted data.
//!
//! The Claude Code hook protocol's PostToolUse is observe-only — we cannot
//! modify the tool result. Instead we use stderr for user-visible warnings
//! and session state + additionalContext for model-visible provenance.
//!
//! The additionalContext injection itself lives in `context.rs` (#850) —
//! this module only handles detection and the operator-facing warning.

use portcullis::Operation;

use crate::classify::map_tool;

// ---------------------------------------------------------------------------
// Web taint detection
// ---------------------------------------------------------------------------

/// Returns `true` if the named tool fetches content from the web.
///
/// Matches:
/// - Built-in `WebFetch` and `WebSearch`
/// - MCP tools whose Operation maps to `WebFetch` or `WebSearch`
///   (i.e., tools with "fetch", "download", "http", "url", "browse" in name)
pub(crate) fn detect_web_taint(tool_name: &str) -> bool {
    matches!(
        map_tool(tool_name),
        Operation::WebFetch | Operation::WebSearch
    )
}

// ---------------------------------------------------------------------------
// Warning generation
// ---------------------------------------------------------------------------

/// Generate a colored stderr warning for the user when web content enters
/// the session context.
///
/// The warning uses ANSI yellow and includes the tool name plus a truncated
/// preview of the result, so the operator can see what data just arrived.
pub(crate) fn web_taint_warning(tool_name: &str, result_preview: &str) -> String {
    let preview = if result_preview.len() > 120 {
        // Truncate at a valid UTF-8 boundary
        let mut end = 117;
        while end > 0 && !result_preview.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &result_preview[..end])
    } else {
        result_preview.to_string()
    };
    format!(
        "\x1b[33mnucleus: \u{26a0}\u{fe0f} WEB CONTENT \u{2014} tool '{}' returned untrusted data \
         (NoAuthority, Adversarial)\x1b[0m\n  preview: {}",
        tool_name, preview
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_web_taint_builtin_tools() {
        assert!(detect_web_taint("WebFetch"));
        assert!(detect_web_taint("WebSearch"));
    }

    #[test]
    fn test_detect_web_taint_non_web_tools() {
        assert!(!detect_web_taint("Read"));
        assert!(!detect_web_taint("Write"));
        assert!(!detect_web_taint("Edit"));
        assert!(!detect_web_taint("Bash"));
        assert!(!detect_web_taint("Glob"));
        assert!(!detect_web_taint("Grep"));
        assert!(!detect_web_taint("Agent"));
    }

    #[test]
    fn test_detect_web_taint_mcp_web_tools() {
        // MCP tools classified as web-fetching by name heuristic
        assert!(detect_web_taint("mcp__server__fetch_page"));
        assert!(detect_web_taint("mcp__browser__download_file"));
        assert!(detect_web_taint("mcp__api__http_get"));
        assert!(detect_web_taint("mcp__scraper__browse_url"));
    }

    #[test]
    fn test_detect_web_taint_mcp_non_web_tools() {
        assert!(!detect_web_taint("mcp__github__create_issue"));
        assert!(!detect_web_taint("mcp__db__read_table"));
    }

    #[test]
    fn test_web_taint_warning_short_preview() {
        let warning = web_taint_warning("WebFetch", "Hello world");
        assert!(warning.contains("WEB CONTENT"));
        assert!(warning.contains("WebFetch"));
        assert!(warning.contains("NoAuthority"));
        assert!(warning.contains("Adversarial"));
        assert!(warning.contains("Hello world"));
    }

    #[test]
    fn test_web_taint_warning_long_preview_truncated() {
        let long = "x".repeat(200);
        let warning = web_taint_warning("WebSearch", &long);
        assert!(warning.contains("..."));
        // Should not contain the full 200 chars
        assert!(warning.len() < 350);
    }

    #[test]
    fn test_web_taint_warning_unicode_boundary() {
        // Ensure truncation doesn't split multi-byte characters
        let s = "\u{1F600}".repeat(50); // 50 x 4-byte emoji = 200 bytes
        let warning = web_taint_warning("WebFetch", &s);
        assert!(warning.contains("..."));
        // Result should be valid UTF-8
        assert!(std::str::from_utf8(warning.as_bytes()).is_ok());
    }
}
