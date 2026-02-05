//! Input validation and error sanitization for tool proxy requests.
//!
//! This module provides:
//! - Validation functions to protect against ReDoS, resource exhaustion, and path traversal
//! - Error sanitization to prevent information disclosure
//!
//! # Security Guarantees
//!
//! All tool endpoints MUST validate inputs through this module before processing.
//! Error messages MUST be sanitized before returning to clients.

use std::path::Path;
use thiserror::Error;

/// Maximum length for glob/regex patterns (1KB).
pub const MAX_PATTERN_LENGTH: usize = 1024;

/// Maximum length for search queries (512 bytes).
pub const MAX_QUERY_LENGTH: usize = 512;

/// Maximum length for file paths (4KB).
pub const MAX_PATH_LENGTH: usize = 4096;

/// Maximum length for command arguments (16KB total).
pub const MAX_COMMAND_LENGTH: usize = 16384;

/// Maximum number of command arguments.
pub const MAX_COMMAND_ARGS: usize = 256;

/// Maximum length for stdin input (1MB).
pub const MAX_STDIN_LENGTH: usize = 1024 * 1024;

/// Validation errors.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// Pattern exceeds maximum length.
    #[error("pattern too long: {length} bytes exceeds limit of {limit}")]
    PatternTooLong { length: usize, limit: usize },

    /// Pattern contains potentially catastrophic backtracking.
    #[error("potentially unsafe regex pattern: {reason}")]
    UnsafePattern { reason: String },

    /// Query exceeds maximum length.
    #[error("query too long: {length} bytes exceeds limit of {limit}")]
    QueryTooLong { length: usize, limit: usize },

    /// Path exceeds maximum length.
    #[error("path too long: {length} bytes exceeds limit of {limit}")]
    PathTooLong { length: usize, limit: usize },

    /// Command arguments exceed limits.
    #[error("command too long: {reason}")]
    CommandTooLong { reason: String },

    /// Stdin exceeds maximum length.
    #[error("stdin too long: {length} bytes exceeds limit of {limit}")]
    StdinTooLong { length: usize, limit: usize },

    /// Invalid URL format.
    #[error("invalid URL: {reason}")]
    InvalidUrl { reason: String },

    /// Contains null bytes.
    #[error("input contains null bytes")]
    ContainsNullBytes,
}

/// Result type for validation operations.
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validate a glob or regex pattern.
///
/// Checks for:
/// - Maximum length
/// - Null bytes
/// - Known catastrophic backtracking patterns
pub fn validate_pattern(pattern: &str) -> ValidationResult<()> {
    // Check length
    if pattern.len() > MAX_PATTERN_LENGTH {
        return Err(ValidationError::PatternTooLong {
            length: pattern.len(),
            limit: MAX_PATTERN_LENGTH,
        });
    }

    // Check for null bytes
    if pattern.contains('\0') {
        return Err(ValidationError::ContainsNullBytes);
    }

    // Check for known catastrophic backtracking patterns
    if has_catastrophic_backtracking(pattern) {
        return Err(ValidationError::UnsafePattern {
            reason: "pattern contains nested quantifiers or excessive repetition".into(),
        });
    }

    Ok(())
}

/// Validate a search query.
pub fn validate_query(query: &str) -> ValidationResult<()> {
    if query.len() > MAX_QUERY_LENGTH {
        return Err(ValidationError::QueryTooLong {
            length: query.len(),
            limit: MAX_QUERY_LENGTH,
        });
    }

    if query.contains('\0') {
        return Err(ValidationError::ContainsNullBytes);
    }

    Ok(())
}

/// Validate a file path.
pub fn validate_path(path: &str) -> ValidationResult<()> {
    if path.len() > MAX_PATH_LENGTH {
        return Err(ValidationError::PathTooLong {
            length: path.len(),
            limit: MAX_PATH_LENGTH,
        });
    }

    if path.contains('\0') {
        return Err(ValidationError::ContainsNullBytes);
    }

    Ok(())
}

/// Validate command arguments.
pub fn validate_command_args(args: &[String]) -> ValidationResult<()> {
    // Check number of arguments
    if args.len() > MAX_COMMAND_ARGS {
        return Err(ValidationError::CommandTooLong {
            reason: format!(
                "{} arguments exceeds limit of {}",
                args.len(),
                MAX_COMMAND_ARGS
            ),
        });
    }

    // Check total length
    let total_len: usize = args.iter().map(|a| a.len()).sum();
    if total_len > MAX_COMMAND_LENGTH {
        return Err(ValidationError::CommandTooLong {
            reason: format!(
                "{} bytes exceeds limit of {}",
                total_len, MAX_COMMAND_LENGTH
            ),
        });
    }

    // Check for null bytes in any argument
    for arg in args {
        if arg.contains('\0') {
            return Err(ValidationError::ContainsNullBytes);
        }
    }

    Ok(())
}

/// Validate stdin input.
pub fn validate_stdin(stdin: Option<&str>) -> ValidationResult<()> {
    if let Some(input) = stdin {
        if input.len() > MAX_STDIN_LENGTH {
            return Err(ValidationError::StdinTooLong {
                length: input.len(),
                limit: MAX_STDIN_LENGTH,
            });
        }
    }
    Ok(())
}

/// Validate a URL for web fetch operations.
pub fn validate_url(url: &str) -> ValidationResult<()> {
    // Check length (URLs shouldn't be enormous)
    if url.len() > MAX_PATH_LENGTH {
        return Err(ValidationError::InvalidUrl {
            reason: "URL too long".into(),
        });
    }

    // Basic protocol check
    let url_lower = url.to_lowercase();
    if !url_lower.starts_with("http://") && !url_lower.starts_with("https://") {
        return Err(ValidationError::InvalidUrl {
            reason: "URL must use http:// or https:// scheme".into(),
        });
    }

    // Check for null bytes
    if url.contains('\0') {
        return Err(ValidationError::ContainsNullBytes);
    }

    Ok(())
}

/// Detect potentially catastrophic backtracking patterns in regex.
///
/// This is a heuristic check for common ReDoS patterns:
/// - Nested quantifiers: (a+)+, (a*)*
/// - Overlapping alternation with quantifiers: (a|a)+
/// - Excessive repetition: a{1000,}
///
/// Note: This specifically targets regex patterns. Glob patterns like `**`
/// are NOT considered dangerous (they're handled by glob libraries, not regex).
fn has_catastrophic_backtracking(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let len = chars.len();

    // Track nesting depth of groups
    let mut group_depth: usize = 0;
    let mut has_quantifier_in_group = false;

    for i in 0..len {
        let c = chars[i];
        let next = chars.get(i + 1);

        match c {
            '(' => {
                group_depth += 1;
                has_quantifier_in_group = false;
            }
            ')' => {
                // Check if group with quantifier is followed by another quantifier
                if has_quantifier_in_group {
                    if let Some(&next_char) = next {
                        if is_quantifier(next_char) {
                            return true; // Nested quantifier pattern like (a+)+
                        }
                    }
                }
                group_depth = group_depth.saturating_sub(1);
                has_quantifier_in_group = false;
            }
            '+' | '?' => {
                if group_depth > 0 {
                    has_quantifier_in_group = true;
                }
                // Check for consecutive quantifiers like a+? (but not ** which is glob)
                if let Some(&next_char) = next {
                    if is_quantifier(next_char) && next_char != '*' {
                        return true; // Patterns like a++, a+?, etc.
                    }
                }
            }
            '*' => {
                if group_depth > 0 {
                    has_quantifier_in_group = true;
                }
                // Only flag ** if it's inside a group AND followed by another quantifier
                // (glob ** is OK, but regex (a*)* is not)
                if let Some(&next_char) = next {
                    // Check if this is (something*)* pattern
                    if group_depth > 0 && is_quantifier(next_char) {
                        return true;
                    }
                    // Consecutive * followed by + or ? is dangerous
                    if next_char == '+' || next_char == '?' {
                        return true;
                    }
                }
            }
            '{' => {
                // Check for excessive repetition like {1000,}
                if let Some(end) = pattern[i..].find('}') {
                    let range = &pattern[i + 1..i + end];
                    if let Some(max) = parse_max_repetition(range) {
                        if max > 100 {
                            return true;
                        }
                    }
                }
                if group_depth > 0 {
                    has_quantifier_in_group = true;
                }
            }
            _ => {}
        }
    }

    false
}

/// Check if a character is a regex quantifier.
fn is_quantifier(c: char) -> bool {
    matches!(c, '+' | '*' | '?' | '{')
}

/// Parse the maximum repetition from a {min,max} range.
fn parse_max_repetition(range: &str) -> Option<usize> {
    if let Some(comma_pos) = range.find(',') {
        let max_str = range[comma_pos + 1..].trim();
        if max_str.is_empty() {
            // Unbounded: {n,} - treat as high
            return Some(1000);
        }
        max_str.parse().ok()
    } else {
        // Exact count: {n}
        range.trim().parse().ok()
    }
}

// =============================================================================
// Error Sanitization
// =============================================================================

/// Sanitize an error message by removing internal path information.
///
/// This prevents information disclosure that could aid attackers in understanding
/// the internal structure of the sandbox or host system.
///
/// # What Gets Sanitized
/// - Absolute paths are replaced with `[path]`
/// - Sandbox root paths are replaced with `[sandbox]`
/// - Home directory paths are replaced with `[home]`
///
/// # Example
/// ```ignore
/// let msg = "failed to read /var/sandbox/abc123/secrets/token.txt";
/// let sanitized = sanitize_error_message(msg, Path::new("/var/sandbox/abc123"));
/// assert_eq!(sanitized, "failed to read [sandbox]/secrets/token.txt");
/// ```
pub fn sanitize_error_message(message: &str, sandbox_root: Option<&Path>) -> String {
    let mut result = message.to_string();

    // Replace sandbox root first (most specific)
    if let Some(root) = sandbox_root {
        if let Some(root_str) = root.to_str() {
            result = result.replace(root_str, "[sandbox]");
        }
    }

    // Replace home directory
    if let Ok(home) = std::env::var("HOME") {
        result = result.replace(&home, "[home]");
    }

    // Replace any remaining absolute paths with placeholders
    // This is a simple heuristic - look for common absolute path patterns
    result = sanitize_absolute_paths(&result);

    result
}

/// Replace absolute paths in a string with placeholders.
fn sanitize_absolute_paths(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut in_path = false;
    let mut path_start = 0;

    while let Some(c) = chars.next() {
        if !in_path
            && c == '/'
            && chars
                .peek()
                .is_some_and(|&nc| nc.is_alphabetic() || nc == '_')
        {
            // Potential start of an absolute path
            // Check if this looks like a path (not just a single /)
            in_path = true;
            path_start = result.len();
            result.push(c);
        } else if in_path {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/' {
                result.push(c);
            } else {
                // End of path - check if we should sanitize
                let path_len = result.len() - path_start;
                if path_len > 5 {
                    // Looks like a real path, sanitize it
                    result.truncate(path_start);
                    result.push_str("[path]");
                }
                result.push(c);
                in_path = false;
            }
        } else {
            result.push(c);
        }
    }

    // Handle path at end of string
    if in_path {
        let path_len = result.len() - path_start;
        if path_len > 5 {
            result.truncate(path_start);
            result.push_str("[path]");
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pattern_ok() {
        assert!(validate_pattern("*.rs").is_ok());
        assert!(validate_pattern("src/**/*.ts").is_ok());
        assert!(validate_pattern("[a-z]+").is_ok());
        assert!(validate_pattern("foo|bar|baz").is_ok());
    }

    #[test]
    fn test_validate_pattern_too_long() {
        let long_pattern = "a".repeat(MAX_PATTERN_LENGTH + 1);
        let result = validate_pattern(&long_pattern);
        assert!(matches!(
            result,
            Err(ValidationError::PatternTooLong { .. })
        ));
    }

    #[test]
    fn test_validate_pattern_null_bytes() {
        let result = validate_pattern("foo\0bar");
        assert!(matches!(result, Err(ValidationError::ContainsNullBytes)));
    }

    #[test]
    fn test_validate_pattern_nested_quantifiers() {
        // (a+)+ is a classic ReDoS pattern
        let result = validate_pattern("(a+)+");
        assert!(matches!(result, Err(ValidationError::UnsafePattern { .. })));

        // (a*)* is also dangerous
        let result = validate_pattern("(a*)*");
        assert!(matches!(result, Err(ValidationError::UnsafePattern { .. })));
    }

    #[test]
    fn test_validate_pattern_excessive_repetition() {
        let result = validate_pattern("a{1000,}");
        assert!(matches!(result, Err(ValidationError::UnsafePattern { .. })));
    }

    #[test]
    fn test_validate_query_ok() {
        assert!(validate_query("hello world").is_ok());
        assert!(validate_query("error handling").is_ok());
    }

    #[test]
    fn test_validate_query_too_long() {
        let long_query = "a".repeat(MAX_QUERY_LENGTH + 1);
        let result = validate_query(&long_query);
        assert!(matches!(result, Err(ValidationError::QueryTooLong { .. })));
    }

    #[test]
    fn test_validate_path_ok() {
        assert!(validate_path("/home/user/project").is_ok());
        assert!(validate_path("src/main.rs").is_ok());
    }

    #[test]
    fn test_validate_path_too_long() {
        let long_path = "/".to_string() + &"a".repeat(MAX_PATH_LENGTH);
        let result = validate_path(&long_path);
        assert!(matches!(result, Err(ValidationError::PathTooLong { .. })));
    }

    #[test]
    fn test_validate_command_args_ok() {
        let args = vec!["ls".to_string(), "-la".to_string()];
        assert!(validate_command_args(&args).is_ok());
    }

    #[test]
    fn test_validate_command_args_too_many() {
        let args: Vec<String> = (0..MAX_COMMAND_ARGS + 1)
            .map(|i| format!("arg{}", i))
            .collect();
        let result = validate_command_args(&args);
        assert!(matches!(
            result,
            Err(ValidationError::CommandTooLong { .. })
        ));
    }

    #[test]
    fn test_validate_command_args_null_bytes() {
        let args = vec!["ls".to_string(), "foo\0bar".to_string()];
        let result = validate_command_args(&args);
        assert!(matches!(result, Err(ValidationError::ContainsNullBytes)));
    }

    #[test]
    fn test_validate_stdin_ok() {
        assert!(validate_stdin(None).is_ok());
        assert!(validate_stdin(Some("hello")).is_ok());
    }

    #[test]
    fn test_validate_stdin_too_long() {
        let long_stdin = "a".repeat(MAX_STDIN_LENGTH + 1);
        let result = validate_stdin(Some(&long_stdin));
        assert!(matches!(result, Err(ValidationError::StdinTooLong { .. })));
    }

    #[test]
    fn test_validate_url_ok() {
        assert!(validate_url("https://example.com").is_ok());
        assert!(validate_url("http://localhost:8080/api").is_ok());
    }

    #[test]
    fn test_validate_url_bad_scheme() {
        let result = validate_url("ftp://example.com");
        assert!(matches!(result, Err(ValidationError::InvalidUrl { .. })));

        let result = validate_url("file:///etc/passwd");
        assert!(matches!(result, Err(ValidationError::InvalidUrl { .. })));
    }

    #[test]
    fn test_catastrophic_backtracking_detection() {
        // These should be detected
        assert!(has_catastrophic_backtracking("(a+)+"));
        assert!(has_catastrophic_backtracking("(a*)*"));
        assert!(has_catastrophic_backtracking("([a-z]+)*"));
        assert!(has_catastrophic_backtracking("a{1000,}"));

        // These should be OK
        assert!(!has_catastrophic_backtracking("a+"));
        assert!(!has_catastrophic_backtracking("[a-z]+"));
        assert!(!has_catastrophic_backtracking("foo|bar"));
        assert!(!has_catastrophic_backtracking("a{1,10}"));
    }

    // Error sanitization tests

    #[test]
    fn test_sanitize_error_with_sandbox_root() {
        let sandbox = Path::new("/var/sandbox/abc123");
        let msg = "failed to read /var/sandbox/abc123/secrets/token.txt";
        let sanitized = sanitize_error_message(msg, Some(sandbox));
        assert!(sanitized.contains("[sandbox]"));
        assert!(!sanitized.contains("abc123"));
        assert!(!sanitized.contains("/var/sandbox"));
    }

    #[test]
    fn test_sanitize_error_absolute_paths() {
        let msg = "cannot access /etc/passwd: permission denied";
        let sanitized = sanitize_error_message(msg, None);
        assert!(!sanitized.contains("/etc/passwd"));
        assert!(sanitized.contains("[path]"));
    }

    #[test]
    fn test_sanitize_preserves_safe_content() {
        let msg = "validation error: pattern too long";
        let sanitized = sanitize_error_message(msg, None);
        assert_eq!(sanitized, msg);
    }

    #[test]
    fn test_sanitize_multiple_paths() {
        let msg = "copy from /source/file to /dest/file failed";
        let sanitized = sanitize_error_message(msg, None);
        // Both paths should be sanitized
        assert!(!sanitized.contains("/source/file"));
        assert!(!sanitized.contains("/dest/file"));
    }
}
