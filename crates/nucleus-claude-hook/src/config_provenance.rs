//! Configuration provenance model (#977).
//!
//! Distinguishes between trusted local config (user's home directory)
//! and repo-supplied config (cloned repository). Repo-supplied configs
//! are labeled as `Adversarial` integrity in the flow graph, preventing
//! them from influencing privileged operations.
//!
//! Also provides Unicode normalization to strip invisible characters
//! (zero-width joiners, bidirectional markers) from config files,
//! preventing the Rules File Backdoor attack.
//!
//! ## CVE references
//! - CVE-2025-59536: Claude Code config injection via .claude/settings.json
//! - CVE-2026-21852: API key exfiltration via project files
//! - Rules File Backdoor: invisible Unicode in .cursor/rules

use std::path::Path;

/// Where a configuration file came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum ConfigProvenance {
    /// User's home directory (~/.claude/, ~/.nucleus/) — trusted.
    UserLocal,
    /// Current working directory (.claude/, .nucleus/) — potentially
    /// attacker-controlled if the repo was cloned from an untrusted source.
    RepoSupplied,
    /// Explicitly provided via CLI flag or env var — trusted.
    Explicit,
}

#[allow(dead_code)]
impl ConfigProvenance {
    /// Determine provenance based on the config file's path.
    pub fn from_path(config_path: &Path) -> Self {
        // If the path is under the user's home directory, it's local.
        if let Some(home) = dirs_next::home_dir() {
            if config_path.starts_with(home.join(".claude"))
                || config_path.starts_with(home.join(".nucleus"))
            {
                return Self::UserLocal;
            }
        }
        // Otherwise, it's repo-supplied (in cwd or a subdirectory).
        Self::RepoSupplied
    }

    /// Whether this config source should be treated as potentially adversarial.
    pub fn is_adversarial(&self) -> bool {
        matches!(self, Self::RepoSupplied)
    }
}

/// Check a configuration string for suspicious invisible Unicode characters.
///
/// Returns a list of (byte_offset, character, description) for each
/// invisible character found. An empty list means the config is clean.
#[allow(dead_code)]
pub(crate) fn detect_invisible_unicode(content: &str) -> Vec<(usize, char, &'static str)> {
    let mut findings = Vec::new();

    for (offset, ch) in content.char_indices() {
        let desc = match ch {
            '\u{200B}' => Some("zero-width space"),
            '\u{200C}' => Some("zero-width non-joiner"),
            '\u{200D}' => Some("zero-width joiner"),
            '\u{200E}' => Some("left-to-right mark"),
            '\u{200F}' => Some("right-to-left mark"),
            '\u{202A}' => Some("left-to-right embedding"),
            '\u{202B}' => Some("right-to-left embedding"),
            '\u{202C}' => Some("pop directional formatting"),
            '\u{202D}' => Some("left-to-right override"),
            '\u{202E}' => Some("right-to-left override"),
            '\u{2060}' => Some("word joiner"),
            '\u{2061}' => Some("function application"),
            '\u{2062}' => Some("invisible times"),
            '\u{2063}' => Some("invisible separator"),
            '\u{2064}' => Some("invisible plus"),
            '\u{FEFF}' => Some("byte order mark (not at start)"),
            '\u{00AD}' => Some("soft hyphen"),
            '\u{034F}' => Some("combining grapheme joiner"),
            _ if ch.is_control() && ch != '\n' && ch != '\r' && ch != '\t' => {
                Some("control character")
            }
            _ => None,
        };

        if let Some(description) = desc {
            // Allow BOM only at byte offset 0.
            if ch == '\u{FEFF}' && offset == 0 {
                continue;
            }
            findings.push((offset, ch, description));
        }
    }

    findings
}

/// Strip all invisible Unicode characters from a string.
#[allow(dead_code)]
pub(crate) fn strip_invisible_unicode(content: &str) -> String {
    let findings = detect_invisible_unicode(content);
    if findings.is_empty() {
        return content.to_string();
    }

    let offsets: std::collections::HashSet<usize> = findings.iter().map(|(o, _, _)| *o).collect();
    content
        .char_indices()
        .filter(|(offset, _)| !offsets.contains(offset))
        .map(|(_, ch)| ch)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_local_config_is_trusted() {
        if let Some(home) = dirs_next::home_dir() {
            let path = home.join(".claude").join("settings.json");
            assert_eq!(
                ConfigProvenance::from_path(&path),
                ConfigProvenance::UserLocal
            );
            assert!(!ConfigProvenance::UserLocal.is_adversarial());
        }
    }

    #[test]
    fn repo_config_is_adversarial() {
        let path = std::path::Path::new("/tmp/project/.claude/settings.json");
        assert_eq!(
            ConfigProvenance::from_path(path),
            ConfigProvenance::RepoSupplied
        );
        assert!(ConfigProvenance::RepoSupplied.is_adversarial());
    }

    #[test]
    fn clean_text_has_no_findings() {
        let findings = detect_invisible_unicode("normal config text\nwith newlines");
        assert!(findings.is_empty());
    }

    #[test]
    fn detects_zero_width_joiner() {
        let evil = "normal\u{200D}text";
        let findings = detect_invisible_unicode(evil);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].2, "zero-width joiner");
    }

    #[test]
    fn detects_bidi_override() {
        let evil = "safe\u{202E}evil";
        let findings = detect_invisible_unicode(evil);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].2, "right-to-left override");
    }

    #[test]
    fn allows_bom_at_start() {
        let with_bom = "\u{FEFF}normal text";
        let findings = detect_invisible_unicode(with_bom);
        assert!(findings.is_empty(), "BOM at start should be allowed");
    }

    #[test]
    fn rejects_bom_in_middle() {
        let evil = "text\u{FEFF}more";
        let findings = detect_invisible_unicode(evil);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn strip_removes_invisible_chars() {
        let evil = "safe\u{200D}\u{200B}text\u{202E}end";
        let cleaned = strip_invisible_unicode(evil);
        assert_eq!(cleaned, "safetextend");
    }

    #[test]
    fn strip_preserves_clean_text() {
        let clean = "normal config text\n";
        assert_eq!(strip_invisible_unicode(clean), clean);
    }
}
