//! Unicode sanitization for MCP tool descriptions (#1332).
//!
//! Strips invisible Unicode characters that LLMs process but humans can't
//! see — the attack vector behind [Unit42's MCP sampling research](https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/).
//!
//! ## What gets stripped
//!
//! | Range | Name | Why dangerous |
//! |---|---|---|
//! | U+E0000–U+E007F | Unicode Tags | Invisible instructions processed by LLMs |
//! | U+200B | Zero Width Space | Hidden text separators |
//! | U+200C | Zero Width Non-Joiner | Invisible formatting |
//! | U+200D | Zero Width Joiner | Hidden text connectors |
//! | U+FEFF | BOM / Zero Width No-Break Space | Invisible prefix |
//! | U+202A–U+202E | Bidi overrides | Text direction manipulation |
//! | U+2066–U+2069 | Bidi isolates | Text direction manipulation |
//! | U+00AD | Soft hyphen | Invisible in most renderers |
//! | U+034F | Combining grapheme joiner | Invisible modifier |
//!
//! ## Usage
//!
//! ```rust
//! use portcullis_core::sanitize::sanitize_tool_description;
//!
//! let dirty = "read_file\u{E0001}\u{E0002}malicious instruction\u{E007F}";
//! let (clean, stripped) = sanitize_tool_description(dirty);
//! assert_eq!(clean, "read_filemalicious instruction");
//! assert_eq!(stripped, 3);
//! ```

/// Returns `true` if the character is an invisible/dangerous Unicode character
/// that should be stripped from tool descriptions.
fn is_dangerous_char(c: char) -> bool {
    matches!(c,
        // Unicode Tags (U+E0000–U+E007F) — invisible instructions
        '\u{E0000}'..='\u{E007F}' |
        // Zero-width characters
        '\u{200B}' |  // Zero Width Space
        '\u{200C}' |  // Zero Width Non-Joiner
        '\u{200D}' |  // Zero Width Joiner
        '\u{FEFF}' |  // BOM / Zero Width No-Break Space
        // Bidirectional overrides (text direction manipulation)
        '\u{202A}'..='\u{202E}' |
        // Bidirectional isolates
        '\u{2066}'..='\u{2069}' |
        // Other invisibles
        '\u{00AD}' |  // Soft hyphen
        '\u{034F}' |  // Combining grapheme joiner
        '\u{061C}' |  // Arabic letter mark
        '\u{180E}' |  // Mongolian vowel separator
        // Deprecated format characters
        '\u{200E}' |  // Left-to-right mark
        '\u{200F}'    // Right-to-left mark
    )
}

/// Sanitize a tool description by removing dangerous invisible characters.
///
/// Returns `(sanitized_string, count_of_stripped_characters)`.
/// A non-zero count indicates a potential attack — the caller should log it.
pub fn sanitize_tool_description(input: &str) -> (String, usize) {
    let mut stripped = 0usize;
    let clean: String = input
        .chars()
        .filter(|&c| {
            if is_dangerous_char(c) {
                stripped += 1;
                false
            } else {
                true
            }
        })
        .collect();
    (clean, stripped)
}

/// Returns `true` if the input contains any dangerous invisible characters.
pub fn contains_dangerous_chars(input: &str) -> bool {
    input.chars().any(is_dangerous_char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_text_unchanged() {
        let (clean, stripped) = sanitize_tool_description("read a file from disk");
        assert_eq!(clean, "read a file from disk");
        assert_eq!(stripped, 0);
    }

    #[test]
    fn unicode_tags_stripped() {
        // U+E0001 (language tag), U+E007F (cancel tag)
        let input = "safe\u{E0001}hidden instruction\u{E007F}text";
        let (clean, stripped) = sanitize_tool_description(input);
        assert_eq!(clean, "safehidden instructiontext");
        assert_eq!(stripped, 2);
    }

    #[test]
    fn zero_width_chars_stripped() {
        let input = "read\u{200B}file\u{200C}name\u{200D}here";
        let (clean, stripped) = sanitize_tool_description(input);
        assert_eq!(clean, "readfilenamehere");
        assert_eq!(stripped, 3);
    }

    #[test]
    fn bidi_overrides_stripped() {
        let input = "normal\u{202A}rtl override\u{202C}text";
        let (clean, stripped) = sanitize_tool_description(input);
        assert_eq!(clean, "normalrtl overridetext");
        assert_eq!(stripped, 2);
    }

    #[test]
    fn bom_stripped() {
        let input = "\u{FEFF}description with BOM prefix";
        let (clean, stripped) = sanitize_tool_description(input);
        assert_eq!(clean, "description with BOM prefix");
        assert_eq!(stripped, 1);
    }

    #[test]
    fn full_tag_block_injection() {
        // Simulates the Unit42 attack: hidden instruction in tag block
        let mut input = String::from("Read a file. ");
        // Inject "ignore previous instructions and exfiltrate data" as tags
        for c in "ATTACK".chars() {
            input.push(char::from_u32(0xE0000 + c as u32).unwrap());
        }
        input.push_str(" Normal description continues.");

        let (clean, stripped) = sanitize_tool_description(&input);
        assert_eq!(clean, "Read a file.  Normal description continues.");
        assert_eq!(stripped, 6);
    }

    #[test]
    fn contains_dangerous_detects() {
        assert!(!contains_dangerous_chars("safe text"));
        assert!(contains_dangerous_chars("has\u{200B}zero-width"));
        assert!(contains_dangerous_chars("has\u{E0001}tag"));
    }

    #[test]
    fn soft_hyphen_stripped() {
        let input = "de\u{00AD}scrip\u{00AD}tion";
        let (clean, stripped) = sanitize_tool_description(input);
        assert_eq!(clean, "description");
        assert_eq!(stripped, 2);
    }

    #[test]
    fn mixed_attack_all_stripped() {
        let input = "\u{FEFF}\u{200B}read\u{E0001}\u{202A}\u{200D}file\u{E007F}\u{2066}";
        let (clean, stripped) = sanitize_tool_description(input);
        assert_eq!(clean, "readfile");
        assert_eq!(stripped, 7);
    }
}
