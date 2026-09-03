//! Matching a URL against the `url_allow` patterns.
//!
//! Extracted from `main.rs` to stay under the line ratchet, and because this
//! is a coherent unit on its own: it is the one place that decides whether an
//! outbound URL is on the allowlist, and it is worth being able to read that
//! decision without the rest of the proxy around it.

/// Simple URL glob matcher for `url_allow` patterns.
///
/// - `*` matches any sequence of characters except `/`
/// - `**` matches any sequence of characters including `/`
/// - All other characters match literally.
pub(crate) fn url_glob_match(pattern: &str, url: &str) -> bool {
    // A URL carrying a control character never matches, whatever the pattern
    // says. `*` matches any non-`/` byte, INCLUDING a NUL, so
    // `https://*.google.com/**` happily matches
    // `https://attacker.com\0.google.com/x` -- the host an allowlist is meant to
    // refuse. Verified against this matcher before the guard was added.
    //
    // Today `validate_url` rejects NUL first, so the allowlist is not currently
    // bypassable. That makes ONE check load-bearing for a property the matcher
    // should hold on its own: reorder the calls, add a caller that skips
    // validation, or relax that rule, and the allowlist silently opens. This is
    // the shape of the SOCKS5 hostname NUL-injection disclosed against another
    // agent runtime in 2026, where `attacker.com\0.google.com` passed an
    // `endsWith` allowlist and `getaddrinfo` then truncated at the NUL.
    //
    // Failing closed here costs nothing: no legitimate URL contains a control
    // character.
    if url.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    url_glob_match_inner(pattern.as_bytes(), url.as_bytes())
}

fn url_glob_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern.len() >= 2 && pattern[0] == b'*' && pattern[1] == b'*' {
        // `**` — match any number of chars (including `/`)
        let rest = &pattern[2..];
        for i in 0..=text.len() {
            if url_glob_match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if pattern[0] == b'*' {
        // `*` — match any number of non-`/` chars
        let rest = &pattern[1..];
        for i in 0..=text.len() {
            if i > 0 && text[i - 1] == b'/' {
                break;
            }
            if url_glob_match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    if pattern[0] == text[0] {
        return url_glob_match_inner(&pattern[1..], &text[1..]);
    }
    false
}
#[cfg(test)]
mod allowlist_control_char_tests {
    use super::*;

    /// The bypass shape: a NUL-forged host that a `*` segment happily swallows.
    ///
    /// `*` matches any non-`/` byte, so `https://*.google.com/**` matched
    /// `https://attacker.com\0.google.com/x` before this guard — the exact host
    /// an allowlist exists to refuse. Named after the 2026 SOCKS5 hostname
    /// NUL-injection, where a resolver truncated at the NUL after an `endsWith`
    /// allowlist had already approved the string.
    #[test]
    fn a_nul_forged_host_does_not_match_an_allowlist_pattern() {
        assert!(!url_glob_match(
            "https://*.google.com/**",
            "https://attacker.com\u{0}.google.com/x"
        ));
    }

    /// Every control byte, not just NUL. CR and LF matter independently: they
    /// are the request-splitting characters, and a matcher that blessed a URL
    /// containing them would be approving something no HTTP client should send.
    #[test]
    fn no_control_character_can_appear_in_a_matched_url() {
        for c in ['\u{0}', '\r', '\n', '\t', '\u{1}', '\u{7f}'] {
            let url = format!("https://good.example.com/{c}x");
            assert!(
                !url_glob_match("https://good.example.com/**", &url),
                "control byte {:?} must not appear in a matched URL",
                c
            );
        }
    }

    /// Non-vacuity, and the reason this guard is safe: ordinary URLs still
    /// match. Without this, "return false always" would satisfy both tests
    /// above and would break every allowlist in the product.
    #[test]
    fn ordinary_urls_still_match_their_patterns() {
        assert!(url_glob_match(
            "https://*.google.com/**",
            "https://api.google.com/v1/x"
        ));
        assert!(url_glob_match(
            "https://example.com/**",
            "https://example.com/a/b"
        ));
        // And a genuinely different host is still refused, with no trickery.
        assert!(!url_glob_match(
            "https://*.google.com/**",
            "https://attacker.com/x"
        ));
    }
}
