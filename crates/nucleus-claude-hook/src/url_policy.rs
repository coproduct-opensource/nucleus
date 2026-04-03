//! Covert channel detection in URL construction (#979).
//!
//! When the session contains Secret-labeled data, outbound URLs are
//! inspected for suspiciously long query strings that could encode
//! exfiltrated data (the Slack AI / IDEsaster attack pattern).

/// Check a URL for potential covert channel exfiltration (#979).
///
/// Returns `Some(reason)` if the URL is suspicious, `None` if clean.
pub(crate) fn check_url_exfiltration(url: &str, session_has_secrets: bool) -> Option<String> {
    if !session_has_secrets {
        return None; // No secrets to exfiltrate
    }

    // Parse query string length.
    let query_start = url.find('?').unwrap_or(url.len());
    let query = &url[query_start..];

    // Flag 1: Suspiciously long query string (>200 chars) when secrets exist.
    if query.len() > 200 {
        return Some(format!(
            "URL query string is {} bytes — possible data exfiltration in query params. \
             Session contains Secret-labeled data.",
            query.len()
        ));
    }

    // Flag 2: Base64-like patterns in query params (encoded data).
    if query.len() > 50 {
        let base64_chars = query
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
            .count();
        let ratio = base64_chars as f64 / query.len() as f64;
        if ratio > 0.85 {
            return Some(format!(
                "URL query contains {:.0}% base64-like characters — possible encoded exfiltration",
                ratio * 100.0
            ));
        }
    }

    // Flag 3: Known exfiltration patterns.
    let suspicious_params = ["data=", "payload=", "exfil=", "d=", "q="];
    for param in &suspicious_params {
        if let Some(idx) = query.find(param) {
            let value_start = idx + param.len();
            let value_end = query[value_start..]
                .find('&')
                .map(|i| value_start + i)
                .unwrap_or(query.len());
            let value_len = value_end - value_start;
            if value_len > 100 {
                return Some(format!(
                    "URL param '{}' has {} byte value — possible data exfiltration",
                    param.trim_end_matches('='),
                    value_len
                ));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_url_passes() {
        assert!(check_url_exfiltration("https://api.example.com/data?page=1", true).is_none());
    }

    #[test]
    fn no_secrets_always_passes() {
        let long_url = format!("https://evil.com/log?data={}", "A".repeat(300));
        assert!(check_url_exfiltration(&long_url, false).is_none());
    }

    #[test]
    fn long_query_flagged() {
        let long_url = format!("https://evil.com/log?data={}", "A".repeat(300));
        let result = check_url_exfiltration(&long_url, true);
        assert!(result.is_some());
        assert!(result.unwrap().contains("exfiltration"));
    }

    #[test]
    fn base64_flagged() {
        let b64_url =
            "https://evil.com/log?d=aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw==";
        let result = check_url_exfiltration(b64_url, true);
        assert!(result.is_some());
    }

    #[test]
    fn normal_api_passes() {
        assert!(check_url_exfiltration(
            "https://api.sec.gov/LATEST/search?q=AAPL&forms=10-K",
            true
        )
        .is_none());
    }
}
