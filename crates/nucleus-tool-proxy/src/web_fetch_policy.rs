//! Shared web_fetch security controls for HTTP and MCP paths.
//!
//! Enforces: URL validation, DNS allowlist, URL allowlist, MIME type gating,
//! and redirect safety. Both the HTTP API and MCP server call these functions
//! to ensure identical security enforcement.

use crate::validation;

/// MIME types allowed for web_fetch responses.
/// Binary formats (images, executables, archives) are blocked to prevent
/// content injection and reduce the agent's attack surface.
pub const ALLOWED_MIME_PREFIXES: &[&str] = &[
    "text/html",
    "text/plain",
    "text/markdown",
    "text/csv",
    "text/xml",
    "text/css",
    "application/json",
    "application/xml",
    "application/javascript",
    "application/typescript",
    "application/x-yaml",
    "application/yaml",
    "application/toml",
];

/// Validate a URL for web_fetch (length, scheme, null bytes).
pub fn validate_url(url: &str) -> Result<(), String> {
    validation::validate_url(url).map_err(|e| format!("validation error: {e}"))
}

/// Check a host:port against the DNS allowlist.
/// Returns Ok(()) if allowed, Err with message if blocked.
pub fn check_dns_allowlist(dns_allow: &[String], host: &str, port: u16) -> Result<(), String> {
    if dns_allow.is_empty() {
        return Ok(());
    }

    let host_port = format!("{host}:{port}");

    let allowed = dns_allow.iter().any(|pattern| {
        if let Some((pat_host, pat_port)) = pattern.rsplit_once(':') {
            // Pattern has an explicit port — match both host and port
            pat_host == host && pat_port == port.to_string()
        } else {
            // Pattern is host-only — allow any port
            pattern == host
        }
    });

    if allowed {
        Ok(())
    } else {
        Err(format!("DNS not allowed: {host_port}"))
    }
}

/// Check a URL against the URL allowlist (glob-style patterns).
/// Returns Ok(()) if allowed or list is empty, Err if blocked.
pub fn check_url_allowlist(url_allow: &[String], url: &str) -> Result<(), String> {
    if url_allow.is_empty() {
        return Ok(());
    }

    let allowed = url_allow
        .iter()
        .any(|pattern| crate::url_glob_match(pattern, url));

    if allowed {
        Ok(())
    } else {
        Err(format!("URL '{}' not in url_allow list", url))
    }
}

/// Check if a response's Content-Type is in the allowed MIME type list.
/// Empty content types are allowed (server didn't specify).
pub fn check_mime_type(content_type: &str) -> Result<(), String> {
    if content_type.is_empty() {
        return Ok(());
    }

    if ALLOWED_MIME_PREFIXES
        .iter()
        .any(|prefix| content_type.starts_with(prefix))
    {
        Ok(())
    } else {
        Err(format!(
            "MIME type '{}' not in allowlist (text and structured data only)",
            content_type
        ))
    }
}

/// Validate the final URL after redirects against the DNS allowlist.
/// This prevents open-redirect bypass attacks where an allowlisted domain
/// redirects to a non-allowlisted domain.
pub fn check_redirect_target(
    dns_allow: &[String],
    url_allow: &[String],
    final_url: &url::Url,
) -> Result<(), String> {
    if let Some(host) = final_url.host_str() {
        let port = final_url.port_or_known_default().unwrap_or(443);
        check_dns_allowlist(dns_allow, host, port)?;
    }
    check_url_allowlist(url_allow, final_url.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_allowlist_host_only() {
        let allow = vec!["github.com".to_string()];
        assert!(check_dns_allowlist(&allow, "github.com", 443).is_ok());
        assert!(check_dns_allowlist(&allow, "github.com", 8080).is_ok());
        assert!(check_dns_allowlist(&allow, "evil.com", 443).is_err());
    }

    #[test]
    fn test_dns_allowlist_host_port() {
        let allow = vec!["github.com:443".to_string()];
        assert!(check_dns_allowlist(&allow, "github.com", 443).is_ok());
        assert!(check_dns_allowlist(&allow, "github.com", 8080).is_err());
    }

    #[test]
    fn test_dns_allowlist_empty() {
        assert!(check_dns_allowlist(&[], "anything.com", 443).is_ok());
    }

    #[test]
    fn test_mime_allowed() {
        assert!(check_mime_type("text/html; charset=utf-8").is_ok());
        assert!(check_mime_type("application/json").is_ok());
        assert!(check_mime_type("").is_ok());
    }

    #[test]
    fn test_mime_blocked() {
        assert!(check_mime_type("application/octet-stream").is_err());
        assert!(check_mime_type("image/png").is_err());
        assert!(check_mime_type("application/zip").is_err());
    }
}
