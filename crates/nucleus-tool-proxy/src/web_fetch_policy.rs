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
#[cfg_attr(not(feature = "mcp"), allow(dead_code))]
pub fn validate_url(url: &str) -> Result<(), String> {
    validation::validate_url(url).map_err(|e| format!("validation error: {e}"))
}

/// Check a host:port against the DNS allowlist.
/// Returns Ok(()) if allowed, Err with message if blocked.
///
/// Handles IPv6 bracket notation: `[::1]:8080` splits on `]:` not `:`.
pub fn check_dns_allowlist(dns_allow: &[String], host: &str, port: u16) -> Result<(), String> {
    if dns_allow.is_empty() {
        return Ok(());
    }

    let host_port = format!("{host}:{port}");

    let allowed = dns_allow.iter().any(|pattern| {
        match split_host_port(pattern) {
            Some((pat_host, pat_port)) => {
                // Pattern has an explicit port — match both host and port
                pat_host == host && pat_port == port.to_string()
            }
            None => {
                // Pattern is host-only — allow any port
                pattern == host
            }
        }
    });

    if allowed {
        Ok(())
    } else {
        Err(host_port)
    }
}

/// Split a pattern into (host, port), handling IPv6 bracket notation.
/// - `"github.com:443"` → `Some(("github.com", "443"))`
/// - `"[::1]:8080"` → `Some(("[::1]", "8080"))`
/// - `"github.com"` → `None`
/// - `"[::1]"` → `None`
fn split_host_port(pattern: &str) -> Option<(&str, &str)> {
    if pattern.starts_with('[') {
        // IPv6 bracket notation: split on `]:`
        pattern
            .find("]:")
            .map(|i| (&pattern[..=i], &pattern[i + 2..]))
    } else {
        // IPv4/hostname: split on last `:`
        pattern.rsplit_once(':')
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

/// Resolve the effective web_fetch response cap.
///
/// The pod's `network.max_response_bytes` overrides the proxy's configured
/// default (`--web-fetch-max-bytes`); an absent or unrepresentable override
/// falls back to that default. Kept pure so the override's precedence is
/// unit-tested rather than trusted at the construction site.
pub fn resolve_max_response_bytes(spec_override: Option<u64>, configured_default: usize) -> usize {
    spec_override
        .and_then(|b| usize::try_from(b).ok())
        .unwrap_or(configured_default)
}

/// Every web_fetch enforcement input resolved from the PodSpec's `network`
/// section, in one place so the construction site does not thread four fields
/// by hand (and so a new one lands here, not scattered).
pub struct WebFetchConfig {
    pub dns_allow: Vec<String>,
    pub url_allow: Vec<String>,
    /// Per-pod MIME allowlist override; `None` keeps the built-in list.
    pub mime_allow: Option<Vec<String>>,
    /// Effective response cap: the pod's override or `configured_default`.
    pub max_bytes: usize,
}

/// Resolve the web_fetch config from a pod's optional `network` spec. The two
/// allowlists default to empty (open) when absent; the two overrides fall back
/// to the built-in list / the configured cap.
pub fn resolve_web_fetch_config(
    network: Option<&nucleus_spec::NetworkSpec>,
    configured_default_max_bytes: usize,
) -> WebFetchConfig {
    WebFetchConfig {
        dns_allow: network.map(|n| n.dns_allow.clone()).unwrap_or_default(),
        url_allow: network.map(|n| n.url_allow.clone()).unwrap_or_default(),
        mime_allow: network.and_then(|n| n.mime_allow.clone()),
        max_bytes: resolve_max_response_bytes(
            network.and_then(|n| n.max_response_bytes),
            configured_default_max_bytes,
        ),
    }
}

/// Check if a response's Content-Type is in the allowed MIME type list.
/// Empty content types are allowed (server didn't specify).
///
/// `allow_override` is the pod's `network.mime_allow`: when `Some`, its prefixes
/// REPLACE the built-in [`ALLOWED_MIME_PREFIXES`]; when `None`, the built-in
/// list applies. An empty override list therefore denies every non-empty
/// content type, which is the operator explicitly narrowing the surface.
pub fn check_mime_type(
    content_type: &str,
    allow_override: Option<&[String]>,
) -> Result<(), String> {
    if content_type.is_empty() {
        return Ok(());
    }

    let allowed = match allow_override {
        Some(prefixes) => prefixes
            .iter()
            .any(|prefix| content_type.starts_with(prefix.as_str())),
        None => ALLOWED_MIME_PREFIXES
            .iter()
            .any(|prefix| content_type.starts_with(prefix)),
    };

    if allowed {
        Ok(())
    } else {
        Err(format!(
            "MIME type '{}' not in allowlist (text and structured data only)",
            content_type
        ))
    }
}

/// Whether a redirect hop to `url` may be followed under the pod's egress
/// policy — the SAME `dns_allow` + `url_allow` the initial request is checked
/// against.
///
/// This is the fix for the SSRF/exfil vector: reqwest follows redirects by
/// default, and checking only the initial and final URL lets an allowlisted
/// host `302` the fetch through an INTERMEDIATE host the policy never
/// authorized (attacker data in the redirect URL reaches it before any content
/// check). Every hop is now gated by this, so a redirect that escapes the
/// allowlist is refused before the request is sent. Empty allowlists mean
/// "open", matching the initial-request semantics.
pub fn redirect_hop_allowed(dns_allow: &[String], url_allow: &[String], url: &url::Url) -> bool {
    let host = url.host_str().unwrap_or("");
    let port = url.port_or_known_default().unwrap_or(443);
    check_dns_allowlist(dns_allow, host, port).is_ok()
        && check_url_allowlist(url_allow, url.as_str()).is_ok()
}

/// Build the web_fetch HTTP client with a redirect policy that re-checks EVERY
/// hop against the pod's `dns_allow`/`url_allow` (via [`redirect_hop_allowed`]).
/// A redirect escaping the allowlist fails the request; the chain is bounded to
/// 10 hops as defense in depth. This is the SSRF/exfil fix — without it reqwest
/// follows redirects by default and only the first and last URL are validated.
pub fn build_web_fetch_client(
    timeout: std::time::Duration,
    dns_allow: Vec<String>,
    url_allow: Vec<String>,
) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent("nucleus-tool-proxy/0.1")
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.error("too many redirects");
            }
            let target = attempt.url().clone();
            if redirect_hop_allowed(&dns_allow, &url_allow, &target) {
                attempt.follow()
            } else {
                attempt.error(format!(
                    "redirect to {target} is blocked by the pod's egress policy"
                ))
            }
        }))
        .build()
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

/// Read an HTTP response body while STRICTLY bounding peak retained allocation to
/// `max_bytes` (+ at most one upstream chunk), independent of the upstream's
/// Content-Length or true size. Streams via `chunk()` and STOPS at the cap, so a
/// malicious upstream cannot OOM-kill the tool-proxy (the enforcement point) —
/// the untrusted-content fail-open of audit H-1. Returns `(body, truncated)`;
/// `truncated` is true iff the upstream had more than `max_bytes` (the surplus is
/// never accumulated).
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<(Vec<u8>, bool), reqwest::Error> {
    let mut buf: Vec<u8> = Vec::new();
    while buf.len() < max_bytes {
        match resp.chunk().await? {
            Some(chunk) => {
                let remaining = max_bytes - buf.len();
                if chunk.len() > remaining {
                    buf.extend_from_slice(&chunk[..remaining]);
                    return Ok((buf, true)); // hit the cap mid-chunk; stop reading
                }
                buf.extend_from_slice(&chunk);
            }
            None => return Ok((buf, false)), // upstream ended within the cap
        }
    }
    // Exactly at the cap: peek one more chunk to set the truncation flag. The
    // surplus chunk is read into reqwest's buffer and immediately dropped — peak
    // retained allocation stays at `max_bytes`.
    let truncated = resp.chunk().await?.is_some();
    Ok((buf, truncated))
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
    fn test_dns_allowlist_ipv6_host_only() {
        let allow = vec!["[::1]".to_string()];
        assert!(check_dns_allowlist(&allow, "[::1]", 443).is_ok());
        assert!(check_dns_allowlist(&allow, "[::1]", 8080).is_ok());
        assert!(check_dns_allowlist(&allow, "[::2]", 443).is_err());
    }

    #[test]
    fn test_dns_allowlist_ipv6_with_port() {
        let allow = vec!["[::1]:8080".to_string()];
        assert!(check_dns_allowlist(&allow, "[::1]", 8080).is_ok());
        assert!(check_dns_allowlist(&allow, "[::1]", 443).is_err());
    }

    #[test]
    fn test_split_host_port() {
        assert_eq!(
            split_host_port("github.com:443"),
            Some(("github.com", "443"))
        );
        assert_eq!(split_host_port("github.com"), None);
        assert_eq!(split_host_port("[::1]:8080"), Some(("[::1]", "8080")));
        assert_eq!(split_host_port("[::1]"), None);
        assert_eq!(
            split_host_port("[2001:db8::1]:443"),
            Some(("[2001:db8::1]", "443"))
        );
    }

    #[test]
    fn test_mime_allowed() {
        assert!(check_mime_type("text/html; charset=utf-8", None).is_ok());
        assert!(check_mime_type("application/json", None).is_ok());
        assert!(check_mime_type("", None).is_ok());
    }

    #[test]
    fn test_mime_blocked() {
        assert!(check_mime_type("application/octet-stream", None).is_err());
        assert!(check_mime_type("image/png", None).is_err());
        assert!(check_mime_type("application/zip", None).is_err());
    }

    /// **The per-pod override actually bites.** A `network.mime_allow` of
    /// `["image/"]` must ADMIT `image/png` (which the built-in list blocks) and
    /// REJECT `text/html` (which the built-in list allows) — proving the
    /// override replaces the built-in set rather than adding to it. Before this
    /// was wired, the field was parsed and silently ignored.
    #[test]
    fn a_pod_mime_override_replaces_the_builtin_list() {
        let override_list = vec!["image/".to_string()];
        assert!(check_mime_type("image/png", Some(&override_list)).is_ok());
        assert!(
            check_mime_type("text/html", Some(&override_list)).is_err(),
            "an override must REPLACE the built-in allowlist, not extend it"
        );
    }

    /// An empty override is the operator narrowing to nothing: every non-empty
    /// content type is refused, but an empty content type still passes (the
    /// server-didn't-say case is orthogonal to the allowlist).
    #[test]
    fn an_empty_mime_override_denies_everything_typed() {
        let empty: Vec<String> = vec![];
        assert!(check_mime_type("application/json", Some(&empty)).is_err());
        assert!(check_mime_type("", Some(&empty)).is_ok());
    }

    /// **The per-pod response cap actually overrides the default.** A spec
    /// value wins over the configured default; absence falls back to it. Before
    /// this was wired, `network.max_response_bytes` was parsed and ignored and
    /// the CLI cap always applied.
    #[test]
    fn a_pod_response_cap_overrides_the_configured_default() {
        assert_eq!(
            resolve_max_response_bytes(Some(1024), 5 * 1024 * 1024),
            1024
        );
        assert_eq!(
            resolve_max_response_bytes(None, 5 * 1024 * 1024),
            5 * 1024 * 1024,
            "absent override must fall back to the configured cap"
        );
    }

    /// **The redirect-hop gate refuses an escape from the allowlist.** An
    /// allowlisted host that 302s to a non-allowlisted host must be blocked
    /// before the intermediate request is sent — the SSRF/exfil vector.
    #[test]
    fn a_redirect_hop_outside_the_allowlist_is_refused() {
        let url_allow = vec!["https://docs.rs/*".to_string()];
        let dns_allow = vec!["docs.rs".to_string()];
        let evil = url::Url::parse("https://evil.example/steal?data=secret").unwrap();
        assert!(
            !redirect_hop_allowed(&dns_allow, &url_allow, &evil),
            "a redirect to a host outside the allowlist must not be followed"
        );
        let metadata = url::Url::parse("http://169.254.169.254/latest/meta-data/").unwrap();
        assert!(!redirect_hop_allowed(&dns_allow, &url_allow, &metadata));
    }

    /// A redirect that STAYS inside the allowlist is still followed — the gate
    /// tightens escapes, it does not break legitimate same-policy redirects.
    #[test]
    fn a_redirect_hop_inside_the_allowlist_is_followed() {
        // `**` spans path separators; `*` does not (see url_glob_match).
        let url_allow = vec!["https://docs.rs/**".to_string()];
        let dns_allow = vec!["docs.rs".to_string()];
        let ok = url::Url::parse("https://docs.rs/crate/serde/latest").unwrap();
        assert!(redirect_hop_allowed(&dns_allow, &url_allow, &ok));
    }

    /// Empty allowlists mean "open" — a pod with no egress policy follows
    /// redirects anywhere, matching how its initial request is unrestricted.
    #[test]
    fn empty_allowlists_permit_any_redirect_hop() {
        let any = url::Url::parse("https://anywhere.example/x").unwrap();
        assert!(redirect_hop_allowed(&[], &[], &any));
    }
}
