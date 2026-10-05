//! How a workload is told about its credentialed upstreams, written once.
//!
//! # Two writers, one spelling
//!
//! The tool-proxy WRITES `NUCLEUS_EGRESS_<NAME>_URL` into the workload's
//! environment: the workload door's `unix://` URL followed by the upstream's
//! egress route. `nucleus-egress-http`, which runs as the workload, READS that
//! variable to learn which upstreams the pod declared, and then OVERWRITES it
//! for the command it manages with the loopback `http://` URL an ordinary HTTP
//! client can dial. If each of the three spelled the key or the route itself,
//! the first to disagree would make a declared upstream look undeclared, or
//! the reverse, far from the cause (ADR 0007 G-1). So the key and the route are
//! functions here, and every party calls them.
//!
//! # What is never here
//!
//! A credential, or anything naming one. These are names and local addresses;
//! the credential stays on the host, which performs the call.

/// The door route every credentialed call is made on, up to the upstream
/// name: `/v1/egress/<name>/<path>`.
pub const ROUTE_PREFIX: &str = "/v1/egress/";

/// The environment variable a workload finds upstream `name`'s URL in:
/// `NUCLEUS_EGRESS_<NAME>_URL`, upper-cased, `-` read as `_`.
#[must_use]
pub fn url_env(name: &str) -> String {
    format!(
        "NUCLEUS_EGRESS_{}_URL",
        name.to_uppercase().replace('-', "_")
    )
}

/// The URL the runtime gives the workload for upstream `name`, under the
/// endpoint `base` (the door's `unix://` URL, or a loopback `http://` origin):
/// `<base>/v1/egress/<name>`.
#[must_use]
pub fn upstream_url(base: &str, name: &str) -> String {
    format!("{}{ROUTE_PREFIX}{name}", base.trim_end_matches('/'))
}

// ── What a call may carry besides its path (#3210) ─────────────────────────
//
// The guest's adapter, the tool-proxy that composes the host frame, and the
// host that performs the call all apply these. One copy, here, for the reason
// `CredentialedEgressSpec::url_for` gives for the path: two copies are two
// chances to fix a hole in one of them only.

/// Longest query a call may carry, in bytes.
pub const MAX_QUERY_BYTES: usize = 1024;

/// Most request headers a call may propose.
pub const MAX_PROPOSED_HEADERS: usize = 16;

/// Longest proposed header value, in bytes.
pub const MAX_HEADER_VALUE_BYTES: usize = 1024;

/// Why a query was refused. Each is named: the query is the workload's own
/// input, so telling it what was wrong reveals nothing it did not send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryRefusal {
    /// `?` with nothing after it. Send no query instead.
    Empty,
    /// Longer than [`MAX_QUERY_BYTES`].
    TooLong {
        /// Its length.
        bytes: usize,
    },
    /// A byte outside the query alphabet (space, `#`, `?`, a control or
    /// non-ASCII byte).
    Character,
    /// A parameter name that is empty or is not a plain token (no escapes):
    /// names are what the credential check reads, so they may not hide.
    Name,
    /// A parameter whose name looks like it carries a credential.
    CredentialParameter {
        /// The parameter's name, as sent.
        name: String,
    },
}

impl std::fmt::Display for QueryRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "the query is empty; send none instead"),
            Self::TooLong { bytes } => write!(
                f,
                "the query is {bytes} bytes, above the {MAX_QUERY_BYTES}-byte bound"
            ),
            Self::Character => write!(
                f,
                "the query contains a byte outside the allowed set (visible ASCII, no space, \
                 `#` or `?`)"
            ),
            Self::Name => write!(
                f,
                "a query parameter name is empty or not a plain token (letters, digits, `-`, \
                 `_`, `.`)"
            ),
            Self::CredentialParameter { name } => write!(
                f,
                "query parameter {name:?} looks like it carries a credential; the host injects \
                 the credential, and the workload may not send one"
            ),
        }
    }
}

impl std::error::Error for QueryRefusal {}

/// Whether `query` (without its `?`) may be sent to an upstream.
///
/// # What this is for
///
/// The host injects the credential in a header the operator fixed. A query is
/// a second place a credential can ride, and the one the workload controls:
/// a workload that has learnt a token (from a file, a previous reply, a
/// misconfigured tool) could attach it as `?access_token=…` and have the host
/// deliver it, or authenticate as someone other than the injected identity.
/// Refusing credential-shaped parameter NAMES closes that without the host
/// having to recognise values it cannot know.
///
/// # Refused, not stripped
///
/// As for the path: a stripped parameter changes what the request means
/// without telling the workload, and a sanitiser is a parser the workload gets
/// unlimited attempts at. So a refusal names the parameter.
///
/// # Errors
/// The first rule `query` breaks; see [`QueryRefusal`].
pub fn check_query(query: &str) -> Result<(), QueryRefusal> {
    if query.is_empty() {
        return Err(QueryRefusal::Empty);
    }
    if query.len() > MAX_QUERY_BYTES {
        return Err(QueryRefusal::TooLong { bytes: query.len() });
    }
    if !query
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'#' && b != b'?')
    {
        return Err(QueryRefusal::Character);
    }
    for pair in query.split('&') {
        let name = pair.split_once('=').map_or(pair, |(name, _)| name);
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Err(QueryRefusal::Name);
        }
        if names_a_credential(name) {
            return Err(QueryRefusal::CredentialParameter {
                name: name.to_string(),
            });
        }
    }
    Ok(())
}

/// Names that are a credential, matched whole, ignoring case and `-`/`_`.
const CREDENTIAL_NAMES: &[&str] = &[
    "key",
    "sig",
    "code",
    "auth",
    "authorization",
    "jwt",
    "bearer",
    "assertion",
    "clientassertion",
    "pwd",
];

/// Fragments that make any name a credential, ignoring case and `-`/`_`.
const CREDENTIAL_FRAGMENTS: &[&str] = &[
    "token",
    "secret",
    "passw",
    "credential",
    "apikey",
    "signature",
    "session",
    "cookie",
];

/// Whether `name` looks like it carries a credential: a whole-name match
/// against [`CREDENTIAL_NAMES`] or any of [`CREDENTIAL_FRAGMENTS`], with case
/// and the `-`/`_` separators ignored, so `Access-Token` and `ACCESSTOKEN`
/// are one name.
#[must_use]
pub fn names_a_credential(name: &str) -> bool {
    let folded: String = name
        .chars()
        .filter(|c| *c != '-' && *c != '_')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    CREDENTIAL_NAMES.contains(&folded.as_str())
        || CREDENTIAL_FRAGMENTS.iter().any(|f| folded.contains(f))
}

/// Header names a guest may never propose, whatever the operator allows.
///
/// The credential headers, which the host alone sets; the framing and hop
/// headers, which the host's HTTP client owns; `content-type`, which travels
/// in its own field; and the forwarding headers that would let a request
/// claim to come from somewhere else.
const NEVER_PROPOSED: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "host",
    "content-type",
    "content-length",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "te",
    "trailer",
    "expect",
    "forwarded",
    "via",
];

/// Prefixes no proposed header name may have.
const NEVER_PROPOSED_PREFIXES: &[&str] = &["proxy-", "x-forwarded-", "x-nucleus-", "sec-"];

/// Whether a guest may propose request header `name` at all.
///
/// Necessary, not sufficient: the host forwards a proposal only when the
/// operator's registry also lists the name for that upstream, and the
/// registry refuses to list a name this rejects. `name` must already be
/// lower-case, as HTTP/2 spells every header and as the frame carries them.
#[must_use]
pub fn guest_may_propose_header(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !NEVER_PROPOSED.contains(&name)
        && !NEVER_PROPOSED_PREFIXES.iter().any(|p| name.starts_with(p))
        && !names_a_credential(name)
}

/// Whether `value` may be sent as a proposed header's value: visible ASCII and
/// spaces, at most [`MAX_HEADER_VALUE_BYTES`].
#[must_use]
pub fn header_value_admissible(value: &str) -> bool {
    value.len() <= MAX_HEADER_VALUE_BYTES && value.bytes().all(|b| (0x20..0x7f).contains(&b))
}

impl crate::CredentialedEgressSpec {
    /// [`Self::url_for`] with a query: the path under the FIXED base, then
    /// `?query` when one is given and [`check_query`] admits it.
    ///
    /// `None` for anything either rule refuses. The host and the guest both
    /// resolve through this, so a query the guest let through and the host
    /// would refuse cannot exist.
    #[must_use]
    pub fn url_for_request(&self, path: &str, query: Option<&str>) -> Option<String> {
        let url = self.url_for(path)?;
        match query {
            None => Some(url),
            Some(query) => {
                check_query(query).ok()?;
                Some(format!("{url}?{query}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_and_the_url_are_spelled_as_the_runtime_has_always_spelled_them() {
        assert_eq!(url_env("model-api"), "NUCLEUS_EGRESS_MODEL_API_URL");
        assert_eq!(
            upstream_url("unix:///run/nucleus-door/workload.sock", "model-api"),
            "unix:///run/nucleus-door/workload.sock/v1/egress/model-api"
        );
        assert_eq!(
            upstream_url("http://127.0.0.1:9/", "git"),
            "http://127.0.0.1:9/v1/egress/git"
        );
    }

    fn spec() -> crate::CredentialedEgressSpec {
        crate::CredentialedEgressSpec {
            name: "git-remote".into(),
            upstream: "https://forge.invalid/".into(),
            credential_env: "NUCLEUS_TEST_EGRESS_CRED".into(),
            header: "authorization".into(),
            value_prefix: "Basic ".into(),
        }
    }

    /// A smart-HTTP ref advertisement's query passes, and lands after the
    /// fixed base and the path.
    #[test]
    fn an_ordinary_query_is_appended_under_the_fixed_base() {
        assert_eq!(
            spec()
                .url_for_request("org/repo.git/info/refs", Some("service=git-upload-pack"))
                .as_deref(),
            Some("https://forge.invalid/org/repo.git/info/refs?service=git-upload-pack")
        );
        assert_eq!(
            spec().url_for_request("v1/x", None).as_deref(),
            Some("https://forge.invalid/v1/x")
        );
        for ok in [
            "a=1&b=2",
            "page=2&per_page=50",
            "q=x%20y",
            "flag",
            "ref=refs/heads/main",
        ] {
            assert_eq!(check_query(ok), Ok(()), "{ok}");
        }
    }

    /// **A credential cannot ride in the query**, under any of the spellings a
    /// workload would reach for, and the refusal names the parameter.
    #[test]
    fn a_credential_looking_parameter_is_refused_by_name() {
        for name in [
            "access_token",
            "token",
            "Access-Token",
            "ACCESSTOKEN",
            "private_token",
            "api_key",
            "apiKey",
            "key",
            "client_secret",
            "password",
            "sig",
            "X-Signature",
            "code",
            "session_id",
            "jwt",
            "auth",
        ] {
            let query = format!("service=git-upload-pack&{name}=abc");
            assert_eq!(
                check_query(&query),
                Err(QueryRefusal::CredentialParameter {
                    name: name.to_string()
                }),
                "{query}"
            );
            assert!(spec().url_for_request("x", Some(&query)).is_none());
        }
        // Names that merely resemble a refused one stay usable.
        for ok in ["author=a", "keyword=x", "monkey=1", "codec=h264"] {
            assert_eq!(check_query(ok), Ok(()), "{ok}");
        }
    }

    /// The other refusals: bounds, alphabet, and names that hide behind an
    /// escape (which the credential check could not read).
    #[test]
    fn a_query_is_bounded_plain_and_unescaped_in_its_names() {
        assert_eq!(check_query(""), Err(QueryRefusal::Empty));
        let long = format!("a={}", "x".repeat(MAX_QUERY_BYTES));
        assert_eq!(
            check_query(&long),
            Err(QueryRefusal::TooLong {
                bytes: MAX_QUERY_BYTES + 2
            })
        );
        for bad in ["a=b c", "a=b#frag", "a=b?c", "a=\u{e9}", "a=\n"] {
            assert_eq!(check_query(bad), Err(QueryRefusal::Character), "{bad:?}");
        }
        for bad in ["=x", "a=1&&b=2", "acc%65ss_token=x", "a[b]=1"] {
            assert_eq!(check_query(bad), Err(QueryRefusal::Name), "{bad:?}");
        }
    }

    /// The path may not smuggle a query or fragment past [`check_query`].
    #[test]
    fn the_path_cannot_carry_a_query() {
        for path in ["info/refs?access_token=x", "x#frag", "x?"] {
            assert!(spec().url_for(path).is_none(), "{path}");
            assert!(spec().url_for_request(path, None).is_none(), "{path}");
        }
    }

    /// The headers a guest may propose: protocol headers yes; anything the
    /// host owns, or that could carry a credential, never.
    #[test]
    fn credential_and_framing_headers_can_never_be_proposed() {
        for ok in [
            "accept",
            "git-protocol",
            "content-encoding",
            "x-api-version",
        ] {
            assert!(guest_may_propose_header(ok), "{ok}");
        }
        for never in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "host",
            "content-type",
            "content-length",
            "transfer-encoding",
            "x-nucleus-actor",
            "x-forwarded-for",
            "x-auth-token",
            "private-token",
            "x-api-key",
            "Accept",
            "",
            "a b",
        ] {
            assert!(!guest_may_propose_header(never), "{never:?}");
        }
        assert!(header_value_admissible("version=2"));
        assert!(!header_value_admissible("a\r\nb"));
        assert!(!header_value_admissible(
            &"x".repeat(MAX_HEADER_VALUE_BYTES + 1)
        ));
    }
}
