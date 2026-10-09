//! The guest-facing parser: one HTTP/1.1 request head, or a named refusal.
//!
//! The only code in this process that reads bytes guest root wrote, so it is
//! small, bounded and total (ADR 0015 §7): every input is either
//! [`Parsed::Partial`], a [`Parsed::Complete`] request, or a [`Refusal`].
//! Nothing panics, nothing allocates past [`MAX_HEAD`], and the fuzz target
//! (`fuzz/fuzz_targets/guest_request.rs`) holds it to that.
//!
//! # Refused, never normalised
//!
//! Tokenising is `httparse` (hyper's parser). Everything after it is this
//! file, and its rule is that a request a second parser could read another
//! way is refused rather than repaired: a dot segment, an encoded slash, two
//! `Host` headers, a `Transfer-Encoding`, a `Host` that disagrees with the
//! target. The node then decides on exactly the request that is forwarded.
//!
//! # What is accepted
//!
//! HTTP/1.1, absolute-form `http://` targets (a proxy request names its
//! origin), the methods in [`Method`], a body framed by `Content-Length` and
//! at most [`MAX_BODY`] bytes. ADR 0015 §4's refusals are each a
//! [`Refusal`]: HTTP/2, `Upgrade` (WebSocket, h2c), `CONNECT`, trailers and
//! proxy authentication.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::Refusal;

/// The longest request line accepted, in bytes (ADR 0015 §7).
pub const MAX_REQUEST_LINE: usize = 8 * 1024;
/// The longest header block accepted, in bytes (ADR 0015 §7).
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// The most header fields accepted (ADR 0015 §7).
pub const MAX_HEADERS: usize = 64;
/// The longest head accepted: request line plus headers plus the blank line.
pub const MAX_HEAD: usize = MAX_REQUEST_LINE + MAX_HEADER_BYTES + 2;
/// The largest request body accepted in E2, in bytes. It is buffered so its
/// digest can be part of the decision.
pub const MAX_BODY: u64 = 1024 * 1024;

/// The HTTP/2 connection preface's first token. No accepted method begins
/// with it, so a head that does is HTTP/2 whatever follows.
const H2_PREFACE_START: &[u8] = b"PRI ";

/// The methods a guest may send. Closed: `CONNECT` is its own refusal and
/// anything else (`TRACE`, an extension method) is
/// [`Refusal::MethodNotSupported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl Method {
    /// Every method, for the summary parser's search.
    pub const ALL: [Method; 7] = [
        Method::Get,
        Method::Head,
        Method::Post,
        Method::Put,
        Method::Patch,
        Method::Delete,
        Method::Options,
    ];

    /// The method token as it is sent.
    pub const fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
        }
    }

    /// The method named by `token`, exactly (methods are case-sensitive).
    pub fn from_token(token: &str) -> Option<Method> {
        Method::ALL.into_iter().find(|m| m.as_str() == token)
    }
}

/// An upstream's host, as the guest named it, canonical.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Host {
    /// A DNS name: lower-case labels of letters, digits and hyphens.
    Name(String),
    /// A dotted-quad IPv4 literal.
    Ipv4(Ipv4Addr),
    /// A bracketed IPv6 literal.
    Ipv6(Ipv6Addr),
}

impl std::fmt::Display for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Host::Name(n) => f.write_str(n),
            Host::Ipv4(a) => write!(f, "{a}"),
            Host::Ipv6(a) => write!(f, "[{a}]"),
        }
    }
}

/// `scheme://host:port`, with the scheme fixed to `http` in E2 and the port
/// always explicit, so one origin has one spelling.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    pub host: Host,
    pub port: u16,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http://{}:{}", self.host, self.port)
    }
}

/// One request head the guest sent, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: Method,
    pub origin: Origin,
    /// Starts with `/`; checked by [`check_path`].
    pub path: String,
    /// Without the `?`; checked by [`check_query`].
    pub query: Option<String>,
    /// End-to-end headers, names lower-case, in the order sent. `Host`,
    /// `Content-Length` and the hop-by-hop names are not here: the proxy
    /// writes those itself.
    pub headers: Vec<(String, String)>,
    pub content_length: u64,
}

/// What [`parse_head`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    /// Not a whole head yet, and nothing refused so far.
    Partial,
    /// A whole head: the request, and how many bytes of the buffer it used.
    Complete { request: Request, head_len: usize },
}

/// Parse the head at the start of `buf`.
///
/// # Errors
/// The [`Refusal`] for the first thing wrong with it.
pub fn parse_head(buf: &[u8]) -> Result<Parsed, Refusal> {
    // HTTP/2's preface, even when only its first token has arrived.
    let probe = buf
        .get(..H2_PREFACE_START.len().min(buf.len()))
        .unwrap_or(buf);
    if H2_PREFACE_START.starts_with(probe) {
        if probe.len() == H2_PREFACE_START.len() {
            return Err(Refusal::Http2);
        }
        if !buf.is_empty() {
            return Ok(Parsed::Partial);
        }
    }
    let line_end = buf.iter().position(|b| *b == b'\n');
    match line_end {
        Some(end) if end > MAX_REQUEST_LINE => return Err(Refusal::RequestLineTooLong),
        None if buf.len() > MAX_REQUEST_LINE => return Err(Refusal::RequestLineTooLong),
        Some(_) | None => {}
    }
    let mut fields = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut fields);
    let head_len = match req.parse(buf) {
        Ok(httparse::Status::Partial) => {
            return if buf.len() >= MAX_HEAD {
                Err(Refusal::HeadersTooLarge)
            } else {
                Ok(Parsed::Partial)
            };
        }
        Ok(httparse::Status::Complete(n)) => n,
        Err(httparse::Error::TooManyHeaders) => return Err(Refusal::TooManyHeaders),
        Err(httparse::Error::Version) => return Err(Refusal::NotHttp11),
        Err(_) => return Err(Refusal::Malformed),
    };
    let line_len = line_end.map_or(head_len, |e| e.saturating_add(1));
    if head_len.saturating_sub(line_len) > MAX_HEADER_BYTES.saturating_add(2) {
        return Err(Refusal::HeadersTooLarge);
    }
    if req.version != Some(1) {
        return Err(Refusal::NotHttp11);
    }
    let method = match req.method {
        Some("CONNECT") => return Err(Refusal::Connect),
        Some(token) => Method::from_token(token).ok_or(Refusal::MethodNotSupported)?,
        None => return Err(Refusal::Malformed),
    };
    let (origin, path, query) = parse_target(req.path.ok_or(Refusal::Malformed)?)?;
    let request = check_headers(req.headers, method, origin, path, query)?;
    Ok(Parsed::Complete { request, head_len })
}

/// Split and check an absolute-form target.
fn parse_target(target: &str) -> Result<(Origin, String, Option<String>), Refusal> {
    if target.starts_with('/') || target == "*" {
        return Err(Refusal::NotAbsoluteForm);
    }
    let Some((scheme, rest)) = target.split_once("://") else {
        return Err(Refusal::NotAbsoluteForm);
    };
    if !scheme.eq_ignore_ascii_case("http") {
        return Err(Refusal::SchemeNotSupported);
    }
    if rest.contains('#') {
        return Err(Refusal::AmbiguousPath);
    }
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(split);
    let origin = parse_authority(authority)?;
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    let path = if path.is_empty() { "/" } else { path };
    check_path(path)?;
    if let Some(q) = query {
        check_query(q)?;
    }
    Ok((origin, path.to_string(), query.map(str::to_string)))
}

/// An authority (`host[:port]`), canonical: a lower-case name or a literal,
/// and the port made explicit (`80` when absent).
///
/// # Errors
/// [`Refusal::BadAuthority`] for userinfo, an empty or malformed host, a
/// trailing dot, a numeric-looking host that is not a dotted quad, or a port
/// that is empty, zero, has a leading zero or does not fit.
pub fn parse_authority(authority: &str) -> Result<Origin, Refusal> {
    if authority.contains('@') {
        return Err(Refusal::BadAuthority);
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (literal, after) = rest.split_once(']').ok_or(Refusal::BadAuthority)?;
        let addr: Ipv6Addr = literal.parse().map_err(|_| Refusal::BadAuthority)?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(Refusal::BadAuthority)?),
        };
        (Host::Ipv6(addr), port)
    } else {
        let (host, port) = match authority.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        (parse_host(host)?, port)
    };
    let port = match port {
        None => 80,
        Some(p) => parse_port(p)?,
    };
    Ok(Origin { host, port })
}

fn parse_port(p: &str) -> Result<u16, Refusal> {
    if p.is_empty() || p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refusal::BadAuthority);
    }
    p.parse::<u16>().map_err(|_| Refusal::BadAuthority)
}

fn parse_host(host: &str) -> Result<Host, Refusal> {
    if host.is_empty() || host.len() > 253 || host.ends_with('.') {
        return Err(Refusal::BadAuthority);
    }
    let last = host.rsplit('.').next().unwrap_or(host);
    if last.bytes().all(|b| b.is_ascii_digit()) {
        // A host whose last label is numeric is an address or nothing: a
        // name like `2130706433` or `127.1` is an address to some parsers.
        return host
            .parse::<Ipv4Addr>()
            .map(Host::Ipv4)
            .map_err(|_| Refusal::BadAuthority);
    }
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !ok {
            return Err(Refusal::BadAuthority);
        }
    }
    Ok(Host::Name(host.to_ascii_lowercase()))
}

/// Check a path: it starts with `/`, uses only the path grammar's bytes, and
/// has no dot segment, no empty segment but a trailing one, and no
/// percent-encoding of `.`, `/`, `\` or a control byte.
///
/// # Errors
/// [`Refusal::AmbiguousPath`].
pub fn check_path(path: &str) -> Result<(), Refusal> {
    let Some(rest) = path.strip_prefix('/') else {
        return Err(Refusal::AmbiguousPath);
    };
    let bytes = path.as_bytes();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'%' {
            let hi = bytes.get(i.saturating_add(1)).copied();
            let lo = bytes.get(i.saturating_add(2)).copied();
            let decoded = match (hi.and_then(hex_value), lo.and_then(hex_value)) {
                (Some(h), Some(l)) => h.saturating_mul(16).saturating_add(l),
                _ => return Err(Refusal::AmbiguousPath),
            };
            if matches!(decoded, b'.' | b'/' | b'\\') || decoded < 0x20 || decoded == 0x7f {
                return Err(Refusal::AmbiguousPath);
            }
            i = i.saturating_add(3);
            continue;
        }
        let allowed = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
            );
        if !allowed {
            return Err(Refusal::AmbiguousPath);
        }
        i = i.saturating_add(1);
    }
    let segments: Vec<&str> = rest.split('/').collect();
    let last = segments.len().saturating_sub(1);
    for (n, segment) in segments.iter().enumerate() {
        if *segment == "." || *segment == ".." || (segment.is_empty() && n != last) {
            return Err(Refusal::AmbiguousPath);
        }
    }
    Ok(())
}

/// Check a query: visible ASCII only, no `#`.
///
/// # Errors
/// [`Refusal::AmbiguousPath`].
pub fn check_query(query: &str) -> Result<(), Refusal> {
    if query
        .bytes()
        .all(|b| (0x21..0x7f).contains(&b) && b != b'#')
    {
        Ok(())
    } else {
        Err(Refusal::AmbiguousPath)
    }
}

fn hex_value(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

/// Header names the proxy writes itself or that describe this hop only.
/// Dropped from what is forwarded, never refused.
const HOP_BY_HOP: [&str; 3] = ["connection", "proxy-connection", "keep-alive"];

fn check_headers(
    fields: &[httparse::Header<'_>],
    method: Method,
    origin: Origin,
    path: String,
    query: Option<String>,
) -> Result<Request, Refusal> {
    let mut host: Option<Origin> = None;
    let mut content_length: Option<u64> = None;
    let mut headers = Vec::new();
    for field in fields {
        let name = field.name.to_ascii_lowercase();
        if !field
            .value
            .iter()
            .all(|b| *b == b'\t' || (0x20..0x7f).contains(b))
        {
            return Err(Refusal::BadHeaderValue);
        }
        // Checked above: visible ASCII, space and tab are UTF-8.
        let value = std::str::from_utf8(field.value)
            .map_err(|_| Refusal::BadHeaderValue)?
            .trim_matches([' ', '\t']);
        match name.as_str() {
            "upgrade" | "http2-settings" => return Err(Refusal::Upgrade),
            "connection" | "proxy-connection"
                if value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade")) =>
            {
                return Err(Refusal::Upgrade);
            }
            "transfer-encoding" => return Err(Refusal::TransferEncoding),
            "te" | "trailer" | "expect" => return Err(Refusal::UnsupportedFraming),
            "proxy-authorization" => return Err(Refusal::ProxyAuthorization),
            "host" => {
                if host.replace(parse_authority(value)?).is_some() {
                    return Err(Refusal::MissingHost);
                }
            }
            "content-length" => {
                let ok = !value.is_empty()
                    && value.len() <= 19
                    && value.bytes().all(|b| b.is_ascii_digit());
                let n = value
                    .parse::<u64>()
                    .ok()
                    .filter(|n| ok && *n <= MAX_BODY)
                    .ok_or(Refusal::BadContentLength)?;
                if content_length.replace(n).is_some() {
                    return Err(Refusal::BadContentLength);
                }
            }
            n if HOP_BY_HOP.contains(&n) => {}
            _ => headers.push((name, value.to_string())),
        }
    }
    match host {
        None => return Err(Refusal::MissingHost),
        Some(h) if h != origin => return Err(Refusal::HostMismatch),
        Some(_) => {}
    }
    Ok(Request {
        method,
        origin,
        path,
        query,
        headers,
        content_length: content_length.unwrap_or(0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Parsed, Refusal> {
        parse_head(s.as_bytes())
    }

    fn complete(s: &str) -> Request {
        match parse(s) {
            Ok(Parsed::Complete { request, .. }) => request,
            other => panic!("expected a request, got {other:?}"),
        }
    }

    #[test]
    fn an_honest_proxy_request_parses() {
        let r = complete(
            "POST http://api.example:8080/v1/items?x=1 HTTP/1.1\r\nHost: api.example:8080\r\n\
             Accept: */*\r\nConnection: keep-alive\r\nContent-Length: 3\r\n\r\nabc",
        );
        assert_eq!(r.method, Method::Post);
        assert_eq!(r.origin.to_string(), "http://api.example:8080");
        assert_eq!(r.path, "/v1/items");
        assert_eq!(r.query.as_deref(), Some("x=1"));
        assert_eq!(r.headers, vec![("accept".to_string(), "*/*".to_string())]);
        assert_eq!(r.content_length, 3);
    }

    /// ADR 0015 §4: HTTP/2 is never offered, so the preface is refused, even
    /// when only its first token has arrived.
    #[test]
    fn http2_is_refused() {
        assert_eq!(
            parse("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"),
            Err(Refusal::Http2)
        );
        assert_eq!(parse("PRI "), Err(Refusal::Http2));
        assert_eq!(parse("PR"), Ok(Parsed::Partial));
        assert_eq!(
            parse("GET http://a.example/ HTTP/2.0\r\nHost: a.example\r\n\r\n"),
            Err(Refusal::NotHttp11)
        );
        assert_eq!(
            parse("GET http://a.example/ HTTP/1.0\r\nHost: a.example\r\n\r\n"),
            Err(Refusal::NotHttp11)
        );
    }

    /// ADR 0015 §4: after an upgrade the bytes are frames no decision covers.
    #[test]
    fn upgrades_are_refused() {
        for extra in [
            "Upgrade: websocket\r\nConnection: Upgrade\r\n",
            "Connection: keep-alive, Upgrade\r\n",
            "HTTP2-Settings: AAMAAABkAAQAAP__\r\n",
            "upgrade: h2c\r\n",
        ] {
            assert_eq!(
                parse(&format!(
                    "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\n{extra}\r\n"
                )),
                Err(Refusal::Upgrade),
                "{extra}"
            );
        }
    }

    #[test]
    fn connect_is_refused_in_e2() {
        assert_eq!(
            parse("CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n"),
            Err(Refusal::Connect)
        );
    }

    #[test]
    fn malformed_heads_are_refused() {
        for (raw, why) in [
            ("GARBAGE\r\n\r\n", Refusal::Malformed),
            (
                "GET http://a.example/ HTTP/1.1\r\nBad Header\r\n\r\n",
                Refusal::Malformed,
            ),
            (
                "TRACE http://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::MethodNotSupported,
            ),
            (
                "GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::NotAbsoluteForm,
            ),
            (
                "GET https://a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::SchemeNotSupported,
            ),
            (
                "GET http://u@a.example/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::BadAuthority,
            ),
            (
                "GET http://a.example:080/ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::BadAuthority,
            ),
            (
                "GET http://2130706433/ HTTP/1.1\r\nHost: 2130706433\r\n\r\n",
                Refusal::BadAuthority,
            ),
            (
                "GET http://a.example./ HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::BadAuthority,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\n\r\n",
                Refusal::MissingHost,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\nHost: a.example\r\n\r\n",
                Refusal::MissingHost,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: b.example\r\n\r\n",
                Refusal::HostMismatch,
            ),
            (
                "GET http://a.example/a/../b HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::AmbiguousPath,
            ),
            (
                "GET http://a.example/a/%2e%2e/b HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::AmbiguousPath,
            ),
            (
                "GET http://a.example/a%2Fb HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::AmbiguousPath,
            ),
            (
                "GET http://a.example/a//b HTTP/1.1\r\nHost: a.example\r\n\r\n",
                Refusal::AmbiguousPath,
            ),
            (
                "POST http://a.example/ HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\n",
                Refusal::TransferEncoding,
            ),
            (
                "POST http://a.example/ HTTP/1.1\r\nHost: a.example\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
                Refusal::BadContentLength,
            ),
            (
                "POST http://a.example/ HTTP/1.1\r\nHost: a.example\r\nContent-Length: +1\r\n\r\n",
                Refusal::BadContentLength,
            ),
            (
                "POST http://a.example/ HTTP/1.1\r\nHost: a.example\r\nContent-Length: 1048577\r\n\r\n",
                Refusal::BadContentLength,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\nTE: trailers\r\n\r\n",
                Refusal::UnsupportedFraming,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\nExpect: 100-continue\r\n\r\n",
                Refusal::UnsupportedFraming,
            ),
            (
                "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\nProxy-Authorization: Basic eA==\r\n\r\n",
                Refusal::ProxyAuthorization,
            ),
        ] {
            assert_eq!(parse(raw), Err(why), "{raw:?}");
        }
    }

    /// A fragment never reaches a decision: httparse or the target check
    /// refuses it, whichever sees it first.
    #[test]
    fn a_fragment_is_refused() {
        let r = parse("GET http://a.example/a#f HTTP/1.1\r\nHost: a.example\r\n\r\n");
        assert!(
            matches!(r, Err(Refusal::AmbiguousPath | Refusal::Malformed)),
            "{r:?}"
        );
    }

    #[test]
    fn bounds_are_refusals_not_allocations() {
        let long = format!(
            "GET http://a.example/{} HTTP/1.1\r\n",
            "a".repeat(MAX_REQUEST_LINE)
        );
        assert_eq!(parse(&long), Err(Refusal::RequestLineTooLong));
        assert_eq!(
            parse(&"a".repeat(MAX_REQUEST_LINE + 1)),
            Err(Refusal::RequestLineTooLong)
        );
        let many: String = (0..=MAX_HEADERS).map(|i| format!("x-{i}: v\r\n")).collect();
        assert_eq!(
            parse(&format!(
                "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\n{many}\r\n"
            )),
            Err(Refusal::TooManyHeaders)
        );
        let big = format!(
            "GET http://a.example/ HTTP/1.1\r\nHost: a.example\r\nx-big: {}\r\n\r\n",
            "v".repeat(MAX_HEADER_BYTES + 8)
        );
        assert_eq!(parse(&big), Err(Refusal::HeadersTooLarge));
    }

    #[test]
    fn literals_and_ports_are_canonical() {
        let r = complete("GET http://[::1]:8443/ HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n");
        assert_eq!(r.origin.to_string(), "http://[::1]:8443");
        let r = complete("GET http://API.Example HTTP/1.1\r\nHost: api.example:80\r\n\r\n");
        assert_eq!(r.origin.to_string(), "http://api.example:80");
        assert_eq!(r.path, "/");
    }
}
