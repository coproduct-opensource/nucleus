//! Every reason the proxy refuses a request, each with its own code (ADR
//! 0007 I-3: the error path and the allow path never share an outcome, and
//! two refusals never share a reason).

use nucleus_decision_protocol::DenyReason;

use crate::decision::HostUnavailable;

/// Why a request did not leave.
///
/// A closed vocabulary. The guest sees [`Refusal::code`] in the
/// `x-nucleus-egress-refusal` header and [`Refusal::status`] as the status
/// line; the node's log sees the same code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    // ── the guest's bytes (request.rs) ─────────────────────────────────────
    /// Not a parseable HTTP/1.x request head.
    Malformed,
    /// The request line is longer than [`crate::request::MAX_REQUEST_LINE`].
    RequestLineTooLong,
    /// The header block is longer than [`crate::request::MAX_HEADER_BYTES`].
    HeadersTooLarge,
    /// More than [`crate::request::MAX_HEADERS`] header fields.
    TooManyHeaders,
    /// The HTTP/2 connection preface. ADR 0015 §4: HTTP/1.1 only toward the
    /// guest.
    Http2,
    /// An HTTP version other than 1.1.
    NotHttp11,
    /// `Upgrade`, `Connection: upgrade` or `HTTP2-Settings` (WebSocket, h2c):
    /// after an upgrade the bytes are frames no request decision covers.
    Upgrade,
    /// `CONNECT`. Refused in E2: without TLS termination (E3) the proxy
    /// cannot see what is inside the tunnel, and a tunnel nobody decided is
    /// what §4 forbids. This covers the non-TLS `CONNECT` §4 refuses for
    /// good.
    Connect,
    /// A method outside [`crate::request::Method`] (`TRACE`, an extension).
    MethodNotSupported,
    /// An origin-form target (`GET /path`). A proxy request names its origin
    /// in the target, so the decision is about a name the guest wrote once.
    NotAbsoluteForm,
    /// A scheme other than `http`. `https` arrives as a `CONNECT` (E3).
    SchemeNotSupported,
    /// The authority is not a lower-case DNS name, a dotted IPv4 literal or a
    /// bracketed IPv6 literal, or carries userinfo or a bad port.
    BadAuthority,
    /// No `Host` header, or more than one.
    MissingHost,
    /// `Host` names a different origin than the target.
    HostMismatch,
    /// A path a normaliser could read two ways: a `.` or `..` segment, an
    /// empty segment, an encoded `.`, `/` or `\`, a fragment, or a byte
    /// outside the path grammar. Refused, never normalised.
    AmbiguousPath,
    /// `Transfer-Encoding` on a request. E2 bodies are `Content-Length`
    /// only, which also rules out a length a second parser could read
    /// differently.
    TransferEncoding,
    /// `Content-Length` repeated, non-numeric or past the body bound.
    BadContentLength,
    /// `TE`, `Trailer` or `Expect`: trailers and interim responses are not
    /// offered.
    UnsupportedFraming,
    /// `Proxy-Authorization`: the proxy takes no credential from the guest.
    ProxyAuthorization,
    /// A header value with a byte outside visible ASCII, space and tab.
    BadHeaderValue,
    /// The guest stopped sending before the head or the body was complete.
    Incomplete,
    /// The canonical summary of this request is longer than one decision
    /// frame can carry, so the node cannot be asked about it.
    SummaryTooLong,

    // ── the node's answer (decision.rs) ────────────────────────────────────
    /// The node's pod policy refused it.
    Denied(DenyReason),
    /// The node asked for a human approval. The proxy holds no approval
    /// flow in E2, so the request is refused rather than parked.
    ApprovalRequired,
    /// The node did not answer: no answer is a denial (ADR 0014 §7).
    HostUnavailable(HostUnavailable),

    // ── the address (address.rs, resolve.rs) ───────────────────────────────
    /// The host's resolver did not answer for the name.
    ResolveFailed,
    /// This proxy has no outbound path to resolve or reach a name through.
    NoOutboundPath,
    /// The name resolved to no address.
    NoAddress,
    /// An address no upstream may have: unspecified, link-local (the cloud
    /// metadata service), multicast, broadcast, reserved, or the node's deny
    /// floor.
    ForbiddenAddress,
    /// A private or loopback address reached through a NAME. Only an
    /// operator-registered literal address may be private (ADR 0015 §3).
    PrivateAddress,

    // ── the upstream (serve.rs) ────────────────────────────────────────────
    /// The connect to the admitted address failed or timed out.
    UpstreamUnreachable,

    // ── capacity (serve.rs) ────────────────────────────────────────────────
    /// The pod already holds [`crate::serve::MAX_CONNECTIONS`] connections.
    TooManyConnections,
    /// The guest took too long to send its request head.
    HeadTimeout,
}

impl Refusal {
    /// The status line the guest receives.
    pub const fn status(self) -> (u16, &'static str) {
        match self {
            Refusal::Malformed
            | Refusal::NotAbsoluteForm
            | Refusal::BadAuthority
            | Refusal::MissingHost
            | Refusal::HostMismatch
            | Refusal::AmbiguousPath
            | Refusal::BadContentLength
            | Refusal::BadHeaderValue
            | Refusal::Incomplete => (400, "Bad Request"),
            Refusal::RequestLineTooLong => (414, "URI Too Long"),
            Refusal::HeadersTooLarge | Refusal::TooManyHeaders | Refusal::SummaryTooLong => {
                (431, "Request Header Fields Too Large")
            }
            Refusal::Http2 | Refusal::NotHttp11 => (505, "HTTP Version Not Supported"),
            Refusal::Upgrade
            | Refusal::Connect
            | Refusal::MethodNotSupported
            | Refusal::SchemeNotSupported
            | Refusal::TransferEncoding
            | Refusal::UnsupportedFraming => (501, "Not Implemented"),
            Refusal::ProxyAuthorization => (400, "Bad Request"),
            Refusal::Denied(_) | Refusal::ApprovalRequired => (403, "Forbidden"),
            Refusal::HostUnavailable(_) | Refusal::TooManyConnections => {
                (503, "Service Unavailable")
            }
            Refusal::ResolveFailed
            | Refusal::NoOutboundPath
            | Refusal::NoAddress
            | Refusal::ForbiddenAddress
            | Refusal::PrivateAddress
            | Refusal::UpstreamUnreachable => (502, "Bad Gateway"),
            Refusal::HeadTimeout => (408, "Request Timeout"),
        }
    }

    /// The machine code, one per reason.
    pub const fn code(self) -> &'static str {
        match self {
            Refusal::Malformed => "malformed",
            Refusal::RequestLineTooLong => "request_line_too_long",
            Refusal::HeadersTooLarge => "headers_too_large",
            Refusal::TooManyHeaders => "too_many_headers",
            Refusal::Http2 => "http2",
            Refusal::NotHttp11 => "not_http11",
            Refusal::Upgrade => "upgrade",
            Refusal::Connect => "connect",
            Refusal::MethodNotSupported => "method_not_supported",
            Refusal::NotAbsoluteForm => "not_absolute_form",
            Refusal::SchemeNotSupported => "scheme_not_supported",
            Refusal::BadAuthority => "bad_authority",
            Refusal::MissingHost => "missing_host",
            Refusal::HostMismatch => "host_mismatch",
            Refusal::AmbiguousPath => "ambiguous_path",
            Refusal::TransferEncoding => "transfer_encoding",
            Refusal::BadContentLength => "bad_content_length",
            Refusal::UnsupportedFraming => "unsupported_framing",
            Refusal::ProxyAuthorization => "proxy_authorization",
            Refusal::BadHeaderValue => "bad_header_value",
            Refusal::Incomplete => "incomplete",
            Refusal::SummaryTooLong => "summary_too_long",
            Refusal::Denied(reason) => match reason {
                DenyReason::NotGranted => "denied_not_granted",
                DenyReason::FlowRefused => "denied_flow_refused",
                DenyReason::BudgetExhausted => "denied_budget_exhausted",
                DenyReason::ApprovalRefused => "denied_approval_refused",
                DenyReason::ApprovalExpired => "denied_approval_expired",
                DenyReason::ApprovalUnknown => "denied_approval_unknown",
                DenyReason::NotRegistered => "denied_not_registered",
                DenyReason::RouteRefused => "denied_route_refused",
            },
            Refusal::ApprovalRequired => "approval_required",
            Refusal::HostUnavailable(why) => why.code(),
            Refusal::ResolveFailed => "resolve_failed",
            Refusal::NoOutboundPath => "no_outbound_path",
            Refusal::NoAddress => "no_address",
            Refusal::ForbiddenAddress => "forbidden_address",
            Refusal::PrivateAddress => "private_address",
            Refusal::UpstreamUnreachable => "upstream_unreachable",
            Refusal::TooManyConnections => "too_many_connections",
            Refusal::HeadTimeout => "head_timeout",
        }
    }

    /// The whole response the guest receives for this refusal. No body: the
    /// code is in a header, so a client that only reads status lines still
    /// sees a refusal and never a partial upstream answer.
    pub fn response(self) -> Vec<u8> {
        let (status, phrase) = self.status();
        format!(
            "HTTP/1.1 {status} {phrase}\r\n{REFUSAL_HEADER}: {}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            self.code()
        )
        .into_bytes()
    }
}

/// The response header that carries [`Refusal::code`].
pub const REFUSAL_HEADER: &str = "x-nucleus-egress-refusal";

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
