//! Where a client reaches the tool-proxy, parsed once.
//!
//! # Why this module exists
//!
//! The proxy is reached two ways, and they are different claims about who is
//! calling:
//!
//! * **`http://host:port`** — a TCP listener. Anyone who can route to it can
//!   connect, so the request carries its authentication (an HMAC over the body,
//!   or a signing proxy in front that adds one).
//! * **`unix:///path/to/socket`** — a Unix socket, today the workload door
//!   (`guest_layout::WORKLOAD_DOOR`, #2696 P1). The proxy reads the caller's uid
//!   from the kernel (`SO_PEERCRED`), so the request carries no secret at all.
//!
//! The tool-proxy WRITES the `unix://` form into the workload's
//! `NUCLEUS_TOOL_PROXY_URL`, and every client READS it. If the writer and each
//! reader spelled the form themselves, the first one to disagree (a relative
//! path, a trailing slash, a `vsock://` the guest cannot dial) would fail far
//! from its cause. So the form is declared here, once: [`ProxyEndpoint`]'s
//! `Display` is what the proxy writes and [`ProxyEndpoint::parse`] is what the
//! clients read, and a round-trip test ties them (ADR 0007 G-1).
//!
//! # What it does not decide
//!
//! How a request on each transport is authenticated. That is the client's
//! type to carry (in `nucleus-mcp`, a transport enum whose TCP arm cannot be
//! built without its auth); this module only says which transport a URL names.

use std::path::{Path, PathBuf};

/// The `unix://` scheme prefix. A Unix socket URL is this followed by the
/// socket's absolute path, so it reads `unix:///run/...`.
const UNIX_SCHEME: &str = "unix://";

/// A tool-proxy endpoint: which transport, and where.
///
/// Two variants, no "unknown": a URL that names neither is refused by
/// [`ProxyEndpoint::parse`], never defaulted to one of them (ADR 0007 B-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyEndpoint {
    /// An HTTP(S) listener. `base` is the URL as given, without a trailing `/`;
    /// a request path is appended to it.
    Http {
        /// `http://host:port` or `https://host:port`, no trailing slash.
        base: String,
    },
    /// A Unix socket. The whole remainder of the URL after `unix://` is the
    /// socket's path; the HTTP request path is sent separately.
    Unix {
        /// Absolute path of the socket.
        socket: PathBuf,
    },
}

/// Why a proxy URL was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EndpointError {
    /// Nothing was given.
    #[error("the tool-proxy URL is empty")]
    Empty,
    /// `unix://` with a path that is not absolute (`unix://run/x.sock` names a
    /// host, not a path; `unix:///run/x.sock` is the socket `/run/x.sock`).
    #[error(
        "`{0}` is not an absolute socket path; a Unix-socket proxy URL is `unix://` followed \
         by an absolute path, e.g. `unix:///run/nucleus-door/workload.sock`"
    )]
    RelativeSocket(String),
    /// A scheme this client cannot dial. `vsock://` is the main case: it is the
    /// host's view of a guest's proxy, and a process inside the guest cannot
    /// connect to its own guest's vsock, which is what the workload door is for.
    #[error(
        "the tool-proxy URL `{0}` names a transport this client cannot dial; expected \
         `http://`, `https://` or `unix:///<socket>`"
    )]
    UnsupportedScheme(String),
    /// `http://` or `https://` with nothing after it.
    #[error("the tool-proxy URL `{0}` has no host")]
    NoHost(String),
}

impl ProxyEndpoint {
    /// The endpoint for a Unix socket at `socket`.
    #[must_use]
    pub fn unix(socket: &Path) -> Self {
        Self::Unix {
            socket: socket.to_path_buf(),
        }
    }

    /// Parse a proxy URL. The one reader of the form [`Display`](std::fmt::Display)
    /// writes.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] for an empty URL, a relative socket path, an
    /// `http(s)://` with no host, or any other scheme.
    pub fn parse(url: &str) -> Result<Self, EndpointError> {
        let url = url.trim();
        if url.is_empty() {
            return Err(EndpointError::Empty);
        }
        if let Some(path) = url.strip_prefix(UNIX_SCHEME) {
            return if path.starts_with('/') {
                Ok(Self::Unix {
                    socket: PathBuf::from(path),
                })
            } else {
                Err(EndpointError::RelativeSocket(url.to_string()))
            };
        }
        for scheme in ["http://", "https://"] {
            if let Some(rest) = url.strip_prefix(scheme) {
                if rest.trim_matches('/').is_empty() {
                    return Err(EndpointError::NoHost(url.to_string()));
                }
                return Ok(Self::Http {
                    base: url.trim_end_matches('/').to_string(),
                });
            }
        }
        Err(EndpointError::UnsupportedScheme(url.to_string()))
    }
}

impl std::fmt::Display for ProxyEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http { base } => f.write_str(base),
            Self::Unix { socket } => write!(f, "{UNIX_SCHEME}{}", socket.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The writer and the reader are one declaration: whatever the proxy writes
    /// for its door, every client parses back to the same socket.
    #[test]
    fn the_door_url_round_trips() {
        let door = ProxyEndpoint::unix(Path::new("/run/nucleus-door/workload.sock"));
        assert_eq!(door.to_string(), "unix:///run/nucleus-door/workload.sock");
        assert_eq!(ProxyEndpoint::parse(&door.to_string()), Ok(door));
    }

    #[test]
    fn an_http_url_keeps_its_base_without_a_trailing_slash() {
        assert_eq!(
            ProxyEndpoint::parse("http://127.0.0.1:8080/"),
            Ok(ProxyEndpoint::Http {
                base: "http://127.0.0.1:8080".into()
            })
        );
        assert_eq!(
            ProxyEndpoint::parse("https://proxy.example:443"),
            Ok(ProxyEndpoint::Http {
                base: "https://proxy.example:443".into()
            })
        );
    }

    /// `unix://run/x.sock` is the classic slip: it parses as host `run`. It is
    /// refused rather than read as `/run/x.sock` or as `run/x.sock` relative to
    /// wherever the client happens to start.
    #[test]
    fn a_relative_socket_is_refused() {
        assert!(matches!(
            ProxyEndpoint::parse("unix://run/nucleus-door/workload.sock"),
            Err(EndpointError::RelativeSocket(_))
        ));
        assert!(matches!(
            ProxyEndpoint::parse("unix://"),
            Err(EndpointError::RelativeSocket(_))
        ));
    }

    /// The host's vsock form is what an old guest gave its workload. A client
    /// inside the guest cannot dial it, and must say so instead of trying TCP.
    #[test]
    fn vsock_and_bare_addresses_are_refused_not_guessed() {
        for url in ["vsock://3:5000", "127.0.0.1:8080", "ftp://x"] {
            assert!(
                matches!(
                    ProxyEndpoint::parse(url),
                    Err(EndpointError::UnsupportedScheme(_))
                ),
                "{url}"
            );
        }
        assert_eq!(ProxyEndpoint::parse("  "), Err(EndpointError::Empty));
        assert!(matches!(
            ProxyEndpoint::parse("http://"),
            Err(EndpointError::NoHost(_))
        ));
    }
}
