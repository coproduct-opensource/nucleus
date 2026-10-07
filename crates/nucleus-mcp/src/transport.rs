//! How the bridge reaches its tool-proxy, and how each request is authenticated.
//!
//! # Two transports, two authentication claims
//!
//! * **TCP** (`http://host:port`). Anyone who can route to the listener can
//!   connect, so every request must carry its authentication, and a signing
//!   proxy in front of the listener adds it ([`TcpAuth::SignedUpstream`], the
//!   node's `SignedProxy`). The bridge used to sign with the proxy's shared
//!   secret itself (`TcpAuth::Hmac`); that tier admits only `/v1/health` since
//!   #2446 step 2, so `--auth-secret` is refused by name rather than sent.
//! * **A Unix socket** (`unix:///…`): the workload door, or the proxy's own
//!   peer-verified listener that `nucleus run --local` and `nucleus shell`
//!   point the host bridge at. Either way the proxy reads the caller's uid
//!   from the kernel.
//! * **The workload door** (`unix:///run/nucleus-door/workload.sock`, #2696
//!   P1). The proxy reads the caller's uid from the kernel and admits only the
//!   workload's, so there is no secret to send, and the workload is given none.
//!
//! These are different claims, so they are different variants. The TCP arm
//! cannot be built without saying how it is authenticated: the old shape was an
//! `Option<secret>` whose `None` silently sent unsigned requests to whatever
//! listener the URL named (ADR 0007 B-2: `None` may not mean unrestricted).
//! And the door arm cannot be handed a secret it would ignore: a bridge in the
//! guest that holds a proxy credential is a bridge that was given one by
//! mistake, and that is refused at startup rather than carried silently.
//!
//! # The Unix connector
//!
//! The door speaks HTTP/1.1 over a Unix socket. ureq has no Unix transport, so
//! [`DoorConnector`] supplies one through ureq's `unversioned` transport API.
//! The agent built over it is configured by [`crate::proxy_agent_config`], the
//! same configuration the TCP agent uses, so `http_status_as_error(false)` (and
//! with it every refusal reason) holds on both transports by construction.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use nucleus_client::endpoint::ProxyEndpoint;
use ureq::config::Config;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, Transport,
};

/// How requests over TCP are authenticated. There is no unauthenticated arm,
/// and since #2446 step 2 no shared-secret arm.
pub(crate) enum TcpAuth {
    /// A signing proxy between this bridge and the tool-proxy signs every
    /// request it forwards (the node's `SignedProxy`). Declared explicitly with
    /// `--signed-upstream`; never inferred from a missing secret.
    SignedUpstream,
}

impl std::fmt::Debug for TcpAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignedUpstream => f.write_str("SignedUpstream"),
        }
    }
}

/// Where the bridge sends its requests, and how they are authenticated.
#[derive(Debug)]
pub(crate) enum ProxyTransport {
    /// A TCP listener at `base_url`.
    Tcp {
        /// `http(s)://host:port`, no trailing slash.
        base_url: String,
        /// How each request proves itself.
        auth: TcpAuth,
    },
    /// The workload door: the proxy admits the caller by its uid.
    Door {
        /// The door's socket.
        socket: PathBuf,
    },
}

/// What the operator configured, before it is checked.
pub(crate) struct TransportConfig<'a> {
    /// `--proxy-url` / `NUCLEUS_MCP_PROXY_URL`.
    pub proxy_url: Option<&'a str>,
    /// `NUCLEUS_TOOL_PROXY_URL`, which the runtime puts in the workload's env.
    pub tool_proxy_url: Option<&'a str>,
    /// `--auth-secret`.
    pub auth_secret: Option<&'a str>,
    /// `--approval-secret`.
    pub approval_secret: Option<&'a str>,
    /// `--signed-upstream`.
    pub signed_upstream: bool,
}

impl ProxyTransport {
    /// The one decider of the transport and its authentication.
    ///
    /// # Errors
    ///
    /// When no URL is given, the two URL sources disagree, the URL does not
    /// parse, a TCP endpoint has no declared authentication (or two), or the
    /// door is handed a secret.
    pub(crate) fn resolve(cfg: &TransportConfig<'_>) -> Result<Self> {
        let url = match (cfg.proxy_url, cfg.tool_proxy_url) {
            (Some(a), Some(b)) if a.trim() != b.trim() => bail!(
                "--proxy-url (NUCLEUS_MCP_PROXY_URL) is `{a}` but NUCLEUS_TOOL_PROXY_URL is \
                 `{b}`; refusing to guess which proxy mediates this agent"
            ),
            (Some(url), _) | (None, Some(url)) => url,
            (None, None) => bail!(
                "no tool-proxy URL: pass --proxy-url (NUCLEUS_MCP_PROXY_URL), or run where the \
                 runtime sets NUCLEUS_TOOL_PROXY_URL"
            ),
        };
        let endpoint = ProxyEndpoint::parse(url).map_err(|e| anyhow!("{e}"))?;
        match endpoint {
            ProxyEndpoint::Unix { socket } => {
                if cfg.auth_secret.is_some() || cfg.approval_secret.is_some() {
                    bail!(
                        "the tool-proxy at `{url}` is a Unix socket, which authenticates the \
                         caller by its uid; this bridge was also given a proxy secret, which \
                         nothing in the guest should hold. Remove NUCLEUS_MCP_AUTH_SECRET / \
                         NUCLEUS_MCP_APPROVAL_SECRET."
                    );
                }
                if cfg.signed_upstream {
                    bail!(
                        "--signed-upstream names a signing proxy on a TCP path; `{url}` is a \
                         Unix socket"
                    );
                }
                Ok(Self::Door { socket })
            }
            ProxyEndpoint::Http { base } => {
                if cfg.auth_secret.is_some() || cfg.approval_secret.is_some() {
                    bail!(
                        "--auth-secret / --approval-secret (NUCLEUS_MCP_AUTH_SECRET, \
                         NUCLEUS_MCP_APPROVAL_SECRET) signed for the tool-proxy's shared-secret \
                         tier, which admits only /v1/health since #2446. Reach the proxy at \
                         `{base}` through a signing proxy (--signed-upstream), or over its \
                         peer-verified socket (a unix:// URL) with no secret"
                    );
                }
                if !cfg.signed_upstream {
                    bail!(
                        "the tool-proxy at `{base}` is TCP, which needs its requests \
                         authenticated: pass --signed-upstream (NUCLEUS_MCP_SIGNED_UPSTREAM) \
                         when a signing proxy sits in front of it, or reach it over a unix:// \
                         socket. (--auth-secret is retired: the shared-secret tier admits \
                         only /v1/health.)"
                    );
                }
                let auth = TcpAuth::SignedUpstream;
                Ok(Self::Tcp {
                    base_url: base,
                    auth,
                })
            }
        }
    }

    /// The URL base requests are built on. The door's authority is a
    /// placeholder: the connector dials the socket, never this host.
    pub(crate) fn base_url(&self) -> &str {
        match self {
            Self::Tcp { base_url, .. } => base_url,
            Self::Door { .. } => DOOR_BASE_URL,
        }
    }

    /// The HTTP agent for this transport, built from `config`.
    pub(crate) fn agent(&self, config: Config) -> ureq::Agent {
        match self {
            Self::Tcp { .. } => config.into(),
            Self::Door { socket } => ureq::Agent::with_parts(
                config,
                DoorConnector {
                    socket: socket.clone(),
                },
                NoLookup,
            ),
        }
    }
}

/// Requests to the door are addressed to this placeholder base. `localhost`
/// because hyper on the proxy side needs SOME `Host`, the same stand-in the
/// node uses for its own Unix-socket hop (`signed_proxy::ProxyTarget`).
const DOOR_BASE_URL: &str = "http://localhost";

/// Dials the door's socket for every connection ureq asks for.
#[derive(Debug)]
pub(crate) struct DoorConnector {
    socket: PathBuf,
}

impl Connector<()> for DoorConnector {
    type Out = DoorTransport;

    fn connect(
        &self,
        details: &ConnectionDetails,
        _chained: Option<()>,
    ) -> Result<Option<Self::Out>, ureq::Error> {
        if details.needs_tls() {
            // The door is plain HTTP on a local socket; a TLS URL here means the
            // base was built wrong, and silently downgrading it would hide that.
            return Err(ureq::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the workload door is not TLS",
            )));
        }
        let stream = connect(&self.socket)?;
        let config = details.config;
        Ok(Some(DoorTransport {
            stream,
            buffers: LazyBuffers::new(config.input_buffer_size(), config.output_buffer_size()),
            timeout_read: None,
            timeout_write: None,
        }))
    }
}

fn connect(socket: &Path) -> Result<UnixStream, ureq::Error> {
    UnixStream::connect(socket).map_err(|e| {
        ureq::Error::Io(io::Error::new(
            e.kind(),
            format!(
                "connecting to the tool-proxy door {}: {e}",
                socket.display()
            ),
        ))
    })
}

/// The door needs no name resolution, and a guest image may have no
/// `/etc/hosts` entry for `localhost`; the connector ignores the address.
#[derive(Debug)]
struct NoLookup;

impl Resolver for NoLookup {
    fn resolve(
        &self,
        _uri: &ureq::http::Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let mut addrs = self.empty();
        addrs.push(std::net::SocketAddr::from(([127, 0, 0, 1], 80)));
        Ok(addrs)
    }
}

/// One HTTP/1.1 connection over the door's socket.
#[derive(Debug)]
pub(crate) struct DoorTransport {
    stream: UnixStream,
    buffers: LazyBuffers,
    timeout_read: Option<std::time::Duration>,
    timeout_write: Option<std::time::Duration>,
}

/// `WouldBlock` from a timed-out blocking socket is a timeout.
fn timed_out(e: io::Error, timeout: NextTimeout) -> ureq::Error {
    if matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        ureq::Error::Timeout(timeout.reason)
    } else {
        ureq::Error::Io(e)
    }
}

impl Transport for DoorTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), ureq::Error> {
        let want = timeout.not_zero().map(|t| *t);
        if want != self.timeout_write {
            self.stream.set_write_timeout(want)?;
            self.timeout_write = want;
        }
        let output = self.buffers.output().get(..amount).ok_or_else(|| {
            ureq::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ureq asked to transmit more than its output buffer holds",
            ))
        })?;
        self.stream
            .write_all(output)
            .map_err(|e| timed_out(e, timeout))
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, ureq::Error> {
        let want = timeout.not_zero().map(|t| *t);
        if want != self.timeout_read {
            self.stream.set_read_timeout(want)?;
            self.timeout_read = want;
        }
        let input = self.buffers.input_append_buf();
        let amount = self.stream.read(input).map_err(|e| timed_out(e, timeout))?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        // A pooled connection is reusable only if the proxy has neither closed
        // it nor sent anything unasked. Probe without blocking.
        if self.stream.set_nonblocking(true).is_err() {
            return false;
        }
        let mut probe = [0u8; 1];
        let open = matches!(
            self.stream.read(&mut probe),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
        );
        open && self.stream.set_nonblocking(false).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(url: &str) -> TransportConfig<'_> {
        TransportConfig {
            proxy_url: Some(url),
            tool_proxy_url: None,
            auth_secret: None,
            approval_secret: None,
            signed_upstream: false,
        }
    }

    /// TCP has no unauthenticated arm. A missing secret used to mean "send
    /// unsigned"; now it is a startup refusal that names both ways to say how.
    #[test]
    fn tcp_without_declared_auth_is_refused() {
        let err = ProxyTransport::resolve(&cfg("http://127.0.0.1:8080"))
            .expect_err("TCP must declare its auth")
            .to_string();
        assert!(err.contains("--auth-secret"), "{err}");
        assert!(err.contains("--signed-upstream"), "{err}");
    }

    /// #2446 step 2: the bridge no longer signs for the shared-secret tier,
    /// which admits only `/v1/health`. A secret is refused by name, never
    /// silently dropped (the request would then go unsigned) nor sent. Red
    /// before: `TcpAuth::Hmac` was built from either secret.
    #[test]
    fn a_shared_secret_is_refused_by_name() {
        for (auth, approval) in [
            (Some("test-token-123"), None),
            (None, Some("test-token-123")),
            (Some("test-token-123"), Some("test-token-456")),
        ] {
            let err = ProxyTransport::resolve(&TransportConfig {
                auth_secret: auth,
                approval_secret: approval,
                ..cfg("http://127.0.0.1:8080")
            })
            .expect_err("the shared-secret tier is retired")
            .to_string();
            assert!(err.contains("#2446"), "{err}");
            assert!(err.contains("/v1/health"), "{err}");
        }
    }

    #[test]
    fn a_signing_upstream_is_declared_not_inferred() {
        let t = ProxyTransport::resolve(&TransportConfig {
            signed_upstream: true,
            ..cfg("http://127.0.0.1:8080")
        })
        .unwrap();
        assert!(matches!(
            t,
            ProxyTransport::Tcp {
                auth: TcpAuth::SignedUpstream,
                ..
            }
        ));
        // Signed in two places is one too many.
        assert!(
            ProxyTransport::resolve(&TransportConfig {
                signed_upstream: true,
                auth_secret: Some("test-token-123"),
                ..cfg("http://127.0.0.1:8080")
            })
            .is_err()
        );
    }

    /// The runtime's variable is enough on its own: that is how the bridge is
    /// configured inside a pod.
    #[test]
    fn the_runtimes_door_url_selects_the_door_with_no_secret() {
        let t = ProxyTransport::resolve(&TransportConfig {
            proxy_url: None,
            tool_proxy_url: Some("unix:///run/nucleus-door/workload.sock"),
            ..cfg("")
        })
        .unwrap();
        let ProxyTransport::Door { socket } = &t else {
            panic!("expected the door, got {t:?}");
        };
        assert_eq!(socket, Path::new("/run/nucleus-door/workload.sock"));
        assert_eq!(t.base_url(), "http://localhost");
    }

    /// A secret handed to a door bridge is refused, not ignored.
    #[test]
    fn the_door_refuses_a_secret_it_would_not_use() {
        for (auth, approval) in [
            (Some("test-token-123"), None),
            (None, Some("test-token-123")),
        ] {
            assert!(
                ProxyTransport::resolve(&TransportConfig {
                    auth_secret: auth,
                    approval_secret: approval,
                    ..cfg("unix:///run/nucleus-door/workload.sock")
                })
                .is_err()
            );
        }
        assert!(
            ProxyTransport::resolve(&TransportConfig {
                signed_upstream: true,
                ..cfg("unix:///run/nucleus-door/workload.sock")
            })
            .is_err()
        );
    }

    #[test]
    fn two_urls_that_disagree_are_refused_and_none_is_refused() {
        assert!(
            ProxyTransport::resolve(&TransportConfig {
                tool_proxy_url: Some("unix:///run/nucleus-door/workload.sock"),
                auth_secret: Some("test-token-123"),
                ..cfg("http://127.0.0.1:8080")
            })
            .is_err()
        );
        assert!(
            ProxyTransport::resolve(&TransportConfig {
                proxy_url: None,
                ..cfg("")
            })
            .is_err()
        );
    }

    /// The host's `vsock://` form, which an old guest gave its workload, is
    /// refused by the shared parser rather than dialled as TCP.
    #[test]
    fn a_vsock_url_is_refused() {
        let err = ProxyTransport::resolve(&cfg("vsock://3:5000"))
            .expect_err("vsock is not dialable from inside the guest")
            .to_string();
        assert!(err.contains("vsock://3:5000"), "{err}");
    }
}
