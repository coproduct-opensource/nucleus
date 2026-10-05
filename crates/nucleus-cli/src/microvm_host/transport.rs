//! How an agent on the Mac reaches a pod's tool proxy inside the host.
//!
//! # The design, and why
//!
//! The node gives each pod a proxy on an ephemeral `127.0.0.1` port inside
//! the container, and macOS cannot reach that. There were three options:
//!
//! - **`container exec -i nucleus-mcp`**, stdio through the CLI. Rejected: the
//!   spike measured it wedging on full-duplex streams and ignoring `SIGTERM`,
//!   and killing the client orphans the process inside (findings, P5a).
//! - **`--publish-socket` to a unix socket.** It would keep the proxy off TCP
//!   on the Mac, but `nucleus-mcp` speaks HTTP to a URL through `ureq`, which
//!   has no unix-socket transport, so it would need a new client transport.
//! - **Published TCP on `127.0.0.1`, relayed inside.** Chosen. The container is
//!   created with [`RELAY_PORTS`] published on the Mac's loopback only. For a
//!   session, `nucleus-hostctl relay` is started detached in one free slot and
//!   forwards to that pod's proxy. The agent's MCP server is then an unchanged
//!   `nucleus-mcp` on the Mac with `NUCLEUS_MCP_PROXY_URL` pointing at the slot.
//!   Nothing new on the MCP side, full duplex, and every `container` call it
//!   makes still has a deadline.
//!
//! # What that exposes
//!
//! A port on the Mac's `127.0.0.1` is reachable by every local process, not
//! only this user's. The node's signed proxy authenticates the pod to the
//! node, not the caller to the proxy, so for the session's lifetime another
//! local user could drive the pod's tools through that port. Under Lima the
//! same proxy was reachable by every process in the VM. A unix socket with
//! `0600` would close this, at the cost of a unix transport in `nucleus-mcp`.
//!
//! # Slots
//!
//! A slot is claimed by holding `relay-<n>.lock` in the host's state directory
//! for the session. The relay inside exits by itself once the pod's proxy
//! refuses a connection, so a slot whose session ended frees within a couple
//! of seconds even if the CLI crashed.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use nucleus_spec::microvm_host::{HOSTCTL, RELAY_PORTS, in_container_bin};

use super::container_cli::ContainerCli;
use super::lifecycle::MicroVmHost;

/// Why no endpoint was opened.
#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The node reported a proxy address that is not `http://127.0.0.1:<port>`.
    NotLoopback(String),
    /// Every relay slot is held by another session.
    NoFreeSlot,
    /// Starting the relay failed.
    RelayStart(String),
    /// The relay never passed a request through to the proxy.
    NotReachable(String),
    /// A lock file could not be opened.
    Lock(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLoopback(a) => write!(f, "pod proxy address {a:?} is not on loopback"),
            Self::NoFreeSlot => write!(
                f,
                "all {} relay slots are in use by other sessions",
                RELAY_PORTS.len()
            ),
            Self::RelayStart(e) => write!(f, "starting the relay: {e}"),
            Self::NotReachable(e) => {
                write!(f, "the pod proxy is not reachable through the relay: {e}")
            }
            Self::Lock(e) => write!(f, "relay slot lock: {e}"),
        }
    }
}

/// A session's way to the pod proxy. Dropping it releases the slot.
///
/// A lease on a relay slot, not a right: it authorizes nothing (see the module
/// docs on local exposure), so it is deliberately NOT `must_use`. `must_use`
/// on a `!Clone` type declares an affine right, which the `life` family then
/// expects to carry a validity bound (ADR 0007 C-5); a slot lock has none to
/// carry. `open` returns a `Result`, so discarding the call is still a warning.
#[derive(Debug)]
pub struct McpEndpoint {
    mac_port: u16,
    _slot: File,
}

impl McpEndpoint {
    /// What the Mac-side `nucleus-mcp` should use as `NUCLEUS_MCP_PROXY_URL`.
    pub fn proxy_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.mac_port)
    }

    /// The environment for a Mac-side `nucleus-mcp`.
    pub fn mcp_env(&self) -> Vec<(&'static str, String)> {
        vec![("NUCLEUS_MCP_PROXY_URL", self.proxy_url())]
    }
}

/// The in-container address of a pod proxy, from the node's `proxy_addr`.
/// Only loopback is accepted: the relay refuses anything else too.
pub fn proxy_target(proxy_addr: &str) -> Result<SocketAddr, TransportError> {
    let bare = proxy_addr
        .strip_prefix("http://")
        .unwrap_or(proxy_addr)
        .trim_end_matches('/');
    match bare.parse::<SocketAddr>() {
        Ok(a) if a.ip().is_loopback() => Ok(a),
        _ => Err(TransportError::NotLoopback(proxy_addr.to_string())),
    }
}

/// The argv that starts a relay for one slot, inside the container.
pub fn relay_argv(container_port: u16, target: SocketAddr) -> Vec<String> {
    vec![
        in_container_bin(HOSTCTL),
        "relay".into(),
        "--listen".into(),
        format!("0.0.0.0:{container_port}"),
        "--to".into(),
        target.to_string(),
    ]
}

/// Open a session's endpoint to the pod proxy at `proxy_addr` (as the node
/// reported it), and wait until a health request passes through.
pub fn open(
    cli: &ContainerCli,
    host: &MicroVmHost,
    proxy_addr: &str,
    ready: Duration,
) -> Result<McpEndpoint, TransportError> {
    let target = proxy_target(proxy_addr)?;
    let (slot, (container_port, mac_port)) = claim_slot(host)?;
    let ready_file = format!("/srv/state/relay-{}.ready", uuid::Uuid::new_v4());
    let expected = format!("0.0.0.0:{container_port}\n{target}\n");
    let mut argv = relay_argv(container_port, target);
    argv.extend(["--ready-file".into(), ready_file.clone()]);
    let argv: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = cli.exec_detached(host.container(), &argv);
    if !out.succeeded() {
        return Err(TransportError::RelayStart(out.describe()));
    }
    let started = Instant::now();
    let mut last = String::new();
    let mut bound = false;
    while started.elapsed() < ready {
        if !bound {
            let record = cli.exec(host.container(), &["/bin/cat", &ready_file]);
            if record.stdout() == Some(expected.as_str()) {
                let removed = cli.exec(host.container(), &["/bin/rm", "--", &ready_file]);
                if !removed.succeeded() {
                    return Err(TransportError::RelayStart(removed.describe()));
                }
                bound = true;
            } else {
                last = format!(
                    "new relay has not acknowledged its listener: {}",
                    record.describe()
                );
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        }
        match health_through(mac_port) {
            Ok(()) => {
                return Ok(McpEndpoint {
                    mac_port,
                    _slot: slot,
                });
            }
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(TransportError::NotReachable(last))
}

fn claim_slot(host: &MicroVmHost) -> Result<(File, (u16, u16)), TransportError> {
    for (n, ports) in host.relay_ports().iter().enumerate() {
        let path = host.state_dir().join(format!("relay-{n}.lock"));
        let file = File::create(&path)
            .map_err(|e| TransportError::Lock(format!("{}: {e}", path.display())))?;
        match file.try_lock() {
            Ok(()) => return Ok((file, *ports)),
            Err(std::fs::TryLockError::WouldBlock) => continue,
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(TransportError::Lock(format!("{}: {e}", path.display())));
            }
        }
    }
    Err(TransportError::NoFreeSlot)
}

/// One `GET /v1/health` through the relay. HTTP/1.0 and a raw socket, so
/// there is no client library between the check and the bytes.
fn health_through(mac_port: u16) -> Result<(), String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], mac_port));
    let mut s =
        TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    s.write_all(b"GET /v1/health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut head = [0u8; 12];
    s.read_exact(&mut head).map_err(|e| e.to_string())?;
    let status = String::from_utf8_lossy(&head);
    if status.starts_with("HTTP/1.") && status.ends_with(" 200") {
        Ok(())
    } else {
        Err(format!("got {status:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn only_a_loopback_proxy_is_a_target() {
        assert_eq!(
            proxy_target("http://127.0.0.1:34567"),
            Ok(SocketAddr::from(([127, 0, 0, 1], 34567)))
        );
        assert!(proxy_target("127.0.0.1:1/").is_ok());
        for bad in [
            "http://10.0.0.2:80",
            "http://0.0.0.0:80",
            "http://example:80",
            "",
        ] {
            assert!(
                matches!(proxy_target(bad), Err(TransportError::NotLoopback(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_relay_listens_on_the_slot_and_forwards_to_the_pod() {
        let argv = relay_argv(7102, SocketAddr::from(([127, 0, 0, 1], 40404))).join(" ");
        assert_eq!(
            argv,
            "/usr/local/bin/nucleus-hostctl relay --listen 0.0.0.0:7102 --to 127.0.0.1:40404"
        );
    }

    /// A proxy stand-in that answers one health request with `status`.
    fn one_shot_server(status: &'static str) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = l.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let mut buf = [0u8; 256];
                let _ = s.read(&mut buf);
                let _ = s.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes());
            }
        });
        port
    }

    #[test]
    fn health_passes_only_on_200() {
        assert_eq!(health_through(one_shot_server("200 OK")), Ok(()));
        assert!(health_through(one_shot_server("503 Service Unavailable")).is_err());
        let closed = TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port();
        assert!(health_through(closed).is_err());
    }
}
