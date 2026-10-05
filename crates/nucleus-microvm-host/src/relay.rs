//! A TCP relay from a published container port to a pod's loopback proxy.
//!
//! # Why it exists
//!
//! The node hands each pod a tool proxy on an ephemeral `127.0.0.1` port inside
//! the host. When the host is an Apple `container`, macOS cannot reach that
//! port. `container exec -i` could carry MCP's stdio instead, but the spike
//! measured it wedging on full-duplex streams and ignoring `SIGTERM`
//! (`docs/findings/microvm-host-apple-container.md`, P5a). So the container is
//! started with a few ports published on the Mac's `127.0.0.1`, and for each
//! session one of these relays listens on one of them and forwards to that
//! session's pod proxy.
//!
//! # Lifetime
//!
//! A relay has no stop command. It stops by itself once its target refuses a
//! connection, which is what happens when the pod is deleted, so a relay that
//! outlives its session frees its port within one liveness interval.
//!
//! # Full duplex
//!
//! Each connection is two threads, one per direction, each blocking in
//! `io::copy`. Neither waits for the other, so a large response written while
//! the request is still arriving cannot stall the way `exec -i` did.

use std::io;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

/// Publish the exact bound listener and target for a fresh caller-owned attempt.
/// Taking the listener ensures a failed bind cannot announce readiness.
pub fn announce_bound(
    listener: &TcpListener,
    target: SocketAddr,
    path: &std::path::Path,
) -> io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    write!(file, "{}\n{target}\n", listener.local_addr()?)?;
    file.sync_all()
}

/// How long the relay waits for its target to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// How often an idle accept loop wakes up.
const ACCEPT_POLL: Duration = Duration::from_millis(50);

/// Why [`serve`] returned.
#[derive(Debug)]
pub enum RelayEnd {
    /// The target refused a connection, so its pod is gone.
    TargetGone,
    /// The listener failed.
    ListenerFailed(io::Error),
}

impl std::fmt::Display for RelayEnd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TargetGone => write!(f, "the target refused a connection; its pod is gone"),
            Self::ListenerFailed(e) => write!(f, "the listener failed: {e}"),
        }
    }
}

/// Relay every connection on `listener` to `target` until the target is gone.
///
/// `liveness` is how often the target is checked while no connection is
/// being accepted.
pub fn serve(listener: TcpListener, target: SocketAddr, liveness: Duration) -> RelayEnd {
    if let Err(e) = listener.set_nonblocking(true) {
        return RelayEnd::ListenerFailed(e);
    }
    let mut last_check = Instant::now();
    loop {
        match listener.accept() {
            Ok((client, _)) => {
                thread::spawn(move || {
                    // A failed connection ends that connection only. The next
                    // liveness check decides whether the target is gone.
                    let _ = relay_one(client, target);
                });
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return RelayEnd::ListenerFailed(e),
        }
        if last_check.elapsed() >= liveness {
            last_check = Instant::now();
            if target_is_gone(target) {
                return RelayEnd::TargetGone;
            }
        }
    }
}

/// Only a refusal means gone. A timeout is a slow target, not an absent one.
fn target_is_gone(target: SocketAddr) -> bool {
    matches!(
        TcpStream::connect_timeout(&target, CONNECT_TIMEOUT),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused
    )
}

fn relay_one(client: TcpStream, target: SocketAddr) -> io::Result<()> {
    // A socket accepted from a non-blocking listener is itself non-blocking on
    // BSD-derived systems, and `io::copy` would then spin on `WouldBlock`.
    client.set_nonblocking(false)?;
    let upstream = TcpStream::connect_timeout(&target, CONNECT_TIMEOUT)?;
    let (client_read, upstream_write) = (client.try_clone()?, upstream.try_clone()?);
    let up = thread::spawn(move || pump(client_read, upstream_write));
    pump(upstream, client);
    let _ = up.join();
    Ok(())
}

/// Copy one direction to EOF, then half-close the other side so the peer sees
/// the end of the stream while the opposite direction keeps flowing.
fn pump(mut from: TcpStream, mut to: TcpStream) {
    let _ = io::copy(&mut from, &mut to);
    let _ = to.shutdown(Shutdown::Write);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn readiness_names_the_owned_listener_and_preserves_existing_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attempt.ready");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let target = "127.0.0.1:4321".parse().unwrap();
        announce_bound(&listener, target, &path).unwrap();
        let expected = format!("{}\n{target}\n", listener.local_addr().unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
        assert!(announce_bound(&listener, target, &path).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), expected);
    }

    /// A server that echoes every byte back, one connection at a time.
    fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let addr = l.local_addr().expect("addr");
        thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(mut s) = conn else { return };
                thread::spawn(move || {
                    let mut r = s.try_clone().expect("clone");
                    let _ = io::copy(&mut r, &mut s);
                    let _ = s.shutdown(Shutdown::Write);
                });
            }
        });
        addr
    }

    fn start_relay(
        target: SocketAddr,
        liveness: Duration,
    ) -> (SocketAddr, thread::JoinHandle<RelayEnd>) {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind relay");
        let addr = l.local_addr().expect("addr");
        (addr, thread::spawn(move || serve(l, target, liveness)))
    }

    /// The failure `container exec -i` had: write 10 MiB while the echo is
    /// already coming back. A half-duplex relay deadlocks here.
    #[test]
    fn ten_mib_full_duplex_is_byte_exact() {
        let (relay, _h) = start_relay(echo_server(), Duration::from_secs(60));
        let payload: Vec<u8> = (0..10 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
        let mut s = TcpStream::connect(relay).expect("connect relay");
        s.set_read_timeout(Some(Duration::from_secs(30)))
            .expect("timeout");
        let mut w = s.try_clone().expect("clone");
        let sent = payload.clone();
        let writer = thread::spawn(move || {
            w.write_all(&sent).expect("write");
            w.shutdown(Shutdown::Write).expect("half close");
        });
        let mut back = Vec::new();
        s.read_to_end(&mut back).expect("read back");
        writer.join().expect("writer");
        assert_eq!(back.len(), payload.len());
        assert!(back == payload, "relayed bytes differ");
    }

    #[test]
    fn the_relay_stops_once_its_target_is_gone() {
        // Bind then drop: the port refuses connections from here on.
        let gone = TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr");
        let (_relay, h) = start_relay(gone, Duration::from_millis(100));
        let started = Instant::now();
        let end = h.join().expect("relay thread");
        assert!(matches!(end, RelayEnd::TargetGone), "{end}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_live_target_keeps_the_relay_up() {
        let (relay, h) = start_relay(echo_server(), Duration::from_millis(50));
        thread::sleep(Duration::from_millis(400));
        assert!(
            !h.is_finished(),
            "the relay stopped while its target was up"
        );
        let mut s = TcpStream::connect(relay).expect("connect");
        s.write_all(b"ping").expect("write");
        s.shutdown(Shutdown::Write).expect("half close");
        let mut back = String::new();
        s.read_to_string(&mut back).expect("read");
        assert_eq!(back, "ping");
    }
}
