use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Upper bound on the vsock CONNECT handshake (connect + request + `OK` line).
/// The guest is untrusted, so a hung or unresponsive peer must not be able to
/// wedge a bridge task forever. The post-handshake `copy_bidirectional` tunnel
/// is intentionally left unbounded — it is the long-lived data path.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long after a bridge opens a handshake EOF is still the guest starting up, rather than the
/// guest being absent.
///
/// Measured on the builder 2026-09-19 from the node's own `boot_trace`: `proxy.health_wait` has a
/// median of 2.1 s and a whole pod boot a median of 21.9 s, so a guest that has not answered
/// within thirty seconds is not slow. Deliberately generous: being wrong high costs one line at
/// DEBUG that should have been ERROR, and being wrong low restores the flood this replaces.
const GUEST_EXPECTED_UP: Duration = Duration::from_secs(30);

/// Whether a failed tunnel is the guest still coming up rather than the guest being absent.
///
/// Only an EOF, and only early. A handshake TIMEOUT is not a race: the guest's port accepted and
/// then said nothing for ten seconds, which is a different fact and keeps its ERROR whenever it
/// happens.
fn is_startup_race(err: &std::io::Error, bridge_age: Duration) -> bool {
    err.kind() == std::io::ErrorKind::UnexpectedEof && bridge_age < GUEST_EXPECTED_UP
}

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

pub struct VsockBridge {
    listen_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl std::fmt::Debug for VsockBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VsockBridge")
            .field("listen_addr", &self.listen_addr)
            .finish()
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl VsockBridge {
    pub async fn start(uds_path: PathBuf, guest_port: u32) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listen_addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        // When this bridge opened. A handshake EOF means the guest's vsock port answered with
        // nothing, and that has two causes of opposite severity: the guest has not started
        // listening YET, which is the ordinary startup race and resolves itself, or the guest is
        // GONE, which is what an over-admitted pod looks like when it dies. Both logged the same
        // ERROR with no port and no clock, so the second was invisible inside the first: 384 of
        // these in three hours on the builder, against 73 bridge shutdowns.
        let opened = std::time::Instant::now();

        let task = tokio::spawn(async move {
            // Tunnels are OWNED here, not spawned and forgotten. Shutdown used to stop
            // accepting and nothing else, so a tunnel already open kept carrying the
            // node's traffic into the guest after `cancel` had shut this bridge — until
            // the VMM's death closed the far end, which Firecracker's cancel reaches
            // only after network teardown. A tunnel is a byte stream with no frame
            // boundary to stop at, so shutdown aborts it.
            let mut tunnels = tokio::task::JoinSet::new();
            let shutdown_requested = loop {
                // Reap finished tunnels so the set is bounded by the live ones.
                while tunnels.try_join_next().is_some() {}
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        info!("vsock bridge shutting down");
                        break true;
                    }
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((stream, _)) => {
                                let uds = uds_path.clone();
                                tunnels.spawn(async move {
                                    if let Err(err) =
                                        handle_connection(stream, &uds, guest_port).await
                                    {
                                        let age_ms = opened.elapsed().as_millis() as u64;
                                        if is_startup_race(&err, opened.elapsed()) {
                                            debug!(
                                                guest_port,
                                                bridge_age_ms = age_ms,
                                                "vsock handshake EOF while the guest is still \
                                                 coming up"
                                            );
                                        } else {
                                            error!(
                                                guest_port,
                                                bridge_age_ms = age_ms,
                                                "vsock bridge connection error: {err}"
                                            );
                                        }
                                    }
                                });
                            }
                            Err(err) => {
                                error!("vsock bridge accept error: {err}");
                                break false;
                            }
                        }
                    }
                }
            };
            // An accept error ends ACCEPTING, as it always did — not the tunnels already
            // open, which run until they finish or shutdown is asked for.
            if !shutdown_requested {
                tokio::select! {
                    _ = &mut shutdown_rx => {}
                    _ = async { while tunnels.join_next().await.is_some() {} } => {}
                }
            }
            // Abort, and wait for the aborts to land: `shutdown` returning means no
            // tunnel is still open, which is what the teardown after it assumes.
            tunnels.shutdown().await;
        });

        Ok(Self {
            listen_addr,
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
async fn handle_connection(
    mut inbound: TcpStream,
    uds_path: &Path,
    guest_port: u32,
) -> std::io::Result<()> {
    // Bound the connect + handshake so an unresponsive guest cannot hang the
    // bridge task indefinitely (γ_bound). Only the handshake is guarded; the
    // tunnel below is deliberately unbounded.
    let mut vsock = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let mut vsock = UnixStream::connect(uds_path).await?;
        let connect_line = format!("CONNECT {guest_port}\n");
        vsock.write_all(connect_line.as_bytes()).await?;
        vsock.flush().await?;

        let mut response = Vec::new();
        loop {
            let mut buf = [0u8; 1];
            let read = vsock.read(&mut buf).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "vsock handshake EOF",
                ));
            }
            response.push(buf[0]);
            if buf[0] == b'\n' {
                break;
            }
            if response.len() > 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "vsock handshake too long",
                ));
            }
        }

        let response_str = String::from_utf8_lossy(&response);
        if !response_str.starts_with("OK ") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("vsock handshake failed: {response_str}"),
            ));
        }
        Ok::<UnixStream, std::io::Error>(vsock)
    })
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "vsock handshake timed out")
    })??;

    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut vsock).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    /// Firecracker's host-side vsock multiplexer, as far as the bridge can tell:
    /// answers `CONNECT <port>` with `OK <n>`, then echoes. Reports when the host
    /// side of each tunnel goes away.
    async fn fake_vsock_mux(path: &Path) -> tokio::sync::mpsc::UnboundedReceiver<()> {
        let listener = UnixListener::bind(path).expect("mux binds");
        let (closed_tx, closed_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let closed = closed_tx.clone();
                tokio::spawn(async move {
                    let mut line = Vec::new();
                    let mut b = [0u8; 1];
                    while s.read(&mut b).await.unwrap_or(0) == 1 {
                        line.push(b[0]);
                        if b[0] == b'\n' {
                            break;
                        }
                    }
                    if !line.starts_with(b"CONNECT ")
                        || s.write_all(b"OK 1073741824\n").await.is_err()
                    {
                        return;
                    }
                    let mut buf = [0u8; 256];
                    loop {
                        match s.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if s.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = closed.send(());
                });
            }
        });
        closed_rx
    }

    async fn echo(stream: &mut TcpStream, msg: &[u8]) -> std::io::Result<Vec<u8>> {
        stream.write_all(msg).await?;
        let mut got = vec![0u8; msg.len()];
        stream.read_exact(&mut got).await?;
        Ok(got)
    }

    #[tokio::test]
    async fn a_tunnel_carries_bytes_to_the_guest_port() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uds = dir.path().join("vsock.sock");
        let _closed = fake_vsock_mux(&uds).await;
        let bridge = VsockBridge::start(uds, 8080).await.expect("bridge");
        let mut client = TcpStream::connect(bridge.listen_addr())
            .await
            .expect("connect");
        assert_eq!(echo(&mut client, b"hello").await.expect("echo"), b"hello");
        bridge.shutdown().await;
    }

    /// Shutdown ends tunnels already established, not only new accepts. It used to
    /// stop the accept loop and nothing else: an open tunnel kept carrying the node's
    /// traffic into the guest's port after `cancel` had shut the bridge, until the
    /// VMM's death closed the other end — which on Firecracker's cancel comes after
    /// network teardown. The same shape as the workload API bridge's (#2930).
    #[tokio::test]
    async fn shutdown_ends_tunnels_already_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let uds = dir.path().join("vsock.sock");
        let mut closed = fake_vsock_mux(&uds).await;
        let bridge = VsockBridge::start(uds, 8080).await.expect("bridge");
        let mut client = TcpStream::connect(bridge.listen_addr())
            .await
            .expect("connect");
        // Non-vacuity: the tunnel is established and carrying bytes before shutdown.
        assert_eq!(echo(&mut client, b"before").await.expect("echo"), b"before");

        bridge.shutdown().await;

        // `shutdown` has returned, so the tunnel must already be gone at both ends —
        // not merely closing. Bounded only so a regression fails instead of hanging.
        let guest_side = tokio::time::timeout(Duration::from_secs(2), closed.recv()).await;
        assert!(
            matches!(guest_side, Ok(Some(()))),
            "the guest side of an open tunnel is still connected after shutdown"
        );
        let host_side =
            tokio::time::timeout(Duration::from_secs(2), echo(&mut client, b"after")).await;
        assert!(
            matches!(host_side, Ok(Err(_))),
            "an open tunnel still carried bytes after shutdown: {host_side:?}"
        );
    }
}


/// A handshake EOF is a startup race or a missing guest, and the two are told apart by the clock.
#[cfg(test)]
mod a_handshake_eof_means_two_things {
    use super::{GUEST_EXPECTED_UP, is_startup_race};
    use std::io::{Error, ErrorKind};
    use std::time::Duration;

    #[test]
    fn early_is_the_guest_starting_and_late_is_the_guest_gone() {
        let eof = || Error::new(ErrorKind::UnexpectedEof, "vsock handshake EOF");

        // The ordinary case: the pod is booting and its port is not listening yet. Measured
        // median pod boot on the builder is 21.9 s, so a second in is unremarkable.
        assert!(is_startup_race(&eof(), Duration::from_secs(1)));
        assert!(is_startup_race(&eof(), GUEST_EXPECTED_UP - Duration::from_millis(1)));

        // Past the window the same EOF is a guest that is not there -- what an over-admitted pod
        // looks like when it dies. This must stay at ERROR or the flood hides it again.
        assert!(!is_startup_race(&eof(), GUEST_EXPECTED_UP));
        assert!(!is_startup_race(&eof(), Duration::from_secs(600)));

        // A timeout is never a race, however early: the port answered and then went quiet.
        let timeout = Error::new(ErrorKind::TimedOut, "handshake timed out");
        assert!(!is_startup_race(&timeout, Duration::from_secs(1)));

        // Nor is a refusal, or a bad handshake response.
        assert!(!is_startup_race(
            &Error::new(ErrorKind::ConnectionRefused, "refused"),
            Duration::from_secs(1)
        ));
        assert!(!is_startup_race(
            &Error::new(ErrorKind::InvalidData, "vsock handshake failed: NO"),
            Duration::from_secs(1)
        ));
    }
}
