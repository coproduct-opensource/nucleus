//! The guest halves of a link between pods (ADR 0017 L4c).
//!
//! **The guest decides nothing here and parses nothing.** ADR 0013's adversary
//! holds root in this guest, so anything the guest checked would be a check the
//! adversary can skip. Every decision — whether a link exists, whether this
//! request may cross it — is the host's (`LinkTable.lean`; the host relay of
//! L4b). These two halves only move bytes:
//!
//! - **Outbound.** The workload cannot open `AF_VSOCK` (its seccomp filter
//!   denies it), so the tool-proxy listens on loopback at [`LINK_PROXY_ADDR`],
//!   advertised to the workload as [`LINK_PROXY_ENV`]. Each connection is
//!   spliced to the host's `PodLink` listener (vsock CID 2, port 1030,
//!   `nucleus_ifc_kernel::VsockListener::PodLink`). The workload speaks HTTP
//!   proxy protocol on it (absolute-form `http://<link-name>:<port>/…`, or
//!   `CONNECT <link-name>:443` for TLS under ADR 0015 E3); the host reads that,
//!   not this code.
//! - **Inbound.** The tool-proxy listens on guest vsock port
//!   [`INBOUND_LINK_PORT`] for the host relay, admitting only peers whose CID
//!   is the host's ([`crate::pod_mgmt::peer_is_host`], a fact the guest kernel
//!   sets). The host sends one line, `PORT <n>\n`, naming the workload's local
//!   listener; the tool-proxy connects to `127.0.0.1:<n>` and splices. The line
//!   is the host's, not the source pod's: the host relay writes it after its
//!   own decision, so this half trusts the line exactly as far as it trusts the
//!   host, which is the whole of this design.
//!
//! **Severing.** When the host's side ends, both halves close at once (see
//! [`splice`]). That is how `unlink_severs` (`LinkTable.lean`) reaches the
//! guest: the host cuts its vsock end and the workload's connection goes with
//! it, instead of lingering half-open.

// The production callers (`start_in_guest`, vsock) are Linux-only, as in
// `pod_mgmt`; off Linux only the tests reach this module.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Where the workload reaches the outbound relay. 3128 is reserved for ADR
/// 0015's egress relay (E4); 3129 is the next port and is used by nothing else
/// in the guest.
pub(crate) const LINK_PROXY_ADDR: &str = "127.0.0.1:3129";

/// The environment variable that tells the workload [`LINK_PROXY_ADDR`], as an
/// HTTP proxy URL. Public runtime configuration (`workload.rs`
/// `PUBLIC_RESERVED`), never a credential.
pub(crate) const LINK_PROXY_ENV: &str = "NUCLEUS_LINK_PROXY";

/// The guest vsock port the host relay dials to deliver an inbound link
/// connection. Guest-side, so it shares no namespace with the host listeners
/// (1027–1030, 15012–15013); it must differ from the tool-proxy's own control
/// port, which the pod spec names (`spec.vsock.port`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const INBOUND_LINK_PORT: u32 = 1031;

/// The longest preamble line accepted, newline included: `PORT 65535\n` is 11.
const MAX_PREAMBLE: usize = 16;

/// Why an inbound connection was refused before any byte reached the workload.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InboundRefusal {
    /// The peer is not the host (a guest process over loopback, or any other).
    NotHost(u32),
    /// The preamble was not exactly `PORT <n>\n`.
    MalformedPreamble,
    /// `<n>` was outside 1..=65535.
    PortOutOfRange,
}

/// Parse the host's preamble line, without its newline.
pub(crate) fn parse_preamble(line: &[u8]) -> Result<u16, InboundRefusal> {
    let text = std::str::from_utf8(line).map_err(|_| InboundRefusal::MalformedPreamble)?;
    let digits = text
        .strip_prefix("PORT ")
        .ok_or(InboundRefusal::MalformedPreamble)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(InboundRefusal::MalformedPreamble);
    }
    let n: u32 = digits.parse().map_err(|_| InboundRefusal::PortOutOfRange)?;
    match u16::try_from(n) {
        Ok(p) if p >= 1 => Ok(p),
        _ => Err(InboundRefusal::PortOutOfRange),
    }
}

/// Read one preamble line byte by byte, so not one byte after the newline is
/// consumed (those belong to the workload).
async fn read_preamble<S: AsyncRead + Unpin>(host: &mut S) -> Result<u16, InboundRefusal> {
    let mut line = Vec::with_capacity(MAX_PREAMBLE);
    loop {
        let mut b = [0u8; 1];
        match host.read(&mut b).await {
            Ok(1) if b[0] == b'\n' => return parse_preamble(&line),
            Ok(1) if line.len() + 1 < MAX_PREAMBLE => line.push(b[0]),
            _ => return Err(InboundRefusal::MalformedPreamble),
        }
    }
}

/// Move bytes between the workload and the host until the host's side ends.
///
/// The host is authoritative: when its read side ends (it closed, or it cut
/// the link), both streams are dropped at once, so the workload sees the close
/// promptly. When only the workload stops sending, its half-close is passed on
/// and the host's answer still flows back, which is what an HTTP client that
/// shuts its write side expects.
pub(crate) async fn splice<W, H>(workload: W, host: H)
where
    W: AsyncRead + AsyncWrite + Unpin,
    H: AsyncRead + AsyncWrite + Unpin,
{
    let (mut wr, mut ww) = tokio::io::split(workload);
    let (mut hr, mut hw) = tokio::io::split(host);
    let down = async {
        let _ = tokio::io::copy(&mut hr, &mut ww).await;
        let _ = ww.shutdown().await;
    };
    let up = async {
        let _ = tokio::io::copy(&mut wr, &mut hw).await;
        let _ = hw.shutdown().await;
    };
    tokio::pin!(down, up);
    let mut up_done = false;
    loop {
        tokio::select! {
            _ = &mut down => break,
            _ = &mut up, if !up_done => up_done = true,
        }
    }
}

/// How the outbound half reaches the host's `PodLink` listener. A seam so the
/// splice is tested without vsock; production is [`VsockHost`].
pub(crate) trait DialHost: Clone + Send + Sync + 'static {
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn dial(&self) -> impl std::future::Future<Output = io::Result<Self::Io>> + Send;
}

/// Serve the outbound half: every workload connection on `listener` is spliced
/// to a fresh host connection. A failed dial closes the workload's connection.
pub(crate) async fn serve_outbound<D: DialHost>(listener: tokio::net::TcpListener, dial: D) {
    loop {
        let Ok((workload, _)) = listener.accept().await else {
            continue;
        };
        let dial = dial.clone();
        tokio::spawn(async move {
            match dial.dial().await {
                Ok(host) => splice(workload, host).await,
                Err(e) => {
                    tracing::warn!(error = %e, "link relay: host PodLink listener unreachable")
                }
            }
        });
    }
}

/// How the inbound half reaches the workload's local listener. A seam for tests.
pub(crate) trait DialWorkload: Clone + Send + Sync + 'static {
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;
    fn dial(&self, port: u16) -> impl std::future::Future<Output = io::Result<Self::Io>> + Send;
}

/// The workload's listeners, on loopback.
#[derive(Clone, Copy)]
pub(crate) struct Loopback;

impl DialWorkload for Loopback {
    type Io = tokio::net::TcpStream;
    async fn dial(&self, port: u16) -> io::Result<Self::Io> {
        tokio::net::TcpStream::connect(("127.0.0.1", port)).await
    }
}

/// Handle one inbound connection from `peer_cid`: admit only the host, read its
/// preamble, connect to the workload's port and splice. Returns why it was
/// refused, if it was; a refused connection is dropped, never answered.
pub(crate) async fn handle_inbound<H, D>(
    mut host: H,
    peer_cid: u32,
    workload: D,
) -> Result<(), InboundRefusal>
where
    H: AsyncRead + AsyncWrite + Unpin + Send,
    D: DialWorkload,
{
    if !crate::pod_mgmt::peer_is_host(peer_cid) {
        return Err(InboundRefusal::NotHost(peer_cid));
    }
    let port = read_preamble(&mut host).await?;
    match workload.dial(port).await {
        Ok(stream) => splice(stream, host).await,
        Err(e) => tracing::warn!(port, error = %e, "link relay: workload listener unreachable"),
    }
    Ok(())
}

/// Production: the host's `PodLink` listener over vsock.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(crate) struct VsockHost;

#[cfg(target_os = "linux")]
impl DialHost for VsockHost {
    type Io = tokio_vsock::VsockStream;
    async fn dial(&self) -> io::Result<Self::Io> {
        tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(
            crate::pod_mgmt::VMADDR_CID_HOST,
            nucleus_ifc_kernel::VsockListener::PodLink.port(),
        ))
        .await
    }
}

/// Bind both halves in a Firecracker guest. Bound before the workload starts,
/// so the address in [`LINK_PROXY_ENV`] is listening when the workload reads it.
#[cfg(target_os = "linux")]
pub(crate) async fn start_in_guest(guest_cid: u32) -> io::Result<()> {
    let outbound = tokio::net::TcpListener::bind(LINK_PROXY_ADDR).await?;
    tokio::spawn(serve_outbound(outbound, VsockHost));
    let inbound = tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(
        guest_cid,
        INBOUND_LINK_PORT,
    ))?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, addr)) = inbound.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                if let Err(refusal) = handle_inbound(stream, addr.cid(), Loopback).await {
                    tracing::warn!(?refusal, "link relay: inbound connection refused");
                }
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pod_mgmt::{VMADDR_CID_HOST, VMADDR_CID_LOCAL};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};
    use tokio::sync::Mutex;

    #[test]
    fn the_preamble_is_exactly_port_n() {
        assert_eq!(parse_preamble(b"PORT 8080"), Ok(8080));
        assert_eq!(parse_preamble(b"PORT 1"), Ok(1));
        assert_eq!(parse_preamble(b"PORT 65535"), Ok(65535));
        for bad in [
            &b"PORT"[..],
            b"PORT ",
            b"port 80",
            b"PORT 80 ",
            b"PORT +80",
            b"PORT -1",
            b"PORTS 80",
            b"PORT 8a",
        ] {
            assert_eq!(
                parse_preamble(bad),
                Err(InboundRefusal::MalformedPreamble),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_port_outside_the_range_is_refused() {
        assert_eq!(
            parse_preamble(b"PORT 0"),
            Err(InboundRefusal::PortOutOfRange)
        );
        assert_eq!(
            parse_preamble(b"PORT 65536"),
            Err(InboundRefusal::PortOutOfRange)
        );
        assert_eq!(
            parse_preamble(b"PORT 99999999999999999999"),
            Err(InboundRefusal::PortOutOfRange)
        );
    }

    /// The workload end of each inbound dial, kept so the test can talk to it.
    #[derive(Clone)]
    struct FakeWorkload {
        ends: Arc<Mutex<Vec<(u16, DuplexStream)>>>,
    }

    impl DialWorkload for FakeWorkload {
        type Io = DuplexStream;
        async fn dial(&self, port: u16) -> io::Result<Self::Io> {
            let (a, b) = duplex(1024);
            self.ends.lock().await.push((port, b));
            Ok(a)
        }
    }

    fn fake() -> FakeWorkload {
        FakeWorkload {
            ends: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[tokio::test]
    async fn a_non_host_peer_is_refused_and_reaches_nothing() {
        let w = fake();
        for cid in [VMADDR_CID_LOCAL, 3, 0] {
            let (h, mut p) = duplex(64);
            p.write_all(b"PORT 8080\n").await.unwrap();
            // Closed, so a handler that wrongly admitted the peer would dial,
            // splice to EOF and return Ok promptly, failing below, not hanging.
            drop(p);
            assert_eq!(
                handle_inbound(h, cid, w.clone()).await,
                Err(InboundRefusal::NotHost(cid))
            );
        }
        assert!(
            w.ends.lock().await.is_empty(),
            "no workload dial for a non-host peer"
        );
    }

    #[tokio::test]
    async fn a_malformed_or_out_of_range_preamble_is_refused() {
        for line in [
            &b"GET / HTTP/1.1\r\n"[..],
            b"PORT 0\n",
            b"PORT 70000\n",
            b"PORT 123456789012345\n",
        ] {
            let w = fake();
            let (host, mut peer) = duplex(64);
            peer.write_all(line).await.unwrap();
            assert!(
                handle_inbound(host, VMADDR_CID_HOST, w.clone())
                    .await
                    .is_err(),
                "{line:?}"
            );
            assert!(w.ends.lock().await.is_empty());
        }
        // A host that closes before the newline is refused too.
        let w = fake();
        let (host, mut peer) = duplex(64);
        peer.write_all(b"PORT 80").await.unwrap();
        drop(peer);
        assert_eq!(
            handle_inbound(host, VMADDR_CID_HOST, w).await,
            Err(InboundRefusal::MalformedPreamble)
        );
    }

    #[tokio::test]
    async fn inbound_bytes_are_spliced_both_ways_after_the_preamble() {
        let w = fake();
        let (host, mut peer) = duplex(1024);
        let task = tokio::spawn(handle_inbound(host, VMADDR_CID_HOST, w.clone()));
        // The request bytes follow the preamble in the same write: none may be lost.
        peer.write_all(b"PORT 8080\nGET / HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut end = loop {
            if let Some((port, s)) = w.ends.lock().await.pop() {
                assert_eq!(port, 8080);
                break s;
            }
            tokio::task::yield_now().await;
        };
        let mut got = [0u8; 18];
        end.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"GET / HTTP/1.1\r\n\r\n");
        end.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let mut back = [0u8; 19];
        peer.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"HTTP/1.1 200 OK\r\n\r\n");
        drop(peer);
        task.await.unwrap().unwrap();
    }

    /// `unlink_severs`, at the guest: the host cutting its end closes the
    /// workload's end, even while the workload is still idle and open.
    #[tokio::test]
    async fn a_closed_host_side_closes_the_workload_side() {
        let (workload, mut app) = duplex(64);
        let (host, cut) = duplex(64);
        let task = tokio::spawn(splice(workload, host));
        drop(cut);
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the splice ends promptly when the host cuts its end")
            .unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(
            app.read(&mut buf).await.unwrap(),
            0,
            "the workload sees EOF"
        );
        assert!(
            app.write_all(b"x").await.is_err(),
            "and cannot keep sending"
        );
    }

    /// The workload's half-close is passed on, and the host's answer still
    /// arrives: an HTTP client that shuts its write side is not cut off.
    #[tokio::test]
    async fn a_workload_half_close_still_gets_the_answer() {
        let (workload, mut app) = duplex(64);
        let (host, mut hostend) = duplex(64);
        let task = tokio::spawn(splice(workload, host));
        app.write_all(b"req").await.unwrap();
        app.shutdown().await.unwrap();
        let mut got = Vec::new();
        hostend.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"req");
        hostend.write_all(b"resp").await.unwrap();
        drop(hostend);
        let mut back = Vec::new();
        app.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"resp");
        task.await.unwrap();
    }

    #[derive(Clone)]
    struct FakeHost {
        ends: Arc<Mutex<Vec<DuplexStream>>>,
    }

    impl DialHost for FakeHost {
        type Io = DuplexStream;
        async fn dial(&self) -> io::Result<Self::Io> {
            let (a, b) = duplex(1024);
            self.ends.lock().await.push(b);
            Ok(a)
        }
    }

    #[tokio::test]
    async fn outbound_bytes_are_spliced_both_ways() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let host = FakeHost {
            ends: Arc::new(Mutex::new(Vec::new())),
        };
        tokio::spawn(serve_outbound(listener, host.clone()));
        let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"GET http://peer:80/ HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut end = loop {
            if let Some(s) = host.ends.lock().await.pop() {
                break s;
            }
            tokio::task::yield_now().await;
        };
        let mut got = [0u8; 32];
        end.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"GET http://peer:80/ HTTP/1.1\r\n\r\n");
        end.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            .await
            .unwrap();
        drop(end);
        let mut back = Vec::new();
        client.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"HTTP/1.1 403 Forbidden\r\n\r\n");
    }
}
