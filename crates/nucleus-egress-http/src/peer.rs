//! Loopback admission: only a process running as this adapter's own uid may use
//! it.
//!
//! # Why the loopback hop needs a check at all
//!
//! The workload door admits a caller by the uid the kernel reports for it
//! (`SO_PEERCRED`), and only the workload's uid. This adapter runs as that uid,
//! so every request it relays reaches the door AS THE WORKLOAD. Without a check
//! of its own, a loopback listener would lend that identity to any process able
//! to connect to `127.0.0.1`: a confused deputy that turns "the kernel says
//! this is the workload" into "somebody on this host's loopback asked". So the
//! adapter asks the same question one hop earlier: which uid owns the socket at
//! the other end of this connection?
//!
//! # How, and why not `SO_PEERCRED`
//!
//! TCP has no `SO_PEERCRED`. The kernel does report every TCP socket's owning
//! uid in `/proc/net/tcp` (`sock_i_uid`, the same field `ss -e` prints), keyed
//! by the connection's four-tuple, for the reading process's own network
//! namespace. The peer's row is the one whose local address is the peer's
//! address and whose remote address is this listener's. That is the kernel's
//! word, as `SO_PEERCRED` is, read through a different interface.
//!
//! The adapter's own uid is read the same way, from its listening socket's row,
//! when it binds. Both sides of the comparison come from one table, so this
//! needs neither `libc` nor a uid passed in by configuration.
//!
//! # Fail closed
//!
//! A table that cannot be read, a peer that is not listed (it closed before it
//! was looked up), or a listener that cannot find itself are refusals, never
//! admissions: "could not look" is not "looked and it was fine" (ADR 0007 A-1).
//! On a system with no `/proc/net/tcp` the adapter cannot bind at all, which is
//! the right answer for a binary whose only home is a Linux guest.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

/// The kernel's per-namespace table of IPv4 TCP sockets.
const TCP_TABLE: &str = "/proc/net/tcp";

/// `/proc/net/tcp`'s state code for an established connection.
const ESTABLISHED: &str = "01";
/// ... and for a listening socket.
const LISTEN: &str = "0A";

/// Why a loopback connection was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerRefusal {
    /// The kernel's socket table could not be read.
    TableUnreadable(String),
    /// No established socket in the table is the other end of this connection.
    PeerNotListed(SocketAddr),
    /// The peer's socket is owned by a uid other than this adapter's.
    NotTheWorkload {
        /// The uid that owns the peer's socket.
        peer: u32,
        /// This adapter's uid, from its own listening socket.
        workload: u32,
    },
}

impl std::fmt::Display for PeerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TableUnreadable(why) => write!(
                f,
                "the kernel's TCP socket table could not be read ({why}); an unidentified peer is \
                 not the workload"
            ),
            Self::PeerNotListed(peer) => write!(
                f,
                "no socket owner is listed for peer {peer}; an unidentified peer is not the \
                 workload"
            ),
            Self::NotTheWorkload { peer, workload } => write!(
                f,
                "peer uid {peer} is not the workload's uid {workload}; this adapter relays for \
                 the workload alone"
            ),
        }
    }
}

/// One row of the table: the two endpoints, the state and the owning uid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row<'a> {
    local: SocketAddrV4,
    remote: SocketAddrV4,
    state: &'a str,
    uid: u32,
}

/// `0100007F:4E21` → `127.0.0.1:20001`. The address is the kernel's `%08X` of
/// a network-order word printed as a native integer, so its native-endian
/// bytes are the address's octets on any host; the port is plain hex.
fn endpoint(field: &str) -> Option<SocketAddrV4> {
    let (ip, port) = field.split_once(':')?;
    if ip.len() != 8 {
        return None;
    }
    let ip = u32::from_str_radix(ip, 16).ok()?;
    let port = u16::from_str_radix(port, 16).ok()?;
    Some(SocketAddrV4::new(Ipv4Addr::from(ip.to_ne_bytes()), port))
}

/// Every well-formed row. A malformed row is skipped: it cannot be the row
/// asked for, and skipping it can only make a lookup fail, never succeed.
fn rows(table: &str) -> impl Iterator<Item = Row<'_>> {
    table.lines().skip(1).filter_map(|line| {
        let mut fields = line.split_whitespace();
        let _slot = fields.next()?;
        let local = endpoint(fields.next()?)?;
        let remote = endpoint(fields.next()?)?;
        let state = fields.next()?;
        // tx_queue:rx_queue, tr:tm->when, retrnsmt, then uid.
        let uid = fields.nth(3)?.parse().ok()?;
        Some(Row {
            local,
            remote,
            state,
            uid,
        })
    })
}

/// The uid owning the listening socket at `local`.
fn listener_uid(table: &str, local: SocketAddrV4) -> Option<u32> {
    rows(table)
        .find(|r| r.state == LISTEN && r.local == local)
        .map(|r| r.uid)
}

/// The admission decision, over a snapshot of the table.
///
/// # Errors
/// [`PeerRefusal`] naming why the peer is not this adapter's uid.
fn admit(
    table: Result<String, String>,
    listener: SocketAddrV4,
    peer: SocketAddr,
    workload: u32,
) -> Result<(), PeerRefusal> {
    let table = table.map_err(PeerRefusal::TableUnreadable)?;
    let SocketAddr::V4(peer_v4) = peer else {
        return Err(PeerRefusal::PeerNotListed(peer));
    };
    let owner = rows(&table)
        .find(|r| r.state == ESTABLISHED && r.local == peer_v4 && r.remote == listener)
        .map(|r| r.uid)
        .ok_or(PeerRefusal::PeerNotListed(peer))?;
    if owner == workload {
        Ok(())
    } else {
        Err(PeerRefusal::NotTheWorkload {
            peer: owner,
            workload,
        })
    }
}

#[cfg(target_os = "linux")]
fn read_table() -> Result<String, String> {
    std::fs::read_to_string(TCP_TABLE).map_err(|e| format!("{TCP_TABLE}: {e}"))
}

#[cfg(not(target_os = "linux"))]
fn read_table() -> Result<String, String> {
    Err(format!(
        "{TCP_TABLE} exists only on Linux; this adapter cannot identify a loopback peer here"
    ))
}

/// A loopback listener that admits only connections from its own uid.
///
/// Constructed only by [`AdmittingListener::bind`], which reads the adapter's
/// uid from the kernel before any connection is accepted.
pub(crate) struct AdmittingListener {
    inner: tokio::net::TcpListener,
    local: SocketAddrV4,
    uid: u32,
}

impl AdmittingListener {
    /// Bind `address` and learn this process's uid from the listening
    /// socket's own row.
    ///
    /// # Errors
    /// The bind failed, the kernel bound something other than an IPv4
    /// address, or the listener could not find itself in the table.
    pub(crate) async fn bind(address: SocketAddrV4) -> Result<Self, String> {
        let inner = tokio::net::TcpListener::bind(address)
            .await
            .map_err(|e| format!("could not bind {address}: {e}"))?;
        let SocketAddr::V4(local) = inner
            .local_addr()
            .map_err(|e| format!("could not read the bound address: {e}"))?
        else {
            return Err("the listener is not an IPv4 socket".into());
        };
        let table = read_table()?;
        let uid = listener_uid(&table, local).ok_or_else(|| {
            format!(
                "the listener at {local} is not in {TCP_TABLE}, so its owner cannot be compared \
                 with a peer's; refusing to serve unidentified callers"
            )
        })?;
        Ok(Self { inner, local, uid })
    }

    /// The bound address.
    pub(crate) fn local(&self) -> SocketAddrV4 {
        self.local
    }
}

impl axum::serve::Listener for AdmittingListener {
    type Io = tokio::net::TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, peer)) => match admit(read_table(), self.local, peer, self.uid) {
                    Ok(()) => return (stream, peer),
                    Err(refusal) => {
                        eprintln!("nucleus-egress-http: refusing a connection: {refusal}");
                        drop(stream);
                    }
                },
                Err(err) => {
                    // Back off rather than spin on a persistent error (EMFILE).
                    eprintln!("nucleus-egress-http: accept error: {err}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(SocketAddr::V4(self.local))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTENER: &str = "127.0.0.1:18081";
    const PEER: &str = "127.0.0.1:40000";

    /// A table as the kernel prints it: the listener (uid 1000), the
    /// adapter's accepted end, the peer's end owned by `peer_uid`, and an
    /// unrelated root socket.
    fn table(peer_uid: u32) -> String {
        format!(
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
             \x20  0: 0100007F:46A1 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 101 1 0 100 0 0 10 0\n\
             \x20  1: 0100007F:46A1 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 102 1 0 20 4 30 10 -1\n\
             \x20  2: 0100007F:9C40 0100007F:46A1 01 00000000:00000000 00:00000000 00000000  {peer_uid:>4}        0 103 1 0 20 4 30 10 -1\n\
             \x20  3: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 104 1 0 100 0 0 10 0\n"
        )
    }

    fn listener() -> SocketAddrV4 {
        LISTENER.parse().unwrap()
    }

    #[test]
    fn the_kernels_encoding_reads_back_as_loopback() {
        assert_eq!(endpoint("0100007F:46A1"), Some(listener()));
        assert_eq!(endpoint("0100007F"), None);
        assert_eq!(endpoint("7F:46A1"), None);
    }

    #[test]
    fn the_listener_finds_its_own_uid() {
        assert_eq!(listener_uid(&table(0), listener()), Some(1000));
        assert_eq!(
            listener_uid(&table(0), "127.0.0.1:9".parse().unwrap()),
            None
        );
    }

    /// The control: a peer owned by the adapter's own uid is admitted.
    #[test]
    fn a_peer_running_as_the_workload_is_admitted() {
        assert_eq!(
            admit(Ok(table(1000)), listener(), PEER.parse().unwrap(), 1000),
            Ok(())
        );
    }

    /// **The confused deputy is closed.** A peer owned by any other uid —
    /// root included — would otherwise reach the door as the workload.
    #[test]
    fn a_peer_running_as_another_uid_is_refused_by_uid() {
        for other in [0, 65534, 1001] {
            assert_eq!(
                admit(Ok(table(other)), listener(), PEER.parse().unwrap(), 1000),
                Err(PeerRefusal::NotTheWorkload {
                    peer: other,
                    workload: 1000
                })
            );
        }
    }

    /// Could-not-look is a refusal, and so is a peer the table does not list.
    /// The adapter's OWN accepted end (local = listener) is not mistaken for
    /// the peer's.
    #[test]
    fn an_unidentified_peer_is_refused() {
        assert!(matches!(
            admit(Err("gone".into()), listener(), PEER.parse().unwrap(), 1000),
            Err(PeerRefusal::TableUnreadable(_))
        ));
        let elsewhere: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        assert_eq!(
            admit(Ok(table(1000)), listener(), elsewhere, 1000),
            Err(PeerRefusal::PeerNotListed(elsewhere))
        );
        let v6: SocketAddr = "[::1]:40000".parse().unwrap();
        assert_eq!(
            admit(Ok(table(1000)), listener(), v6, 1000),
            Err(PeerRefusal::PeerNotListed(v6))
        );
    }

    /// Against the real kernel: a connection from this test process (the
    /// same uid as the listener) is admitted through the live table, so the
    /// lookup is not vacuously refusing everything.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_live_table_admits_a_same_uid_peer() {
        use axum::serve::Listener as _;
        let mut listener = AdmittingListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = listener.local();
        let client = tokio::spawn(tokio::net::TcpStream::connect(address));
        let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .expect("a same-uid peer is admitted");
        let client = client.await.unwrap().unwrap();
        assert_eq!(accepted.1, client.local_addr().unwrap());
    }
}
