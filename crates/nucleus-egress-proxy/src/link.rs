//! Link mode (ADR 0017 L4b, proxy side): the same proxy, parser and decision
//! channel as egress, with one difference: the upstream is another pod.
//!
//! A source pod's workload names a link by host, through its guest relay
//! (L4c, `127.0.0.1:3129` in the guest, spliced to this proxy's vsock 1030
//! listener):
//!
//! ```text
//! GET http://<dst-uuid>.link.nucleus.invalid:<port>/path HTTP/1.1
//! CONNECT <dst-uuid>.link.nucleus.invalid:443 HTTP/1.1     (TLS, E3)
//! ```
//!
//! Each request is summarised and decided by the node exactly as an egress
//! request is (the summary's URL carries the destination pod and port). Only
//! then does the proxy look at its own routes, and it delivers only through
//! the kernel's extracted [`may_deliver`] — the connection is live AND the
//! host admitted this request — which `LinkTableExtracted.lean` proves equal
//! to `LinkTable.step (.request …)`.
//!
//! # Where an upstream comes from: the node, never the guest
//!
//! The proxy never builds a path from guest bytes. The node tells it, over a
//! one-way control channel ([`Control`]), which links this pod holds and,
//! for each, the destination pod's Firecracker vsock socket and the guest
//! port its relay listens on:
//!
//! ```text
//! LINK <dst-uuid> <port> <guest-port> <uds-path>
//! SEVER <dst-uuid> <port>
//! ```
//!
//! A link the node has not announced is not live, whatever the guest asks.
//! `SEVER` drops the route and closes every live connection on it at once
//! (ADR 0017 §3: unlink severs; exit drops). A control line that does not
//! parse fails closed: every route is dropped and every connection severed.
//!
//! # Why a separate channel, not a decision frame
//!
//! The decision channel is strictly request–answer, numbered
//! ([`crate::decision`]): an unsolicited frame there would be read as the
//! answer to the next question (`OutOfSequence`, and the channel poisoned).
//! Severing is the node speaking first, so it has its own one-way stream.
//!
//! # Upstream bytes
//!
//! To the destination: Firecracker's host-initiated vsock handshake
//! (`CONNECT <guest-port>\n`, then `OK …`), then the guest relay's preamble
//! `PORT <port>\n`, then the decided request re-serialised by the proxy in
//! origin form. Plain HTTP over vsock: TLS from the source, if any, ended at
//! this proxy (E3); the hop to the destination never crosses a network.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use nucleus_ifc_kernel::extracted::link::may_deliver;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::watch;

use crate::Refusal;
use crate::request::Host;

/// The suffix that makes a host a link name. `.invalid` (RFC 6761) never
/// resolves, so a link name can never reach the internet by accident.
pub const LINK_SUFFIX: &str = ".link.nucleus.invalid";

/// The longest control line accepted, newline included.
pub const MAX_CONTROL_LINE: usize = 4096;

/// How long the destination's vsock mux has to answer `CONNECT`.
pub const DIAL_DEADLINE: Duration = Duration::from_secs(5);

/// A link, as this source pod sees it: the destination pod and its port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkTarget {
    pub dst: u128,
    pub port: u16,
}

/// Where the node said a link's destination is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    /// The destination pod's Firecracker vsock socket on the host.
    pub uds: PathBuf,
    /// The guest port the destination's relay listens on (L4c: 1031).
    pub guest_port: u32,
}

/// A pod UUID in its canonical spelling, `8-4-4-4-12` lower-case hex.
#[must_use]
pub fn parse_uuid(s: &str) -> Option<u128> {
    let groups: Vec<&str> = s.split('-').collect();
    let lens = [8usize, 4, 4, 4, 12];
    if groups.len() != lens.len() {
        return None;
    }
    let mut hex = String::with_capacity(32);
    for (g, want) in groups.iter().zip(lens) {
        if g.len() != want || !g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return None;
        }
        hex.push_str(g);
    }
    u128::from_str_radix(&hex, 16).ok()
}

/// The canonical spelling of a pod UUID.
#[must_use]
pub fn uuid_string(id: u128) -> String {
    let h = format!("{id:032x}");
    let part = |a: usize, b: usize| h.get(a..b).unwrap_or_default().to_string();
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}

/// The destination pod a host names, if it is a link name.
#[must_use]
pub fn link_dst(host: &Host) -> Option<u128> {
    match host {
        Host::Name(name) => name.strip_suffix(LINK_SUFFIX).and_then(parse_uuid),
        Host::Ipv4(_) | Host::Ipv6(_) => None,
    }
}

/// The link name for a destination pod: the TLS name a source dials
/// (`CONNECT <name>:443`) and the leaf the link proxy mints for it.
#[must_use]
pub fn link_name(dst: u128) -> String {
    format!("{}{LINK_SUFFIX}", uuid_string(dst))
}

/// The subtree a pod CA must permit for a link proxy to terminate TLS: the
/// node mints every CA with it (`pod_ca`), and the guest's trust store accepts
/// a link leaf only under it. Which link a name is, is the table's decision.
pub const LINK_SUBTREE: &str = "link.nucleus.invalid";

/// TLS termination for a link proxy: leaves and verdicts only for announced
/// link names ([`Links::permits`]).
///
/// # Errors
/// A CA whose constraints do not include [`LINK_SUBTREE`] (a leaf it signed
/// for a link name would be refused by the guest's trust store, so the proxy
/// would mint what no client accepts), or a rustls configuration error.
pub fn termination(
    ca: crate::tls::PodCa,
    upstream_roots: rustls::RootCertStore,
    clock: fn() -> u64,
    links: &std::sync::Arc<Links>,
) -> Result<crate::tls::Termination, String> {
    if !ca.permits_subtree(LINK_SUBTREE) {
        return Err(format!(
            "the pod CA does not permit {LINK_SUBTREE}: it cannot vouch for a link name"
        ));
    }
    crate::tls::Termination::with_names(
        std::sync::Arc::new(ca),
        upstream_roots,
        clock,
        Links::permits(links),
    )
}

/// The destination a TLS name (an SNI, lower-cased) names, if it is a link name.
#[must_use]
pub fn link_dst_of_name(name: &str) -> Option<u128> {
    name.strip_suffix(LINK_SUFFIX).and_then(parse_uuid)
}

/// One line from the node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Control {
    Link(LinkTarget, Route),
    Sever(LinkTarget),
}

/// Why a control line was refused. Any of these fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    Shape,
    Uuid,
    Port,
    GuestPort,
    Path,
}

/// Parse one control line (without its newline). Total.
///
/// # Errors
/// The first [`ControlError`] found.
pub fn parse_control(line: &str) -> Result<Control, ControlError> {
    let mut words = line.split(' ');
    let verb = words.next().ok_or(ControlError::Shape)?;
    let dst = words
        .next()
        .and_then(parse_uuid)
        .ok_or(ControlError::Uuid)?;
    let port = words.next().and_then(port_of).ok_or(ControlError::Port)?;
    let target = LinkTarget { dst, port };
    match verb {
        "SEVER" => match words.next() {
            None => Ok(Control::Sever(target)),
            Some(_) => Err(ControlError::Shape),
        },
        "LINK" => {
            let guest_port = words
                .next()
                .and_then(canonical_u32)
                .filter(|p| *p != 0)
                .ok_or(ControlError::GuestPort)?;
            let path = words.next().ok_or(ControlError::Path)?;
            if words.next().is_some() {
                return Err(ControlError::Shape);
            }
            if !path.starts_with('/') || path.contains('\0') {
                return Err(ControlError::Path);
            }
            Ok(Control::Link(
                target,
                Route {
                    uds: PathBuf::from(path),
                    guest_port,
                },
            ))
        }
        _ => Err(ControlError::Shape),
    }
}

fn canonical_u32(w: &str) -> Option<u32> {
    let n: u32 = w.parse().ok()?;
    (n.to_string() == w).then_some(n)
}

fn port_of(w: &str) -> Option<u16> {
    canonical_u32(w)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|p| *p != 0)
}

/// The routes this pod holds, and a sever signal per route.
#[derive(Debug, Default)]
pub struct Links {
    routes: Mutex<BTreeMap<LinkTarget, (Route, watch::Sender<bool>)>>,
}

impl Links {
    /// Apply one control line.
    pub fn apply(&self, control: Control) {
        let Ok(mut routes) = self.routes.lock() else {
            return;
        };
        match control {
            Control::Link(target, route) => {
                let (tx, _rx) = watch::channel(false);
                if let Some((_, old)) = routes.insert(target, (route, tx)) {
                    // A re-announced link starts clean: anything riding the
                    // old route is closed, as on unlink.
                    let _ = old.send(true);
                }
            }
            Control::Sever(target) => {
                if let Some((_, tx)) = routes.remove(&target) {
                    let _ = tx.send(true);
                }
            }
        }
    }

    /// Drop every route and close every connection: the fail-closed answer
    /// to a control channel that broke or said something unparseable.
    pub fn sever_all(&self) {
        if let Ok(mut routes) = self.routes.lock() {
            for (_, (_, tx)) in std::mem::take(&mut *routes) {
                let _ = tx.send(true);
            }
        }
    }

    /// The route for `target` and a receiver that turns `true` when it is
    /// severed, if the node announced it.
    pub fn live(&self, target: LinkTarget) -> Option<(Route, watch::Receiver<bool>)> {
        let routes = self.routes.lock().ok()?;
        routes
            .get(&target)
            .map(|(route, tx)| (route.clone(), tx.subscribe()))
    }

    /// Whether the node has announced a live link to `dst` on any port.
    #[must_use]
    pub fn has_dst(&self, dst: u128) -> bool {
        self.routes
            .lock()
            .map(|r| r.keys().any(|t| t.dst == dst))
            .unwrap_or(false)
    }

    /// The link proxy's TLS name predicate (`tls::NamePermit`): a link name
    /// whose destination the node has announced a live `LINK` to. Consulted
    /// for the leaf and for the verdict, so a severed link stops minting too.
    #[must_use]
    pub fn permits(links: &std::sync::Arc<Links>) -> crate::tls::NamePermit {
        let links = std::sync::Arc::clone(links);
        std::sync::Arc::new(move |name: &str| {
            link_dst_of_name(name).is_some_and(|dst| links.has_dst(dst))
        })
    }

    /// How many links are live.
    pub fn len(&self) -> usize {
        self.routes.lock().map(|r| r.len()).unwrap_or(0)
    }

    /// Whether no link is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read control lines from the node until it closes the channel. A line
    /// that does not parse, a line too long, or the channel ending all sever
    /// everything: no answer is a denial (ADR 0014 §7).
    pub async fn follow<C: AsyncRead + Unpin>(&self, control: C) {
        let mut lines = BufReader::new(control);
        let mut line = Vec::with_capacity(256);
        loop {
            line.clear();
            let read = (&mut lines)
                .take(u64::try_from(MAX_CONTROL_LINE).unwrap_or(u64::MAX))
                .read_until(b'\n', &mut line)
                .await;
            let complete = matches!(read, Ok(n) if n > 0) && line.last() == Some(&b'\n');
            let parsed = complete
                .then(|| line.get(..line.len().saturating_sub(1)))
                .flatten()
                .and_then(|l| std::str::from_utf8(l).ok())
                .map(parse_control);
            match parsed {
                Some(Ok(c)) => self.apply(c),
                Some(Err(e)) => {
                    tracing::error!(error = ?e, "link control line refused; severing every link");
                    self.sever_all();
                    return;
                }
                None => {
                    tracing::warn!("link control channel ended; severing every link");
                    self.sever_all();
                    return;
                }
            }
        }
    }
}

/// Whether a decided request may be delivered: the kernel's extracted
/// predicate, nothing restated.
#[must_use]
pub fn deliverable(live: bool, host_admits: bool) -> bool {
    may_deliver(live, host_admits)
}

/// Dial a link's destination: Firecracker's vsock handshake to the relay's
/// guest port, then the relay's preamble naming the workload's port.
///
/// # Errors
/// [`Refusal::LinkUnreachable`] on any failure or past [`DIAL_DEADLINE`].
pub async fn dial(route: &Route, port: u16) -> Result<UnixStream, Refusal> {
    let attempt = async {
        let mut s = UnixStream::connect(&route.uds)
            .await
            .map_err(|_| Refusal::LinkUnreachable)?;
        s.write_all(format!("CONNECT {}\n", route.guest_port).as_bytes())
            .await
            .map_err(|_| Refusal::LinkUnreachable)?;
        // Read the mux's one-line answer byte by byte, so nothing past the
        // newline is consumed.
        let mut answer = Vec::with_capacity(32);
        loop {
            let b = s.read_u8().await.map_err(|_| Refusal::LinkUnreachable)?;
            if b == b'\n' {
                break;
            }
            answer.push(b);
            if answer.len() > 64 {
                return Err(Refusal::LinkUnreachable);
            }
        }
        if !answer.starts_with(b"OK ") {
            return Err(Refusal::LinkUnreachable);
        }
        s.write_all(format!("PORT {port}\n").as_bytes())
            .await
            .map_err(|_| Refusal::LinkUnreachable)?;
        Ok(s)
    };
    tokio::time::timeout(DIAL_DEADLINE, attempt)
        .await
        .map_err(|_| Refusal::LinkUnreachable)?
}

#[cfg(test)]
mod tests {
    use super::*;

    const U: &str = "0123abcd-0000-4000-8000-00000000beef";

    #[test]
    fn uuids_and_link_names_round_trip_in_one_spelling() {
        let id = parse_uuid(U).unwrap();
        assert_eq!(uuid_string(id), U);
        assert_eq!(link_name(id), format!("{U}{LINK_SUFFIX}"));
        assert_eq!(link_dst(&Host::Name(link_name(id))), Some(id));
        for bad in [
            "0123ABCD-0000-4000-8000-00000000beef",
            "0123abcd00004000800000000000beef",
            "0123abcd-0000-4000-8000-00000000bee",
            "0123abcd-0000-4000-8000-00000000beefg",
            "",
        ] {
            assert_eq!(parse_uuid(bad), None, "{bad}");
        }
        assert_eq!(link_dst(&Host::Name("api.test".into())), None);
        assert_eq!(
            link_dst(&Host::Name(format!("x.{U}{LINK_SUFFIX}"))),
            None,
            "one label, exactly"
        );
    }

    #[test]
    fn control_lines_parse_exactly() {
        let id = parse_uuid(U).unwrap();
        let t = LinkTarget { dst: id, port: 80 };
        assert_eq!(
            parse_control(&format!("SEVER {U} 80")),
            Ok(Control::Sever(t))
        );
        assert_eq!(
            parse_control(&format!("LINK {U} 80 1031 /run/pods/x/vsock.sock")),
            Ok(Control::Link(
                t,
                Route {
                    uds: "/run/pods/x/vsock.sock".into(),
                    guest_port: 1031
                }
            ))
        );
        for bad in [
            format!("LINK {U} 80 1031 relative/path"),
            format!("LINK {U} 0 1031 /p"),
            format!("LINK {U} 080 1031 /p"),
            format!("LINK {U} 80 0 /p"),
            format!("LINK {U} 80 1031 /p extra"),
            format!("SEVER {U} 80 extra"),
            format!("DROP {U} 80"),
            format!("LINK {U}  80 1031 /p"),
            "SEVER".to_string(),
        ] {
            assert!(parse_control(&bad).is_err(), "{bad}");
        }
    }

    #[tokio::test]
    async fn sever_signals_every_receiver_and_drops_the_route() {
        let links = Links::default();
        let t = LinkTarget {
            dst: parse_uuid(U).unwrap(),
            port: 80,
        };
        links.apply(Control::Link(
            t,
            Route {
                uds: "/p".into(),
                guest_port: 1031,
            },
        ));
        let (_, mut a) = links.live(t).unwrap();
        let (_, mut b) = links.live(t).unwrap();
        links.apply(Control::Sever(t));
        a.changed().await.unwrap();
        b.changed().await.unwrap();
        assert!(*a.borrow() && *b.borrow());
        assert!(links.live(t).is_none());
    }

    #[tokio::test]
    async fn a_bad_control_line_severs_everything() {
        let links = Links::default();
        let t = LinkTarget {
            dst: parse_uuid(U).unwrap(),
            port: 80,
        };
        let (mut node, proxy) = tokio::io::duplex(1024);
        node.write_all(format!("LINK {U} 80 1031 /p\n").as_bytes())
            .await
            .unwrap();
        node.write_all(b"garbage\n").await.unwrap();
        links.follow(proxy).await;
        assert!(links.is_empty());
        assert!(links.live(t).is_none());
    }
}
