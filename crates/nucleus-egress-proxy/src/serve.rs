//! One guest connection: read one request, ask the node, perform what it
//! allowed, relay the answer, close.
//!
//! The order is the point (ADR 0007 D-1, one function, top to bottom):
//!
//! 1. **parse** the head the guest sent ([`crate::request`]), bounded in size
//!    and in time, and read its `Content-Length` body;
//! 2. **ask** the node about the request's canonical summary
//!    ([`crate::decision`]); anything but an allow refuses, and no answer is
//!    a refusal;
//! 3. **resolve** the name on the host ([`crate::resolve`]) and **admit** the
//!    addresses ([`crate::address`]);
//! 4. **connect** to an admitted address and forward exactly the request
//!    that was decided, re-serialised by the proxy, never the guest's bytes;
//! 5. **relay** the upstream's response and close.
//!
//! One request per connection (`connection: close` both ways), so a request
//! the node did not decide can never ride behind one it did.
//!
//! # `CONNECT` (E3)
//!
//! With a pod CA ([`crate::tls::Termination`]), a `CONNECT host:port` whose
//! next bytes are a TLS ClientHello is terminated: the proxy answers `200`,
//! completes TLS with a leaf it mints for the TLS name, reads ONE request in
//! clear, and takes it through steps 2–5 above, upstream over TLS. Each
//! handshake ends in one kernel [`TlsVerdict`] and is journalled with its TLS
//! name. Without a CA, `CONNECT` is refused as in E2. Nothing is tunnelled
//! opaquely: a handshake the client abandons is refused, never forwarded.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use ipnet::IpNet;
use nucleus_ifc_kernel::extracted::tls::TlsVerdict;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::Semaphore;

use crate::Refusal;
use crate::address::admit;
use crate::decision::{Decided, HostAnswer, SharedDecider};
use crate::link::{LinkTarget, Links, deliverable, dial, link_dst};
use crate::request::{
    ConnectParsed, Host, MAX_HEAD, Method, Origin, Parsed, Request, Scheme, parse_connect_head,
    parse_head, parse_head_tunnelled,
};
use crate::resolve::{NoOutboundPath, Resolve};
use crate::summary::{Summary, digest};
use crate::tls::Termination;

/// The most guest connections one pod's proxy serves at once (ADR 0015
/// §10). The next one is refused with [`Refusal::TooManyConnections`].
pub const MAX_CONNECTIONS: usize = 64;

/// How long the guest has to send its whole head and body.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

/// How long the proxy tries to reach an admitted address.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(5);

/// How long one link exchange may run once its request is delivered (ADR 0017).
/// A destination that never closes its end would otherwise hold one of the
/// source pod's [`MAX_CONNECTIONS`] slots forever: found on the x86 gauntlet
/// (2026-11-19), where 63 of 200 linked requests were delivered before the
/// slots ran out. This is the backstop; the guest relay closing on the
/// server's end-of-stream is the fix.
pub const LINK_EXCHANGE_DEADLINE: Duration = Duration::from_secs(30);

/// How many terminated handshakes the journal keeps (oldest dropped first).
pub const TLS_JOURNAL_LEN: usize = 1024;

/// The first byte of a TLS record carrying a handshake.
const TLS_HANDSHAKE_RECORD: u8 = 0x16;

/// One terminated handshake, as journalled: the TLS name the client sent (if
/// any) and the kernel's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsRecord {
    pub sni: Option<String>,
    pub verdict: TlsVerdict,
}

/// One pod's proxy.
pub struct Proxy<D, R> {
    decider: SharedDecider<D>,
    resolver: R,
    floor: Vec<IpNet>,
    slots: Arc<Semaphore>,
    tls: Option<Arc<Termination>>,
    journal: Mutex<VecDeque<TlsRecord>>,
    /// Link mode (ADR 0017 L4b): the routes the node announced. `None` is
    /// the egress proxy, where a link name is refused.
    links: Option<Arc<Links>>,
    /// [`LINK_EXCHANGE_DEADLINE`], shortened in tests.
    link_exchange: Duration,
}

/// What a connection ended in, for the log and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The decided request was sent upstream and its response relayed.
    Forwarded,
    /// Refused, with the reason the guest was told.
    Refused(Refusal),
}

/// How `handle` ended when it did not forward.
enum Stop {
    /// Tell the guest, in clear.
    Refuse(Refusal),
    /// Already told (inside TLS) or cannot be told (a failed handshake).
    Told(Refusal),
}

impl From<Refusal> for Stop {
    fn from(r: Refusal) -> Self {
        Stop::Refuse(r)
    }
}

/// A head the guest sent: a proxy request with its body, or a `CONNECT`.
enum Head {
    Request(Request, Vec<u8>),
    Connect(Origin, Vec<u8>),
}

impl<D, R> Proxy<D, R>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: Resolve,
{
    /// A proxy that asks `decider`, resolves with `resolver`, and never
    /// connects into `floor` (the node's deny floor).
    pub fn new(decider: SharedDecider<D>, resolver: R, floor: Vec<IpNet>) -> Self {
        Self {
            decider,
            resolver,
            floor,
            slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            tls: None,
            journal: Mutex::new(VecDeque::new()),
            links: None,
            link_exchange: LINK_EXCHANGE_DEADLINE,
        }
    }

    /// The same proxy, terminating `CONNECT` with the pod's CA (E3).
    #[must_use]
    pub fn with_tls(mut self, termination: Termination) -> Self {
        self.tls = Some(Arc::new(termination));
        self
    }

    /// The terminated handshakes so far, oldest first.
    pub fn tls_journal(&self) -> Vec<TlsRecord> {
        self.journal
            .lock()
            .map(|j| j.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn record(&self, sni: Option<String>, verdict: TlsVerdict) {
        tracing::info!(sni = ?sni, verdict = ?verdict, "egress tls handshake");
        if let Ok(mut j) = self.journal.lock() {
            if j.len() >= TLS_JOURNAL_LEN {
                j.pop_front();
            }
            j.push_back(TlsRecord { sni, verdict });
        }
    }

    /// Accept guest connections on `listener` until the process ends.
    pub async fn serve(self: Arc<Self>, listener: UnixListener) {
        loop {
            let guest = match listener.accept().await {
                Ok((guest, _)) => guest,
                Err(e) => {
                    tracing::warn!(error = %e, "egress proxy accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let proxy = Arc::clone(&self);
            tokio::spawn(async move {
                let served = proxy.connection(guest).await;
                tracing::info!(outcome = ?served, "egress request");
            });
        }
    }

    /// Serve one guest connection, holding one of the pod's connection
    /// slots for its whole life.
    pub async fn connection<G: AsyncRead + AsyncWrite + Unpin>(&self, mut guest: G) -> Served {
        let Ok(_slot) = Arc::clone(&self.slots).try_acquire_owned() else {
            return refuse(&mut guest, Refusal::TooManyConnections).await;
        };
        match self.handle(&mut guest).await {
            Ok(()) => Served::Forwarded,
            Err(Stop::Refuse(refusal)) => refuse(&mut guest, refusal).await,
            Err(Stop::Told(refusal)) => {
                let _ = guest.shutdown().await;
                Served::Refused(refusal)
            }
        }
    }

    async fn handle<G: AsyncRead + AsyncWrite + Unpin>(&self, guest: &mut G) -> Result<(), Stop> {
        // 1. parse
        let tls = self.tls.is_some();
        let head = tokio::time::timeout(REQUEST_DEADLINE, read_head(guest, tls))
            .await
            .map_err(|_| Refusal::HeadTimeout)??;
        match head {
            Head::Request(request, body) => {
                self.decide_and_forward(&request, &body, guest, None)
                    .await?;
                Ok(())
            }
            Head::Connect(origin, early) => self.tunnel(guest, origin, early).await,
        }
    }

    /// Steps 2–5 for one parsed request. `tls_name` is the name to verify
    /// upstream when the request came through a terminated tunnel.
    async fn decide_and_forward<G: AsyncRead + AsyncWrite + Unpin>(
        &self,
        request: &Request,
        body: &[u8],
        guest: &mut G,
        tls_name: Option<&str>,
    ) -> Result<(), Refusal> {
        // Which path this request may take is fixed by the proxy's mode
        // before anyone is asked: a link name only through the link proxy,
        // and the link proxy only to link names.
        let link = link_dst(&request.origin.host).map(|dst| LinkTarget {
            dst,
            port: request.origin.port,
        });
        match (&self.links, link) {
            (None, Some(_)) => return Err(Refusal::LinkNotHere),
            (Some(_), None) => return Err(Refusal::NotALink),
            (None, None) | (Some(_), Some(_)) => {}
        }
        // 2. ask
        let summary = Summary::of(request, body);
        let subject = summary.subject()?;
        let answer = self.decider.decide(subject, digest(&summary.text())).await;
        if let (Some(links), Some(target)) = (&self.links, link) {
            return self
                .deliver_link(links, target, answer, request, body, guest)
                .await;
        }
        // Exhaustive, no `_` arm (ADR 0007 B-3): only an allow continues.
        match answer {
            HostAnswer::Verdict(Decided::Allowed) => {}
            HostAnswer::Verdict(Decided::Denied(reason)) => return Err(Refusal::Denied(reason)),
            HostAnswer::Verdict(Decided::ApprovalRequired) => {
                return Err(Refusal::ApprovalRequired);
            }
            HostAnswer::Unreachable(why) => return Err(Refusal::HostUnavailable(why)),
        }
        // 3. resolve and admit
        let host = &request.origin.host;
        let resolved: Vec<IpAddr> = match host {
            Host::Name(name) => self.resolver.resolve(name).await?,
            Host::Ipv4(a) => vec![IpAddr::V4(*a)],
            Host::Ipv6(a) => vec![IpAddr::V6(*a)],
        };
        let admitted = admit(host, &resolved, &self.floor)?;
        // 4. connect and forward what was decided
        let tcp = connect(&admitted, request.origin.port).await?;
        let bytes = upstream_request(request, body);
        // 5. relay. The response is past the decision: an error from here on
        // ends the connection, it does not become a refusal the guest could
        // read as part of the upstream's answer.
        match (request.origin.scheme, tls_name, &self.tls) {
            (Scheme::Https, Some(name), Some(t)) => {
                let mut upstream = upstream_tls(tcp, name, t).await?;
                upstream
                    .write_all(&bytes)
                    .await
                    .map_err(|_| Refusal::UpstreamUnreachable)?;
                let _ = tokio::io::copy(&mut upstream, guest).await;
            }
            (Scheme::Http, None, _) => {
                let mut upstream = tcp;
                upstream
                    .write_all(&bytes)
                    .await
                    .map_err(|_| Refusal::UpstreamUnreachable)?;
                let _ = tokio::io::copy(&mut upstream, guest).await;
            }
            // An https origin outside a terminated tunnel, or a tunnelled
            // request without a CA: no path that was decided for it.
            _ => return Err(Refusal::UpstreamUnreachable),
        }
        let _ = guest.shutdown().await;
        Ok(())
    }

    /// Steps 3–5 in link mode: deliver a decided request to another pod, only
    /// through the kernel's `may_deliver(connection_live, host_admits)`.
    async fn deliver_link<G: AsyncRead + AsyncWrite + Unpin>(
        &self,
        links: &Links,
        target: LinkTarget,
        answer: HostAnswer,
        request: &Request,
        body: &[u8],
        guest: &mut G,
    ) -> Result<(), Refusal> {
        let host_admits = matches!(answer, HostAnswer::Verdict(Decided::Allowed));
        let live = links.live(target);
        if !deliverable(live.is_some(), host_admits) {
            // Say why: the node's refusal if it refused, else the link.
            // Exhaustive, no `_` arm (ADR 0007 B-3).
            return Err(match answer {
                HostAnswer::Verdict(Decided::Denied(reason)) => Refusal::Denied(reason),
                HostAnswer::Verdict(Decided::ApprovalRequired) => Refusal::ApprovalRequired,
                HostAnswer::Unreachable(why) => Refusal::HostUnavailable(why),
                HostAnswer::Verdict(Decided::Allowed) => Refusal::LinkNotLive,
            });
        }
        let Some((route, severed)) = live else {
            return Err(Refusal::LinkNotLive);
        };
        let mut upstream = dial(&route, target.port).await?;
        upstream
            .write_all(&upstream_request(request, body))
            .await
            .map_err(|_| Refusal::LinkUnreachable)?;
        // Past the decision: a sever ends the exchange at once, mid-response
        // included (ADR 0017 §3). The guest stream is borrowed, so the sever
        // is a signal raced against the relay rather than a task to abort.
        let exchange = async {
            tokio::select! {
                _ = tokio::io::copy(&mut upstream, &mut *guest) => {}
                () = until_severed(severed) => {
                    tracing::info!(dst = %crate::link::uuid_string(target.dst), port = target.port, "link severed mid-exchange");
                }
            }
        };
        if tokio::time::timeout(self.link_exchange, exchange)
            .await
            .is_err()
        {
            tracing::info!(dst = %crate::link::uuid_string(target.dst), port = target.port, "link exchange deadline: the destination did not close");
        }
        drop(upstream);
        let _ = guest.shutdown().await;
        Ok(())
    }

    /// A terminated `CONNECT` (E3).
    async fn tunnel<G: AsyncRead + AsyncWrite + Unpin>(
        &self,
        guest: &mut G,
        connect_origin: Origin,
        early: Vec<u8>,
    ) -> Result<(), Stop> {
        let Some(t) = self.tls.clone() else {
            return Err(Refusal::Connect.into());
        };
        guest
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await
            .map_err(|_| Stop::Told(Refusal::Incomplete))?;
        let mut first = early;
        if first.is_empty() {
            let mut b = [0u8; 1];
            let n = tokio::time::timeout(REQUEST_DEADLINE, guest.read(&mut b))
                .await
                .map_err(|_| Refusal::HeadTimeout)?
                .map_err(|_| Refusal::Incomplete)?;
            first.extend_from_slice(b.get(..n).unwrap_or_default());
        }
        if first.first() != Some(&TLS_HANDSHAKE_RECORD) {
            return Err(Refusal::NotTls.into());
        }
        let stream = Prefixed {
            prefix: first,
            at: 0,
            inner: guest,
        };
        let start = tokio::time::timeout(
            REQUEST_DEADLINE,
            tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream),
        )
        .await
        .map_err(|_| Stop::Told(Refusal::HeadTimeout))?
        .map_err(|_| Stop::Told(Refusal::NotTls))?;
        let sni = start
            .client_hello()
            .server_name()
            .map(str::to_ascii_lowercase);
        let now = (t.clock)();
        let mut tls =
            match tokio::time::timeout(REQUEST_DEADLINE, start.into_stream(Arc::clone(&t.server)))
                .await
            {
                Ok(Ok(tls)) => tls,
                // The handshake did not complete: the kernel says why, in the
                // model's order (no CA or expired, name, then the client).
                Ok(Err(_)) | Err(_) => {
                    let verdict = t.verdict(now, sni.as_deref(), false, true);
                    self.record(sni, verdict);
                    return Err(Stop::Told(refusal_for(verdict)));
                }
            };
        let read = tokio::time::timeout(REQUEST_DEADLINE, read_tunnelled(&mut tls)).await;
        let (request, body) = match read {
            Ok(Ok(rb)) => rb,
            Ok(Err(refusal)) => {
                let _ = tls.write_all(&refusal.response()).await;
                let _ = tls.shutdown().await;
                return Err(Stop::Told(refusal));
            }
            Err(_) => {
                let _ = tls.write_all(&Refusal::HeadTimeout.response()).await;
                let _ = tls.shutdown().await;
                return Err(Stop::Told(Refusal::HeadTimeout));
            }
        };
        let agree = sni.as_deref().is_some_and(|name| {
            connect_origin.host == Host::Name(name.to_string()) && request.origin == connect_origin
        });
        let verdict = t.verdict(now, sni.as_deref(), true, agree);
        self.record(sni.clone(), verdict);
        let outcome = match (verdict, sni.as_deref()) {
            (TlsVerdict::Decided, Some(name)) => {
                self.decide_and_forward(&request, &body, &mut tls, Some(name))
                    .await
            }
            (verdict, _) => Err(refusal_for(verdict)),
        };
        match outcome {
            Ok(()) => Ok(()),
            Err(refusal) => {
                let _ = tls.write_all(&refusal.response()).await;
                let _ = tls.shutdown().await;
                Err(Stop::Told(refusal))
            }
        }
    }
}

/// Resolves once the route is severed. A sender that went away without
/// saying so counts as severed: no answer is a denial.
async fn until_severed(mut severed: tokio::sync::watch::Receiver<bool>) {
    loop {
        if *severed.borrow_and_update() {
            return;
        }
        if severed.changed().await.is_err() {
            return;
        }
    }
}

impl<D> Proxy<D, NoOutboundPath>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    /// The link proxy (ADR 0017 L4b): decides through `decider`, delivers
    /// only to the routes `links` holds. It has no resolver and no address
    /// path: a link name is the only upstream it knows.
    pub fn link(decider: SharedDecider<D>, links: Arc<Links>) -> Self {
        let mut proxy = Proxy::new(decider, NoOutboundPath, Vec::new());
        proxy.links = Some(links);
        proxy
    }

    /// A shorter [`LINK_EXCHANGE_DEADLINE`], for tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_link_exchange(mut self, deadline: Duration) -> Self {
        self.link_exchange = deadline;
        self
    }
}

/// The guest-facing refusal for a TLS verdict. `Decided` is never refused;
/// mapping it to [`Refusal::Malformed`] keeps the match exhaustive without a
/// `_` arm, and `tunnel` never passes it here.
fn refusal_for(verdict: TlsVerdict) -> Refusal {
    match verdict {
        TlsVerdict::RefusedExpired => Refusal::TlsExpired,
        TlsVerdict::RefusedNameNotPermitted => Refusal::TlsNameNotPermitted,
        TlsVerdict::RefusedClientRejected => Refusal::ClientRejectedInterception,
        TlsVerdict::RefusedFronting => Refusal::Fronting,
        TlsVerdict::Decided => Refusal::Malformed,
    }
}

/// The upstream TLS client: rustls, the configured roots, hostname `name`.
async fn upstream_tls(
    tcp: TcpStream,
    name: &str,
    t: &Termination,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, Refusal> {
    let server_name =
        ServerName::try_from(name.to_string()).map_err(|_| Refusal::UpstreamUnreachable)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::clone(&t.upstream));
    tokio::time::timeout(CONNECT_DEADLINE, connector.connect(server_name, tcp))
        .await
        .map_err(|_| Refusal::UpstreamUnreachable)?
        .map_err(|_| Refusal::UpstreamUnreachable)
}

/// The guest stream with the bytes already read put back in front.
struct Prefixed<'a, G> {
    prefix: Vec<u8>,
    at: usize,
    inner: &'a mut G,
}

impl<G: AsyncRead + Unpin> AsyncRead for Prefixed<'_, G> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if let Some(rest) = this.prefix.get(this.at..).filter(|r| !r.is_empty()) {
            let n = rest.len().min(buf.remaining());
            buf.put_slice(rest.get(..n).unwrap_or_default());
            this.at = this.at.saturating_add(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

impl<G: AsyncWrite + Unpin> AsyncWrite for Prefixed<'_, G> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

/// Read one head: a proxy request and its body, or (only with a CA) a
/// `CONNECT` and any bytes the guest sent after it.
async fn read_head<G: AsyncRead + Unpin>(guest: &mut G, tls: bool) -> Result<Head, Refusal> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = guest
            .read(&mut chunk)
            .await
            .map_err(|_| Refusal::Incomplete)?;
        if n == 0 {
            return Err(Refusal::Incomplete);
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
        match parse_head(&buf) {
            Err(Refusal::Connect) if tls => match parse_connect_head(&buf)? {
                ConnectParsed::Partial => {}
                ConnectParsed::Complete { origin, head_len } => {
                    return Ok(Head::Connect(origin, buf.split_off(head_len)));
                }
            },
            Err(refusal) => return Err(refusal),
            Ok(Parsed::Partial) if buf.len() >= MAX_HEAD => return Err(Refusal::HeadersTooLarge),
            Ok(Parsed::Partial) => {}
            Ok(Parsed::Complete { request, head_len }) => {
                let body = read_body(guest, &request, buf.split_off(head_len)).await?;
                return Ok(Head::Request(request, body));
            }
        }
    }
}

/// Read one request head and body inside a terminated tunnel.
async fn read_tunnelled<G: AsyncRead + Unpin>(
    guest: &mut G,
) -> Result<(Request, Vec<u8>), Refusal> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = guest
            .read(&mut chunk)
            .await
            .map_err(|_| Refusal::Incomplete)?;
        if n == 0 {
            return Err(Refusal::Incomplete);
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
        match parse_head_tunnelled(&buf)? {
            Parsed::Partial if buf.len() >= MAX_HEAD => return Err(Refusal::HeadersTooLarge),
            Parsed::Partial => {}
            Parsed::Complete { request, head_len } => {
                let body = read_body(guest, &request, buf.split_off(head_len)).await?;
                return Ok((request, body));
            }
        }
    }
}

/// Read the rest of a `Content-Length` body after `body` (what came with the
/// head).
async fn read_body<G: AsyncRead + Unpin>(
    guest: &mut G,
    request: &Request,
    mut body: Vec<u8>,
) -> Result<Vec<u8>, Refusal> {
    let mut chunk = [0u8; 4096];
    let want = usize::try_from(request.content_length).map_err(|_| Refusal::BadContentLength)?;
    while body.len() < want {
        let n = guest
            .read(&mut chunk)
            .await
            .map_err(|_| Refusal::Incomplete)?;
        if n == 0 {
            return Err(Refusal::Incomplete);
        }
        body.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    // Bytes past the declared body would be a second request on a connection
    // that carries one. Refused rather than dropped, so the guest learns it.
    if body.len() > want {
        return Err(Refusal::Malformed);
    }
    Ok(body)
}

/// Connect to the first admitted address that answers within
/// [`CONNECT_DEADLINE`] in total.
async fn connect(admitted: &[IpAddr], port: u16) -> Result<TcpStream, Refusal> {
    let attempt = async {
        for ip in admitted {
            if let Ok(s) = TcpStream::connect(SocketAddr::new(*ip, port)).await {
                return Ok(s);
            }
        }
        Err(Refusal::UpstreamUnreachable)
    };
    tokio::time::timeout(CONNECT_DEADLINE, attempt)
        .await
        .map_err(|_| Refusal::UpstreamUnreachable)?
}

/// The bytes sent upstream: the decided request in origin form, written by
/// the proxy from the parsed value. `host` and `content-length` are the
/// proxy's, the guest's end-to-end headers follow, and the connection closes
/// after one exchange.
pub fn upstream_request(request: &Request, body: &[u8]) -> Vec<u8> {
    let Request {
        method,
        origin,
        path,
        query,
        headers,
        content_length: _,
    } = request;
    let target = match query {
        Some(q) => format!("{path}?{q}"),
        None => path.clone(),
    };
    let host = if origin.port == origin.scheme.default_port() {
        origin.host.to_string()
    } else {
        format!("{}:{}", origin.host, origin.port)
    };
    let mut out = format!("{} {target} HTTP/1.1\r\nhost: {host}\r\n", method.as_str());
    for (name, value) in headers {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    let has_body = !body.is_empty() || matches!(method, Method::Post | Method::Put | Method::Patch);
    if has_body {
        out.push_str(&format!("content-length: {}\r\n", body.len()));
    }
    out.push_str("connection: close\r\n\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn refuse<G: AsyncWrite + Unpin>(guest: &mut G, refusal: Refusal) -> Served {
    let _ = guest.write_all(&refusal.response()).await;
    let _ = guest.shutdown().await;
    Served::Refused(refusal)
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "serve_tls_tests.rs"]
mod tls_tests;

#[cfg(test)]
#[path = "serve_link_tests.rs"]
mod link_tests;
