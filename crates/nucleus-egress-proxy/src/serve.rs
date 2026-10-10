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
//! One request per connection in E2 (`connection: close` both ways), so a
//! request the node did not decide can never ride behind one it did.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ipnet::IpNet;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::Semaphore;

use crate::Refusal;
use crate::address::admit;
use crate::decision::{Decided, HostAnswer, SharedDecider};
use crate::request::{Host, MAX_HEAD, Method, Parsed, Request, parse_head};
use crate::resolve::Resolve;
use crate::summary::{Summary, digest};

/// The most guest connections one pod's proxy serves at once (ADR 0015
/// §10). The next one is refused with [`Refusal::TooManyConnections`].
pub const MAX_CONNECTIONS: usize = 64;

/// How long the guest has to send its whole head and body.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

/// How long the proxy tries to reach an admitted address.
pub const CONNECT_DEADLINE: Duration = Duration::from_secs(5);

/// One pod's proxy.
pub struct Proxy<D, R> {
    decider: SharedDecider<D>,
    resolver: R,
    floor: Vec<IpNet>,
    slots: Arc<Semaphore>,
}

/// What a connection ended in, for the log and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Served {
    /// The decided request was sent upstream and its response relayed.
    Forwarded,
    /// Refused, with the reason the guest was told.
    Refused(Refusal),
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
            Err(refusal) => refuse(&mut guest, refusal).await,
        }
    }

    async fn handle<G: AsyncRead + AsyncWrite + Unpin>(
        &self,
        guest: &mut G,
    ) -> Result<(), Refusal> {
        // 1. parse
        let (request, body) = tokio::time::timeout(REQUEST_DEADLINE, read_request(guest))
            .await
            .map_err(|_| Refusal::HeadTimeout)??;
        // 2. ask
        let summary = Summary::of(&request, &body);
        let subject = summary.subject()?;
        let answer = self.decider.decide(subject, digest(&summary.text())).await;
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
        let mut upstream = connect(&admitted, request.origin.port).await?;
        upstream
            .write_all(&upstream_request(&request, &body))
            .await
            .map_err(|_| Refusal::UpstreamUnreachable)?;
        // 5. relay. The response is past the decision: an error from here on
        // ends the connection, it does not become a refusal the guest could
        // read as part of the upstream's answer.
        let _ = tokio::io::copy(&mut upstream, guest).await;
        let _ = guest.shutdown().await;
        Ok(())
    }
}

/// Read one head and its body.
async fn read_request<G: AsyncRead + Unpin>(guest: &mut G) -> Result<(Request, Vec<u8>), Refusal> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let (request, head_len) = loop {
        let n = guest
            .read(&mut chunk)
            .await
            .map_err(|_| Refusal::Incomplete)?;
        if n == 0 {
            return Err(Refusal::Incomplete);
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
        match parse_head(&buf)? {
            Parsed::Partial if buf.len() >= MAX_HEAD => return Err(Refusal::HeadersTooLarge),
            Parsed::Partial => {}
            Parsed::Complete { request, head_len } => break (request, head_len),
        }
    };
    let want = usize::try_from(request.content_length).map_err(|_| Refusal::BadContentLength)?;
    let mut body = buf.split_off(head_len);
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
    Ok((request, body))
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
    let host = match origin.port {
        80 => origin.host.to_string(),
        port => format!("{}:{port}", origin.host),
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
