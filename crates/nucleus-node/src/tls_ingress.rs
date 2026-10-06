//! Server-authenticated TLS listeners that ask for NO client certificate.
//!
//! The node's API listener requires a client certificate at the handshake
//! (`http_serve`). Two kinds of caller cannot have one: an outside runtime
//! exchanging its own issuer's token for an SVID (`federation_ingress`), and a
//! stranger fetching the evidence a receipt names (`public_evidence`). Each is
//! served on its own listener, with its own router, built from these pieces —
//! one copy of the handshake bounds rather than one per listener (ADR 0007 G-1).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use tokio::sync::Semaphore;

/// A TLS handshake that has not finished in this long is dropped. Handshakes
/// run off the accept loop, so a slow or silent client holds a task, never the
/// listener.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Handshakes in flight at once. Past it, new connections wait in the kernel's
/// backlog rather than as tasks here.
const MAX_HANDSHAKES: usize = 256;

/// A server-authenticated TLS listener whose handshakes run off the accept
/// loop. See [`HANDSHAKE_TIMEOUT`].
struct TlsListener {
    rx: tokio::sync::mpsc::Receiver<(
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        SocketAddr,
    )>,
    addr: SocketAddr,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.rx.recv().await {
            Some(conn) => conn,
            // The acceptor task ended (its listener failed); serve nothing
            // further rather than spin.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(self.addr)
    }
}

fn spawn_acceptor(
    tcp: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    name: &'static str,
) -> tokio::sync::mpsc::Receiver<(
    tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    SocketAddr,
)> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    let slots = Arc::new(Semaphore::new(MAX_HANDSHAKES));
    tokio::spawn(async move {
        loop {
            let Ok(permit) = slots.clone().acquire_owned().await else {
                return;
            };
            let (stream, addr) = match tcp.accept().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, listener = name, "accept failed");
                    continue;
                }
            };
            let (acceptor, tx) = (acceptor.clone(), tx.clone());
            tokio::spawn(async move {
                let _permit = permit;
                if let Ok(Ok(tls)) =
                    tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await
                {
                    let _ = tx.send((tls, addr)).await;
                }
            });
        }
    });
    rx
}

/// A server-auth-only TLS config from an operator's PEM files. `flag` is the
/// flag prefix the files came from (e.g. `--federation-tls`), so an error
/// names what the operator typed.
pub(crate) fn operator_tls(
    cert: &Path,
    key: &Path,
    flag: &str,
) -> Result<rustls::ServerConfig, String> {
    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .map_err(|e| format!("{flag}-cert {}: {e}", cert.display()))?;
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| format!("{flag}-key {}: {e}", key.display()))?;
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("{flag} listener certificate: {e}"))
}

/// The listener's TLS config: the operator's files when both are given, the
/// node's own certificate (rotated like the API listener's) when neither is.
/// One of the two alone is a misconfiguration, said at start.
pub(crate) async fn server_config(
    state: &crate::NodeState,
    cert: Option<&Path>,
    key: Option<&Path>,
    flag: &str,
) -> Result<rustls::ServerConfig, String> {
    match (cert, key) {
        (Some(cert), Some(key)) => operator_tls(cert, key, flag),
        (None, None) => {
            let identity = state
                .identity_manager
                .clone()
                .ok_or_else(|| format!("the {flag} listener needs the node identity"))?;
            let node_cert = identity.node_certificate().await?;
            let resolver = Arc::new(
                nucleus_identity::tls::RotatingServerCert::new(&node_cert)
                    .map_err(|e| format!("{flag} listener certificate: {e}"))?,
            );
            crate::http_serve::spawn_certificate_rotation(state, resolver.clone());
            Ok(rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver))
        }
        _ => Err(format!("{flag}-cert and {flag}-key go together")),
    }
}

/// Serve `app` over server-authenticated TLS on `tcp`. No client certificate
/// is asked for.
pub(crate) fn serve_tls(
    tcp: tokio::net::TcpListener,
    config: rustls::ServerConfig,
    app: Router,
    name: &'static str,
) {
    let addr = tcp
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let listener = TlsListener {
        rx: spawn_acceptor(tcp, tokio_rustls::TlsAcceptor::from(Arc::new(config)), name),
        addr,
    };
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, listener = name, "listener stopped");
        }
    });
}
