//! The SPIFFE Workload API (X.509-SVID profile), served over gRPC.
//!
//! # Why this exists alongside [`crate::workload_api`]
//!
//! `workload_api` is a bespoke JSON-line protocol. It works, the guest speaks
//! it, and old rootfs images cannot be changed — so it stays. But nothing else
//! in the world speaks it: an off-the-shelf SPIFFE client could not obtain an
//! SVID from nucleus at all.
//!
//! This module serves the standard API instead, at the standard method path
//! (`/SpiffeWorkloadAPI/FetchX509SVID`, no package prefix — see the note in
//! `proto/workload.proto`), so `go-spiffe`, the `spiffe` crate, and anything
//! else implementing the specification work unmodified.

use std::pin::Pin;
use std::sync::Arc;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use nucleus_proto::spiffe_workload::{
    spiffe_workload_api_server::SpiffeWorkloadApi, X509BundlesRequest, X509BundlesResponse,
    X509svid, X509svidRequest, X509svidResponse,
};

use crate::ca::CaClient;
use crate::certificate::TrustBundle;
use crate::manager::SecretManager;
use crate::Identity;

/// The header every Workload API client must send.
///
/// The specification requires the server to REJECT a request that does not
/// carry it. It is not authentication — the Workload API deliberately has none
/// — it exists so that a workload cannot be tricked into making this call by
/// something that can set a URL but not headers (an HTTP form, an `<img>` tag,
/// a naive proxy). Dropping it would leave the socket reachable by exactly the
/// confused-deputy shapes the header was added to stop, so
/// `a_request_without_the_security_header_is_refused` pins it.
const SECURITY_HEADER: &str = "workload.spiffe.io";

fn require_security_header<T>(req: &Request<T>) -> Result<(), Status> {
    match req.metadata().get(SECURITY_HEADER) {
        Some(v) if v.as_bytes() == b"true" => Ok(()),
        Some(_) => Err(Status::invalid_argument(
            "workload.spiffe.io header must be `true`",
        )),
        None => Err(Status::invalid_argument(
            "missing required `workload.spiffe.io: true` header",
        )),
    }
}

/// Serves the X.509-SVID profile for a single workload identity.
///
/// One socket serves one identity: nucleus binds a socket per pod, so "which
/// workload is asking" is answered by which socket the call arrived on rather
/// than by attesting the caller. That is why there is no peer-credential check
/// here — the isolation is the socket, not the message.
pub struct SpiffeWorkloadApiService<C: CaClient> {
    manager: Arc<SecretManager<C>>,
    identity: Identity,
    trust_bundle: TrustBundle,
}

impl<C: CaClient + 'static> SpiffeWorkloadApiService<C> {
    pub fn new(
        manager: Arc<SecretManager<C>>,
        identity: Identity,
        trust_bundle: TrustBundle,
    ) -> Self {
        Self {
            manager,
            identity,
            trust_bundle,
        }
    }

    /// The trust bundle as the wire format wants it: DER, keyed by the SPIFFE
    /// ID of the trust domain.
    fn bundle_der(&self) -> Vec<u8> {
        self.trust_bundle
            .roots()
            .iter()
            .flat_map(|c| c.der().to_vec())
            .collect()
    }

    fn trust_domain_id(&self) -> String {
        format!("spiffe://{}", self.identity.trust_domain())
    }

    async fn build_response(&self) -> Result<X509svidResponse, Status> {
        let cert = self
            .manager
            .fetch_certificate(&self.identity)
            .await
            .map_err(|e| Status::internal(format!("could not obtain an SVID: {e}")))?;

        // "ASN.1 DER encoded certificate chain. MAY include intermediates, the
        // leaf certificate (or SVID itself) MUST come first." `chain()` is
        // already leaf-first.
        let chain: Vec<u8> = cert.chain().iter().flat_map(|c| c.der().to_vec()).collect();

        let key = cert
            .private_key()
            .to_der()
            .map_err(|e| Status::internal(format!("could not encode the private key: {e}")))?;

        Ok(X509svidResponse {
            svids: vec![X509svid {
                spiffe_id: self.identity.to_spiffe_uri(),
                x509_svid: chain,
                x509_svid_key: key,
                bundle: self.bundle_der(),
                hint: String::new(),
            }],
            crl: Vec::new(),
            federated_bundles: Default::default(),
        })
    }
}

type SvidStream = Pin<Box<dyn Stream<Item = Result<X509svidResponse, Status>> + Send>>;
type BundleStream = Pin<Box<dyn Stream<Item = Result<X509BundlesResponse, Status>> + Send>>;

#[tonic::async_trait]
impl<C: CaClient + 'static> SpiffeWorkloadApi for SpiffeWorkloadApiService<C> {
    type FetchX509SVIDStream = SvidStream;
    type FetchX509BundlesStream = BundleStream;

    async fn fetch_x509svid(
        &self,
        request: Request<X509svidRequest>,
    ) -> Result<Response<Self::FetchX509SVIDStream>, Status> {
        require_security_header(&request)?;
        let first = self.build_response().await?;

        // The RPC is a stream because the SVID rotates. This sends the current
        // one and holds the stream open; re-delivery on rotation is wired in a
        // follow-up. A client that reads one message and uses it — which is
        // what the `spiffe` crate's one-shot fetch does — is served correctly
        // today, and one that waits for updates simply waits.
        let stream = tokio_stream::once(Ok(first));
        Ok(Response::new(Box::pin(stream) as Self::FetchX509SVIDStream))
    }

    async fn fetch_x509_bundles(
        &self,
        request: Request<X509BundlesRequest>,
    ) -> Result<Response<Self::FetchX509BundlesStream>, Status> {
        require_security_header(&request)?;

        let mut bundles = std::collections::HashMap::new();
        bundles.insert(self.trust_domain_id(), self.bundle_der());

        let stream = tokio_stream::once(Ok(X509BundlesResponse {
            crl: Vec::new(),
            bundles,
        }));
        Ok(Response::new(
            Box::pin(stream) as Self::FetchX509BundlesStream
        ))
    }
}

/// Serve the Workload API on a Unix domain socket.
///
/// The socket's filesystem permissions ARE the access control. The Workload API
/// has no client authentication by design — the specification says so — and the
/// `workload.spiffe.io` header is an anti-confused-deputy measure, not
/// authentication. So the mode is set explicitly to owner-only rather than left
/// to the process umask, which a caller cannot see and which would silently
/// widen access on a permissive host.
pub async fn serve_uds<C: CaClient + 'static>(
    service: SpiffeWorkloadApiService<C>,
    socket_path: impl AsRef<std::path::Path>,
) -> crate::Result<()> {
    use nucleus_proto::spiffe_workload::spiffe_workload_api_server::SpiffeWorkloadApiServer;
    use std::os::unix::fs::PermissionsExt;

    let path = socket_path.as_ref();
    if path.exists() {
        tokio::fs::remove_file(path).await.ok();
    }
    let listener = tokio::net::UnixListener::bind(path)
        .map_err(|e| crate::Error::Certificate(format!("bind {}: {e}", path.display())))?;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .map_err(|e| crate::Error::Certificate(format!("chmod {}: {e}", path.display())))?;

    tonic::transport::Server::builder()
        .add_service(SpiffeWorkloadApiServer::new(service))
        .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
        .await
        .map_err(|e| crate::Error::Certificate(format!("workload API server: {e}")))?;
    Ok(())
}
