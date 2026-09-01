//! Interop: a real SPIFFE client must be able to fetch an SVID from nucleus.
//!
//! This is the test that gives Phase 2 its meaning. A client we wrote ourselves
//! would only prove we agree with ourselves; the point of serving the standard
//! API is that software we did not write can use it. So the client here is the
//! `spiffe` crate — the same one used to talk to SPIRE — driven against our
//! server over a Unix socket.
#![cfg(feature = "spire")]

use std::sync::Arc;
use std::time::Duration;

use nucleus_identity::ca::CaClient;
use nucleus_identity::manager::SecretManager;
use nucleus_identity::spiffe_workload_api::{serve_uds, SpiffeWorkloadApiService};
use nucleus_identity::{Identity, SelfSignedCa};

async fn start_server(sock: &std::path::Path) -> Identity {
    let ca = Arc::new(SelfSignedCa::new("nucleus.local").unwrap());
    let bundle = ca.trust_bundle().clone();
    let identity = Identity::new("nucleus.local", "default", "interop");
    let manager = SecretManager::new(ca, Duration::from_secs(3600));
    let svc = SpiffeWorkloadApiService::new(manager, identity.clone(), bundle);

    let path = sock.to_path_buf();
    tokio::spawn(async move {
        let _ = serve_uds(svc, path).await;
    });
    // Wait for the socket to appear rather than sleeping a guessed interval.
    for _ in 0..100 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    identity
}

#[tokio::test]
async fn an_off_the_shelf_spiffe_client_can_fetch_an_svid() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("workload.sock");
    let identity = start_server(&sock).await;

    let client = spiffe::WorkloadApiClient::connect_to(format!("unix:{}", sock.display()))
        .await
        .expect("a standard SPIFFE client must be able to connect");

    let svid = client
        .fetch_x509_svid()
        .await
        .expect("a standard SPIFFE client must be able to fetch an SVID");

    // The client parsed our response and agrees on the identity — which means
    // the method path, the message encoding and the certificate all matched.
    assert_eq!(svid.spiffe_id().to_string(), identity.to_spiffe_uri());
    assert!(
        !svid.cert_chain().is_empty(),
        "the SVID must carry a certificate chain"
    );

    // Closing the loop between Phase 1 and Phase 2: what we SERVE must satisfy
    // the validator we REJECT with. If issuance ever drifts from the rules,
    // this fails here rather than in production.
    let leaf = svid.leaf();
    let uri = nucleus_identity::spiffe_uri_from_svid(leaf.as_bytes())
        .expect("the SVID we serve must pass our own X.509-SVID validation");
    assert_eq!(uri, identity.to_spiffe_uri());
}

/// The specification requires the server to REJECT a request without the
/// `workload.spiffe.io: true` header. It is the easiest thing to leave out and
/// never notice, because every conforming client sends it — so the only way to
/// know the check exists is to make a request that omits it.
#[tokio::test]
async fn a_request_without_the_security_header_is_refused() {
    use nucleus_proto::spiffe_workload::spiffe_workload_api_client::SpiffeWorkloadApiClient;

    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("workload.sock");
    start_server(&sock).await;

    let path = sock.clone();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")
        .unwrap()
        .connect_with_connector(tower::service_fn(move |_| {
            let p = path.clone();
            async move {
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(
                    tokio::net::UnixStream::connect(p).await?,
                ))
            }
        }))
        .await
        .expect("raw channel");

    let mut raw = SpiffeWorkloadApiClient::new(channel);
    let err = raw
        .fetch_x509svid(nucleus_proto::spiffe_workload::X509svidRequest {})
        .await
        .expect_err("a request without the security header must be refused");
    assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err:?}");
    assert!(err.message().contains("workload.spiffe.io"), "{err:?}");
}
