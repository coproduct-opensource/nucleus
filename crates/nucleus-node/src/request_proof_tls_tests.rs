//! Real TLS acceptance for the production request-proof adapter. This tests the
//! key/transport/replay boundary, not pod authorization or federation issuance.
use super::RequestProofs;
use axum::{Router, extract::State, middleware, response::IntoResponse, routing::get};
use nucleus_identity::mtls::{MtlsConfig, MtlsConnectInfo, MtlsListener};
use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsClientConfig};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const DOMAIN: &str = "proof-tls.nucleus.local";

async fn check(
    State(state): State<Arc<RequestProofs>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    let (parts, body) = request.into_parts();
    match state.api(&parts) {
        Ok(()) => next.run(axum::http::Request::from_parts(parts, body)).await,
        Err(e) => e.into_response(),
    }
}

async fn request(connector: &tokio_rustls::TlsConnector, addr: SocketAddr, headers: &str) -> u16 {
    tokio::time::timeout(Duration::from_secs(5), async {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from(DOMAIN.to_owned()).unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();
        tls.write_all(
            format!("GET /probe HTTP/1.1\r\nHost: {DOMAIN}\r\nConnection: close\r\n{headers}\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut bytes = Vec::new();
        tls.read_to_end(&mut bytes).await.unwrap();
        String::from_utf8(bytes)
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap()
    })
    .await
    .expect("TLS request deadline")
}

#[tokio::test]
async fn request_proof_real_mtls_binds_peer_key_and_persists_replay() {
    let dir = tempfile::tempdir().unwrap();
    let ca = SelfSignedCa::new(DOMAIN).unwrap();
    let bundle = ca.trust_bundle().clone();
    let server_identity = Identity::new(DOMAIN, "system", "node");
    let server_csr = CsrOptions::new(server_identity.to_spiffe_uri())
        .generate()
        .unwrap();
    let server_cert = ca
        .sign_csr(
            server_csr.csr(),
            server_csr.private_key(),
            &server_identity,
            Duration::from_secs(300),
        )
        .await
        .unwrap();
    let mut clients = Vec::new();
    for name in ["one", "two"] {
        let identity = Identity::new(DOMAIN, "clients", name);
        let csr = CsrOptions::new(identity.to_spiffe_uri())
            .generate()
            .unwrap();
        let key = rcgen::KeyPair::from_pem(csr.private_key())
            .unwrap()
            .serialize_der();
        let cert = ca
            .sign_csr(
                csr.csr(),
                csr.private_key(),
                &identity,
                Duration::from_secs(300),
            )
            .await
            .unwrap();
        let connector = TlsClientConfig::new(cert, bundle.clone())
            .with_spiffe_trust_domain(DOMAIN)
            .build_connector()
            .unwrap();
        clients.push((connector, key));
    }
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let origin = format!("https://{DOMAIN}:{}", addr.port());
    let args = crate::federation_ingress::FederationArgs {
        request_proof_api_origin: Some(origin.clone()),
        request_proof_exchange_origin: Some("https://exchange.example.test".into()),
        ..crate::federation_ingress::FederationArgs::default()
    };
    let state = RequestProofs::open(&args, dir.path(), false)
        .unwrap()
        .unwrap();
    let app = Router::new()
        .route("/probe", get(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(state.clone(), check));
    let listener = MtlsListener::new(tcp, &MtlsConfig::new(server_cert, bundle)).unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<MtlsConnectInfo>(),
        )
        .await
    });
    let make = |method: &str, uri: &str, token: Option<&str>| {
        let mut builder = nucleus_identity::dpop::DpopProofBuilder::new(method, uri);
        if let Some(token) = token {
            builder = builder.with_access_token(token);
        }
        builder.build(&clients[0].1).unwrap()
    };
    let uri = format!("{origin}/probe");
    let proof = make("GET", &uri, None);
    let headers = format!("DPoP: {proof}\r\n");
    assert_eq!(request(&clients[0].0, addr, "").await, 401);
    // Copying the proof to a separately valid mTLS identity must fail before
    // replay consumption; its legitimate key can still use the proof once.
    assert_eq!(request(&clients[1].0, addr, &headers).await, 401);
    assert_eq!(request(&clients[0].0, addr, &headers).await, 200);
    assert_eq!(request(&clients[0].0, addr, &headers).await, 401);
    for bad in [
        make("POST", &uri, None),
        make("GET", "https://wrong.example/probe", None),
        make("GET", &format!("{origin}/other"), None),
    ] {
        assert_eq!(
            request(&clients[0].0, addr, &format!("DPoP: {bad}\r\n")).await,
            401
        );
    }
    let fresh = make("GET", &uri, None);
    assert_eq!(
        request(
            &clients[0].0,
            addr,
            &format!("DPoP: {fresh}\r\nDPoP: {fresh}\r\n")
        )
        .await,
        401
    );
    let token = "binding-fixture-not-authority";
    assert_eq!(
        request(
            &clients[0].0,
            addr,
            &format!("X-Nucleus-Delegation-Cert: {token}\r\n")
        )
        .await,
        401
    );
    let bound = make("GET", &uri, Some(token));
    assert_eq!(
        request(
            &clients[0].0,
            addr,
            &format!("DPoP: {bound}\r\nX-Nucleus-Delegation-Cert: changed\r\n")
        )
        .await,
        401
    );
    assert_eq!(
        request(
            &clients[0].0,
            addr,
            &format!("DPoP: {bound}\r\nX-Nucleus-Delegation-Cert: {token}\r\n")
        )
        .await,
        200
    );
    server.abort();
    let _ = server.await;
    drop(state);
    let reopened = RequestProofs::open(&args, dir.path(), false)
        .unwrap()
        .unwrap();
    let mut parts = axum::http::Request::builder()
        .uri("/probe")
        .header("dpop", proof)
        .body(())
        .unwrap()
        .into_parts()
        .0;
    // Reopen persistence is independently exercised against the actual key;
    // no reconstructed TLS extension is needed to ask the native replay gate.
    let cert_key = nucleus_identity::dpop::DpopProofBuilder::new("GET", &uri)
        .build(&clients[0].1)
        .unwrap();
    let parsed: serde_json::Value = {
        use base64::Engine;
        serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(cert_key.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap()
    };
    let key = serde_json::from_value(parsed["jwk"].clone()).unwrap();
    assert!(
        reopened
            .api
            .verify(
                parts.headers.remove("dpop").unwrap().to_str().unwrap(),
                "GET",
                "/probe",
                None,
                &key
            )
            .is_err()
    );
}
