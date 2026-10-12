// Included in the existing federation tests to reuse the real issuer/CA fixture.
#[tokio::test]
async fn request_proof_real_tls_exchange_then_mtls_api() {
    use nucleus_identity::dpop::DpopProofBuilder;
    use nucleus_identity::mtls::{MtlsConfig, MtlsConnectInfo, MtlsListener};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut f = fixture();
    let exchange_tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let exchange_addr = exchange_tcp.local_addr().unwrap();
    let exchange_origin = format!("https://localhost:{}", exchange_addr.port());
    let api_tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_tcp.local_addr().unwrap();
    let api_origin = format!("https://{NODE_TD}:{}", api_addr.port());
    let args = FederationArgs {
        request_proof_api_origin: Some(api_origin.clone()),
        request_proof_exchange_origin: Some(exchange_origin.clone()),
        ..FederationArgs::default()
    };
    f.st.request_proofs =
        crate::request_proof::RequestProofs::open(&args, f._dir.path(), false).unwrap();
    let tls_key = rcgen::KeyPair::generate().unwrap();
    let tls_cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&tls_key)
        .unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![tls_cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(tls_key.serialize_der()).into(),
        )
        .unwrap();
    crate::tls_ingress::serve_tls(exchange_tcp, config, router(f.st.clone()), "proof-test");
    let http = reqwest::Client::builder()
        .no_proxy()
        .https_only(true)
        .add_root_certificate(reqwest::Certificate::from_pem(tls_cert.pem().as_bytes()).unwrap())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let csr = nucleus_identity::CsrOptions::new(principal_a("alice"))
        .generate()
        .unwrap();
    let key = rcgen::KeyPair::from_pem(csr.private_key())
        .unwrap()
        .serialize_der();
    let target = format!("{exchange_origin}/v1/federation/exchange");
    let probe = DpopProofBuilder::new("POST", &target).build(&key).unwrap();
    let header: nucleus_identity::dpop::DpopHeader = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(probe.split('.').next().unwrap())
            .unwrap(),
    )
    .unwrap();
    let jkt = nucleus_request_proof::thumbprint(&header.jwk).unwrap();
    let mut claims = f.a.claims("alice", now());
    claims["cnf"] = json!({"jkt":jkt});
    let token = f.a.sign(f.a.header(), claims);
    let proof = || {
        DpopProofBuilder::new("POST", &target)
            .with_access_token(&token)
            .build(&key)
            .unwrap()
    };
    let send = |scheme: &str| {
        http.post(&target)
            .header("authorization", format!("{scheme} {token}"))
            .header("content-type", "application/json")
            .body(body(csr.csr(), None))
    };
    assert_eq!(send("DPoP").send().await.unwrap().status().as_u16(), 401);
    assert_eq!(
        send("Bearer")
            .header("dpop", proof())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401
    );
    let response = send("DPoP").header("dpop", proof()).send().await.unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let result: Value = response.json().await.unwrap();
    assert_eq!(result["cnf"]["jkt"], jkt);
    assert_eq!(
        send("DPoP")
            .header("dpop", proof())
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        401,
        "fresh proof must not revive a spent issuer assertion"
    );
    let issued = nucleus_identity::WorkloadCertificate::from_pem(
        result["svid_chain_pem"].as_str().unwrap(),
        csr.private_key(),
    )
    .unwrap();
    assert_eq!(
        nucleus_request_proof::thumbprint(
            &nucleus_request_proof::certificate_key(issued.leaf().der()).unwrap()
        )
        .unwrap(),
        jkt
    );
    let bundle = f.st.identity.trust_bundle().clone();
    let server_cert = f.st.identity.node_certificate().await.unwrap();
    let listener = MtlsListener::new(
        api_tcp,
        &MtlsConfig::new(server_cert.as_ref().clone(), bundle.clone()),
    )
    .unwrap();
    async fn check(
        axum::extract::State(proofs): axum::extract::State<
            Arc<crate::request_proof::RequestProofs>,
        >,
        request: axum::extract::Request,
        next: axum::middleware::Next,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let (parts, body) = request.into_parts();
        match proofs.api(&parts) {
            Ok(()) => next.run(axum::http::Request::from_parts(parts, body)).await,
            Err(e) => e.into_response(),
        }
    }
    let api = axum::Router::new()
        .route("/probe", axum::routing::get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(
            f.st.request_proofs.clone().unwrap(),
            check,
        ));
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            api.into_make_service_with_connect_info::<MtlsConnectInfo>(),
        )
        .await
    });
    let connector = nucleus_identity::TlsClientConfig::new(issued, bundle)
        .with_spiffe_trust_domain(NODE_TD)
        .build_connector()
        .unwrap();
    let delegation = result["delegation_cert"].as_str().unwrap();
    let api_proof = DpopProofBuilder::new("GET", &format!("{api_origin}/probe"))
        .with_access_token(delegation)
        .build(&key)
        .unwrap();
    for expected in [200, 401] {
        let status = tokio::time::timeout(Duration::from_secs(5), async {
            let tcp = tokio::net::TcpStream::connect(api_addr).await.unwrap();
            let name = rustls::pki_types::ServerName::try_from(NODE_TD.to_owned()).unwrap();
            let mut tls = connector.connect(name, tcp).await.unwrap();
            tls.write_all(format!("GET /probe HTTP/1.1\r\nHost: {NODE_TD}\r\nConnection: close\r\nDPoP: {api_proof}\r\nX-Nucleus-Delegation-Cert: {delegation}\r\n\r\n").as_bytes()).await.unwrap();
            let mut bytes = Vec::new();
            tls.read_to_end(&mut bytes).await.unwrap();
            String::from_utf8(bytes).unwrap().split_whitespace().nth(1).unwrap().parse::<u16>().unwrap()
        }).await.expect("API handshake deadline");
        assert_eq!(status, expected);
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn request_proof_exchange_checks_issuer_csr_key_and_http_proof() {
    use nucleus_identity::dpop::DpopProofBuilder;
    use tower::ServiceExt;
    let mut f = fixture();
    let args = FederationArgs {
        request_proof_api_origin: Some("https://api.example.test".into()),
        request_proof_exchange_origin: Some("https://exchange.example.test".into()),
        ..FederationArgs::default()
    };
    f.st.request_proofs =
        crate::request_proof::RequestProofs::open(&args, f._dir.path(), false).unwrap();
    let csr = nucleus_identity::CsrOptions::new(principal_a("alice"))
        .generate()
        .unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
    let probe = DpopProofBuilder::new(
        "POST",
        "https://exchange.example.test/v1/federation/exchange",
    )
    .build(&pem.contents)
    .unwrap();
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(probe.split('.').next().unwrap())
        .unwrap();
    let header: nucleus_identity::dpop::DpopHeader = serde_json::from_slice(&raw).unwrap();
    let jkt = nucleus_request_proof::thumbprint(&header.jwk).unwrap();
    let router = router(f.st.clone());
    for case in [
        "missing",
        "bearer",
        "wrong-key",
        "wrong-method",
        "wrong-target",
        "duplicate",
        "valid",
    ] {
        let mut claims = f.a.claims("alice", now());
        claims["jti"] = json!(uuid::Uuid::new_v4().to_string());
        claims["cnf"] = json!({"jkt":if case=="wrong-key" {"incorrect"}else{&jkt}});
        let token = f.a.sign(f.a.header(), claims);
        let proof = DpopProofBuilder::new(
            if case == "wrong-method" {
                "GET"
            } else {
                "POST"
            },
            if case == "wrong-target" {
                "https://exchange.example.test/else"
            } else {
                "https://exchange.example.test/v1/federation/exchange"
            },
        )
        .with_access_token(&token)
        .build(&pem.contents)
        .unwrap();
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/federation/exchange")
            .header("content-type", "application/json")
            .header(
                "authorization",
                format!(
                    "{} {token}",
                    if case == "bearer" { "Bearer" } else { "DPoP" }
                ),
            );
        if case != "missing" {
            request = request.header("dpop", &proof);
        }
        if case == "duplicate" {
            request = request.header("dpop", &proof);
        }
        let response = router
            .clone()
            .oneshot(
                request
                    .body(axum::body::Body::from(body(csr.csr(), None)))
                    .unwrap(),
            )
            .await
            .unwrap();
        if case == "valid" {
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            let result: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(result["cnf"]["jkt"], jkt);
            let cert = nucleus_identity::certificate::Certificate::from_pem(
                result["svid_chain_pem"].as_str().unwrap(),
            )
            .unwrap();
            assert_eq!(
                nucleus_request_proof::thumbprint(
                    &nucleus_request_proof::certificate_key(cert.der()).unwrap()
                )
                .unwrap(),
                jkt
            );
            let replay = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/v1/federation/exchange")
                        .header("content-type", "application/json")
                        .header("authorization", format!("DPoP {token}"))
                        .header("dpop", proof)
                        .body(axum::body::Body::from(body(csr.csr(), None)))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(replay.status(), axum::http::StatusCode::UNAUTHORIZED);
        } else {
            assert_eq!(
                response.status(),
                axum::http::StatusCode::UNAUTHORIZED,
                "{case}"
            );
        }
    }
}
