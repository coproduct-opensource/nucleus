use super::*;
use axum::body::Body;
use axum::http::Method;
use tower::ServiceExt as _;

const EXECUTOR: [u8; 32] = [7; 32];

/// A store holding one document under its true name, and the name.
fn store_with_doc(bytes: &[u8]) -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let digest = hex::encode(nucleus_node_evidence::evidence_digest(bytes));
    std::fs::write(dir.path().join(format!("{digest}.json")), bytes).unwrap();
    (dir, digest)
}

fn app(store: Store) -> Router {
    router(PublicState::new(store, EXECUTOR, 1000))
}

async fn send(app: &Router, method: Method, uri: &str) -> (StatusCode, Vec<u8>) {
    let resp = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, body.to_vec())
}

const DOC: &[u8] = br#"{"eat_profile":"nucleus-node-evidence/v1","fixture":true}"#;

#[tokio::test]
async fn a_stored_document_is_served_by_its_digest() {
    let (dir, digest) = store_with_doc(DOC);
    let app = app(Store::Dir(dir.path().to_path_buf()));
    let (status, body) = send(&app, Method::GET, &format!("/v1/evidence/{digest}")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, DOC);
    assert_eq!(
        hex::encode(nucleus_node_evidence::evidence_digest(&body)),
        digest
    );
}

#[tokio::test]
async fn a_name_that_is_not_a_digest_never_reaches_the_disk() {
    let (dir, digest) = store_with_doc(DOC);
    // A file the traversal would reach if the name were joined unchecked.
    std::fs::write(dir.path().join("secret.json"), b"{}").unwrap();
    let app = app(Store::Dir(dir.path().join("sub")));
    for bad in [
        digest.to_uppercase(),
        digest[..63].to_string(),
        format!("{digest}0"),
        "..%2Fsecret".to_string(),
        "secret".to_string(),
    ] {
        let (status, _) = send(&app, Method::GET, &format!("/v1/evidence/{bad}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn an_unknown_digest_is_404_and_a_corrupt_store_is_not_served() {
    let (dir, digest) = store_with_doc(DOC);
    let app = app(Store::Dir(dir.path().to_path_buf()));
    let (status, _) = send(
        &app,
        Method::GET,
        &format!("/v1/evidence/{}", "0".repeat(64)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // The bytes under the name no longer hash to it.
    std::fs::write(dir.path().join(format!("{digest}.json")), b"{\"x\":1}").unwrap();
    let (status, body) = send(&app, Method::GET, &format!("/v1/evidence/{digest}")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_ne!(body, b"{\"x\":1}");
}

#[tokio::test]
async fn a_document_over_the_cap_is_not_served() {
    let dir = tempfile::tempdir().unwrap();
    let big = vec![b' '; usize::try_from(MAX_DOCUMENT_BYTES).unwrap() + 1];
    let digest = hex::encode(nucleus_node_evidence::evidence_digest(&big));
    std::fs::write(dir.path().join(format!("{digest}.json")), &big).unwrap();
    let app = app(Store::Dir(dir.path().to_path_buf()));
    let (status, body) = send(&app, Method::GET, &format!("/v1/evidence/{digest}")).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(body.len() < 1024);
}

#[tokio::test]
async fn a_node_without_evidence_says_so_with_its_reason() {
    let app = app(Store::Unattested("no TPM attester configured".into()));
    let (status, body) = send(
        &app,
        Method::GET,
        &format!("/v1/evidence/{}", "a".repeat(64)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["unattested"], "no TPM attester configured");

    let (status, body) = send(&app, Method::GET, "/v1/node/keys").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        v["node_platform"]["unattested"],
        "no TPM attester configured"
    );
}

#[tokio::test]
async fn the_keys_document_names_the_executor_key() {
    let dir = tempfile::tempdir().unwrap();
    let app = app(Store::Dir(dir.path().to_path_buf()));
    let (status, body) = send(&app, Method::GET, "/v1/node/keys").await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["profile"], "nucleus-node-keys/v1");
    assert_eq!(v["executor"]["alg"], "ed25519");
    assert_eq!(v["executor"]["public_key_hex"], hex::encode(EXECUTOR));
    assert_eq!(v["node_platform"]["evidence"], "tpm");
}

/// Every route the node's API mounts (`main.rs`, `node_evidence::routes`,
/// `workload_result::routes`, `pod_api::effect_approvals::routes`) and the
/// federation listener's one route, each with the method that serves it.
/// Mounting any of them here turns this red (A-19).
const API_ROUTES: &[(&str, &str)] = &[
    ("GET", "/v1/pods"),
    ("POST", "/v1/pods"),
    ("GET", "/v1/pods/p1/logs"),
    ("POST", "/v1/pods/p1/cancel"),
    ("POST", "/v1/pods/p1/snapshot"),
    ("GET", "/v1/pods/p1/receipt"),
    ("GET", "/v1/pods/p1/workload-admission"),
    ("GET", "/v1/pods/p1/workload-result"),
    ("GET", "/v1/pods/p1/workload-logs/stdout"),
    ("GET", "/v1/pods/p1/workload-logs/stderr"),
    ("GET", "/v1/pods/p1/execution-receipt"),
    ("POST", "/v1/pods/p1/execution-receipt"),
    ("GET", "/v1/pods/p1/effect-approvals"),
    ("GET", "/v1/pods/p1/effect-approvals/a1"),
    ("POST", "/v1/pods/p1/effect-approvals/a1"),
    ("POST", "/v1/art12/s1"),
    ("GET", "/v1/health"),
    ("GET", "/v1/node/evidence"),
    ("POST", "/v1/node/evidence/challenge"),
    ("POST", "/v1/federation/exchange"),
    ("GET", "/"),
    ("GET", "/v1/evidence"),
    ("GET", "/v1/node"),
];

#[tokio::test]
async fn no_other_route_is_mounted_on_the_public_listener() {
    let (dir, digest) = store_with_doc(DOC);
    let app = app(Store::Dir(dir.path().to_path_buf()));
    // The mTLS path to the same document, by the same digest.
    let mtls_by_digest = format!("/v1/node/evidence/{digest}");
    let mut routes: Vec<(&str, &str)> = API_ROUTES.to_vec();
    routes.push(("GET", &mtls_by_digest));
    for (method, uri) in routes {
        let (status, _) = send(&app, Method::from_bytes(method.as_bytes()).unwrap(), uri).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {uri} answered {status} on the public listener"
        );
    }
    // Only GET serves the two routes that do exist.
    let (status, _) = send(&app, Method::POST, &format!("/v1/evidence/{digest}")).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _) = send(&app, Method::POST, "/v1/node/keys").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn past_the_rate_the_listener_answers_429() {
    let (dir, digest) = store_with_doc(DOC);
    let app = router(PublicState::new(
        Store::Dir(dir.path().to_path_buf()),
        EXECUTOR,
        3,
    ));
    let uri = format!("/v1/evidence/{digest}");
    let mut statuses = Vec::new();
    for _ in 0..5 {
        statuses.push(send(&app, Method::GET, &uri).await.0);
    }
    assert_eq!(&statuses[..3], &[StatusCode::OK; 3]);
    assert!(
        statuses[3..]
            .iter()
            .all(|s| *s == StatusCode::TOO_MANY_REQUESTS),
        "{statuses:?}"
    );
}

#[test]
fn the_bucket_refills_at_its_rate_and_never_past_one_second() {
    let start = Instant::now();
    let mut b = Bucket {
        tokens: 2.0,
        last: start,
        rate: 2.0,
    };
    assert!(b.take(start));
    assert!(b.take(start));
    assert!(!b.take(start));
    assert!(b.take(start + Duration::from_millis(500)));
    // A long idle period refills to the burst, not beyond it.
    let later = start + Duration::from_secs(3600);
    assert!(b.take(later) && b.take(later));
    assert!(!b.take(later));
}

#[tokio::test]
async fn served_over_tls_to_a_client_with_no_certificate() {
    // The real transport: an operator certificate for a DNS name, an HTTPS
    // client that trusts it and presents NO client certificate.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let tls_dir = tempfile::tempdir().unwrap();
    let (cert_path, key_path) = (tls_dir.path().join("c.pem"), tls_dir.path().join("k.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();

    let (dir, digest) = store_with_doc(DOC);
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    crate::tls_ingress::serve_tls(
        tcp,
        crate::tls_ingress::operator_tls(&cert_path, &key_path, "--public-evidence-tls").unwrap(),
        app(Store::Dir(dir.path().to_path_buf())),
        "public-evidence",
    );

    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(cert.pem().as_bytes()).unwrap())
        .resolve(
            "localhost",
            std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        )
        .build()
        .unwrap();
    let resp = client
        .get(format!("https://localhost:{port}/v1/evidence/{digest}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.bytes().await.unwrap().as_ref(), DOC);

    let resp = client
        .get(format!("https://localhost:{port}/v1/pods"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
}
