use super::*;
use nucleus_identity::dpop::{DpopHeader, DpopProofBuilder};
fn material() -> (Vec<u8>, JsonWebKey) {
    let csr = nucleus_identity::CsrOptions::new("spiffe://test/ns/host/sa/observer")
        .generate()
        .unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes()).unwrap();
    let proof = DpopProofBuilder::new("GET", "http://127.0.0.1:1234/v1/health")
        .build(&pem.contents)
        .unwrap();
    let header: DpopHeader =
        serde_json::from_slice(&B64.decode(proof.split('.').next().unwrap()).unwrap()).unwrap();
    (pem.contents, header.jwk)
}
fn sign(key: &[u8], method: &str, path: &str, body: &[u8]) -> String {
    DpopProofBuilder::new(method, &format!("http://127.0.0.1:1234{path}"))
        .with_access_token(&hex::encode(Sha256::digest(body)))
        .build(key)
        .unwrap()
}
#[test]
fn observation_key_is_separate_scoped_and_replay_protected() {
    let (client_secret, client) = material();
    let (health_secret, health) = material();
    let (secret, observer) = material();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proof");
    let expiry = chrono::Utc::now().timestamp() as u64 + 300;
    assert!(
        LoopbackGate::open(
            "http://127.0.0.1:1234",
            &dir.path().join("same-client"),
            client.clone(),
            expiry
        )
        .unwrap()
        .with_observation_key(client.clone())
        .is_err()
    );
    assert!(
        LoopbackGate::open(
            "http://127.0.0.1:1234",
            &dir.path().join("same-health"),
            client.clone(),
            expiry
        )
        .unwrap()
        .with_health_key(health.clone())
        .unwrap()
        .with_observation_key(health.clone())
        .is_err()
    );
    assert!(
        LoopbackGate::open(
            "http://127.0.0.1:1234",
            &dir.path().join("same-health-reverse"),
            client.clone(),
            expiry
        )
        .unwrap()
        .with_observation_key(observer.clone())
        .unwrap()
        .with_health_key(observer.clone())
        .is_err()
    );
    let gate = LoopbackGate::open("http://127.0.0.1:1234", &path, client.clone(), expiry)
        .unwrap()
        .with_health_key(health.clone())
        .unwrap()
        .with_observation_key(observer.clone())
        .unwrap();
    for path in [
        "/v1/workload/result",
        "/v1/workload/logs/stdout",
        "/v1/workload/logs/stderr",
    ] {
        let proof = sign(&secret, "GET", path, b"");
        assert!(gate.verify(&proof, "GET", path, b"").is_ok());
        assert!(gate.verify(&proof, "GET", path, b"").is_err());
        for other in [&client_secret, &health_secret] {
            assert!(
                gate.verify(&sign(other, "GET", path, b""), "GET", path, b"")
                    .is_err()
            );
        }
    }
    for (method, path, body) in [
        ("POST", "/v1/workload/result", b"".as_slice()),
        ("GET", "/v1/workload/result", b"unexpected".as_slice()),
        ("GET", "/v1/workload/result?x=1", b"".as_slice()),
        ("GET", "/v1/workload/result/", b"".as_slice()),
        ("GET", "/v1/health", b"".as_slice()),
        ("POST", "/v1/approve", b"{}".as_slice()),
        ("POST", "/v1/write", b"{}".as_slice()),
    ] {
        assert!(
            gate.verify(&sign(&secret, method, path, body), method, path, body)
                .is_err()
        );
    }
    let proof = sign(&secret, "GET", "/v1/workload/result", b"");
    assert!(
        gate.verify(&proof, "GET", "/v1/workload/logs/stdout", b"")
            .is_err()
    );
    assert!(
        gate.verify(&proof, "GET", "/v1/workload/result", b"")
            .is_ok()
    );
    drop(gate);
    let gate = LoopbackGate::open("http://127.0.0.1:1234", &path, client, expiry)
        .unwrap()
        .with_health_key(health)
        .unwrap()
        .with_observation_key(observer)
        .unwrap();
    assert!(
        gate.verify(&proof, "GET", "/v1/workload/result", b"")
            .is_err()
    );
}
