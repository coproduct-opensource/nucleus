//! #2446 step 3a, driven through the real binary: a host-tier launcher proves
//! the proxy it starts with an identity it mints for the run
//! (`nucleus_identity::pod_files::issue_ephemeral`, what `nucleus run --local`,
//! `nucleus shell` and nucleus-perf now do), with no `--auth-secret` and no
//! orchestrator token. The proxy reads it as sandbox proof tier 2 and serves
//! over its peer-verified socket.
//!
//! Red before: those launchers had no proof but the tier-3 token, so a proxy
//! started as they start it, minus the secret, exited 78 (`NakedProcess`).
#![expect(
    clippy::disallowed_methods,
    reason = "integration fixture owns temporary files, child processes, and loopback HTTP"
)]
#![expect(
    clippy::disallowed_types,
    reason = "integration fixture launches the proxy and calls its socket API directly"
)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use nucleus_ifc_kernel::Operation;
use nucleus_provenance_memory::{SignedTaskRef, TokenScope};
use serde_json::{Value, json};

const CONTENTS: &str = "read me with no secret anywhere";

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Start the proxy as a host-tier launcher does: the socket, a public approval
/// key, the session task token, and the run's minted identity. Nothing else.
async fn launch(root: &Path) -> (Proxy, std::path::PathBuf) {
    let ws = root.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("notes.txt"), CONTENTS).unwrap();
    let spec_path = root.join("pod.json");
    std::fs::write(
        &spec_path,
        serde_json::to_vec(&json!({
            "apiVersion":"nucleus/v1", "kind":"Pod", "metadata":{"name":"host-tier-identity"},
            "spec":{"work_dir":ws,"policy":{"type":"profile","name":"permissive"}}
        }))
        .unwrap(),
    )
    .unwrap();
    let identity = nucleus_identity::pod_files::issue_ephemeral(
        root,
        "host-tier-identity",
        Duration::from_secs(600),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = SigningKey::from_bytes(&[42; 32]);
    let nonce = [7; 16];
    let token = SignedTaskRef::issue(
        "host-tier-identity",
        TokenScope::new(vec![Operation::ReadFiles], Vec::new()),
        nonce,
        now,
        600,
        &key,
    );
    let approver = SigningKey::from_bytes(&[9; 32]);
    let socket = root.join("p.sock");
    let announce = root.join("announce");
    let log_path = root.join("proxy.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let binary = std::env::var_os("NUCLEUS_TEST_PROXY_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nucleus-tool-proxy").into());
    let child = Command::new(binary)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .envs(identity.env())
        .env("NUCLEUS_TASK_TOKEN", serde_json::to_string(&token).unwrap())
        .env("NUCLEUS_TASK_TOKEN_NONCE", hex::encode(nonce))
        .env(
            "NUCLEUS_TASK_TOKEN_ISSUER",
            hex::encode(key.verifying_key().to_bytes()),
        )
        .env("NUCLEUS_TOOL_PROXY_DRAND_ENABLED", "false")
        .arg("--unsandboxed")
        .arg("--spec")
        .arg(&spec_path)
        .arg("--listen-unix")
        .arg(&socket)
        .arg("--approval-pubkeys")
        .arg(hex::encode(approver.verifying_key().to_bytes()))
        .arg("--audit-log")
        .arg(root.join("audit.jsonl"))
        .arg("--announce-path")
        .arg(&announce)
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let mut proxy = Proxy(child);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if std::fs::read_to_string(&announce).is_ok_and(|a| !a.trim().is_empty()) {
            return (proxy, socket);
        }
        if let Some(status) = proxy.0.try_wait().unwrap() {
            panic!(
                "proxy exited {status}: {}",
                std::fs::read_to_string(&log_path).unwrap()
            );
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "startup timed out: {}",
            std::fs::read_to_string(&log_path).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The minted identity is the proof: tier 2, named by the run's SPIFFE ID, and
/// a read is served over the socket with no secret anywhere.
#[tokio::test]
async fn a_host_tier_proxy_is_proven_by_its_minted_identity() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();
    let (_proxy, socket) = launch(root.path()).await;
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .build()
        .unwrap();

    let health: Value = client
        .get("http://localhost/v1/health")
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        health["sandbox_proof"],
        json!({"tier": 2, "label": "spiffe-identity"}),
        "{health}"
    );

    let response = client
        .post("http://localhost/v1/read")
        .timeout(Duration::from_secs(10))
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&json!({"path": "notes.txt"})).unwrap())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    let body = response.text().await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(body.contains(CONTENTS), "{body}");
}
