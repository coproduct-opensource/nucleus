//! #2446 step 2, driven through the real binary: the shared-secret (HMAC) tier
//! admits only `/v1/health`, and the peer-verified socket that replaced it for
//! every host-side caller serves the same request.
//!
//! Red before step 2: a request signed with the shared secret was admitted
//! under the pod's whole policy, so the read below returned the file.
#![expect(
    clippy::disallowed_methods,
    reason = "integration fixture owns temporary files, child processes, and loopback HTTP"
)]
#![expect(
    clippy::disallowed_types,
    reason = "integration fixture launches the proxy and calls its loopback API directly"
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use nucleus_ifc_kernel::Operation;
use nucleus_provenance_memory::{SignedTaskRef, TokenScope};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SECRET: &str = "shared-secret-tier-fixture-32-bytes!";
const CONTENTS: &str = "read me through the tier that may";

struct Proxy {
    child: Child,
    /// What the proxy announced: `host:port`, or `unix:///…`.
    announced: String,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The transport the proxy is started on.
enum Listen {
    /// Loopback TCP, where the shared-secret tier is the one selected.
    Tcp,
    /// The peer-verified socket at this path.
    Unix(PathBuf),
}

fn workspace(root: &Path) -> PathBuf {
    let ws = root.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    std::fs::write(ws.join("notes.txt"), CONTENTS).unwrap();
    std::fs::write(
        root.join("pod.json"),
        serde_json::to_vec(&json!({
            "apiVersion":"nucleus/v1", "kind":"Pod", "metadata":{"name":"secret-tier"},
            "spec":{"work_dir":ws,"policy":{"type":"profile","name":"permissive"}}
        }))
        .unwrap(),
    )
    .unwrap();
    ws
}

async fn launch(root: &Path, listen: Listen) -> Proxy {
    let spec_path = root.join("pod.json");
    let spec = std::fs::read(&spec_path).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = SigningKey::from_bytes(&[42; 32]);
    let nonce = [7; 16];
    let token = SignedTaskRef::issue(
        "secret-tier",
        TokenScope::new(vec![Operation::ReadFiles], Vec::new()),
        nonce,
        now,
        600,
        &key,
    );
    let announce = root.join("announce");
    let _ = std::fs::remove_file(&announce);
    let log_path = root.join("proxy.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let binary = std::env::var_os("NUCLEUS_TEST_PROXY_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nucleus-tool-proxy").into());
    let mut command = Command::new(binary);
    match &listen {
        Listen::Tcp => {}
        Listen::Unix(path) => {
            command.arg("--listen-unix").arg(path);
        }
    }
    let child = command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .env(
            "NUCLEUS_SANDBOX_TOKEN",
            nucleus_client::generate_sandbox_token(
                SECRET.as_bytes(),
                "secret-tier",
                &hex::encode(Sha256::digest(&spec)),
            ),
        )
        .env("NUCLEUS_TASK_TOKEN", serde_json::to_string(&token).unwrap())
        .env("NUCLEUS_TASK_TOKEN_NONCE", hex::encode(nonce))
        .env(
            "NUCLEUS_TASK_TOKEN_ISSUER",
            hex::encode(key.verifying_key().to_bytes()),
        )
        .env("NUCLEUS_TOOL_PROXY_DRAND_ENABLED", "false")
        .arg("--spec")
        .arg(spec_path)
        .arg("--unsandboxed")
        .arg("--auth-secret")
        .arg(SECRET)
        .arg("--approval-secret")
        .arg("separate-fixture-approval-secret")
        .arg("--audit-log")
        .arg(root.join("audit.jsonl"))
        .arg("--announce-path")
        .arg(&announce)
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let mut proxy = Proxy {
        child,
        announced: String::new(),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(address) = std::fs::read_to_string(&announce)
            && !address.trim().is_empty()
        {
            proxy.announced = address.trim().to_string();
            return proxy;
        }
        assert!(
            proxy.child.try_wait().unwrap().is_none(),
            "proxy exited: {}",
            std::fs::read_to_string(&log_path).unwrap()
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "startup timed out: {}",
            std::fs::read_to_string(&log_path).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn read_notes(client: &reqwest::Client, base: &str, signed: bool) -> (u16, Value) {
    let bytes = serde_json::to_vec(&json!({"path": "notes.txt"})).unwrap();
    let mut request = client
        .post(format!("{base}/v1/read"))
        .timeout(Duration::from_secs(10))
        .header("content-type", "application/json");
    if signed {
        for (key, value) in
            nucleus_client::sign_http_headers(SECRET.as_bytes(), None, &bytes).headers
        {
            request = request.header(key, value);
        }
    }
    let response = request.body(bytes).send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

/// A request the shared secret signs correctly is refused, by name, on every
/// route but `/v1/health`.
#[tokio::test]
async fn the_shared_secret_tier_admits_only_health() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();
    workspace(root.path());
    let proxy = launch(root.path(), Listen::Tcp).await;
    let base = format!("http://{}", proxy.announced);
    let client = reqwest::Client::new();

    let health = client
        .get(format!("{base}/v1/health"))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status().as_u16(), 200, "health stays answerable");

    let (status, body) = read_notes(&client, &base, true).await;
    assert_eq!(
        status, 401,
        "a shared-secret request must be refused: {body}"
    );
    assert!(
        body.to_string().contains("carries no authority"),
        "the refusal names the retired tier: {body}"
    );
    assert!(
        !body.to_string().contains(CONTENTS),
        "nothing was read: {body}"
    );
}

/// The peer-verified socket every host-side caller moved to serves the same
/// read with no secret at all.
#[tokio::test]
async fn the_peer_verified_socket_serves_what_the_secret_no_longer_can() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();
    workspace(root.path());
    let socket = root.path().join("p.sock");
    let proxy = launch(root.path(), Listen::Unix(socket.clone())).await;
    assert!(
        proxy.announced.starts_with("unix://"),
        "the socket is what is announced: {}",
        proxy.announced
    );
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .build()
        .unwrap();
    let (status, body) = read_notes(&client, "http://localhost", false).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.to_string().contains(CONTENTS), "{body}");
}
