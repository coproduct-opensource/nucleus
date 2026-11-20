//! #2446 step 3, driven through the real binary: the shared-secret tier, the
//! tier-3 orchestrator token and the `--auth-secret` that keyed both are
//! deleted, and what a launcher used to pass for them is refused by name.
//!
//! Red before step 3 (the binary from main, as `NUCLEUS_TEST_PROXY_BIN`):
//! - the old container launch (token + secret, no identity) started at sandbox
//!   proof tier 3;
//! - a leftover token beside a minted identity was read silently;
//! - plain TCP without mTLS exited for want of a secret, never for want of a
//!   transport that proves a caller.
#![expect(
    clippy::disallowed_methods,
    reason = "integration fixture owns temporary files and child processes"
)]
#![expect(
    clippy::disallowed_types,
    reason = "integration fixture launches the proxy and calls its socket API directly"
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use hmac::{Mac, digest::KeyInit};
use nucleus_ifc_kernel::Operation;
use nucleus_provenance_memory::{SignedTaskRef, TokenScope};
use serde_json::{Value, json};

const SECRET: &str = "shared-secret-tier-fixture-32-bytes!";

struct Proxy {
    child: Child,
    log: PathBuf,
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// How the fixture starts the proxy. Each field is one input a launcher
/// either passed before step 3 or passes now.
struct Launch {
    /// `--listen-unix <root>/p.sock`; otherwise loopback TCP.
    socket: bool,
    /// The run's minted identity (`pod_files::issue_ephemeral`), the proof
    /// every launcher now writes.
    identity: bool,
    /// `--auth-secret`, the retired key.
    secret: bool,
    /// `NUCLEUS_SANDBOX_TOKEN`, the retired tier-3 token, HMAC'd as the node
    /// used to mint it.
    token: bool,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The token exactly as `nucleus_client::generate_sandbox_token` minted it
/// before step 3 deleted it: `sandbox-proof.{pod}.{spec_hash}.{ts}.{hmac}`.
fn old_token() -> String {
    let message = format!("sandbox-proof.secret-tier.{}.{}", "ab".repeat(32), now());
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
    mac.update(message.as_bytes());
    format!("{message}.{}", hex::encode(mac.finalize().into_bytes()))
}

fn start(root: &Path, launch: &Launch) -> Proxy {
    let ws = root.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let spec_path = root.join("pod.json");
    std::fs::write(
        &spec_path,
        serde_json::to_vec(&json!({
            "apiVersion":"nucleus/v1", "kind":"Pod", "metadata":{"name":"secret-tier"},
            "spec":{"work_dir":ws,"policy":{"type":"profile","name":"permissive"}}
        }))
        .unwrap(),
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    let nonce = [7; 16];
    let task = SignedTaskRef::issue(
        "secret-tier",
        TokenScope::new(vec![Operation::ReadFiles], Vec::new()),
        nonce,
        now(),
        600,
        &key,
    );
    let approver = SigningKey::from_bytes(&[9; 32]);
    let log = root.join("proxy.log");
    let binary = std::env::var_os("NUCLEUS_TEST_PROXY_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nucleus-tool-proxy").into());
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .env("NUCLEUS_TASK_TOKEN", serde_json::to_string(&task).unwrap())
        .env("NUCLEUS_TASK_TOKEN_NONCE", hex::encode(nonce))
        .env(
            "NUCLEUS_TASK_TOKEN_ISSUER",
            hex::encode(key.verifying_key().to_bytes()),
        )
        .env("NUCLEUS_TOOL_PROXY_DRAND_ENABLED", "false")
        .arg("--unsandboxed")
        .arg("--spec")
        .arg(&spec_path)
        .arg("--approval-pubkeys")
        .arg(hex::encode(approver.verifying_key().to_bytes()))
        .arg("--audit-log")
        .arg(root.join("audit.jsonl"))
        .arg("--announce-path")
        .arg(root.join("announce"));
    if launch.socket {
        command.arg("--listen-unix").arg(root.join("p.sock"));
    } else {
        command.arg("--listen").arg("127.0.0.1:0");
    }
    if launch.identity {
        let files = nucleus_identity::pod_files::issue_ephemeral(
            root,
            "secret-tier",
            Duration::from_secs(600),
        )
        .unwrap();
        command.envs(files.env());
    }
    if launch.secret {
        command.arg("--auth-secret").arg(SECRET);
    }
    if launch.token {
        command.env("NUCLEUS_SANDBOX_TOKEN", old_token());
    }
    let file = std::fs::File::create(&log).unwrap();
    let child = command
        .stdin(Stdio::null())
        .stdout(file.try_clone().unwrap())
        .stderr(file)
        .spawn()
        .unwrap();
    Proxy { child, log }
}

/// Wait for the proxy to exit, and return its code and log. Panics if it is
/// still serving: every caller here expects a refusal.
async fn refused(root: &Path, proxy: &mut Proxy) -> (Option<i32>, String) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(status) = proxy.child.try_wait().unwrap() {
            return (status.code(), std::fs::read_to_string(&proxy.log).unwrap());
        }
        let announced = std::fs::read_to_string(root.join("announce")).unwrap_or_default();
        assert!(
            announced.trim().is_empty(),
            "the proxy started and announced {announced:?}: {}",
            std::fs::read_to_string(&proxy.log).unwrap()
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "neither started nor refused: {}",
            std::fs::read_to_string(&proxy.log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The container driver's old `tcp-hmac` launch, minus the TCP: a token the
/// shared secret signs, the secret itself, and no identity. It used to start
/// at sandbox proof tier 3. It is refused, naming the flag.
#[tokio::test]
async fn the_old_token_and_secret_launch_is_refused_by_name() {
    let root = tempfile::tempdir().unwrap();
    let mut proxy = start(
        root.path(),
        &Launch {
            socket: true,
            identity: false,
            secret: true,
            token: true,
        },
    );
    let (code, log) = refused(root.path(), &mut proxy).await;
    assert_eq!(code, Some(78), "{log}");
    for needle in ["--auth-secret", "#2446", "retired"] {
        assert!(log.contains(needle), "missing {needle:?} in: {log}");
    }
}

/// A node from before step 3 still sets the token beside the identity files.
/// The identity is the proof (tier 2), and the token is named as ignored,
/// never read.
#[tokio::test]
async fn a_leftover_token_is_named_and_the_identity_is_the_proof() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();
    let proxy = start(
        root.path(),
        &Launch {
            socket: true,
            identity: true,
            secret: false,
            token: true,
        },
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut proxy = proxy;
    while std::fs::read_to_string(root.path().join("announce"))
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        if let Some(status) = proxy.child.try_wait().unwrap() {
            panic!(
                "proxy exited {status}: {}",
                std::fs::read_to_string(&proxy.log).unwrap()
            );
        }
        assert!(tokio::time::Instant::now() < deadline, "startup timed out");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let client = reqwest::Client::builder()
        .unix_socket(root.path().join("p.sock"))
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
    let log = std::fs::read_to_string(&proxy.log).unwrap();
    assert!(
        log.contains("NUCLEUS_SANDBOX_TOKEN is set") && log.contains("ignored"),
        "the leftover token is named: {log}"
    );
}

/// Plain TCP without mTLS proves no caller. With the shared-secret tier gone
/// it would answer only `/v1/health`, so it is refused at startup, naming the
/// transports that work, rather than for want of a secret.
#[tokio::test]
async fn plain_tcp_without_mtls_is_refused_by_name() {
    let root = tempfile::tempdir().unwrap();
    let mut proxy = start(
        root.path(),
        &Launch {
            socket: false,
            identity: true,
            secret: false,
            token: false,
        },
    );
    let (code, log) = refused(root.path(), &mut proxy).await;
    assert_eq!(code, Some(78), "{log}");
    for needle in ["--mtls", "--listen-unix", "#2446"] {
        assert!(log.contains(needle), "missing {needle:?} in: {log}");
    }
}
