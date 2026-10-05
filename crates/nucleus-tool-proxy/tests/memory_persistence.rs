//! Ordinary process-restart validation of the shipped memory HTTP handlers.
#![expect(
    clippy::disallowed_methods,
    reason = "integration fixture owns temporary files, child processes, and loopback HTTP"
)]
#![expect(
    clippy::disallowed_types,
    reason = "integration fixture launches the proxy and calls its loopback API directly"
)]

use ed25519_dalek::SigningKey;
use nucleus_ifc_kernel::Operation;
use nucleus_provenance_memory::{
    ContentHash, MemoryDerivation, SchemaType, SignedTaskRef, SourceClass, TokenScope,
    recompute::derive_label,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SECRET: &str = "memory-runtime-fixture-secret-32-bytes";

struct Proxy {
    child: Child,
    url: String,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn launch(root: &Path, iteration: usize) -> Proxy {
    let spec_path = root.join("pod.json");
    let spec = std::fs::read(&spec_path).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = SigningKey::from_bytes(&[42; 32]);
    let nonce = [iteration as u8; 16];
    let token = SignedTaskRef::issue(
        "memory-runtime",
        TokenScope::new(
            vec![Operation::WriteFiles, Operation::ReadFiles],
            vec!["memory://**".into()],
        ),
        nonce,
        now,
        600,
        &key,
    );
    let announce = root.join(format!("announce-{iteration}"));
    let log_path = root.join(format!("proxy-{iteration}.log"));
    let log = std::fs::File::create(&log_path).unwrap();
    let binary = std::env::var_os("NUCLEUS_TEST_PROXY_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nucleus-tool-proxy").into());
    let child = Command::new(binary)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .env(
            "NUCLEUS_SANDBOX_TOKEN",
            nucleus_client::generate_sandbox_token(
                SECRET.as_bytes(),
                "memory-runtime",
                &hex::encode(Sha256::digest(&spec)),
            ),
        )
        .env("NUCLEUS_TASK_TOKEN", serde_json::to_string(&token).unwrap())
        .env("NUCLEUS_TASK_TOKEN_NONCE", hex::encode(nonce))
        .env(
            "NUCLEUS_TASK_TOKEN_ISSUER",
            hex::encode(key.verifying_key().to_bytes()),
        )
        .arg("--spec")
        .arg(spec_path)
        .arg("--unsandboxed")
        .arg("--auth-secret")
        .arg(SECRET)
        .arg("--approval-secret")
        .arg("separate-fixture-approval-secret")
        .arg("--audit-log")
        .arg(root.join(format!("audit-{iteration}.jsonl")))
        .arg("--announce-path")
        .arg(&announce)
        .arg("--memory-store")
        .arg(root.join("state/memory.jsonl"))
        .arg("--memory-namespace")
        .arg("project-a")
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let mut proxy = Proxy {
        child,
        url: String::new(),
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(address) = std::fs::read_to_string(&announce) {
            proxy.url = format!("http://{}", address.trim());
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

async fn post(proxy: &Proxy, route: &str, body: Value) -> Value {
    let bytes = serde_json::to_vec(&body).unwrap();
    let mut request = reqwest::Client::new()
        .post(format!("{}{route}", proxy.url))
        .timeout(Duration::from_secs(10))
        .header("content-type", "application/json");
    for (key, value) in nucleus_client::sign_http_headers(SECRET.as_bytes(), None, &bytes).headers {
        request = request.header(key, value);
    }
    let response = request.body(bytes).send().await.unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert!(status.is_success(), "{route}: {status}: {body}");
    serde_json::from_str(&body).unwrap()
}

#[tokio::test]
async fn live_memory_write_survives_proxy_restart_and_recall_preserves_label() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let workspace = root.path().join("workspace");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::create_dir(&workspace).unwrap();
    std::fs::write(
        root.path().join("pod.json"),
        serde_json::to_vec(&json!({
            "apiVersion":"nucleus/v1", "kind":"Pod", "metadata":{"name":"memory-runtime"},
            "spec":{"work_dir":workspace,"policy":{"type":"profile","name":"permissive"}}
        }))
        .unwrap(),
    )
    .unwrap();
    let value = "Project uses the standard test command.";
    let derivation = MemoryDerivation::RawIngest {
        source_class: SourceClass::Web,
        source_hash: ContentHash::of_canonical_bytes(value.as_bytes()),
    };
    let label = derive_label(&derivation, &[]);
    let first = launch(root.path(), 1).await;
    let write = post(
        &first,
        "/v1/memory/write",
        json!({"value":value,"schema":SchemaType::String,"label":label,"derivation":derivation}),
    )
    .await;
    assert_eq!(write["admitted"], true);
    drop(first);
    let second = launch(root.path(), 2).await;
    let recall = post(
        &second,
        "/v1/memory/recall",
        json!({"content_hash":write["content_hash"],"declassify":null}),
    )
    .await;
    assert_eq!(recall["value"], value);
    assert_eq!(recall["label"], serde_json::to_value(label).unwrap());
    assert_eq!(recall["declassified"], false);
    let journal = std::fs::read_to_string(state.join("memory.jsonl")).unwrap();
    let record: Value = serde_json::from_str(journal.lines().nth(1).unwrap()).unwrap();
    assert_eq!(
        record["derivation"],
        serde_json::to_value(derivation).unwrap()
    );
}
