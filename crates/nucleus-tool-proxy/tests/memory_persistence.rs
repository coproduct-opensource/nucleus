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
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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

/// Which tier the proxy's children are on, as the launcher declares it.
#[derive(Clone, Copy)]
enum Children {
    /// No `--unsandboxed`: a non-root proxy spawns no child at all (each is
    /// refused by name) and a root one drops them, so no child can reach the
    /// journal (#3454).
    Separated,
    /// `--unsandboxed`: a non-root proxy's children run at its own uid.
    BareTier,
}

async fn launch(root: &Path, iteration: usize) -> Proxy {
    start(root, iteration, Children::Separated)
        .await
        .unwrap_or_else(|log| panic!("proxy exited: {log}"))
}

/// Start the proxy and wait for it to announce, or for it to exit (`Err`
/// with its log).
async fn start(root: &Path, iteration: usize, children: Children) -> Result<Proxy, String> {
    let spec_path = root.join("pod.json");
    let identity_dir = root.join(format!("identity-{iteration}"));
    std::fs::create_dir_all(&identity_dir).unwrap();
    let identity = nucleus_identity::pod_files::issue_ephemeral(
        &identity_dir,
        "memory-runtime",
        Duration::from_secs(600),
    )
    .unwrap();
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
        // The run's minted identity is the sandbox proof, as for every
        // host-tier launcher (#2446 step 3 deleted the HMAC'd token).
        .envs(identity.env())
        .env("NUCLEUS_TASK_TOKEN", serde_json::to_string(&token).unwrap())
        .env("NUCLEUS_TASK_TOKEN_NONCE", hex::encode(nonce))
        .env(
            "NUCLEUS_TASK_TOKEN_ISSUER",
            hex::encode(key.verifying_key().to_bytes()),
        )
        .arg("--spec")
        .arg(spec_path)
        .args(match children {
            Children::Separated => None,
            Children::BareTier => Some("--unsandboxed"),
        })
        // The peer-verified socket: the shared-secret tier this fixture used
        // to sign for is deleted (#2446 step 3).
        .arg("--listen-unix")
        .arg(root.join(format!("p{iteration}.sock")))
        .arg("--approval-pubkeys")
        .arg(hex::encode(
            SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        ))
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
            if !address.trim().is_empty() {
                proxy.url = address.trim().to_string();
                return Ok(proxy);
            }
        }
        if proxy.child.try_wait().unwrap().is_some() {
            return Err(std::fs::read_to_string(&log_path).unwrap());
        }
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
    let socket = proxy
        .url
        .strip_prefix("unix://")
        .unwrap_or_else(|| panic!("announced {} rather than a socket", proxy.url));
    let response = reqwest::Client::builder()
        .unix_socket(socket)
        .build()
        .unwrap()
        .post(format!("http://localhost{route}"))
        .timeout(Duration::from_secs(10))
        .header("content-type", "application/json")
        .body(bytes)
        .send()
        .await
        .unwrap();
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
    assert!(journal.starts_with("{\"schema\":\"nucleus.memory-journal.v2\""));
    let commit: Value = serde_json::from_str(journal.lines().nth(1).unwrap()).unwrap();
    assert_eq!(commit["version"], 1);
    assert_eq!(
        commit["records"][0]["derivation"],
        serde_json::to_value(derivation).unwrap()
    );
}

/// **#3454 on the live startup path.** A proxy whose children are on the bare
/// host tier (`--unsandboxed`, non-root) would let every `/v1/run` child and
/// the workload `cat` and `>>` the journal outside mediation, so it does not
/// open one: it exits naming the tier, before creating the journal. Red on the
/// parent commit, where this proxy started and served. A root runtime drops
/// its children even here, so it starts.
#[tokio::test]
async fn a_bare_tier_proxy_refuses_a_persistent_journal_by_name() {
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
    match (
        nucleus::runtime_uid(),
        start(root.path(), 1, Children::BareTier).await,
    ) {
        (0, Ok(_proxy)) => {}
        (0, Err(log)) => panic!("a root proxy drops its children and must start: {log}"),
        (_, Ok(_proxy)) => {
            panic!("a bare-tier proxy opened a persistent journal its children can read and append")
        }
        (_, Err(log)) => {
            assert!(log.contains("bare host tier"), "refused by name: {log}");
            assert!(
                !state.join("memory.jsonl").exists(),
                "refused before the journal was created"
            );
        }
    }
}
