//! The guest half of host-performs-the-call, composed through the shipped
//! adapter process (#3031, #2906).
//!
//! ```text
//! workload (this test, same uid) --TCP loopback--> nucleus-egress-http (process)
//!   --Unix socket--> stand-in door + host --HTTP--> fake upstream
//! ```
//!
//! The adapter is the real binary, started the way a pod starts it: as the
//! workload command, with the environment the runtime gives a pod that declared
//! `model-api` and nothing else. The door + host is a stand-in: it holds the
//! credential (a constant in this test's memory, never in any environment),
//! meters the upload against the pod's real `EgressLedger`, injects the header,
//! and streams the upstream's reply back. The tool-proxy's real door and relay
//! are tested in `nucleus-tool-proxy` (`egress::tests`), and the node's real
//! injection against a real upstream in `nucleus-node` (`broker_stream`); this
//! test is about what the GUEST-side process holds, admits and carries.
//!
//! Linux only: the adapter identifies loopback peers through `/proc/net/tcp`.
#![cfg(target_os = "linux")]
#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "test fixtures: a fake upstream client, and executing the built adapter"
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path as Route, Request, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use nucleus_spec::workload_egress::{upstream_url, url_env};
use portcullis::{EgressCeiling, EgressDecision, EgressLedger, EgressPace, EgressSettlement};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_stream::StreamExt as _;

/// What the HOST holds and injects. Never in any environment in this test.
const TOKEN: &str = "test-token-123";
/// The only upstream the pod declared.
const DECLARED: &str = "model-api";
/// Larger than the 256 KiB single-frame perform cap, in both directions.
const MIB: usize = 1024 * 1024;

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| b"0123456789abcdef"[i % 16]).collect()
}

/// What the fake upstream received.
#[derive(Debug, Default, Clone)]
struct Seen {
    calls: usize,
    authorization: Vec<String>,
    paths: Vec<String>,
    body_len: Vec<usize>,
}

/// The fake upstream: records each call and streams back 1 MiB.
async fn upstream(seen: Arc<Mutex<Seen>>) -> String {
    let app = Router::new().fallback(move |request: Request| {
        let seen = seen.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 4 * MIB).await.unwrap();
            {
                let mut seen = seen.lock().unwrap();
                seen.calls += 1;
                seen.authorization.push(
                    parts
                        .headers
                        .get(header::AUTHORIZATION)
                        .map(|v| v.to_str().unwrap().to_string())
                        .unwrap_or_default(),
                );
                seen.paths.push(parts.uri.path().to_string());
                seen.body_len.push(body.len());
            }
            let chunks: Vec<Result<Bytes, std::io::Error>> = payload(MIB)
                .chunks(16 * 1024)
                .map(|c| Ok(Bytes::copy_from_slice(c)))
                .collect();
            Response::builder()
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from_stream(tokio_stream::iter(chunks)))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    origin
}

#[derive(Clone)]
struct Host {
    upstream: String,
    ledger: Arc<Mutex<EgressLedger>>,
    client: reqwest::Client,
}

/// The stand-in door + host on `/v1/egress/{name}/{*path}`.
async fn host_call(
    State(host): State<Host>,
    Route((name, path)): Route<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if name != DECLARED {
        return (
            StatusCode::FORBIDDEN,
            format!("no credentialed upstream named {name:?} is configured for this pod"),
        )
            .into_response();
    }
    // Meter every chunk against the pod's one ledger BEFORE it may leave, as
    // the host does; a refusal names the dimension.
    let mut stream = body.into_data_stream();
    let mut upload = Vec::new();
    let mut refused = None;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.unwrap();
        if refused.is_some() {
            // Drain, as the real host does, so the sender reads the refusal
            // rather than a reset.
            continue;
        }
        let decision = host.ledger.lock().unwrap().reserve(chunk.len() as u64, 0);
        match decision {
            EgressDecision::Admitted(hold) => host
                .ledger
                .lock()
                .unwrap()
                .settle(hold, EgressSettlement::Sent)
                .unwrap(),
            EgressDecision::Refused(refusal, _) => refused = Some(refusal),
        }
        upload.extend_from_slice(&chunk);
    }
    if let Some(refusal) = refused {
        return (StatusCode::FORBIDDEN, refusal.to_string()).into_response();
    }
    let mut call = host
        .client
        .post(format!("{}/{path}", host.upstream))
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .body(upload);
    if let Some(ct) = headers.get(header::CONTENT_TYPE) {
        call = call.header(header::CONTENT_TYPE, ct);
    }
    let reply = call.send().await.unwrap();
    let status = reply.status();
    let mut out = Response::new(Body::from_stream(reply.bytes_stream()));
    *out.status_mut() = status;
    out
}

fn http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

/// Serve the stand-in door at `dir/door.sock`; returns its `unix://` URL.
fn door(dir: &Path, upstream: String, ceiling: u64) -> String {
    let path = dir.join("door.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let host = Host {
        upstream,
        ledger: Arc::new(Mutex::new(EgressLedger::new(EgressCeiling::new(
            ceiling,
            EgressPace::Unpaced,
        )))),
        client: http_client(),
    };
    let app = Router::new()
        .route("/v1/egress/{name}/{*path}", axum::routing::post(host_call))
        .with_state(host);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("unix://{}", path.display())
}

/// The environment the runtime gives a pod that declared only `model-api`.
fn runtime_env(door: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("NUCLEUS_TOOL_PROXY_URL".to_string(), door.to_string()),
        (url_env(DECLARED), upstream_url(door, DECLARED)),
    ])
}

/// A running adapter whose managed command dumps its environment, then waits
/// for `done`.
struct Adapter {
    child: tokio::process::Child,
    origin: String,
    env_file: PathBuf,
    done: PathBuf,
}

async fn start_adapter(dir: &Path, env: &BTreeMap<String, String>) -> Adapter {
    let env_file = dir.join("workload.env");
    let done = dir.join("done");
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_nucleus-egress-http"))
        .env_clear()
        .envs(env)
        .args([
            "--upstream",
            DECLARED,
            "--export",
            "HARNESS_BASE_URL=model-api",
            "--placeholder",
            "HARNESS_TOKEN",
            "--",
            "/bin/sh",
            "-c",
            // Bounded: a failed test must not leave a shell polling forever.
            "env > \"$1\"; i=0; while [ ! -e \"$2\" ] && [ $i -lt 600 ]; do sleep 0.05; \
             i=$((i+1)); done",
            "workload",
        ])
        .arg(&env_file)
        .arg(&done)
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = tokio::time::timeout(Duration::from_secs(10), lines.next_line())
        .await
        .expect("the adapter reported ready")
        .unwrap()
        .expect("a ready line");
    let origin = ready
        .strip_prefix(&format!("NUCLEUS_EGRESS_HTTP_READY {DECLARED} "))
        .unwrap_or_else(|| panic!("unexpected ready line {ready:?}"))
        .to_string();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !env_file.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the workload started");
    Adapter {
        child,
        origin,
        env_file,
        done,
    }
}

impl Adapter {
    /// The managed command's environment, as it dumped it.
    async fn workload_env(&self) -> String {
        // `env > file` may still be writing when the file appears.
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::fs::read_to_string(&self.env_file).unwrap()
    }

    /// The adapter process's own environment, as the kernel holds it.
    fn own_environ(&self) -> Vec<u8> {
        std::fs::read(format!("/proc/{}/environ", self.child.id().unwrap())).unwrap()
    }

    async fn finish(mut self) -> std::process::ExitStatus {
        std::fs::write(&self.done, b"").unwrap();
        tokio::time::timeout(Duration::from_secs(10), self.child.wait())
            .await
            .expect("the adapter exits with its workload")
            .unwrap()
    }
}

impl Drop for Adapter {
    /// On a failed assertion too: release the managed shell, which the
    /// adapter's `kill_on_drop` would otherwise orphan with the test's stdio.
    fn drop(&mut self) {
        let _ = std::fs::write(&self.done, b"");
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

/// **(a) + (d): the call reaches the upstream with the host's credential, and
/// the credential is nowhere the guest can see.** A 1 MiB upload and a 1 MiB
/// streamed reply, both past the old 256 KiB frame cap. The workload is told
/// loopback URLs under the runtime's key and its own variable, plus a
/// placeholder; the placeholder it sends is stripped, the host's token is what
/// the upstream sees, and neither the workload's environment nor the adapter's
/// carries the token.
///
/// A-19: putting the token in the environment the runtime gives the workload
/// (`runtime_env`) reds the two environment assertions.
#[tokio::test]
async fn a_declared_call_carries_the_hosts_credential_and_the_guest_holds_none() {
    let dir = tempfile::tempdir().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let upstream = upstream(seen.clone()).await;
    let door = door(dir.path(), upstream, 64 * MIB as u64);
    let adapter = start_adapter(dir.path(), &runtime_env(&door)).await;

    let env = adapter.workload_env().await;
    let origin = &adapter.origin;
    assert!(
        env.contains(&format!("NUCLEUS_EGRESS_MODEL_API_URL={origin}\n")),
        "the runtime's key now names the loopback URL: {env}"
    );
    assert!(
        env.contains(&format!("HARNESS_BASE_URL={origin}\n")),
        "{env}"
    );
    let placeholder = "nucleus-egress-placeholder-not-a-credential";
    assert!(
        env.contains(&format!("HARNESS_TOKEN={placeholder}\n")),
        "{env}"
    );
    assert!(
        !env.contains(TOKEN),
        "the credential reached the workload's env"
    );
    assert!(
        !contains(&adapter.own_environ(), TOKEN),
        "the credential reached the adapter's env"
    );

    let body = payload(MIB);
    let reply = http_client()
        .post(format!("{origin}/v1/messages"))
        .header(header::AUTHORIZATION, format!("Bearer {placeholder}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    let mut received = 0;
    let mut stream = reply.bytes_stream();
    let mut chunks = 0;
    while let Some(chunk) = stream.next().await {
        received += chunk.unwrap().len();
        chunks += 1;
    }
    assert_eq!(received, MIB, "the whole reply streamed back");
    assert!(chunks > 1, "the reply arrived in pieces, not one frame");

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.calls, 1);
    assert_eq!(seen.authorization, [format!("Bearer {TOKEN}")]);
    assert_eq!(seen.paths, ["/v1/messages"]);
    assert_eq!(seen.body_len, [MIB]);
    assert!(adapter.finish().await.success());
}

/// **(c): the pod's egress ledger still applies through this path, and its
/// refusal reaches the workload by name.** A 1.5 MiB ceiling admits the first
/// 1 MiB upload and refuses the second, which never reaches the upstream.
#[tokio::test]
async fn the_egress_ceiling_refuses_through_the_adapter_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let upstream = upstream(seen.clone()).await;
    let door = door(dir.path(), upstream, (3 * MIB / 2) as u64);
    let adapter = start_adapter(dir.path(), &runtime_env(&door)).await;
    let client = http_client();
    let send = || {
        client
            .post(format!("{}/v1/messages", adapter.origin))
            .body(payload(MIB))
            .send()
    };
    assert_eq!(send().await.unwrap().status(), StatusCode::OK);
    let refused = send().await.unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    let reason = refused.text().await.unwrap();
    assert!(
        reason.contains("egress budget exhausted (egress.max_bytes)"),
        "the workload must see why: {reason}"
    );
    assert_eq!(seen.lock().unwrap().calls, 1, "the refused call never left");
    assert!(adapter.finish().await.success());
}

/// **(b): an upstream the pod did not declare is refused by name before the
/// workload starts**, and the managed command never runs.
#[tokio::test]
async fn an_undeclared_upstream_is_refused_before_the_workload_runs() {
    let dir = tempfile::tempdir().unwrap();
    let door = format!("unix://{}", dir.path().join("door.sock").display());
    let ran = dir.path().join("ran");
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_nucleus-egress-http"))
        .env_clear()
        .envs(runtime_env(&door))
        .args([
            "--upstream",
            "git-remote",
            "--",
            "/bin/sh",
            "-c",
            "touch \"$1\"",
            "x",
        ])
        .arg(&ran)
        .output()
        .await
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`git-remote` is not declared"), "{stderr}");
    assert!(stderr.contains("declared: model-api"), "{stderr}");
    assert!(!ran.exists(), "the workload ran under a refused adapter");
}
