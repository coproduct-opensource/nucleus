//! A real version-control client pushing and listing refs through the shipped
//! adapter (#3210), with the credential only on the host side.
//!
//! ```text
//! client (git, as the workload) --TCP loopback--> nucleus-egress-http (process)
//!   --Unix socket--> stand-in door + host --HTTP--> fake smart-HTTP remote
//! ```
//!
//! The client is the real `git` binary, run as the adapter's managed command
//! with the remote rewritten onto the adapter's loopback origin by
//! `url.<origin>/.insteadOf` (the snippet in `examples/egress-git-remote/`).
//! No credential helper, no `http.extraHeader`: the client holds nothing.
//!
//! The door + host is a stand-in that performs the call the way the node does
//! for a version 2 open frame: the method and query the workload sent, the
//! protocol headers an operator would allow, and the credential header
//! injected last. The node's own handling of the same frame, against a fake
//! remote, is `nucleus-node`'s `broker_stream::tests::git`; this test is about
//! what the guest-side process carries and holds.
//!
//! Linux only, as the adapter is. It requires `git` on `PATH` and fails, not
//! skips, without it: a test that passes because the client was missing
//! would say nothing.
#![cfg(target_os = "linux")]
#![expect(
    clippy::disallowed_types,
    clippy::disallowed_methods,
    reason = "test fixtures: a fake remote, a stand-in host client, and executing git"
)]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{Path as Route, RawQuery, Request, State};
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use nucleus_spec::workload_egress::{upstream_url, url_env};

/// What the HOST holds and injects. Never in any environment in this test.
const TOKEN: &str = "test-token-123";
/// The upstream the pod declared for its remote.
const DECLARED: &str = "git-remote";
/// The headers an operator lists for this upstream (`request_headers`).
const ALLOWED: [&str; 3] = ["accept", "git-protocol", "content-encoding"];
/// The commit the fake remote advertises.
const MAIN: &str = "1111111111111111111111111111111111111111";

/// One pkt-line: four hex digits of length (including themselves), then the
/// payload.
fn pkt(payload: &str) -> String {
    format!("{:04x}{payload}", payload.len() + 4)
}

/// What the fake remote received.
#[derive(Debug, Clone)]
struct Hit {
    method: String,
    path: String,
    query: Option<String>,
    authorization: Option<String>,
    git_protocol: Option<String>,
    body: Vec<u8>,
}

type Hits = Arc<Mutex<Vec<Hit>>>;

/// A minimal smart-HTTP remote with canned answers: protocol v2 `ls-refs` for
/// fetch-side listing, and a v0 ref advertisement plus a successful report
/// for push. Records every request.
async fn remote(hits: Hits) -> String {
    let app = Router::new().fallback(move |request: Request| {
        let hits = hits.clone();
        async move {
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 16 << 20).await.unwrap().to_vec();
            let header = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let hit = Hit {
                method: parts.method.to_string(),
                path: parts.uri.path().to_string(),
                query: parts.uri.query().map(str::to_string),
                authorization: header("authorization"),
                git_protocol: header("git-protocol"),
                body,
            };
            hits.lock().unwrap().push(hit.clone());
            if hit.authorization.as_deref() != Some(&format!("Bearer {TOKEN}")) {
                return (StatusCode::UNAUTHORIZED, "credential required").into_response();
            }
            let (content_type, reply) = match (hit.method.as_str(), hit.query.as_deref()) {
                ("GET", Some("service=git-upload-pack")) => (
                    "application/x-git-upload-pack-advertisement",
                    format!("{}{}0000", pkt("version 2\n"), pkt("ls-refs\n")),
                ),
                ("POST", None) if hit.path.ends_with("/git-upload-pack") => (
                    "application/x-git-upload-pack-result",
                    format!("{}0000", pkt(&format!("{MAIN} refs/heads/main\n"))),
                ),
                ("GET", Some("service=git-receive-pack")) => (
                    "application/x-git-receive-pack-advertisement",
                    format!(
                        "{}0000{}0000",
                        pkt("# service=git-receive-pack\n"),
                        pkt(&format!(
                            "{} capabilities^{{}}\0report-status delete-refs\n",
                            "0".repeat(40)
                        )),
                    ),
                ),
                ("POST", None) if hit.path.ends_with("/git-receive-pack") => (
                    "application/x-git-receive-pack-result",
                    format!("{}{}0000", pkt("unpack ok\n"), pkt("ok refs/heads/main\n")),
                ),
                _ => return (StatusCode::NOT_FOUND, "no such route").into_response(),
            };
            ([(header::CONTENT_TYPE, content_type)], reply).into_response()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    origin
}

#[derive(Clone)]
struct Host {
    remote: String,
    client: reqwest::Client,
}

/// The stand-in door + host on `GET|POST /v1/egress/{name}/{*path}`.
async fn host_call(
    State(host): State<Host>,
    Route((name, path)): Route<(String, String)>,
    RawQuery(query): RawQuery,
    method: Method,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if name != DECLARED {
        return (StatusCode::FORBIDDEN, "not declared").into_response();
    }
    if let Some(query) = &query
        && let Err(refusal) = nucleus_spec::workload_egress::check_query(query)
    {
        return (StatusCode::BAD_REQUEST, refusal.to_string()).into_response();
    }
    let url = match &query {
        Some(query) => format!("{}/{path}?{query}", host.remote),
        None => format!("{}/{path}", host.remote),
    };
    let mut call = host.client.request(method.clone(), url);
    for name in ALLOWED {
        if let Some(value) = headers.get(name) {
            call = call.header(name, value);
        }
    }
    if method == Method::POST {
        if let Some(ct) = headers.get(header::CONTENT_TYPE) {
            call = call.header(header::CONTENT_TYPE, ct);
        }
        let body = axum::body::to_bytes(body, 16 << 20).await.unwrap();
        call = call.body(body);
    }
    call = call.header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
    let reply = call.send().await.unwrap();
    let mut out = Response::builder().status(reply.status());
    if let Some(ct) = reply.headers().get(header::CONTENT_TYPE) {
        out = out.header(header::CONTENT_TYPE, ct);
    }
    out.body(Body::from_stream(reply.bytes_stream())).unwrap()
}

fn door(dir: &Path, remote: String) -> String {
    let path = dir.join("door.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let host = Host {
        remote,
        client: reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap(),
    };
    let app = Router::new()
        .route(
            "/v1/egress/{name}/{*path}",
            axum::routing::get(host_call).post(host_call),
        )
        .with_state(host);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("unix://{}", path.display())
}

/// The workload: list the remote's refs, then push one commit to it, both
/// through the remote's ordinary `https://` URL rewritten onto the adapter.
const WORKLOAD: &str = r#"set -e
env > "$1/workload.env"
export HOME="$1/home" GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
mkdir -p "$HOME"
remote="https://forge.invalid/org/repo.git"
rewrite="url.$NUCLEUS_EGRESS_GIT_REMOTE_URL/.insteadOf=https://forge.invalid/"
git -c "$rewrite" -c protocol.version=2 ls-remote "$remote" > "$1/ls-remote.out"
git -c init.defaultBranch=main init -q "$1/work"
cd "$1/work"
git -c user.name=agent -c user.email=agent@example.invalid commit -q --allow-empty -m change
git -c "$rewrite" push "$remote" HEAD:refs/heads/main 2> "$1/push.err"
"#;

/// **(a) + (b): a real client lists refs and pushes through the adapter, the
/// remote sees the host's credential on every request, and the credential is
/// in neither the workload's environment nor the adapter's.** The ref
/// advertisement is a GET with its `service` query, the protocol-v2 listing
/// carries `Git-Protocol`, and the push's pack goes up as a POST.
///
/// A-19: putting the token in the environment the runtime gives the workload
/// reds the environment assertion; the adapter refusing GET (as before #3210)
/// reds every git step.
#[tokio::test]
async fn a_real_client_lists_and_pushes_with_the_credential_held_by_the_host() {
    let dir = tempfile::tempdir().unwrap();
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let remote = remote(hits.clone()).await;
    let door = door(dir.path(), remote);
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_nucleus-egress-http"))
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("NUCLEUS_TOOL_PROXY_URL", &door)
            .env(url_env(DECLARED), upstream_url(&door, DECLARED))
            .args([
                "--upstream",
                DECLARED,
                "--",
                "/bin/sh",
                "-c",
                WORKLOAD,
                "workload",
            ])
            .arg(dir.path())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("the workload finished within 60 s")
    .unwrap();
    let read = |name: &str| std::fs::read_to_string(dir.path().join(name)).unwrap_or_default();
    assert!(
        output.status.success(),
        "the workload failed: {}\nstderr: {}\npush: {}\nremote saw: {:#?}",
        output.status,
        String::from_utf8_lossy(&output.stderr),
        read("push.err"),
        hits.lock().unwrap()
    );

    assert!(
        read("ls-remote.out").contains(&format!("{MAIN}\trefs/heads/main")),
        "{}",
        read("ls-remote.out")
    );
    let env = read("workload.env");
    assert!(
        env.contains("NUCLEUS_EGRESS_GIT_REMOTE_URL=http://127.0.0.1:"),
        "{env}"
    );
    assert!(
        !env.contains(TOKEN),
        "the credential reached the workload's env"
    );

    let hits = hits.lock().unwrap().clone();
    let shape: Vec<(&str, &str, Option<&str>)> = hits
        .iter()
        .map(|h| (h.method.as_str(), h.path.as_str(), h.query.as_deref()))
        .collect();
    assert_eq!(
        shape,
        [
            (
                "GET",
                "/org/repo.git/info/refs",
                Some("service=git-upload-pack")
            ),
            ("POST", "/org/repo.git/git-upload-pack", None),
            (
                "GET",
                "/org/repo.git/info/refs",
                Some("service=git-receive-pack")
            ),
            ("POST", "/org/repo.git/git-receive-pack", None),
        ]
    );
    for hit in &hits {
        assert_eq!(
            hit.authorization.as_deref(),
            Some(&*format!("Bearer {TOKEN}")),
            "{} {}",
            hit.method,
            hit.path
        );
    }
    assert_eq!(hits[0].git_protocol.as_deref(), Some("version=2"));
    let push = String::from_utf8_lossy(&hits[3].body);
    assert!(
        push.contains("refs/heads/main") && push.contains("PACK"),
        "{push}"
    );
}
