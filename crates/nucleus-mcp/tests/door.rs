//! The bridge as an agent runs it inside a pod: configured only by the
//! runtime's `NUCLEUS_TOOL_PROXY_URL=unix://<door>`, holding no secret, speaking
//! MCP on stdio, and reaching its proxy over a real Unix socket (#2696 P2).
//!
//! These drive the built binary, not its internals, so they say what an agent
//! sees: the tool list, a tool call's answer, and a refusal's reason.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;

use nucleus_client::wire::{ReadRequest, ReadResponse};
use serde_json::{Value, json};

/// One request as the test door received it.
struct Seen {
    request_line: String,
    head: String,
    body: Vec<u8>,
}

fn read_request(stream: &mut UnixStream) -> Seen {
    let mut req = Vec::new();
    let mut buf = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut buf).expect("read request");
        assert!(n > 0, "connection closed mid-request");
        req.extend_from_slice(&buf[..n]);
        if let Some(i) = req.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&req[..head_end]).into_owned();
    let len: usize = head
        .to_ascii_lowercase()
        .lines()
        .find_map(|l| l.strip_prefix("content-length:").map(str::to_owned))
        .map_or(0, |v| v.trim().parse().expect("content-length"));
    while req.len() < head_end + len {
        let n = stream.read(&mut buf).expect("read body");
        assert!(n > 0, "connection closed mid-body");
        req.extend_from_slice(&buf[..n]);
    }
    Seen {
        request_line: head.lines().next().unwrap_or_default().to_owned(),
        head,
        body: req[head_end..].to_vec(),
    }
}

fn respond(stream: &mut UnixStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write response");
}

/// A test proxy door. `/v1/read` of `hello.txt` answers with its contents
/// through the shared wire type; any other path is refused the way the
/// tool-proxy's `ApiError` refuses a sandbox escape. Serves `n` requests and
/// reports each.
fn test_door(listener: UnixListener, n: usize) -> mpsc::Receiver<Seen> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for _ in 0..n {
            let (mut stream, _) = listener.accept().expect("accept");
            let seen = read_request(&mut stream);
            let req: ReadRequest = serde_json::from_slice(&seen.body).expect("a wire ReadRequest");
            if seen.request_line.starts_with("POST /v1/read ") && req.path == "hello.txt" {
                let reply = serde_json::to_string(&ReadResponse {
                    contents: "hello from the door".into(),
                })
                .unwrap();
                respond(&mut stream, "200 OK", &reply);
            } else {
                respond(
                    &mut stream,
                    "403 Forbidden",
                    r#"{"error":"path escapes the sandbox root","kind":"sandbox_escape"}"#,
                );
            }
            let _ = tx.send(seen);
        }
    });
    rx
}

/// Run the bridge with `env` (and nothing inherited), feed it `requests`, and
/// return its stdout lines and exit status.
fn run_bridge(
    env: &[(&str, &str)],
    requests: &[Value],
) -> (Vec<Value>, std::process::ExitStatus, String) {
    run_bridge_with_args(&[], env, requests)
}

/// [`run_bridge`] with command-line `args` as well.
fn run_bridge_with_args(
    args: &[&str],
    env: &[(&str, &str)],
    requests: &[Value],
) -> (Vec<Value>, std::process::ExitStatus, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nucleus-mcp"));
    cmd.args(args)
        .env_clear()
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn nucleus-mcp");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        for r in requests {
            // A bridge that exited at startup closes its stdin; the exit
            // status below is what the test asserts then.
            if writeln!(stdin, "{r}").is_err() {
                break;
            }
        }
    }
    let out = child.wait_with_output().expect("wait");
    let lines = BufReader::new(out.stdout.as_slice())
        .lines()
        .map(|l| serde_json::from_str(&l.expect("utf-8 line")).expect("a JSON-RPC line"))
        .collect();
    (
        lines,
        out.status,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn rpc(id: u64, method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })
}

/// A pod spec whose policy is the named profile.
fn spec_doc(profile: &str) -> String {
    format!(
        "apiVersion: nucleus/v1\nkind: Pod\nspec:\n  policy:\n    type: profile\n    name: {profile}\n"
    )
}

fn tool_names(lines: &[Value], id: u64) -> Vec<String> {
    reply(lines, id)["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect()
}

/// ADR 0007 B-2: a bridge given a good door and no spec refuses to start, by
/// name, before it answers anything. Red before: it started, ran its kernel on
/// `PermissionLattice::permissive` and listed read, write, run, web_fetch,
/// glob and grep.
#[test]
fn a_bridge_without_a_spec_refuses_to_start_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("workload.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    let url = format!("unix://{}", socket.display());

    let (lines, status, stderr) = run_bridge(
        &[("NUCLEUS_TOOL_PROXY_URL", &url)],
        &[
            rpc(1, "initialize", json!({ "protocolVersion": "2025-11-25" })),
            rpc(2, "tools/list", json!({})),
        ],
    );
    assert!(!status.success(), "started with no spec: {lines:?}");
    assert!(lines.is_empty(), "answered with no spec: {lines:?}");
    for name in [
        "--spec",
        "NUCLEUS_MCP_SPEC",
        "--spec-yaml",
        "NUCLEUS_MCP_SPEC_YAML",
    ] {
        assert!(stderr.contains(name), "{name} not named: {stderr}");
    }
}

/// The tools offered are the spec's, and only the spec's: a read-only spec
/// offers no write, run or fetch.
#[test]
fn the_spec_decides_the_offered_tools() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("workload.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    let url = format!("unix://{}", socket.display());
    let spec = spec_doc("read-only");

    let (lines, status, stderr) = run_bridge(
        &[
            ("NUCLEUS_TOOL_PROXY_URL", &url),
            ("NUCLEUS_MCP_SPEC_YAML", &spec),
        ],
        &[rpc(1, "tools/list", json!({}))],
    );
    assert!(status.success(), "bridge failed: {status}\n{stderr}");
    let tools = tool_names(&lines, 1);
    assert!(tools.iter().any(|t| t == "read"), "{tools:?}");
    for denied in ["write", "run", "web_fetch", "create_pod"] {
        assert!(
            !tools.iter().any(|t| t == denied),
            "{denied} offered: {tools:?}"
        );
    }
}

fn reply(lines: &[Value], id: u64) -> &Value {
    lines
        .iter()
        .find(|l| l["id"] == id)
        .unwrap_or_else(|| panic!("no reply to request {id}: {lines:#?}"))
}

/// `tools/list` and two `read`s over a real Unix socket: the first gets the
/// door's answer, the second the door's refusal with its reason. The bridge is
/// given the door URL the way the runtime gives it, and no secret, and sends
/// none.
#[test]
fn an_agent_lists_tools_and_reads_through_the_door() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("workload.sock");
    let door = test_door(UnixListener::bind(&socket).unwrap(), 2);
    let url = format!("unix://{}", socket.display());

    // The bridge's own kernel is not what this test is about, so the spec
    // names the unrestricted profile -- by name, the only way to get it.
    let spec = spec_doc("permissive");
    let (lines, status, stderr) = run_bridge(
        &[
            ("NUCLEUS_TOOL_PROXY_URL", &url),
            ("NUCLEUS_MCP_SPEC_YAML", &spec),
        ],
        &[
            rpc(1, "initialize", json!({ "protocolVersion": "2025-11-25" })),
            rpc(2, "tools/list", json!({})),
            rpc(
                3,
                "tools/call",
                json!({ "name": "read", "arguments": { "path": "hello.txt" } }),
            ),
            rpc(
                4,
                "tools/call",
                json!({ "name": "read", "arguments": { "path": "../etc/shadow" } }),
            ),
        ],
    );
    assert!(status.success(), "bridge failed: {status}\n{stderr}");

    let tools: Vec<&str> = reply(&lines, 2)["result"]["tools"]
        .as_array()
        .expect("a tool list")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(tools.contains(&"read"), "{tools:?}");

    let ok = &reply(&lines, 3)["result"];
    assert_eq!(ok["isError"], false, "{ok}");
    assert_eq!(ok["content"][0]["text"], "hello from the door", "{ok}");

    // The refusal surfaces with the proxy's kind and sentence, not a bare 403.
    let refused = &reply(&lines, 4)["result"];
    assert_eq!(refused["isError"], true, "{refused}");
    let text = refused["content"][0]["text"].as_str().unwrap_or_default();
    assert!(text.contains("sandbox_escape"), "{text}");
    assert!(text.contains("path escapes the sandbox root"), "{text}");

    for _ in 0..2 {
        let seen = door.recv().expect("the door saw both reads");
        let head = seen.head.to_ascii_lowercase();
        assert!(
            seen.request_line.starts_with("POST /v1/read "),
            "{}",
            seen.head
        );
        assert!(!head.contains("x-nucleus-signature"), "{}", seen.head);
    }
}

/// TCP still requires its auth: a bridge pointed at a TCP proxy with neither a
/// secret nor a declared signing upstream refuses to start, rather than send
/// unsigned requests.
#[test]
fn a_tcp_proxy_without_auth_is_refused_at_startup() {
    let spec = spec_doc("permissive");
    let (lines, status, stderr) = run_bridge(
        &[
            ("NUCLEUS_MCP_PROXY_URL", "http://127.0.0.1:9"),
            ("NUCLEUS_MCP_SPEC_YAML", &spec),
        ],
        &[rpc(1, "tools/list", json!({}))],
    );
    assert!(!status.success(), "started unauthenticated: {lines:?}");
    assert!(stderr.contains("--auth-secret"), "{stderr}");
}

/// #2446 step 3c: `NUCLEUS_MCP_SANDBOX_TOKEN` is set by nothing since the
/// tier-3 token stopped being minted, and the bridge never read it. A caller
/// still setting it is refused at startup by name, not ignored, even with an
/// otherwise good door configuration. Red before: the bridge started and
/// answered.
#[test]
fn a_retired_sandbox_token_variable_is_refused_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("workload.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    let url = format!("unix://{}", socket.display());

    for value in ["test-token-123", ""] {
        let (lines, status, stderr) = run_bridge(
            &[
                ("NUCLEUS_TOOL_PROXY_URL", &url),
                ("NUCLEUS_MCP_SANDBOX_TOKEN", value),
            ],
            &[rpc(1, "tools/list", json!({}))],
        );
        assert!(!status.success(), "started with it set: {lines:?}");
        assert!(lines.is_empty(), "answered with it set: {lines:?}");
        assert!(stderr.contains("NUCLEUS_MCP_SANDBOX_TOKEN"), "{stderr}");
    }
}

/// The flag itself is refused by clap, by name. Red before: it parsed.
#[test]
fn a_retired_sandbox_token_flag_is_refused_at_startup() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("workload.sock");
    let _listener = UnixListener::bind(&socket).unwrap();
    let url = format!("unix://{}", socket.display());

    let (lines, status, stderr) = run_bridge_with_args(
        &["--sandbox-token", "test-token-123"],
        &[("NUCLEUS_TOOL_PROXY_URL", &url)],
        &[rpc(1, "tools/list", json!({}))],
    );
    assert!(!status.success(), "started with the flag: {lines:?}");
    assert!(stderr.contains("--sandbox-token"), "{stderr}");
}
