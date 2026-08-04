//! Drop-in stdio MCP proxy (observe-only).
//!
//! Spawns the real MCP server as a child and relays newline-delimited JSON-RPC in
//! both directions **byte-verbatim** — so it is transparent to both the agent and
//! the server (zero agent changes). It intercepts `tools/call` requests (egress
//! checks) and their responses (taint) to drive a [`SessionMonitor`]. The free
//! tier only *observes*; the enforcement tier (paid) would block on a denied
//! verdict here instead of forwarding.

use crate::report::SessionReport;
use crate::session::SessionMonitor;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

/// Run the proxy: wrap `cmd args` (the real MCP server), relay JSON-RPC, and feed
/// the shared monitor. Returns the session report when the streams close.
pub async fn run_stdio_proxy(
    monitor: Arc<Mutex<SessionMonitor>>,
    cmd: &str,
    args: &[String],
) -> Result<SessionReport> {
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .with_context(|| format!("failed to spawn MCP server: {cmd}"))?;

    let mut child_stdin = child.stdin.take().context("child has no stdin")?;
    let child_stdout = child.stdout.take().context("child has no stdout")?;

    // Maps a JSON-RPC request id -> the tool name, so a response can be attributed.
    let pending: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));

    // Agent -> server: intercept `tools/call` requests (the egress points).
    let mon_a = monitor.clone();
    let pend_a = pending.clone();
    let up = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                if v.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
                    if let Some(name) = v.pointer("/params/name").and_then(|n| n.as_str()) {
                        if let Some(id) = v.get("id") {
                            pend_a
                                .lock()
                                .unwrap()
                                .insert(id.to_string(), name.to_string());
                        }
                        let finding = mon_a.lock().unwrap().observe_call(name);
                        if let Some(f) = finding {
                            eprintln!(
                                "[trifecta-gate] /!\\ egress flagged: `{}` while holding [{}] — {}",
                                f.sink_tool,
                                f.verdict.declared_inputs.join(" + "),
                                f.verdict.reason
                            );
                        }
                    }
                }
            }
            if child_stdin.write_all(line.as_bytes()).await.is_err()
                || child_stdin.write_all(b"\n").await.is_err()
            {
                break;
            }
            let _ = child_stdin.flush().await;
        }
        drop(child_stdin); // EOF to the server
    });

    // Server -> agent: attribute `tools/call` responses (the taint).
    let mon_b = monitor.clone();
    let pend_b = pending.clone();
    let down = tokio::spawn(async move {
        let mut lines = BufReader::new(child_stdout).lines();
        let mut out = tokio::io::stdout();
        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                if let Some(id) = v.get("id") {
                    let name = pend_b.lock().unwrap().remove(&id.to_string());
                    if let Some(name) = name {
                        mon_b.lock().unwrap().observe_result(&name);
                    }
                }
            }
            if out.write_all(line.as_bytes()).await.is_err() || out.write_all(b"\n").await.is_err()
            {
                break;
            }
            let _ = out.flush().await;
        }
    });

    let _ = up.await;
    let _ = down.await;
    let _ = child.wait().await;

    let report = SessionReport::from_monitor(&monitor.lock().unwrap());
    Ok(report)
}
