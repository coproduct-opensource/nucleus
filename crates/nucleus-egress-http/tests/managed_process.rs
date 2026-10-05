//! Exercise the shipped process boundary without sharing a listener with other
//! unit tests' concurrent fork/exec operations.
//!
//! Linux only: the adapter identifies loopback peers through `/proc/net/tcp`
//! and refuses to bind where there is none (`src/peer.rs`).
#![cfg(target_os = "linux")]
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

#[tokio::test]
#[expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "integration fixture executes the built adapter to verify its process lifetime"
)]
async fn adapter_preserves_workload_exit_and_releases_its_listener() {
    let directory = tempfile::tempdir().unwrap();
    let door = format!("unix://{}", directory.path().join("door.sock").display());
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_nucleus-egress-http"));
    command
        .env_clear()
        // What the runtime gives a pod that declared `model`.
        .env(
            nucleus_spec::workload_egress::url_env("model"),
            nucleus_spec::workload_egress::upstream_url(&door, "model"),
        )
        .arg("--door")
        .arg(&door)
        .args([
            "--upstream",
            "model",
            "--listen",
            "127.0.0.1:0",
            "--",
            "/bin/sh",
            "-c",
            "printf '%s\\n' \"$NUCLEUS_EGRESS_HTTP_URL\"; exit 7",
        ])
        .kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(10), command.output())
        .await
        .expect("adapter did not exit with its workload")
        .unwrap();
    assert_eq!(output.status.code(), Some(7), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let mut lines = stdout.lines();
    let ready = lines
        .next()
        .unwrap()
        .strip_prefix("NUCLEUS_EGRESS_HTTP_READY model ")
        .unwrap();
    let workload_url = lines.next().unwrap();
    assert_eq!(workload_url, ready);
    assert!(lines.next().is_none());
    let address: SocketAddr = workload_url
        .strip_prefix("http://")
        .unwrap()
        .parse()
        .unwrap();
    assert!(address.ip().is_loopback());
    assert_ne!(address.port(), 0);
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_secs(1)).is_err(),
        "adapter listener remained reachable after process exit: {address}"
    );
}
