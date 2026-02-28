//! Integration test: verify nucleus-tool-proxy exits with code 78 (EX_CONFIG)
//! when launched outside a managed sandbox (no SPIFFE socket, no sandbox token,
//! no identity cert).

use std::process::Command;

#[test]
fn exits_78_without_sandbox_proof() {
    let bin = env!("CARGO_BIN_EXE_nucleus-tool-proxy");

    let output = Command::new(bin)
        .arg("--auth-secret")
        .arg("test-secret")
        .arg("--approval-secret")
        .arg("test-approval-secret")
        .arg("--spec")
        .arg("/dev/null")
        // Ensure no sandbox-related env vars leak from the test environment
        .env_remove("NUCLEUS_SANDBOX_TOKEN")
        .env_remove("SPIFFE_ENDPOINT_SOCKET")
        .env_remove("NUCLEUS_IDENTITY_CERT")
        .output()
        .expect("failed to execute nucleus-tool-proxy binary");

    assert_eq!(
        output.status.code(),
        Some(78),
        "expected exit code 78 (EX_CONFIG), got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
}
