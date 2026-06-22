//! Regression-locks the `cargo xtask policy-gate` exit codes (most-paranoid #5).
//!
//! This is the constitutional gate the in-repo CI workflow runs: a non-monotone
//! PolicyManifest amendment must fail the build (exit 1), an identity/monotone
//! amendment must pass (exit 0). Exercises the real ck-kernel admission path via
//! the built binary.

use std::process::Command;

fn xtask() -> Command {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
}

fn root_manifest() -> String {
    format!("{}/../../PolicyManifest.toml", env!("CARGO_MANIFEST_DIR"))
}

fn fixture(name: &str) -> String {
    format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn identity_amendment_accepted_exit_0() {
    let base = root_manifest();
    let status = xtask()
        .args(["policy-gate", "--base", &base, "--candidate", &base])
        .status()
        .expect("run xtask policy-gate");
    assert!(
        status.success(),
        "identity amendment must be accepted (exit 0), got {status:?}"
    );
}

#[test]
fn capability_escalation_rejected_exit_1() {
    let base = root_manifest();
    let candidate = fixture("escalated_after.toml");
    let status = xtask()
        .args(["policy-gate", "--base", &base, "--candidate", &candidate])
        .status()
        .expect("run xtask policy-gate");
    assert_eq!(
        status.code(),
        Some(1),
        "capability escalation must be rejected with exit 1, got {status:?}"
    );
}
