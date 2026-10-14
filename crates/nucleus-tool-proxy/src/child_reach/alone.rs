//! Test-only: run one test alone, in its own process (#3461).

/// Run the calling test alone, in a fresh copy of this test binary: it seals
/// the process (`nucleus::seal_runtime`), and the seal is process-wide. In a
/// harness that runs every test in one process (`cargo test`, coverage), a
/// test beside it would lose `/proc/<pid>/environ` too. `true` in the copy,
/// where the body runs; `false` in the caller once the copy passed.
#[expect(
    clippy::disallowed_methods,
    reason = "test-only self-execution isolates the process-wide seal from other tests"
)]
pub(super) fn alone(test: &str) -> bool {
    const CHILD: &str = "NUCLEUS_TEST_SEAL_CHILD";
    if std::env::var_os(CHILD).is_some() {
        return true;
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success(), "{test} failed in its own process");
    false
}
