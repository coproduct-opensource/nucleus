//! `nucleus run --dry-run` at the CLI boundary (#3267): a dry run launches
//! nothing, so it must not wait on stdin, read a node identity, or need a node
//! configured. On a machine with no node and stdin held open it returns at once.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Generous for a debug binary on a loaded runner; a hang is unbounded.
const DEADLINE: Duration = Duration::from_secs(30);

struct Fixture {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("upstreams.toml"), "").unwrap();
        Self { home, work }
    }

    /// `nucleus run --dry-run --egress …` with an empty `HOME` (no config, no
    /// provisioned identity), no node in the environment, and a stdin pipe the
    /// test holds open and never writes: a read of it blocks forever.
    fn spawn(&self, extra: &[&str]) -> Child {
        let home = self.home.path();
        Command::new(env!("CARGO_BIN_EXE_nucleus"))
            .env_clear()
            .env("HOME", home)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("NUCLEUS_CONFIG", home.join("absent-config.toml"))
            .args(["run", "--dry-run", "--egress", "model", "--upstreams"])
            .arg(home.join("upstreams.toml"))
            .arg("-d")
            .arg(self.work.path())
            .args(extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
}

/// Wait for `child` up to [`DEADLINE`]; a child still running then is killed
/// and reported as hung. Returns (success, stdout, stderr).
fn finish(mut child: Child) -> (bool, String, String) {
    // Hold stdin open (never written, never closed) until the child exits.
    let _stdin = child.stdin.take();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > DEADLINE {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("run --dry-run still running after {DEADLINE:?}: it blocked");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut out = String::new();
    let mut err = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    (status.success(), out, err)
}

/// Prompt `-` with stdin open: the dry run must not read it, and must not
/// refuse for want of a node URL or identity.
#[test]
fn dry_run_with_stdin_prompt_does_not_read_stdin() {
    let fixture = Fixture::new();
    let (ok, out, err) = finish(fixture.spawn(&["-"]));
    assert!(ok, "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("Dry run - would execute with:"), "{out}");
    assert!(
        out.contains("Prompt: from stdin (not read in a dry run)"),
        "{out}"
    );
    assert!(out.contains("Node: (not configured:"), "{out}");
}

/// A node URL but no provisioned identity: a dry run shows the node and does
/// not try to load (or refuse for want of) an identity.
#[test]
fn dry_run_with_node_url_needs_no_identity() {
    let fixture = Fixture::new();
    let (ok, out, err) = finish(fixture.spawn(&[
        "--node-url",
        "https://node.invalid:8443",
        "check the project",
    ]));
    assert!(ok, "stdout:\n{out}\nstderr:\n{err}");
    assert!(out.contains("Node URL: https://node.invalid:8443"), "{out}");
}
