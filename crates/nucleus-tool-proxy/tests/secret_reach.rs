//! #3461, driven through the real binary: no child of the tool-proxy reaches
//! a secret or authority file the proxy holds.
//!
//! Each test starts the proxy as a host-tier launcher does (the run's minted
//! identity as sandbox proof, a public approval key, the peer-verified
//! socket). It then gives the proxy one thing a child must not reach. The
//! proxy either refuses to start and names the thing, or it starts and a real
//! workload child, at the uid the spawn deciders give it, cannot reach it.
//!
//! Red on main (run with `NUCLEUS_TEST_PROXY_BIN` set to a binary built from
//! main): the trust-roots and argv proxies start, and the bare-tier workload
//! reads the broker secret from `/proc/<proxy>/environ` and inherits the
//! launcher's descriptor.
#![expect(
    clippy::disallowed_methods,
    reason = "integration fixture owns temporary files, child processes, and loopback HTTP"
)]
#![expect(
    clippy::disallowed_types,
    reason = "integration fixture launches the proxy binary itself"
)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde_json::json;

const SECRET: &str = "broker-secret-3461-do-not-leak";

struct Proxy(Child);

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Whether this harness runs as root, so the proxy drops its children.
fn root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// The proxy, as a host-tier launcher starts it, plus `extra` arguments and
/// environment. Not yet spawned.
fn command(root: &Path, spec: &serde_json::Value, extra: &[&str]) -> (Command, PathBuf, PathBuf) {
    let ws = root.join("workspace");
    std::fs::create_dir_all(&ws).unwrap();
    let spec_path = root.join("pod.json");
    let mut spec = spec.clone();
    spec["spec"]["work_dir"] = json!(ws);
    std::fs::write(&spec_path, serde_json::to_vec(&spec).unwrap()).unwrap();
    let identity = nucleus_identity::pod_files::issue_ephemeral(
        &root.join("identity"),
        "secret-reach",
        Duration::from_secs(600),
    )
    .unwrap();
    let approver = SigningKey::from_bytes(&[9; 32]);
    let announce = root.join("announce");
    let log_path = root.join("proxy.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let binary = std::env::var_os("NUCLEUS_TEST_PROXY_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_nucleus-tool-proxy").into());
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", root)
        .envs(identity.env())
        .env("NUCLEUS_TOOL_PROXY_DRAND_ENABLED", "false")
        .arg("--unsandboxed")
        .arg("--spec")
        .arg(&spec_path)
        .arg("--listen-unix")
        .arg(root.join("p.sock"))
        .arg("--workload-door")
        .arg(root.join("workload.sock"))
        .arg("--approval-pubkeys")
        .arg(hex::encode(approver.verifying_key().to_bytes()))
        .arg("--audit-log")
        .arg(root.join("audit.jsonl"))
        .arg("--announce-path")
        .arg(&announce)
        .args(extra)
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    (command, announce, log_path)
}

/// Wait for the proxy to announce (`Ok`) or exit (`Err` with its log).
async fn started(mut proxy: Proxy, announce: &Path, log: &Path) -> Result<Proxy, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if std::fs::read_to_string(announce).is_ok_and(|a| !a.trim().is_empty()) {
            return Ok(proxy);
        }
        if proxy.0.try_wait().unwrap().is_some() {
            return Err(std::fs::read_to_string(log).unwrap());
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "startup timed out: {}",
            std::fs::read_to_string(log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn spec() -> serde_json::Value {
    json!({
        "apiVersion": "nucleus/v1", "kind": "Pod", "metadata": {"name": "secret-reach"},
        "spec": {"policy": {"type": "profile", "name": "permissive"}}
    })
}

/// Durable authority on the bare host tier: the owner-decision trust roots
/// (#3453). A child at the proxy's uid could rewrite them, and the next start
/// would trust what it wrote. On a non-root harness the proxy refuses by
/// name. A root harness drops its children, the roots are root's, and it
/// starts.
#[tokio::test]
async fn bare_tier_decision_trust_roots_are_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    // Valid roots, so a proxy that does not check reach starts (main did).
    let roots = dir.path().join("roots.json");
    let owner = SigningKey::from_bytes(&[5; 32]);
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(owner.verifying_key().as_bytes());
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, der)
    );
    let file = json!([{
        "kid": nucleus_signed_decision::kid_for(&pem), "public_key": pem, "who": "owner"
    }]);
    std::fs::write(&roots, file.to_string()).unwrap();
    std::fs::create_dir(dir.path().join("bundles")).unwrap();
    let (mut command, announce, log) = command(
        dir.path(),
        &spec(),
        &[
            "--decision-trust-roots",
            roots.to_str().unwrap(),
            "--decision-bundles",
            dir.path().join("bundles").to_str().unwrap(),
            "--decision-tenant",
            "github~owner~name",
        ],
    );
    let proxy = Proxy(command.spawn().unwrap());
    match (started(proxy, &announce, &log).await, root()) {
        (Err(log), false) => assert!(
            log.contains("--decision-trust-roots (durable authority)")
                && log.contains("bare host tier"),
            "refused, but not by name: {log}"
        ),
        (Ok(_), false) => {
            panic!("a bare-tier proxy started holding trust roots its child can rewrite")
        }
        // Root: the trust roots are refused for another reason or none; what
        // matters is that a refusal, if any, is not about reach.
        (Err(log), true) => assert!(!log.contains("durable authority"), "{log}"),
        (Ok(_), true) => {}
    }
}

/// A secret on the command line is in `/proc/<pid>/cmdline`, which every
/// process on the host reads, whatever its uid. Refused by name, on every
/// tier.
#[tokio::test]
async fn a_secret_flag_is_refused_on_every_tier() {
    let dir = tempfile::tempdir().unwrap();
    let (mut command, announce, log) = command(
        dir.path(),
        &spec(),
        &["--approval-secret", "shared-secret-on-argv"],
    );
    let proxy = Proxy(command.spawn().unwrap());
    let log = match started(proxy, &announce, &log).await {
        Err(log) => log,
        Ok(_) => panic!("a proxy started with a secret on its command line"),
    };
    assert!(
        log.contains(
            "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET (a secret) is on this process's command line"
        ),
        "{log}"
    );
}

/// **A real workload child, at its decided uid, gets none of the proxy's
/// environment secret, none of the launcher's descriptors, and no secret in
/// its own environment.** The launcher gives the proxy a secret in its
/// environment and a descriptor without close-on-exec, as a careless
/// launcher would. The workload prints what `/proc/<proxy>/environ`, its own
/// environment and its descriptors show.
///
/// Red on main, on a non-root harness: the bare tier's child read
/// `/proc/$PPID/environ` (the secret was in it) and held the launcher's
/// descriptor. The environment scrub held already (`env_clear`); this pins it.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_workload_child_reaches_no_environment_secret_or_inherited_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    // The workload must be able to write its report and, when dropped, to
    // reach the workspace through the temp directory.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let leaked = dir.path().join("launcher-descriptor");
    std::fs::write(&leaked, b"held open by the launcher").unwrap();
    let held = std::fs::File::open(&leaked).unwrap();
    // A careless launcher: the descriptor survives exec into the proxy.
    nix::fcntl::fcntl(
        &held,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();
    let report = "probe.out";
    let script = format!(
        "{{ echo PARENT; tr '\\0' '\\n' < /proc/$PPID/environ; echo OWN; env; echo FDS; \
         for f in /proc/self/fd/*; do readlink \"$f\"; done; }} > probe.tmp 2>&1; \
         mv probe.tmp {report}"
    );
    let mut spec = spec();
    spec["spec"]["workload"] = json!({"command": "/bin/sh", "args": ["-c", script]});
    let (mut command, announce, log) = command(dir.path(), &spec, &[]);
    command.env("NUCLEUS_TOOL_PROXY_BROKER_SECRET", SECRET);
    let proxy = Proxy(command.spawn().unwrap());
    drop(held);
    let _proxy = started(proxy, &announce, &log)
        .await
        .unwrap_or_else(|log| panic!("proxy exited: {log}"));
    let out = dir.path().join("workspace").join(report);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while !out.exists() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the workload never reported: {}",
            std::fs::read_to_string(&log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let seen = std::fs::read_to_string(&out).unwrap();
    // Non-vacuity: the probe ran all three sections and listed its stdio.
    for section in ["PARENT", "OWN", "FDS", "PATH="] {
        assert!(
            seen.contains(section),
            "the probe did not run fully: {seen}"
        );
    }
    assert!(
        !seen.contains(SECRET),
        "the workload reached the proxy's environment secret:\n{seen}"
    );
    assert!(
        !seen.contains(leaked.to_str().unwrap()),
        "the workload inherited the launcher's descriptor:\n{seen}"
    );
}
