//! Program C, C2, experiment 1, through the ACTUAL spawn: a disposable canary
//! protected exactly like the node's CA key (a 0600 file in a 0700 directory
//! under a 0700 state directory, all owned by this process's uid, which plays
//! the node), and a pod workload that tries to read it through
//! [`spawn_admitted`], the one spawn the tool-proxy has.
//!
//! * The shared-uid bare tier (`--unsandboxed`, what main runs) reads it: the
//!   control, and the defect.
//! * The separated bare tier (`--unsandboxed --subordinate-ids`) does not, and
//!   the child reports the subordinate uid as its own.
//!
//! A host whose realization contract is unmet (no `uidmap`, no delegation,
//! user namespaces restricted) cannot run the second half; the test then says
//! so and stops, unless `NUCLEUS_REQUIRE_SUBORDINATE_IDS` is set, which turns
//! "could not look" into a failure (ADR 0007 A-1). The builders that prove C2
//! set it.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use nucleus_spec::WorkloadSpec;

use super::{WorkloadLaunch, nix_getuid, spawn_admitted};

const SECRET: &str = "c2-canary-7f3a";

fn required() -> bool {
    std::env::var_os("NUCLEUS_REQUIRE_SUBORDINATE_IDS").is_some()
}

/// `<state>/ca/ca-key.pem`, laid out and protected like the node's.
fn canary_like_the_ca_key(state: &Path) -> PathBuf {
    let private =
        |p: &Path, mode| std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode));
    private(state, 0o700).expect("state 0700");
    let ca = state.join("ca");
    std::fs::create_dir(&ca).expect("ca dir");
    private(&ca, 0o700).expect("ca 0700");
    let key = ca.join("ca-key.pem");
    std::fs::write(&key, SECRET).expect("canary");
    private(&key, 0o600).expect("canary 0600");
    key
}

fn reads(canary: &Path) -> WorkloadSpec {
    WorkloadSpec {
        command: "/bin/sh".into(),
        args: vec![
            "-c".into(),
            "id -u; cat \"$0\"".into(),
            canary.display().to_string(),
        ],
        env: BTreeMap::new(),
        artifacts: BTreeMap::new(),
        uid: None,
        companion: None,
    }
}

async fn run(
    spec: &WorkloadSpec,
    work: &Path,
    opt_in: nucleus::UnsandboxedOptIn,
) -> std::process::Output {
    let plan = WorkloadLaunch::build(spec, "unix:///nonexistent/door.sock", work, &[])
        .admit(
            nucleus::ContainmentMode::Unsandboxed,
            opt_in,
            nucleus::LandlockWaiver::Absent,
        )
        .expect("admitted");
    let (child, _receipt) = spawn_admitted(
        plan,
        nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
        portcullis::SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        ),
        &nucleus::WorkspaceWrites::Writable,
    )
    .expect("spawned");
    child.wait_with_output().await.expect("waited")
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_canary_protected_like_the_ca_key_is_unreadable_through_spawn_admitted() {
    if nix_getuid() == 0 {
        // A root runtime drops every child to `nobody` already; the bare
        // tier this experiment is about is the non-root one.
        return;
    }
    let state = tempfile::tempdir().expect("state");
    let canary = canary_like_the_ca_key(state.path());
    let work = tempfile::tempdir().expect("work");
    let spec = reads(&canary);

    // The control, and the defect: at the node's uid the workload reads it.
    let shared = run(&spec, work.path(), nucleus::UnsandboxedOptIn::Explicit).await;
    assert!(
        String::from_utf8_lossy(&shared.stdout).contains(SECRET),
        "control: the shared-uid bare tier should read the canary: {shared:?}"
    );

    #[expect(
        clippy::disallowed_methods,
        reason = "a test: the realization probe's /bin/sh, handed to the contract check"
    )]
    let sh = std::process::Command::new("/bin/sh");
    let range = match nucleus::LocalRealization::check(state.path(), sh) {
        nucleus::LocalRealization::Separated(range) => range,
        nucleus::LocalRealization::SharedUid(why) => {
            assert!(
                !required(),
                "NUCLEUS_REQUIRE_SUBORDINATE_IDS is set and the contract is unmet: {why}"
            );
            eprintln!("not run: this host cannot separate the bare tier ({why})");
            return;
        }
    };
    let ids = range
        .ids(nucleus::FIRST_POD_OFFSET + 11)
        .expect("a pod's ids");
    let out = run(
        &spec,
        work.path(),
        nucleus::UnsandboxedOptIn::Subordinate(ids),
    )
    .await;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        stdout.lines().next(),
        Some(ids.uid().to_string().as_str()),
        "the child runs at its subordinate uid: {out:?}"
    );
    assert!(
        !stdout.contains(SECRET),
        "a separated child read the node's canary: {out:?}"
    );
    assert!(!out.status.success(), "{out:?}");
    assert!(stderr.contains("Permission denied"), "{stderr}");
    assert_ne!(ids.uid(), nix_getuid());
}
