//! The separated bare tier, live (Program C, C2): a child confined with
//! subordinate host ids, spawned through `ChildConfinement::apply`.
//!
//! Each test asks the realization contract first. On a host where it is unmet
//! (no `uidmap`, no delegation, user namespaces restricted) the test says why
//! and stops, unless `NUCLEUS_REQUIRE_SUBORDINATE_IDS` is set: then "could not
//! look" is a failure (ADR 0007 A-1). The builders that prove C2 set it.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use nucleus::portcullis::{NetworkEgress, PermissionLattice, SeccompPolicy};
use nucleus::{
    ChildConfinement, ChildUid, ContainmentMode, LandlockWaiver, LocalRealization, RlimitPolicy,
    SeparationUnmet, SubordinateIds, UnsandboxedOptIn, WorkspaceWrites,
};

fn required() -> bool {
    std::env::var_os("NUCLEUS_REQUIRE_SUBORDINATE_IDS").is_some()
}

fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).expect("0700");
    dir
}

/// Ids for a test child, or `None` (with the reason printed) where the
/// contract is unmet and not required.
fn ids(state: &Path, offset: u32) -> Option<SubordinateIds> {
    match LocalRealization::check(state, std::process::Command::new("/bin/sh")) {
        LocalRealization::Separated(range) => Some(range.ids(offset).expect("ids")),
        LocalRealization::SharedUid(why) => {
            assert!(
                !required(),
                "NUCLEUS_REQUIRE_SUBORDINATE_IDS is set and the contract is unmet: {why}"
            );
            eprintln!("not run: this host cannot separate the bare tier ({why})");
            None
        }
    }
}

/// `sh -c script args…` confined with `ids`, its output.
fn run_as(ids: SubordinateIds, script: &str, args: &[&str]) -> std::process::Output {
    let confinement = ChildConfinement::for_containment(
        ContainmentMode::Unsandboxed,
        UnsandboxedOptIn::Subordinate(ids),
        LandlockWaiver::Absent,
    )
    .expect("confinement");
    assert_eq!(confinement.child_uid(), ChildUid::Distinct(ids.uid()));
    let mut cmd = std::process::Command::new("/bin/sh");
    cmd.arg("-c")
        .arg(script)
        .arg("sh")
        .args(args)
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    let hardening = confinement.apply(
        &mut cmd,
        RlimitPolicy::node_ceiling().at_ceiling(),
        SeccompPolicy::derive(&PermissionLattice::permissive(), NetworkEgress::Declared),
        &WorkspaceWrites::Writable,
    );
    assert!(hardening.is_hardened(), "{hardening:?}");
    cmd.output().expect("spawn")
}

/// The child's host ids are the subordinate ones, from the host's own view
/// (`/proc/<pid>/status` names host ids) and its own, with no supplementary
/// group left over from the node.
#[test]
fn the_child_runs_at_its_subordinate_ids_with_no_groups() {
    let state = private_dir();
    let Some(ids) = ids(state.path(), nucleus::FIRST_POD_OFFSET + 21) else {
        return;
    };
    let out = run_as(
        ids,
        "id -u; id -g; grep -E '^(Uid|Gid|Groups):' /proc/self/status; cat /proc/self/uid_map",
        &[],
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{out:?}");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], ids.uid().to_string(), "{text}");
    assert_eq!(lines[1], ids.gid().to_string(), "{text}");
    let field = |name: &str| {
        lines
            .iter()
            .find(|l| l.starts_with(name))
            .map(|l| l.split_whitespace().skip(1).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let uid = ids.uid().to_string();
    assert_eq!(field("Uid:"), vec![uid.as_str(); 4], "{text}");
    assert!(
        field("Groups:").is_empty(),
        "supplementary groups survived: {text}"
    );
    assert!(nucleus::map_is_exactly(
        lines.last().expect("uid_map").as_bytes(),
        ids.uid()
    ));
}

/// Clause 1, measured: a canary laid out like the CA key (0600 in a 0700
/// directory owned by the node) is unreadable, while the same read at the
/// node's uid succeeds (the control: the shared-uid tier main runs).
#[test]
fn a_canary_like_the_ca_key_is_unreadable_and_readable_at_the_node_uid() {
    let state = private_dir();
    let ca = state.path().join("ca");
    std::fs::create_dir(&ca).expect("ca");
    std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o700)).expect("0700");
    let key = ca.join("ca-key.pem");
    std::fs::write(&key, "c2-canary").expect("canary");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).expect("0600");
    assert_eq!(std::fs::read_to_string(&key).expect("control"), "c2-canary");
    let Some(ids) = ids(state.path(), nucleus::FIRST_POD_OFFSET + 22) else {
        return;
    };
    let out = run_as(ids, "cat \"$1\"", &[key.to_str().expect("utf-8")]);
    assert!(!out.status.success(), "{out:?}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("c2-canary"));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("Permission denied"),
        "{out:?}"
    );
}

/// Clause 2, measured: the child cannot signal this process (the node), and
/// clause 4: it cannot make a user namespace of its own to remap itself.
#[test]
fn the_child_cannot_signal_the_node_or_make_a_namespace() {
    let state = private_dir();
    let Some(ids) = ids(state.path(), nucleus::FIRST_POD_OFFSET + 23) else {
        return;
    };
    let me = std::process::id().to_string();
    let out = run_as(ids, "kill -0 \"$1\"", &[&me]);
    assert!(
        !out.status.success(),
        "the child signalled the node: {out:?}"
    );
    let out = run_as(
        ids,
        "command -v unshare >/dev/null || exit 77; unshare -U true",
        &[],
    );
    match out.status.code() {
        Some(77) => eprintln!("no unshare(1) here: the namespace half not run"),
        Some(0) => panic!("the child made a user namespace: {out:?}"),
        _ => {}
    }
}

/// The contract refuses a state directory another uid can reach, by name,
/// rather than reporting the tier separated.
#[test]
fn a_shared_state_directory_is_not_separated() {
    let state = private_dir();
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o755)).expect("0755");
    match LocalRealization::check(state.path(), std::process::Command::new("/bin/sh")) {
        LocalRealization::SharedUid(SeparationUnmet::StateDirShared { .. }) => {}
        LocalRealization::SharedUid(other) => {
            assert!(!required(), "unmet for another reason: {other}");
        }
        LocalRealization::Separated(_) => panic!("a 0755 state directory read as separated"),
    }
}
