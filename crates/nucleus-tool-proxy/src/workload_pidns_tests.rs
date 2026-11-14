//! #3344: a guest workload runs in its own PID namespace, on a real spawn.
//!
//! Each test admits a workload under `MicroVM`, as the guest does, and spawns
//! it through `spawn_admitted`. A root runtime (the guest's, or `sudo` on a
//! builder) makes the namespace, and the assertions are about what the
//! workload can see and reach from inside it. A non-root runtime cannot drop,
//! so `MicroVM` refuses it by name and each test asserts that refusal instead.

use super::*;

const NO_WAIVER: nucleus::LandlockWaiver = nucleus::LandlockWaiver::Absent;
const OPTED_IN: nucleus::UnsandboxedOptIn = nucleus::UnsandboxedOptIn::Explicit;

/// Admit `script` as a guest workload (`/bin/sh -c`), or `None` after
/// asserting the non-root refusal.
fn admitted(script: &str, dir: &std::path::Path) -> Option<AdmittedWorkloadPlan> {
    admitted_with(script, dir, &[])
}

fn admitted_with(
    script: &str,
    dir: &std::path::Path,
    env: &[(&str, &str)],
) -> Option<AdmittedWorkloadPlan> {
    let spec = WorkloadSpec {
        command: "/bin/sh".into(),
        artifacts: Default::default(),
        args: vec!["-c".into(), script.into()],
        namespace: nucleus_spec::WorkloadNamespace::Runtime {},
        uid: None,
        companion: None,
        // The shell's own error text is matched below.
        env: env
            .iter()
            .chain(&[("LC_ALL", "C")])
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    };
    let admission = WorkloadLaunch::build(&spec, "http://127.0.0.1:8080", dir, &[]).admit(
        nucleus::ContainmentMode::MicroVM,
        OPTED_IN,
        NO_WAIVER,
    );
    match (nix_getuid(), admission) {
        (0, Ok(plan)) => Some(plan),
        (0, Err(refused)) => panic!("a root runtime must drop, not refuse: {refused}"),
        (_, Ok(_)) => panic!("a non-root runtime admitted a guest workload"),
        (_, Err(refused)) => {
            assert!(
                refused.0.contains("child separation unavailable"),
                "refused by name: {refused}"
            );
            None
        }
    }
}

fn spawn(plan: AdmittedWorkloadPlan) -> std::io::Result<(tokio::process::Child, LaunchReceipt)> {
    spawn_admitted(
        plan,
        nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
        portcullis::SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        ),
        &nucleus::WorkspaceWrites::Writable,
    )
}

/// Run `script` to completion: its stdout and exit code, and the receipt.
async fn run(script: &str) -> Option<(String, Option<i32>, LaunchReceipt)> {
    let dir = tempfile::tempdir().unwrap();
    let plan = admitted(script, dir.path())?;
    let (child, receipt) = spawn(plan).expect("the workload starts");
    let out = tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("the workload finishes")
        .unwrap();
    Some((
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.code(),
        receipt,
    ))
}

/// The numeric entries of a `/proc` listing.
fn pids(listing: &str) -> Vec<u32> {
    listing
        .split_whitespace()
        .filter_map(|w| w.parse().ok())
        .collect()
}

/// **The workload cannot see or signal the runtime.** Inside, `/proc` lists
/// only the namespace's processes of the workload's uid: the shell as pid 2
/// and its children (the root init, pid 1, is hidden as the guest's `/proc`
/// hides it). The runtime's pid is not among them, and `kill -0` on it is
/// `ESRCH`, not the `EPERM` a visible root process answers. The receipt says
/// `own`, read off what the hook installed.
#[tokio::test]
async fn the_guest_workload_cannot_see_or_signal_the_runtime() {
    let runtime = std::process::id();
    let script = format!(
        "echo self=$$; echo procs=$(ls /proc); \
         kill -0 {runtime} 2>&1; echo kill=$?"
    );
    let Some((out, code, receipt)) = run(&script).await else {
        return;
    };
    assert_eq!(code, Some(0), "{out}");
    assert!(
        out.contains("self=2\n"),
        "the shell is pid 2, the init's child: {out}"
    );
    let procs = out
        .lines()
        .find_map(|l| l.strip_prefix("procs="))
        .expect("the listing was printed");
    let seen = pids(procs);
    // `hidepid=invisible`, as the guest's: the root init is not listed either.
    assert!(seen.contains(&2) && !seen.contains(&1), "{procs}");
    assert!(
        !seen.contains(&runtime),
        "the runtime's pid {runtime} is visible: {procs}"
    );
    assert!(
        seen.iter().all(|&p| p <= 16),
        "only the namespace's handful of processes: {procs}"
    );
    assert!(out.contains("No such process"), "kill -0 is ESRCH: {out}");
    assert!(out.contains("kill=1\n"), "{out}");
    match receipt.hardening {
        nucleus::SpawnHardening::Hardened(h) => {
            assert_eq!(h.pid_namespace(), nucleus::PidNamespace::Own);
        }
        other => panic!("a guest workload is hardened: {other:?}"),
    }
}

/// **Orphans are reaped.** A grandchild whose parent exits is reparented to
/// the namespace's init, which must wait for it; nothing in the namespace is
/// left a zombie (state `Z` in `/proc/<pid>/stat`).
#[tokio::test]
async fn orphans_in_the_workload_namespace_are_reaped() {
    let script = "for i in 1 2 3 4 5; do sh -c 'sleep 0.1 & exit 0'; done; sleep 1; \
                  echo self=$$; for s in /proc/[0-9]*/stat; do cat $s; echo; done";
    let Some((out, code, _)) = run(script).await else {
        return;
    };
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("self=2\n"), "in its own namespace: {out}");
    // `pid (comm) state ...`: the state follows the last `)`.
    let zombies: Vec<&str> = out
        .lines()
        .filter(|l| {
            l.rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
        })
        .collect();
    assert!(zombies.is_empty(), "unreaped: {zombies:?}\n{out}");
}

/// **The runtime reads the workload's own exit status** through the waiter
/// and the init.
#[tokio::test]
async fn the_workload_exit_status_reaches_the_runtime() {
    let Some((_, code, _)) = run("exit 7").await else {
        return;
    };
    assert_eq!(code, Some(7));
    let Some((_, code, _)) = run("kill -TERM $$").await else {
        return;
    };
    assert_eq!(code, Some(128 + libc::SIGTERM), "a signal death as 128 + n");
}

/// **Killing the handle empties the namespace.** The runtime's `SIGKILL`
/// reaches the waiter, the waiter's death the init, and the init's death
/// every process in the namespace, the workload's background children
/// included.
#[tokio::test]
async fn killing_the_workload_handle_kills_its_whole_namespace() {
    // Every process in the namespace inherits this, so the runtime finds
    // them by it in its own `/proc`.
    let marker = format!("PIDNS_TEST_MARKER=handle-{}", std::process::id());
    let (key, value) = marker.split_once('=').unwrap();
    let dir = tempfile::tempdir().unwrap();
    let Some(plan) = admitted_with("sleep 300 & sleep 301; wait", dir.path(), &[(key, value)])
    else {
        return;
    };
    let alive = || {
        std::fs::read_dir("/proc")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| {
                std::fs::read(e.path().join("environ"))
                    .is_ok_and(|c| String::from_utf8_lossy(&c).contains(&marker))
            })
            .count()
    };
    let (mut child, _) = spawn(plan).expect("the workload starts");
    let mut seen = 0;
    for _ in 0..50 {
        seen = alive();
        if seen > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(seen > 0, "positive control: the workload's processes run");
    child.kill().await.unwrap();
    let mut left = seen;
    for _ in 0..50 {
        left = alive();
        if left == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(left, 0, "processes outlived the workload's handle");
}

/// **A workload that cannot exec fails its spawn**, and does not hang it:
/// the waiter and the init each close their copy of std's status pipe, so
/// the parent reads the workload's own exec error.
#[tokio::test]
async fn a_guest_workload_that_cannot_exec_fails_its_spawn() {
    let dir = tempfile::tempdir().unwrap();
    let Some(mut plan) = admitted("true", dir.path()) else {
        return;
    };
    plan.command = "/nonexistent/workload".into();
    let started = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || spawn(plan).map(drop)),
    )
    .await
    .expect("the spawn returns rather than hangs")
    .unwrap();
    let err = started.expect_err("no such program");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound, "{err}");
}

/// Admit `script` as a guest workload placed in `private_user_network`
/// (#3528), at the stated outer uid, or `None` after asserting the refusal:
/// a non-root runtime cannot drop, and a kernel without user namespaces is
/// refused by name at admission.
fn admitted_private(
    script: &str,
    dir: &std::path::Path,
    inner_uid: u32,
    loopback: bool,
) -> Option<AdmittedWorkloadPlan> {
    let spec = WorkloadSpec {
        command: "/bin/sh".into(),
        artifacts: Default::default(),
        args: vec!["-c".into(), script.into()],
        namespace: nucleus_spec::WorkloadNamespace::PrivateUserNetwork {
            inner_uid,
            loopback,
        },
        uid: Some(nucleus::DEFAULT_CHILD_UID),
        companion: None,
        env: [("LC_ALL".to_string(), "C".to_string())].into(),
    };
    let admission = WorkloadLaunch::build(&spec, "http://127.0.0.1:8080", dir, &[]).admit(
        nucleus::ContainmentMode::MicroVM,
        OPTED_IN,
        NO_WAIVER,
    );
    let userns = nucleus::UserNamespaces::probe();
    match (nix_getuid(), userns, admission) {
        (0, nucleus::UserNamespaces::Available, Ok(plan)) => Some(plan),
        (0, nucleus::UserNamespaces::Available, Err(refused)) => {
            panic!("a root guest runtime with user namespaces must place it: {refused}")
        }
        (0, nucleus::UserNamespaces::Unavailable { reason }, Err(refused)) => {
            assert!(
                refused.0.contains("workload namespace") && refused.0.contains("refused"),
                "refused by name ({reason}): {refused}"
            );
            None
        }
        (_, _, Ok(_)) => panic!("admitted a private namespace it cannot make"),
        (_, _, Err(refused)) => {
            assert!(
                refused.0.contains("child separation unavailable"),
                "refused by name: {refused}"
            );
            None
        }
    }
}

/// **A guest workload in a private user and network namespace (#3528), end
/// to end.** Admitted from its spec, spawned through `spawn_admitted`: it is
/// pid 2 of its own PID namespace, its id is the inner uid, its map is the
/// one line `inner 65534 1`, its `lo` has an address iff asked, and the
/// runtime is still invisible to it. The launch receipt (schema 6) records
/// `ns=private_user_network:...` beside `pids=own`, read off what the hook
/// installed, and that is in the hash: four placements, four hashes, none
/// equal to runtime placement's.
#[tokio::test]
async fn a_guest_workload_in_a_private_namespace_is_mapped_and_recorded() {
    let runtime = std::process::id();
    let script = format!(
        "echo self=$$; echo uid=$(id -u) gid=$(id -g); echo map=$(cat /proc/self/uid_map); \
         echo lo=$(grep -c 127.0.0.1 /proc/net/fib_trie); \
         kill -0 {runtime} 2>/dev/null; echo kill=$?"
    );
    let mut hashes = std::collections::BTreeSet::new();
    let Some((_, _, runtime_receipt)) = run(&script).await else {
        return;
    };
    assert_eq!(runtime_receipt.schema_version, 6);
    assert_eq!(
        runtime_receipt.namespace,
        nucleus_spec::NamespaceSetup::Runtime {}
    );
    hashes.insert(runtime_receipt.hash.clone());
    for (inner, loopback) in [(0, false), (0, true), (1001, false), (1001, true)] {
        let what = format!("inner {inner}, loopback {loopback}");
        let dir = tempfile::tempdir().unwrap();
        let Some(plan) = admitted_private(&script, dir.path(), inner, loopback) else {
            return;
        };
        let (child, receipt) = spawn(plan).unwrap_or_else(|e| panic!("{what}: spawn: {e}"));
        let out =
            tokio::time::timeout(std::time::Duration::from_secs(30), child.wait_with_output())
                .await
                .expect("the workload finishes")
                .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        eprintln!("{what}: {stdout:?}");
        assert_eq!(out.status.code(), Some(0), "{what}: {stdout}");
        assert!(stdout.contains("self=2\n"), "{what}: {stdout}");
        assert!(
            stdout.contains(&format!("uid={inner} gid={inner}\n")),
            "{what}: {stdout}"
        );
        let map: Vec<&str> = stdout
            .lines()
            .find_map(|l| l.strip_prefix("map="))
            .map(|m| m.split_whitespace().collect())
            .unwrap_or_default();
        let outer = nucleus::DEFAULT_CHILD_UID.to_string();
        assert_eq!(
            map,
            [inner.to_string().as_str(), outer.as_str(), "1"],
            "{what}: exactly one mapping: {stdout}"
        );
        let lo = stdout
            .lines()
            .find_map(|l| l.strip_prefix("lo="))
            .and_then(|n| n.trim().parse::<u32>().ok())
            .unwrap_or_else(|| panic!("{what}: {stdout}"));
        assert_eq!(
            lo > 0,
            loopback,
            "{what}: lo has 127.0.0.1 iff asked: {stdout}"
        );
        assert!(
            stdout.contains("kill=1\n"),
            "{what}: the runtime is not signalable: {stdout}"
        );
        let expected = nucleus_spec::NamespaceSetup::PrivateUserNetwork {
            outer_uid: nucleus::DEFAULT_CHILD_UID,
            inner_uid: inner,
            loopback,
        };
        assert_eq!(receipt.schema_version, 6, "{what}");
        assert_eq!(receipt.namespace, expected, "{what}");
        match receipt.hardening {
            nucleus::SpawnHardening::Hardened(h) => {
                assert_eq!(h.pid_namespace(), nucleus::PidNamespace::Own, "{what}");
                assert_eq!(h.namespace(), expected, "{what}");
            }
            other => panic!("{what}: a placed workload is hardened: {other:?}"),
        }
        assert!(
            hashes.insert(receipt.hash.clone()),
            "{what}: the placement is in the launch hash"
        );
    }
}
