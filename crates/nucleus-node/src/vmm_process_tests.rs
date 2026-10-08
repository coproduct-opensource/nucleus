//! The jail's pid file, and the process it names (#2571).
use super::*;

#[test]
fn the_pid_file_is_one_decimal_pid() {
    assert_eq!(parse_pid_file("4242").unwrap(), VmmPid(4242));
    assert_eq!(parse_pid_file("4242\n").unwrap(), VmmPid(4242));
    for bad in [
        "",
        "\n",
        "0",
        "-1",
        "+5",
        " 42",
        "42 ",
        "4 2",
        "42a",
        "0x2a",
        "4294967296",
        "42\n\n",
    ] {
        assert!(
            matches!(parse_pid_file(bad), Err(Handoff::PidFileMalformed(_))),
            "{bad:?} must be refused"
        );
    }
}

/// `--new-pid-ns` makes the VMM pid 1 of a namespace below the node's. Without the flag the
/// pid in the file is an ordinary process in the node's own namespace, and it is refused.
#[test]
fn only_the_init_of_a_child_pid_namespace_is_a_jailed_vmm() {
    let status = |nspid: &str| format!("Name:\tfirecracker\nPid:\t4242\n{nspid}\nSeccomp:\t2\n");
    let init = parse_nspid(&status("NSpid:\t4242\t1")).unwrap();
    assert_eq!(init, vec![4242, 1]);
    assert!(is_namespace_init(&init));
    // A node that itself runs in a container sees one more level.
    assert!(is_namespace_init(
        &parse_nspid(&status("NSpid:\t9\t4242\t1")).unwrap()
    ));
    // The jailer without `--new-pid-ns`: the VMM shares the node's namespace.
    assert!(!is_namespace_init(
        &parse_nspid(&status("NSpid:\t4242")).unwrap()
    ));
    // A deeper process that is not its namespace's init.
    assert!(!is_namespace_init(
        &parse_nspid(&status("NSpid:\t4242\t7")).unwrap()
    ));
    assert_eq!(parse_nspid("Name:\tx\nPid:\t1\n"), None);
    assert_eq!(parse_nspid("NSpid:\t\n"), None);
    assert_eq!(parse_nspid("NSpid:\t12\tx\n"), None);
}

#[test]
fn the_jail_id_must_be_an_adjacent_argument_pair() {
    let argv = |args: &[&str]| args.join("\0").into_bytes();
    let vmm = argv(&["/firecracker", "--id", "jail-1", "--start-time-us", "5"]);
    assert!(carries_jail_id(&vmm, "jail-1"));
    assert!(!carries_jail_id(&vmm, "jail-2"));
    assert!(!carries_jail_id(
        &argv(&["/firecracker", "--id=jail-1"]),
        "jail-1"
    ));
    assert!(!carries_jail_id(&argv(&["--id", "x", "jail-1"]), "jail-1"));
    assert!(!carries_jail_id(b"", "jail-1"));
}

#[test]
fn the_pid_file_is_where_the_jailer_writes_it() {
    let layout = JailLayout::new(
        Path::new("/srv/jailer"),
        Path::new("/usr/local/bin/firecracker"),
        "pod-1",
    );
    assert_eq!(
        layout.vmm_pid_file(Path::new("/usr/local/bin/firecracker")),
        Path::new("/srv/jailer/firecracker/pod-1/root/firecracker.pid")
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    /// A stand-in jailer: `sh -c <script> sh <pid file>`. No executable file is written, so the
    /// tests run where the temp dir is mounted noexec.
    fn jailer(script: &str, pid_file: &Path) -> Child {
        Command::new("/bin/sh")
            .args(["-c", script, "sh"])
            .arg(pid_file)
            .kill_on_drop(true)
            .spawn()
            .expect("sh spawns")
    }

    /// The jailer's hand-off without the namespace: a sleeper forked off, its pid recorded,
    /// and the parent gone. That is what the old argv produced.
    const FORK_AND_RECORD: &str = "sleep 30 >/dev/null 2>&1 & printf %s $! > \"$1\"";

    fn alive(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            // A zombie has exited; only its reaper's wait is outstanding.
            Ok(stat) => !stat
                .rsplit_once(')')
                .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z')),
            Err(_) => false,
        }
    }

    async fn gone_within(pid: u32, bound: Duration) -> bool {
        let deadline = std::time::Instant::now() + bound;
        while std::time::Instant::now() < deadline {
            if !alive(pid) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        !alive(pid)
    }

    #[tokio::test]
    async fn a_jailer_that_fails_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("firecracker.pid");
        let err = handoff(jailer("exit 3", &pid_file), &pid_file, "j", JAILER_HANDOFF)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Handoff::JailerFailed(s) if s.code() == Some(3)),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_jailer_that_never_hands_off_times_out_by_name_and_is_killed() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("firecracker.pid");
        let child = jailer("exec sleep 30", &pid_file);
        let pid = child.id().unwrap();
        let err = handoff(child, &pid_file, "j", Duration::from_millis(200))
            .await
            .unwrap_err();
        assert!(matches!(err, Handoff::Timeout(_)), "{err}");
        assert!(
            gone_within(pid, Duration::from_secs(5)).await,
            "the jailer was left running"
        );
    }

    #[tokio::test]
    async fn a_missing_or_malformed_pid_file_is_named() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("firecracker.pid");
        let err = handoff(jailer("exit 0", &pid_file), &pid_file, "j", JAILER_HANDOFF)
            .await
            .unwrap_err();
        assert!(matches!(err, Handoff::PidFileUnreadable { .. }), "{err}");
        let err = handoff(
            jailer("printf 'not-a-pid' > \"$1\"", &pid_file),
            &pid_file,
            "j",
            JAILER_HANDOFF,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Handoff::PidFileMalformed(_)), "{err}");
    }

    /// The jailer's behaviour without `--new-pid-ns`, end to end: the pid file names a live
    /// process in the node's own namespace, and the handoff refuses it rather than supervising
    /// a VMM that shares the host's pid namespace.
    #[tokio::test]
    async fn a_vmm_outside_its_own_pid_namespace_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("firecracker.pid");
        let err = handoff(
            jailer(FORK_AND_RECORD, &pid_file),
            &pid_file,
            "j",
            JAILER_HANDOFF,
        )
        .await
        .unwrap_err();
        let pid: u32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        VmmProcess::adopt_for_test(pid).kill().await.unwrap();
        assert!(
            matches!(&err, Handoff::NotNamespaceInit { nspid: Some(n), .. } if n.len() == 1),
            "{err}"
        );
    }

    /// The defect #2571 names: the spawned process exits as soon as the VMM exists, so
    /// supervising it supervises nothing. A process the node did not spawn is observed, killed
    /// and waited for through its pidfd.
    #[tokio::test]
    async fn the_recorded_process_is_supervised_after_its_spawner_exits() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("firecracker.pid");
        let mut spawner = jailer(FORK_AND_RECORD, &pid_file);
        assert!(spawner.wait().await.unwrap().success());
        let pid: u32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();

        let mut vmm = VmmProcess::adopt_for_test(pid);
        assert_eq!(vmm.pid().get(), pid);
        assert!(vmm.try_wait().unwrap().is_none(), "the VMM is running");
        // A wait that is cancelled leaves the process as it was.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), vmm.wait())
                .await
                .is_err()
        );
        assert!(vmm.try_wait().unwrap().is_none());

        vmm.kill().await.unwrap();
        let exit = vmm.try_wait().unwrap().expect("killed means exited");
        assert_eq!(exit, vmm.wait().await.unwrap(), "the exit is remembered");
        assert!(gone_within(pid, Duration::from_secs(5)).await);
        // Killing again is not an error.
        vmm.kill().await.unwrap();
    }

    #[tokio::test]
    async fn dropping_the_handle_kills_the_vmm() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("firecracker.pid");
        let mut spawner = jailer(FORK_AND_RECORD, &pid_file);
        assert!(spawner.wait().await.unwrap().success());
        let pid: u32 = std::fs::read_to_string(&pid_file).unwrap().parse().unwrap();
        drop(VmmProcess::adopt_for_test(pid));
        assert!(
            gone_within(pid, Duration::from_secs(5)).await,
            "kill on drop"
        );
    }

    /// The whole jailed launch against a real pid namespace: the stand-in jailer clones its
    /// "VMM" with `unshare --pid --fork`, records the clone's pid, and exits. Needs root.
    #[tokio::test]
    #[ignore = "needs root for unshare --pid; run with sudo on a Linux host"]
    async fn a_jailed_launch_supervises_the_namespace_init_in_the_pid_file() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("firecracker.pid");
        // `unshare` stays as the clone's parent; the "VMM" is a shell carrying `--id jail-1`.
        let script = "unshare --pid --fork /bin/sh -c 'sleep 30; :' --id jail-1 & \
                      for _ in $(seq 100); do \
                        c=$(cat /proc/$!/task/$!/children 2>/dev/null); \
                        [ -n \"$c\" ] && printf %s $c > \"$1\" && exit 0; sleep 0.05; \
                      done; exit 1";
        let launch = Launch::Jailed {
            command: {
                let mut c = Command::new("/bin/sh");
                c.args(["-c", script, "sh"]).arg(&pid_file);
                c
            },
            pid_file: pid_file.clone(),
            jail_id: "jail-1".to_string(),
            cgroup: None,
        };
        let mut vmm = launch.start(|c| c.spawn()).await.expect("handoff");
        let pid = vmm.pid().get();
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        assert!(
            is_namespace_init(&parse_nspid(&status).unwrap()),
            "{status}"
        );
        assert!(vmm.try_wait().unwrap().is_none());
        vmm.kill().await.unwrap();
        assert!(gone_within(pid, Duration::from_secs(5)).await);
    }
}
