use super::*;

fn me() -> u32 {
    nucleus::runtime_uid()
}

/// A uid that owns nothing the harness made.
fn stranger() -> u32 {
    me().wrapping_add(4242)
}

fn held(exposure: Exposure, at: At) -> Held {
    Held {
        name: "--held",
        exposure,
        at,
    }
}

fn at(p: &Path) -> At {
    At::Path(p.to_path_buf())
}

fn chmod(p: &Path, mode: u32) {
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// A private directory holding one private file: what a careful operator
/// provisions. Returns (dir, file).
fn private_file() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    chmod(dir.path(), 0o700);
    let file = dir.path().join("held");
    std::fs::write(&file, b"held").unwrap();
    chmod(&file, 0o600);
    (dir, file)
}

fn admit(children: Vec<ChildUid>, item: Held) -> Result<(), String> {
    ChildReach::for_test(children).admit(&[item], &RuntimeSeal::unsealed())
}

/// #3461, the bare host tier: a child at the proxy's own uid reaches every
/// file the proxy holds. A secret or durable item is refused by name. A
/// session item is the tier's declared exposure and admitted.
#[test]
fn the_bare_tier_may_hold_no_secret_or_durable_file() {
    let (_dir, file) = private_file();
    for exposure in [Exposure::Secret, Exposure::Durable] {
        let refused = admit(vec![ChildUid::SharedWithRuntime], held(exposure, at(&file)))
            .expect_err("a bare-tier child reaches it");
        assert!(
            refused.contains("--held") && refused.contains("bare host tier"),
            "{refused}"
        );
    }
    assert!(
        admit(
            vec![ChildUid::SharedWithRuntime],
            held(Exposure::Session, at(&file))
        )
        .is_ok()
    );
    assert!(
        admit(vec![], held(Exposure::Secret, at(&file))).is_ok(),
        "no child, no reach"
    );
}

/// #3461, a separated child: refused exactly when it owns the item, owns a
/// directory above it, can write the item, or can read a secret. The private
/// layout admits it; each relaxation is refused, by the right reason.
#[test]
fn a_separated_child_is_refused_by_ownership_bits_and_directories() {
    let (dir, file) = private_file();
    let other = vec![ChildUid::Distinct(stranger())];
    for exposure in [Exposure::Secret, Exposure::Durable, Exposure::Session] {
        assert!(
            admit(other.clone(), held(exposure, at(&file))).is_ok(),
            "{exposure:?}"
        );
    }
    // The child owns the directory (and the file): the harness's own uid.
    let refused = admit(
        vec![ChildUid::Distinct(me())],
        held(Exposure::Session, at(&file)),
    )
    .unwrap_err();
    assert!(
        refused.contains(&format!("uid {}, which a child runs as, owns", me())),
        "{refused}"
    );

    // Other-readable: a secret is reached, a durable item is not.
    chmod(&file, 0o644);
    let refused = admit(other.clone(), held(Exposure::Secret, at(&file))).unwrap_err();
    assert!(refused.contains("is readable by a child"), "{refused}");
    assert!(admit(other.clone(), held(Exposure::Durable, at(&file))).is_ok());

    // Other-writable: every class is reached.
    chmod(&file, 0o606);
    for exposure in [Exposure::Secret, Exposure::Durable, Exposure::Session] {
        let refused = admit(other.clone(), held(exposure, at(&file))).unwrap_err();
        assert!(refused.contains("is writable by a child"), "{refused}");
    }
    chmod(&file, 0o600);

    // A directory above that the child can write, without the sticky bit:
    // the file can be replaced. With the sticky bit it cannot.
    chmod(dir.path(), 0o777);
    let refused = admit(other.clone(), held(Exposure::Durable, at(&file))).unwrap_err();
    assert!(refused.contains("is replaceable"), "{refused}");
    chmod(dir.path(), 0o1777);
    assert!(admit(other.clone(), held(Exposure::Durable, at(&file))).is_ok());
    // But a name not created yet in a directory the child can write, sticky
    // or not, can be created by the child first.
    let refused = admit(
        other.clone(),
        held(Exposure::Session, at(&dir.path().join("not-yet"))),
    )
    .unwrap_err();
    assert!(refused.contains("can create"), "{refused}");
    chmod(dir.path(), 0o700);
    assert!(
        admit(
            other,
            held(Exposure::Session, at(&dir.path().join("not-yet")))
        )
        .is_ok()
    );
}

/// #3461: a held path that is a symlink is checked where the bytes are, not
/// only where it was named.
#[test]
fn a_symlink_is_followed_to_the_file_it_names() {
    let (_dir, file) = private_file();
    let open = tempfile::tempdir().unwrap();
    chmod(open.path(), 0o777);
    let real = open.path().join("real");
    std::fs::write(&real, b"held").unwrap();
    chmod(&real, 0o600);
    let link = file.with_file_name("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let refused = admit(
        vec![ChildUid::Distinct(stranger())],
        held(Exposure::Secret, at(&link)),
    )
    .unwrap_err();
    assert!(refused.contains("is replaceable"), "{refused}");
}

/// #3461: a secret on the command line is reachable by every child; in the
/// environment, only by a child at the proxy's own uid, and by it only while
/// the runtime is unsealed.
#[test]
fn argv_is_reached_by_every_child_and_the_environment_only_unsealed() {
    for child in [ChildUid::SharedWithRuntime, ChildUid::Distinct(stranger())] {
        let refused = admit(vec![child], held(Exposure::Secret, At::Argv)).unwrap_err();
        assert!(refused.contains("command line"), "{refused}");
    }
    assert!(
        admit(
            vec![ChildUid::Distinct(stranger())],
            held(Exposure::Secret, At::Env)
        )
        .is_ok()
    );
    let refused = admit(
        vec![ChildUid::SharedWithRuntime],
        held(Exposure::Secret, At::Env),
    )
    .unwrap_err();
    assert!(refused.contains("environment"), "{refused}");
    #[cfg(target_os = "linux")]
    {
        let sealed = nucleus::seal_runtime().expect("a Linux harness can seal itself");
        assert_eq!(sealed.environment(), EnvironmentReach::ClosedToSameUid);
        assert!(
            ChildReach::for_test(vec![ChildUid::SharedWithRuntime])
                .admit(&[held(Exposure::Secret, At::Env)], &sealed)
                .is_ok()
        );
    }
}

/// #3461: `--peer-uids` naming a child's uid serves that child as the host.
#[test]
fn a_front_door_peer_that_is_a_child_is_refused() {
    let child = stranger();
    let refused = admit(
        vec![ChildUid::Distinct(child)],
        held(Exposure::Session, At::FrontDoorPeer(child)),
    )
    .unwrap_err();
    assert!(
        refused.contains(&format!("admits uid {child}")),
        "{refused}"
    );
    assert!(
        admit(
            vec![ChildUid::Distinct(child)],
            held(Exposure::Session, At::FrontDoorPeer(child + 1))
        )
        .is_ok()
    );
}

/// The census, over a parsed command line: a key path is held only where it
/// is read, and a secret given as a flag is held on the command line.
#[test]
fn the_census_holds_what_is_read_where_clap_found_it() {
    use clap::{CommandFactory, FromArgMatches};
    let parse = |argv: &[&str]| {
        let matches = crate::Args::command()
            .try_get_matches_from(
                ["nucleus-tool-proxy", "--spec", "/s.yaml"]
                    .iter()
                    .chain(argv)
                    .copied(),
            )
            .unwrap();
        let args = crate::Args::from_arg_matches(&matches).unwrap();
        let none = |_: &str| false;
        crate::secret_census::held(
            &args,
            &matches,
            &crate::secret_census::Facts {
                guest_proof: false,
                workload: false,
                env_set: &none,
            },
        )
    };
    let names = |held: &[Held]| held.iter().map(|h| h.name).collect::<Vec<_>>();
    let base = parse(&[]);
    assert_eq!(names(&base), ["--spec", "--audit-log"]);
    // Unread: no node client, no mTLS listener.
    let unread = parse(&["--identity-key", "/k.pem", "--tls-key", "/t.pem"]);
    assert_eq!(names(&unread), ["--spec", "--audit-log"]);
    let read = parse(&[
        "--identity-key",
        "/k.pem",
        "--enable-pod-mgmt",
        "--tls-key",
        "/t.pem",
        "--mtls",
    ]);
    assert!(read.contains(&Held {
        name: "--identity-key",
        exposure: Exposure::Secret,
        at: At::Path("/k.pem".into()),
    }));
    assert!(read.contains(&Held {
        name: "--tls-key",
        exposure: Exposure::Secret,
        at: At::Path("/t.pem".into()),
    }));
    let flag = parse(&["--approval-secret", "s3cret"]);
    assert!(flag.contains(&Held {
        name: "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
        exposure: Exposure::Secret,
        at: At::Argv,
    }));
    let set = |name: &str| name == "NUCLEUS_TOOL_PROXY_BROKER_SECRET";
    let matches = crate::Args::command()
        .try_get_matches_from(["nucleus-tool-proxy", "--spec", "/s.yaml"])
        .unwrap();
    let args = crate::Args::from_arg_matches(&matches).unwrap();
    let env = crate::secret_census::held(
        &args,
        &matches,
        &crate::secret_census::Facts {
            guest_proof: true,
            workload: true,
            env_set: &set,
        },
    );
    for (name, exposure) in [
        (
            "--audit-log (its request-proof replay ledger)",
            Exposure::Durable,
        ),
        ("--workload-proof-state", Exposure::Secret),
        ("NUCLEUS_TOOL_PROXY_BROKER_SECRET", Exposure::Secret),
    ] {
        assert!(
            env.iter().any(|h| h.name == name && h.exposure == exposure),
            "{name}: {env:?}"
        );
    }
}

/// Spawn `script` as the proxy spawns a workload, under the harness's
/// declared posture, and return its stdout. The same posture the reach was
/// asked about: [`HARNESS`], opted in.
#[cfg(target_os = "linux")]
async fn run_probe(script: String, work_dir: &Path) -> String {
    let spec = nucleus_spec::WorkloadSpec {
        command: "/bin/sh".into(),
        artifacts: Default::default(),
        args: vec!["-c".into(), script],
        uid: None,
        env: Default::default(),
    };
    let plan =
        crate::workload::WorkloadLaunch::build(&spec, "http://127.0.0.1:8080", work_dir, &[])
            .admit(
                HARNESS,
                nucleus::UnsandboxedOptIn::Explicit,
                nucleus::LandlockWaiver::Absent,
            )
            .expect("the harness admits its probe");
    let (child, _) = crate::workload::spawn_admitted(
        plan,
        nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
        portcullis::SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        ),
    )
    .unwrap();
    let out = child.wait_with_output().await.unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[cfg(target_os = "linux")]
const HARNESS: nucleus::ContainmentMode = nucleus::ContainmentMode::Unsandboxed;

/// The reach a real workload child of this harness has.
#[cfg(target_os = "linux")]
fn harness_reach() -> ChildReach {
    ChildReach::of(
        Some(&nucleus_spec::WorkloadSpec {
            command: "/bin/sh".into(),
            artifacts: Default::default(),
            args: vec![],
            uid: None,
            env: Default::default(),
        }),
        HARNESS,
        nucleus::UnsandboxedOptIn::Explicit,
        nucleus::LandlockWaiver::Absent,
    )
}

/// **#3461, on a real spawn, per file class.** A secret and a durable item,
/// each in a private file, each as the proxy would hold it. The real
/// deciders say who the workload runs as. Either the proxy refuses to hold
/// the item, by name, or the workload child, spawned as the proxy spawns
/// one, cannot read (secret) or write (durable) it.
///
/// On a non-root harness the child shares the proxy's uid, so both are
/// refused, and a positive control shows the child could have reached them.
/// On a root harness the child drops to 65534 and both are admitted and out
/// of its reach. Red with the reach check removed from `admit`, on a
/// non-root harness: both were admitted, and the child read and wrote them.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_workload_child_reaches_no_secret_or_durable_file() {
    let (dir, file) = private_file();
    // A root harness's dropped child must be able to reach the workspace
    // to run in it at all; the held file stays private.
    let workspace = tempfile::tempdir().unwrap();
    let reach = harness_reach();
    for exposure in [Exposure::Secret, Exposure::Durable] {
        std::fs::write(&file, b"held-bytes").unwrap();
        let probe = format!(
            "cat '{0}' && echo READ; printf x >> '{0}' && echo WROTE; true",
            file.display()
        );
        match reach.admit(&[held(exposure, at(&file))], &RuntimeSeal::unsealed()) {
            Ok(()) => {
                let seen = run_probe(probe, workspace.path()).await;
                assert!(
                    !seen.contains("held-bytes") && !seen.contains("READ"),
                    "{seen}"
                );
                assert!(!seen.contains("WROTE"), "{seen}");
                assert_eq!(std::fs::read(&file).unwrap(), b"held-bytes");
            }
            Err(refused) => {
                assert!(refused.contains("bare host tier"), "{refused}");
                // Positive control: the refusal is not vacuous.
                let seen = run_probe(probe, workspace.path()).await;
                assert!(seen.contains("READ") && seen.contains("WROTE"), "{seen}");
            }
        }
    }
    drop(dir);
}

/// **#3461, the environment, on a real spawn.** A bare-tier child (the
/// harness is non-root) reads `/proc/$PPID/environ`. After
/// `nucleus::seal_runtime` it cannot, and [`ChildReach::admit`] admits an
/// environment secret on the bare tier only then. A root harness's child is
/// another uid, which reads it neither before the seal nor after.
///
/// Red with `seal_runtime` reduced to a no-op that still claims a seal: the
/// sealed probe read the environment.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn sealing_closes_the_environment_to_a_same_uid_child() {
    let workspace = tempfile::tempdir().unwrap();
    let probe = || {
        String::from(
            "tr '\\0' '\\n' < /proc/$PPID/environ | grep -q '^PATH=' && echo ENVIRON; \
             echo RAN",
        )
    };
    let bare = !nix::unistd::geteuid().is_root();
    let before = run_probe(probe(), workspace.path()).await;
    assert!(before.contains("RAN"), "{before}");
    if bare {
        // Positive control: unsealed, a same-uid child reads it.
        assert!(before.contains("ENVIRON"), "{before}");
    }
    let seal = nucleus::seal_runtime().unwrap();
    assert_eq!(seal.environment(), EnvironmentReach::ClosedToSameUid);
    let after = run_probe(probe(), workspace.path()).await;
    assert!(after.contains("RAN"), "{after}");
    assert!(!after.contains("ENVIRON"), "sealed, yet read: {after}");
    let item = Held {
        name: "PATH",
        exposure: Exposure::Secret,
        at: At::Env,
    };
    assert!(
        harness_reach()
            .admit(std::slice::from_ref(&item), &seal)
            .is_ok()
    );
    if bare {
        assert!(
            harness_reach()
                .admit(&[item], &RuntimeSeal::unsealed())
                .is_err()
        );
    }
}

/// **#3461, inherited descriptors, on a real spawn.** The proxy holds a
/// descriptor without close-on-exec, as one inherited from a careless
/// launcher or a build tool's jobserver is. A workload child, spawned as the
/// proxy spawns one under the harness's posture, does not get it: every
/// posture sweeps descriptors above stdio at exec, the bare tier included.
///
/// Red on main, on a non-root harness: the bare tier swept nothing and the
/// child listed the descriptor.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_workload_child_inherits_no_descriptor_the_proxy_holds() {
    let workspace = tempfile::tempdir().unwrap();
    let marker = tempfile::NamedTempFile::new().unwrap();
    let held_fd = marker.reopen().unwrap();
    nix::fcntl::fcntl(
        &held_fd,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    )
    .unwrap();
    let seen = run_probe(
        String::from("for f in /proc/self/fd/*; do readlink \"$f\"; done; echo RAN"),
        workspace.path(),
    )
    .await;
    // Non-vacuity: the probe ran and listed at least its own stdout.
    assert!(seen.contains("RAN") && seen.contains("pipe:"), "{seen}");
    assert!(
        !seen.contains(marker.path().to_str().unwrap()),
        "the child inherited the proxy's descriptor:\n{seen}"
    );
    // The sweep is the child's: this process's descriptor still works.
    assert!(held_fd.metadata().is_ok());
}
