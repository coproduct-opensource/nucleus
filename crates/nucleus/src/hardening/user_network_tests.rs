//! The private user and network namespace's decider tests (#3528), beside
//! `hardening.rs`'s own so the decider stays under the line ceiling.

use super::*;

/// A kernel that enforces, and no waiver, as in `hardening.rs`'s tests.
const LL: LandlockSupport = LandlockSupport::Abi(MIN_LANDLOCK_ABI);
const NO: LandlockWaiver = LandlockWaiver::Absent;

const OWN: PidNamespace = PidNamespace::Own;
const KERNEL_HAS_USERNS: UserNamespaces = UserNamespaces::Available;

fn private(outer_uid: u32, inner_uid: u32, loopback: bool) -> NamespaceSetup {
    NamespaceSetup::PrivateUserNetwork {
        outer_uid,
        inner_uid,
        loopback,
    }
}

/// The guest's workload under a root runtime: a filtered drop to 65534,
/// with the guest layout's Landlock ruleset.
fn guest_workload() -> ChildConfinement {
    ChildConfinement::decide_workload(
        ContainmentMode::MicroVM,
        Some(DEFAULT_CHILD_UID),
        0,
        UnsandboxedOptIn::Absent,
        LL,
        NO,
    )
    .expect("a root guest runtime drops its workload")
}

/// The one row that places it: a dropped, filtered workload in its own
/// PID namespace on a kernel with user namespaces. The placed workload
/// keeps every property of the base it was placed on (uid, filter,
/// Landlock), and runtime placement leaves the base unchanged.
#[test]
fn a_private_namespace_is_placed_on_a_filtered_drop_in_its_own_pid_namespace() {
    let base = guest_workload();
    for (inner, loopback) in [(0, false), (0, true), (1001, false), (1001, true)] {
        let placed = base
            .place(
                private(DEFAULT_CHILD_UID, inner, loopback),
                OWN,
                KERNEL_HAS_USERNS,
            )
            .expect("placed");
        assert_ne!(placed, base);
        assert_eq!(placed.child_uid(), ChildUid::Distinct(DEFAULT_CHILD_UID));
        assert_eq!(placed.syscall_filter(), SyscallFilter::WorkloadDenylist);
        assert_eq!(placed.filesystem(), base.filesystem());
        assert!(placed.restricts() && placed.closes_inherited_fds() && !placed.is_unsandboxed());
        assert_eq!(
            base.user_network_base(OWN, KERNEL_HAS_USERNS)
                .map(|(uid, _)| uid)
                .ok(),
            Some(DEFAULT_CHILD_UID)
        );
    }
    assert_eq!(
        base.place(NamespaceSetup::Runtime {}, OWN, KERNEL_HAS_USERNS)
            .unwrap(),
        base
    );
}

/// Every other row is a named refusal: no PID namespace of its own (a
/// host tier), no user namespaces in the kernel, an unfiltered or
/// same-uid base, a host service, a second placement, an outer uid other
/// than the drop, or a setup that is not a workload placement.
#[test]
fn every_other_placement_is_refused_by_name() {
    let refused = |got: Result<ChildConfinement>, why: &str| match got {
        Err(NucleusError::WorkloadNamespaceUnavailable { reason }) => reason,
        other => panic!("{why}: expected a named refusal, got {other:?}"),
    };
    let base = guest_workload();
    let want = private(DEFAULT_CHILD_UID, 0, true);
    refused(
        base.place(want, PidNamespace::Shared, KERNEL_HAS_USERNS),
        "shared PID namespace",
    );
    let reason = refused(
        base.place(
            want,
            OWN,
            UserNamespaces::Unavailable {
                reason: "user.max_user_namespaces is 0 or unreadable",
            },
        ),
        "no user namespaces",
    );
    assert!(reason.contains("max_user_namespaces"), "{reason}");
    refused(
        base.place(private(4242, 0, true), OWN, KERNEL_HAS_USERNS),
        "outer uid is not the drop",
    );
    for setup in [
        NamespaceSetup::Unrecorded {},
        NamespaceSetup::PrivateNetwork {},
    ] {
        refused(base.place(setup, OWN, KERNEL_HAS_USERNS), "not a placement");
    }
    let placed = base.place(want, OWN, KERNEL_HAS_USERNS).unwrap();
    refused(placed.place(want, OWN, KERNEL_HAS_USERNS), "placed twice");
    let root_bare = ChildConfinement::decide_workload(
        ContainmentMode::Unsandboxed,
        Some(DEFAULT_CHILD_UID),
        0,
        UnsandboxedOptIn::Absent,
        LL,
        NO,
    )
    .unwrap();
    refused(
        root_bare.place(want, OWN, KERNEL_HAS_USERNS),
        "unfiltered drop",
    );
    let non_root_bare = ChildConfinement::decide_workload(
        ContainmentMode::Unsandboxed,
        None,
        1000,
        UnsandboxedOptIn::Explicit,
        LL,
        NO,
    )
    .unwrap();
    refused(
        non_root_bare.place(want, OWN, KERNEL_HAS_USERNS),
        "bare tier",
    );
    let restricted = ChildConfinement::decide(
        ContainmentMode::HostHardened,
        1000,
        UnsandboxedOptIn::Absent,
        LL,
        NO,
    )
    .unwrap();
    refused(restricted.place(want, OWN, KERNEL_HAS_USERNS), "same uid");
    let service = ChildConfinement::decide_isolated(0, 4242, 4242, LL).unwrap();
    refused(
        service.place(private(4242, 0, true), OWN, KERNEL_HAS_USERNS),
        "host service",
    );
    // What the tool-proxy hands `admit` follows the same rule: no PID
    // namespace of its own, no private placement, whatever the kernel.
    assert_eq!(
        base.namespace_enforcement(PidNamespace::Shared),
        NamespaceEnforcement::RuntimeOnly
    );
}

/// The receipt's `pids=` and `ns=` are read off the isolation the hook
/// runs, and only the user-network isolation records a private user
/// namespace (with its own PID namespace).
#[test]
fn the_receipt_reads_both_namespaces_off_the_isolation_the_hook_runs() {
    let rows = [
        (
            Isolation::None,
            PidNamespace::Shared,
            NamespaceSetup::Runtime {},
        ),
        (
            Isolation::NetnsThenDrop { uid: 7, gid: 7 },
            PidNamespace::Shared,
            NamespaceSetup::PrivateNetwork {},
        ),
        (
            Isolation::PidnsThenDrop { uid: 7, gid: 7 },
            PidNamespace::Own,
            NamespaceSetup::Runtime {},
        ),
        (
            Isolation::PidnsThenUserNetwork {
                uid: 65534,
                gid: 65534,
                inner_uid: 1001,
                loopback: false,
            },
            PidNamespace::Own,
            private(65534, 1001, false),
        ),
    ];
    for (isolation, pids, namespace) in rows {
        assert_eq!(isolation.pids(), pids, "{isolation:?}");
        assert_eq!(isolation.namespace(), namespace, "{isolation:?}");
    }
}

/// The probe is not the control; the hook is. Forced past the probe (the
/// placement made as if the kernel offered user namespaces), a root
/// runtime's spawn either runs in the namespace, where the kernel does
/// offer it, or fails, where it does not. It never runs without it.
#[cfg(target_os = "linux")]
#[test]
fn past_the_probe_the_hook_runs_in_the_namespace_or_refuses_the_spawn() {
    if runtime_uid() != 0 {
        eprintln!("skipped: the placement needs a root runtime");
        return;
    }
    let forced = guest_workload()
        .place(private(DEFAULT_CHILD_UID, 0, true), OWN, KERNEL_HAS_USERNS)
        .unwrap();
    let mut cmd = std::process::Command::new("/bin/true");
    cmd.current_dir("/");
    let hardening = forced.apply_with_pids(
        &mut cmd,
        RlimitPolicy::node_ceiling().at_ceiling(),
        SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        ),
        &WorkspaceWrites::Writable,
        OWN,
    );
    assert_eq!(
        hardening.namespace(),
        private(DEFAULT_CHILD_UID, 0, true),
        "the record is the placement"
    );
    let got = cmd.status();
    match UserNamespaces::probe() {
        UserNamespaces::Available => {
            assert!(got.expect("this kernel offers it").success());
        }
        UserNamespaces::Unavailable { reason } => {
            let refused = got.expect_err("must not run without the namespace");
            eprintln!("{reason}: the spawn was refused: {refused}");
        }
    }
}

/// A placed workload has no shared-PID form: asked to spawn without its
/// own PID namespace, the hook refuses the spawn rather than run it in
/// the runtime's user and network namespaces.
#[test]
fn a_placed_workload_is_refused_without_its_own_pid_namespace() {
    let placed = guest_workload()
        .place(private(DEFAULT_CHILD_UID, 0, true), OWN, KERNEL_HAS_USERNS)
        .unwrap();
    let mut cmd = std::process::Command::new("/usr/bin/true");
    let got = placed.apply_with_pids(
        &mut cmd,
        RlimitPolicy::node_ceiling().at_ceiling(),
        SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        ),
        &WorkspaceWrites::Writable,
        PidNamespace::Shared,
    );
    assert_eq!(got, SpawnHardening::Unhardened(Unhardened::Refused));
    assert_eq!(
        cmd.status().map_err(|e| e.raw_os_error()),
        Err(Some(libc::EOPNOTSUPP))
    );
}
