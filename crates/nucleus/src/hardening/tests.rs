//! The confinement decider's unit tests (`hardening.rs`), in their own file
//! so the decider stays under the line ceiling.

use super::*;

/// A kernel that enforces, and no waiver: the posture every test below
/// that is not about Landlock runs under.
const LL: LandlockSupport = LandlockSupport::Abi(MIN_LANDLOCK_ABI);
const NO: LandlockWaiver = LandlockWaiver::Absent;

/// An isolated host service (the egress proxy) is separated or refused:
/// a non-root runtime cannot make the namespace or the drop, and a uid or
/// gid of 0 is no drop at all.
#[test]
fn an_isolated_service_is_separated_or_refused() {
    let c = ChildConfinement::decide_isolated(0, 4242, 4243, LL).expect("root can isolate");
    assert_eq!(c.child_uid(), ChildUid::Distinct(4242));
    assert_eq!(c.syscall_filter(), SyscallFilter::WorkloadDenylist);
    assert_eq!(c.filesystem(), FilesystemConfinement::NotApplied);
    assert!(c.restricts() && c.closes_inherited_fds() && !c.is_unsandboxed());
    assert!(matches!(
        ChildConfinement::decide_isolated(1000, 4242, 4243, LL),
        Err(NucleusError::ChildSeparationUnavailable { .. })
    ));
    for (uid, gid) in [(0, 4243), (4242, 0)] {
        assert!(matches!(
            ChildConfinement::decide_isolated(0, uid, gid, LL),
            Err(NucleusError::ChildSharesRuntimeUid { .. })
        ));
    }
}

/// The derived policy that adds nothing to the denylist.
#[cfg(all(unix, not(target_os = "linux")))]
fn nothing_derived() -> SeccompPolicy {
    SeccompPolicy::derive(
        &portcullis::PermissionLattice::permissive(),
        portcullis::NetworkEgress::Declared,
    )
}

#[cfg(all(unix, not(target_os = "linux")))]
#[test]
fn a_required_syscall_filter_refuses_the_spawn_off_linux() {
    let confinement = ChildConfinement::decide(
        ContainmentMode::HostHardened,
        1000,
        UnsandboxedOptIn::Absent,
        LL,
        NO,
    )
    .expect("the posture requires a filter");
    let mut cmd = std::process::Command::new("/bin/true");
    let _ = confinement.apply(
        &mut cmd,
        RlimitPolicy::node_ceiling().at_ceiling(),
        nothing_derived(),
        &WorkspaceWrites::Writable,
    );
    let err = cmd
        .status()
        .expect_err("an unavailable filter must prevent exec");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
}

/// Owner decision 2 (2026-10-02): a root runtime's `/v1/run` child drops
/// to the workload uid in every mode, not only `MicroVM`. Red before the
/// decision: `Unsandboxed` and `HostHardened` returned `drop_uid() ==
/// None` for runtime uid 0, i.e. a root child.
#[test]
fn a_root_runtimes_child_drops_in_every_mode() {
    for mode in [
        ContainmentMode::Unsandboxed,
        ContainmentMode::HostHardened,
        ContainmentMode::MicroVM,
    ] {
        let c = ChildConfinement::decide(mode, 0, UnsandboxedOptIn::Absent, LL, NO)
            .expect("a declared mode confines");
        assert_eq!(c.drop_uid(), Some(DEFAULT_CHILD_UID), "{mode:?}");
        assert!(c.restricts(), "{mode:?}");
        assert!(!c.is_unsandboxed(), "{mode:?}");
    }
}

/// Owner decision 1 (2026-10-02): a non-root runtime runs a workload at
/// its own uid only on an explicit opt-in; without one it refuses BY NAME.
/// Red before the decision: declaring `Unsandboxed` alone admitted it.
#[test]
fn a_bare_tier_workload_needs_the_explicit_opt_in() {
    assert!(matches!(
        ChildConfinement::decide_workload(
            ContainmentMode::Unsandboxed,
            None,
            1000,
            UnsandboxedOptIn::Absent,
            LL,
            NO
        ),
        Err(NucleusError::UnsandboxedNotOptedIn { runtime_uid: 1000 })
    ));
    let c = ChildConfinement::decide_workload(
        ContainmentMode::Unsandboxed,
        None,
        1000,
        UnsandboxedOptIn::Explicit,
        LL,
        NO,
    )
    .expect("the opted-in bare tier runs");
    assert!(c.is_unsandboxed());
    assert_eq!(c.child_uid(), ChildUid::SharedWithRuntime);
    // The opt-in is not needed where nothing shares a uid: a root runtime
    // drops, with or without it.
    for opt_in in [UnsandboxedOptIn::Absent, UnsandboxedOptIn::Explicit] {
        let c = ChildConfinement::decide_workload(
            ContainmentMode::Unsandboxed,
            None,
            0,
            opt_in,
            LL,
            NO,
        )
        .unwrap();
        assert_eq!(c.child_uid(), ChildUid::Distinct(DEFAULT_CHILD_UID));
    }
}

/// The follow-up decision: the `/v1/run` child needs the same opt-in as
/// the workload, through the same rule. Declaring `Unsandboxed` on a
/// non-root runtime without it is a named refusal; with it, bare; and a
/// root runtime drops either way.
#[test]
fn a_bare_run_child_needs_the_same_opt_in_as_the_workload() {
    assert!(matches!(
        ChildConfinement::decide(
            ContainmentMode::Unsandboxed,
            1000,
            UnsandboxedOptIn::Absent,
            LL,
            NO
        ),
        Err(NucleusError::UnsandboxedNotOptedIn { runtime_uid: 1000 })
    ));
    for opt_in in [UnsandboxedOptIn::Absent, UnsandboxedOptIn::Explicit] {
        assert_eq!(
            ChildConfinement::decide(ContainmentMode::Unsandboxed, 1000, opt_in, LL, NO).ok(),
            ChildConfinement::decide_workload(
                ContainmentMode::Unsandboxed,
                None,
                1000,
                opt_in,
                LL,
                NO
            )
            .ok(),
            "{opt_in:?}: the run child and the default workload are one decision"
        );
        let c = ChildConfinement::decide(ContainmentMode::Unsandboxed, 0, opt_in, LL, NO).unwrap();
        assert_eq!(c.drop_uid(), Some(DEFAULT_CHILD_UID));
    }
}

/// The opt-in reaches only the bare tier: it never turns a refused
/// separation in another mode into a same-uid workload.
#[test]
fn the_opt_in_grants_nothing_outside_the_bare_tier() {
    for mode in [ContainmentMode::HostHardened, ContainmentMode::MicroVM] {
        assert!(
            matches!(
                ChildConfinement::decide_workload(
                    mode,
                    None,
                    1000,
                    UnsandboxedOptIn::Explicit,
                    LL,
                    NO
                ),
                Err(NucleusError::ChildSeparationUnavailable { .. })
            ),
            "{mode:?}"
        );
    }
}

/// THE finding (A-19): inside a guest the runtime is root, and a MicroVM
/// child must leave root. Red on the commit before this module, where the
/// Executor handed the spawn home `None` for every mode but HostHardened.
#[test]
fn a_microvm_child_of_a_root_runtime_drops_to_the_workload_uid_and_is_restricted() {
    let c = ChildConfinement::decide(
        ContainmentMode::MicroVM,
        0,
        UnsandboxedOptIn::Absent,
        LL,
        NO,
    )
    .expect("MicroVM confines");
    assert_eq!(c.drop_uid(), Some(DEFAULT_CHILD_UID));
    assert_eq!(c.drop_uid(), Some(65534));
    assert!(c.restricts(), "no_new_privs + rlimits");
    assert!(c.closes_inherited_fds());
}

/// The MicroVM `/v1/run` child and the default workload are the SAME
/// decision, at every runtime uid — including the refusal.
#[test]
fn the_microvm_child_and_the_default_workload_are_one_decision() {
    for runtime in [0, 1000] {
        assert_eq!(
            ChildConfinement::decide(
                ContainmentMode::MicroVM,
                runtime,
                UnsandboxedOptIn::Absent,
                LL,
                NO
            )
            .ok(),
            ChildConfinement::decide_workload(
                ContainmentMode::MicroVM,
                None,
                runtime,
                UnsandboxedOptIn::Absent,
                LL,
                NO
            )
            .ok(),
        );
    }
}

/// #3120 item 2, at the decision: separation wanted and impossible is a
/// named refusal, not a same-uid child. Before the fix this returned a
/// `CloseInherited` posture — the runtime's uid — for a non-root runtime,
/// the state the workload admission refuses.
#[test]
fn a_non_root_runtime_refuses_a_microvm_child_by_name() {
    assert!(matches!(
        ChildConfinement::decide(
            ContainmentMode::MicroVM,
            1000,
            UnsandboxedOptIn::Absent,
            LL,
            NO
        ),
        Err(NucleusError::ChildSeparationUnavailable {
            runtime_uid: 1000,
            child_uid: DEFAULT_CHILD_UID,
        })
    ));
}

/// Every mode that wants a separated workload refuses one a non-root
/// runtime cannot drop, whatever the uid asked for.
#[test]
fn a_non_root_runtime_refuses_every_separated_workload_by_name() {
    for mode in [ContainmentMode::MicroVM, ContainmentMode::HostHardened] {
        for requested in [None, Some(4242)] {
            for opt_in in [UnsandboxedOptIn::Absent, UnsandboxedOptIn::Explicit] {
                assert!(
                    matches!(
                        ChildConfinement::decide_workload(mode, requested, 1000, opt_in, LL, NO),
                        Err(NucleusError::ChildSeparationUnavailable { .. })
                    ),
                    "{mode:?} / {requested:?} / {opt_in:?}"
                );
            }
        }
    }
}

/// The bare host tier is reached only by declaring it, and only for the
/// default uid: an explicit `workload.uid` is honoured or refused.
#[test]
fn unsandboxed_is_the_only_same_uid_workload_and_only_by_default() {
    let c = ChildConfinement::decide_workload(
        ContainmentMode::Unsandboxed,
        None,
        1000,
        UnsandboxedOptIn::Explicit,
        LL,
        NO,
    )
    .expect("the declared, opted-in bare tier runs");
    assert!(c.is_unsandboxed());
    assert_eq!(c.child_uid(), ChildUid::SharedWithRuntime);
    // Owner decision 3: an explicit uid is honoured or refused, opt-in or not.
    for opt_in in [UnsandboxedOptIn::Absent, UnsandboxedOptIn::Explicit] {
        assert!(matches!(
            ChildConfinement::decide_workload(
                ContainmentMode::Unsandboxed,
                Some(4242),
                1000,
                opt_in,
                LL,
                NO
            ),
            Err(NucleusError::ChildSeparationUnavailable { .. })
        ));
    }
}

/// The runtime's own uid is never a boundary, in any mode, root or not.
#[test]
fn a_workload_asking_for_the_runtimes_uid_is_refused_by_name() {
    for mode in [
        ContainmentMode::Unsandboxed,
        ContainmentMode::HostHardened,
        ContainmentMode::MicroVM,
    ] {
        for opt_in in [UnsandboxedOptIn::Absent, UnsandboxedOptIn::Explicit] {
            assert!(matches!(
                ChildConfinement::decide_workload(mode, Some(1000), 1000, opt_in, LL, NO),
                Err(NucleusError::ChildSharesRuntimeUid { uid: 1000 })
            ));
            assert!(matches!(
                ChildConfinement::decide_workload(mode, Some(0), 0, opt_in, LL, NO),
                Err(NucleusError::ChildSharesRuntimeUid { uid: 0 })
            ));
        }
    }
}

/// A root runtime drops an explicit uid to exactly that uid.
#[test]
fn a_root_runtime_drops_an_explicit_workload_uid() {
    let c = ChildConfinement::decide_workload(
        ContainmentMode::MicroVM,
        Some(4242),
        0,
        UnsandboxedOptIn::Absent,
        LL,
        NO,
    )
    .unwrap();
    assert_eq!(c.child_uid(), ChildUid::Distinct(4242));
    assert!(c.restricts());
}

/// #2696 P3b: the syscall filter per mode, at every runtime uid that
/// confines, for the `/v1/run` child and the workload alike. `MicroVM` and
/// `HostHardened` filter; `Unsandboxed` does not, even when a root runtime
/// drops it (owner decision 2: the bare tier means no seccomp). Red before
/// P3b: there was no filter in any posture.
#[test]
fn every_confining_mode_filters_syscalls_and_the_bare_tier_does_not() {
    for runtime in [0, 1000] {
        for opt_in in [UnsandboxedOptIn::Absent, UnsandboxedOptIn::Explicit] {
            for (mode, want) in [
                (ContainmentMode::MicroVM, SyscallFilter::WorkloadDenylist),
                (
                    ContainmentMode::HostHardened,
                    SyscallFilter::WorkloadDenylist,
                ),
                (ContainmentMode::Unsandboxed, SyscallFilter::Unfiltered),
            ] {
                let run_child = ChildConfinement::decide(mode, runtime, opt_in, LL, NO);
                let workload =
                    ChildConfinement::decide_workload(mode, None, runtime, opt_in, LL, NO);
                for (what, got) in [("run child", run_child), ("workload", workload)] {
                    // A refusal (non-root MicroVM, unopted bare tier) has
                    // no filter to check; every posture that runs does.
                    if let Ok(c) = got {
                        assert_eq!(
                            c.syscall_filter(),
                            want,
                            "{what}: {mode:?} at uid {runtime}, {opt_in:?}"
                        );
                    }
                }
            }
        }
    }
    // Non-vacuity: the filtering rows above were actually reached.
    assert_eq!(
        ChildConfinement::decide(
            ContainmentMode::MicroVM,
            0,
            UnsandboxedOptIn::Absent,
            LL,
            NO
        )
        .unwrap()
        .syscall_filter(),
        SyscallFilter::WorkloadDenylist
    );
    assert_eq!(
        ChildConfinement::decide(
            ContainmentMode::HostHardened,
            1000,
            UnsandboxedOptIn::Absent,
            LL,
            NO
        )
        .unwrap()
        .syscall_filter(),
        SyscallFilter::WorkloadDenylist
    );
    // A root runtime's Unsandboxed child drops its uid and is still
    // unfiltered.
    let root_bare = ChildConfinement::decide(
        ContainmentMode::Unsandboxed,
        0,
        UnsandboxedOptIn::Absent,
        LL,
        NO,
    )
    .unwrap();
    assert_eq!(root_bare.drop_uid(), Some(DEFAULT_CHILD_UID));
    assert_eq!(root_bare.syscall_filter(), SyscallFilter::Unfiltered);
}

/// The kernels a MicroVM child must refuse without a waiver: Landlock
/// compiled out or disabled at boot (the 6.1.141 guest, #3148), and ABI 1.
const BELOW_MINIMUM: [LandlockSupport; 2] = [LandlockSupport::Unavailable, LandlockSupport::Abi(1)];

/// #2696 P3c, fail closed (A-19): on a kernel that cannot enforce the
/// ruleset, a MicroVM child, the workload and the `/v1/run` child alike,
/// is REFUSED by name. Red if the absent-waiver arm ever answers anything
/// but the refusal (a skipped ruleset is "could not look ⇒ fine").
#[test]
fn a_microvm_child_on_a_kernel_without_landlock_is_refused_by_name() {
    for kernel in BELOW_MINIMUM {
        for requested in [None, Some(4242)] {
            let workload = ChildConfinement::decide_workload(
                ContainmentMode::MicroVM,
                requested,
                0,
                UnsandboxedOptIn::Absent,
                kernel,
                LandlockWaiver::Absent,
            );
            assert!(
                matches!(
                    workload,
                    Err(NucleusError::LandlockUnavailable {
                        minimum: MIN_LANDLOCK_ABI,
                        ..
                    })
                ),
                "{kernel:?} / {requested:?}: {workload:?}"
            );
        }
        let run_child = ChildConfinement::decide(
            ContainmentMode::MicroVM,
            0,
            UnsandboxedOptIn::Absent,
            kernel,
            LandlockWaiver::Absent,
        );
        assert!(
            matches!(run_child, Err(NucleusError::LandlockUnavailable { .. })),
            "{kernel:?}: {run_child:?}"
        );
    }
    // The refusal names the way through, so an operator is not left to
    // guess which flag means "I accept this".
    let msg = ChildConfinement::decide(
        ContainmentMode::MicroVM,
        0,
        UnsandboxedOptIn::Absent,
        BELOW_MINIMUM[0],
        LandlockWaiver::Absent,
    )
    .unwrap_err()
    .to_string();
    assert!(msg.contains("--allow-workload-without-landlock"), "{msg}");
}

/// The operator's waiver admits the child and SAYS so: the posture is
/// `Waived` with the kernel's answer, never `Landlock`, and the uid drop
/// and syscall filter are untouched by it.
#[test]
fn the_waiver_admits_the_child_as_waived_never_as_confined() {
    for kernel in BELOW_MINIMUM {
        let c = ChildConfinement::decide_workload(
            ContainmentMode::MicroVM,
            None,
            0,
            UnsandboxedOptIn::Absent,
            kernel,
            LandlockWaiver::Explicit,
        )
        .expect("a waived kernel admits");
        assert_eq!(c.filesystem(), FilesystemConfinement::Waived { kernel });
        assert_eq!(c.drop_uid(), Some(DEFAULT_CHILD_UID));
        assert_eq!(c.syscall_filter(), SyscallFilter::WorkloadDenylist);
    }
}

/// A waiver cannot turn an enforceable ruleset off: on a Landlock kernel
/// the child is confined whether or not the operator waived it.
#[test]
fn a_waiver_does_not_disable_landlock_on_a_kernel_that_has_it() {
    for abi in [2, 3, 7] {
        for landlock in [LandlockWaiver::Absent, LandlockWaiver::Explicit] {
            let c = ChildConfinement::decide(
                ContainmentMode::MicroVM,
                0,
                UnsandboxedOptIn::Absent,
                LandlockSupport::Abi(abi),
                landlock,
            )
            .unwrap();
            assert_eq!(c.filesystem(), FilesystemConfinement::Landlock { abi });
        }
    }
}

/// Only the guest gets the guest layout's ruleset. `HostHardened` and the
/// bare tier are not filesystem-confined by it, on any kernel, and a
/// kernel without Landlock never refuses them.
#[test]
fn only_microvm_children_are_held_to_the_guest_ruleset() {
    for kernel in BELOW_MINIMUM.into_iter().chain([LL]) {
        for (mode, runtime) in [
            (ContainmentMode::HostHardened, 0),
            (ContainmentMode::HostHardened, 1000),
            (ContainmentMode::Unsandboxed, 0),
        ] {
            let c = ChildConfinement::decide(mode, runtime, UnsandboxedOptIn::Absent, kernel, NO)
                .unwrap_or_else(|e| panic!("{mode:?}/{runtime}/{kernel:?}: {e}"));
            assert_eq!(c.filesystem(), FilesystemConfinement::NotApplied);
        }
    }
}

/// The uid boundary is decided first: a non-root runtime is refused for
/// the separation it cannot do, whatever its kernel, so the refusal an
/// operator sees names the actual first problem.
#[test]
fn a_non_root_microvm_refusal_names_the_uid_before_the_kernel() {
    assert!(matches!(
        ChildConfinement::decide(
            ContainmentMode::MicroVM,
            1000,
            UnsandboxedOptIn::Absent,
            BELOW_MINIMUM[0],
            NO
        ),
        Err(NucleusError::ChildSeparationUnavailable { .. })
    ));
}

#[test]
fn unconfigured_is_refused_not_passed_through() {
    assert!(matches!(
        ChildConfinement::decide(
            ContainmentMode::Unconfigured,
            0,
            UnsandboxedOptIn::Absent,
            LL,
            NO
        ),
        Err(NucleusError::IsolationNotConfigured)
    ));
    assert!(matches!(
        ChildConfinement::decide_workload(
            ContainmentMode::Unconfigured,
            None,
            0,
            UnsandboxedOptIn::Explicit,
            LL,
            NO
        ),
        Err(NucleusError::IsolationNotConfigured)
    ));
}

/// A non-root `HostHardened` runtime cannot drop, so it self-restricts.
#[test]
fn host_hardened_restricts_without_a_uid_change() {
    let c = ChildConfinement::decide(
        ContainmentMode::HostHardened,
        1000,
        UnsandboxedOptIn::Absent,
        LL,
        NO,
    )
    .unwrap();
    assert_eq!(c.drop_uid(), None);
    assert!(c.restricts());
}

/// The bare posture: a non-root runtime under `Unsandboxed`. A root one
/// drops instead (owner decision 2).
#[test]
fn unsandboxed_is_the_one_bare_posture() {
    let c = ChildConfinement::decide(
        ContainmentMode::Unsandboxed,
        1000,
        UnsandboxedOptIn::Explicit,
        LL,
        NO,
    )
    .unwrap();
    assert!(c.is_unsandboxed());
    assert_eq!(c.drop_uid(), None);
    assert!(!c.restricts());
    // #3461: its one step of the hook, where there is a hook.
    assert_eq!(c.closes_inherited_fds(), cfg!(target_os = "linux"));
    for mode in [ContainmentMode::HostHardened, ContainmentMode::MicroVM] {
        assert!(
            ChildConfinement::decide(mode, 0, UnsandboxedOptIn::Absent, LL, NO)
                .is_ok_and(|c| !c.is_unsandboxed()),
            "{mode:?}"
        );
    }
}

/// #3461: the bare posture restricts nothing, yet on Linux its child
/// inherits no descriptor above stdio; off Linux it has no hook to do it.
#[test]
fn the_bare_posture_sweeps_inherited_fds_where_it_can() {
    let c = ChildConfinement::decide(
        ContainmentMode::Unsandboxed,
        1000,
        UnsandboxedOptIn::Explicit,
        LL,
        NO,
    )
    .unwrap();
    assert!(!c.restricts());
    assert_eq!(c.closes_inherited_fds(), cfg!(target_os = "linux"));
}

/// #2572: only an installed hook claims hardening, and the claim carries
/// the limits the hook sets. The declared bare tier cannot claim it, and
/// neither can a platform with no hook.
#[test]
fn only_an_installed_hook_claims_hardening() {
    let rlimits = RlimitPolicy::for_pod(std::time::Duration::from_secs(60), Some(2)).at_ceiling();
    // Derives the socket class only, so no exec pin is needed for
    // `/bin/true` on a host without one.
    let derived = SeccompPolicy::derive(
        &portcullis::PermissionLattice::codegen(),
        portcullis::NetworkEgress::None,
    );
    let bare = ChildConfinement::decide(
        ContainmentMode::Unsandboxed,
        1000,
        UnsandboxedOptIn::Explicit,
        LL,
        NO,
    )
    .unwrap();
    assert_eq!(
        bare.apply(
            &mut std::process::Command::new("/bin/true"),
            rlimits,
            derived,
            &WorkspaceWrites::Writable
        ),
        SpawnHardening::Unhardened(Unhardened::DeclaredBareTier)
    );
    let restricted = ChildConfinement::decide(
        ContainmentMode::HostHardened,
        1000,
        UnsandboxedOptIn::Absent,
        LL,
        NO,
    )
    .unwrap();
    let got = restricted.apply(
        &mut std::process::Command::new("/bin/true"),
        rlimits,
        derived,
        &WorkspaceWrites::Writable,
    );
    #[cfg(target_os = "linux")]
    match got {
        SpawnHardening::Hardened(h) => {
            assert_eq!(h.rlimits(), rlimits);
            // #2907: the receipt's one record of the derived classes is
            // what the hook installs, read off the posture's filter.
            assert_eq!(h.syscalls(), InstalledFilter::WorkloadDenylist { derived });
        }
        SpawnHardening::Unhardened(why) => {
            panic!("a restricted child was not hardened: {why:?}")
        }
    }
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        got,
        SpawnHardening::Unhardened(Unhardened::NoHookOnThisPlatform)
    );
    // A root runtime's bare-tier child drops its uid and is hardened, but
    // its posture has no filter, so the receipt must not claim the
    // derived classes were installed.
    #[cfg(target_os = "linux")]
    {
        let root_bare = ChildConfinement::decide(
            ContainmentMode::Unsandboxed,
            0,
            UnsandboxedOptIn::Absent,
            LL,
            NO,
        )
        .unwrap();
        match root_bare.apply(
            &mut std::process::Command::new("/bin/true"),
            rlimits,
            derived,
            &WorkspaceWrites::Writable,
        ) {
            SpawnHardening::Hardened(h) => {
                assert_eq!(h.syscalls(), InstalledFilter::Unfiltered);
            }
            SpawnHardening::Unhardened(why) => panic!("{why:?}"),
        }
    }
}

// ── #3528: a private user and network namespace ─────────────────────────

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
