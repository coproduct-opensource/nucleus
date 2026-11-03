//! The subordinate-id tier and the guest's own PID namespace (#3344), refused together.

use super::*;

/// A subordinate-id child and its own PID namespace (#3344) are not composed:
/// asked for both, the hook refuses the spawn rather than drop either, and
/// the configuration that would ask for both is never produced (a PID
/// namespace is the guest's, subordinate ids the bare tier's).
#[test]
fn a_subordinate_child_in_its_own_pid_namespace_is_refused() {
    const RUNTIME: u32 = 1001;
    const SUB: u32 = 165_536;
    let ids = SubordinateIds::for_test(SUB, SUB);
    let opt_in = UnsandboxedOptIn::Subordinate(ids);
    let child = ChildConfinement::decide_workload(
        ContainmentMode::Unsandboxed,
        None,
        RUNTIME,
        opt_in,
        LL,
        NO,
    )
    .expect("default workload");
    assert_eq!(child.subordinate(), Some(ids));
    let derived = portcullis::SeccompPolicy::derive(
        &portcullis::PermissionLattice::codegen(),
        portcullis::NetworkEgress::None,
    );
    let rlimits = RlimitPolicy::node_ceiling().at_ceiling();
    let mut cmd = std::process::Command::new("/bin/true");
    assert_eq!(
        child.apply_with_pids(
            &mut cmd,
            rlimits,
            derived,
            &WorkspaceWrites::Writable,
            PidNamespace::Own,
        ),
        SpawnHardening::Unhardened(Unhardened::Refused)
    );
    let err = cmd.status().expect_err("the refused spawn must not exec");
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
    // Control: the same child with the runtime's PID namespace is not refused.
    assert_ne!(
        child.apply_with_pids(
            &mut std::process::Command::new("/bin/true"),
            rlimits,
            derived,
            &WorkspaceWrites::Writable,
            PidNamespace::Shared,
        ),
        SpawnHardening::Unhardened(Unhardened::Refused)
    );
    // No containment mode yields both: the PID namespace is the guest's alone,
    // and the subordinate opt-in reaches only the bare tier.
    for mode in [
        ContainmentMode::Unconfigured,
        ContainmentMode::Unsandboxed,
        ContainmentMode::HostHardened,
        ContainmentMode::MicroVM,
    ] {
        let subordinate = ChildConfinement::decide_workload(mode, None, RUNTIME, opt_in, LL, NO)
            .is_ok_and(|c| c.subordinate().is_some());
        assert!(
            !(subordinate && PidNamespace::for_workload(mode) == PidNamespace::Own),
            "{mode:?}"
        );
    }
}
