//! The realization contract's pure halves: the delegation files, the id
//! checks, the map a child accepts, the ACL encoding, and the decision
//! table a subordinate opt-in produces. The live halves (a real spawn) are
//! `tests/child_subordinate.rs` and the tool-proxy's canary.

use super::*;
use crate::command::ContainmentMode;
use crate::hardening::{
    ChildConfinement, ChildUid, LandlockSupport, LandlockWaiver, MIN_LANDLOCK_ABI, SyscallFilter,
    UnsandboxedOptIn,
};

const RUNTIME: u32 = 1001;
const SUB: u32 = 165_536;

fn helpers() -> MapHelpers {
    MapHelpers {
        uidmap: UIDMAP_HELPERS[0],
        gidmap: GIDMAP_HELPERS[0],
    }
}

#[test]
fn the_runtime_user_is_named_from_passwd() {
    let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                  ubuntu:x:1000:1000::/home/ubuntu:/bin/bash\n\
                  builder:x:1001:1002::/home/builder:/bin/bash\n";
    assert_eq!(user_name(passwd, 1001), Some("builder"));
    assert_eq!(user_name(passwd, 0), Some("root"));
    assert_eq!(user_name(passwd, 4242), None);
    assert_eq!(user_name("broken\n:x:1001:1\n", 1001), None);
}

#[test]
fn a_delegation_is_matched_by_name_or_uid_and_nothing_else() {
    let body = "# comment\n\
                ubuntu:100000:65536\n\
                builder:165536:65536\n\
                1001:300000:10\n\
                builder:400000:0\n\
                builder:abc:10\n\
                builder:500000:10:extra\n\
                \n";
    assert_eq!(
        delegated_ranges(body, "builder", 1001),
        vec![
            IdRange {
                start: 165_536,
                count: 65_536
            },
            IdRange {
                start: 300_000,
                count: 10
            },
        ]
    );
    assert!(delegated_ranges(body, "nobody-here", 4242).is_empty());
    assert!(
        IdRange {
            start: 10,
            count: 2
        }
        .contains(11)
    );
    assert!(
        !IdRange {
            start: 10,
            count: 2
        }
        .contains(12)
    );
    assert!(
        !IdRange {
            start: u32::MAX,
            count: 2
        }
        .contains(0)
    );
}

fn range(uid_start: u32, gid_start: u32, count: u32) -> SubordinateRange {
    let user = Delegation {
        name: "builder".into(),
        uids: vec![IdRange {
            start: uid_start,
            count,
        }],
        gids: vec![IdRange {
            start: gid_start,
            count,
        }],
    };
    SubordinateRange::from_delegation(&user, RUNTIME, helpers()).expect("range")
}

#[test]
fn offsets_pair_uid_and_gid_and_end_at_the_range() {
    let r = range(SUB, SUB + 10, 4);
    let ids = r.ids(FIRST_POD_OFFSET).expect("offset 1");
    assert_eq!((ids.uid(), ids.gid()), (SUB + 1, SUB + 11));
    assert_eq!(r.ids(PROBE_OFFSET).expect("probe").uid(), SUB);
    assert_eq!(r.ids(4), Err(SeparationUnmet::Exhausted { count: 4 }));
    assert_ne!(
        PROBE_OFFSET, FIRST_POD_OFFSET,
        "a pod never shares the probe's id"
    );
}

/// A range that reaches the runtime's own uid, or root, is not subordinate:
/// a child mapped there IS the node, or root.
#[test]
fn an_id_that_is_the_runtime_or_root_is_refused() {
    let r = range(RUNTIME - 1, SUB, 4);
    assert!(r.ids(0).is_ok());
    assert_eq!(
        r.ids(1),
        Err(SeparationUnmet::IdIsNotSubordinate {
            id: RUNTIME,
            runtime: RUNTIME
        })
    );
    assert_eq!(
        range(0, SUB, 4).ids(0),
        Err(SeparationUnmet::IdIsNotSubordinate {
            id: 0,
            runtime: RUNTIME
        })
    );
    assert!(check_ids(SUB, SUB, RUNTIME).is_ok());
    assert!(check_ids(SUB, RUNTIME, RUNTIME).is_err());
}

#[test]
fn an_empty_side_of_the_delegation_is_named() {
    let user = Delegation {
        name: "builder".into(),
        uids: vec![IdRange {
            start: SUB,
            count: 1,
        }],
        gids: Vec::new(),
    };
    assert!(matches!(
        SubordinateRange::from_delegation(&user, RUNTIME, helpers()),
        Err(SeparationUnmet::NoDelegation { file, .. }) if file == SUBGID_FILE
    ));
}

/// The map a child accepts before it execs: exactly `id id 1`. The shape an
/// unprivileged `unshare -r` writes (namespace uid 0 over the caller's own
/// host uid) is the node under another name, and is refused, for every id.
#[test]
fn only_a_one_id_identity_map_of_the_subordinate_id_is_accepted() {
    assert!(map_is_exactly(b"    165536     165536          1\n", SUB));
    assert!(map_is_exactly(b"165536 165536 1", SUB));
    for refused in [
        // namespace uid 0 over the runtime's own host uid: `unshare -r`.
        &b"         0       1001          1\n"[..],
        // namespace uid 0 over the subordinate id: not the shape we wrote.
        b"0 165536 1\n",
        // the runtime's uid, identity-mapped.
        b"1001 1001 1\n",
        // more than one id.
        b"165536 165536 2\n",
        // a second line.
        b"165536 165536 1\n0 1001 1\n",
        b"",
        b"165536 165536",
        b"165536 165536 1 7",
        b"165536 165536 x\n",
        b"99999999999 99999999999 1\n",
    ] {
        assert!(
            !map_is_exactly(refused, SUB),
            "accepted {:?}",
            String::from_utf8_lossy(refused)
        );
    }
    // Whatever id is asked about, namespace uid 0 over the runtime is no
    // separation.
    for id in [0, RUNTIME, SUB] {
        assert!(!map_is_exactly(b"0 1001 1\n", id), "id {id}");
    }
}

/// The ACL the workspace grant writes: version 2, sorted by tag then id, the
/// subordinate ids with the owner's bits, a mask that grants nothing the owner
/// lacks, and on a default ACL the runtime's uid too.
#[test]
fn the_acl_encoding_names_the_subordinate_ids_with_the_owners_bits() {
    fn entries(b: &[u8]) -> Vec<(u16, u16, u32)> {
        assert_eq!(&b[..4], &2u32.to_le_bytes());
        b[4..]
            .chunks(8)
            .map(|c| {
                (
                    u16::from_le_bytes([c[0], c[1]]),
                    u16::from_le_bytes([c[2], c[3]]),
                    u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                )
            })
            .collect()
    }
    let none = u32::MAX;
    assert_eq!(
        entries(&acl::encode(0o640, SUB, SUB + 1, None)),
        vec![
            (0x01, 0o6, none),
            (0x02, 0o6, SUB),
            (0x04, 0o4, none),
            (0x08, 0o6, SUB + 1),
            (0x10, 0o6, none),
            (0x20, 0o0, none),
        ]
    );
    assert_eq!(
        entries(&acl::encode(0o700, SUB, SUB, Some(RUNTIME))),
        vec![
            (0x01, 0o7, none),
            (0x02, 0o7, RUNTIME),
            (0x02, 0o7, SUB),
            (0x04, 0o0, none),
            (0x08, 0o7, SUB),
            (0x10, 0o7, none),
            (0x20, 0o0, none),
        ]
    );
}

const LL: LandlockSupport = LandlockSupport::Abi(MIN_LANDLOCK_ABI);
const NO: LandlockWaiver = LandlockWaiver::Absent;

/// With subordinate ids, the bare tier's `/v1/run` child and default-uid
/// workload are separated (a distinct uid, the denylist, the restriction
/// steps), never at the runtime's uid; an explicit `workload.uid` is honoured
/// only when it is the subordinate uid itself.
#[test]
fn a_subordinate_opt_in_separates_every_bare_tier_child() {
    let ids = SubordinateIds::for_test(SUB, SUB);
    let opt_in = UnsandboxedOptIn::Subordinate(ids);
    let run = ChildConfinement::decide(ContainmentMode::Unsandboxed, RUNTIME, opt_in, LL, NO)
        .expect("run child");
    for child in [
        run,
        ChildConfinement::decide_workload(
            ContainmentMode::Unsandboxed,
            None,
            RUNTIME,
            opt_in,
            LL,
            NO,
        )
        .expect("default workload"),
        ChildConfinement::decide_workload(
            ContainmentMode::Unsandboxed,
            Some(SUB),
            RUNTIME,
            opt_in,
            LL,
            NO,
        )
        .expect("workload asking for the subordinate uid"),
    ] {
        assert_eq!(child.child_uid(), ChildUid::Distinct(SUB));
        assert_eq!(child.subordinate(), Some(ids));
        assert_eq!(child.syscall_filter(), SyscallFilter::WorkloadDenylist);
        assert!(!child.is_unsandboxed());
        assert!(child.restricts());
        assert!(child.closes_inherited_fds());
    }
    // Another explicit uid cannot be honoured by a non-root runtime.
    assert!(
        ChildConfinement::decide_workload(
            ContainmentMode::Unsandboxed,
            Some(SUB + 1),
            RUNTIME,
            opt_in,
            LL,
            NO,
        )
        .is_err()
    );
    // The opt-in reaches only the bare tier: a microVM child of a non-root
    // runtime is still refused, and a root runtime still drops to nobody.
    assert!(ChildConfinement::decide(ContainmentMode::MicroVM, RUNTIME, opt_in, LL, NO).is_err());
    let root = ChildConfinement::decide(ContainmentMode::Unsandboxed, 0, opt_in, LL, NO)
        .expect("root runtime");
    assert_eq!(
        root.child_uid(),
        ChildUid::Distinct(crate::hardening::DEFAULT_CHILD_UID)
    );
    assert_eq!(root.subordinate(), None);
    // Control: the plain opt-in is the shared-uid bare tier it always was.
    let shared = ChildConfinement::decide(
        ContainmentMode::Unsandboxed,
        RUNTIME,
        UnsandboxedOptIn::Explicit,
        LL,
        NO,
    )
    .expect("shared");
    assert_eq!(shared.child_uid(), ChildUid::SharedWithRuntime);
    assert!(shared.is_unsandboxed());
}

/// A subordinate-id child and its own PID namespace (#3344) are not composed:
/// asked for both, the hook refuses the spawn rather than drop either, and
/// the configuration that would ask for both is never produced (a PID
/// namespace is the guest's, subordinate ids the bare tier's).
#[test]
fn a_subordinate_child_in_its_own_pid_namespace_is_refused() {
    use crate::hardening::{
        PidNamespace, RlimitPolicy, SpawnHardening, Unhardened, WorkspaceWrites,
    };
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
