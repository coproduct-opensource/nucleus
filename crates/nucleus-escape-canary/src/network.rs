//! Network refusals require independent kernel topology evidence.
//!
//! This measures a fixed guest network namespace, not a firewall or the
//! absence of all possible exfiltration channels. Two snapshots cannot attest
//! that an adversarial privileged actor never changed topology between them.
//! The ordinary gate and its canary must use the same no-NIC guest contract.

#[cfg(any(target_os = "linux", test))]
use crate::Verdict;

/// What the active TCP/UDP/DNS probe observed, without inferring confinement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Connectivity {
    /// A connection or name resolution succeeded.
    Reached,
    /// The probe ran but obtained no connection or DNS answer.
    NotReached,
    /// The probe could not execute or complete its observation.
    CouldNotRun,
}

impl Connectivity {
    /// An errno from a failed Linux socket operation, never a confinement verdict.
    /// Exhaustion, malformed probes and errno-less errors remain unexecuted.
    #[must_use]
    pub fn from_linux_errno(errno: Option<i32>) -> Self {
        match errno {
            Some(1 | 11 | 13 | 101 | 110 | 111 | 113) => Self::NotReached,
            _ => Self::CouldNotRun,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
struct NamespaceId(u64, u64);

#[cfg(any(target_os = "linux", test))]
fn check_interfaces(flags: impl IntoIterator<Item = bool>) -> Result<(), Verdict> {
    let mut observed = false;
    for is_loopback in flags {
        observed = true;
        if !is_loopback {
            return Err(Verdict::CouldNotLook(
                "guest has an external network interface",
            ));
        }
    }
    if observed {
        Ok(())
    } else {
        Err(Verdict::CouldNotLook(
            "kernel returned an empty interface inventory",
        ))
    }
}

#[cfg(any(target_os = "linux", test))]
fn decide(
    before: Result<NamespaceId, Verdict>,
    after: Result<NamespaceId, Verdict>,
    observation: Connectivity,
) -> Verdict {
    match observation {
        Connectivity::Reached => Verdict::Breach,
        Connectivity::CouldNotRun => Verdict::CouldNotLook("network probe did not complete"),
        Connectivity::NotReached => match (before, after) {
            (Ok(a), Ok(b)) if a == b => Verdict::Refused,
            (Ok(_), Ok(_)) => Verdict::CouldNotLook("network namespace changed during probe"),
            (Err(reason), _) | (_, Err(reason)) => reason,
        },
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::MetadataExt;

    // Private constructor: callers cannot turn an errno into topology evidence.
    // Keep the namespace FD alive across the probe so its inode cannot be reused.
    struct LoopbackOnly {
        _namespace: File,
        identity: NamespaceId,
    }
    impl LoopbackOnly {
        fn inspect() -> Result<Self, Verdict> {
            let namespace = File::open("/proc/self/ns/net")
                .map_err(|_| Verdict::CouldNotLook("cannot open network namespace"))?;
            let metadata = namespace
                .metadata()
                .map_err(|_| Verdict::CouldNotLook("cannot identify network namespace"))?;
            let interfaces = nix::ifaddrs::getifaddrs()
                .map_err(|_| Verdict::CouldNotLook("cannot enumerate network interfaces"))?;
            check_interfaces(interfaces.map(|i| {
                i.flags
                    .contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK)
            }))?;
            Ok(Self {
                _namespace: namespace,
                identity: NamespaceId(metadata.dev(), metadata.ino()),
            })
        }
        fn identity(&self) -> NamespaceId {
            NamespaceId(self.identity.0, self.identity.1)
        }
    }

    /// Observe topology before and after an active probe in the same namespace.
    /// This never creates a stronger namespace just for the canary.
    pub fn observe(probe: impl FnOnce() -> Connectivity) -> Verdict {
        let before = LoopbackOnly::inspect();
        let observation = probe();
        let after = LoopbackOnly::inspect();
        let result = decide(
            before
                .as_ref()
                .map(LoopbackOnly::identity)
                .map_err(Clone::clone),
            after
                .as_ref()
                .map(LoopbackOnly::identity)
                .map_err(Clone::clone),
            observation,
        );
        if result == Verdict::Refused {
            eprintln!(
                "network evidence: loopback-only interface inventories in the same namespace before and after the failed probe"
            );
        }
        result
    }
}
#[cfg(target_os = "linux")]
pub use linux::observe;

#[cfg(test)]
mod tests {
    use super::*;
    fn namespace() -> Result<NamespaceId, Verdict> {
        Ok(NamespaceId(1, 2))
    }

    #[test]
    fn errno_never_supplies_topology_evidence() {
        for errno in [1, 11, 13, 101, 110, 111, 113] {
            let observation = Connectivity::from_linux_errno(Some(errno));
            assert_eq!(observation, Connectivity::NotReached);
            assert!(matches!(
                decide(
                    Err(Verdict::CouldNotLook("no topology evidence")),
                    namespace(),
                    observation
                ),
                Verdict::CouldNotLook(_)
            ));
        }
        for errno in [
            None,
            Some(2),
            Some(5),
            Some(12),
            Some(22),
            Some(24),
            Some(97),
        ] {
            assert_eq!(
                Connectivity::from_linux_errno(errno),
                Connectivity::CouldNotRun
            );
        }
    }

    #[test]
    fn empty_unknown_and_external_interfaces_cannot_mint_evidence() {
        assert!(check_interfaces([]).is_err());
        assert!(check_interfaces([true, false]).is_err());
        assert!(check_interfaces([false]).is_err());
        assert!(check_interfaces([true]).is_ok());
        assert!(check_interfaces([true, true]).is_ok());
    }

    #[test]
    fn timeout_with_a_nic_is_not_refusal_but_no_nic_is_independent_evidence() {
        let with_nic = check_interfaces([true, false]).map(|()| NamespaceId(1, 2));
        assert!(matches!(
            decide(with_nic, namespace(), Connectivity::NotReached),
            Verdict::CouldNotLook(_)
        ));
        assert_eq!(
            decide(namespace(), namespace(), Connectivity::NotReached),
            Verdict::Refused
        );
    }

    #[test]
    fn missing_or_changed_snapshots_never_pass() {
        for (before, after) in [
            (
                Err(Verdict::CouldNotLook("inventory unavailable")),
                namespace(),
            ),
            (
                namespace(),
                Err(Verdict::CouldNotLook("inventory unavailable")),
            ),
            (namespace(), Ok(NamespaceId(1, 3))),
        ] {
            assert!(matches!(
                decide(before, after, Connectivity::NotReached),
                Verdict::CouldNotLook(_)
            ));
        }
    }

    #[test]
    fn active_probe_success_dominates_and_unexecuted_probes_remain_blind() {
        assert_eq!(
            decide(namespace(), namespace(), Connectivity::Reached),
            Verdict::Breach
        );
        assert_eq!(
            decide(
                Err(Verdict::CouldNotLook("missing")),
                namespace(),
                Connectivity::Reached
            ),
            Verdict::Breach
        );
        assert!(matches!(
            decide(namespace(), namespace(), Connectivity::CouldNotRun),
            Verdict::CouldNotLook(_)
        ));
    }
}
