//! A confined child's resource limits as a lattice, bounded by the pod's
//! policy (#2572).
//!
//! Before this module the four limits were constants in the `pre_exec` hook
//! (`NPROC=512`, `NOFILE=4096`, `FSIZE=8 GiB`, `CPU=3600 s`): no policy input,
//! no test, nothing relating them to the pod they bounded. Now:
//!
//! * [`RlimitVector`] is the four limits, ordered pointwise ([`RlimitVector::leq`])
//!   with a pointwise [`RlimitVector::meet`]. Every component is a finite
//!   `u64`; there is no "unlimited" value (ADR 0007 B-2), because the only
//!   ceilings are bounded by [`RlimitVector::NODE_CEILING`].
//! * [`RlimitPolicy`] is the ceiling one pod's spec puts on its children
//!   ([`RlimitPolicy::for_pod`]). It can only lower the node ceiling, never
//!   raise it. No `Default` (B-1): a caller with no pod spec names
//!   [`RlimitPolicy::node_ceiling`].
//! * [`AppliedRlimits`] is the evidence "these limits are ≤ that policy"
//!   (C-1, C-2): private fields, minted only by [`RlimitPolicy::at_ceiling`],
//!   so applied limits exist only as some policy's ceiling and the invariant
//!   holds by construction rather than by a check a caller could skip.
//!   [`crate::ChildConfinement::apply`] takes one by value, so the hook can
//!   only set limits a policy produced; the constants are gone from the hook.
//!
//! # The derivation rule
//!
//! `ResourceSpec` names cores and memory, and the pod names a timeout. The
//! ceiling is the node ceiling met with what those imply:
//!
//! | limit | ceiling |
//! |---|---|
//! | `RLIMIT_CPU` | `min(3600, timeout_seconds × cpu_cores)` when `cpu_cores` is declared, else 3600 |
//! | `RLIMIT_FSIZE` | 8 GiB |
//! | `RLIMIT_NOFILE` | 4096 |
//! | `RLIMIT_NPROC` | 512 |
//!
//! `RLIMIT_CPU` is per process and counts every thread, so a process on
//! `cpu_cores` cores cannot use more than `timeout × cores` CPU-seconds inside
//! the pod's deadline; a larger limit could never bind before the node's
//! reaper does. The rlimit is the kernel-exact backstop of that deadline (the
//! reaper is not exact-time). With no declared core count the node's default
//! size is not known here, so the timeout alone would undercount a
//! multi-threaded child, and the node ceiling applies instead. Zero is lifted
//! to one on both factors: a zero CPU limit kills the child at its first tick.
//!
//! No spec field names a disk size, a descriptor count or a task count, so the
//! other three are the node ceiling. `memory_mib` does not bound `FSIZE`: the
//! workload's scratch is a block device, not memory. When the spec gains a
//! disk size, its derivation belongs in [`RlimitPolicy::for_pod`].
//!
//! A pod cannot raise a limit above the node ceiling. That is an operator's
//! decision about the node, not a field in a pod's spec.

use std::time::Duration;

/// The four limits the confinement hook sets, one value per limit, ordered
/// pointwise. Finite by construction: there is no "unlimited" component.
///
/// A plain value, not evidence: only [`AppliedRlimits`] reaches a child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RlimitVector {
    /// `RLIMIT_NPROC`: tasks the child's real uid may have.
    ///
    /// The kernel counts this per real uid (per user namespace since Linux
    /// 5.14), not per process tree. It is a per-workload bound only because
    /// the child runs under a uid nothing else on the kernel uses — see
    /// `imp::hook_limits` in `hardening.rs` for which paths that holds on.
    pub nproc: u64,
    /// `RLIMIT_NOFILE`: open file descriptors per process.
    pub nofile: u64,
    /// `RLIMIT_FSIZE`: the largest file the process may write, in bytes.
    pub fsize_bytes: u64,
    /// `RLIMIT_CPU`: CPU-seconds per process, all threads counted.
    pub cpu_seconds: u64,
}

impl RlimitVector {
    /// The node ceiling: the four limits every confined child got before
    /// #2572, when they were constants in the hook. Generous but bounded:
    /// they contain abuse without breaking build and test work.
    pub const NODE_CEILING: Self = Self {
        nproc: 512,
        nofile: 4096,
        fsize_bytes: 8 * 1024 * 1024 * 1024,
        cpu_seconds: 3600,
    };

    /// The lattice order: every limit in `self` is at most the same limit in
    /// `other`.
    #[must_use]
    pub fn leq(&self, other: &Self) -> bool {
        // Destructured without `..` (ADR 0007 E-1): a fifth limit does not
        // compile until it is ordered here.
        let Self {
            nproc,
            nofile,
            fsize_bytes,
            cpu_seconds,
        } = *self;
        nproc <= other.nproc
            && nofile <= other.nofile
            && fsize_bytes <= other.fsize_bytes
            && cpu_seconds <= other.cpu_seconds
    }

    /// The greatest lower bound: the tighter of each pair of limits.
    #[must_use]
    pub fn meet(&self, other: &Self) -> Self {
        let Self {
            nproc,
            nofile,
            fsize_bytes,
            cpu_seconds,
        } = *self;
        Self {
            nproc: nproc.min(other.nproc),
            nofile: nofile.min(other.nofile),
            fsize_bytes: fsize_bytes.min(other.fsize_bytes),
            cpu_seconds: cpu_seconds.min(other.cpu_seconds),
        }
    }
}

/// The ceiling a pod's policy puts on its children's limits.
///
/// Private field; minted by [`Self::for_pod`] and [`Self::node_ceiling`],
/// both of which stay at or below [`RlimitVector::NODE_CEILING`]. No
/// `Default` (ADR 0007 B-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RlimitPolicy {
    ceiling: RlimitVector,
}

impl RlimitPolicy {
    /// The node ceiling as a policy, for a caller that has no pod spec to
    /// derive one from (a bare `Executor`, a test). Named rather than a
    /// `Default`, so the caller says it.
    #[must_use]
    pub fn node_ceiling() -> Self {
        Self {
            ceiling: RlimitVector::NODE_CEILING,
        }
    }

    /// The ceiling derived from a pod's `timeout_seconds` and its
    /// `resources.cpu_cores` (`None` when the spec declares no core count).
    /// The rule is in the module docs. `None` is the node's default size,
    /// never "unlimited": it leaves the CPU limit at the node ceiling.
    #[must_use]
    pub fn for_pod(timeout: Duration, cpu_cores: Option<u32>) -> Self {
        let node = RlimitVector::NODE_CEILING;
        let cpu_seconds = match cpu_cores {
            Some(cores) => timeout
                .as_secs()
                .max(1)
                .saturating_mul(u64::from(cores.max(1))),
            None => node.cpu_seconds,
        };
        let derived = RlimitVector {
            nproc: node.nproc,
            nofile: node.nofile,
            fsize_bytes: node.fsize_bytes,
            cpu_seconds,
        };
        Self {
            ceiling: node.meet(&derived),
        }
    }

    /// The ceiling itself.
    #[must_use]
    pub fn ceiling(&self) -> RlimitVector {
        self.ceiling
    }

    /// The limits a child under this policy gets: the policy's ceiling, as
    /// evidence. The ONE constructor of [`AppliedRlimits`].
    #[must_use]
    pub fn at_ceiling(&self) -> AppliedRlimits {
        AppliedRlimits {
            limits: self.ceiling,
        }
    }
}

/// Limits some [`RlimitPolicy`] produced: the evidence that the hook's limits
/// are at or below a policy (ADR 0007 C-1, C-2).
///
/// Private field; minted only by [`RlimitPolicy::at_ceiling`], so the
/// limits a child gets cannot be written down anywhere else — the hook's
/// constants are gone. `Copy` because it grants nothing: it only takes away.
/// No `Default` and no `Deserialize`, so it cannot be fabricated from data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct AppliedRlimits {
    limits: RlimitVector,
}

impl AppliedRlimits {
    /// The limits the hook sets.
    #[must_use]
    pub fn limits(&self) -> RlimitVector {
        self.limits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn vector() -> impl Strategy<Value = RlimitVector> {
        (any::<u64>(), any::<u64>(), any::<u64>(), any::<u64>()).prop_map(
            |(nproc, nofile, fsize_bytes, cpu_seconds)| RlimitVector {
                nproc,
                nofile,
                fsize_bytes,
                cpu_seconds,
            },
        )
    }

    proptest! {
        /// `proof_rlimit_leq_policy` (#2572). Kani is not wired for the
        /// `nucleus` crate (its jobs run portcullis, portcullis-core,
        /// ck-kernel, nucleus-ifc-kernel and nucleus-econ-kernels), so the
        /// invariant is a property test over every timeout and core count a
        /// spec can carry: the limits a child gets are at or below its pod's
        /// policy, and the policy is at or below the node ceiling, so no
        /// spec can raise a limit.
        #[test]
        fn proof_rlimit_leq_policy(secs in any::<u64>(), cores in proptest::option::of(any::<u32>())) {
            let policy = RlimitPolicy::for_pod(Duration::from_secs(secs), cores);
            let applied = policy.at_ceiling().limits();
            prop_assert!(applied.leq(&policy.ceiling()));
            prop_assert!(policy.ceiling().leq(&RlimitVector::NODE_CEILING));
            prop_assert!(applied.cpu_seconds >= 1, "a zero CPU limit kills at the first tick");
        }

        /// `leq` is a partial order and `meet` is its greatest lower bound.
        #[test]
        fn leq_is_a_partial_order_with_meet_as_glb(a in vector(), b in vector(), c in vector()) {
            prop_assert!(a.leq(&a));
            if a.leq(&b) && b.leq(&a) {
                prop_assert_eq!(a, b);
            }
            if a.leq(&b) && b.leq(&c) {
                prop_assert!(a.leq(&c));
            }
            let m = a.meet(&b);
            prop_assert!(m.leq(&a) && m.leq(&b));
            if c.leq(&a) && c.leq(&b) {
                prop_assert!(c.leq(&m));
            }
        }

        /// The derivation is monotone: a shorter timeout or fewer cores never
        /// yields a looser ceiling.
        #[test]
        fn for_pod_is_monotone(s1 in any::<u64>(), s2 in any::<u64>(), c1 in any::<u32>(), c2 in any::<u32>()) {
            let lo = RlimitPolicy::for_pod(Duration::from_secs(s1.min(s2)), Some(c1.min(c2)));
            let hi = RlimitPolicy::for_pod(Duration::from_secs(s1.max(s2)), Some(c1.max(c2)));
            prop_assert!(lo.ceiling().leq(&hi.ceiling()));
        }
    }

    /// The rule, on the numbers: a 60 s pod on two cores gets 120 CPU-seconds;
    /// one with no core count, or a long timeout, gets the node ceiling; a
    /// zero timeout or zero cores still gets one second, not an instant kill.
    #[test]
    fn the_cpu_ceiling_follows_the_timeout_and_cores() {
        let cpu = |secs, cores| {
            RlimitPolicy::for_pod(Duration::from_secs(secs), cores)
                .at_ceiling()
                .limits()
                .cpu_seconds
        };
        assert_eq!(cpu(60, Some(2)), 120);
        assert_eq!(cpu(60, None), 3600);
        assert_eq!(cpu(30 * 24 * 3600, Some(8)), 3600);
        assert_eq!(cpu(0, Some(0)), 1);
        assert_eq!(cpu(u64::MAX, Some(u32::MAX)), 3600);
        let other = RlimitPolicy::for_pod(Duration::from_secs(60), Some(2)).ceiling();
        assert_eq!(
            (other.nproc, other.nofile, other.fsize_bytes),
            (512, 4096, 8 * 1024 * 1024 * 1024),
            "no spec field bounds these, so they are the node ceiling"
        );
    }
}
