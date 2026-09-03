//! What the launch path needs from the host, as data.
//!
//! # Why a table rather than scattered `if !exists` checks
//!
//! Every requirement here was previously discovered by FAILING at the moment it
//! was used, and each failure named the symptom rather than the cause:
//!
//! * `/dev/vhost-vsock` was not checked anywhere in the node. Without it
//!   Firecracker cannot create the vsock device, so the socket never appears and
//!   the launch died three seconds later with `vsock socket not found at
//!   /path/to/vsock.sock` — a path, for a missing kernel module.
//! * `CAP_NET_ADMIN` was not checked at all. Without it `ip`/`iptables` exit
//!   non-zero somewhere inside `setup_network`, after a partial namespace, a
//!   veth pair, or a bridge already exist.
//!
//! `/dev/kvm` was already checked on the launch path and is folded in here so
//! there is one place that says what a host must provide.
//!
//! # The split that makes this testable
//!
//! [`observe`] does I/O and is not provable. [`unmet`] is pure and total: given
//! what was observed, it says which requirements are missing. All the logic
//! worth testing lives in `unmet`, and it runs on a host with no KVM, no vsock
//! and no capabilities — which is exactly where the tests run.
//!
//! # This is a preflight, not a guarantee
//!
//! A module can be unloaded between the check and the use. The value is turning
//! a late, confusing failure into an early, actionable one; it is not a promise
//! that the operation will succeed.

/// How to observe whether one requirement is satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Probe {
    /// A path that must exist.
    PathExists(&'static str),
    /// A Linux capability that must be in this process's EFFECTIVE set,
    /// identified by its bit number in `/proc/self/status`'s `CapEff`.
    Capability { name: &'static str, bit: u32 },
}

/// One thing the launch path needs from the host.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HostRequirement {
    /// What is missing, in the operator's vocabulary.
    pub what: &'static str,
    pub probe: Probe,
    /// What breaks without it — the consequence, not the mechanism.
    pub because: &'static str,
    /// What to actually do about it.
    pub remedy: &'static str,
}

/// `CAP_NET_ADMIN` is capability 12. Named rather than inlined because a wrong
/// bit here would silently check some other capability and pass.
const CAP_NET_ADMIN: u32 = 12;

/// Everything a pod launch needs.
///
/// `needs_network` gates the networking requirements: a pod with no `network`
/// block never enters `setup_network`, so demanding CAP_NET_ADMIN of it would
/// refuse launches that would have worked.
pub(crate) fn requirements(needs_network: bool) -> Vec<HostRequirement> {
    let mut reqs = vec![
        HostRequirement {
            what: "/dev/kvm",
            probe: Probe::PathExists("/dev/kvm"),
            because: "Firecracker is a KVM-based VMM; without it it does not fall back to \
                      emulation, it refuses to start",
            remedy: "run on a host with KVM, or recreate the VM with nested virtualisation \
                     (nucleus setup --force)",
        },
        HostRequirement {
            what: "/dev/vhost-vsock",
            probe: Probe::PathExists("/dev/vhost-vsock"),
            because: "every pod talks to the host over vsock; without this device Firecracker \
                      cannot create the vsock device and the socket never appears, which \
                      surfaces ~3s later as `vsock socket not found`",
            remedy: "sudo modprobe vhost_vsock  (persist: echo vhost_vsock | sudo tee \
                     /etc/modules-load.d/nucleus.conf)",
        },
    ];
    if needs_network {
        reqs.push(HostRequirement {
            what: "CAP_NET_ADMIN",
            probe: Probe::Capability {
                name: "CAP_NET_ADMIN",
                bit: CAP_NET_ADMIN,
            },
            because: "setup_network creates a network namespace, a veth pair, a bridge and a \
                      tap; without this capability those fail partway, leaving half-built \
                      interfaces behind",
            remedy: "run nucleus-node as root, or grant it CAP_NET_ADMIN \
                     (setcap cap_net_admin+ep /usr/local/bin/nucleus-node)",
        });
    }
    reqs
}

/// Which requirements are not satisfied. Pure and total.
///
/// `satisfied` is the observation, injected so this can be tested on a host that
/// has none of these things.
pub(crate) fn unmet(
    reqs: &[HostRequirement],
    satisfied: impl Fn(&Probe) -> bool,
) -> Vec<HostRequirement> {
    reqs.iter()
        .filter(|r| !satisfied(&r.probe))
        .copied()
        .collect()
}

/// One operator-facing message for everything missing.
///
/// Pure, so the wording is testable. Reports ALL missing requirements rather
/// than the first: a host missing two things should learn both in one run
/// instead of one per attempt.
pub(crate) fn explain(missing: &[HostRequirement]) -> String {
    let mut s = String::from("the host is missing what this pod needs:\n");
    for r in missing {
        s.push_str(&format!(
            "  * {} — {}\n    fix: {}\n",
            r.what, r.because, r.remedy
        ));
    }
    s
}

/// Observe one probe. I/O; the only part that is not testable here.
#[cfg(target_os = "linux")]
pub(crate) fn observe(probe: &Probe) -> bool {
    match probe {
        Probe::PathExists(p) => std::path::Path::new(p).exists(),
        Probe::Capability { bit, .. } => effective_capabilities()
            .map(|caps| caps & (1u64 << bit) != 0)
            .unwrap_or(true), // unreadable /proc: do not invent a failure
    }
}

/// This process's effective capability set, from `/proc/self/status`.
///
/// `None` when the field cannot be read or parsed. The caller treats that as
/// "cannot tell" and does NOT refuse: a preflight that blocks launches because
/// it could not read /proc would be worse than the late failure it replaces.
#[cfg(target_os = "linux")]
fn effective_capabilities() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("CapEff:"))?;
    let hex = line.split_whitespace().nth(1)?;
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_present(_: &Probe) -> bool {
        true
    }
    fn none_present(_: &Probe) -> bool {
        false
    }

    #[test]
    fn a_host_with_everything_has_nothing_unmet() {
        assert!(unmet(&requirements(true), all_present).is_empty());
    }

    /// Non-vacuity for the test above: if `unmet` returned empty for everything,
    /// the first test would pass on a completely broken host.
    #[test]
    fn a_host_with_nothing_is_missing_every_requirement() {
        let reqs = requirements(true);
        assert_eq!(unmet(&reqs, none_present).len(), reqs.len());
        assert!(
            !reqs.is_empty(),
            "an empty requirement set would prove nothing"
        );
    }

    /// A pod with no network block never reaches setup_network, so demanding
    /// CAP_NET_ADMIN of it would refuse a launch that would have worked.
    #[test]
    fn capabilities_are_only_required_when_the_pod_asks_for_networking() {
        let with = requirements(true);
        let without = requirements(false);
        assert!(with.iter().any(|r| r.what == "CAP_NET_ADMIN"));
        assert!(
            !without.iter().any(|r| r.what == "CAP_NET_ADMIN"),
            "a pod with no network block must not be refused for a capability it never uses"
        );
        // The device requirements apply either way.
        for w in ["/dev/kvm", "/dev/vhost-vsock"] {
            assert!(
                without.iter().any(|r| r.what == w),
                "{w} is needed by every pod"
            );
        }
    }

    /// vsock is the one this was written for: it had NO check anywhere in the
    /// node, and its absence surfaced as a missing socket path three seconds
    /// into the launch.
    #[test]
    fn vsock_is_required_and_its_remedy_names_the_module() {
        let reqs = requirements(false);
        let vsock = reqs
            .iter()
            .find(|r| r.what == "/dev/vhost-vsock")
            .expect("every pod needs vsock");
        assert!(vsock.remedy.contains("modprobe vhost_vsock"));
        assert!(
            vsock.remedy.contains("modules-load.d"),
            "a bare modprobe does not survive a reboot"
        );
    }

    /// The message must name every missing thing, not just the first.
    #[test]
    fn the_explanation_lists_all_of_them_with_a_remedy_each() {
        let reqs = requirements(true);
        let missing = unmet(&reqs, none_present);
        let msg = explain(&missing);
        for r in &reqs {
            assert!(msg.contains(r.what), "{} missing from the message", r.what);
            assert!(msg.contains(r.remedy), "no remedy given for {}", r.what);
        }
    }

    /// CAP_NET_ADMIN is bit 12. A wrong constant would silently probe a
    /// different capability and pass on a host that lacks the one that matters.
    #[test]
    fn cap_net_admin_is_bit_twelve() {
        assert_eq!(CAP_NET_ADMIN, 12);
        let reqs = requirements(true);
        let cap = reqs.iter().find(|r| r.what == "CAP_NET_ADMIN").unwrap();
        assert_eq!(
            cap.probe,
            Probe::Capability {
                name: "CAP_NET_ADMIN",
                bit: 12
            }
        );
    }
}
