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
//! * `nsenter`, `ip`, `iptables`, `iptables-save`, `sysctl` and `dnsmasq` were
//!   each probed by the network code at the moment it first ran them. On a host
//!   without `nsenter` the launch got as far as a running, seccomp-filtered
//!   Firecracker before failing (#3027). They are [`Probe::Command`]s now, and
//!   the network code needs the [`CheckedCommands`] witness to run them.
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

pub mod kvm;

/// How to observe whether one requirement is satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// A path that must exist.
    PathExists(&'static str),
    /// A Linux capability that must be in this process's EFFECTIVE set,
    /// identified by its bit number in `/proc/self/status`'s `CapEff`.
    Capability { name: &'static str, bit: u32 },
    /// A sysfs file whose trimmed contents must be one of `any_of`.
    ///
    /// Unreadable counts as NOT satisfied, which is the opposite polarity to
    /// [`Probe::Capability`] and deliberately so. A capability that cannot be
    /// read must not block a launch that would have worked. A hardening
    /// property that cannot be read must not be reported as present: "could
    /// not tell" and "it is off" are the same answer to an attacker, and
    /// `confinement.rs` already settles this — a control that is green because
    /// nothing could make it red is the defect, not the check.
    SysfsValue {
        path: &'static str,
        any_of: &'static [&'static str],
    },
    /// A program the launch path runs, which must be an executable file on
    /// `PATH` — the same lookup `Command::new` performs when it spawns it.
    Command(HostCommand),
}

/// A host program the launch path runs to build a pod's network.
///
/// A closed set rather than a `&str`, so the node can only ask the preflight's
/// witness ([`CheckedCommands`]) for a program this table knows how to probe
/// and how to tell an operator to install (#3027).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HostCommand {
    /// iproute2's `ip`: namespaces, veth pairs, the bridge, `ip netns exec`.
    Ip,
    /// `iptables`: the default-deny baseline and the egress chain.
    Iptables,
    /// `iptables-save`: the drift monitor's baseline and its comparisons.
    IptablesSave,
    /// `sysctl`: forwarding on the host side of the pod's link.
    Sysctl,
    /// util-linux's `nsenter`: applying the egress chain inside the running
    /// VMM's network namespace.
    Nsenter,
    /// `dnsmasq`: the per-pod resolver, only when the spec has `dns_allow`.
    Dnsmasq,
}

impl HostCommand {
    /// The program name spawned, and looked up on `PATH`.
    pub fn program(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Iptables => "iptables",
            Self::IptablesSave => "iptables-save",
            Self::Sysctl => "sysctl",
            Self::Nsenter => "nsenter",
            Self::Dnsmasq => "dnsmasq",
        }
    }

    /// The requirement this program imposes, with the package that provides it.
    pub fn requirement(self) -> HostRequirement {
        let (because, remedy) = match self {
            Self::Ip => (
                "the pod's network namespace, veth pair and bridge are made with `ip`; without \
                 it the launch fails at the first namespace operation",
                "install iproute2 (apt-get install iproute2 / apk add iproute2)",
            ),
            Self::Iptables => (
                "the default-deny baseline and the egress chain are iptables rules; without it \
                 a namespace exists with no policy applied and the launch fails",
                "install iptables (apt-get install iptables / apk add iptables)",
            ),
            Self::IptablesSave => (
                "the netns drift monitor snapshots the rule set with iptables-save; without it \
                 the launch fails after Firecracker is already running",
                "install iptables, which ships iptables-save (apt-get install iptables / apk add \
                 iptables), or run the node with the netns drift check off",
            ),
            Self::Sysctl => (
                "forwarding on the host side of the pod's link is enabled with sysctl",
                "install procps (apt-get install procps / apk add procps)",
            ),
            Self::Nsenter => (
                "the egress chain is applied inside the running VMM's namespace with nsenter; \
                 without it the launch fails after Firecracker is already running",
                "install util-linux, which ships nsenter (apt-get install util-linux / apk add \
                 util-linux-misc); BusyBox does not provide it",
            ),
            Self::Dnsmasq => (
                "a spec with `dns_allow` gets a per-pod resolver, which is dnsmasq",
                "install dnsmasq (apt-get install dnsmasq / apk add dnsmasq)",
            ),
        };
        HostRequirement {
            what: self.program(),
            probe: Probe::Command(self),
            because,
            remedy,
        }
    }
}

/// Witness that the launch preflight found every command in it on `PATH`.
///
/// Minted only by [`preflight`], after [`unmet`] returned nothing for a
/// requirement set that included each of these commands. The node's network
/// code takes one of these instead of probing for a program at the moment it
/// is used, which is how `nsenter` came to be discovered missing only after a
/// seccomp-filtered Firecracker was already running (#3027).
///
/// [`Self::require`] asks whether a program was DECLARED to the preflight; it
/// does no I/O. A stage that needs a program its plan never declared fails on
/// every host, so the omission is found by the first test or run, not by the
/// first host that lacks the binary. ADR 0007 C-1: the evidence has a private
/// constructor and is minted by the checker. Not one-shot, so `Clone` is fine:
/// the drift monitor keeps using it for the pod's whole life.
#[derive(Debug, Clone)]
pub struct CheckedCommands {
    commands: Vec<HostCommand>,
}

impl CheckedCommands {
    /// `Ok` when every one of `needed` was observed by the preflight.
    pub fn require(&self, needed: &[HostCommand]) -> Result<(), String> {
        let undeclared: Vec<&str> = needed
            .iter()
            .filter(|c| !self.commands.contains(c))
            .map(|c| c.program())
            .collect();
        if undeclared.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "host command(s) {} were never declared to the launch preflight, so nothing \
                 checked they exist before the pod was built; declare them in the plan's host \
                 commands",
                undeclared.join(", ")
            ))
        }
    }
}

/// `program` is an executable regular file in one of `path`'s directories.
///
/// The lookup `Command::new` does when spawning a bare name, minus the spawn.
/// Running `<cmd> --version` instead (the old `ensure_command`) also depended
/// on each tool's flag spelling — BusyBox applets exit 1 for `--version`.
#[cfg(unix)]
pub fn on_path(program: &str, path: Option<&std::ffi::OsStr>) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Some(path) = path else {
        return false;
    };
    std::env::split_paths(path).any(|dir| {
        std::fs::metadata(dir.join(program))
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    })
}

/// One thing the launch path needs from the host.
#[derive(Debug, Clone, Copy)]
pub struct HostRequirement {
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
pub fn requirements(needs_network: bool) -> Vec<HostRequirement> {
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

/// What a host must provide before a snapshot taken on it may be REUSED.
///
/// Separate from [`requirements`] on purpose: none of these is needed to launch a pod, and
/// folding them in would refuse ordinary launches on every unhardened developer machine. They
/// describe whether a base taken here is one another pod should boot from, which is a different
/// question asked at a different moment.
///
/// Sourced from the co-residency analysis. Only the sysfs-readable ones are here — cpuset
/// pinning, CAT/MBA and ECC are defence in depth that this cannot observe, and claiming them
/// would be worse than omitting them.
pub fn sharing_requirements() -> Vec<HostRequirement> {
    vec![
        HostRequirement {
            what: "SMT disabled on the host",
            probe: Probe::SysfsValue {
                path: "/sys/devices/system/cpu/smt/control",
                any_of: &["off", "forceoff", "notsupported", "notimplemented"],
            },
            because: "a sibling hyperthread shares L1 and the store buffer with whatever runs                       beside it, so two pods on one core can observe each other regardless of                       what the guest topology says. `machine_config.smt: false` is GUEST                       topology and does not satisfy this",
            remedy: "echo off | sudo tee /sys/devices/system/cpu/smt/control  (persist:                      nosmt on the host kernel command line)",
        },
        HostRequirement {
            what: "KSM disabled",
            probe: Probe::SysfsValue {
                path: "/sys/kernel/mm/ksm/run",
                any_of: &["0"],
            },
            because: "kernel same-page merging deduplicates identical pages ACROSS tenants                       without anyone declaring it, which turns a write-timing difference into a                       content-discovery oracle — the classic cross-VM memory disclosure",
            remedy: "echo 0 | sudo tee /sys/kernel/mm/ksm/run",
        },
        HostRequirement {
            what: "transparent hugepages not `always`",
            probe: Probe::SysfsValue {
                path: "/sys/kernel/mm/transparent_hugepage/enabled",
                any_of: &["always [madvise] never", "always madvise [never]"],
            },
            because: "a 2 MiB page is a 2 MiB copy-on-write granule; it widens any sharing                       channel and makes a rowhammer target easier to place",
            remedy: "echo madvise | sudo tee /sys/kernel/mm/transparent_hugepage/enabled",
        },
    ]
}

/// Which requirements are not satisfied. Pure and total.
///
/// `satisfied` is the observation, injected so this can be tested on a host that
/// has none of these things.
pub fn unmet(reqs: &[HostRequirement], satisfied: impl Fn(&Probe) -> bool) -> Vec<HostRequirement> {
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
pub fn explain(missing: &[HostRequirement]) -> String {
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
pub fn observe(probe: &Probe) -> bool {
    match probe {
        Probe::PathExists(p) => std::path::Path::new(p).exists(),
        Probe::Capability { bit, .. } => effective_capabilities()
            .map(|caps| 1u64.checked_shl(*bit).is_some_and(|mask| caps & mask != 0))
            .unwrap_or(true), // unreadable /proc: do not invent a failure
        // Unreadable or unexpected: NOT satisfied. See the variant's doc comment for why this
        // is the opposite of the line above.
        Probe::SysfsValue { path, any_of } => {
            sysfs_satisfied(std::fs::read_to_string(path).ok().as_deref(), any_of)
        }
        Probe::Command(c) => on_path(c.program(), std::env::var_os("PATH").as_deref()),
    }
}

/// [`requirements`] plus one requirement per host command the launch will run.
pub fn launch_requirements(needs_network: bool, commands: &[HostCommand]) -> Vec<HostRequirement> {
    let mut reqs = requirements(needs_network);
    let mut commands = commands.to_vec();
    commands.sort();
    commands.dedup();
    reqs.extend(commands.into_iter().map(HostCommand::requirement));
    reqs
}

/// The launch decision, split from the observation so it is testable on a host
/// with none of these things: the witness exactly when nothing is unmet.
///
/// Private on purpose: with `satisfied` injectable, a public version would mint
/// the witness for `|_| true`. Outside this module only [`preflight`] can.
#[cfg(any(target_os = "linux", test))]
fn preflight_with(
    needs_network: bool,
    commands: &[HostCommand],
    satisfied: impl Fn(&Probe) -> bool,
) -> Result<CheckedCommands, String> {
    let missing = unmet(&launch_requirements(needs_network, commands), satisfied);
    if missing.is_empty() {
        Ok(CheckedCommands {
            commands: commands.to_vec(),
        })
    } else {
        Err(explain(&missing))
    }
}

/// The launch preflight: every requirement a pod needs — devices, capability,
/// and each host command the launch will run — observed now, BEFORE anything
/// is built, and one message naming all that are missing. On success, the
/// witness the network code needs to run any of those commands.
#[cfg(target_os = "linux")]
pub fn preflight(needs_network: bool, commands: &[HostCommand]) -> Result<CheckedCommands, String> {
    preflight_with(needs_network, commands, observe)
}

/// Whether a sysfs reading satisfies a requirement. Pure, so the polarity is testable.
///
/// `None` — the file is missing, or unreadable — is NOT satisfied. That is the whole point: this
/// module's other probe treats an unreadable `/proc` as "do not invent a failure", which is right
/// for a capability that gates a launch and wrong for a hardening property. "Could not tell" and
/// "it is off" are the same answer to an attacker.
pub fn sysfs_satisfied(contents: Option<&str>, any_of: &[&str]) -> bool {
    contents.is_some_and(|v| any_of.contains(&v.trim()))
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

    /// A hardening property that cannot be read is NOT satisfied.
    ///
    /// The opposite polarity to `Probe::Capability`, and the difference is the point. An
    /// unreadable capability must not block a launch that would have worked. An unreadable
    /// hardening property must not be reported as present — that is a control green because
    /// nothing could make it red, which `confinement.rs` names as the defect.
    #[test]
    fn a_hardening_property_that_cannot_be_read_is_not_satisfied() {
        assert!(sysfs_satisfied(Some("0"), &["0"]));
        assert!(sysfs_satisfied(Some("off\n"), &["off"]), "trailing newline");
        assert!(sysfs_satisfied(Some("  off  "), &["off"]), "whitespace");
        assert!(!sysfs_satisfied(Some("1"), &["0"]));
        assert!(
            !sysfs_satisfied(None, &["0"]),
            "unreadable must not read as satisfied"
        );
        assert!(
            !sysfs_satisfied(Some(""), &["0"]),
            "an empty file is not a zero"
        );
        // A value nobody anticipated is not satisfied either — allowlist, not denylist.
        assert!(!sysfs_satisfied(Some("something-new"), &["off", "0"]));
    }

    /// The sharing requirements are separate from the launch requirements.
    ///
    /// Folding them together would refuse ordinary launches on every unhardened developer
    /// machine, for a property no launch needs — they describe whether a base taken here is one
    /// another pod should boot from, which is a different question at a different moment.
    #[test]
    fn hardening_requirements_do_not_gate_an_ordinary_launch() {
        let launch: Vec<&str> = requirements(true).iter().map(|r| r.what).collect();
        for r in sharing_requirements() {
            assert!(
                !launch.contains(&r.what),
                "{} must not be required to launch a pod",
                r.what
            );
            assert!(
                matches!(r.probe, Probe::SysfsValue { .. }),
                "{} must be observed, not assumed",
                r.what
            );
            assert!(!r.remedy.is_empty(), "{} needs a remedy", r.what);
        }
        // And an unhardened host is fully unmet rather than partially, so nothing is silently
        // treated as present.
        assert_eq!(
            unmet(&sharing_requirements(), none_present).len(),
            sharing_requirements().len()
        );
    }

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

    /// #3027: a host without `nsenter` is refused by the preflight, before
    /// anything is built, with the package that provides it — not after a
    /// running Firecracker by the network code.
    #[test]
    fn a_host_missing_a_declared_command_is_refused_before_anything_is_built() {
        let commands = [HostCommand::Ip, HostCommand::Iptables, HostCommand::Nsenter];
        let missing_nsenter = |p: &Probe| !matches!(p, Probe::Command(HostCommand::Nsenter));
        let err = preflight_with(true, &commands, missing_nsenter)
            .expect_err("a host without nsenter must not pass the preflight");
        assert!(err.contains("nsenter"), "{err}");
        assert!(
            err.contains("util-linux"),
            "the remedy names the package: {err}"
        );
        assert!(
            !err.contains("  * ip "),
            "only what is missing is listed: {err}"
        );

        // Non-vacuity: the same declaration on a complete host passes and
        // yields a witness for exactly those commands.
        let checked = preflight_with(true, &commands, all_present).expect("complete host");
        assert!(checked.require(&commands).is_ok());
    }

    /// The witness answers for what was DECLARED, not for what a host happens
    /// to have: a stage needing a program its plan never declared is refused on
    /// every host, so the omission cannot hide behind a well-provisioned one.
    #[test]
    fn the_witness_refuses_a_command_the_preflight_never_declared() {
        let checked = preflight_with(true, &[HostCommand::Ip], all_present).expect("passes");
        assert!(checked.require(&[HostCommand::Ip]).is_ok());
        let err = checked
            .require(&[HostCommand::Ip, HostCommand::Nsenter])
            .expect_err("nsenter was never declared");
        assert!(err.contains("nsenter") && !err.contains("ip,"), "{err}");
    }

    /// Every host command has a requirement probed as a command, naming the
    /// program, with a remedy that says how to install it.
    #[test]
    fn every_host_command_is_probed_and_has_an_install_remedy() {
        use HostCommand::*;
        for c in [Ip, Iptables, IptablesSave, Sysctl, Nsenter, Dnsmasq] {
            let r = c.requirement();
            assert_eq!(r.probe, Probe::Command(c));
            assert_eq!(r.what, c.program());
            assert!(r.remedy.contains("install"), "{}: {}", r.what, r.remedy);
        }
        // Declared twice, required once.
        let reqs = launch_requirements(false, &[Ip, Ip]);
        assert_eq!(reqs.iter().filter(|r| r.what == "ip").count(), 1);
    }

    /// The PATH lookup the probe makes: an executable file counts, a
    /// non-executable one and a directory do not, nor does an unset PATH.
    #[cfg(unix)]
    #[test]
    fn on_path_finds_executables_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let exe = dir.path().join("tool-x");
        std::fs::write(&exe, "#!/bin/sh\n").expect("write");
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let plain = dir.path().join("tool-y");
        std::fs::write(&plain, "").expect("write");
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        std::fs::create_dir(dir.path().join("tool-z")).expect("mkdir");

        let path = std::env::join_paths(["/nonexistent-3027", dir.path().to_str().unwrap()])
            .expect("join");
        assert!(on_path("tool-x", Some(&path)));
        assert!(!on_path("tool-y", Some(&path)), "not executable");
        assert!(!on_path("tool-z", Some(&path)), "a directory");
        assert!(!on_path("tool-missing", Some(&path)));
        assert!(!on_path("tool-x", None), "no PATH finds nothing");
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
