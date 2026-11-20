//! The syscall classes a pod's children are denied, derived from its lattice
//! (#2907).
//!
//! # Why derive
//!
//! A child confined by the runtime already runs under the workload denylist
//! (`nucleus::hardening`'s seccomp table: vsock, namespaces, ptrace and the
//! rest). That list is the same for every pod. It cannot know that a pod whose
//! policy says `run_bash: never` has no business calling `execve`, or that one
//! with no fetch capability and no egress has no business opening an internet
//! socket: without a policy-derived filter, one exec-capable child buys every
//! syscall the denylist does not name, and the lattice sees none of them.
//!
//! [`SeccompPolicy::derive`] is that missing step, written once and here, where
//! the lattice lives. It is a pure function of the [`PermissionLattice`] and of
//! which address families the pod declares network egress in
//! ([`NetworkEgress`]). The guest
//! compiles the result to BPF and installs it with the denylist, as their
//! union: a derived class adds denials, it never removes one.
//!
//! # The rule
//!
//! | class | denied when |
//! |---|---|
//! | [`SyscallClass::Exec`] | `run_bash` is `never` |
//! | [`SyscallClass::InetSocket`] | `web_fetch` is `never` AND the pod declares no egress ([`NetworkEgress::None`]) |
//! | [`SyscallClass::Inet6Socket`] | `web_fetch` is `never` AND every destination the pod declares is IPv4 ([`NetworkEgress::Ipv4Only`] or less) |
//!
//! The socket classes are one per address family, so a pod is denied each
//! family it declares nothing in: an IPv4 allowlist does not hand the workload
//! `AF_INET6` (#2907). Nothing else is read. `fork` and `clone` are not a class: a process that
//! cannot exec gains nothing by copying itself (the copy runs the same,
//! already-filtered image), threads are `clone`, and `RLIMIT_NPROC` already
//! bounds how many copies there can be.
//!
//! # Monotone
//!
//! A tighter lattice, or less egress, denies a superset:
//! `a ≤ b ∧ e ≤ f ⇒ derive(a, e).at_least_as_tight_as(derive(b, f))`. Each
//! class's condition is a conjunction of "this dimension is at or below a
//! fixed point of its chain", which is downward closed, so the property holds
//! by the shape of the rule. It is checked by a property test below and by the Kani harness
//! `proof_seccomp_policy_monotone` (`src/kani.rs`).
//!
//! # Evidence
//!
//! The fields are private and [`SeccompPolicy::derive`] is the only
//! constructor besides [`SeccompPolicy::from_capabilities`], which it calls:
//! a policy exists only as some lattice's derivation (ADR 0007 C-1). No
//! `Default` (B-1), no `Deserialize`, so it cannot be fabricated from data.

use crate::{CapabilityLattice, CapabilityLevel, PermissionLattice};

/// Which address families a pod declares network egress in: hosts it may
/// reach directly, DNS names pinned for it, or credentialed upstreams (whose
/// guest adapter listens on IPv4 loopback).
///
/// Named cases rather than a `bool` (ADR 0007 A), and no `Default` (B-1): the
/// caller states which one it has. Ordered `None < Ipv4Only < Declared`, the
/// way the lattice orders "less" below "more", so the meet stays a `min`. An
/// IPv6-only declaration is [`Self::Declared`]: it gives back both families,
/// which never denies more than the pod declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkEgress {
    /// Nothing is declared: the pod's network fence denies every destination.
    None,
    /// Every declared destination is IPv4: the workload needs `AF_INET`, and
    /// nothing it may reach is reached over `AF_INET6`.
    Ipv4Only,
    /// Some declared destination is not known to be IPv4 (an IPv6 address,
    /// or a caller that does not narrow): both families.
    Declared,
}

/// A class of syscalls the derived policy can deny. Each class names what it
/// takes away; the guest maps it to syscall numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SyscallClass {
    /// Running a new program: `execve`, and `execveat` on anything but the
    /// one descriptor the runtime starts the child through. Denied when the
    /// lattice says `run_bash: never`.
    Exec,
    /// An `AF_INET` socket. Denied when the lattice says `web_fetch: never`
    /// and the pod declares no egress.
    InetSocket,
    /// An `AF_INET6` socket. Denied when the lattice says `web_fetch: never`
    /// and every destination the pod declares is IPv4, or it declares none:
    /// the family is narrowed to what the pod declares (#2907).
    Inet6Socket,
}

impl SyscallClass {
    /// Every class, in the order the canonical form lists them.
    pub const ALL: [SyscallClass; 3] = [
        SyscallClass::Exec,
        SyscallClass::InetSocket,
        SyscallClass::Inet6Socket,
    ];

    /// The class's name in the canonical form and the receipt.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            SyscallClass::Exec => "exec",
            SyscallClass::InetSocket => "inet_socket",
            SyscallClass::Inet6Socket => "inet6_socket",
        }
    }
}

/// Whether one class is denied. A private two-case enum rather than a `bool`
/// field, so the record reads as what it decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Verdict {
    Denied,
    Allowed,
}

/// The syscall classes one pod's children are denied, derived from its
/// lattice. See the module docs for the rule and why it is monotone.
///
/// Private fields; minted only by [`Self::derive`] (and
/// [`Self::from_capabilities`], the same rule on the capability part alone).
/// `Copy` because it grants nothing: it only takes away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeccompPolicy {
    exec: Verdict,
    inet_socket: Verdict,
    inet6_socket: Verdict,
}

impl SeccompPolicy {
    /// The classes a pod under `lattice`, with `egress`, is denied.
    #[must_use]
    pub fn derive(lattice: &PermissionLattice, egress: NetworkEgress) -> Self {
        Self::from_capabilities(&lattice.capabilities, egress)
    }

    /// The rule itself, on the capability part of the lattice: the only part
    /// it reads. Separate so the Kani harness can reach it without the
    /// lattice's heap-allocated fields.
    #[must_use]
    pub fn from_capabilities(caps: &CapabilityLattice, egress: NetworkEgress) -> Self {
        // Exhaustive, no `_` arm (ADR 0007 B-3): a fourth level does not
        // compile until somebody says what it denies.
        let exec = match caps.run_bash {
            CapabilityLevel::Never => Verdict::Denied,
            CapabilityLevel::LowRisk | CapabilityLevel::Always => Verdict::Allowed,
        };
        let inet_socket = match (caps.web_fetch, egress) {
            (CapabilityLevel::Never, NetworkEgress::None) => Verdict::Denied,
            (CapabilityLevel::Never, NetworkEgress::Ipv4Only | NetworkEgress::Declared)
            | (CapabilityLevel::LowRisk | CapabilityLevel::Always, _) => Verdict::Allowed,
        };
        let inet6_socket = match (caps.web_fetch, egress) {
            (CapabilityLevel::Never, NetworkEgress::None | NetworkEgress::Ipv4Only) => {
                Verdict::Denied
            }
            (CapabilityLevel::Never, NetworkEgress::Declared)
            | (CapabilityLevel::LowRisk | CapabilityLevel::Always, _) => Verdict::Allowed,
        };
        Self {
            exec,
            inet_socket,
            inet6_socket,
        }
    }

    /// Whether `class` is denied.
    #[must_use]
    pub fn denies(&self, class: SyscallClass) -> bool {
        let verdict = match class {
            SyscallClass::Exec => self.exec,
            SyscallClass::InetSocket => self.inet_socket,
            SyscallClass::Inet6Socket => self.inet6_socket,
        };
        match verdict {
            Verdict::Denied => true,
            Verdict::Allowed => false,
        }
    }

    /// The denied classes, in [`SyscallClass::ALL`] order.
    pub fn denied(&self) -> impl Iterator<Item = SyscallClass> + '_ {
        SyscallClass::ALL.into_iter().filter(|c| self.denies(*c))
    }

    /// Whether this policy denies at least every class `other` denies: the
    /// order the derivation is monotone in.
    #[must_use]
    pub fn at_least_as_tight_as(&self, other: &Self) -> bool {
        SyscallClass::ALL
            .into_iter()
            .all(|c| !other.denies(c) || self.denies(c))
    }

    /// The canonical spelling: the denied classes' names joined by `,`, or
    /// `none`. What a receipt's hashed preimage carries.
    #[must_use]
    pub fn canonical(&self) -> String {
        let names: Vec<&str> = self.denied().map(SyscallClass::name).collect();
        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(",")
        }
    }
}

/// Serialized as the list of denied class names. Serialize only: a policy is
/// never read back from data (ADR 0007 C-1).
#[cfg(feature = "serde")]
impl serde::Serialize for SeccompPolicy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(None)?;
        for class in self.denied() {
            seq.serialize_element(class.name())?;
        }
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn level() -> impl Strategy<Value = CapabilityLevel> {
        prop_oneof![
            Just(CapabilityLevel::Never),
            Just(CapabilityLevel::LowRisk),
            Just(CapabilityLevel::Always),
        ]
    }

    fn egress() -> impl Strategy<Value = NetworkEgress> {
        prop_oneof![
            Just(NetworkEgress::None),
            Just(NetworkEgress::Ipv4Only),
            Just(NetworkEgress::Declared)
        ]
    }

    /// Every one of the thirteen core dimensions arbitrary, so the property is
    /// over the whole capability lattice, not only the two fields the rule
    /// reads today.
    fn caps() -> impl Strategy<Value = CapabilityLattice> {
        (
            (
                level(),
                level(),
                level(),
                level(),
                level(),
                level(),
                level(),
            ),
            (level(), level(), level(), level(), level(), level()),
        )
            .prop_map(
                |(
                    (
                        read_files,
                        write_files,
                        edit_files,
                        run_bash,
                        glob_search,
                        grep_search,
                        web_search,
                    ),
                    (web_fetch, git_commit, git_push, create_pr, manage_pods, spawn_agent),
                )| CapabilityLattice {
                    read_files,
                    write_files,
                    edit_files,
                    run_bash,
                    glob_search,
                    grep_search,
                    web_search,
                    web_fetch,
                    git_commit,
                    git_push,
                    create_pr,
                    manage_pods,
                    spawn_agent,
                    extensions: Default::default(),
                },
            )
    }

    proptest! {
        /// #2907 acceptance: `tighter(a, b) ⇒ allowed(a) ⊆ allowed(b)`. `a` is
        /// built as `b ∧ c`, so `a ≤ b` holds by construction rather than by a
        /// filter that could discard every case; the assertion below that
        /// `leq` agrees keeps that honest.
        #[test]
        fn the_derivation_is_monotone(b in caps(), c in caps(), eb in egress(), ec in egress()) {
            let a = b.meet(&c);
            prop_assert!(a.leq(&b));
            let ea = eb.min(ec);
            let tight = SeccompPolicy::from_capabilities(&a, ea);
            let loose = SeccompPolicy::from_capabilities(&b, eb);
            prop_assert!(
                tight.at_least_as_tight_as(&loose),
                "{a:?}/{ea:?} denies {} but {b:?}/{eb:?} denies {}",
                tight.canonical(),
                loose.canonical()
            );
        }

        /// The order is a preorder on policies, and the derivation reads only
        /// the two fields its table names.
        #[test]
        fn only_run_bash_and_web_fetch_matter(a in caps(), b in caps(), e in egress()) {
            let pa = SeccompPolicy::from_capabilities(&a, e);
            prop_assert!(pa.at_least_as_tight_as(&pa));
            let mut b = b;
            b.run_bash = a.run_bash;
            b.web_fetch = a.web_fetch;
            prop_assert_eq!(pa, SeccompPolicy::from_capabilities(&b, e));
        }
    }

    /// The table, row by row, with the boundary on each side.
    #[test]
    fn the_rule_on_its_rows() {
        let with = |run_bash, web_fetch, egress| {
            let caps = CapabilityLattice {
                run_bash,
                web_fetch,
                ..CapabilityLattice::default()
            };
            SeccompPolicy::from_capabilities(&caps, egress).canonical()
        };
        use CapabilityLevel::{Always, LowRisk, Never};
        use NetworkEgress::{Declared, Ipv4Only};
        let none = NetworkEgress::None;
        assert_eq!(with(Never, Never, none), "exec,inet_socket,inet6_socket");
        assert_eq!(with(Never, Never, Ipv4Only), "exec,inet6_socket");
        assert_eq!(with(Never, Never, Declared), "exec");
        assert_eq!(with(Never, LowRisk, none), "exec");
        assert_eq!(with(Never, LowRisk, Ipv4Only), "exec");
        assert_eq!(with(LowRisk, Never, none), "inet_socket,inet6_socket");
        assert_eq!(with(Always, Never, none), "inet_socket,inet6_socket");
        assert_eq!(with(Always, Never, Ipv4Only), "inet6_socket");
        assert_eq!(with(LowRisk, LowRisk, none), "none");
        assert_eq!(with(Always, Always, Declared), "none");
    }

    /// #2907: an IPv4-only declaration narrows the socket classes to its
    /// family. `AF_INET` is given back and `AF_INET6` is not; a declaration
    /// the rule cannot narrow gives both, and the narrowed policy is the
    /// strictly tighter one.
    #[test]
    fn an_ipv4_only_declaration_keeps_the_inet6_family_denied() {
        let caps = CapabilityLattice {
            web_fetch: CapabilityLevel::Never,
            ..CapabilityLattice::default()
        };
        let v4 = SeccompPolicy::from_capabilities(&caps, NetworkEgress::Ipv4Only);
        assert!(!v4.denies(SyscallClass::InetSocket));
        assert!(v4.denies(SyscallClass::Inet6Socket));
        let both = SeccompPolicy::from_capabilities(&caps, NetworkEgress::Declared);
        assert!(!both.denies(SyscallClass::Inet6Socket));
        assert!(v4.at_least_as_tight_as(&both));
        assert!(!both.at_least_as_tight_as(&v4));
    }

    /// The shipped presets the issue names: `read_only` and `untrusted-model`
    /// deny both classes with no egress; `codegen` keeps exec (its whole job is
    /// `cargo test`) and loses the internet socket; `permissive` loses
    /// nothing.
    #[test]
    fn the_shipped_presets() {
        let none = NetworkEgress::None;
        assert_eq!(
            SeccompPolicy::derive(&PermissionLattice::read_only(), none).canonical(),
            "exec,inet_socket,inet6_socket"
        );
        assert_eq!(
            SeccompPolicy::derive(&PermissionLattice::codegen(), none).canonical(),
            "inet_socket,inet6_socket"
        );
        assert_eq!(
            SeccompPolicy::derive(&PermissionLattice::permissive(), none).canonical(),
            "none"
        );
    }

    #[cfg(feature = "spec")]
    #[test]
    fn the_untrusted_model_profile_denies_both_classes() {
        let registry = crate::profile::ProfileRegistry::canonical().expect("canonical profiles");
        let lattice = registry
            .resolve("untrusted-model")
            .expect("untrusted-model is a canonical profile");
        let policy = SeccompPolicy::derive(&lattice, NetworkEgress::None);
        assert!(policy.denies(SyscallClass::Exec));
        assert!(policy.denies(SyscallClass::InetSocket));
        assert!(policy.denies(SyscallClass::Inet6Socket));
        // Declaring egress gives the declared families back, never exec.
        let v4 = SeccompPolicy::derive(&lattice, NetworkEgress::Ipv4Only);
        assert_eq!(v4.canonical(), "exec,inet6_socket");
        let declared = SeccompPolicy::derive(&lattice, NetworkEgress::Declared);
        assert_eq!(declared.canonical(), "exec");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn it_serializes_as_the_denied_class_names() {
        let caps = CapabilityLattice {
            run_bash: CapabilityLevel::Never,
            web_fetch: CapabilityLevel::Never,
            ..CapabilityLattice::default()
        };
        let p = SeccompPolicy::from_capabilities(&caps, NetworkEgress::None);
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"["exec","inet_socket","inet6_socket"]"#
        );
    }
}
