//! How a spawned child is confined — the ONE decider and the ONE mechanism
//! (ADR 0007 G-1).
//!
//! Every child the runtime starts goes through [`ChildConfinement`]: the
//! [`Executor`](crate::Executor)'s `/v1/run`-style spawns, and the tool-proxy's
//! pod workload. Before this module there were two hardening hooks — this
//! crate's host-only `HostSandbox` and a private copy in the tool-proxy's
//! `workload.rs` — and they disagreed about the case that mattered: under
//! [`ContainmentMode::MicroVM`] the Executor applied *nothing*, so inside a
//! Firecracker guest, where the tool-proxy is PID 1 and root, every permitted
//! command ran as guest root and could read `/proc/1/environ` (the broker
//! secret, the mediation signing key, the audit credentials) — while the
//! workload beside it had been dropped to an unprivileged uid since FM-5.
//!
//! # Shape (ADR 0007 B, C, D)
//!
//! * [`ChildConfinement`] has a private field and two constructors:
//!   [`ChildConfinement::for_containment`] (the Executor's) and
//!   [`ChildConfinement::workload`] (the tool-proxy workload's). There is no
//!   `Default` (B-1).
//! * Both are exhaustive `match`es on [`ContainmentMode`] with no `_` arm
//!   (B-3, E): `Unconfigured` is refused, and a mode added later does not
//!   compile until somebody says how its children are confined.
//! * The Executor holds no `Option<hook>` it could leave empty: every spawn
//!   site asks `for_containment` and hands the result's [`apply`] to the
//!   sealed spawn home, so a MicroVM spawn without the uid drop has no line of
//!   code that could express it.
//!
//! # Separation is enforced or refused, never assumed (#3120)
//!
//! "This child must not share the runtime's uid" is decided in one private
//! function, `separate`, and it has exactly two outcomes: a uid drop, or a
//! named refusal ([`NucleusError::ChildSeparationUnavailable`],
//! [`NucleusError::ChildSharesRuntimeUid`]). Before #3120 it had a third: a
//! runtime that could not drop (anything but root) quietly ran the child at
//! its own uid with inherited fds closed. The tool-proxy's admission refused a
//! same-uid workload and then the spawn produced one, because the check and
//! the effect were two decisions. The admission now IS this decision: the
//! plan carries the `ChildConfinement` it was admitted with, and the spawn
//! applies that value.
//!
//! The one posture that runs a child at the runtime's uid is the bare host
//! tier, [`ContainmentMode::Unsandboxed`] — an explicit, audited opt-in whose
//! own documentation says the child is a normal host process. A non-root
//! runtime cannot reach that posture by failing to drop; it reaches it only by
//! having declared `Unsandboxed`.
//!
//! # Owner decisions (2026-10-02, #3129)
//!
//! 1. **Every bare execution traces to an explicit opt-in.** Declaring
//!    `Unsandboxed` is not enough for any child -- a `/v1/run` child or a pod
//!    *workload* -- to run at a non-root runtime's uid: the operator must also
//!    pass [`UnsandboxedOptIn::Explicit`] (the tool-proxy's `--unsandboxed`,
//!    which `nucleus run --local`, `nucleus shell` and a node's deliberately
//!    unsandboxed local driver pass). Without it the spawn or admission is
//!    refused with [`NucleusError::UnsandboxedNotOptedIn`]. Both kinds of child
//!    reach that answer through one private rule, `bare`. A log line and a
//!    banner are what the opt-in buys, not a substitute for it.
//! 2. **A root runtime's children are never root.** Whenever the runtime is
//!    root, every child drops to [`DEFAULT_CHILD_UID`] — in every mode,
//!    `HostHardened` and `Unsandboxed` included. `Unsandboxed` then means no
//!    namespace or seccomp confinement, but not root.
//! 3. **An explicit `workload.uid` the runtime cannot honour is refused** by
//!    name, never replaced by the runtime's uid.
//!
//! # What the child gets
//!
//! | Mode | runtime root | runtime not root | syscall filter |
//! |---|---|---|---|
//! | `Unconfigured` | refused | refused | — |
//! | `Unsandboxed`, `/v1/run` child, opted in | drop to 65534 | bare: runtime's uid | none |
//! | `Unsandboxed`, `/v1/run` child, no opt-in | drop to 65534 | **refused** | none |
//! | `Unsandboxed`, workload, no `workload.uid`, opted in | drop to 65534 | bare: runtime's uid | none |
//! | `Unsandboxed`, workload, no `workload.uid`, no opt-in | drop to 65534 | **refused** | none |
//! | `Unsandboxed`, workload, explicit `workload.uid` | drop to it | **refused** | none |
//! | `HostHardened`, `/v1/run` child | drop to 65534 | restricted, runtime's uid | denylist |
//! | `HostHardened`, workload | drop | **refused** | denylist |
//! | `MicroVM` (child or workload) | drop | **refused** | denylist |
//!
//! "Bare" = no fd closing, no `no_new_privs`, no rlimits. "Restricted" = fds
//! above 2 close-on-exec, `no_new_privs`, rlimits ([`AppliedRlimits`], from
//! the pod's [`RlimitPolicy`], #2572), no uid change. "Drop" =
//! restricted, and uid/gid changed first. An explicit `workload.uid` is a
//! request the runtime must honour or refuse; only the unset default may
//! collapse to the bare tier, because only then did nobody ask for a uid.
//!
//! A non-root `HostHardened` `/v1/run` child keeps the runtime's uid: that
//! mode's documented contract is self-restriction (it attests
//! `process: Shared`), and a non-root runtime cannot drop. The tool-proxy
//! never selects it — its containment comes only from `SandboxProof`, which
//! yields `MicroVM` or `Unsandboxed`.
//!
//! # The syscall filter (#2696 P3b)
//!
//! Every posture that confines installs the workload denylist
//! (`hardening/seccomp.rs`): no AF_VSOCK socket, no new namespace, no
//! `clone3` (answered `ENOSYS` so libc falls back to the `clone` the filter
//! can read), no ptrace-class access to a sibling, and no io_uring, bpf, perf,
//! keyring, mount or module calls. The P3 spike (#3148) measured a non-root
//! workload opening AF_VSOCK and creating a user namespace on the guest
//! kernel. The uid drop does not take those away, because every uid has them.
//!
//! Which mode gets it is decided once, by `ChildConfinement::syscall_filter_for`,
//! an exhaustive match. `MicroVM` and `HostHardened` get the denylist.
//! `Unsandboxed` gets none, even when a root runtime drops its uid, because
//! that tier is declared to mean "no namespace or seccomp confinement" (owner
//! decision 2). The program is compiled in the parent and installed by the
//! `pre_exec` hook after the uid drop and `no_new_privs`. A program that
//! cannot be compiled or installed fails the spawn; it is never skipped
//! (ADR 0007 A-1).
//!
//! # The filesystem: Landlock (#2696 P3c)
//!
//! A `MicroVM` child is also held to a Landlock ruleset compiled from the
//! guest layout (`hardening/landlock.rs`, `nucleus_spec::guest_layout`): the
//! image read-only, `/work`, `/tmp` and `/cache` read-write, the pod spec,
//! `/etc/nucleus` and `/run` hidden, only the ordinary devices. Which mode gets
//! it, and what happens on a kernel without it, is decided once, by
//! `ChildConfinement::filesystem_for`:
//!
//! | Mode | kernel at ABI ≥ 2 | kernel below ABI 2 / no Landlock |
//! |---|---|---|
//! | `MicroVM` | enforced | **refused** ([`NucleusError::LandlockUnavailable`]), or [`FilesystemConfinement::Waived`] with [`LandlockWaiver::Explicit`] |
//! | `HostHardened`, `Unsandboxed` | not applied | not applied |
//!
//! Fail closed, not best-effort (#3148): "could not confine" is never "fine"
//! (ADR 0007 A-1). The waiver is the node operator's (`nucleus-node
//! --allow-workload-without-landlock`), reaches the guest as
//! `guest_layout::WORKLOAD_LANDLOCK_WAIVED_ARG`, and is recorded in the
//! workload's launch receipt. `HostHardened` is not given the guest's ruleset
//! because the host's filesystem is not the guest layout; a host ruleset is
//! its own decision, not made here.
//!
//! The ruleset is compiled in the parent and only `landlock_restrict_self`
//! runs in the `pre_exec` hook, after `no_new_privs` and before the syscall
//! filter.
//!
//! [`apply`]: ChildConfinement::apply

use std::path::Path;

use crate::command::ContainmentMode;
use crate::error::{NucleusError, Result};

mod landlock;
mod rlimit;
#[cfg(target_os = "linux")]
mod seccomp;

pub use landlock::{LandlockSupport, MIN_LANDLOCK_ABI};
pub use rlimit::{AppliedRlimits, RlimitPolicy, RlimitVector};

/// The uid a separated child runs as when nothing more specific is
/// configured: `nobody`. A high, unprivileged, non-root value — the guest
/// runtime is root and holds every per-pod secret in its environment, so a
/// child sharing its uid could read them via `/proc/<pid>/environ`.
///
/// The tool-proxy's `DEFAULT_WORKLOAD_UID` is this constant; the guest's
/// seeded workspace and `/cache` are owned by it (`nucleus-guest-init`).
pub const DEFAULT_CHILD_UID: u32 = 65534;

/// How one child process is confined at spawn. See the module docs.
///
/// Private field; minted only by [`Self::for_containment`] and
/// [`Self::workload`]. `Copy` because it is a decision, not an authority: it
/// grants nothing, it only takes away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildConfinement {
    posture: Posture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Posture {
    /// The child is a plain host process at the runtime's uid, and can read
    /// everything the runtime can, its environment included. Reachable ONLY
    /// from `ContainmentMode::Unsandboxed` — never as the fallback of a
    /// separation that could not happen. It carries no filter: a filter needs
    /// `no_new_privs`, which this posture does not set.
    Unsandboxed,
    /// Self-restriction without a uid change (`ContainmentMode::HostHardened`).
    Restricted(SyscallFilter),
    /// Drop to this uid (and gid), then self-restrict.
    DropTo(u32, SyscallFilter, FilesystemConfinement),
}

/// How a confined child's filesystem is held (#2696 P3c). Decided per
/// [`ContainmentMode`] and per kernel in one exhaustive match; see the module
/// docs.
///
/// Three named cases rather than an `Option` (ADR 0007 B-2), no `Default`
/// (B-1), and "the kernel could not" is not a case at all: it is the refusal
/// [`NucleusError::LandlockUnavailable`] unless the operator waived it, and
/// then it is [`Self::Waived`], which says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemConfinement {
    /// The guest layout's Landlock ruleset, enforced at this ABI (at least
    /// [`MIN_LANDLOCK_ABI`]). Failing to compile or apply it fails the spawn.
    Landlock {
        /// The kernel's Landlock ABI.
        abi: u32,
    },
    /// The kernel cannot enforce Landlock at the minimum ABI, and the operator
    /// waived it ([`LandlockWaiver::Explicit`]): the child's filesystem is
    /// held by DAC, the uid drop and nothing else. Recorded, never silent.
    Waived {
        /// What the kernel offered instead.
        kernel: LandlockSupport,
    },
    /// This mode does not hold the filesystem with Landlock: the bare tier,
    /// and `HostHardened`, whose filesystem is the host's, not the guest
    /// layout the ruleset is compiled from.
    NotApplied,
}

impl FilesystemConfinement {
    /// The console verdict the tool-proxy prints for this posture, in the
    /// vocabulary the node parses (`guest_layout::WorkloadLandlockVerdict`).
    #[must_use]
    pub fn verdict(self) -> nucleus_spec::guest_layout::WorkloadLandlockVerdict {
        use nucleus_spec::guest_layout::WorkloadLandlockVerdict as V;
        match self {
            Self::Landlock { abi } => V::Enforced { abi },
            Self::Waived { kernel } => V::Waived {
                kernel: kernel.to_string(),
            },
            Self::NotApplied => V::NotApplied,
        }
    }
}

/// The node operator's explicit acceptance that a guest whose kernel cannot
/// enforce Landlock at [`MIN_LANDLOCK_ABI`] may still run its workload and
/// `/v1/run` children, filesystem-unconfined (#2696 P3c).
///
/// A named two-case type rather than a `bool` (ADR 0007 A), with no `Default`
/// (B-1): the absent case is the refusal. It reaches the tool-proxy only as
/// `--workload-without-landlock`, which guest-init passes when the node put
/// `guest_layout::WORKLOAD_LANDLOCK_WAIVED_ARG` on the kernel command line.
/// It changes nothing on a kernel that has Landlock: the waiver cannot turn an
/// enforceable ruleset off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LandlockWaiver {
    /// No waiver: a kernel without Landlock refuses every `MicroVM` child.
    Absent,
    /// The operator waived Landlock for kernels that lack it.
    Explicit,
}

/// Which syscall filter a confined child installs (#2696 P3b).
///
/// Two named cases rather than an `Option` (ADR 0007 B-2: `None` may not mean
/// "unrestricted"), and no `Default` (B-1). Decided per [`ContainmentMode`] in
/// one exhaustive match; see the module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallFilter {
    /// The workload denylist. It refuses AF_VSOCK sockets, new namespaces,
    /// `clone3` (with `ENOSYS`), ptrace-class calls, io_uring, bpf, perf,
    /// keyrings, mounts and kernel modules. It is installed after the uid drop
    /// and `no_new_privs`, and failing to install it fails the spawn.
    WorkloadDenylist,
    /// No filter: the declared bare tier, `ContainmentMode::Unsandboxed`,
    /// whose contract is "no namespace or seccomp confinement".
    Unfiltered,
}

/// The operator's explicit acceptance that a child -- a `/v1/run` command or
/// a pod workload -- may run as a non-root runtime's own uid on the bare host
/// tier (owner decision 1, 2026-10-02).
///
/// A named two-case type rather than a `bool` (ADR 0007 A): the absent case
/// is the refusal, and nothing defaults to the other one — there is no
/// `Default` (B-1). It reaches [`ChildConfinement::for_containment`] and
/// [`ChildConfinement::workload`] only from the tool-proxy's `--unsandboxed`
/// flag (or the Executor's own `allow_unsandboxed_local`); it grants nothing
/// to a root runtime (which drops anyway) or to a mode other than
/// `Unsandboxed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsandboxedOptIn {
    /// No opt-in: a child that would share the runtime's uid is refused with
    /// [`NucleusError::UnsandboxedNotOptedIn`].
    Absent,
    /// The operator passed `--unsandboxed`: under
    /// `ContainmentMode::Unsandboxed` on a non-root runtime, `/v1/run`
    /// children and a default-uid workload run at the runtime's uid,
    /// announced by a log line and a banner.
    Explicit,
}

/// Who the child runs as, relative to the runtime. Two-valued on purpose: a
/// confinement either changes the uid or it does not, and there is no third
/// state now that "wanted to, could not" is a refusal rather than a posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildUid {
    /// A uid that is not the runtime's.
    Distinct(u32),
    /// The runtime's own uid: the child can read the runtime's environment.
    SharedWithRuntime,
}

impl ChildConfinement {
    /// The confinement an [`Executor`](crate::Executor) under `mode` gives
    /// every child it spawns.
    ///
    /// # Errors
    /// * [`NucleusError::IsolationNotConfigured`] for
    ///   [`ContainmentMode::Unconfigured`] — no posture, no spawn.
    /// * [`NucleusError::ChildSeparationUnavailable`] for
    ///   [`ContainmentMode::MicroVM`] when the runtime is not root.
    /// * [`NucleusError::UnsandboxedNotOptedIn`] for
    ///   [`ContainmentMode::Unsandboxed`] on a non-root runtime without
    ///   [`UnsandboxedOptIn::Explicit`].
    ///
    /// * [`NucleusError::LandlockUnavailable`] for [`ContainmentMode::MicroVM`]
    ///   on a kernel below [`MIN_LANDLOCK_ABI`] without
    ///   [`LandlockWaiver::Explicit`].
    ///
    /// A root runtime's child drops to [`DEFAULT_CHILD_UID`] in every mode
    /// (owner decision 2), so it needs no opt-in.
    pub fn for_containment(
        mode: ContainmentMode,
        opt_in: UnsandboxedOptIn,
        landlock: LandlockWaiver,
    ) -> Result<Self> {
        Self::decide(
            mode,
            runtime_uid(),
            opt_in,
            LandlockSupport::probe(),
            landlock,
        )
    }

    /// The decision itself, with the runtime's uid and the kernel's Landlock
    /// support as inputs so the root and no-Landlock cases are testable
    /// anywhere.
    pub(crate) fn decide(
        mode: ContainmentMode,
        runtime_uid: u32,
        opt_in: UnsandboxedOptIn,
        kernel: LandlockSupport,
        landlock: LandlockWaiver,
    ) -> Result<Self> {
        let syscalls = Self::syscall_filter_for(mode)?;
        let filesystem = || Self::filesystem_for(mode, kernel, landlock);
        // Exhaustive and `_`-free on purpose (ADR 0007 B-3): a new mode does
        // not compile until its children's confinement is written here.
        match mode {
            ContainmentMode::Unconfigured => Err(NucleusError::IsolationNotConfigured),
            // Owner decision 2 (2026-10-02): a root runtime's child is never
            // root, whatever the mode. The bare tier still means "no
            // namespace or seccomp confinement" (its `syscalls` is
            // `Unfiltered`), but a root runtime can always drop, so it does.
            ContainmentMode::Unsandboxed | ContainmentMode::HostHardened if runtime_uid == 0 => {
                Self::separate(DEFAULT_CHILD_UID, runtime_uid, syscalls, filesystem)
            }
            ContainmentMode::Unsandboxed => Self::bare(runtime_uid, opt_in),
            ContainmentMode::HostHardened => Ok(Self {
                posture: Posture::Restricted(syscalls),
            }),
            // The VM is the boundary against the HOST; inside it, the
            // tool-proxy is PID 1 and root, and holds every pod secret. A
            // command it runs for the agent is separated from it exactly as
            // the workload is — or not run.
            ContainmentMode::MicroVM => {
                Self::separate(DEFAULT_CHILD_UID, runtime_uid, syscalls, filesystem)
            }
        }
    }

    /// The ONE answer to "which syscall filter do this mode's children get"
    /// (ADR 0007 G-1), for the `/v1/run` child and the workload alike.
    /// Exhaustive with no `_` arm (B-3, E): a new mode does not compile until
    /// its filter is stated here.
    fn syscall_filter_for(mode: ContainmentMode) -> Result<SyscallFilter> {
        match mode {
            ContainmentMode::Unconfigured => Err(NucleusError::IsolationNotConfigured),
            // The declared bare tier. "No namespace or seccomp confinement"
            // is its documented contract (owner decision 2), and a non-root
            // child here sets no `no_new_privs`, without which the kernel
            // would refuse the filter anyway. A root runtime still drops the
            // uid but adds no filter: the operator opted in to this tier's
            // stated meaning, and the mode attests nothing about syscalls.
            ContainmentMode::Unsandboxed => Ok(SyscallFilter::Unfiltered),
            // Self-restriction on a Linux host: the filter is the syscall
            // half of what this mode attests ("reduces syscall surface").
            ContainmentMode::HostHardened => Ok(SyscallFilter::WorkloadDenylist),
            // The guest, where the exposure was measured (#3148). Every child
            // of the root tool-proxy gets it: the workload and `/v1/run`.
            ContainmentMode::MicroVM => Ok(SyscallFilter::WorkloadDenylist),
        }
    }

    /// The confinement of a pod workload under `mode` that asked for
    /// `requested` (`workload.uid`; `None` = the default,
    /// [`DEFAULT_CHILD_UID`]), with the operator's `opt_in` to the bare tier.
    ///
    /// This is the workload's ADMISSION, not only its spawn: the tool-proxy
    /// admits a workload by obtaining this value and spawns by applying it,
    /// so what was checked and what is enforced are one value (#3120).
    ///
    /// # Errors
    /// * [`NucleusError::IsolationNotConfigured`] for `Unconfigured`.
    /// * [`NucleusError::ChildSharesRuntimeUid`] when the uid asked for is
    ///   the runtime's own.
    /// * [`NucleusError::ChildSeparationUnavailable`] when separation is
    ///   required and the runtime cannot drop: every mode but `Unsandboxed`,
    ///   and `Unsandboxed` with an explicit `workload.uid`.
    /// * [`NucleusError::UnsandboxedNotOptedIn`] for the bare tier
    ///   (`Unsandboxed`, default uid, non-root runtime) without
    ///   [`UnsandboxedOptIn::Explicit`].
    /// * [`NucleusError::LandlockUnavailable`] under `MicroVM` on a kernel
    ///   below [`MIN_LANDLOCK_ABI`] without [`LandlockWaiver::Explicit`].
    pub fn workload(
        mode: ContainmentMode,
        requested: Option<u32>,
        opt_in: UnsandboxedOptIn,
        landlock: LandlockWaiver,
    ) -> Result<Self> {
        Self::decide_workload(
            mode,
            requested,
            runtime_uid(),
            opt_in,
            LandlockSupport::probe(),
            landlock,
        )
    }

    pub(crate) fn decide_workload(
        mode: ContainmentMode,
        requested: Option<u32>,
        runtime_uid: u32,
        opt_in: UnsandboxedOptIn,
        kernel: LandlockSupport,
        landlock: LandlockWaiver,
    ) -> Result<Self> {
        let uid = requested.unwrap_or(DEFAULT_CHILD_UID);
        let syscalls = Self::syscall_filter_for(mode)?;
        let filesystem = || Self::filesystem_for(mode, kernel, landlock);
        match mode {
            ContainmentMode::Unconfigured => Err(NucleusError::IsolationNotConfigured),
            // The bare host tier, declared. A root runtime still drops (a
            // stronger posture costs nothing); a non-root one cannot, and
            // the workload runs as a plain host process — which is what
            // `Unsandboxed` means. Only when no uid was asked for: an
            // explicit `workload.uid` the runtime cannot honour is refused
            // rather than silently replaced by the runtime's. And only on the
            // operator's explicit opt-in (owner decision 1): declaring the
            // mode is not, by itself, consent to a same-uid workload.
            ContainmentMode::Unsandboxed => match requested {
                None if runtime_uid != 0 => Self::bare(runtime_uid, opt_in),
                None | Some(_) => Self::separate(uid, runtime_uid, syscalls, filesystem),
            },
            ContainmentMode::HostHardened | ContainmentMode::MicroVM => {
                Self::separate(uid, runtime_uid, syscalls, filesystem)
            }
        }
    }

    /// The bare host tier -- a child at a non-root runtime's own uid -- and
    /// the ONE place it is granted, for the `/v1/run` child and the workload
    /// alike: only on the operator's explicit opt-in (owner decision,
    /// 2026-10-02). Declaring `Unsandboxed` alone is a named refusal.
    fn bare(runtime_uid: u32, opt_in: UnsandboxedOptIn) -> Result<Self> {
        match opt_in {
            UnsandboxedOptIn::Explicit => Ok(Self {
                posture: Posture::Unsandboxed,
            }),
            UnsandboxedOptIn::Absent => Err(NucleusError::UnsandboxedNotOptedIn { runtime_uid }),
        }
    }

    /// "This child must not share the runtime's authority" — the one rule the
    /// workload and the MicroVM `/v1/run` child share. A drop, or a named
    /// refusal; there is no third outcome.
    ///
    /// The filesystem is decided only once the uid boundary holds, so a
    /// runtime that cannot drop is refused for THAT, by name, whatever its
    /// kernel offers.
    fn separate(
        uid: u32,
        runtime_uid: u32,
        syscalls: SyscallFilter,
        filesystem: impl FnOnce() -> Result<FilesystemConfinement>,
    ) -> Result<Self> {
        if uid == runtime_uid {
            Err(NucleusError::ChildSharesRuntimeUid { uid })
        } else if runtime_uid != 0 {
            Err(NucleusError::ChildSeparationUnavailable {
                runtime_uid,
                child_uid: uid,
            })
        } else {
            Ok(Self {
                posture: Posture::DropTo(uid, syscalls, filesystem()?),
            })
        }
    }

    /// The ONE answer to "how is this mode's children's filesystem held"
    /// (#2696 P3c, ADR 0007 G-1), for the workload and the `/v1/run` child
    /// alike. Exhaustive with no `_` arm (B-3, E).
    ///
    /// `MicroVM` enforces the guest layout's Landlock ruleset, or refuses:
    /// below [`MIN_LANDLOCK_ABI`] the child does not start unless the operator
    /// waived it, and a waiver is a named posture, not a silent skip (A-1).
    fn filesystem_for(
        mode: ContainmentMode,
        kernel: LandlockSupport,
        landlock: LandlockWaiver,
    ) -> Result<FilesystemConfinement> {
        match mode {
            ContainmentMode::Unconfigured => Err(NucleusError::IsolationNotConfigured),
            // The bare tier attests nothing about confinement; `HostHardened`
            // runs on the host, whose filesystem is not the guest layout the
            // ruleset is compiled from.
            ContainmentMode::Unsandboxed | ContainmentMode::HostHardened => {
                Ok(FilesystemConfinement::NotApplied)
            }
            ContainmentMode::MicroVM => match (kernel.enforceable(), landlock) {
                (Some(abi), LandlockWaiver::Absent | LandlockWaiver::Explicit) => {
                    Ok(FilesystemConfinement::Landlock { abi })
                }
                (None, LandlockWaiver::Explicit) => Ok(FilesystemConfinement::Waived { kernel }),
                (None, LandlockWaiver::Absent) => Err(NucleusError::LandlockUnavailable {
                    kernel: kernel.to_string(),
                    minimum: MIN_LANDLOCK_ABI,
                }),
            },
        }
    }

    /// Who the child runs as, relative to the runtime.
    #[must_use]
    pub fn child_uid(&self) -> ChildUid {
        match self.posture {
            Posture::DropTo(uid, ..) => ChildUid::Distinct(uid),
            Posture::Unsandboxed | Posture::Restricted(_) => ChildUid::SharedWithRuntime,
        }
    }

    /// The syscall filter the child installs.
    #[must_use]
    pub fn syscall_filter(&self) -> SyscallFilter {
        match self.posture {
            Posture::Unsandboxed => SyscallFilter::Unfiltered,
            Posture::Restricted(filter) | Posture::DropTo(_, filter, _) => filter,
        }
    }

    /// How the child's filesystem is held (#2696 P3c).
    #[must_use]
    pub fn filesystem(&self) -> FilesystemConfinement {
        match self.posture {
            Posture::DropTo(_, _, fs) => fs,
            Posture::Unsandboxed | Posture::Restricted(_) => FilesystemConfinement::NotApplied,
        }
    }

    /// Compile this child's Landlock ruleset NOW, in the parent, and name
    /// what stopped it (#2696 P3c). A spawn site calls this before the spawn,
    /// so an operator sees [`NucleusError::LandlockRuleset`] with the path
    /// and the reason, not the bare errno the `pre_exec` hook can carry back.
    /// The hook still refuses on its own if the compile fails there: this is
    /// the naming, not the enforcement.
    ///
    /// # Errors
    /// [`NucleusError::LandlockRuleset`] under
    /// [`FilesystemConfinement::Landlock`] when the ruleset cannot be compiled.
    pub fn preflight_filesystem(&self) -> Result<()> {
        match self.filesystem() {
            FilesystemConfinement::Landlock { abi } => landlock::Ruleset::compile(abi)
                .map(drop)
                .map_err(|e| NucleusError::LandlockRuleset {
                    path: e.path.display().to_string(),
                    error: e.error,
                }),
            FilesystemConfinement::Waived { .. } | FilesystemConfinement::NotApplied => Ok(()),
        }
    }

    /// The uid the child will run as, when it is not the runtime's.
    #[must_use]
    pub fn drop_uid(&self) -> Option<u32> {
        match self.child_uid() {
            ChildUid::Distinct(uid) => Some(uid),
            ChildUid::SharedWithRuntime => None,
        }
    }

    /// Whether this is the bare host tier: the declared `Unsandboxed`
    /// posture, the one in which a child reads the runtime's environment.
    /// Callers print the banner off this.
    #[must_use]
    pub fn is_unsandboxed(&self) -> bool {
        match self.posture {
            Posture::Unsandboxed => true,
            Posture::Restricted(_) | Posture::DropTo(..) => false,
        }
    }

    /// Whether the child sets `no_new_privs` and the resource limits.
    #[must_use]
    pub fn restricts(&self) -> bool {
        match self.posture {
            Posture::Restricted(_) | Posture::DropTo(..) => true,
            Posture::Unsandboxed => false,
        }
    }

    /// Whether inherited descriptors above stdio are closed at exec.
    #[must_use]
    pub fn closes_inherited_fds(&self) -> bool {
        match self.posture {
            Posture::Restricted(_) | Posture::DropTo(..) => true,
            Posture::Unsandboxed => false,
        }
    }

    /// Declare this confinement on a command about to be spawned.
    ///
    /// The uid/gid drop is DECLARED on the command rather than done in the
    /// hook, because std applies it in the right window: `do_exec` runs
    /// setgid, the supplementary-group drop (`setgroups(0, NULL)`, automatic
    /// when a uid is set, the parent is root and no groups were given) and
    /// setuid BEFORE `chdir` and BEFORE any `pre_exec` closure. A hook that
    /// tried `setgroups` itself would run as the already-dropped uid and get
    /// `EPERM` — the run-5 boot found that the hard way.
    ///
    /// Because `chdir` follows the drop, the child's working directory must be
    /// traversable by the dropped uid; [`Self::hand_over`] is the ergonomic
    /// half of that.
    ///
    /// The syscall filter, when this confinement has one, is compiled HERE,
    /// in the parent, and moved into the hook. The child only hands it to
    /// `prctl`, after the uid drop and `no_new_privs`. A filter that cannot be
    /// compiled or installed fails the spawn (`Unsupported`, or the kernel's
    /// errno); it is never skipped.
    ///
    /// The Landlock ruleset, under [`FilesystemConfinement::Landlock`], is
    /// compiled here too, and the hook calls `landlock_restrict_self` after
    /// `no_new_privs` and before the syscall filter. A ruleset that cannot be
    /// compiled or applied fails the spawn the same way.
    /// The resource limits are `rlimits`, taken by value: only a
    /// [`RlimitPolicy`] mints them, so the hook sets limits at or below the
    /// pod's policy and nothing else (#2572). They are converted to plain
    /// scalars here, before the fork.
    ///
    /// Returns what the child will get, for the launch receipt: a
    /// [`SpawnHardening::Hardened`] only this method can mint, and only when
    /// it installed the hook.
    ///
    /// For a `tokio::process::Command`, pass `cmd.as_std_mut()`.
    pub fn apply(
        &self,
        cmd: &mut std::process::Command,
        rlimits: AppliedRlimits,
    ) -> SpawnHardening {
        match self.posture {
            Posture::Unsandboxed => SpawnHardening::Unhardened(Unhardened::DeclaredBareTier),
            Posture::Restricted(filter) => {
                Self::restrict(cmd, filter, FilesystemConfinement::NotApplied, rlimits)
            }
            Posture::DropTo(uid, filter, filesystem) => {
                imp::drop_to(cmd, uid);
                Self::restrict(cmd, filter, filesystem, rlimits)
            }
        }
    }

    /// Install the self-restriction hook and say what it does. The ONE place a
    /// [`Hardened`] is minted.
    fn restrict(
        cmd: &mut std::process::Command,
        filter: SyscallFilter,
        filesystem: FilesystemConfinement,
        rlimits: AppliedRlimits,
    ) -> SpawnHardening {
        match imp::install(cmd, filter, filesystem, rlimits) {
            Hook::Installed => SpawnHardening::Hardened(Hardened { rlimits }),
            Hook::NoneOnThisPlatform => {
                SpawnHardening::Unhardened(Unhardened::NoHookOnThisPlatform)
            }
        }
    }

    /// Give `path` to the child's uid (non-recursive), so a dropped child can
    /// enter and write its working directory. A no-op unless this confinement
    /// drops.
    ///
    /// An ergonomic aid, not the security control — the uid drop is. Callers
    /// treat failure as non-fatal: it legitimately fails on a read-only
    /// scratch, where the child could not write regardless.
    ///
    /// # Errors
    /// The `chown` failure, for the caller to log.
    pub fn hand_over(&self, path: &Path) -> std::io::Result<()> {
        match self.drop_uid() {
            Some(uid) => imp::chown(path, uid),
            None => Ok(()),
        }
    }
}

/// What a spawn's confinement hook does to the child, as its launch receipt
/// states it (#2572).
///
/// The hardened case carries a [`Hardened`], which has a private field and is
/// minted only by [`ChildConfinement::apply`] when it installed the hook, so
/// the bare tier — or a platform with no hook — cannot claim it. Before this,
/// the receipt carried a `bool` the caller computed beside the spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SpawnHardening {
    /// Inherited fds above 2 close-on-exec, `no_new_privs`, the rlimits,
    /// and the syscall filter when the posture has one.
    Hardened(Hardened),
    /// No hook: the child is a plain process, and why.
    Unhardened(Unhardened),
}

impl SpawnHardening {
    /// Whether the hook was installed.
    #[must_use]
    pub fn is_hardened(&self) -> bool {
        match self {
            Self::Hardened(_) => true,
            Self::Unhardened(_) => false,
        }
    }
}

/// The evidence that the confinement hook was installed, and with which
/// limits. Private field: only [`ChildConfinement::apply`] mints one (ADR
/// 0007 C-1, C-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Hardened {
    rlimits: AppliedRlimits,
}

impl Hardened {
    /// The limits the hook sets.
    #[must_use]
    pub fn rlimits(&self) -> AppliedRlimits {
        self.rlimits
    }
}

/// Why a spawn has no confinement hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Unhardened {
    /// The declared bare host tier (`ContainmentMode::Unsandboxed` on a
    /// non-root runtime, explicitly opted in).
    DeclaredBareTier,
    /// A posture without a syscall filter on a platform that has no hook
    /// (a root runtime's `Unsandboxed` child off Linux): the uid drop
    /// happens, nothing else does.
    NoHookOnThisPlatform,
}

/// Whether `imp::install` put a hook on the command. Each platform's `imp`
/// returns one of the two, so the other is dead there.
enum Hook {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Installed,
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    NoneOnThisPlatform,
}

/// The runtime's own uid.
///
/// Read through `std` (the owner of `/proc/self`) so this needs neither
/// `unsafe` nor a new dependency. Where there is no procfs it falls back to
/// the owner of the working directory, and failing both, `u32::MAX`.
///
/// Both directions of a wrong answer fail closed. Reading a root runtime as
/// non-root makes every separated spawn a
/// [`NucleusError::ChildSeparationUnavailable`] refusal; reading a non-root
/// runtime as root declares a uid change the kernel then refuses (`EPERM`),
/// so the spawn fails. Neither runs a separated child at the runtime's uid.
#[must_use]
pub fn runtime_uid() -> u32 {
    imp::runtime_uid()
}

#[cfg(unix)]
mod uid {
    use std::os::unix::process::CommandExt;
    use std::path::Path;

    pub(super) fn drop_to(cmd: &mut std::process::Command, uid: u32) {
        // gid alongside uid, so the child does not keep root's primary gid.
        cmd.uid(uid);
        cmd.gid(uid);
    }

    pub(super) fn chown(path: &Path, uid: u32) -> std::io::Result<()> {
        std::os::unix::fs::chown(path, Some(uid), Some(uid))
    }

    pub(super) fn runtime_uid() -> u32 {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self")
            .or_else(|_| std::fs::metadata("."))
            .map(|m| m.uid())
            // Neither stat-able: say "not root", the answer that cannot drop
            // and so cannot be wrong in the dangerous direction.
            .unwrap_or(u32::MAX)
    }
}

// The crate denies `unsafe_code` globally. This module and `imp` (Linux) are
// the audited exceptions, with one `unsafe` block each: the hook install here,
// and the child-side syscall sequence there.
#[cfg(unix)]
#[allow(unsafe_code)]
mod hook {
    use std::os::unix::process::CommandExt;

    /// The ONE place this module installs a `pre_exec` hook.
    ///
    /// Contract, which every caller in this file honours: `hook` runs in the
    /// forked child before exec, so it must be async-signal-safe: raw
    /// syscalls only, no allocation, no locks. Its callers are
    /// `imp::harden_child` (Linux) and the non-Linux refusal, which returns a
    /// constant error.
    pub(super) fn pre_exec<F>(cmd: &mut std::process::Command, hook: F)
    where
        F: FnMut() -> std::io::Result<()> + Send + Sync + 'static,
    {
        // SAFETY: per the contract above, `hook` performs only
        // async-signal-safe syscalls and does not allocate.
        unsafe {
            cmd.pre_exec(hook);
        }
    }
}

#[cfg(target_os = "linux")]
// The crate denies `unsafe_code` globally; this module is an audited
// exception. Child-side hardening is intrinsically `unsafe` FFI: it calls
// `close_range`/`prctl`/`setrlimit`, which must be async-signal-safe. One
// `unsafe` block: the syscall sequence. The hook install is `hook::pre_exec`.
#[allow(unsafe_code)]
mod imp {
    use std::io;

    use super::landlock::Ruleset;
    use super::seccomp::Program;
    pub(super) use super::uid::{chown, drop_to, runtime_uid};
    use super::{AppliedRlimits, FilesystemConfinement, Hook, RlimitVector, SyscallFilter};

    // `setrlimit` takes `__rlimit_resource_t` on glibc but plain `c_int` on
    // musl (the guest rootfs).
    #[cfg(target_env = "gnu")]
    type RlimitResource = libc::__rlimit_resource_t;
    #[cfg(not(target_env = "gnu"))]
    type RlimitResource = libc::c_int;

    /// The limits as the hook sets them: plain scalars, computed in the parent
    /// so the child neither decides nor allocates.
    type HookLimits = [(RlimitResource, libc::rlim_t); 4];

    /// The four `setrlimit` calls `applied` asks for. Each `u64` is assigned
    /// to `rlim_t` without a conversion, which compiles only where `rlim_t` is
    /// 64 bits (every target the runtime ships); a narrower `rlim_t` would be
    /// a compile error, never a truncation to `RLIM_INFINITY`.
    ///
    /// `RLIMIT_NPROC` counts tasks per REAL UID (per user namespace since
    /// Linux 5.14), not per process tree. It bounds one workload only because
    /// the uid is that workload's alone, and that holds on one path:
    /// * In a microVM guest every child of the tool-proxy (the workload and
    ///   every `/v1/run` command) drops to `DEFAULT_CHILD_UID`, and the guest
    ///   kernel runs one pod, so the bound is per pod. The syscall filter
    ///   refuses new user namespaces, so the child cannot move to a fresh
    ///   count.
    /// * On a root host runtime every pod's children drop to the same
    ///   `DEFAULT_CHILD_UID`, so the 512 tasks are shared across pods and
    ///   with anything else running as that uid.
    /// * A `Restricted` child (`HostHardened`, non-root runtime) keeps the
    ///   runtime's uid, so the count includes every process of that user.
    fn hook_limits(applied: AppliedRlimits) -> HookLimits {
        let RlimitVector {
            nproc,
            nofile,
            fsize_bytes,
            cpu_seconds,
        } = applied.limits();
        [
            (libc::RLIMIT_NPROC, nproc),
            (libc::RLIMIT_NOFILE, nofile),
            (libc::RLIMIT_FSIZE, fsize_bytes),
            (libc::RLIMIT_CPU, cpu_seconds),
        ]
        .map(|(resource, max)| (resource as RlimitResource, max))
    }

    /// `CLOSE_RANGE_CLOEXEC` from uapi `linux/close_range.h` (kernel ≥ 5.11).
    /// Local because the `libc` crate's binding varies by target.
    const CLOSE_RANGE_CLOEXEC: libc::c_long = 1 << 2;

    /// The syscall filter as the hook sees it: decided AND compiled in the
    /// parent, so the child neither decides nor allocates. Three cases, not an
    /// `Option` (ADR 0007 A-1, B-2): "the filter could not be built" is a
    /// refusal, not "no filter".
    enum Seccomp {
        /// `SyscallFilter::Unfiltered`.
        NotRequested,
        /// The compiled denylist, installed after `no_new_privs`.
        Install(Program),
        /// The denylist was required and could not be compiled, so the spawn
        /// fails. The reason was logged in the parent.
        Refuse,
    }

    /// The Landlock ruleset as the hook sees it: decided AND compiled in the
    /// parent. Three cases for the same reason as [`Seccomp`].
    enum Landlock {
        /// `FilesystemConfinement::Waived` or `NotApplied`.
        NotRequested,
        /// The compiled ruleset, applied after `no_new_privs`.
        Restrict(Ruleset),
        /// The ruleset was required and could not be compiled, so the spawn
        /// fails. The reason was logged in the parent.
        Refuse,
    }

    /// Runs after fork, after std's stdio `dup2`, uid drop and `chdir`, and
    /// before exec. MUST be async-signal-safe: raw syscalls only, no
    /// allocation, no locks. Any `Err` fails the spawn (the child never execs).
    fn harden_child(
        seccomp: &mut Seccomp,
        landlock: &mut Landlock,
        limits: &HookLimits,
    ) -> io::Result<()> {
        // SAFETY: every call below is an async-signal-safe libc syscall taking
        // scalars or a pointer to a fully-initialized local `rlimit`; none
        // allocates or takes a lock, satisfying the `pre_exec` contract.
        unsafe {
            // Mark every fd from 3 up close-on-exec rather than closing it
            // HERE: std still owns a CLOEXEC status pipe in this window, used
            // to report a failed later step back to the parent. Closing it now
            // turned such a failure into `fatal runtime error: assertion
            // failed: output.write(&bytes).is_ok()` (the run-5 boot).
            // CLOSE_RANGE_CLOEXEC gives the same post-exec result — nothing
            // above 2 survives the exec (the runc CVE-2024-21626 shape) —
            // while leaving the pipe usable until then.
            //
            // The raw syscall, not `libc::close_range` (a glibc-only wrapper;
            // the guest is musl). ENOSYS (pre-5.9) is tolerated: std marks
            // what it creates CLOEXEC. EINVAL (5.9–5.10: no CLOEXEC flag)
            // falls back to closing outright. Anything else fails the spawn.
            if libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_long,
                libc::c_uint::MAX as libc::c_long,
                CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENOSYS) => {}
                    Some(libc::EINVAL) => {
                        if libc::syscall(
                            libc::SYS_close_range,
                            3 as libc::c_long,
                            libc::c_uint::MAX as libc::c_long,
                            0 as libc::c_long,
                        ) != 0
                        {
                            let err = io::Error::last_os_error();
                            if err.raw_os_error() != Some(libc::ENOSYS) {
                                return Err(err);
                            }
                        }
                    }
                    _ => return Err(err),
                }
            }
            // What any process may do to itself — the uid, if it was to
            // change, already has.
            // No new privileges: defeats setuid/file-capability escalation,
            // and is what lets an unprivileged process install the filter
            // below (without it the kernel answers EACCES).
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            for &(resource, max) in limits {
                let rl = libc::rlimit {
                    rlim_cur: max,
                    rlim_max: max,
                };
                if libc::setrlimit(resource, &rl) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            // The filesystem ruleset: after `no_new_privs` (without which an
            // unprivileged `landlock_restrict_self` is `EPERM`) and before the
            // syscall filter, so the filter can never stand between the
            // child and its own restriction.
            match landlock {
                Landlock::NotRequested => {}
                Landlock::Refuse => return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
                Landlock::Restrict(ruleset) => ruleset.restrict_self()?,
            }
            // The syscall filter, LAST: after the uid drop (std did it before
            // this hook ran) and after `no_new_privs`. `fprog` borrows the
            // parent-compiled instructions, and `ErrorKind` errors do not
            // allocate.
            match seccomp {
                Seccomp::NotRequested => {}
                Seccomp::Refuse => return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
                Seccomp::Install(program) => {
                    let fprog = program.fprog();
                    if libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER,
                        &raw const fprog,
                    ) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }
        Ok(())
    }

    /// Install the self-restriction hook, with `filter` and the filesystem
    /// ruleset compiled and `rlimits` converted here, in the parent.
    pub(super) fn install(
        cmd: &mut std::process::Command,
        filter: SyscallFilter,
        filesystem: FilesystemConfinement,
        rlimits: AppliedRlimits,
    ) -> Hook {
        let limits = hook_limits(rlimits);
        let mut landlock = match filesystem {
            FilesystemConfinement::NotApplied | FilesystemConfinement::Waived { .. } => {
                Landlock::NotRequested
            }
            FilesystemConfinement::Landlock { abi } => match Ruleset::compile(abi) {
                Ok(ruleset) => Landlock::Restrict(ruleset),
                Err(e) => {
                    tracing::error!(
                        path = %e.path.display(),
                        error = %e.error,
                        abi,
                        "the Landlock ruleset could not be compiled; refusing the confined spawn"
                    );
                    Landlock::Refuse
                }
            },
        };
        let mut seccomp = match filter {
            SyscallFilter::Unfiltered => Seccomp::NotRequested,
            SyscallFilter::WorkloadDenylist => match Program::workload_denylist() {
                Ok(program) => Seccomp::Install(program),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "the workload syscall filter could not be built; refusing the confined spawn"
                    );
                    Seccomp::Refuse
                }
            },
        };
        super::hook::pre_exec(cmd, move || {
            harden_child(&mut seccomp, &mut landlock, &limits)
        });
        Hook::Installed
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod imp {
    pub(super) use super::uid::{chown, drop_to, runtime_uid};
    use super::{AppliedRlimits, FilesystemConfinement, Hook, SyscallFilter};

    /// No `close_range`/`prctl`/seccomp off Linux. `HostHardened` is refused
    /// before any spawn there (`attest_containment`), and the guest is Linux.
    /// A posture that requires the syscall filter cannot have it here, so its
    /// spawn fails rather than running unfiltered (ADR 0007 A-1).
    ///
    /// Landlock likewise: the probe answers `Unavailable` off Linux, so a
    /// `Landlock` posture cannot be decided here, and if one were, it refuses.
    ///
    /// No limit is set here either, so nothing this returns claims a hook
    /// (`rlimits` is unused off Linux).
    pub(super) fn install(
        cmd: &mut std::process::Command,
        filter: SyscallFilter,
        filesystem: FilesystemConfinement,
        _rlimits: AppliedRlimits,
    ) -> Hook {
        let landlock_required = match filesystem {
            FilesystemConfinement::Landlock { .. } => true,
            FilesystemConfinement::Waived { .. } | FilesystemConfinement::NotApplied => false,
        };
        match (filter, landlock_required) {
            (SyscallFilter::Unfiltered, false) => {}
            (SyscallFilter::WorkloadDenylist, _) | (SyscallFilter::Unfiltered, true) => {
                // std transports a pre_exec error by errno; a bare ErrorKind loses
                // its identity and arrives in the parent as EINVAL.
                super::hook::pre_exec(cmd, || {
                    Err(std::io::Error::from_raw_os_error(libc::EOPNOTSUPP))
                });
            }
        }
        Hook::NoneOnThisPlatform
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A kernel that enforces, and no waiver: the posture every test below
    /// that is not about Landlock runs under.
    const LL: LandlockSupport = LandlockSupport::Abi(MIN_LANDLOCK_ABI);
    const NO: LandlockWaiver = LandlockWaiver::Absent;

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
        let _ = confinement.apply(&mut cmd, RlimitPolicy::node_ceiling().at_ceiling());
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
            let c =
                ChildConfinement::decide(ContainmentMode::Unsandboxed, 0, opt_in, LL, NO).unwrap();
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
                            ChildConfinement::decide_workload(
                                mode, requested, 1000, opt_in, LL, NO
                            ),
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
    const BELOW_MINIMUM: [LandlockSupport; 2] =
        [LandlockSupport::Unavailable, LandlockSupport::Abi(1)];

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
                let c =
                    ChildConfinement::decide(mode, runtime, UnsandboxedOptIn::Absent, kernel, NO)
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
        assert!(!c.closes_inherited_fds());
        for mode in [ContainmentMode::HostHardened, ContainmentMode::MicroVM] {
            assert!(
                ChildConfinement::decide(mode, 0, UnsandboxedOptIn::Absent, LL, NO)
                    .is_ok_and(|c| !c.is_unsandboxed()),
                "{mode:?}"
            );
        }
    }

    /// #2572: only an installed hook claims hardening, and the claim carries
    /// the limits the hook sets. The declared bare tier cannot claim it, and
    /// neither can a platform with no hook.
    #[test]
    fn only_an_installed_hook_claims_hardening() {
        let rlimits =
            RlimitPolicy::for_pod(std::time::Duration::from_secs(60), Some(2)).at_ceiling();
        let bare = ChildConfinement::decide(
            ContainmentMode::Unsandboxed,
            1000,
            UnsandboxedOptIn::Explicit,
            LL,
            NO,
        )
        .unwrap();
        assert_eq!(
            bare.apply(&mut std::process::Command::new("/bin/true"), rlimits),
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
        let got = restricted.apply(&mut std::process::Command::new("/bin/true"), rlimits);
        #[cfg(target_os = "linux")]
        match got {
            SpawnHardening::Hardened(h) => assert_eq!(h.rlimits(), rlimits),
            SpawnHardening::Unhardened(why) => {
                panic!("a restricted child was not hardened: {why:?}")
            }
        }
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            got,
            SpawnHardening::Unhardened(Unhardened::NoHookOnThisPlatform)
        );
    }
}
