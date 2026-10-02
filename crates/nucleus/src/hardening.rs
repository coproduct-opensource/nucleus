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
//! # What the child gets
//!
//! | Mode | runtime root | runtime not root |
//! |---|---|---|
//! | `Unconfigured` | refused | refused |
//! | `Unsandboxed`, `/v1/run` child | bare: runtime's uid | bare: runtime's uid |
//! | `Unsandboxed`, workload, no `workload.uid` | drop to 65534 | bare: runtime's uid |
//! | `Unsandboxed`, workload, explicit `workload.uid` | drop to it | **refused** |
//! | `HostHardened`, `/v1/run` child | restricted, runtime's uid | restricted, runtime's uid |
//! | `HostHardened`, workload | drop | **refused** |
//! | `MicroVM` (child or workload) | drop | **refused** |
//!
//! "Bare" = no fd closing, no `no_new_privs`, no rlimits. "Restricted" = fds
//! above 2 close-on-exec, `no_new_privs`, rlimits, no uid change. "Drop" =
//! restricted, and uid/gid changed first. An explicit `workload.uid` is a
//! request the runtime must honour or refuse; only the unset default may
//! collapse to the bare tier, because only then did nobody ask for a uid.
//!
//! `HostHardened`'s `/v1/run` child keeps the runtime's uid: that mode's
//! documented contract is self-restriction (it attests `process: Shared`), and
//! the tool-proxy never selects it — its containment comes only from
//! `SandboxProof`, which yields `MicroVM` or `Unsandboxed`.
//!
//! [`apply`]: ChildConfinement::apply

use std::path::Path;

use crate::command::ContainmentMode;
use crate::error::{NucleusError, Result};

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
    /// separation that could not happen.
    Unsandboxed,
    /// Self-restriction without a uid change (`ContainmentMode::HostHardened`).
    Restricted,
    /// Drop to this uid (and gid), then self-restrict.
    DropTo(u32),
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
    pub fn for_containment(mode: ContainmentMode) -> Result<Self> {
        Self::decide(mode, runtime_uid())
    }

    /// The decision itself, with the runtime's uid as an input so the root
    /// case is testable without root.
    pub(crate) fn decide(mode: ContainmentMode, runtime_uid: u32) -> Result<Self> {
        // Exhaustive and `_`-free on purpose (ADR 0007 B-3): a new mode does
        // not compile until its children's confinement is written here.
        match mode {
            ContainmentMode::Unconfigured => Err(NucleusError::IsolationNotConfigured),
            ContainmentMode::Unsandboxed => Ok(Self {
                posture: Posture::Unsandboxed,
            }),
            ContainmentMode::HostHardened => Ok(Self {
                posture: Posture::Restricted,
            }),
            // The VM is the boundary against the HOST; inside it, the
            // tool-proxy is PID 1 and root, and holds every pod secret. A
            // command it runs for the agent is separated from it exactly as
            // the workload is — or not run.
            ContainmentMode::MicroVM => Self::separate(DEFAULT_CHILD_UID, runtime_uid),
        }
    }

    /// The confinement of a pod workload under `mode` that asked for
    /// `requested` (`workload.uid`; `None` = the default,
    /// [`DEFAULT_CHILD_UID`]).
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
    pub fn workload(mode: ContainmentMode, requested: Option<u32>) -> Result<Self> {
        Self::decide_workload(mode, requested, runtime_uid())
    }

    pub(crate) fn decide_workload(
        mode: ContainmentMode,
        requested: Option<u32>,
        runtime_uid: u32,
    ) -> Result<Self> {
        let uid = requested.unwrap_or(DEFAULT_CHILD_UID);
        match mode {
            ContainmentMode::Unconfigured => Err(NucleusError::IsolationNotConfigured),
            // The bare host tier, declared. A root runtime still drops (a
            // stronger posture costs nothing); a non-root one cannot, and
            // the workload runs as a plain host process — which is what
            // `Unsandboxed` means. Only when no uid was asked for: an
            // explicit `workload.uid` the runtime cannot honour is refused
            // rather than silently replaced by the runtime's.
            ContainmentMode::Unsandboxed => match requested {
                None if runtime_uid != 0 => Ok(Self {
                    posture: Posture::Unsandboxed,
                }),
                None | Some(_) => Self::separate(uid, runtime_uid),
            },
            ContainmentMode::HostHardened | ContainmentMode::MicroVM => {
                Self::separate(uid, runtime_uid)
            }
        }
    }

    /// "This child must not share the runtime's authority" — the one rule the
    /// workload and the MicroVM `/v1/run` child share. A drop, or a named
    /// refusal; there is no third outcome.
    fn separate(uid: u32, runtime_uid: u32) -> Result<Self> {
        if uid == runtime_uid {
            Err(NucleusError::ChildSharesRuntimeUid { uid })
        } else if runtime_uid != 0 {
            Err(NucleusError::ChildSeparationUnavailable {
                runtime_uid,
                child_uid: uid,
            })
        } else {
            Ok(Self {
                posture: Posture::DropTo(uid),
            })
        }
    }

    /// Who the child runs as, relative to the runtime.
    #[must_use]
    pub fn child_uid(&self) -> ChildUid {
        match self.posture {
            Posture::DropTo(uid) => ChildUid::Distinct(uid),
            Posture::Unsandboxed | Posture::Restricted => ChildUid::SharedWithRuntime,
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
            Posture::Restricted | Posture::DropTo(_) => false,
        }
    }

    /// Whether the child sets `no_new_privs` and the resource limits.
    #[must_use]
    pub fn restricts(&self) -> bool {
        match self.posture {
            Posture::Restricted | Posture::DropTo(_) => true,
            Posture::Unsandboxed => false,
        }
    }

    /// Whether inherited descriptors above stdio are closed at exec.
    #[must_use]
    pub fn closes_inherited_fds(&self) -> bool {
        match self.posture {
            Posture::Restricted | Posture::DropTo(_) => true,
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
    /// For a `tokio::process::Command`, pass `cmd.as_std_mut()`.
    pub fn apply(&self, cmd: &mut std::process::Command) {
        match self.posture {
            Posture::Unsandboxed => {}
            Posture::Restricted => imp::install(cmd, true),
            Posture::DropTo(uid) => {
                imp::drop_to(cmd, uid);
                imp::install(cmd, true);
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

#[cfg(target_os = "linux")]
// The crate denies `unsafe_code` globally; this module is the single, audited
// exception. Child-side hardening is intrinsically `unsafe` FFI: it calls
// `close_range`/`prctl`/`setrlimit` and installs a `pre_exec` hook, which must
// be async-signal-safe. Two `unsafe` blocks: the syscall sequence and the hook
// install.
#[allow(unsafe_code)]
mod imp {
    use std::io;
    use std::os::unix::process::CommandExt;

    pub(super) use super::uid::{chown, drop_to, runtime_uid};

    // Generous-but-bounded: contain abuse without breaking build/test work.
    const RLIMIT_NPROC_MAX: libc::rlim_t = 512;
    const RLIMIT_NOFILE_MAX: libc::rlim_t = 4096;
    const RLIMIT_FSIZE_MAX: libc::rlim_t = 8 * 1024 * 1024 * 1024; // 8 GiB
    const RLIMIT_CPU_SECS: libc::rlim_t = 3600; // 1 hour of CPU time

    // `setrlimit` takes `__rlimit_resource_t` on glibc but plain `c_int` on
    // musl (the guest rootfs).
    #[cfg(target_env = "gnu")]
    type RlimitResource = libc::__rlimit_resource_t;
    #[cfg(not(target_env = "gnu"))]
    type RlimitResource = libc::c_int;

    /// `CLOSE_RANGE_CLOEXEC` from uapi `linux/close_range.h` (kernel ≥ 5.11).
    /// Local because the `libc` crate's binding varies by target.
    const CLOSE_RANGE_CLOEXEC: libc::c_long = 1 << 2;

    /// Runs after fork, after std's stdio `dup2`, uid drop and `chdir`, and
    /// before exec. MUST be async-signal-safe: raw syscalls only, no
    /// allocation, no locks. Any `Err` fails the spawn (the child never execs).
    fn harden_child(restrict: bool) -> io::Result<()> {
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
            if restrict {
                // What any process may do to itself — the uid, if it was to
                // change, already has.
                // No new privileges: defeats setuid/file-capability escalation.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                for (resource, max) in [
                    (libc::RLIMIT_NPROC, RLIMIT_NPROC_MAX),
                    (libc::RLIMIT_NOFILE, RLIMIT_NOFILE_MAX),
                    (libc::RLIMIT_FSIZE, RLIMIT_FSIZE_MAX),
                    (libc::RLIMIT_CPU, RLIMIT_CPU_SECS),
                ] {
                    let rl = libc::rlimit {
                        rlim_cur: max,
                        rlim_max: max,
                    };
                    if libc::setrlimit(resource as RlimitResource, &rl) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn install(cmd: &mut std::process::Command, restrict: bool) {
        // SAFETY: `harden_child` only invokes async-signal-safe syscalls and
        // does not allocate.
        unsafe {
            cmd.pre_exec(move || harden_child(restrict));
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
mod imp {
    pub(super) use super::uid::{chown, drop_to, runtime_uid};

    /// No `close_range`/`prctl` off Linux. `HostHardened` is refused before
    /// any spawn there (`attest_containment`), and the guest is Linux.
    pub(super) fn install(_cmd: &mut std::process::Command, _restrict: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE finding (A-19): inside a guest the runtime is root, and a MicroVM
    /// child must leave root. Red on the commit before this module, where the
    /// Executor handed the spawn home `None` for every mode but HostHardened.
    #[test]
    fn a_microvm_child_of_a_root_runtime_drops_to_the_workload_uid_and_is_restricted() {
        let c = ChildConfinement::decide(ContainmentMode::MicroVM, 0).expect("MicroVM confines");
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
                ChildConfinement::decide(ContainmentMode::MicroVM, runtime).ok(),
                ChildConfinement::decide_workload(ContainmentMode::MicroVM, None, runtime).ok(),
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
            ChildConfinement::decide(ContainmentMode::MicroVM, 1000),
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
                assert!(
                    matches!(
                        ChildConfinement::decide_workload(mode, requested, 1000),
                        Err(NucleusError::ChildSeparationUnavailable { .. })
                    ),
                    "{mode:?} / {requested:?}"
                );
            }
        }
    }

    /// The bare host tier is reached only by declaring it, and only for the
    /// default uid: an explicit `workload.uid` is honoured or refused.
    #[test]
    fn unsandboxed_is_the_only_same_uid_workload_and_only_by_default() {
        let c = ChildConfinement::decide_workload(ContainmentMode::Unsandboxed, None, 1000)
            .expect("the declared bare tier runs");
        assert!(c.is_unsandboxed());
        assert_eq!(c.child_uid(), ChildUid::SharedWithRuntime);
        assert!(matches!(
            ChildConfinement::decide_workload(ContainmentMode::Unsandboxed, Some(4242), 1000),
            Err(NucleusError::ChildSeparationUnavailable { .. })
        ));
        // A root runtime still drops, even on the bare tier.
        let c = ChildConfinement::decide_workload(ContainmentMode::Unsandboxed, None, 0).unwrap();
        assert_eq!(c.child_uid(), ChildUid::Distinct(DEFAULT_CHILD_UID));
    }

    /// The runtime's own uid is never a boundary, in any mode, root or not.
    #[test]
    fn a_workload_asking_for_the_runtimes_uid_is_refused_by_name() {
        for mode in [
            ContainmentMode::Unsandboxed,
            ContainmentMode::HostHardened,
            ContainmentMode::MicroVM,
        ] {
            assert!(matches!(
                ChildConfinement::decide_workload(mode, Some(1000), 1000),
                Err(NucleusError::ChildSharesRuntimeUid { uid: 1000 })
            ));
            assert!(matches!(
                ChildConfinement::decide_workload(mode, Some(0), 0),
                Err(NucleusError::ChildSharesRuntimeUid { uid: 0 })
            ));
        }
    }

    /// A root runtime drops an explicit uid to exactly that uid.
    #[test]
    fn a_root_runtime_drops_an_explicit_workload_uid() {
        let c = ChildConfinement::decide_workload(ContainmentMode::MicroVM, Some(4242), 0).unwrap();
        assert_eq!(c.child_uid(), ChildUid::Distinct(4242));
        assert!(c.restricts());
    }

    #[test]
    fn unconfigured_is_refused_not_passed_through() {
        assert!(matches!(
            ChildConfinement::decide(ContainmentMode::Unconfigured, 0),
            Err(NucleusError::IsolationNotConfigured)
        ));
        assert!(matches!(
            ChildConfinement::decide_workload(ContainmentMode::Unconfigured, None, 0),
            Err(NucleusError::IsolationNotConfigured)
        ));
    }

    #[test]
    fn host_hardened_restricts_without_a_uid_change() {
        let c = ChildConfinement::decide(ContainmentMode::HostHardened, 0).unwrap();
        assert_eq!(c.drop_uid(), None);
        assert!(c.restricts());
    }

    #[test]
    fn unsandboxed_is_the_one_bare_posture() {
        for runtime in [0, 1000] {
            let c = ChildConfinement::decide(ContainmentMode::Unsandboxed, runtime).unwrap();
            assert!(c.is_unsandboxed());
            assert_eq!(c.drop_uid(), None);
            assert!(!c.restricts());
            assert!(!c.closes_inherited_fds());
        }
        for mode in [ContainmentMode::HostHardened, ContainmentMode::MicroVM] {
            assert!(
                ChildConfinement::decide(mode, 0).is_ok_and(|c| !c.is_unsandboxed()),
                "{mode:?}"
            );
        }
    }
}
