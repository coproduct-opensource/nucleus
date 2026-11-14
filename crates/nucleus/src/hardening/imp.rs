//! The Linux half of the confinement hook (`hardening.rs`): the child-side
//! syscall sequence and its parent-side preparation, in its own file so the
//! decider stays under the line ceiling. Its `unsafe` is audited with
//! `hardening.rs`'s `hook` and `pidns::enter`.

use std::io;

use portcullis::{SeccompPolicy, SyscallClass};

use super::exec_pin::PinnedExec;
use super::landlock::Ruleset;
use super::pidns::Mapping;
use super::seccomp::Program;
pub(super) use super::uid::{chown, drop_to, runtime_uid};
use super::{
    AppliedRlimits, FilesystemConfinement, Hook, Isolation, RlimitVector, SyscallFilter, WriteLayer,
};

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
/// * A workload placed in a private user namespace (#3528) is counted in
///   that namespace, which is new and holds only the workload, so the
///   bound is that workload's alone. The runtime made the namespace; the
///   filter still refuses the workload a further one.
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

/// How much of the hook runs. Two named cases rather than an `Option`
/// of limits (ADR 0007 B-2).
enum Restrict<'a> {
    /// Every step: `no_new_privs`, these limits, Landlock, the filter.
    Full(&'a HookLimits),
    /// The descriptor sweep only (the declared bare tier, #3461).
    SweepOnly,
}

/// The isolation as the hook runs it: decided in the parent, with any map
/// line formatted there (`pidns::Mapping::new`), so the child neither
/// decides nor allocates.
enum Entry {
    None,
    NetnsThenDrop {
        uid: u32,
        gid: u32,
    },
    PidnsThenDrop {
        uid: u32,
        gid: u32,
    },
    PidnsThenUserNetwork {
        uid: u32,
        gid: u32,
        mapping: Mapping,
    },
}

impl Entry {
    fn of(isolation: Isolation) -> Self {
        match isolation {
            Isolation::None => Self::None,
            Isolation::NetnsThenDrop { uid, gid } => Self::NetnsThenDrop { uid, gid },
            Isolation::PidnsThenDrop { uid, gid } => Self::PidnsThenDrop { uid, gid },
            Isolation::PidnsThenUserNetwork {
                uid,
                gid,
                inner_uid,
                loopback,
            } => Self::PidnsThenUserNetwork {
                uid,
                gid,
                mapping: Mapping::new(uid, inner_uid, loopback),
            },
        }
    }
}

/// Who execs the child once the hook is done (#2907). Two named cases
/// rather than an `Option` (ADR 0007 B-2).
enum Start {
    /// std's own `execvp`, after the hook returns.
    ByStd,
    /// The policy denies exec: the hook execs through the pin, the one
    /// exec the filter allows, and returns only its error.
    Pinned(PinnedExec),
}

/// Runs after fork, after std's stdio `dup2`, uid drop and `chdir`, and
/// before exec. MUST be async-signal-safe: raw syscalls only, no
/// allocation, no locks. Any `Err` fails the spawn (the child never execs).
fn harden_child(
    entry: &Entry,
    seccomp: &mut Seccomp,
    landlock: &mut Landlock,
    writes: &mut Landlock,
    restrict: Restrict<'_>,
    start: &Start,
) -> io::Result<()> {
    // SAFETY: every call below is an async-signal-safe libc syscall taking
    // scalars, a pointer to a fully-initialized local `rlimit`, or (the
    // pinned `execveat`) pointers into buffers the parent built and the
    // closure owns; none allocates or takes a lock, satisfying the
    // `pre_exec` contract.
    unsafe {
        // A host service's own network namespace, entered while the
        // child is still root, and only then the drop (std did not drop:
        // `Isolated` declares no uid on the command). `setresuid` from
        // root to a non-root uid clears every capability set, ambient
        // included, because the hook never sets `SECBIT_KEEP_CAPS`.
        match *entry {
            Entry::None => {}
            Entry::NetnsThenDrop { uid, gid } => {
                if libc::unshare(libc::CLONE_NEWNET) != 0
                    || libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            // Returns only in the workload, dropped (`pidns.rs`).
            Entry::PidnsThenDrop { uid, gid } => {
                super::pidns::enter(uid, gid, super::pidns::Runtime)?;
            }
            // The same, then the workload's own user and network
            // namespace: unshared, mapped by the init and read back, and
            // every capability shed, each step consuming the one before
            // (`pidns/user_network.rs`, ADR 0007 D-1).
            Entry::PidnsThenUserNetwork { uid, gid, mapping } => {
                let _placed: super::pidns::Placed = super::pidns::enter(uid, gid, mapping)?
                    .map()?
                    .shed_capabilities()?;
            }
        }
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
        // The bare tier stops here: descriptors swept, nothing else.
        // Under a read-only workspace (#2907) it also installs the write
        // layer, and nothing else: `restrict_self` sets `no_new_privs`
        // itself, which an unprivileged `landlock_restrict_self` needs.
        let limits = match restrict {
            Restrict::Full(limits) => limits,
            Restrict::SweepOnly => {
                return match writes {
                    Landlock::NotRequested => Ok(()),
                    Landlock::Refuse => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
                    Landlock::Restrict(ruleset) => ruleset.restrict_self(),
                };
            }
        };
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
        match (landlock, entry) {
            (Landlock::NotRequested, _) => {}
            (Landlock::Refuse, _) => {
                return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));
            }
            // Its own `/proc` is a new procfs the parent's rule is not on.
            (
                Landlock::Restrict(ruleset),
                Entry::PidnsThenDrop { uid: _, gid: _ }
                | Entry::PidnsThenUserNetwork {
                    uid: _,
                    gid: _,
                    mapping: _,
                },
            ) => {
                ruleset.grant_own_proc()?;
                ruleset.restrict_self()?;
            }
            (
                Landlock::Restrict(ruleset),
                Entry::None | Entry::NetnsThenDrop { uid: _, gid: _ },
            ) => ruleset.restrict_self()?,
        }
        // The write layer (#2907), a second Landlock domain over the
        // first: the two intersect, so a read-only workspace stays
        // readable through the layout and is written by nothing.
        match writes {
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
        // Under the filter now. A policy that denies exec allows exactly
        // the pinned `execveat`, which does not return on success: its
        // descriptor and the NUL-terminated argv/envp arrays (addresses
        // of `CString`s the pin keeps alive; `usize` and a pointer share
        // one layout) were built in the parent, and the kernel only reads
        // them (#2907).
        match start {
            Start::ByStd => {}
            Start::Pinned(pinned) => {
                let (fd, argv, envp) = pinned.execveat_args();
                libc::syscall(
                    libc::SYS_execveat,
                    libc::c_long::from(fd),
                    c"".as_ptr(),
                    argv,
                    envp,
                    libc::c_long::from(libc::AT_EMPTY_PATH),
                );
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}

/// Install the self-restriction hook, with `filter` (the denylist plus
/// `syscalls`' classes) and the filesystem ruleset compiled, `rlimits`
/// converted and any exec pin opened here, in the parent.
pub(super) fn install(
    cmd: &mut std::process::Command,
    isolation: Isolation,
    filter: SyscallFilter,
    filesystem: FilesystemConfinement,
    layer: WriteLayer<'_>,
    rlimits: AppliedRlimits,
    syscalls: SeccompPolicy,
) -> Hook {
    let limits = hook_limits(rlimits);
    let mut writes = write_layer(layer);
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
    let (mut seccomp, start) = match filter {
        SyscallFilter::Unfiltered => (Seccomp::NotRequested, Start::ByStd),
        SyscallFilter::WorkloadDenylist => match compile(cmd, syscalls, rlimits.limits().nofile) {
            Ok((program, start)) => (Seccomp::Install(program), start),
            Err(error) => {
                tracing::error!(
                    %error,
                    derived = %syscalls.canonical(),
                    "the workload syscall filter could not be built; refusing the confined spawn"
                );
                (Seccomp::Refuse, Start::ByStd)
            }
        },
    };
    let entry = Entry::of(isolation);
    super::hook::pre_exec(cmd, move || {
        harden_child(
            &entry,
            &mut seccomp,
            &mut landlock,
            &mut writes,
            Restrict::Full(&limits),
            &start,
        )
    });
    Hook::Installed
}

/// The write layer (#2907), compiled in the parent. A layer that cannot
/// be compiled refuses the spawn; the reason is logged here and named by
/// `preflight_filesystem`.
fn write_layer(layer: WriteLayer<'_>) -> Landlock {
    match layer {
        WriteLayer::None => Landlock::NotRequested,
        WriteLayer::ReadOnly { abi, workspace } => {
            match Ruleset::compile_write_scope(abi, workspace) {
                Ok(ruleset) => Landlock::Restrict(ruleset),
                Err(e) => {
                    tracing::error!(
                        path = %e.path.display(),
                        error = %e.error,
                        abi,
                        "the Landlock write layer could not be compiled; refusing the spawn"
                    );
                    Landlock::Refuse
                }
            }
        }
    }
}

/// The denylist plus `syscalls`' classes, and who starts the child: a
/// policy that denies exec gets a pin at or above `nofile` (the limit the
/// hook sets), and the program pins `execveat` to it.
fn compile(
    cmd: &mut std::process::Command,
    syscalls: SeccompPolicy,
    nofile: u64,
) -> Result<(Program, Start), String> {
    let start = if syscalls.denies(SyscallClass::Exec) {
        Start::Pinned(PinnedExec::prepare(cmd, nofile).map_err(|e| e.to_string())?)
    } else {
        Start::ByStd
    };
    let pin = match &start {
        Start::Pinned(p) => Some(p.pin()),
        Start::ByStd => None,
    };
    let program = Program::workload(syscalls, pin).map_err(|e| e.to_string())?;
    Ok((program, start))
}

/// The runtime's seal (#3461): non-dumpable, confirmed by reading it
/// back. Through `rustix`'s safe `prctl` wrappers, so no `unsafe`.
pub(super) fn seal_self() -> io::Result<bool> {
    use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};
    set_dumpable_behavior(DumpableBehavior::NotDumpable)?;
    if matches!(dumpable_behavior()?, DumpableBehavior::NotDumpable) {
        Ok(true)
    } else {
        Err(io::Error::other("the process still reads as dumpable"))
    }
}

/// The bare tier's one confinement (#3461): every descriptor above stdio
/// marked close-on-exec at the child's exec, so a descriptor the runtime
/// inherited without close-on-exec (from a careless launcher, or a build
/// tool's jobserver) does not pass on to a command the agent runs. No
/// `no_new_privs`, no limits, no filter: the tier's stated meaning stands.
///
/// Under a read-only workspace (#2907) the same hook also installs the
/// write layer `layer` names, and still nothing else.
pub(super) fn sweep_inherited(cmd: &mut std::process::Command, layer: WriteLayer<'_>) -> Hook {
    let mut writes = write_layer(layer);
    super::hook::pre_exec(cmd, move || {
        harden_child(
            &Entry::None,
            &mut Seccomp::NotRequested,
            &mut Landlock::NotRequested,
            &mut writes,
            Restrict::SweepOnly,
            &Start::ByStd,
        )
    });
    Hook::Installed
}
