//! The guest workload's own PID namespace (#3344).
//!
//! Defence in depth under ADR 0013, never a boundary the host relies on: a
//! guest root can enter or leave any namespace in its own kernel. What it
//! changes is what an unprivileged workload can reach on the way to that root.
//! In the runtime's PID namespace the workload enumerates the tool-proxy and
//! guest-init in `/proc` and names them to `kill`, and only procfs and ptrace
//! access checks stand between it and them (the retired
//! `KB-GUEST-PID-SHARED`). In a namespace of its own, with a `/proc` mounted
//! for that namespace, no pid it can name denotes them: the kernel's PID
//! namespace checks decide that, not access checks over a visible table.
//!
//! # Three processes
//!
//! A process cannot move itself into a new PID namespace: `unshare(CLONE_NEWPID)`
//! places only its later children there, and the first becomes the namespace's
//! pid 1. Pid 1 is special twice over. It must reap every orphan in the
//! namespace, and the kernel delivers it only the signals it has a handler for.
//! A workload is written for neither, so it does not run as pid 1:
//!
//! 1. **The waiter**, the process std forked and the runtime holds as the
//!    workload's `Child`. Still in the runtime's namespace. It unshares the
//!    PID and mount namespaces, forks the init, closes every descriptor it
//!    holds, and exits with the init's status.
//! 2. **The init**, pid 1 of the new namespace, still root. It sets
//!    `PR_SET_PDEATHSIG(SIGKILL)` so it dies with the waiter, makes the mount
//!    tree private, mounts a fresh `/proc` for its namespace (`hidepid=invisible`,
//!    like the guest's), forks the
//!    workload, closes every descriptor, and reaps every child until the
//!    workload exits. It then exits with the workload's status (a signal `n`
//!    as `128 + n`), and its exit kills whatever is left in the namespace.
//! 3. **The workload**, pid 2. It drops to its uid and gid here, after the
//!    mount (the drop takes the privilege `mount` needs, which is why the
//!    uid is not declared on the command for this posture), and returns to the
//!    rest of the hook: the descriptor sweep, `no_new_privs`, the rlimits,
//!    Landlock and the syscall filter, in their usual order. Then std execs it.
//!
//! So the runtime's kill (`kill_on_drop`, `SIGKILL`) reaches the waiter, the
//! waiter's death the init, and the init's death every process in the
//! namespace.
//!
//! std reports a failed hook or exec through a close-on-exec pipe, and its
//! parent reads until every copy of the write end is closed. The waiter and
//! the init never exec, so each closes all of its descriptors (that pipe,
//! and the copies of the workload's stdout and stderr) once its own fork is
//! done. A failure in the init before its fork, or in the workload before or
//! at exec, still reaches the parent through the copy that process holds.
//!
//! The forks are raw `clone(SIGCHLD)`, not `fork(3)`: the waiter is a fork of a
//! multithreaded runtime, and libc's `fork` takes locks another thread of the
//! runtime may have held when it was copied.
//!
//! # A private user and network namespace inside it
//!
//! A workload that asks for `private_user_network` gets one more layer, made
//! LAST, by the workload itself once dropped, and mapped by the init
//! (`user_network.rs`; the order and why it is this one are in
//! `docs/findings/workload-user-network-namespace.md`):
//!
//! * the init makes a `socketpair` before it forks the workload and keeps one
//!   end; it serves exactly one request on it before it starts reaping;
//! * the workload, dropped, unshares a user and a network namespace, raises
//!   `lo` only if asked, and asks the init for its map;
//! * the init checks the new user namespace is owned by the outer uid, writes
//!   `uid_map`, `setgroups` = `deny` and `gid_map` (the one line `inner outer
//!   1`, formatted in the parent), and answers granted or refused;
//! * the workload reads its map back from the kernel and sheds every
//!   capability before the rest of the hook runs.
//!
//! The PID and mount namespaces are made by root, so they belong to the initial
//! user namespace, and nothing the workload holds in its own user namespace
//! reaches them.

use crate::command::ContainmentMode;

/// Whether a child runs in a PID namespace of its own (#3344): what a spawn
/// asks [`super::ChildConfinement::apply_with_pids`] for, and what the
/// [`super::Hardened`] it returns says the hook does.
///
/// Two named cases, not a `bool` (ADR 0007 A), and no `Default` (B-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PidNamespace {
    /// The child is the only child of the init of a PID namespace the hook
    /// created, with a `/proc` for that namespace mounted in a private mount
    /// namespace. Nothing outside the namespace has a pid it can name.
    Own,
    /// The child shares the runtime's PID namespace and its `/proc`.
    Shared,
}

impl PidNamespace {
    /// What a workload under `mode` is spawned in. The ONE decider (ADR 0007
    /// G-1). Exhaustive, no `_` arm (B-3).
    ///
    /// Only the guest makes one. A root guest runtime has `CAP_SYS_ADMIN` in
    /// its own kernel, and ADR 0013 keeps every in-guest layer as defence in
    /// depth. On a host tier the runtime is a container's or an operator's
    /// process, which may hold no such capability; there the uid drop and
    /// procfs access checks remain the boundary, and the receipt says
    /// `shared`.
    #[must_use]
    pub fn for_workload(mode: ContainmentMode) -> Self {
        match mode {
            ContainmentMode::MicroVM => Self::Own,
            ContainmentMode::Unconfigured
            | ContainmentMode::Unsandboxed
            | ContainmentMode::HostHardened => Self::Shared,
        }
    }

    /// The spelling a launch receipt's hashed preimage carries.
    #[must_use]
    pub fn canonical(self) -> &'static str {
        match self {
            Self::Own => "own",
            Self::Shared => "shared",
        }
    }
}

/// The new `/proc`'s options: `hidepid=invisible`, as guest-init mounts the
/// guest's (#2696 P3d), so the workload sees no other uid's process, the root
/// init included, in its namespace either.
#[cfg(target_os = "linux")]
const PROC_OPTIONS: &std::ffi::CStr = c"hidepid=invisible";

/// The init's name (`comm`), so an operator listing the guest's processes
/// does not read it as a second runtime: it is a fork of the runtime that
/// never execs.
#[cfg(target_os = "linux")]
const INIT_NAME: &std::ffi::CStr = c"nucleus-init";

/// The workload's private user and network namespace, made inside this PID
/// namespace and mapped by its init.
#[cfg(target_os = "linux")]
mod user_network;
#[cfg(target_os = "linux")]
pub(super) use user_network::Mapping;

/// What goes inside the PID namespace besides the drop: the runtime's user and
/// network namespaces ([`Runtime`], entered as `()`), or a private pair mapped
/// by the init ([`Mapping`], entered as [`Unshared`]). Sealed, so what
/// [`enter`] returns is tied by type to what it was asked to make (ADR 0007
/// D-1).
#[cfg(target_os = "linux")]
pub(super) trait Inside: sealed::Sealed + Copy {
    /// What the workload holds when [`enter`] returns in it.
    type Entered;
    /// The mapping the init serves, when there is one.
    fn mapping(&self) -> Option<&Mapping>;
    /// The return value, from the workload's end of the init's channel.
    fn entered(self, channel: Option<std::os::fd::OwnedFd>) -> std::io::Result<Self::Entered>;
}

#[cfg(target_os = "linux")]
mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Runtime {}
    impl Sealed for super::Mapping {}
}

/// The runtime's user and network namespaces: only the PID and mount
/// namespaces are the workload's own.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub(super) struct Runtime;

#[cfg(target_os = "linux")]
impl Inside for Runtime {
    type Entered = ();
    fn mapping(&self) -> Option<&Mapping> {
        None
    }
    fn entered(self, channel: Option<std::os::fd::OwnedFd>) -> std::io::Result<()> {
        match channel {
            None => Ok(()),
            Some(_) => Err(std::io::Error::from_raw_os_error(libc::EINVAL)),
        }
    }
}

/// The workload, dropped to its outer uid, in its own PID namespace and in a
/// fresh user and network namespace that is not mapped yet, holding its end
/// of the init's channel. Only [`enter`]'s workload branch mints one; the next
/// step is `Unshared::map` (`user_network.rs`).
#[cfg(target_os = "linux")]
#[must_use = "an unshared workload that is never mapped must fail its spawn, not exec"]
pub(super) struct Unshared {
    channel: std::os::fd::OwnedFd,
    mapping: Mapping,
}

/// The workload, mapped exactly `inner outer 1` for uid and gid with
/// `setgroups` denied, as it read back from the kernel. Only `Unshared::map`
/// mints one; the next step is `Mapped::shed_capabilities`.
#[cfg(target_os = "linux")]
#[must_use = "a mapped workload still holds every capability in its user namespace"]
pub(super) struct Mapped {
    _sealed: (),
}

/// The workload, mapped and holding no capability, with `SECBIT_NOROOT`
/// locked. Only `Mapped::shed_capabilities` mints one. The rest of the hook
/// (sweep, `no_new_privs`, rlimits, Landlock, the filter) follows.
#[cfg(target_os = "linux")]
#[must_use]
pub(super) struct Placed {
    _sealed: (),
}

/// `SIOC[GS]IFFLAGS` as `ioctl` takes them: `c_ulong` on glibc, `c_int` on
/// musl (the guest).
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast, reason = "c_ulong on glibc, c_int on musl")]
const SIOCGIFFLAGS: libc::Ioctl = libc::SIOCGIFFLAGS as libc::Ioctl;
#[cfg(target_os = "linux")]
#[allow(clippy::unnecessary_cast, reason = "c_ulong on glibc, c_int on musl")]
const SIOCSIFFLAGS: libc::Ioctl = libc::SIOCSIFFLAGS as libc::Ioctl;

/// Run the waiter and the init (module docs). Returns only in the workload,
/// dropped to `uid`/`gid`, in its own PID and mount namespaces and, when
/// `inside` is a [`Mapping`], in a fresh user and network namespace awaiting
/// its map ([`Unshared`]); or with the error that stopped it before the init's
/// fork.
///
/// One `unsafe` block, like `imp::harden_child`'s: the helpers are closures
/// inside it, so the audited surface is this function.
///
/// # Safety
/// Only from a `pre_exec` hook, in the child std forked, while it is still
/// root: everything here is a raw async-signal-safe syscall, and two of the
/// three processes it makes never return from it.
#[cfg(target_os = "linux")]
#[expect(
    unsafe_code,
    reason = "#3344: the namespace setup is raw syscalls in a pre_exec hook; audited with imp"
)]
pub(super) unsafe fn enter<I: Inside>(
    uid: u32,
    gid: u32,
    inside: I,
) -> std::io::Result<I::Entered> {
    use std::io;
    use std::os::fd::FromRawFd;
    let mapping = inside.mapping();
    // SAFETY: scalar and static-string arguments, and pointers to live
    // locals, to async-signal-safe syscalls in a single-threaded forked
    // child; no allocation, no lock. The one adopted descriptor is the
    // workload's end of a socketpair this function made and nothing else
    // holds in the workload.
    unsafe {
        // `clone(SIGCHLD)`: fork's semantics without libc's locks. No stack
        // and no tid pointers: the child continues on a copy of this stack.
        let fork_raw = || -> io::Result<libc::pid_t> {
            let pid = libc::syscall(
                libc::SYS_clone,
                libc::c_long::from(libc::SIGCHLD),
                0,
                0,
                0,
                0,
            );
            if pid < 0 {
                Err(io::Error::last_os_error())
            } else {
                libc::pid_t::try_from(pid)
                    .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
            }
        };
        // Every descriptor this process holds but `keep` (-1: none): std's
        // status pipe and the copies of the workload's stdio, which a process
        // that never execs would otherwise hold open for as long as it lives.
        // Without close_range (pre-5.9), close up to the limit the hook sets.
        let close_except = |keep: libc::c_int| {
            let range = |low: libc::c_int, high: libc::c_uint| {
                libc::syscall(
                    libc::SYS_close_range,
                    libc::c_long::from(low),
                    high as libc::c_long,
                    0 as libc::c_long,
                ) == 0
            };
            let closed = if keep < 0 {
                range(0, libc::c_uint::MAX)
            } else {
                (keep == 0 || range(0, keep.unsigned_abs() - 1))
                    && range(keep + 1, libc::c_uint::MAX)
            };
            if !closed {
                for fd in (0..65_536).filter(|&fd| fd != keep) {
                    libc::close(fd);
                }
            }
        };
        // Wait (for `pid`, or any child under -1) until `until` is reaped,
        // and return its status. Leaves on any error but EINTR.
        let wait_for = |pid: libc::pid_t, until: libc::pid_t| -> libc::c_int {
            let mut status: libc::c_int = 0;
            loop {
                let r = libc::waitpid(pid, &raw mut status, 0);
                if r == until {
                    return status;
                }
                if r < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    libc::_exit(127);
                }
            }
        };
        // The init's half of the map exchange: the workload's user namespace
        // must be owned by the outer uid (made by the workload once dropped),
        // and then the one line `inner outer 1` is written for uid and gid,
        // `setgroups` denied first. `/proc/<pid>` is this namespace's procfs,
        // and `workload` is the init's own unreaped child, so the number
        // cannot name another process.
        let write_map = |workload: libc::pid_t, mapping: &Mapping| -> bool {
            let mut path = [0u8; 24];
            path[..6].copy_from_slice(b"/proc/");
            let mut digits = [0u8; 10];
            let mut rest = u32::try_from(workload).unwrap_or(0);
            let mut len = 0;
            loop {
                digits[len] = b'0' + u8::try_from(rest % 10).unwrap_or(0);
                len += 1;
                rest /= 10;
                if rest == 0 {
                    break;
                }
            }
            for i in 0..len {
                path[6 + i] = digits[len - 1 - i];
            }
            let dir = libc::open(
                path.as_ptr().cast(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            );
            if dir < 0 {
                return false;
            }
            let mut owner: libc::uid_t = libc::uid_t::MAX;
            let ns = libc::openat(dir, c"ns/user".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            let mut granted = ns >= 0
                && libc::ioctl(ns, libc::NS_GET_OWNER_UID, &raw mut owner) == 0
                && owner == mapping.outer();
            if ns >= 0 {
                libc::close(ns);
            }
            for (leaf, bytes) in [
                (c"uid_map", mapping.line()),
                (c"setgroups", &b"deny\n"[..]),
                (c"gid_map", mapping.line()),
            ] {
                if !granted {
                    break;
                }
                let file = libc::openat(dir, leaf.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                granted = file >= 0
                    && usize::try_from(libc::write(file, bytes.as_ptr().cast(), bytes.len()))
                        == Ok(bytes.len());
                if file >= 0 && libc::close(file) != 0 {
                    granted = false;
                }
            }
            libc::close(dir);
            granted
        };
        // Serve exactly one request, then close. No request (the workload
        // failed before it asked) is no answer: the workload is gone.
        let serve = |channel: libc::c_int, workload: libc::pid_t, mapping: &Mapping| {
            let mut request = [0u8; 1];
            let read = loop {
                let n = libc::read(channel, request.as_mut_ptr().cast(), 1);
                if n < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break n;
            };
            if read == 1 && request[0] == user_network::REQUEST {
                let answer = [if write_map(workload, mapping) {
                    user_network::GRANTED
                } else {
                    user_network::REFUSED
                }];
                // A workload that died meanwhile must not take the init with
                // it: no SIGPIPE.
                libc::send(channel, answer.as_ptr().cast(), 1, libc::MSG_NOSIGNAL);
            }
            libc::close(channel);
        };
        // `lo` up in the workload's fresh network namespace: the only
        // interface it has, down until this runs.
        let loopback_up = || -> io::Result<()> {
            let up = libc::c_short::try_from(libc::IFF_UP)
                .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
            let socket = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if socket < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut request: libc::ifreq = std::mem::zeroed();
            std::ptr::copy_nonoverlapping(c"lo".as_ptr(), request.ifr_name.as_mut_ptr(), 3);
            let mut result = libc::ioctl(socket, SIOCGIFFLAGS, &raw mut request);
            if result == 0 {
                request.ifr_ifru.ifru_flags |= up;
                result = libc::ioctl(socket, SIOCSIFFLAGS, &raw const request);
            }
            let failure = (result != 0).then(io::Error::last_os_error);
            libc::close(socket);
            failure.map_or(Ok(()), Err)
        };

        if libc::unshare(libc::CLONE_NEWPID | libc::CLONE_NEWNS) != 0 {
            return Err(io::Error::last_os_error());
        }
        let init = fork_raw()?;
        if init > 0 {
            // The waiter: leave with the init's status, a signal death as
            // the same signal, so the runtime reads what it would have read
            // off the init.
            close_except(-1);
            let status = wait_for(init, init);
            if libc::WIFSIGNALED(status) {
                let sig = libc::WTERMSIG(status);
                libc::signal(sig, libc::SIG_DFL);
                libc::kill(libc::getpid(), sig);
                libc::_exit(128 + sig);
            }
            libc::_exit(libc::WEXITSTATUS(status));
        }
        // Pid 1. Dies with the waiter, so the runtime's kill reaches the
        // namespace. Set before anything can fail, and never cleared: this
        // process changes no credential.
        if libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        // The new mount namespace is a copy whose mounts may still propagate
        // to the runtime's; make it private before mounting over `/proc`.
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
            || libc::mount(
                c"proc".as_ptr(),
                c"/proc".as_ptr(),
                c"proc".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                PROC_OPTIONS.as_ptr().cast(),
            ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        // The channel to the workload, made here so it serves this spawn
        // and no other: [the init's end, the workload's end].
        let mut channel: [libc::c_int; 2] = [-1, -1];
        if mapping.is_some()
            && libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                channel.as_mut_ptr(),
            ) != 0
        {
            return Err(io::Error::last_os_error());
        }
        let workload = fork_raw()?;
        if workload > 0 {
            // The init: answer the workload's one map request, if it has
            // one, and only then reap every child (an orphan is reparented
            // here) until the workload exits; leave with its status, and the
            // kernel kills what is left in the namespace.
            libc::prctl(libc::PR_SET_NAME, INIT_NAME.as_ptr(), 0, 0, 0);
            close_except(channel[0]);
            if let Some(mapping) = mapping {
                serve(channel[0], workload, mapping);
            }
            let status = wait_for(-1, workload);
            if libc::WIFSIGNALED(status) {
                libc::_exit(128 + libc::WTERMSIG(status));
            }
            libc::_exit(libc::WEXITSTATUS(status));
        }
        if channel[0] >= 0 {
            libc::close(channel[0]);
        }
        // The workload: drop here, now the privileged steps are done.
        // `setresuid` from root clears every capability set.
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setresgid(gid, gid, gid) != 0
            || libc::setresuid(uid, uid, uid) != 0
        {
            return Err(io::Error::last_os_error());
        }
        // Dropped: now, and only now, a user namespace of its own (owned by
        // `uid`, which the init checks) and a network namespace inside it.
        // Non-dumpable first, so nothing of the same outer uid can open this
        // process's `/proc` files while it holds capabilities there.
        if let Some(mapping) = mapping {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
                || libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if mapping.loopback() {
                loopback_up()?;
            }
        }
        let channel = (channel[1] >= 0).then(|| std::os::fd::OwnedFd::from_raw_fd(channel[1]));
        inside.entered(channel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the guest makes a namespace; every host tier keeps the runtime's
    /// and says so.
    #[test]
    fn only_a_guest_workload_gets_its_own_pid_namespace() {
        assert_eq!(
            PidNamespace::for_workload(ContainmentMode::MicroVM),
            PidNamespace::Own
        );
        for mode in [
            ContainmentMode::Unconfigured,
            ContainmentMode::Unsandboxed,
            ContainmentMode::HostHardened,
        ] {
            assert_eq!(
                PidNamespace::for_workload(mode),
                PidNamespace::Shared,
                "{mode:?}"
            );
        }
        assert_eq!(PidNamespace::Own.canonical(), "own");
        assert_eq!(PidNamespace::Shared.canonical(), "shared");
    }
}

/// The map exchange (#3528), driven on real namespaces: the init's owner
/// check, the workload's read-back, and the closed-channel refusal. Each is
/// a check the success path cannot show, so each test is built to pass only
/// because that one check is there.
#[cfg(test)]
#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "test hooks: pre_exec closures over the production steps"
)]
mod exchange_tests {
    use std::io::{self, Read, Write};
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    use super::user_network::{GRANTED, REQUEST};
    use super::{Mapping, Unshared, enter};
    use crate::hardening::UserNamespaces;

    /// What stands in for the init.
    enum Peer {
        /// Answers granted and writes no map.
        GrantsWithoutMapping,
        /// Reads the request and closes without answering.
        ClosesAfterTheRequest,
        /// Is gone before the request is sent.
        ClosedBeforeTheRequest,
    }

    /// Whether this process may make a user namespace at all; the tests
    /// below report and return where it may not. The sysctls are not the
    /// whole answer: a test run inside a sandbox inherits its seccomp filter
    /// (a gate step under this very confinement denies `unshare`), so a child
    /// is asked to make one first, as `child_seccomp`'s user-namespace control
    /// does.
    fn userns() -> bool {
        if let UserNamespaces::Unavailable { reason } = UserNamespaces::probe() {
            eprintln!("skipped: {reason}");
            return false;
        }
        let mut control = Command::new("/bin/true");
        control.current_dir("/");
        // SAFETY: one raw `unshare` in the single-threaded forked child.
        unsafe {
            control.pre_exec(|| {
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        match control.status() {
            Ok(status) if status.success() => true,
            other => {
                eprintln!("skipped: this process may not make a user namespace: {other:?}");
                false
            }
        }
    }

    /// Spawn `/bin/true` behind a hook that makes an (unprivileged) user
    /// namespace and runs the workload's half of the exchange against `peer`
    /// instead of the init. The inner uid is 65534, which is also the
    /// overflow id an UNMAPPED process reports, so the id check alone passes
    /// without any map: only the read-back of `uid_map` can refuse.
    fn against(peer: Peer) -> io::Result<std::process::ExitStatus> {
        let (mut ours, theirs) = UnixStream::pair()?;
        // The fork copies the peer's end into the child too, as the init's
        // end would be in the workload; the child closes it, as the workload
        // does, or it never reads the end of a closed channel.
        let peer_end = ours.as_raw_fd();
        let mapping = Mapping::new(rustix::process::getuid().as_raw(), 65534, false);
        let serving = match peer {
            Peer::ClosedBeforeTheRequest => {
                drop(ours);
                None
            }
            Peer::GrantsWithoutMapping | Peer::ClosesAfterTheRequest => {
                Some(std::thread::spawn(move || {
                    let mut request = [0u8; 1];
                    if ours.read_exact(&mut request).is_ok()
                        && request[0] == REQUEST
                        && matches!(peer, Peer::GrantsWithoutMapping)
                    {
                        let _ = ours.write_all(&[GRANTED]);
                    }
                }))
            }
        };
        let open_peer = serving.is_some();
        let mut channel = Some(OwnedFd::from(theirs));
        let mut cmd = Command::new("/bin/true");
        cmd.current_dir("/");
        // SAFETY: a raw `close` of the peer's copied end and a raw `unshare`,
        // then the production exchange, which is async-signal-safe; in the
        // single-threaded forked child.
        unsafe {
            cmd.pre_exec(move || {
                if open_peer {
                    libc::close(peer_end);
                }
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let channel = channel
                    .take()
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
                Unshared { channel, mapping }.map().map(drop)
            });
        }
        let status = cmd.status();
        drop(cmd);
        if let Some(serving) = serving {
            serving.join().expect("the peer");
        }
        status
    }

    fn errno(got: io::Result<std::process::ExitStatus>) -> Option<i32> {
        match got {
            Ok(status) => panic!("the child must not exec; it ran: {status:?}"),
            Err(e) => e.raw_os_error(),
        }
    }

    /// "Granted" with no map behind it is refused by the read-back: the
    /// workload believes the kernel, not the answer.
    #[test]
    fn a_grant_without_a_map_is_refused_by_the_read_back() {
        if !userns() {
            return;
        }
        assert_eq!(
            errno(against(Peer::GrantsWithoutMapping)),
            Some(libc::EACCES)
        );
    }

    /// A channel closed with no answer is `EPIPE` (507f0c042's closed-mapper
    /// refusal), and so is one closed before the request is even sent: an
    /// error through std's status pipe, not a `SIGPIPE` that kills the child
    /// before it can report.
    #[test]
    fn a_closed_channel_is_refused_as_epipe_not_killed_by_sigpipe() {
        if !userns() {
            return;
        }
        assert_eq!(
            errno(against(Peer::ClosesAfterTheRequest)),
            Some(libc::EPIPE)
        );
        assert_eq!(
            errno(against(Peer::ClosedBeforeTheRequest)),
            Some(libc::EPIPE)
        );
    }

    /// The init maps a namespace only if the outer uid owns it. Here the
    /// workload drops to 65534 and the map was prepared for 4242, inner
    /// 65534: the kernel would accept the write (the init is root), the
    /// read-back would match it, and an unmapped 65534 would pass the id
    /// check, so the owner check is the one thing that refuses. The control
    /// is the same exchange with the map prepared for 65534.
    #[test]
    fn the_init_refuses_to_map_a_namespace_the_outer_uid_does_not_own() {
        if rustix::process::getuid().as_raw() != 0 {
            eprintln!("skipped: the init's half needs a root runtime");
            return;
        }
        if !userns() {
            return;
        }
        let run = |mapping: Mapping| {
            let mut cmd = Command::new("/bin/true");
            cmd.current_dir("/");
            // SAFETY: the production hook steps, as root, in the forked child.
            unsafe {
                cmd.pre_exec(move || {
                    enter(65534, 65534, mapping)?
                        .map()?
                        .shed_capabilities()
                        .map(drop)
                });
            }
            cmd.status()
        };
        assert!(
            run(Mapping::new(65534, 65534, false))
                .expect("control: the outer uid's own namespace is mapped")
                .success()
        );
        assert_eq!(
            errno(run(Mapping::new(4242, 65534, false))),
            Some(libc::EACCES)
        );
    }
}
