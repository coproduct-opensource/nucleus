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

use crate::command::ContainmentMode;

/// Requested namespaces; admission and the installed hook must agree on all coordinates.
#[derive(Debug, Clone, Copy)]
pub struct NamespaceRequest {
    /// Whether the workload gets a private process table.
    pub pids: PidNamespace,
    /// Which network interfaces the child may reach.
    pub network: NetworkNamespace,
    /// Optional single-ID map of the already-dropped outer UID/GID.
    pub user_namespace_uid: Option<u32>,
}

/// Parent-compiled single-ID maps. No formatting or allocation after fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UidMapping {
    pub(super) inner: u32,
    uid: [u8; 32],
    uid_len: usize,
    gid: [u8; 32],
    gid_len: usize,
}

impl UidMapping {
    pub(super) fn compile(inner: u32, uid: u32, gid: u32) -> std::io::Result<Self> {
        if inner == 0 || inner == u32::MAX {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
        }
        let uid_text = format!("{inner} {uid} 1\n");
        let gid_text = format!("{inner} {gid} 1\n");
        let mut mapping = Self {
            inner,
            uid: [0; 32],
            uid_len: uid_text.len(),
            gid: [0; 32],
            gid_len: gid_text.len(),
        };
        mapping.uid[..mapping.uid_len].copy_from_slice(uid_text.as_bytes());
        mapping.gid[..mapping.gid_len].copy_from_slice(gid_text.as_bytes());
        Ok(mapping)
    }
}

/// The network a trusted launcher creates before dropping and filtering a child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkNamespace {
    /// Preserve the pod's network; the existing default.
    Shared,
    /// A fresh namespace with every interface down and no routes.
    PrivateOffline,
    /// A fresh namespace with only its loopback interface enabled.
    PrivateLoopback,
}

impl NetworkNamespace {
    /// The spelling bound into the launch receipt.
    #[must_use]
    pub fn canonical(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::PrivateOffline => "private_offline",
            Self::PrivateLoopback => "private_loopback",
        }
    }
}

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

/// Run the waiter and the init (module docs). Returns only in the workload,
/// dropped to `uid`/`gid` and in its own PID and mount namespaces, or with the
/// error that stopped it before the init's fork.
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
pub(super) unsafe fn enter(
    uid: u32,
    gid: u32,
    network: NetworkNamespace,
    mapping: Option<UidMapping>,
) -> std::io::Result<()> {
    use std::io;
    // SAFETY: scalar and static-string arguments, and pointers to live
    // locals, to async-signal-safe syscalls in a single-threaded forked
    // child; no allocation, no lock.
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
        // Every descriptor this process holds: std's status pipe and the
        // copies of the workload's stdio, which a process that never execs
        // would otherwise hold open for as long as it lives. Without
        // close_range (pre-5.9), close up to the limit the hook sets.
        let close_everything = || {
            if libc::syscall(
                libc::SYS_close_range,
                0 as libc::c_long,
                libc::c_uint::MAX as libc::c_long,
                0 as libc::c_long,
            ) != 0
            {
                for fd in 0..65_536 {
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

        let net_flags = match network {
            NetworkNamespace::Shared => 0,
            NetworkNamespace::PrivateOffline | NetworkNamespace::PrivateLoopback => {
                libc::CLONE_NEWNET
            }
        };
        if libc::unshare(libc::CLONE_NEWPID | libc::CLONE_NEWNS | net_flags) != 0 {
            return Err(io::Error::last_os_error());
        }
        if network == NetworkNamespace::PrivateLoopback {
            // Raw syscalls only in this forked child. The socket belongs to
            // the new namespace and never crosses the eventual exec.
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut request: libc::ifreq = std::mem::zeroed();
            request.ifr_name[0] = b'l' as libc::c_char;
            request.ifr_name[1] = b'o' as libc::c_char;
            let result = if libc::ioctl(fd, libc::SIOCGIFFLAGS, &raw mut request) != 0 {
                Err(io::Error::last_os_error())
            } else {
                request.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
                if libc::ioctl(fd, libc::SIOCSIFFLAGS, &raw const request) != 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            };
            libc::close(fd);
            result?;
        }
        let init = fork_raw()?;
        if init > 0 {
            // The waiter: leave with the init's status, a signal death as
            // the same signal, so the runtime reads what it would have read
            // off the init.
            close_everything();
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
        let workload = fork_raw()?;
        if workload > 0 {
            // The init: reap every child (an orphan is reparented here)
            // until the workload exits, then leave with its status; the
            // kernel kills what is left in the namespace.
            libc::prctl(libc::PR_SET_NAME, INIT_NAME.as_ptr(), 0, 0, 0);
            close_everything();
            let status = wait_for(-1, workload);
            if libc::WIFSIGNALED(status) {
                libc::_exit(128 + libc::WTERMSIG(status));
            }
            libc::_exit(libc::WEXITSTATUS(status));
        }
        // The workload: drop here, now the privileged steps are done.
        // `setresuid` from root clears every capability set.
        if libc::setgroups(0, std::ptr::null()) != 0
            || libc::setresgid(gid, gid, gid) != 0
            || libc::setresuid(uid, uid, uid) != 0
        {
            return Err(io::Error::last_os_error());
        }
        if let Some(mapping) = mapping {
            // Map only our already-unprivileged outer identity. A one-ID map
            // is available without privilege in the parent user namespace.
            // Restore ownership of our own proc map files after setresuid;
            // the runtime stays sealed in a different PID namespace.
            if libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) != 0
                || libc::unshare(libc::CLONE_NEWUSER) != 0
            {
                return Err(io::Error::last_os_error());
            }
            let write_map = |path: &std::ffi::CStr, bytes: &[u8]| -> io::Result<()> {
                let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let written = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
                let result = if written < 0 {
                    Err(io::Error::last_os_error())
                } else if written as usize != bytes.len() {
                    Err(io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                };
                libc::close(fd);
                result
            };
            write_map(c"/proc/self/uid_map", &mapping.uid[..mapping.uid_len])?;
            write_map(c"/proc/self/setgroups", b"deny\n")?;
            write_map(c"/proc/self/gid_map", &mapping.gid[..mapping.gid_len])?;
            // Creating a user namespace grants namespace-local capabilities.
            // Relinquish them explicitly, before Landlock and seccomp, even
            // though the nonzero UID and no_new_privs would strip them at exec.
            #[repr(C)]
            struct Header {
                version: u32,
                pid: i32,
            }
            #[repr(C)]
            struct Data {
                effective: u32,
                permitted: u32,
                inheritable: u32,
            }
            let header = Header {
                version: 0x2008_0522,
                pid: 0,
            };
            let data = [
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
                Data {
                    effective: 0,
                    permitted: 0,
                    inheritable: 0,
                },
            ];
            if libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) != 0
                || libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
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
