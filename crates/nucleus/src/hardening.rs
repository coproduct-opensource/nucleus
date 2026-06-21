//! OS-level guest hardening for spawned subprocesses (most-paranoid #2).
//!
//! Applied via a `pre_exec` hook on Linux when the [`Executor`](crate::Executor)
//! runs in [`ContainmentMode::HostHardened`](crate::ContainmentMode::HostHardened).
//! This is defense-in-depth *inside* the isolation boundary; the fail-closed
//! isolation gate in [`crate::command`] is the primary control.
//!
//! Currently installs (Linux only):
//!   - `PR_SET_NO_NEW_PRIVS` — the child can never gain privileges via
//!     setuid/setgid binaries or file capabilities across `exec`.
//!   - Resource limits (`RLIMIT_NPROC`/`RLIMIT_NOFILE`/`RLIMIT_FSIZE`/`RLIMIT_CPU`)
//!     to contain fork bombs, descriptor exhaustion, disk fills and runaway CPU.
//!
//! ## Deliberately deferred (tracked follow-up)
//!
//! seccomp-bpf syscall allowlisting (via `seccompiler`) and Landlock filesystem
//! confinement (via `landlock`) are NOT shipped here. A wrong seccomp allowlist
//! either fails open or breaks all execution, and this is security code that
//! cannot be compiled or exercised on a non-Linux developer host — so it must be
//! authored and validated under Linux CI rather than shipped unverified. See the
//! Move 2 PR notes and `SECURITY_TODO.md`.
//!
//! On non-Linux platforms the Executor's `attest_containment` returns
//! `HardeningUnavailable` *before* any spawn, so the apply paths below are never
//! reached off Linux. The non-Linux stub exists only so the crate compiles.

/// Marker for the host-hardening capability. Construction is infallible; the
/// per-spawn `pre_exec` hook is what actually enforces (and reports failure to
/// the parent, which aborts the spawn — fail-closed).
pub(crate) struct HostSandbox;

#[cfg(target_os = "linux")]
// The crate denies `unsafe_code` globally; this module is the single, audited
// exception. OS-level guest hardening is intrinsically `unsafe` FFI: it calls
// `prctl`/`setrlimit` and installs a `pre_exec` hook (which must be
// async-signal-safe). Every `unsafe` block below carries a SAFETY justification.
#[allow(unsafe_code)]
mod imp {
    use std::io;
    use std::os::unix::process::CommandExt;

    // Generous-but-bounded limits: contain abuse without breaking normal
    // build/test workloads. Tune via policy in a follow-up.
    const RLIMIT_NPROC_MAX: libc::rlim_t = 512;
    const RLIMIT_NOFILE_MAX: libc::rlim_t = 4096;
    const RLIMIT_FSIZE_MAX: libc::rlim_t = 8 * 1024 * 1024 * 1024; // 8 GiB
    const RLIMIT_CPU_SECS: libc::rlim_t = 3600; // 1 hour of CPU time

    fn set_rlimit(resource: libc::__rlimit_resource_t, limit: libc::rlim_t) -> io::Result<()> {
        let rl = libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        };
        // SAFETY: `rl` is a fully-initialized rlimit; `setrlimit` is
        // async-signal-safe and takes a pointer to it by const reference.
        if unsafe { libc::setrlimit(resource, &rl) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Child-side hardening, run after fork and before exec.
    ///
    /// MUST be async-signal-safe: only raw syscalls, no allocation, no locks.
    /// Any `Err` returned here causes the parent's spawn to fail (fail-closed):
    /// the child never execs the target program.
    fn harden_child() -> io::Result<()> {
        // No new privileges: defeats setuid/setgid/file-capability escalation and
        // is a prerequisite for unprivileged seccomp (future).
        // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is async-signal-safe.
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        set_rlimit(libc::RLIMIT_NPROC, RLIMIT_NPROC_MAX)?;
        set_rlimit(libc::RLIMIT_NOFILE, RLIMIT_NOFILE_MAX)?;
        set_rlimit(libc::RLIMIT_FSIZE, RLIMIT_FSIZE_MAX)?;
        set_rlimit(libc::RLIMIT_CPU, RLIMIT_CPU_SECS)?;
        Ok(())
    }

    pub(crate) fn harden_std(cmd: &mut std::process::Command) {
        // SAFETY: `harden_child` only invokes async-signal-safe syscalls and does
        // not allocate, satisfying `pre_exec`'s contract.
        unsafe {
            cmd.pre_exec(harden_child);
        }
    }

    #[cfg(feature = "async")]
    pub(crate) fn harden_tokio(cmd: &mut tokio::process::Command) {
        // SAFETY: see `harden_std`.
        unsafe {
            cmd.pre_exec(harden_child);
        }
    }
}

impl HostSandbox {
    /// Attach the hardening `pre_exec` hook to a synchronous command.
    /// No-op on non-Linux (never reached: the gate fails closed first).
    #[allow(unused_variables)]
    pub(crate) fn harden_std(cmd: &mut std::process::Command) {
        #[cfg(target_os = "linux")]
        imp::harden_std(cmd);
    }

    /// Attach the hardening `pre_exec` hook to an async (tokio) command.
    #[cfg(feature = "async")]
    #[allow(unused_variables)]
    pub(crate) fn harden_tokio(cmd: &mut tokio::process::Command) {
        #[cfg(target_os = "linux")]
        imp::harden_tokio(cmd);
    }
}
