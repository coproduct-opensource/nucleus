//! The VMM a Firecracker launch supervises, tracked by the pid its jail recorded (#2571).
//!
//! # Why the spawned child is not the VMM
//!
//! `jailer --new-pid-ns` puts Firecracker in a new pid namespace as that namespace's init. In
//! v1.17.0 (`src/jailer/src/env.rs`, `exec_into_new_pid_ns`) the jailer `clone`s with
//! `CLONE_NEWPID`, writes the clone's pid to `<jail root>/<exec>.pid`, and exits 0. So the
//! process the node spawned exits within milliseconds. Before this module, every consumer took
//! the spawned child's pid: the seccomp check, `nsenter` for the egress chain and the drift
//! monitor, `kill` on every failure path, the reaper's exit detection, and the SIGTERM drain.
//! With the flag, all of them would act on a dead jailer. The launch would abort at the seccomp
//! check, or a running pod would read as exited.
//!
//! # The rule
//!
//! [`VmmPid`] and [`VmmProcess`] have private constructors (ADR 0007 C-1) and are minted only
//! here, by the code that checks them (C-2). The launch arm that builds the command says which
//! kind of process it starts ([`Launch`]):
//!
//! - **Jailed.** The pid comes only from the jail's pid file, read after the jailer has exited
//!   successfully. Before it is accepted, a pidfd is opened on it, and the process must be
//!   pid 1 of its own pid namespace and carry this jail's `--id`. The pidfd then performs every
//!   kill and wait, so a recycled pid is never signalled.
//! - **Direct** (the unjailed development path). The spawned program is Firecracker itself, or
//!   `ip netns exec`, which `exec`s it in place, so the child is the VMM.
//!
//! A jailed launch cannot become a [`VmmProcess`] any other way. A raw `u32` from `Child::id`
//! cannot be passed where the VMM's pid is meant, because those consumers take a [`VmmPid`].
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use tokio::process::{Child, Command};

use crate::ApiError;
use crate::firecracker_config::JailLayout;

/// How long the jailer has to hand the VMM off: build the chroot, apply the cgroup and limits,
/// clone, write the pid file, and exit. That takes milliseconds. The bound exists so that a
/// jailer that never exits becomes a named launch failure instead of a launch that never ends.
pub(crate) const JAILER_HANDOFF: Duration = Duration::from_secs(10);

/// The VMM's pid in the node's pid namespace. See the module docs for how one is minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VmmPid(u32);

impl VmmPid {
    pub(crate) fn get(self) -> u32 {
        self.0
    }

    /// A pid for a test that needs a value of this type and never signals it.
    #[cfg(test)]
    pub(crate) fn for_test(pid: u32) -> Self {
        Self(pid)
    }
}

impl fmt::Display for VmmPid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Parse the jailer's pid file: one decimal pid and nothing else (it writes `{pid}` with no
/// newline). An empty file, a sign, a zero or trailing text means the jailer did not write it,
/// so it is refused (ADR 0007 I-2: parse to a type).
pub(crate) fn parse_pid_file(text: &str) -> Result<VmmPid, Handoff> {
    let malformed = || Handoff::PidFileMalformed(text.chars().take(64).collect());
    let digits = text.strip_suffix('\n').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed());
    }
    match digits.parse::<u32>() {
        Ok(0) | Err(_) => Err(malformed()),
        Ok(pid) => Ok(VmmPid(pid)),
    }
}

/// The `NSpid:` field of `/proc/<pid>/status`: the process's pid in each pid namespace it is in,
/// from the reader's namespace down to its own.
pub(crate) fn parse_nspid(status: &str) -> Option<Vec<u32>> {
    let line = status.lines().find_map(|l| l.strip_prefix("NSpid:"))?;
    let pids = line
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<Vec<u32>, _>>()
        .ok()?;
    (!pids.is_empty()).then_some(pids)
}

/// Whether an `NSpid` chain is the init of a pid namespace below the reader's: at least two
/// levels, with pid 1 in the innermost one. This is what `--new-pid-ns` produces.
pub(crate) fn is_namespace_init(nspid: &[u32]) -> bool {
    nspid.len() >= 2 && nspid.last() == Some(&1)
}

/// Whether a `/proc/<pid>/cmdline` carries `--id <jail id>` as two adjacent arguments. Both the
/// jailer and the Firecracker it `exec`s carry it, so the check holds before and after `exec`.
pub(crate) fn carries_jail_id(cmdline: &[u8], jail_id: &str) -> bool {
    cmdline
        .split(|b| *b == 0)
        .collect::<Vec<_>>()
        .windows(2)
        .any(|w| w[0] == b"--id" && w[1] == jail_id.as_bytes())
}

/// Why a jailed launch has no VMM to supervise. Each case is named, so the error says which
/// step of the handoff failed (ADR 0007 A-4: no single catch-all variant).
#[derive(Debug, thiserror::Error)]
pub(crate) enum Handoff {
    #[error(
        "the jailer did not hand off the VMM within {}s (no exit after spawn); it was killed",
        .0.as_secs()
    )]
    Timeout(Duration),
    #[error("the jailer exited {0} before handing off the VMM; its stderr is in firecracker.log")]
    JailerFailed(ExitStatus),
    #[error("the jailer exited 0 but its pid file {} is unreadable: {error}", .path.display())]
    PidFileUnreadable {
        path: PathBuf,
        error: std::io::Error,
    },
    #[error("the jailer's pid file holds {0:?}, which is not a pid")]
    PidFileMalformed(String),
    #[error("the VMM (pid {0}) exited before the node could supervise it; see firecracker.log")]
    VmmGone(VmmPid),
    #[error(
        "pid {pid} is not the init of its own pid namespace (NSpid {nspid:?}); the jailer was \
         expected to run it under --new-pid-ns"
    )]
    NotNamespaceInit {
        pid: VmmPid,
        nspid: Option<Vec<u32>>,
    },
    #[error("pid {pid} does not carry --id {jail_id}, so it is not this jail's VMM")]
    NotThisJail { pid: VmmPid, jail_id: String },
    #[error("the VMM's process state could not be observed: {0}")]
    Unobservable(std::io::Error),
    #[cfg(not(target_os = "linux"))]
    #[error("a jailed launch needs Linux")]
    Unsupported,
}

impl From<Handoff> for ApiError {
    fn from(handoff: Handoff) -> Self {
        ApiError::Driver(format!("jailed launch failed: {handoff}"))
    }
}

/// How the VMM's process is started. The launch arm that builds the command decides this, so
/// a jailer's child can never be taken for the VMM.
pub(crate) enum Launch {
    /// Under the jailer, which hands the VMM off and exits.
    Jailed {
        command: Command,
        pid_file: PathBuf,
        jail_id: String,
        /// The jail's cgroup, killed whole if the handoff fails after the jailer may have cloned.
        cgroup: Option<PathBuf>,
    },
    /// Firecracker itself, or `ip netns exec`, which `exec`s it in place.
    Direct(Command),
}

impl Launch {
    /// A jailed launch. The pid file is where the jailer writes it: `<exec file name>.pid` in the
    /// jail root, the exec file being the copy of `firecracker_path` it puts there.
    pub(crate) fn jailed(
        command: Command,
        layout: &JailLayout,
        firecracker_path: &Path,
        jail_id: &str,
    ) -> Self {
        Launch::Jailed {
            command,
            pid_file: layout.vmm_pid_file(firecracker_path),
            jail_id: jail_id.to_string(),
            cgroup: crate::jail_reclaim::jailer_cgroup_dir(
                Path::new(crate::jail_reclaim::CGROUP_ROOT),
                layout,
            ),
        }
    }

    pub(crate) fn command_mut(&mut self) -> &mut Command {
        match self {
            Launch::Jailed { command, .. } | Launch::Direct(command) => command,
        }
    }

    /// Spawn the command and resolve the process that is the VMM.
    pub(crate) async fn start(
        self,
        spawn: impl FnOnce(&mut Command) -> std::io::Result<Child>,
    ) -> Result<VmmProcess, ApiError> {
        let spawn_failed =
            |err: std::io::Error| ApiError::Driver(format!("failed to spawn firecracker: {err}"));
        match self {
            Launch::Direct(mut command) => {
                let child = spawn(&mut command).map_err(spawn_failed)?;
                let pid = child
                    .id()
                    .ok_or_else(|| ApiError::Driver("firecracker exited at spawn".to_string()))?;
                Ok(VmmProcess {
                    pid: VmmPid(pid),
                    kind: Kind::Direct(child),
                })
            }
            Launch::Jailed {
                mut command,
                pid_file,
                jail_id,
                cgroup,
            } => {
                let jailer = spawn(&mut command).map_err(spawn_failed)?;
                let resolved = handoff(jailer, &pid_file, &jail_id, JAILER_HANDOFF).await;
                // A failed handoff may follow the clone: kill everything in the jail's cgroup,
                // so a VMM the node will not supervise is not left running.
                if resolved.is_err()
                    && let Some(cgroup) = cgroup
                    && let Err(error) = crate::jail_reclaim::kill_cgroup(&cgroup)
                {
                    tracing::error!(%error, cgroup = %cgroup.display(), "failed handoff could not kill its jail's cgroup");
                }
                Ok(resolved?)
            }
        }
    }
}

/// How a VMM ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VmmExit {
    /// The node reaped it and read its status.
    Status(ExitStatus),
    /// It exited and another parent reaped it. Under `--new-pid-ns` the jailer exits first, so
    /// the VMM is reparented to the nearest subreaper or init, and only that process can read
    /// its status. When the node is that process (it is PID 1 in the host container), the
    /// status is read.
    Unobserved,
}

impl VmmExit {
    pub(crate) fn code(self) -> Option<i32> {
        match self {
            VmmExit::Status(status) => status.code(),
            VmmExit::Unobserved => None,
        }
    }
}

impl fmt::Display for VmmExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmmExit::Status(status) => status.fmt(f),
            VmmExit::Unobserved => f.write_str("exited; status held by its reaper"),
        }
    }
}

/// The VMM, with the means to observe and stop it. Dropping it kills the VMM, as `kill_on_drop`
/// did for the direct child.
#[derive(Debug)]
pub(crate) struct VmmProcess {
    pid: VmmPid,
    kind: Kind,
}

#[derive(Debug)]
enum Kind {
    Direct(Child),
    #[cfg(target_os = "linux")]
    Jailed(pidfd::PidFd),
}

impl VmmProcess {
    pub(crate) fn pid(&self) -> VmmPid {
        self.pid
    }

    /// Whether it has exited, without blocking. An exit is reaped when the node is its parent.
    pub(crate) fn try_wait(&mut self) -> std::io::Result<Option<VmmExit>> {
        match &mut self.kind {
            Kind::Direct(child) => Ok(child.try_wait()?.map(VmmExit::Status)),
            #[cfg(target_os = "linux")]
            Kind::Jailed(fd) => fd.try_wait(),
        }
    }

    /// Wait for it to exit. Cancel-safe: a dropped wait leaves the process as it was.
    pub(crate) async fn wait(&mut self) -> std::io::Result<VmmExit> {
        match &mut self.kind {
            Kind::Direct(child) => Ok(VmmExit::Status(child.wait().await?)),
            #[cfg(target_os = "linux")]
            Kind::Jailed(fd) => fd.wait().await,
        }
    }

    /// SIGKILL it and wait for it to exit. Killing a VMM that has already exited is not an
    /// error for a jailed VMM; for a direct child it is, as `Child::kill` reports.
    pub(crate) async fn kill(&mut self) -> std::io::Result<()> {
        match &mut self.kind {
            Kind::Direct(child) => child.kill().await,
            #[cfg(target_os = "linux")]
            Kind::Jailed(fd) => {
                fd.kill()?;
                fd.wait().await.map(drop)
            }
        }
    }

    /// A process that stands in for the VMM in a test: the child is the VMM.
    #[cfg(test)]
    pub(crate) fn direct_for_test(child: Child) -> Self {
        let pid = VmmPid(child.id().expect("a live test child"));
        Self {
            pid,
            kind: Kind::Direct(child),
        }
    }

    /// A process the node did not spawn, supervised through a pidfd as a jailed VMM is, without
    /// the namespace and jail-id checks only a real jailer can satisfy.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn adopt_for_test(pid: u32) -> Self {
        let pid = VmmPid(pid);
        let fd = pidfd::PidFd::open(pid).expect("a pidfd on a live test process");
        Self {
            pid,
            kind: Kind::Jailed(fd),
        }
    }
}

/// Wait for the jailer to exit, then mint the VMM from its pid file. On failure the caller kills
/// everything in the jail's cgroup.
#[cfg(target_os = "linux")]
async fn handoff(
    mut jailer: Child,
    pid_file: &Path,
    jail_id: &str,
    within: Duration,
) -> Result<VmmProcess, Handoff> {
    let status = match tokio::time::timeout(within, jailer.wait()).await {
        Ok(status) => status.map_err(Handoff::Unobservable)?,
        Err(_) => {
            let _ = jailer.kill().await;
            return Err(Handoff::Timeout(within));
        }
    };
    if !status.success() {
        return Err(Handoff::JailerFailed(status));
    }
    let text = std::fs::read_to_string(pid_file).map_err(|error| Handoff::PidFileUnreadable {
        path: pid_file.to_path_buf(),
        error,
    })?;
    let pid = parse_pid_file(&text)?;
    let fd = pidfd::PidFd::open(pid)?;
    // Read through /proc only while the pidfd is open, then confirm through the pidfd that the
    // process had not exited: what was read belongs to the process the pidfd names, not to a
    // later holder of the same pid.
    let proc_dir = Path::new("/proc").join(pid.get().to_string());
    let status = std::fs::read_to_string(proc_dir.join("status"));
    let cmdline = std::fs::read(proc_dir.join("cmdline"));
    if fd.try_exit_now()? {
        return Err(Handoff::VmmGone(pid));
    }
    let nspid = parse_nspid(&status.map_err(Handoff::Unobservable)?);
    if !nspid.as_deref().is_some_and(is_namespace_init) {
        return Err(Handoff::NotNamespaceInit { pid, nspid });
    }
    if !carries_jail_id(&cmdline.map_err(Handoff::Unobservable)?, jail_id) {
        return Err(Handoff::NotThisJail {
            pid,
            jail_id: jail_id.to_string(),
        });
    }
    Ok(VmmProcess {
        pid,
        kind: Kind::Jailed(fd),
    })
}

#[cfg(not(target_os = "linux"))]
async fn handoff(
    _jailer: Child,
    _pid_file: &Path,
    _jail_id: &str,
    _within: Duration,
) -> Result<VmmProcess, Handoff> {
    Err(Handoff::Unsupported)
}

/// The pidfd half: Linux 5.3 for `pidfd_open` and poll, 5.4 for `waitid(P_PIDFD)`.
#[cfg(target_os = "linux")]
mod pidfd {
    use std::os::fd::{AsFd, OwnedFd};

    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
    use rustix::io::Errno;
    use rustix::process::{Pid, PidfdFlags, Signal, pidfd_open, pidfd_send_signal};
    use std::os::unix::process::ExitStatusExt;
    use tokio::io::unix::AsyncFd;

    use super::{Handoff, VmmExit, VmmPid};

    #[derive(Debug)]
    pub(super) struct PidFd {
        fd: AsyncFd<OwnedFd>,
        exit: Option<VmmExit>,
    }

    impl PidFd {
        pub(super) fn open(pid: VmmPid) -> Result<Self, Handoff> {
            let raw = i32::try_from(pid.get())
                .ok()
                .and_then(Pid::from_raw)
                .ok_or_else(|| Handoff::PidFileMalformed(pid.get().to_string()))?;
            let owned = pidfd_open(raw, PidfdFlags::empty()).map_err(|errno| match errno {
                Errno::SRCH => Handoff::VmmGone(pid),
                errno => Handoff::Unobservable(errno.into()),
            })?;
            let fd = AsyncFd::with_interest(owned, tokio::io::Interest::READABLE)
                .map_err(Handoff::Unobservable)?;
            Ok(Self { fd, exit: None })
        }

        /// Whether the process has exited, by polling the pidfd without blocking. A pidfd
        /// becomes readable when its process exits.
        pub(super) fn try_exit_now(&self) -> Result<bool, Handoff> {
            exited_now(&self.fd).map_err(Handoff::Unobservable)
        }

        pub(super) fn try_wait(&mut self) -> std::io::Result<Option<VmmExit>> {
            if let Some(exit) = self.exit {
                return Ok(Some(exit));
            }
            if !exited_now(&self.fd)? {
                return Ok(None);
            }
            Ok(Some(self.reap()))
        }

        pub(super) async fn wait(&mut self) -> std::io::Result<VmmExit> {
            if let Some(exit) = self.exit {
                return Ok(exit);
            }
            // Readiness is level-triggered for an exited process; the guard is dropped without
            // clearing it, so a later wait sees the same answer.
            drop(self.fd.readable().await?);
            Ok(self.reap())
        }

        /// SIGKILL through the pidfd, never by pid. A process that has already exited is not
        /// an error: the caller's wait observes it.
        pub(super) fn kill(&self) -> std::io::Result<()> {
            if self.exit.is_some() {
                return Ok(());
            }
            match pidfd_send_signal(self.fd.get_ref(), Signal::KILL) {
                Ok(()) | Err(Errno::SRCH) => Ok(()),
                Err(errno) => Err(errno.into()),
            }
        }

        /// Read its status if the node is its parent, which reaps it. Any other parent (init, a
        /// subreaper) reaps it itself, and its status is not the node's to read.
        fn reap(&mut self) -> VmmExit {
            let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOHANG;
            let exit = match waitid(Id::PIDFd(self.fd.get_ref().as_fd()), flags) {
                Ok(WaitStatus::Exited(_, code)) => {
                    VmmExit::Status(std::process::ExitStatus::from_raw((code & 0xff) << 8))
                }
                Ok(WaitStatus::Signaled(_, signal, core)) => VmmExit::Status(
                    std::process::ExitStatus::from_raw(signal as i32 | if core { 0x80 } else { 0 }),
                ),
                _ => VmmExit::Unobserved,
            };
            self.exit = Some(exit);
            exit
        }
    }

    fn exited_now(fd: &AsyncFd<OwnedFd>) -> std::io::Result<bool> {
        let mut fds = [PollFd::new(fd.get_ref().as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut fds, PollTimeout::ZERO)?;
        Ok(ready > 0)
    }

    impl Drop for PidFd {
        /// `kill_on_drop` for a process the node did not spawn directly.
        fn drop(&mut self) {
            if self.exit.is_none()
                && let Err(error) = self.kill()
            {
                tracing::error!(%error, "dropped VMM handle could not kill its VMM");
            }
        }
    }
}

#[cfg(test)]
#[path = "vmm_process_tests.rs"]
mod tests;
