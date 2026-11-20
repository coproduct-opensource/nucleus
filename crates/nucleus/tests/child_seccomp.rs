//! The workload syscall filter, observed on a REAL confined child
//! (#2696 P3b; the exposure was measured in #3148).
//!
//! Each test spawns this test binary again as the child, confined by
//! `ChildConfinement::apply` exactly as the tool-proxy's workload and the
//! Executor's `/v1/run` children are. The child runs one operation, selected by
//! an environment variable, and prints its result on one line. Nothing here
//! goes around the public API: on a tree without the filter these tests
//! compile unchanged and fail (A-19).
//!
//! What runs depends on the runtime's uid, because the confinement does:
//!
//! * non-root: `HostHardened` (restricted at the runtime's uid);
//! * root: `MicroVM` and `HostHardened` (both drop to 65534). The child binary
//!   is copied somewhere uid 65534 can execute it.
//!
//! Run it both ways: `cargo test -p nucleus --test child_seccomp`, then the
//! built binary under `sudo`.
//!
//! The pod's DERIVED classes (#2907) are checked the same way: a child under a
//! policy derived from `run_bash: never` is started (through the exec pin) and
//! then cannot exec; one derived from `web_fetch: never` with no egress cannot
//! open an internet socket. Each has a control under the policy that derives
//! nothing, so the denial is the derived class's and not the host's.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;

use nucleus::portcullis::{
    CapabilityLattice, CapabilityLevel, NetworkEgress, PermissionLattice, SeccompPolicy,
};
use nucleus::{
    ChildConfinement, ContainmentMode, LandlockWaiver, NamespaceSetup, PidNamespace,
    UnsandboxedOptIn, UserNamespaces,
};

const OP_ENV: &str = "NUCLEUS_CHILD_SECCOMP_OP";
const RESULT: &str = "CHILD_SECCOMP_RESULT ";

// ---------------------------------------------------------------- child side

/// The child's entry point. A no-op when run as an ordinary test.
#[test]
fn child_entry() {
    let Ok(op) = std::env::var(OP_ENV) else {
        return;
    };
    let result = run_op(&op);
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{RESULT}{result}");
    let _ = out.flush();
    std::process::exit(0);
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn rendered(rc: libc::c_long) -> String {
    if rc >= 0 {
        "ok".to_string()
    } else {
        format!("errno={}", errno())
    }
}

/// Wait for `pid` and return its exit code, or `-signal`.
fn reap(pid: libc::pid_t) -> i32 {
    let mut status = 0;
    // SAFETY: waits on a child this process just created.
    let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if rc != pid {
        return -1000;
    }
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -libc::WTERMSIG(status)
    }
}

fn seccomp_filters() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|l| l.strip_prefix("Seccomp_filters:"))
        .map_or_else(|| "unreadable".to_string(), |v| v.trim().to_string())
}

fn run_op(op: &str) -> String {
    match op {
        "filters" => format!("filters={}", seccomp_filters()),
        // #3528: who the child is, as its own kernel answers.
        "placement" => placement(),
        "vsock" => {
            // SAFETY: plain syscall; the fd is closed below.
            let fd =
                unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            let r = rendered(libc::c_long::from(fd));
            if fd >= 0 {
                // SAFETY: closes the fd opened above.
                unsafe { libc::close(fd) };
            }
            r
        }
        // In a single-threaded fork: the kernel refuses CLONE_NEWUSER to a
        // threaded caller (EINVAL), which would hide the real answer.
        "unshare_userns" => {
            // SAFETY: the forked child makes one syscall and `_exit`s.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // SAFETY: plain syscall in the forked child.
                let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
                let code = if rc == 0 { 0 } else { errno().clamp(1, 250) };
                // SAFETY: in the forked child.
                unsafe { libc::_exit(code) };
            }
            if pid < 0 {
                return rendered(-1);
            }
            match reap(pid) {
                0 => "ok".to_string(),
                e if e > 0 => format!("errno={e}"),
                sig => format!("signal={}", -sig),
            }
        }
        "clone_newuser" => {
            let flags = libc::c_ulong::try_from(libc::CLONE_NEWUSER | libc::SIGCHLD).unwrap();
            // SAFETY: a fork-like raw clone (no new stack); the child only
            // calls `_exit`.
            let pid = unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) };
            if pid == 0 {
                // SAFETY: in the cloned child.
                unsafe { libc::_exit(0) };
            }
            if pid > 0 {
                reap(libc::pid_t::try_from(pid).unwrap());
            }
            rendered(pid)
        }
        // In a single-threaded fork: this harness is multithreaded, and a
        // traced multithreaded process cannot finish exiting until its tracer
        // (our parent, which only waits for the leader) reaps every thread.
        "ptrace" => {
            // SAFETY: the forked child makes one syscall and `_exit`s.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // SAFETY: plain syscalls in the forked child.
                let rc = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
                let code = if rc == 0 { 0 } else { errno().clamp(1, 250) };
                // SAFETY: in the forked child.
                unsafe { libc::_exit(code) };
            }
            if pid < 0 {
                return rendered(-1);
            }
            match reap(pid) {
                0 => "ok".to_string(),
                e if e > 0 => format!("errno={e}"),
                sig => format!("signal={}", -sig),
            }
        }
        "tcp" => {
            let tcp = || -> std::io::Result<()> {
                let listener = TcpListener::bind("127.0.0.1:0")?;
                let mut client = TcpStream::connect(listener.local_addr()?)?;
                let (mut server, _) = listener.accept()?;
                client.write_all(b"x")?;
                let mut buf = [0u8; 1];
                server.read_exact(&mut buf)?;
                Ok(())
            };
            match tcp() {
                Ok(()) => "ok".to_string(),
                Err(e) => format!("errno={}", e.raw_os_error().unwrap_or(-1)),
            }
        }
        "fork" => {
            // SAFETY: the child only calls `_exit`.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                // SAFETY: in the forked child.
                unsafe { libc::_exit(7) };
            }
            if pid < 0 {
                return rendered(-1);
            }
            match reap(pid) {
                7 => "ok".to_string(),
                other => format!("exit={other}"),
            }
        }
        // std's spawn: clone3 (ENOSYS under the filter) falls back to clone.
        "exec" => match Command::new("/bin/sh").args(["-c", "exit 3"]).status() {
            Ok(s) if s.code() == Some(3) => "ok".to_string(),
            Ok(s) => format!("status={s}"),
            Err(e) => format!("errno={}", e.raw_os_error().unwrap_or(-1)),
        },
        // A raw `execve` in a single-threaded fork, so the answer is the
        // kernel's and not std's spawn plumbing.
        "execve" => {
            // SAFETY: the forked child makes one syscall and `_exit`s.
            let pid = unsafe { libc::fork() };
            if pid == 0 {
                let argv = [
                    c"/bin/sh".as_ptr(),
                    c"-c".as_ptr(),
                    c"exit 0".as_ptr(),
                    std::ptr::null(),
                ];
                let envp = [std::ptr::null::<libc::c_char>()];
                // SAFETY: NUL-terminated arrays of static C strings.
                unsafe { libc::execve(c"/bin/sh".as_ptr(), argv.as_ptr(), envp.as_ptr()) };
                // SAFETY: in the forked child, after a failed exec.
                unsafe { libc::_exit(errno().clamp(1, 250)) };
            }
            if pid < 0 {
                return rendered(-1);
            }
            match reap(pid) {
                0 => "ok".to_string(),
                e if e > 0 => format!("errno={e}"),
                sig => format!("signal={}", -sig),
            }
        }
        // The exec pin's premise: no descriptor at or above RLIMIT_NOFILE can
        // be made, by `dup2` or `fcntl(F_DUPFD)`.
        "dup_at_limit" => {
            let mut rl = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: plain syscalls on an initialized local and fd 0.
            let (dup2, dupfd) = unsafe {
                libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl);
                let at = libc::c_int::try_from(rl.rlim_max).unwrap_or(libc::c_int::MAX);
                let a = libc::dup2(0, at);
                let a = if a >= 0 { 0 } else { errno() };
                let b = libc::fcntl(0, libc::F_DUPFD, at);
                let b = if b >= 0 { 0 } else { errno() };
                (a, b)
            };
            format!("dup2={dup2},dupfd={dupfd}")
        }
        "inet" | "inet6" | "unix" => {
            let family = match op {
                "inet" => libc::AF_INET,
                "inet6" => libc::AF_INET6,
                _ => libc::AF_UNIX,
            };
            // SAFETY: plain syscall; the fd is closed below.
            let fd = unsafe { libc::socket(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            let r = rendered(libc::c_long::from(fd));
            if fd >= 0 {
                // SAFETY: closes the fd opened above.
                unsafe { libc::close(fd) };
            }
            r
        }
        // #3528: reach a TCP listener the PARENT holds on its loopback.
        other if other.starts_with("connect=") => {
            let port: u16 = other["connect=".len()..].parse().unwrap();
            match TcpStream::connect(("127.0.0.1", port)) {
                Ok(_) => "ok".to_string(),
                Err(e) => format!("errno={}", e.raw_os_error().unwrap_or(-1)),
            }
        }
        other => format!("unknown-op={other}"),
    }
}

/// The child's placement (#3528), as one line: its pid, real/effective/saved
/// uid and gid, its uid and gid maps, its `setgroups`, its four capability
/// sets (inheritable, permitted, effective, ambient), its securebits and its
/// network namespace.
fn placement() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .map_or_else(
                || "?".to_string(),
                |v| v.split_whitespace().collect::<Vec<_>>().join(","),
            )
    };
    let words = |path: &str| {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(",")
    };
    // SAFETY: plain syscalls that only read this process's state.
    let (pid, securebits) = unsafe {
        (
            libc::getpid(),
            libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0),
        )
    };
    let net = std::fs::read_link("/proc/self/ns/net")
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    format!(
        "pid={pid};uid={};gid={};uid_map={};gid_map={};setgroups={};caps={}/{}/{}/{};\
         securebits={securebits};net={net}",
        field("Uid:"),
        field("Gid:"),
        words("/proc/self/uid_map"),
        words("/proc/self/gid_map"),
        words("/proc/self/setgroups"),
        field("CapInh:"),
        field("CapPrm:"),
        field("CapEff:"),
        field("CapAmb:"),
    )
}

// --------------------------------------------------------------- parent side

/// The child binary, at a path the child's uid can execute: the test binary
/// itself when the runtime keeps its uid, otherwise a world-executable copy.
struct ChildExe {
    path: PathBuf,
    _dir: Option<TempDir>,
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn child_exe(drops: bool) -> ChildExe {
    let me = std::env::current_exe().expect("current_exe");
    if !drops {
        return ChildExe {
            path: me,
            _dir: None,
        };
    }
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!(
        "nucleus-child-seccomp-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace("::", "-")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.join("child");
    std::fs::copy(&me, &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    ChildExe {
        path,
        _dir: Some(TempDir(dir)),
    }
}

/// The derived policy that adds nothing to the denylist.
fn nothing() -> SeccompPolicy {
    SeccompPolicy::derive(&PermissionLattice::permissive(), NetworkEgress::Declared)
}

/// A derived policy from the two levels the rule reads, with no egress.
fn derived(run_bash: CapabilityLevel, web_fetch: CapabilityLevel) -> SeccompPolicy {
    let caps = CapabilityLattice {
        run_bash,
        web_fetch,
        ..CapabilityLattice::default()
    };
    SeccompPolicy::from_capabilities(&caps, NetworkEgress::None)
}

/// Run `op` in a child confined by `confinement` (`None` = an unconfined
/// control), and return the child's result line.
fn run(confinement: Option<ChildConfinement>, op: &str) -> String {
    run_under(confinement, nothing(), op)
}

/// [`run`], with the pod's derived classes `policy`.
fn run_under(confinement: Option<ChildConfinement>, policy: SeccompPolicy, op: &str) -> String {
    try_run_under(confinement, policy, op)
        .unwrap_or_else(|e| panic!("{op}: the confined child did not spawn: {e}"))
}

/// [`run_under`], with a spawn failure returned rather than a panic.
fn try_run_under(
    confinement: Option<ChildConfinement>,
    policy: SeccompPolicy,
    op: &str,
) -> std::io::Result<String> {
    try_run_in(confinement, PidNamespace::Shared, policy, op)
}

/// [`try_run_under`], spawned in its own PID namespace when `pids` says so
/// (#3344), the way the guest's workload is.
fn try_run_in(
    confinement: Option<ChildConfinement>,
    pids: PidNamespace,
    policy: SeccompPolicy,
    op: &str,
) -> std::io::Result<String> {
    let exe = child_exe(confinement.and_then(|c| c.drop_uid()).is_some());
    let mut cmd = Command::new(&exe.path);
    cmd.args([
        "--exact",
        "child_entry",
        "--nocapture",
        "--test-threads=1",
        "-q",
    ])
    .env(OP_ENV, op)
    .current_dir(Path::new("/"));
    if let Some(c) = confinement {
        let _ = c.apply_with_pids(
            &mut cmd,
            nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
            policy,
            &nucleus::WorkspaceWrites::Writable,
            pids,
        );
    }
    // Under root each test writes its own copy of this binary while other
    // threads fork; a child forked in that window holds the copy's write
    // descriptor until it execs, and the exec of the copy is then `ETXTBSY`.
    // That is the harness racing itself, not the confinement, so retry it.
    let mut attempt = 0;
    let out = loop {
        match cmd.output() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && attempt < 20 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => break other?,
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(stdout
        .lines()
        .find_map(|l| l.strip_prefix(RESULT))
        .map(str::to_string)
        .unwrap_or_else(|| {
            panic!(
                "{op}: no result line (status {}); stdout:\n{stdout}\nstderr:\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        }))
}

/// Whether this runtime can place an exec pin: a descriptor at or above the
/// child's `RLIMIT_NOFILE` (the node ceiling, 4096). A root runtime raises its
/// own hard limit; a non-root one needs a hard limit above the ceiling. A
/// runner whose hard limit is the kernel's default 4096 (the gate lanes) can
/// not, and must REFUSE the exec-denied child rather than start it unfiltered
/// (ADR 0007 A-1); `Err` carries the hard limit for the message.
fn pin_fits() -> Result<(), u64> {
    let ceiling = nucleus::RlimitVector::NODE_CEILING.nofile;
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit into an initialized local.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut rl) };
    assert_eq!(rc, 0, "getrlimit");
    if nucleus::runtime_uid() == 0 || rl.rlim_max > ceiling {
        Ok(())
    } else {
        Err(rl.rlim_max)
    }
}

/// Where the pin cannot be placed: every exec-denied child is refused at the
/// spawn, in every mode, and nothing runs. Returns true when that is the
/// case, so the caller asserts the refusal instead of the denial.
fn exec_denial_is_refused_here(policy: SeccompPolicy) -> bool {
    let Err(hard) = pin_fits() else {
        return false;
    };
    eprintln!(
        "RLIMIT_NOFILE hard {hard} cannot hold an exec pin: asserting that every exec-denied \
         child is refused instead"
    );
    for (mode, c) in confining() {
        let got = try_run_under(Some(c), policy, "execve");
        assert_eq!(
            got.as_ref().map_err(std::io::Error::raw_os_error),
            Err(Some(libc::EOPNOTSUPP)),
            "{mode:?}: an exec-denied child that cannot be pinned must not start"
        );
    }
    true
}

/// Every mode that confines on this runtime, with its confinement.
fn confining() -> Vec<(ContainmentMode, ChildConfinement)> {
    let modes: &[ContainmentMode] = if nucleus::runtime_uid() == 0 {
        &[ContainmentMode::MicroVM, ContainmentMode::HostHardened]
    } else {
        // A non-root runtime refuses MicroVM children (#3120).
        &[ContainmentMode::HostHardened]
    };
    let all: Vec<_> = modes
        .iter()
        .map(|&m| {
            let c = ChildConfinement::for_containment(
                m,
                UnsandboxedOptIn::Absent,
                LandlockWaiver::Absent,
            )
            .unwrap_or_else(|e| panic!("{m:?} confines on this runtime: {e}"));
            (m, c)
        })
        .collect();
    assert!(
        !all.is_empty(),
        "non-vacuity: at least one confining mode ran"
    );
    all
}

fn denied() -> String {
    format!("errno={}", libc::EPERM)
}

/// THE measured exposure (#3148): a confined child opened AF_VSOCK. Red on
/// main, where the child gets fd >= 0 (or `EAFNOSUPPORT` on a host without
/// the vsock module), never the filter's `EPERM`.
#[test]
fn a_confined_child_cannot_open_a_vsock_socket() {
    let control = run(None, "vsock");
    let attributed = attributable("vsock", &control);
    for (mode, c) in confining() {
        assert_eq!(
            run(Some(c), "vsock"),
            denied(),
            "{mode:?} (control: {control})"
        );
        attributed.or_counted(c, mode);
    }
}

/// Whether the confined child's `EPERM` for `op` can be attributed to the
/// filter `ChildConfinement` installs, by an unconfined control that is NOT
/// denied.
///
/// A process that already runs under a seccomp filter which denies `op` (a
/// gate step under the trusted launcher's filter, measured on the arm64 lane
/// 2026-10-30) passes that filter to the control too, and then no errno can
/// say which filter answered. That case is reported on stderr and the test
/// falls back to the attribution it still has: the confined child carries
/// exactly one filter more than this process. The denial itself is asserted
/// either way. A control denied with NO inherited filter is still a failure:
/// then something other than seccomp answers, and this test proves nothing
/// about the filter.
fn attributable(op: &str, control: &str) -> Attribution {
    if control != denied() {
        return Attribution::ByErrno;
    }
    let inherited: u32 = seccomp_filters()
        .parse()
        .expect("Seccomp_filters is readable (Linux 5.9+)");
    assert!(
        inherited > 0,
        "attribution: unconfined, this host already answers EPERM to {op} without a \
         seccomp filter of its own"
    );
    eprintln!(
        "UNATTRIBUTED {op}: this process already runs under {inherited} seccomp filter(s) \
         that deny it (control: {control}); asserting the confined child's EPERM and that it \
         carries {} filters, not which filter denied it",
        inherited + 1
    );
    Attribution::ByFilterCount(inherited)
}

/// How a test attributes a confined child's denial; see [`attributable`].
#[derive(Clone, Copy)]
enum Attribution {
    ByErrno,
    ByFilterCount(u32),
}

impl Attribution {
    fn or_counted(self, c: ChildConfinement, mode: ContainmentMode) {
        if let Self::ByFilterCount(inherited) = self {
            assert_eq!(
                run(Some(c), "filters"),
                format!("filters={}", inherited + 1),
                "{mode:?}: the confined child adds exactly one filter"
            );
        }
    }
}

/// The other measured exposure: a user namespace, by `unshare` and by a raw
/// `clone(CLONE_NEWUSER)`.
#[test]
fn a_confined_child_cannot_create_a_user_namespace() {
    // Reported, not required: whether this host lets an unconfined process
    // create one is host policy (sysctls, AppArmor, a container's filter).
    eprintln!(
        "control: unshare {} / clone {}",
        run(None, "unshare_userns"),
        run(None, "clone_newuser")
    );
    for (mode, c) in confining() {
        assert_eq!(
            run(Some(c), "unshare_userns"),
            denied(),
            "{mode:?}: unshare"
        );
        assert_eq!(run(Some(c), "clone_newuser"), denied(), "{mode:?}: clone");
    }
}

#[test]
fn a_confined_child_cannot_ptrace() {
    let control = run(None, "ptrace");
    let attributed = attributable("ptrace", &control);
    for (mode, c) in confining() {
        assert_eq!(
            run(Some(c), "ptrace"),
            denied(),
            "{mode:?} (control: {control})"
        );
        attributed.or_counted(c, mode);
    }
}

/// The filter takes away only what it lists: ordinary TCP, fork, and exec
/// (std's spawn, whose `clone3` is answered `ENOSYS` and falls back) work.
#[test]
fn a_confined_child_still_has_tcp_fork_and_exec() {
    for (mode, c) in confining() {
        for op in ["tcp", "fork", "exec"] {
            assert_eq!(run(Some(c), op), "ok", "{mode:?}: {op}");
        }
    }
}

/// Attribution independent of errno: a confined child carries exactly one
/// more seccomp filter than an unconfined one (the runner may already sit
/// under its own, e.g. a container's), and the declared bare tier carries
/// none of ours (owner decision 2).
#[test]
fn a_confined_child_carries_one_more_filter_and_the_bare_tier_none() {
    let base: u32 = run(None, "filters")
        .strip_prefix("filters=")
        .and_then(|n| n.parse().ok())
        .expect("Seccomp_filters is readable (Linux 5.9+)");
    for (mode, c) in confining() {
        assert_eq!(
            run(Some(c), "filters"),
            format!("filters={}", base + 1),
            "{mode:?}"
        );
    }
    let bare = ChildConfinement::for_containment(
        ContainmentMode::Unsandboxed,
        UnsandboxedOptIn::Explicit,
        LandlockWaiver::Absent,
    )
    .expect("the opted-in bare tier runs");
    assert_eq!(run(Some(bare), "filters"), format!("filters={base}"));
}

/// #2907, A-19: a child under a policy derived from `run_bash: never` is
/// STARTED (through the exec pin: the filter is already installed when the
/// hook execs it) and then cannot exec anything, by `execve` or by std's
/// spawn. Red with the `Exec` class's rules removed from `derived_rules`:
/// the child's `execve` succeeds. The control under the policy that derives
/// nothing execs, so the `EPERM` is the derived class's.
#[test]
fn a_child_under_run_bash_never_cannot_exec() {
    let policy = derived(CapabilityLevel::Never, CapabilityLevel::Always);
    if exec_denial_is_refused_here(policy) {
        return;
    }
    for (mode, c) in confining() {
        assert_eq!(run(Some(c), "execve"), "ok", "{mode:?}: control");
        assert_eq!(
            run_under(Some(c), policy, "execve"),
            denied(),
            "{mode:?}: execve"
        );
        assert_eq!(
            run_under(Some(c), policy, "exec"),
            denied(),
            "{mode:?}: std spawn"
        );
        // Only exec is taken: fork and an internet socket still work.
        assert_eq!(run_under(Some(c), policy, "fork"), "ok", "{mode:?}: fork");
        assert_eq!(run_under(Some(c), policy, "inet"), "ok", "{mode:?}: inet");
        // The pin's premise, observed: the child cannot make a descriptor at
        // its limit, so it cannot recreate the pinned number.
        assert_eq!(
            run_under(Some(c), policy, "dup_at_limit"),
            format!("dup2={},dupfd={}", libc::EBADF, libc::EINVAL),
            "{mode:?}"
        );
    }
}

/// #2907, A-19: a child under a policy derived from `web_fetch: never` with
/// no declared egress cannot open an `AF_INET` or `AF_INET6` socket, and
/// keeps `AF_UNIX` (the workload door). Red with the `InetSocket` class's
/// rules removed: the socket opens. Control: the policy that derives nothing
/// opens it here, so the host does not already refuse it.
#[test]
fn a_child_under_web_fetch_never_without_egress_cannot_open_an_inet_socket() {
    let policy = derived(CapabilityLevel::Always, CapabilityLevel::Never);
    for (mode, c) in confining() {
        assert_eq!(run(Some(c), "inet"), "ok", "{mode:?}: control");
        assert_eq!(
            run_under(Some(c), policy, "inet"),
            denied(),
            "{mode:?}: inet"
        );
        assert_ne!(
            run_under(Some(c), policy, "inet6"),
            "ok",
            "{mode:?}: inet6 (EPERM, or EAFNOSUPPORT on a host without IPv6)"
        );
        assert_eq!(run_under(Some(c), policy, "unix"), "ok", "{mode:?}: unix");
        // Still the union: the denylist's vsock refusal stands.
        assert_eq!(
            run_under(Some(c), policy, "vsock"),
            denied(),
            "{mode:?}: vsock"
        );
        // Exec is not this class's.
        assert_eq!(run_under(Some(c), policy, "exec"), "ok", "{mode:?}: exec");
    }
}

/// #2907: a child under `web_fetch: never` whose pod declares only IPv4
/// egress keeps `AF_INET` (its declared destinations) and cannot open
/// `AF_INET6`. Where the confined control opens `AF_INET6`, the filter's
/// answer is exactly `EPERM`. Where it cannot (a sandbox without IPv6 may
/// answer `EAFNOSUPPORT` whatever the filter says), the socket still must
/// not open, as in the test above. Red on a rule that gives both families
/// back once anything is declared: the `AF_INET6` socket opens.
#[test]
fn a_child_under_ipv4_only_egress_cannot_open_an_inet6_socket() {
    // `run_bash: Always`, so the policy derives the socket class alone. The
    // default lattice's `run_bash: Never` adds `exec`, and an exec-denied
    // child is refused at the spawn where no exec pin fits (a gate lane's
    // hard RLIMIT_NOFILE of 4096, `pin_fits`): the child never ran.
    let caps = CapabilityLattice {
        run_bash: CapabilityLevel::Always,
        web_fetch: CapabilityLevel::Never,
        ..CapabilityLattice::default()
    };
    let policy = SeccompPolicy::from_capabilities(&caps, NetworkEgress::Ipv4Only);
    for (mode, c) in confining() {
        assert_eq!(run_under(Some(c), policy, "inet"), "ok", "{mode:?}: inet");
        let filtered = run_under(Some(c), policy, "inet6");
        if run(Some(c), "inet6") == "ok" {
            assert_eq!(filtered, denied(), "{mode:?}: inet6");
        } else {
            assert_ne!(filtered, "ok", "{mode:?}: inet6 without host IPv6");
        }
        assert_eq!(run_under(Some(c), policy, "unix"), "ok", "{mode:?}: unix");
    }
}

/// Both classes are one filter with the denylist, not a second one stacked
/// on it.
#[test]
fn the_derived_classes_add_no_second_filter() {
    let base: u32 = run(None, "filters")
        .strip_prefix("filters=")
        .and_then(|n| n.parse().ok())
        .expect("Seccomp_filters is readable (Linux 5.9+)");
    // Both classes where the exec pin fits; the socket class alone where it
    // cannot (that runner refuses an exec-denied child, which
    // `a_child_under_run_bash_never_cannot_exec` asserts).
    let run_bash = match pin_fits() {
        Ok(()) => CapabilityLevel::Never,
        Err(_) => CapabilityLevel::Always,
    };
    let policy = derived(run_bash, CapabilityLevel::Never);
    for (mode, c) in confining() {
        assert_eq!(
            run_under(Some(c), policy, "filters"),
            format!("filters={}", base + 1),
            "{mode:?}"
        );
    }
}

// ── #3528: a private user and network namespace inside the PID namespace ────

/// The value of `key` in a `placement` line.
fn placed_field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split(';')
        .find_map(|kv| kv.strip_prefix(key)?.strip_prefix('='))
        .unwrap_or_else(|| panic!("no {key} in {line}"))
}

/// The guest workload's base posture under a root runtime, and what this
/// kernel lets it be placed in; `None` (after asserting the refusal) where
/// the runtime is not root and so cannot drop at all.
fn guest_base() -> Option<(ChildConfinement, nucleus_spec::NamespaceEnforcement)> {
    let base = ChildConfinement::workload(
        ContainmentMode::MicroVM,
        Some(nucleus::DEFAULT_CHILD_UID),
        UnsandboxedOptIn::Absent,
        LandlockWaiver::Absent,
    );
    if nucleus::runtime_uid() != 0 {
        assert!(
            matches!(
                base,
                Err(nucleus::NucleusError::ChildSeparationUnavailable { .. })
            ),
            "a non-root runtime cannot drop, so it places nothing: {base:?}"
        );
        return None;
    }
    let base = base.expect("a root runtime drops its guest workload");
    Some((base, base.namespace_enforcement(PidNamespace::Own)))
}

/// **The ordering the receipt depends on (#3528 on #3344).** As root, a
/// guest workload placed in `private_user_network` runs as pid 2 of its own
/// PID namespace, AND in a fresh user namespace mapping exactly `inner 65534
/// 1` for uid and gid with `setgroups` denied, AND in a fresh network
/// namespace whose `lo` is up iff asked, with every capability set empty and
/// `SECBIT_NOROOT` locked. The hook's record says exactly that, and the rest
/// of the confinement still holds: no further user namespace, a derived
/// network denial still wins over the available loopback, and the runtime's
/// own loopback is out of reach.
///
/// Where the kernel offers no user namespaces the placement is refused by
/// name instead, and that is asserted.
#[test]
fn a_private_user_network_namespace_is_made_inside_the_workloads_own_pid_namespace() {
    let Some((base, enforcement)) = guest_base() else {
        return;
    };
    if let UserNamespaces::Unavailable { reason } = UserNamespaces::probe() {
        eprintln!("this kernel offers no user namespaces ({reason}): asserting the refusal");
        assert_eq!(enforcement, nucleus_spec::NamespaceEnforcement::RuntimeOnly);
        return;
    }
    assert_eq!(
        enforcement,
        nucleus_spec::NamespaceEnforcement::PrivateUserNetwork
    );
    let original = std::fs::read_link("/proc/self/ns/net").unwrap();
    let outer = nucleus::DEFAULT_CHILD_UID;
    // A listener on the RUNTIME's loopback, which a private namespace must
    // not reach.
    let runtime_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let runtime_port = runtime_listener.local_addr().unwrap().port();
    for (inner, loopback) in [(0, false), (0, true), (1001, false), (1001, true)] {
        let what = format!("inner {inner}, loopback {loopback}");
        let admitted = nucleus_spec::WorkloadNamespace::PrivateUserNetwork {
            inner_uid: inner,
            loopback,
        }
        .admit(Some(outer), enforcement)
        .expect("admitted where enforced");
        let placed = base.placed(admitted, PidNamespace::Own).expect("placed");

        // The record: what `apply` says the hook does, minted with the hook.
        let mut probe = Command::new("/usr/bin/true");
        probe.current_dir("/");
        match placed.apply_with_pids(
            &mut probe,
            nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
            nothing(),
            &nucleus::WorkspaceWrites::Writable,
            PidNamespace::Own,
        ) {
            nucleus::SpawnHardening::Hardened(h) => {
                assert_eq!(h.pid_namespace(), PidNamespace::Own, "{what}");
                assert_eq!(
                    h.namespace(),
                    NamespaceSetup::PrivateUserNetwork {
                        outer_uid: outer,
                        inner_uid: inner,
                        loopback
                    },
                    "{what}"
                );
            }
            other => panic!("{what}: a placed workload is hardened: {other:?}"),
        }
        assert!(probe.status().unwrap().success(), "{what}: /usr/bin/true");

        // The effect, as the child's own kernel answers.
        let line = try_run_in(Some(placed), PidNamespace::Own, nothing(), "placement")
            .unwrap_or_else(|e| panic!("{what}: the placed child did not spawn: {e}"));
        eprintln!("{what}: {line}");
        assert_eq!(
            placed_field(&line, "pid"),
            "2",
            "{what}: pid 2 of its own: {line}"
        );
        let ids = format!("{inner},{inner},{inner},{inner}");
        assert_eq!(placed_field(&line, "uid"), ids, "{what}: {line}");
        assert_eq!(placed_field(&line, "gid"), ids, "{what}: {line}");
        let map = format!("{inner},{outer},1");
        assert_eq!(placed_field(&line, "uid_map"), map, "{what}: {line}");
        assert_eq!(placed_field(&line, "gid_map"), map, "{what}: {line}");
        assert_eq!(placed_field(&line, "setgroups"), "deny", "{what}: {line}");
        assert_eq!(
            placed_field(&line, "caps"),
            "0000000000000000/0000000000000000/0000000000000000/0000000000000000",
            "{what}: {line}"
        );
        let securebits: i32 = placed_field(&line, "securebits").parse().unwrap();
        assert_eq!(securebits & 0b11, 0b11, "{what}: NOROOT locked: {line}");
        assert_ne!(
            placed_field(&line, "net"),
            original.display().to_string(),
            "{what}: a network namespace of its own"
        );

        let tcp = run_in(placed, "tcp");
        if loopback {
            assert_eq!(tcp, "ok", "{what}: lo is up");
        } else {
            // Measured 2026-11-14 (Debian 12, 6.1.0-54): no route to a
            // 127.0.0.1 whose interface was never raised.
            assert_eq!(
                tcp,
                format!("errno={}", libc::ENETUNREACH),
                "{what}: lo stays down"
            );
        }
        eprintln!("{what}: tcp on its own loopback: {tcp}");
        assert_ne!(
            run_in(placed, &format!("connect={runtime_port}")),
            "ok",
            "{what}: the runtime's loopback is not reachable"
        );
        assert_eq!(run_in(placed, "fork"), "ok", "{what}");
        assert_eq!(run_in(placed, "unshare_userns"), denied(), "{what}");
        assert_eq!(run_in(placed, "clone_newuser"), denied(), "{what}");
        // A derived network denial still wins over the loopback it has.
        let no_net = derived(CapabilityLevel::Always, CapabilityLevel::Never);
        assert_eq!(
            try_run_in(Some(placed), PidNamespace::Own, no_net, "tcp").unwrap(),
            denied(),
            "{what}: the derived class still holds"
        );
    }
    drop(runtime_listener);
    assert_eq!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        original,
        "the runtime stayed where it was"
    );
}

/// [`try_run_in`] in the workload's own PID namespace, under no derived
/// classes, panicking on a spawn failure.
fn run_in(c: ChildConfinement, op: &str) -> String {
    try_run_in(Some(c), PidNamespace::Own, nothing(), op)
        .unwrap_or_else(|e| panic!("{op}: the placed child did not spawn: {e}"))
}

/// **The PID namespace alone is unchanged (#3344).** Runtime placement in a
/// guest still gets its own PID namespace, the runtime's user and network
/// namespaces, and a record that says `runtime` beside `own`.
#[test]
fn runtime_placement_keeps_its_own_pid_namespace_and_records_runtime() {
    let Some((base, enforcement)) = guest_base() else {
        return;
    };
    let admitted = nucleus_spec::WorkloadNamespace::Runtime {}
        .admit(Some(nucleus::DEFAULT_CHILD_UID), enforcement)
        .unwrap();
    let placed = base.placed(admitted, PidNamespace::Own).unwrap();
    assert_eq!(placed, base, "runtime placement changes nothing");
    let mut probe = Command::new("/usr/bin/true");
    match placed.apply_with_pids(
        &mut probe,
        nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
        nothing(),
        &nucleus::WorkspaceWrites::Writable,
        PidNamespace::Own,
    ) {
        nucleus::SpawnHardening::Hardened(h) => {
            assert_eq!(h.pid_namespace(), PidNamespace::Own);
            assert_eq!(h.namespace(), NamespaceSetup::Runtime {});
        }
        other => panic!("{other:?}"),
    }
    let line = run_in(placed, "placement");
    let original = std::fs::read_link("/proc/self/ns/net").unwrap();
    assert_eq!(placed_field(&line, "pid"), "2", "{line}");
    assert_eq!(placed_field(&line, "uid_map"), "0,0,4294967295", "{line}");
    assert_eq!(
        placed_field(&line, "net"),
        original.display().to_string(),
        "{line}"
    );
}
