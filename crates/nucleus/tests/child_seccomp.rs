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
use nucleus::{ChildConfinement, ContainmentMode, LandlockWaiver, UnsandboxedOptIn};

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
        other => format!("unknown-op={other}"),
    }
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
        let _ = c.apply(
            &mut cmd,
            nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
            policy,
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
            other => {
                break other
                    .unwrap_or_else(|e| panic!("{op}: the confined child did not spawn: {e}"));
            }
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(RESULT))
        .map(str::to_string)
        .unwrap_or_else(|| {
            panic!(
                "{op}: no result line (status {}); stdout:\n{stdout}\nstderr:\n{}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            )
        })
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
    assert_ne!(
        control,
        denied(),
        "attribution: unconfined, this host does not already answer EPERM"
    );
    for (mode, c) in confining() {
        assert_eq!(
            run(Some(c), "vsock"),
            denied(),
            "{mode:?} (control: {control})"
        );
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
    assert_ne!(
        control,
        denied(),
        "attribution: unconfined ptrace is not EPERM here"
    );
    for (mode, c) in confining() {
        assert_eq!(
            run(Some(c), "ptrace"),
            denied(),
            "{mode:?} (control: {control})"
        );
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

/// Both classes are one filter with the denylist, not a second one stacked
/// on it.
#[test]
fn the_derived_classes_add_no_second_filter() {
    let base: u32 = run(None, "filters")
        .strip_prefix("filters=")
        .and_then(|n| n.parse().ok())
        .expect("Seccomp_filters is readable (Linux 5.9+)");
    let policy = derived(CapabilityLevel::Never, CapabilityLevel::Never);
    for (mode, c) in confining() {
        assert_eq!(
            run_under(Some(c), policy, "filters"),
            format!("filters={}", base + 1),
            "{mode:?}"
        );
    }
}
