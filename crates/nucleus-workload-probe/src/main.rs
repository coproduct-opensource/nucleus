//! `nucleus-workload-probe` — the FM-5 posture, checked on the REAL workload
//! child inside a booted microVM.
//!
//! Everything else in the FM-5 arc is proved (the Lean noninterference and
//! channel theorems) or host-unit-tested (`workload.rs`). Nothing checked the
//! *actual* workload process the tool-proxy spawns in a real guest. This binary
//! is run as a pod's `workload.command`; it reads its OWN `/proc/self/...` and
//! asserts the posture the launch builder is supposed to establish:
//!
//!   - no FM-5 identity variable is present in its environment,
//!   - no file descriptor above its own stdio leaked in (the `close_range`
//!     structural closure — the runc CVE-2024-21626 shape),
//!   - if it was given a distinct uid, its supplementary groups were dropped,
//!   - its root filesystem is mounted read-only,
//!   - it runs under the workload syscall filter (#2696 P3b): AF_VSOCK, a user
//!     namespace and ptrace are refused with the filter's `EPERM`, while an
//!     ordinary socket, fork and exec still work. Also a stage of its own,
//!     `--syscall-filter`, for a `/v1/run` child.
//!   - if it runs under a non-root uid, PID 1 (the tool-proxy, guest root) is
//!     invisible in its `/proc` (`hidepid=invisible`, #2696 P3d).
//!
//! It is baked into the musl rootfs as a static binary, exactly like
//! `nucleus-net-probe`. Everything but the syscall-filter stage is a
//! `std::fs` read of procfs; that stage needs raw syscalls, so `libc` is the
//! one dependency.
//! The verdict is a sentinel line on BOTH stdout and stderr plus the exit code
//! — the tool-proxy drains the child's stderr into the guest console log, where
//! `nucleus verify --tier2` reads it back on the host.
//!
//! A missing/expected value is reported as a FAIL with its reason rather than a
//! panic: the probe's whole job is to report, so it must not crash on the one
//! surprise it exists to catch.

use std::collections::BTreeSet;

const PASS_SENTINEL: &str = "NUCLEUS_WORKLOAD_PROBE: PASS";
const FAIL_SENTINEL: &str = "NUCLEUS_WORKLOAD_PROBE: FAIL";

/// The FM-5 identity variables the workload must never see. Kept in sync with
/// the `IDENTITY_VARS` list in `nucleus-tool-proxy/src/workload.rs` tests.
const IDENTITY_VARS: &[&str] = &[
    "NUCLEUS_TOOL_PROXY_BROKER_SECRET",
    "NUCLEUS_TOOL_PROXY_BROKER_PORT",
    "NUCLEUS_TASK_TOKEN",
    "NUCLEUS_TASK_TOKEN_NONCE",
    "NUCLEUS_TASK_TOKEN_ISSUER",
    "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
    "NUCLEUS_POD_CALLER_TOKEN",
    "NUCLEUS_SANDBOX_TOKEN",
    "NUCLEUS_IDENTITY_CERT",
    "NUCLEUS_DLC_CREDENTIALS",
    "NUCLEUS_DLC_TRUSTED_KEYS",
    "NUCLEUS_DLC_ISSUER",
];

/// The e2e canary's non-secret PREFIX. The CI plants `NUCLEUS_E2E_CANARY=<prefix><hex>`
/// in the NODE's environment; this probe searches the guest's reachable leak sites
/// for the prefix and reports only a boolean, never a value — so the guest never
/// learns the full canary and no secret ever reaches the console.
const CANARY_PREFIX: &str = "nucleus-e2e-canary-";

/// The `/v1/run` child's sentinels — a different stage from the workload's, so
/// one console log can carry both verdicts without either masking the other.
const RUN_CHILD_PASS: &str = "NUCLEUS_RUN_CHILD_PROBE: PASS";
const RUN_CHILD_FAIL: &str = "NUCLEUS_RUN_CHILD_PROBE: FAIL";

/// The syscall-filter stage's sentinels. Not `NUCLEUS_CONFINEMENT_PROBE`: that
/// name is reserved for guest-init's boot verdict (#3148, P3d).
const SYSCALL_FILTER_PASS: &str = "NUCLEUS_SYSCALL_FILTER_PROBE: PASS";
const SYSCALL_FILTER_FAIL: &str = "NUCLEUS_SYSCALL_FILTER_PROBE: FAIL";
const SYSCALL_FILTER_OP_FLAG: &str = "--syscall-filter-op";
const SYSCALL_FILTER_OP_LINE: &str = "NUCLEUS_SYSCALL_FILTER_OP: ";

/// The errno the workload filter answers (`nucleus::hardening::seccomp`'s
/// `DENIED_ERRNO`). `EPERM` is 1 on every Linux architecture
/// (`asm-generic/errno-base.h`); restated because this binary is
/// dependency-light and runs only in the guest.
const FILTER_ERRNO: i32 = 1;

/// The contention probe's per-request line and its summary line, read back off
/// the guest console by whoever ran the pod.
const CONTEND_SENTINEL: &str = "NUCLEUS_CONTEND";

mod loopback;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--loopback") {
        match loopback::round_trip() {
            Ok(()) => {
                println!("NUCLEUS_LOOPBACK_PROBE: PASS");
                eprintln!("NUCLEUS_LOOPBACK_PROBE: PASS");
            }
            Err(error) => {
                eprintln!("NUCLEUS_LOOPBACK_PROBE: FAIL: {error}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Stage 2: invoked as a `/v1/run` command
    // (`{"args": ["/usr/local/bin/nucleus-workload-probe", "--run-child"]}`)
    // rather than as the pod workload. A command the tool-proxy runs for the
    // agent must not be guest root: the proxy is PID 1 and root, and its
    // environment holds the pod's secrets.
    if std::env::args().nth(1).as_deref() == Some("--run-child") {
        let status = std::fs::read_to_string("/proc/self/status");
        let pid1_environ = std::fs::read("/proc/1/environ");
        let view = observe_pid1();
        let fails = run_child_failures(status.as_deref().ok(), &pid1_environ, &view);
        if fails.is_empty() {
            println!("{RUN_CHILD_PASS}");
            eprintln!("{RUN_CHILD_PASS}");
        } else {
            let reason = fails.join("; ");
            println!("{RUN_CHILD_FAIL}: {reason}");
            eprintln!("{RUN_CHILD_FAIL}: {reason}");
            std::process::exit(1);
        }
        return;
    }

    // Internal: one syscall-filter operation, in a subprocess of its own (a
    // successful `unshare` or `ptrace(TRACEME)` changes the caller).
    if std::env::args().nth(1).as_deref() == Some(SYSCALL_FILTER_OP_FLAG) {
        let result = std::env::args()
            .nth(2)
            .as_deref()
            .and_then(FilterOp::from_name)
            .map_or_else(|| "unknown-op".to_string(), |op| op.run().render());
        println!("{SYSCALL_FILTER_OP_LINE}{result}");
        return;
    }

    // Stage 3: the workload syscall filter alone, e.g. as a `/v1/run` command
    // (`{"args": ["/usr/local/bin/nucleus-workload-probe", "--syscall-filter"]}`).
    if std::env::args().nth(1).as_deref() == Some("--syscall-filter") {
        let mut fails = Vec::new();
        check_syscall_filter(&mut fails);
        if fails.is_empty() {
            println!("{SYSCALL_FILTER_PASS}");
            eprintln!("{SYSCALL_FILTER_PASS}");
        } else {
            let reason = fails.join("; ");
            println!("{SYSCALL_FILTER_FAIL}: {reason}");
            eprintln!("{SYSCALL_FILTER_FAIL}: {reason}");
            std::process::exit(1);
        }
        return;
    }

    // `contend N` (#2988): the composition probe for the authority exchange.
    // N child PROCESSES — distinct kernel-reported pids, so distinct bidders —
    // each ask the pod's proxy for the same auctioned dimension inside one
    // clearing window, at a different declared value. The proxy's verdicts come
    // back as one line per child, and the parent's summary says whether the
    // round was CONTESTED at all: a run where nobody was outbid proves nothing.
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("contend") => {
            let n = args.get(2).and_then(|s| s.parse::<u32>().ok()).unwrap_or(3);
            std::process::exit(contend(n));
        }
        Some("contend-child") => {
            let bid = args.get(2).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            std::process::exit(contend_child(bid));
        }
        _ => {}
    }

    let mut fails: Vec<String> = Vec::new();

    check_environment(&mut fails);
    check_file_descriptors(&mut fails);
    check_groups(&mut fails);
    check_root_readonly(&mut fails);
    check_syscall_filter(&mut fails);
    check_pid1_invisible(&mut fails);
    check_credential_absence();

    if fails.is_empty() {
        // Both streams: the proxy drains stderr, but /v1/run captures stdout.
        println!("{PASS_SENTINEL}");
        eprintln!("{PASS_SENTINEL}");
    } else {
        let reason = fails.join("; ");
        println!("{FAIL_SENTINEL}: {reason}");
        eprintln!("{FAIL_SENTINEL}: {reason}");
        std::process::exit(1);
    }
}

/// Sweep the enumerable places a node-held secret could surface inside the guest,
/// and report — as booleans, never values — whether the e2e canary prefix appears.
///
/// The guest DUMPS nothing and the host SEARCHES nothing here: to avoid putting the
/// secret in the guest AND to avoid putting any value on the console, the probe reads
/// each site, searches it in-process, and prints only `looked` (a per-site
/// positive-control token was present, so the read+search actually work — "no leak"
/// is distinguishable from "no look") and `canary` (prefix present or absent). Values
/// never leave this process. `nucleus verify --tier2` reads these lines back off the
/// guest console. Emitted on BOTH streams because the proxy drains stderr to the
/// console log and `/v1/run` captures stdout.
fn check_credential_absence() {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let env_blob: String = std::env::vars()
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    let proxy_environ = std::fs::read("/proc/1/environ")
        .map(|b| String::from_utf8_lossy(&b).replace('\0', "\n"))
        .unwrap_or_default();
    let pod_spec = std::fs::read_to_string("/etc/nucleus/pod.yaml").unwrap_or_default();

    // (site, content, a token known to be present in that site = the positive control)
    let sites: [(&str, &str, &str); 4] = [
        ("cmdline", cmdline.as_str(), "console"),
        ("workload-env", env_blob.as_str(), "NUCLEUS_TOOL_PROXY_URL"),
        (
            "proxy-environ",
            proxy_environ.as_str(),
            "NUCLEUS_TOOL_PROXY",
        ),
        ("pod-spec", pod_spec.as_str(), "apiVersion"),
    ];
    for (name, content, token) in sites {
        let looked = if content.contains(token) { "yes" } else { "no" };
        let canary = if content.contains(CANARY_PREFIX) {
            "PRESENT"
        } else {
            "absent"
        };
        let line = format!("NUCLEUS_E2E_LEAK {name}: looked={looked} canary={canary}");
        println!("{line}");
        eprintln!("{line}");
    }
}

/// Read `/proc/self/environ` (NUL-separated `KEY=VALUE`) and confirm no identity
/// variable is present — with a non-vacuity control that the proxy URL, which
/// the workload legitimately gets, IS present (else an empty environment would
/// pass every "does not contain" check while being completely broken).
fn check_environment(fails: &mut Vec<String>) {
    let raw = match std::fs::read("/proc/self/environ") {
        Ok(bytes) => bytes,
        Err(err) => {
            fails.push(format!("cannot read /proc/self/environ: {err}"));
            return;
        }
    };
    let mut keys: BTreeSet<String> = BTreeSet::new();
    for entry in raw.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let entry = String::from_utf8_lossy(entry);
        let key = entry.split('=').next().unwrap_or("").to_string();
        keys.insert(key);
    }

    // Inventory for the boot gate's conformance step: every observed NAME (never
    // a value) on stderr, which the proxy drains into the guest log where
    // `nucleus-delivery-conformance` replays it through the production
    // classifier and the extracted `ident_may_deliver` oracle — the categorical
    // check behind the fixed list below. Emitted before the checks so even a
    // FAIL run ships its evidence.
    for key in &keys {
        eprintln!("NUCLEUS_WORKLOAD_ENV: {key}");
    }

    for var in IDENTITY_VARS {
        if keys.contains(*var) {
            fails.push(format!(
                "identity variable {var} is present in the workload's environment"
            ));
        }
    }

    // Non-vacuity: the workload must still be told where its proxy is.
    if !keys.contains("NUCLEUS_TOOL_PROXY_URL") {
        fails.push(
            "NUCLEUS_TOOL_PROXY_URL absent — the environment is empty or the probe was not run \
             as a mediated workload, so the identity-absence checks would pass vacuously"
                .to_string(),
        );
    }
}

/// Enumerate `/proc/self/fd`. After the launch builder's `close_range(3, ..)`,
/// the child has only 0/1/2 at exec; the `read_dir` here opens one directory fd,
/// so the expected count is small. A leaked descriptor beyond that set is the
/// runc-CVE-2024-21626 shape — a socket or log handle the workload should never
/// have inherited.
fn check_file_descriptors(fails: &mut Vec<String>) {
    let entries = match std::fs::read_dir("/proc/self/fd") {
        Ok(e) => e,
        Err(err) => {
            fails.push(format!("cannot read /proc/self/fd: {err}"));
            return;
        }
    };
    let mut fds: Vec<u32> = Vec::new();
    for entry in entries.flatten() {
        // Let-chain: clippy's `collapsible_if` fires on the nested form under
        // edition 2024, and CI runs -D warnings.
        if let Some(name) = entry.file_name().to_str()
            && let Ok(fd) = name.parse::<u32>()
        {
            fds.push(fd);
        }
    }
    fds.sort_unstable();
    // 0/1/2 plus the one dir fd `read_dir` holds open while iterating. Anything
    // beyond that is a leak; allow a tiny margin for the readdir fd only.
    if fds.len() > 4 {
        fails.push(format!(
            "inherited file descriptors beyond stdio: {fds:?} — close_range did not shut every \
             parent fd"
        ));
    }
    // Non-vacuity: 0/1/2 must be present, or the child got no stdio at all.
    for std_fd in [0u32, 1, 2] {
        if !fds.contains(&std_fd) {
            fails.push(format!("standard fd {std_fd} is missing"));
        }
    }
}

/// If the workload runs under a distinct (non-root) uid, its supplementary
/// groups must have been dropped (`setgroups([])`) — otherwise it keeps the
/// runtime's ambient group authority. Read from `/proc/self/status` (`Uid:` and
/// `Groups:` lines) so the probe needs no libc.
fn check_groups(fails: &mut Vec<String>) {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(err) => {
            fails.push(format!("cannot read /proc/self/status: {err}"));
            return;
        }
    };
    let mut uid: Option<u32> = None;
    let mut groups_line: Option<String> = None;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest.split_whitespace().next().and_then(|v| v.parse().ok());
        } else if let Some(rest) = line.strip_prefix("Groups:") {
            groups_line = Some(rest.trim().to_string());
        }
    }
    // Only a security requirement when a distinct unprivileged uid was assigned.
    // A probe running as root (no uid set in the spec) has nothing to assert
    // here — that is the reject_credential_readable_workload / operator choice,
    // not this check's subject.
    if matches!(uid, Some(u) if u != 0) {
        match groups_line {
            Some(g) if g.is_empty() => {}
            Some(g) => fails.push(format!(
                "workload runs under a distinct uid but retains supplementary groups: [{g}]"
            )),
            None => fails.push("no Groups: line in /proc/self/status".to_string()),
        }
    }
}

/// The guest root filesystem is remounted read-only before the workload starts.
/// Confirm the mount over `/` carries `ro` in `/proc/self/mountinfo`.
fn check_root_readonly(fails: &mut Vec<String>) {
    let mountinfo = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(s) => s,
        Err(err) => {
            fails.push(format!("cannot read /proc/self/mountinfo: {err}"));
            return;
        }
    };
    // Each line: "<id> <parent> <maj:min> <root> <mountpoint> <options> ...".
    // The mountpoint is field 5 (1-indexed); options is field 6.
    let mut root_ro: Option<bool> = None;
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        if fields[4] == "/" {
            root_ro = Some(fields[5].split(',').any(|opt| opt == "ro"));
        }
    }
    match root_ro {
        Some(true) => {}
        Some(false) => fails.push("root filesystem is mounted read-write".to_string()),
        None => fails.push("no root (/) mount found in /proc/self/mountinfo".to_string()),
    }
}

/// What one syscall-filter operation returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Ok,
    Errno(i32),
}

impl Outcome {
    fn render(self) -> String {
        match self {
            Outcome::Ok => "ok".to_string(),
            Outcome::Errno(e) => format!("errno={e}"),
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "ok" => Some(Outcome::Ok),
            other => other
                .strip_prefix("errno=")
                .and_then(|e| e.parse().ok())
                .map(Outcome::Errno),
        }
    }
}

/// The operations the syscall-filter stage tries, each in its own
/// subprocess. That subprocess is a fork and exec of this binary, so the stage
/// running at all is the "fork and exec still work" check for std's spawn
/// (whose `clone3` the filter answers `ENOSYS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterOp {
    /// `socket(AF_VSOCK)`: measured OPEN to the workload in #3148.
    Vsock,
    /// `unshare(CLONE_NEWUSER)`: measured OPEN in #3148.
    UnshareUserns,
    /// `clone(CLONE_NEWUSER | SIGCHLD)`, the other door to a user namespace.
    CloneNewuser,
    /// `ptrace(PTRACE_TRACEME)`.
    Ptrace,
    /// `socket(AF_INET, SOCK_STREAM)`: must still work.
    InetSocket,
    /// A raw fork (`clone(SIGCHLD)`): must still work.
    Fork,
}

impl FilterOp {
    const ALL: [FilterOp; 6] = [
        FilterOp::Vsock,
        FilterOp::UnshareUserns,
        FilterOp::CloneNewuser,
        FilterOp::Ptrace,
        FilterOp::InetSocket,
        FilterOp::Fork,
    ];

    fn name(self) -> &'static str {
        match self {
            FilterOp::Vsock => "vsock",
            FilterOp::UnshareUserns => "unshare-userns",
            FilterOp::CloneNewuser => "clone-newuser",
            FilterOp::Ptrace => "ptrace",
            FilterOp::InetSocket => "inet-socket",
            FilterOp::Fork => "fork",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.name() == name)
    }

    /// What the workload filter must answer.
    fn expected(self) -> Outcome {
        match self {
            FilterOp::Vsock
            | FilterOp::UnshareUserns
            | FilterOp::CloneNewuser
            | FilterOp::Ptrace => Outcome::Errno(FILTER_ERRNO),
            FilterOp::InetSocket | FilterOp::Fork => Outcome::Ok,
        }
    }

    #[cfg(target_os = "linux")]
    fn run(self) -> Outcome {
        use libc::c_long;
        let outcome = |r: Result<c_long, i32>| match r {
            Ok(_) => Outcome::Ok,
            Err(e) => Outcome::Errno(e),
        };
        // A fork-like clone whose child exits at once; the parent reaps it.
        let clone_and_reap = |flags: c_long| {
            let r = sys(libc::SYS_clone, [flags, 0, 0, 0, 0]);
            match r {
                Ok(0) => {
                    let _ = sys(libc::SYS_exit_group, [0, 0, 0, 0, 0]);
                    unreachable!("exit_group returned")
                }
                Ok(pid) => {
                    let _ = sys(libc::SYS_wait4, [pid, 0, 0, 0, 0]);
                }
                Err(_) => {}
            }
            outcome(r)
        };
        match self {
            FilterOp::Vsock | FilterOp::InetSocket => {
                let family = if self == FilterOp::Vsock {
                    libc::AF_VSOCK
                } else {
                    libc::AF_INET
                };
                let r = sys(
                    libc::SYS_socket,
                    [
                        c_long::from(family),
                        c_long::from(libc::SOCK_STREAM | libc::SOCK_CLOEXEC),
                        0,
                        0,
                        0,
                    ],
                );
                if let Ok(fd) = r {
                    let _ = sys(libc::SYS_close, [fd, 0, 0, 0, 0]);
                }
                outcome(r)
            }
            FilterOp::UnshareUserns => outcome(sys(
                libc::SYS_unshare,
                [c_long::from(libc::CLONE_NEWUSER), 0, 0, 0, 0],
            )),
            FilterOp::CloneNewuser => {
                clone_and_reap(c_long::from(libc::CLONE_NEWUSER | libc::SIGCHLD))
            }
            FilterOp::Ptrace => outcome(sys(
                libc::SYS_ptrace,
                [c_long::from(libc::PTRACE_TRACEME), 0, 0, 0, 0],
            )),
            FilterOp::Fork => clone_and_reap(c_long::from(libc::SIGCHLD)),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn run(self) -> Outcome {
        // No seccomp off Linux; the guest is Linux. ENOSYS reads as a FAIL.
        Outcome::Errno(38)
    }
}

/// The one raw-syscall door of this binary. Every caller passes scalars only
/// (no pointer the kernel would read or write), so nothing here touches this
/// process's memory.
#[cfg(target_os = "linux")]
fn sys(nr: libc::c_long, a: [libc::c_long; 5]) -> Result<libc::c_long, i32> {
    // SAFETY: a raw syscall with scalar arguments only (see the doc comment);
    // `wait4` is passed NULL for both of its out-pointers.
    let rc = unsafe { libc::syscall(nr, a[0], a[1], a[2], a[3], a[4]) };
    if rc < 0 {
        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))
    } else {
        Ok(rc)
    }
}

/// Run every [`FilterOp`] in its own subprocess and check the answers, plus
/// `/proc/self/status`'s `Seccomp:` mode.
fn check_syscall_filter(fails: &mut Vec<String>) {
    let mode = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("Seccomp:"))
                .map(|v| v.trim().to_string())
        });
    let observed: Vec<(FilterOp, Result<Outcome, String>)> = FilterOp::ALL
        .into_iter()
        .map(|op| (op, observe(op)))
        .collect();
    for (op, seen) in &observed {
        let line = match seen {
            Ok(o) => o.render(),
            Err(e) => format!("not observed: {e}"),
        };
        eprintln!("NUCLEUS_SYSCALL_FILTER {}: {line}", op.name());
    }
    fails.extend(syscall_filter_failures(mode.as_deref(), &observed));
}

/// Spawn this binary to run `op`. A spawn that fails, or a child that prints
/// no result, is "could not look", which is reported as such (ADR 0007 A-1).
fn observe(op: FilterOp) -> Result<Outcome, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let out = std::process::Command::new(exe)
        .args([SYSCALL_FILTER_OP_FLAG, op.name()])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("spawn (fork+exec under the filter): {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(SYSCALL_FILTER_OP_LINE))
        .and_then(Outcome::parse)
        .ok_or_else(|| format!("no result line (exit {})", out.status))
}

/// The syscall-filter verdict, pure so it is testable off-guest.
///
/// * `Seccomp:` in `/proc/self/status` must be `2` (filter mode);
/// * each [`FilterOp`] must answer exactly [`FilterOp::expected`]. A denial
///   with any other errno is not the filter's, and an op that could not be
///   run is not a pass.
fn syscall_filter_failures(
    seccomp_mode: Option<&str>,
    observed: &[(FilterOp, Result<Outcome, String>)],
) -> Vec<String> {
    let mut fails = Vec::new();
    match seccomp_mode {
        Some("2") => {}
        Some(m) => fails.push(format!(
            "the workload runs without a seccomp filter (Seccomp: {m}); the workload syscall \
             filter was not installed"
        )),
        None => fails.push("could not read Seccomp: from /proc/self/status".to_string()),
    }
    for op in FilterOp::ALL {
        match observed.iter().find(|(o, _)| *o == op).map(|(_, r)| r) {
            Some(Ok(seen)) if *seen == op.expected() => {}
            Some(Ok(seen)) => fails.push(format!(
                "{}: expected {}, got {}",
                op.name(),
                op.expected().render(),
                seen.render()
            )),
            Some(Err(e)) => fails.push(format!("{}: not observed ({e})", op.name())),
            None => fails.push(format!("{}: never run", op.name())),
        }
    }
    fails
}

// ── contend: the authority exchange's composition probe (#2988) ─────────────

/// Spawn `n` children, each a distinct process bidding a distinct value for the
/// same auctioned dimension, and summarise what the proxy decided. Exit 0 when
/// the round was contested (at least one winner AND at least one outbid), 1
/// otherwise: an uncontested run is a posted price wearing a theorem's name.
fn contend(n: u32) -> i32 {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            println!("{CONTEND_SENTINEL}: FAIL current_exe: {e}");
            return 1;
        }
    };
    // Values 1 000 000, 2 000 000, … µUSD: distinct, so the second-price rule
    // has something to discover, and all under the certificate ceilings the
    // live specs use.
    let mut children = Vec::new();
    let mut failed = false;
    for i in 1..=n {
        let bid = u64::from(i) * 1_000_000;
        match std::process::Command::new(&exe)
            .arg("contend-child")
            .arg(bid.to_string())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()
        {
            Ok(c) => children.push(c),
            Err(e) => {
                failed = true;
                println!("{CONTEND_SENTINEL}: FAIL spawn child {i}: {e}");
            }
        }
    }
    let (mut won, mut outbid, mut denied, mut other) = (0u32, 0u32, 0u32, 0u32);
    for c in children {
        let out = match c.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                failed = true;
                println!("{CONTEND_SENTINEL}: FAIL wait: {e}");
                continue;
            }
        };
        failed |= !out.status.success();
        let line = String::from_utf8_lossy(&out.stdout);
        // Echo the child's line so the console carries every verdict.
        print!("{line}");
        eprint!("{line}");
        let outcome = line
            .split_whitespace()
            .find_map(|word| word.strip_prefix("outcome="));
        if outcome == Some("won") {
            won += 1;
        } else if outcome == Some("outbid") {
            outbid += 1;
        } else if outcome == Some("denied") {
            denied += 1;
        } else {
            other += 1;
        }
    }
    let contested = !failed && other == 0 && won >= 1 && outbid >= 1;
    let summary = format!(
        "{CONTEND_SENTINEL}: SUMMARY children={n} won={won} outbid={outbid} denied={denied} \
         other={other} contested={contested}"
    );
    println!("{summary}");
    eprintln!("{summary}");
    if contested { 0 } else { 1 }
}

/// One bidder: POST an egress request over the pod's Unix socket with a
/// declared value, and classify the proxy's answer.
fn contend_child(bid: u64) -> i32 {
    use std::io::{Read, Write};

    let pid = std::process::id();
    let url = std::env::var("NUCLEUS_TOOL_PROXY_URL").unwrap_or_default();
    let Some(path) = url.strip_prefix("unix://") else {
        println!("{CONTEND_SENTINEL}: bid={bid} pid={pid} outcome=no-unix-socket url={url:?}");
        return 1;
    };
    let body = r#"{"url":"http://contend.invalid/","method":"GET"}"#;
    let request = format!(
        "POST /v1/web_fetch HTTP/1.1\r\nHost: nucleus\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nx-nucleus-bid-micro-usd: {bid}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = match std::os::unix::net::UnixStream::connect(path) {
        Ok(s) => s,
        Err(e) => {
            // A connect refusal is a permission FACT, so report the facts that
            // decide it rather than leaving the reader to guess: our uid, and
            // the mode/owner of the socket and of every directory above it.
            use std::os::unix::fs::MetadataExt;
            let uid = std::fs::metadata("/proc/self")
                .map(|m| m.uid())
                .unwrap_or(u32::MAX);
            let mut modes = String::new();
            let mut acc = std::path::PathBuf::from("/");
            for part in std::path::Path::new(path).iter().skip(1) {
                acc.push(part);
                let d = match std::fs::metadata(&acc) {
                    Ok(m) => format!(
                        "{}=mode{:o},uid{} ",
                        acc.display(),
                        m.mode() & 0o7777,
                        m.uid()
                    ),
                    Err(e) => format!("{}=<{}> ", acc.display(), e.kind()),
                };
                modes.push_str(&d);
            }
            println!(
                "{CONTEND_SENTINEL}: bid={bid} pid={pid} outcome=connect-failed error={e} \
                 my_uid={uid} path_modes=[{}]",
                modes.trim_end()
            );
            return 1;
        }
    };
    if let Err(e) = stream.set_read_timeout(Some(std::time::Duration::from_secs(30))) {
        println!("{CONTEND_SENTINEL}: bid={bid} pid={pid} outcome=timeout-setup-failed error={e}");
        return 1;
    }
    if let Err(e) = stream.write_all(request.as_bytes()) {
        println!("{CONTEND_SENTINEL}: bid={bid} pid={pid} outcome=write-failed error={e}");
        return 1;
    }
    let mut reply = Vec::new();
    if let Err(e) = stream.take(32 * 1024 + 1).read_to_end(&mut reply) {
        println!("{CONTEND_SENTINEL}: bid={bid} pid={pid} outcome=read-failed error={e}");
        return 1;
    }
    if reply.len() > 32 * 1024 {
        return 1;
    }
    let reply = String::from_utf8_lossy(&reply);
    let status = reply.split_whitespace().nth(1).unwrap_or("?").to_string();
    let outcome = auction_outcome(&reply);
    let tail: String = reply
        .chars()
        .rev()
        .take(120)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    println!(
        "{CONTEND_SENTINEL}: bid={bid} pid={pid} status={status} outcome={outcome} tail={:?}",
        tail.replace('\n', " ")
    );
    i32::from(outcome == "other")
}

/// HTTP status/body alone never establishes an auction result. Only the
/// proxy's decision header does; duplicate or malformed evidence is refused.
fn auction_outcome(reply: &str) -> &'static str {
    let Some((headers, _)) = reply.split_once("\r\n\r\n") else {
        return "other";
    };
    let mut lines = headers.split("\r\n");
    let mut status = lines.next().unwrap_or("").split_whitespace();
    if !matches!(status.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return "other";
    }
    let Some(code) = status
        .next()
        .and_then(|s| s.parse::<u16>().ok())
        .filter(|n| (200..600).contains(n))
    else {
        return "other";
    };
    let mut outcome = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return "other";
        };
        if name.eq_ignore_ascii_case("x-nucleus-auction-outcome") {
            if outcome.is_some() {
                return "other";
            }
            outcome = Some(value.trim());
        }
    }
    match outcome {
        Some("won") => "won",
        Some("outbid") if code == 403 => "outbid",
        _ => "other",
    }
}

/// What a process saw of PID 1 in its own `/proc`.
///
/// Three outcomes, not a bool (ADR 0007 A-1, A-2): PID 1 always exists, so
/// "not there" means hidden ONLY when `/proc` demonstrably answers. A `/proc`
/// that cannot be listed, or that does not even list this process, is a probe
/// that could not look, and that is never reported as hidden.
#[derive(Debug, PartialEq, Eq)]
enum Pid1View {
    /// Absent from the `/proc` listing and `/proc/1/cmdline` is `ENOENT`, while
    /// the same listing shows this process: `hidepid=invisible` at work.
    Invisible,
    /// The workload can see PID 1. Which of the two leaked is kept, so the
    /// failure says what a fix has to close.
    Visible {
        listed: bool,
        cmdline_readable: bool,
    },
    /// The observation itself failed, with why.
    Unobserved(String),
}

/// Look at PID 1 from here. The effectful half of [`pid1_view`].
fn observe_pid1() -> Pid1View {
    let listing = std::fs::read_dir("/proc").map(|entries| {
        entries
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_owned))
            .collect::<Vec<String>>()
    });
    let cmdline = std::fs::read("/proc/1/cmdline");
    pid1_view(&listing, std::process::id(), &cmdline)
}

/// Classify one observation of PID 1. Pure, so the red case (a plain `/proc`)
/// is testable off-guest.
fn pid1_view(
    listing: &std::io::Result<Vec<String>>,
    self_pid: u32,
    pid1_cmdline: &std::io::Result<Vec<u8>>,
) -> Pid1View {
    let names = match listing {
        Ok(names) => names,
        Err(e) => return Pid1View::Unobserved(format!("cannot list /proc: {e}")),
    };
    // Non-vacuity: an empty or foreign `/proc` "hides" PID 1 too.
    let self_name = self_pid.to_string();
    if !names.contains(&self_name) {
        return Pid1View::Unobserved(format!(
            "/proc does not list this process (pid {self_pid}), so PID 1's absence \
             from it shows nothing"
        ));
    }
    let listed = names.iter().any(|n| n == "1");
    let cmdline_readable = match pid1_cmdline {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        // hidepid=noaccess answers EACCES for a pid it still lists; an unlisted
        // PID 1 that fails with anything but ENOENT is not invisibility.
        Err(e) if !listed => {
            return Pid1View::Unobserved(format!(
                "PID 1 is unlisted but /proc/1/cmdline fails with {e}, not ENOENT"
            ));
        }
        Err(_) => false,
    };
    if listed || cmdline_readable {
        Pid1View::Visible {
            listed,
            cmdline_readable,
        }
    } else {
        Pid1View::Invisible
    }
}

/// The failure, if any, for a non-root process's view of PID 1.
fn pid1_failure(view: &Pid1View) -> Option<String> {
    match view {
        Pid1View::Invisible => None,
        Pid1View::Visible {
            listed,
            cmdline_readable,
        } => Some(format!(
            "PID 1 is visible to the workload (listed in /proc: {listed}, /proc/1/cmdline \
             readable: {cmdline_readable}); /proc is not mounted hidepid=invisible"
        )),
        Pid1View::Unobserved(why) => Some(format!(
            "could not observe PID 1's visibility: {why}; containment was not observed"
        )),
    }
}

/// `/proc` is mounted `hidepid=invisible` (#2696 P3d): a non-root workload
/// must not see PID 1 at all.
///
/// Root sees every pid whatever the mount says, so for a root workload there is
/// nothing to observe and this asserts nothing, as `check_groups` does. The
/// probe pod (`examples/openclaw-demo/probe-pod.yaml`) runs as 65534.
fn check_pid1_invisible(fails: &mut Vec<String>) {
    let uid = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| status_uid(&s));
    match uid {
        Some(0) => {}
        Some(_) => fails.extend(pid1_failure(&observe_pid1())),
        None => fails.push("could not read the workload's uid from /proc/self/status".into()),
    }
}

/// The real uid: the first field of `/proc/self/status`'s `Uid:` line.
fn status_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|v| v.parse::<u32>().ok())
}

/// The `--run-child` verdict, pure so it is testable off-guest.
///
/// * the real uid (`Uid:` first field) must not be 0;
/// * PID 1 must be invisible to it (`hidepid=invisible`, P3d);
/// * `/proc/1/environ` must be refused: `EACCES` (the uid fence), or `ENOENT`
///   when PID 1 was observed to be invisible. "Could not look" for any other
///   reason (no procfs, an `ENOENT` nothing explains) is not "looked and it
///   was denied" (ADR 0007 A-2), so it fails too: the probe cannot vouch for
///   containment it did not observe.
fn run_child_failures(
    status: Option<&str>,
    pid1_environ: &std::io::Result<Vec<u8>>,
    pid1: &Pid1View,
) -> Vec<String> {
    let mut fails = Vec::new();
    let uid = status.and_then(status_uid);
    match uid {
        Some(0) => fails.push("the /v1/run child runs as root (uid 0)".to_string()),
        Some(_) => {}
        None => fails.push("could not read the child's uid from /proc/self/status".to_string()),
    }
    match pid1_environ {
        Ok(_) => fails
            .push("the /v1/run child can read /proc/1/environ — the runtime's secrets".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && *pid1 == Pid1View::Invisible => {}
        Err(e) => fails.push(format!(
            "/proc/1/environ unreadable for a reason other than permission ({e}); \
             containment was not observed"
        )),
    }
    fails.extend(pid1_failure(pid1));
    fails
}

#[cfg(test)]
mod syscall_filter_tests {
    use super::{FILTER_ERRNO, FilterOp, Outcome, syscall_filter_failures};

    fn filtered() -> Vec<(FilterOp, Result<Outcome, String>)> {
        FilterOp::ALL
            .into_iter()
            .map(|op| (op, Ok(op.expected())))
            .collect()
    }

    #[test]
    fn the_filtered_workload_passes() {
        assert!(syscall_filter_failures(Some("2"), &filtered()).is_empty());
    }

    /// What #3148 measured on the unfiltered guest: AF_VSOCK, both user
    /// namespace doors and ptrace succeed, and there is no filter.
    #[test]
    fn the_unfiltered_guest_fails_on_every_measured_exposure() {
        let unfiltered: Vec<_> = FilterOp::ALL
            .into_iter()
            .map(|op| (op, Ok(Outcome::Ok)))
            .collect();
        let fails = syscall_filter_failures(Some("0"), &unfiltered);
        assert_eq!(fails.len(), 5, "{fails:#?}");
    }

    /// A denial with another errno (DAC, a host policy) is not the filter's.
    #[test]
    fn a_denial_with_another_errno_is_not_the_filter() {
        let mut seen = filtered();
        seen[0].1 = Ok(Outcome::Errno(97)); // EAFNOSUPPORT
        assert_eq!(syscall_filter_failures(Some("2"), &seen).len(), 1);
    }

    /// Could not look is not a pass (ADR 0007 A-1).
    #[test]
    fn an_op_that_could_not_run_or_a_missing_mode_fails() {
        let mut seen = filtered();
        seen[4].1 = Err("spawn failed".to_string());
        assert_eq!(syscall_filter_failures(Some("2"), &seen).len(), 1);
        assert_eq!(syscall_filter_failures(None, &filtered()).len(), 1);
        assert_eq!(
            syscall_filter_failures(Some("2"), &[]).len(),
            FilterOp::ALL.len()
        );
    }

    #[test]
    fn ops_round_trip_by_name_and_outcomes_by_rendering() {
        for op in FilterOp::ALL {
            assert_eq!(FilterOp::from_name(op.name()), Some(op));
        }
        for o in [
            Outcome::Ok,
            Outcome::Errno(FILTER_ERRNO),
            Outcome::Errno(97),
        ] {
            assert_eq!(Outcome::parse(&o.render()), Some(o));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_restated_errno_is_eperm() {
        assert_eq!(FILTER_ERRNO, libc::EPERM);
    }
}

#[cfg(test)]
mod tests {
    use super::{Pid1View, pid1_failure, pid1_view, run_child_failures};
    use std::io;

    const NOBODY: &str = "Name:\tprobe\nUid:\t65534\t65534\t65534\t65534\n";
    const ROOT: &str = "Name:\tprobe\nUid:\t0\t0\t0\t0\n";

    fn denied() -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }

    fn missing() -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::NotFound))
    }

    fn listing(pids: &[&str]) -> io::Result<Vec<String>> {
        Ok(pids.iter().map(|p| (*p).to_string()).collect())
    }

    /// The child's own pid in the fixtures below.
    const SELF: u32 = 42;

    /// Plain `/proc`, which the guest mounted before P3d, as a uid-65534 child
    /// saw it in the P3 spike (section 5): PID 1 listed and its cmdline
    /// readable. The red case for the new stage.
    fn plain_proc() -> Pid1View {
        pid1_view(
            &listing(&["1", "42", "self", "cmdline"]),
            SELF,
            &Ok(b"/init\0".to_vec()),
        )
    }

    /// `hidepid=invisible`: only the child's own pid, and `ENOENT` for PID 1.
    fn hidepid_proc() -> Pid1View {
        pid1_view(&listing(&["42", "self", "cmdline"]), SELF, &missing())
    }

    #[test]
    fn plain_proc_shows_pid1_and_fails() {
        assert_eq!(
            plain_proc(),
            Pid1View::Visible {
                listed: true,
                cmdline_readable: true
            }
        );
        assert!(pid1_failure(&plain_proc()).is_some());
    }

    #[test]
    fn hidepid_invisible_hides_pid1_and_passes() {
        assert_eq!(hidepid_proc(), Pid1View::Invisible);
        assert!(pid1_failure(&hidepid_proc()).is_none());
    }

    /// `hidepid=noaccess` lists PID 1 and answers `EACCES`: enumerable, so not
    /// the posture.
    #[test]
    fn hidepid_noaccess_still_lists_pid1_and_fails() {
        let denied_cmdline = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        let v = pid1_view(&listing(&["1", "42"]), SELF, &denied_cmdline);
        assert_eq!(
            v,
            Pid1View::Visible {
                listed: true,
                cmdline_readable: false
            }
        );
    }

    /// Absence of PID 1 is evidence only when `/proc` demonstrably answers.
    #[test]
    fn an_empty_or_unlistable_proc_is_not_invisibility() {
        assert!(matches!(
            pid1_view(&listing(&[]), SELF, &missing()),
            Pid1View::Unobserved(_)
        ));
        assert!(matches!(
            pid1_view(
                &Err(io::Error::from(io::ErrorKind::NotFound)),
                SELF,
                &missing()
            ),
            Pid1View::Unobserved(_)
        ));
        let odd = Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(matches!(
            pid1_view(&listing(&["42"]), SELF, &odd),
            Pid1View::Unobserved(_)
        ));
        assert!(pid1_failure(&Pid1View::Unobserved("x".into())).is_some());
    }

    #[test]
    fn an_unprivileged_child_that_is_refused_pid1s_environ_passes() {
        assert!(run_child_failures(Some(NOBODY), &denied(), &Pid1View::Invisible).is_empty());
    }

    /// With hidepid, PID 1's environ is `ENOENT`, not `EACCES`, and that is the
    /// stronger containment: accepted because PID 1 was observed invisible.
    #[test]
    fn enoent_on_pid1s_environ_passes_when_pid1_is_invisible() {
        assert!(run_child_failures(Some(NOBODY), &missing(), &hidepid_proc()).is_empty());
    }

    /// The pre-hidepid guest: the uid fence held (`EACCES`) but PID 1 was
    /// visible, which is now a failure of its own.
    #[test]
    fn a_child_that_sees_pid1_fails_even_when_environ_is_denied() {
        let fails = run_child_failures(Some(NOBODY), &denied(), &plain_proc());
        assert_eq!(fails.len(), 1, "{fails:?}");
        assert!(fails[0].contains("PID 1 is visible"), "{fails:?}");
    }

    /// The pre-fix guest: root, the read succeeds, and PID 1 is visible.
    #[test]
    fn a_root_child_that_reads_pid1s_environ_fails_three_times() {
        let fails = run_child_failures(Some(ROOT), &Ok(b"K=V\0".to_vec()), &plain_proc());
        assert_eq!(fails.len(), 3, "{fails:?}");
    }

    #[test]
    fn could_not_look_is_not_denied() {
        let unobserved = Pid1View::Unobserved("no /proc".into());
        // An ENOENT that hidepid does not explain is not containment.
        assert_eq!(
            run_child_failures(Some(NOBODY), &missing(), &unobserved).len(),
            2
        );
        assert_eq!(
            run_child_failures(None, &denied(), &Pid1View::Invisible).len(),
            1
        );
    }
}

#[cfg(test)]
mod auction_tests {
    use super::auction_outcome;

    #[test]
    fn generic_successes_refusals_and_server_errors_are_not_auction_wins() {
        for status in [200, 401, 403, 404, 500, 502] {
            assert_eq!(
                auction_outcome(&format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n\r\n"
                )),
                "other"
            );
        }
        assert_eq!(
            auction_outcome("HTTP/1.1 403 Forbidden\r\n\r\noutbid for the slot"),
            "other"
        );
    }

    #[test]
    fn only_one_explicit_header_establishes_the_outcome() {
        assert_eq!(
            auction_outcome("HTTP/1.1 502 Bad Gateway\r\nX-Nucleus-Auction-Outcome: won\r\n\r\n"),
            "won",
            "the slot was paid for even when the downstream fetch failed"
        );
        assert_eq!(
            auction_outcome("HTTP/1.1 403 Forbidden\r\nx-nucleus-auction-outcome: outbid\r\n\r\n"),
            "outbid"
        );
        for reply in [
            "HTTP/1.1 200 OK\r\nx-nucleus-auction-outcome: outbid\r\n\r\n",
            "HTTP/1.1 200 OK\r\nx-nucleus-auction-outcome: won\r\nx-nucleus-auction-outcome: won\r\n\r\n",
            "HTTP/1.1 200 OK\r\nx-nucleus-auction-outcome: won",
            "HTTP/1.1 200 OK\r\n\r\nx-nucleus-auction-outcome: won",
            "garbage 200 OK\r\nx-nucleus-auction-outcome: won\r\n\r\n",
        ] {
            assert_eq!(auction_outcome(reply), "other", "{reply:?}");
        }
    }
}
