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
//!   - its root filesystem is mounted read-only.
//!
//! Zero dependencies (it is baked into the musl rootfs as a static binary,
//! exactly like `nucleus-net-probe`); everything is a `std::fs` read of procfs.
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

/// The contention probe's per-request line and its summary line, read back off
/// the guest console by whoever ran the pod.
const CONTEND_SENTINEL: &str = "NUCLEUS_CONTEND";

fn main() {
    // Stage 2: invoked as a `/v1/run` command
    // (`{"args": ["/usr/local/bin/nucleus-workload-probe", "--run-child"]}`)
    // rather than as the pod workload. A command the tool-proxy runs for the
    // agent must not be guest root: the proxy is PID 1 and root, and its
    // environment holds the pod's secrets.
    if std::env::args().nth(1).as_deref() == Some("--run-child") {
        let status = std::fs::read_to_string("/proc/self/status");
        let pid1_environ = std::fs::read("/proc/1/environ");
        let fails = run_child_failures(status.as_deref().ok(), &pid1_environ);
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
            Err(e) => println!("{CONTEND_SENTINEL}: FAIL spawn child {i}: {e}"),
        }
    }
    let (mut won, mut outbid, mut denied, mut other) = (0u32, 0u32, 0u32, 0u32);
    for c in children {
        let out = match c.wait_with_output() {
            Ok(o) => o,
            Err(e) => {
                println!("{CONTEND_SENTINEL}: FAIL wait: {e}");
                continue;
            }
        };
        let line = String::from_utf8_lossy(&out.stdout);
        // Echo the child's line so the console carries every verdict.
        print!("{line}");
        eprint!("{line}");
        if line.contains("outcome=won") {
            won += 1;
        } else if line.contains("outcome=outbid") {
            outbid += 1;
        } else if line.contains("outcome=denied") {
            denied += 1;
        } else {
            other += 1;
        }
    }
    let contested = won >= 1 && outbid >= 1;
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
            let mut parts: Vec<&std::ffi::OsStr> = std::path::Path::new(path).iter().collect();
            parts.remove(0);
            for part in parts {
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
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(30)));
    if let Err(e) = stream.write_all(request.as_bytes()) {
        println!("{CONTEND_SENTINEL}: bid={bid} pid={pid} outcome=write-failed error={e}");
        return 1;
    }
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    let reply = String::from_utf8_lossy(&reply);
    let status = reply.split_whitespace().nth(1).unwrap_or("?").to_string();
    let outcome = if reply.contains("outbid for the") {
        "outbid"
    } else if reply.contains("slot not granted") || reply.contains("required to bid") {
        "denied"
    } else if status.starts_with('2') || status.starts_with('4') || status.starts_with('5') {
        // Anything the auction let THROUGH: the handler's own answer (an egress
        // refusal is fine — the slot was won, the fetch itself is not the
        // question).
        "won"
    } else {
        "other"
    };
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
    0
}

/// The `--run-child` verdict, pure so it is testable off-guest.
///
/// * the real uid (`Uid:` first field) must not be 0;
/// * `/proc/1/environ` must be refused with a PERMISSION error. "Could not
///   look" for any other reason (no procfs, no PID 1) is not "looked and it
///   was denied" (ADR 0007 A-1), so it fails too: the probe cannot vouch for
///   containment it did not observe.
fn run_child_failures(
    status: Option<&str>,
    pid1_environ: &std::io::Result<Vec<u8>>,
) -> Vec<String> {
    let mut fails = Vec::new();
    let uid = status.and_then(|s| {
        s.lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|v| v.parse::<u32>().ok())
    });
    match uid {
        Some(0) => fails.push("the /v1/run child runs as root (uid 0)".to_string()),
        Some(_) => {}
        None => fails.push("could not read the child's uid from /proc/self/status".to_string()),
    }
    match pid1_environ {
        Ok(_) => fails
            .push("the /v1/run child can read /proc/1/environ — the runtime's secrets".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
        Err(e) => fails.push(format!(
            "/proc/1/environ unreadable for a reason other than permission ({e}); \
             containment was not observed"
        )),
    }
    fails
}

#[cfg(test)]
mod tests {
    use super::run_child_failures;
    use std::io;

    const NOBODY: &str = "Name:\tprobe\nUid:\t65534\t65534\t65534\t65534\n";
    const ROOT: &str = "Name:\tprobe\nUid:\t0\t0\t0\t0\n";

    fn denied() -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }

    #[test]
    fn an_unprivileged_child_that_is_refused_pid1s_environ_passes() {
        assert!(run_child_failures(Some(NOBODY), &denied()).is_empty());
    }

    /// The pre-fix guest: root, and the read succeeds.
    #[test]
    fn a_root_child_that_reads_pid1s_environ_fails_twice() {
        let fails = run_child_failures(Some(ROOT), &Ok(b"K=V\0".to_vec()));
        assert_eq!(fails.len(), 2, "{fails:?}");
    }

    #[test]
    fn could_not_look_is_not_denied() {
        let missing = Err(io::Error::from(io::ErrorKind::NotFound));
        assert_eq!(run_child_failures(Some(NOBODY), &missing).len(), 1);
        assert_eq!(run_child_failures(None, &denied()).len(), 1);
    }
}
