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

fn main() {
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
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(fd) = name.parse::<u32>() {
                fds.push(fd);
            }
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
