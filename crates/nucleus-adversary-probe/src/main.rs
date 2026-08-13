//! `nucleus-adversary-probe` — an ACTIVE attacker run as a pod's workload.
//!
//! `nucleus-workload-probe` is a passive posture reader (it looks at its own
//! `/proc/self/*` and reports booleans) and `nucleus-egress-probe` tests one axis
//! (TCP egress). This binary is their offensive twin: baked into a pod as the
//! `workload.command`, it *actively campaigns* against the sandbox from inside the
//! guest — trying to steal an identity secret from the mediator (PID 1), tamper
//! the read-only rootfs, and exfiltrate over the network — and reports whether the
//! pod **contained** every attempt. It is the microVM analogue of the in-process
//! `red_team_harness`: where that drives an LLM adversary against an in-process
//! Portcullis, this drives a scripted adversary against a *real booted pod*.
//!
//! # What it proves, and the anti-vacuity discipline
//!
//! A security property is an uninhabitedness claim: "the workload cannot reach the
//! mediator's secrets / cannot write the rootfs / cannot egress." An attacker that
//! is simply *broken* — one that never really tries — certifies nothing. So the
//! verdict rests on:
//!
//!   * a POSITIVE control (`NUCLEUS_ADVERSARY_CONTROL: live`): the probe can make a
//!     socket, move bytes, and read its own environment where the mediator planted
//!     `NUCLEUS_TOOL_PROXY_URL`. A dead attacker (crashed, no environment, no
//!     sockets) is **INCONCLUSIVE**, never CONTAINED;
//!   * per-stage `attempted=yes` lines, so a run that crashes after stage 1 is
//!     missing later stages and cannot look contained (the boot gate greps the
//!     full fixed stage list back on the host);
//!   * booleans ONLY — never a stolen value. The probe reporting a leak must not
//!     itself become the exfil channel to the host-readable console.
//!
//! Verdict: `CONTAINED` iff the control is live AND every stage attempted its
//! attack AND every attack was blocked; otherwise `BREACH:<stage>` (stage name
//! only) or `INCONCLUSIVE`.
//!
//! # Configuration (for the host-side falsifier)
//!
//! Each attack surface is overridable by env var so `scripts/check-adversary-
//! probe.sh` can reconstruct all three verdict states hermetically without a boot
//! (point a stage at a decoy secret / a writable dir / a live listener to force a
//! BREACH; withhold the proxy URL to force INCONCLUSIVE). In the real guest the
//! defaults hit the real surfaces (`/proc/1/environ`, `/`, the public internet).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// The FM-5 identity variables the workload must never obtain — kept in sync with
/// `nucleus-workload-probe`'s `IDENTITY_VARS` and `nucleus-tool-proxy`'s tests.
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

/// The e2e canary's non-secret PREFIX (the CI plants `NUCLEUS_E2E_CANARY=<prefix>
/// <hex>` in the NODE env). Matching only the prefix means a positive detection is
/// still reported as a boolean; the full secret is never echoed.
const CANARY_PREFIX: &str = "nucleus-e2e-canary-";

fn main() {
    let mut breaches: Vec<&'static str> = Vec::new();
    let timeout = Duration::from_millis(
        env_var("NUCLEUS_ADVERSARY_TIMEOUT_MS")
            .and_then(|v| v.parse().ok())
            .unwrap_or(500),
    );

    // The campaign — each stage attempts a real attack and reports a boolean.
    stage_pid1_secret_theft(&mut breaches);
    stage_rootfs_tamper(&mut breaches);
    stage_exfil(&mut breaches, timeout);

    // The positive control decides whether a "no breach" result means anything.
    let live = control_live();
    emit(&format!(
        "NUCLEUS_ADVERSARY_CONTROL: {}",
        if live { "live" } else { "dead" }
    ));

    if !live {
        // A dead attacker proves nothing — refuse to certify containment.
        emit("NUCLEUS_ADVERSARY: INCONCLUSIVE");
        std::process::exit(2);
    }
    if let Some(stage) = breaches.first() {
        emit(&format!("NUCLEUS_ADVERSARY: BREACH:{stage}"));
        std::process::exit(1);
    }
    emit("NUCLEUS_ADVERSARY: CONTAINED");
}

/// Stage 1 — try to steal an identity secret from the mediator (PID 1). The
/// workload must never be able to read the tool-proxy's environment; if it can and
/// an `IDENTITY_VARS` key or the canary prefix is present, that is a BREACH. Report
/// only booleans, never the value read (the probe must not become the leak).
fn stage_pid1_secret_theft(breaches: &mut Vec<&'static str>) {
    let path =
        env_var("NUCLEUS_ADVERSARY_PID1_ENVIRON").unwrap_or_else(|| "/proc/1/environ".to_string());
    let (looked, stole) = match std::fs::read(&path) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            let has_identity_key = text.split('\0').any(|entry| {
                let key = entry.split('=').next().unwrap_or("");
                IDENTITY_VARS.contains(&key)
            });
            let has_canary = text.contains(CANARY_PREFIX);
            (true, has_identity_key || has_canary)
        }
        // Could not even read PID 1's environment — the strongest containment.
        Err(_) => (false, false),
    };
    stage_line(
        "pid1-secret-theft",
        true,
        !stole,
        &format!("looked={}", yn(looked)),
    );
    if stole {
        breaches.push("pid1-secret-theft");
    }
}

/// Stage 2 — try to tamper the (read-only) rootfs. A confined workload cannot
/// write outside its own scratch; a successful write to the target is a BREACH.
fn stage_rootfs_tamper(breaches: &mut Vec<&'static str>) {
    let dir = env_var("NUCLEUS_ADVERSARY_WRITE_TARGET").unwrap_or_else(|| "/".to_string());
    let target = format!("{}/.nucleus-adversary-tamper", dir.trim_end_matches('/'));
    let wrote = std::fs::write(&target, b"tamper").is_ok();
    if wrote {
        // If we somehow could, do not leave the artifact behind.
        let _ = std::fs::remove_file(&target);
    }
    stage_line("rootfs-tamper", true, !wrote, "");
    if wrote {
        breaches.push("rootfs-tamper");
    }
}

/// Stage 3 — try to exfiltrate over the network. Thin by design: the deep
/// netns/iptables version is `nucleus-egress-probe`; here egress is one axis of the
/// campaign. A non-allowlisted TCP connect that SUCCEEDS is a BREACH.
fn stage_exfil(breaches: &mut Vec<&'static str>, timeout: Duration) {
    let targets = env_var("NUCLEUS_ADVERSARY_DENY_TARGETS")
        .unwrap_or_else(|| "1.1.1.1:443,8.8.8.8:53".to_string());
    let mut probed = 0usize;
    let mut escaped = false;
    for target in targets.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        // Literal IP:port only — the exfil posture must not depend on a resolver.
        let Ok(addr) = target.parse::<std::net::SocketAddr>() else {
            continue;
        };
        probed += 1;
        if TcpStream::connect_timeout(&addr, timeout).is_ok() {
            escaped = true;
        }
    }
    let attempted = probed > 0;
    stage_line(
        "exfil",
        attempted,
        attempted && !escaped,
        &format!("targets={probed}"),
    );
    if escaped {
        breaches.push("exfil");
    } else if !attempted {
        // No targets probed — the posture would be vacuously "blocked".
        breaches.push("exfil-no-targets");
    }
}

/// The anti-vacuity witness. The attacker must be a live process that can make a
/// socket, move bytes, and read its own environment (where the mediator planted
/// `NUCLEUS_TOOL_PROXY_URL`). If any of that fails the attacker is dead and its
/// "no breach" result is meaningless — the verdict becomes INCONCLUSIVE.
fn control_live() -> bool {
    let socket_ok = UnixStream::pair()
        .and_then(|(mut a, mut b)| {
            b.set_read_timeout(Some(Duration::from_millis(500)))?;
            a.write_all(b"live")?;
            let mut buf = [0u8; 4];
            b.read_exact(&mut buf)?;
            Ok(&buf == b"live")
        })
        .unwrap_or(false);

    let env_ok = std::fs::read("/proc/self/environ")
        .map(|bytes| {
            String::from_utf8_lossy(&bytes)
                .split('\0')
                .any(|entry| entry.split('=').next() == Some("NUCLEUS_TOOL_PROXY_URL"))
        })
        .unwrap_or(false)
        // Fallback for the host falsifier, where /proc/self/environ may not reflect
        // an exported var identically across shells: trust the live process env too.
        || env_var("NUCLEUS_TOOL_PROXY_URL").is_some();

    socket_ok && env_ok
}

/// Emit a per-stage line. Booleans only — never a value.
fn stage_line(name: &str, attempted: bool, blocked: bool, extra: &str) {
    let line = format!(
        "NUCLEUS_ADVERSARY_STAGE {name}: attempted={} blocked={}{}",
        yn(attempted),
        yn(blocked),
        if extra.is_empty() {
            String::new()
        } else {
            format!(" {extra}")
        }
    );
    eprintln!("{line}");
    println!("{line}");
}

/// The verdict/control lines go to BOTH streams: the tool-proxy drains the child's
/// stderr into the guest console log (where the boot gate greps it), while a direct
/// `/v1/run` capture reads stdout.
fn emit(line: &str) {
    eprintln!("{line}");
    println!("{line}");
}

fn yn(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn env_var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}
