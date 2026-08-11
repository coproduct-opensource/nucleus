//! `nucleus-egress-probe` — the C6 egress backstop, checked on the REAL guest.
//!
//! The Lean egress matcher is proved (`EgressConfinementExtracted.lean`:
//! `unmatched_is_dropped`, deny-before-allow, …) and `net::apply_default_deny`
//! is host-unit-tested — but nothing checked that the netns/iptables default-deny
//! egress policy is *actually applied inside a booted microVM*. The C6 ledger
//! note says as much: channels 5 and 10 (in-shell / raw-socket egress) are
//! `backstopped-only`, "fenced only by a *documented* netns default-deny, not
//! yet proven-applied-on-boot". This binary converts that from *documented* to
//! *runtime-observed*: it runs as the workload inside a `network.allow: []` pod
//! and asserts, from a process running as the workload uid in the guest, that
//! egress is confined.
//!
//! It is the network twin of `nucleus-workload-probe`: zero dependencies, a
//! static musl binary baked into the rootfs, and its verdict is a sentinel line
//! on BOTH stdout and stderr plus the exit code — the tool-proxy drains the
//! child's stderr into the guest console log, where the boot gate greps it back
//! on the host.
//!
//! # Anti-vacuity (the load-bearing part)
//!
//! A probe that reports PASS because it is *broken* — a no-op that never really
//! attempts a connect — would certify nothing. A security property is an
//! uninhabitedness claim, and "no external host is reachable" is only the
//! guarantee if the probe genuinely tried and the network genuinely refused. So
//! the verdict rests on two independent witnesses:
//!
//!   - POSITIVE control: a `socketpair(AF_UNIX)` byte round-trip that MUST
//!     succeed. It proves the probe is a live process that can create sockets and
//!     move bytes — so a denied TCP connect is a *refusal*, not a broken binary
//!     that fails every syscall. (It is AF_UNIX on purpose: the guest workload
//!     runs with loopback DOWN — `/sys/class/net/lo/flags` = `0x8`, documented in
//!     nucleus-guest-init — and under `network.allow: []` there is no reachable
//!     TCP endpoint by design, so a loopback or on-net positive control cannot
//!     exist here. The socketpair needs neither an interface nor a route.)
//!   - NEGATIVE posture: a raw TCP connect to each of ≥1 non-allowlisted hosts
//!     MUST fail. Refusing to pass when *zero* targets were probed closes the
//!     other vacuous door (an empty target list).
//!
//! PASS requires the socketpair witness AND at least one probed deny target AND
//! every connect failing.
//!
//! # Why TCP egress only — and why it must be fast
//!
//! The probe is deliberately narrow: it observes **TCP egress confinement** on
//! the live guest (C6 channels 5 and 10 — in-shell / raw-socket egress). DNS
//! fail-closed (channel 6) is a *separate* property, already gated by
//! `the_dns_proxy_has_no_upstream_and_cannot_forward` and the pure
//! `net::dnsmasq_config`; a fully default-deny pod has no resolver at all, so a
//! DNS resolve there only *hangs* (`getaddrinfo` blocks on its own multi-second
//! timeout) and observes nothing new.
//!
//! That hang matters because the workload's window is tiny: the tool-proxy comes
//! up late (measured `proxy.health_wait` ≈ 5.7 s of a ~6 s boot), the workload is
//! spawned only after it is healthy, and the guest is torn down shortly after. A
//! probe that blocks even a few hundred ms may be killed before its sentinel
//! drains to the console. So every check here is non-blocking: the socketpair is
//! instant, and a denied connect returns `ENETUNREACH` immediately (the fenced
//! guest has no route out). The verdict is emitted within a few ms of start.
//!
//! # Configuration (for the host-side falsifier)
//!
//! Defaults target the public internet, which is what the real guest sees. The
//! deny targets and name are overridable by environment variable so
//! `scripts/check-egress-probe.sh` can point them at a hermetic peer it controls
//! inside a netns.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const PASS_SENTINEL: &str = "NUCLEUS_EGRESS_PROBE: PASS";
const FAIL_SENTINEL: &str = "NUCLEUS_EGRESS_PROBE: FAIL";

const DEFAULT_DENY_TARGETS: &str = "1.1.1.1:443,8.8.8.8:53";
const DEFAULT_TIMEOUT_MS: u64 = 500;

fn main() {
    let mut fails: Vec<String> = Vec::new();

    let timeout = Duration::from_millis(
        std::env::var("NUCLEUS_EGRESS_PROBE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_MS),
    );

    check_positive_control(&mut fails);
    check_denied_connects(&mut fails, timeout);

    if fails.is_empty() {
        // Both streams: the proxy drains stderr into the guest log, but a direct
        // /v1/run capture reads stdout.
        println!("{PASS_SENTINEL}");
        eprintln!("{PASS_SENTINEL}");
    } else {
        let reason = fails.join("; ");
        println!("{FAIL_SENTINEL}: {reason}");
        eprintln!("{FAIL_SENTINEL}: {reason}");
        std::process::exit(1);
    }
}

/// POSITIVE control — the anti-vacuity witness. A `socketpair(AF_UNIX)` byte
/// round-trip that MUST succeed. It proves the probe is a live process that can
/// create sockets and move bytes, so a denied TCP connect below is a refusal and
/// not a binary that errors on every syscall. AF_UNIX needs neither a network
/// interface (the guest's loopback is DOWN) nor a route (the pod is default-deny).
fn check_positive_control(fails: &mut Vec<String>) {
    let (mut a, mut b) = match UnixStream::pair() {
        Ok(p) => p,
        Err(err) => {
            fails.push(format!(
                "positive control: could not create a socketpair ({err}) — the probe process \
                 cannot make sockets, so a denied connect proves nothing (refusing to pass \
                 vacuously)"
            ));
            return;
        }
    };
    // A short read timeout so a broken pair reports rather than blocks.
    let _ = b.set_read_timeout(Some(Duration::from_millis(500)));
    let msg = b"egress-probe-liveness";
    if let Err(err) = a.write_all(msg) {
        fails.push(format!("positive control: socketpair write failed ({err})"));
        return;
    }
    let mut buf = [0u8; 21];
    match b.read_exact(&mut buf) {
        Ok(()) if buf == *msg => {
            eprintln!("NUCLEUS_EGRESS_CHECK: positive-control socketpair round-trip ok")
        }
        Ok(()) => fails.push("positive control: socketpair round-trip returned wrong bytes".into()),
        Err(err) => fails.push(format!(
            "positive control: socketpair read failed ({err}) — the probe cannot move bytes \
             through a socket, so a denied connect proves nothing (refusing to pass vacuously)"
        )),
    }
}

/// NEGATIVE posture — a raw TCP connect to a non-allowlisted host MUST fail
/// under the netns default-deny OUTPUT policy (or the absence of any route out).
/// A SUCCESS means the fence is not applied on this guest: the exact thing C6
/// phase 2 exists to catch.
fn check_denied_connects(fails: &mut Vec<String>, timeout: Duration) {
    let targets = std::env::var("NUCLEUS_EGRESS_PROBE_DENY_TARGETS")
        .unwrap_or_else(|_| DEFAULT_DENY_TARGETS.to_string());
    let mut probed = 0usize;
    for target in targets.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        // Parse to a SocketAddr WITHOUT DNS: the connect posture must be
        // independent of the resolver (that is a separate check). Literal
        // IP:port only; a hostname target here is a config error.
        let addr = match target.parse::<std::net::SocketAddr>() {
            Ok(a) => a,
            Err(_) => {
                fails.push(format!(
                    "deny target {target:?} is not a literal IP:port — connect posture must not \
                     depend on DNS"
                ));
                continue;
            }
        };
        probed += 1;
        match TcpStream::connect_timeout(&addr, timeout) {
            Err(err) => {
                eprintln!("NUCLEUS_EGRESS_CHECK: denied-connect {addr} REFUSED ({err}) (ok)");
            }
            Ok(_) => fails.push(format!(
                "egress to {addr} SUCCEEDED — the netns default-deny OUTPUT policy is NOT applied \
                 on this guest; in-shell / raw-socket egress is unconfined"
            )),
        }
    }
    if probed == 0 {
        fails.push(
            "no deny targets were probed — NUCLEUS_EGRESS_PROBE_DENY_TARGETS is empty, so the \
             posture check would pass vacuously"
                .to_string(),
        );
    }
}
