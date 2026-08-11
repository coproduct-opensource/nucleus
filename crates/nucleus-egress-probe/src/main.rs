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
//!     MUST fail, and a DNS resolve of an off-allowlist name MUST NOT resolve.
//!     Refusing to pass when *zero* targets were probed closes the other vacuous
//!     door (an empty target list).
//!
//! PASS requires the socketpair witness AND at least one probed deny target AND
//! every negative failing.
//!
//! # Bounded, non-hanging
//!
//! In a fully-fenced pod there is no resolver, so `getaddrinfo` on an off-list
//! name blocks until its own multi-second timeout — long enough that the pod is
//! torn down before the verdict is emitted. The DNS check therefore runs on a
//! worker thread with a short join bound; not resolving within the bound is the
//! expected fenced outcome, not a hang. Connects use a short timeout too. The
//! sentinel is emitted promptly so it reaches the guest log within the workload's
//! lifetime.
//!
//! # Configuration (for the host-side falsifier)
//!
//! Defaults target the public internet, which is what the real guest sees. The
//! deny targets and name are overridable by environment variable so
//! `scripts/check-egress-probe.sh` can point them at a hermetic peer it controls
//! inside a netns.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const PASS_SENTINEL: &str = "NUCLEUS_EGRESS_PROBE: PASS";
const FAIL_SENTINEL: &str = "NUCLEUS_EGRESS_PROBE: FAIL";

const DEFAULT_DENY_TARGETS: &str = "1.1.1.1:443,8.8.8.8:53";
const DEFAULT_DENY_NAME: &str = "example.com";
const DEFAULT_TIMEOUT_MS: u64 = 700;
const DNS_BOUND_MS: u64 = 700;

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
    check_denied_dns(&mut fails);

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

/// NEGATIVE posture — resolving an off-allowlist name MUST NOT succeed. A guest
/// with a resolver (dnsmasq via `net::dnsmasq_config`) fails closed on an
/// unlisted name (`no-resolv`, no upstream); a fully default-deny pod has no
/// resolver reachable at all. Either way the resolve must not return an address.
///
/// Bounded: `getaddrinfo` blocks on its own multi-second timeout when no resolver
/// answers, which would outlive the pod. Run it on a worker thread and treat "no
/// answer within the bound" as the expected fenced outcome — the sentinel must
/// not wait on a resolver that is designed not to exist.
fn check_denied_dns(fails: &mut Vec<String>) {
    let name = std::env::var("NUCLEUS_EGRESS_PROBE_DENY_NAME")
        .unwrap_or_else(|_| DEFAULT_DENY_NAME.to_string());
    let (tx, rx) = mpsc::channel();
    let probe_name = name.clone();
    thread::spawn(move || {
        // Port is irrelevant to resolution; :80 just makes it a valid host:port.
        let resolved = (probe_name.as_str(), 80u16)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next());
        let _ = tx.send(resolved);
    });
    match rx.recv_timeout(Duration::from_millis(DNS_BOUND_MS)) {
        Ok(Some(addr)) => fails.push(format!(
            "DNS resolved {name:?} to {addr} — the guest resolver is forwarding to an upstream \
             instead of failing closed on an unlisted name"
        )),
        Ok(None) => eprintln!("NUCLEUS_EGRESS_CHECK: denied-dns {name:?} UNRESOLVED (ok)"),
        Err(_) => {
            eprintln!("NUCLEUS_EGRESS_CHECK: denied-dns {name:?} no answer within bound (ok)")
        }
    }
}
