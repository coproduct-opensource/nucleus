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
//! A fence that blocks *everything* — a dead guest NIC, an unconfigured
//! loopback, or a probe that cannot run — trivially passes a "connect fails"
//! check. That is the textbook vacuous pass: a security property is an
//! uninhabitedness claim, and "no host is reachable because the stack is dead"
//! is not the guarantee "an arbitrary host is denied by policy". So the probe
//! carries a **satisfiable witness beside the refutable one**:
//!
//!   - POSITIVE control: a loopback connection the guest MUST be able to make
//!     (the default-deny chain accepts `-o lo`). If it fails, the probe reports
//!     FAIL — it refuses to certify a fence it cannot distinguish from a dead
//!     network.
//!   - NEGATIVE posture: a raw TCP connect to a non-allowlisted host, and a DNS
//!     resolve of an off-allowlist name, which MUST both fail.
//!
//! PASS requires the positive control to succeed AND every negative to fail.
//!
//! # Configuration (for the host-side falsifier)
//!
//! Defaults target the public internet, which is what the real guest sees. The
//! deny targets and name are overridable by environment variable so
//! `scripts/check-egress-probe.sh` can point them at a hermetic peer it controls
//! inside a netns — proving the probe reds when the fence is removed and passes
//! when it is present, without reaching the real internet.

use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;

const PASS_SENTINEL: &str = "NUCLEUS_EGRESS_PROBE: PASS";
const FAIL_SENTINEL: &str = "NUCLEUS_EGRESS_PROBE: FAIL";

const DEFAULT_DENY_TARGETS: &str = "1.1.1.1:443,8.8.8.8:53";
const DEFAULT_DENY_NAME: &str = "example.com";
const DEFAULT_TIMEOUT_MS: u64 = 1200;

fn main() {
    let mut fails: Vec<String> = Vec::new();

    let timeout = Duration::from_millis(
        std::env::var("NUCLEUS_EGRESS_PROBE_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_MS),
    );

    check_positive_control(&mut fails, timeout);
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

/// POSITIVE control — the anti-vacuity witness. The default-deny chain accepts
/// loopback (`-A OUTPUT -o lo -j ACCEPT`), so a connect to a listener the probe
/// itself binds on `127.0.0.1` MUST succeed. A listening socket accepts the SYN
/// into its backlog without an `accept()` call, so no second thread is needed.
///
/// If this fails, the guest network stack is not usable at all — and every
/// "connect was denied" result below would be indistinguishable from "the net is
/// dead / the probe is broken". The probe then reports FAIL rather than passing
/// on a fence it cannot tell apart from a corpse.
fn check_positive_control(fails: &mut Vec<String>, timeout: Duration) {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(err) => {
            fails.push(format!(
                "positive control: could not bind a loopback listener ({err}) — cannot certify \
                 egress confinement without a live-stack witness (refusing to pass vacuously)"
            ));
            return;
        }
    };
    let addr = match listener.local_addr() {
        Ok(a) => a,
        Err(err) => {
            fails.push(format!("positive control: no local_addr on the listener ({err})"));
            return;
        }
    };
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => eprintln!("NUCLEUS_EGRESS_CHECK: positive-control loopback={addr} CONNECTED (ok)"),
        Err(err) => fails.push(format!(
            "positive control: loopback connect to {addr} FAILED ({err}) — the guest network stack \
             is dead or the probe cannot run, so a denied external connect proves nothing \
             (refusing to pass vacuously)"
        )),
    }
}

/// NEGATIVE posture — a raw TCP connect to a non-allowlisted host MUST fail
/// under the netns default-deny OUTPUT policy. A SUCCESS means the fence is not
/// applied on this guest: the exact thing C6 phase 2 exists to catch.
fn check_denied_connects(fails: &mut Vec<String>, timeout: Duration) {
    let targets = std::env::var("NUCLEUS_EGRESS_PROBE_DENY_TARGETS")
        .unwrap_or_else(|_| DEFAULT_DENY_TARGETS.to_string());
    let mut probed = 0usize;
    for target in targets.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        probed += 1;
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

/// NEGATIVE posture — resolving an off-allowlist name MUST fail. The guest
/// resolver is the gateway dnsmasq built by `net::dnsmasq_config` with
/// `no-resolv` and only static `address=` entries: an unlisted name has no
/// answer and no upstream to forward to. A successful resolve means the resolver
/// is forwarding — a tunnel/exfil channel.
fn check_denied_dns(fails: &mut Vec<String>) {
    let name = std::env::var("NUCLEUS_EGRESS_PROBE_DENY_NAME")
        .unwrap_or_else(|_| DEFAULT_DENY_NAME.to_string());
    // Port is irrelevant to resolution; :80 just makes it a valid host:port.
    match (name.as_str(), 80u16).to_socket_addrs() {
        Err(err) => {
            eprintln!("NUCLEUS_EGRESS_CHECK: denied-dns {name:?} UNRESOLVED ({err}) (ok)");
        }
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                fails.push(format!(
                    "DNS resolved {name:?} to {addr} — the guest resolver is forwarding to an \
                     upstream instead of failing closed on an unlisted name"
                ));
            } else {
                eprintln!("NUCLEUS_EGRESS_CHECK: denied-dns {name:?} resolved to no addresses (ok)");
            }
        }
    }
}
