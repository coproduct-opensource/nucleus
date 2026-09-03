//! Reading the guest console when a pod fails to come up.
//!
//! # Why
//!
//! A pod that does not become healthy reports `proxy health check timed out`.
//! That sentence is true and almost never the cause. The cause is in the guest
//! console, which the node already captures to `firecracker.log` and never
//! looked at.
//!
//! The cost is concrete. Booting a pod from a current `nucleus-node` against
//! the pinned v2.1.0 rootfs produces:
//!
//! ```text
//! nucleus-guest-init error: missing approval secret (set nucleus.approval_secret …)
//! Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000000
//! ```
//!
//! because #2214 (2026-08-08) stopped the node injecting
//! `nucleus.approval_secret` while the July rootfs's guest-init still requires
//! it. PID 1 exits and the kernel panics. What the operator was told was
//! "health check timed out". Finding the real reason took mounting the image
//! and reading a console by hand.
//!
//! This turns that into one sentence at the moment of failure.
//!
//! # What it is not
//!
//! Pattern matching on console text, and deliberately so: it needs no protocol
//! change, no version marker, and no cooperation from the guest — which matters
//! precisely because the guests it must diagnose are OLD ones that cannot be
//! changed. A signature that stops matching degrades to today's behaviour
//! (the generic message), never to a wrong answer, and
//! [`the_matcher_still_recognises_its_own_signatures`] fails if one rots.

// Everything here is reached only from the Firecracker spawn path, which is
// Linux-gated, so on other hosts the whole module is legitimately unreachable.
// The tests below still exercise `diagnose` on every platform.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{ApiError, PROXY_HEALTH_TIMEOUT_SECS_DEFAULT};

/// A known failure signature and what it means.
struct Signature {
    /// Substring to look for in the guest console.
    marker: &'static str,
    /// What the operator should be told.
    explanation: &'static str,
}

/// Ordered most-specific first: the first match wins, so a precise cause beats
/// the generic "init died" that always accompanies it.
const SIGNATURES: &[Signature] = &[
    Signature {
        marker: "missing approval secret",
        explanation:
            "the guest rootfs PREDATES this node. #2214 (2026-08-08) replaced the guest's \
             shared approval secret with Ed25519 verification against the node's public key, \
             so this node sends `nucleus.approval_pubkeys` and no longer sends \
             `nucleus.approval_secret` — which this rootfs's guest-init still requires. \
             Rebuild the rootfs from this checkout: `bash \
             scripts/firecracker/build-rootfs.sh` (or `just guest-rootfs`). It preflights \
             the host tooling first and, on macOS, prints how to run it in the Linux VM. \
             Or run a nucleus-node from the same release as the rootfs.",
    },
    Signature {
        marker: "failed to fetch identity",
        explanation: "the guest could not reach the workload API over vsock. Either the node's \
             WorkloadApiVsockBridge did not start before the guest connected, or the \
             per-pod socket (vsock.sock_<port>) is missing — check the pod directory for a \
             `vsock.sock_*` entry alongside `vsock.sock`.",
    },
    Signature {
        marker: "failed to exec",
        explanation: "guest-init could not start the tool-proxy: the binary is missing from the \
             rootfs at /usr/local/bin/nucleus-tool-proxy, or is built for the wrong \
             architecture or libc.",
    },
    Signature {
        marker: "panicked at",
        explanation: "a guest process panicked. As PID 1 that takes the kernel with it, so the \
             panic message above is the real failure, not the health-check timeout.",
    },
    // Least specific: always present when init dies, so it must sort last.
    Signature {
        marker: "Attempted to kill init",
        explanation:
            "PID 1 exited, so the guest kernel panicked. The lines immediately above this \
             in the console are the actual cause.",
    },
];

/// Diagnose a failed pod launch from its captured console.
///
/// Returns `None` when the console is unreadable or carries no known signature —
/// in which case the caller's own message stands, unchanged.
pub(crate) fn diagnose(console_path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(console_path).ok()?;
    let hit = SIGNATURES.iter().find(|s| text.contains(s.marker))?;

    // The console line that matched, so the operator sees the evidence and not
    // only our interpretation of it.
    let evidence = text
        .lines()
        .find(|l| l.contains(hit.marker))
        .unwrap_or("")
        .trim()
        .chars()
        .take(200)
        .collect::<String>();

    Some(format!(
        "guest console says: \"{evidence}\" — {}",
        hit.explanation
    ))
}

/// The host-side wait for the guest to become healthy.
///
/// # Why this carries the `proxy.health_wait` stage
///
/// It is the single largest span in a pod launch, and until now it had none.
/// `boot_trace` reported 92% of warm pod-create wall time as `unaccounted`
/// (~2.3 s of ~2.5 s) because the last measured stage ended at +200 ms and
/// nothing covered the wait that follows (#2374).
///
/// The instrumentation was not missing — it was ATTACHED TO THE WRONG FUNCTION.
/// When this function moved out of `main.rs` into this module (#2355), its
/// attributes stayed behind and silently reattached to the next item, which was
/// `serve_grpc`: a server that runs for the node's entire lifetime. Rust
/// attributes bind to the following item regardless of the blank line between
/// them, so this compiled, ran, and mislabelled a long-lived task as a boot
/// stage while the real stage went unmeasured.
#[tracing::instrument(skip_all, fields(boot.stage = "proxy.health_wait"))]
pub(crate) async fn wait_for_proxy_health(
    addr: SocketAddr,
    console: &Path,
) -> Result<(), ApiError> {
    wait_for_proxy_health_within(
        addr,
        Duration::from_secs(
            std::env::var("NUCLEUS_NODE_PROXY_HEALTH_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(PROXY_HEALTH_TIMEOUT_SECS_DEFAULT),
        ),
    )
    .await
    .map_err(|e| {
        // The console the node already captured usually says exactly why.
        // Reporting only "health check timed out" is true and almost never the
        // cause; finding the real one meant mounting the image by hand.
        match diagnose(console) {
            Some(d) => ApiError::Driver(format!("{e}\n\n{d}")),
            None => e,
        }
    })
}

/// What the last health probe actually saw.
///
/// # Why this type exists
///
/// The probe used to discard every outcome into one message: "proxy health check
/// timed out". A refused connection, a guest that answered `401`, a bridge that
/// answered `502`, and a guest that never came up were indistinguishable — to an
/// operator and to whoever was debugging it. That is the same defect class as a
/// panic naming `reqwest` when the real cause was a missing CA store: the
/// information existed and the code threw it away.
#[derive(Debug, Clone)]
enum HealthProbe {
    /// Nothing has been attempted yet.
    NotAttempted,
    /// The TCP connection to the signed proxy was refused or failed.
    ConnectFailed(String),
    /// Connected, but the request could not be written.
    WriteFailed(String),
    /// Request sent, but no readable response came back.
    ReadFailed(String),
    /// The guest answered — with something other than 200.
    ///
    /// This is the case worth separating most: it means the whole chain WORKS
    /// (signed proxy, bridge, guest) and the guest is refusing, which is a
    /// completely different investigation from "nothing is listening".
    NotOk { status: String },
}

impl std::fmt::Display for HealthProbe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthProbe::NotAttempted => write!(f, "no probe completed"),
            HealthProbe::ConnectFailed(e) => write!(
                f,
                "could not connect to the signed proxy ({e}) — the host-side proxy is not \
                 accepting, so the guest was never reached"
            ),
            HealthProbe::WriteFailed(e) => {
                write!(f, "connected but could not send the request ({e})")
            }
            HealthProbe::ReadFailed(e) => write!(
                f,
                "sent the request but got no response ({e}) — the signed proxy accepted and \
                 then failed to complete, so look at the vsock bridge rather than the guest"
            ),
            HealthProbe::NotOk { status } => write!(
                f,
                "the guest ANSWERED with `{status}` instead of 200 — the chain works end to \
                 end and the guest is refusing, so this is an authorization or routing \
                 question, not a liveness one"
            ),
        }
    }
}

async fn wait_for_proxy_health_within(addr: SocketAddr, budget: Duration) -> Result<(), ApiError> {
    let start = std::time::Instant::now();
    let host = addr.ip();
    let mut last = HealthProbe::NotAttempted;
    while start.elapsed() < budget {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(mut stream) => {
                let request =
                    format!("GET /v1/health HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
                if let Err(e) = stream.write_all(request.as_bytes()).await {
                    last = HealthProbe::WriteFailed(e.to_string());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }

                let mut buf = Vec::new();
                if let Err(e) = stream.read_to_end(&mut buf).await {
                    last = HealthProbe::ReadFailed(e.to_string());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
                let response = String::from_utf8_lossy(&buf);
                if response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200") {
                    return Ok(());
                }
                // Keep only the status line. The body may carry guest-influenced
                // text, and this string ends up in an API error and the node log.
                let status = response.lines().next().unwrap_or("<empty response>");
                last = HealthProbe::NotOk {
                    status: status.chars().take(120).collect(),
                };
            }
            Err(e) => last = HealthProbe::ConnectFailed(e.to_string()),
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(ApiError::Driver(format!(
        "proxy health check timed out after {}s: {last}. The guest fetches its SVID and \
         session token from the host over vsock before it serves, so a slow image can \
         legitimately exceed this; raise NUCLEUS_NODE_PROXY_HEALTH_TIMEOUT_SECS if the pod \
         log shows the guest still starting.",
        budget.as_secs()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn console(body: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().expect("temp");
        write!(f, "{body}").expect("write");
        f
    }

    /// The failure that motivated this module, end to end.
    #[test]
    fn the_version_skew_is_named_not_guessed() {
        let f = console(
            "[    1.47] Run /init as init process\n\
             fetched identity: spiffe://nucleus.local/ns/pods/sa/abc\n\
             nucleus-guest-init error: missing approval secret (set nucleus.approval_secret …)\n\
             [    1.58] Kernel panic - not syncing: Attempted to kill init!\n",
        );
        let d = diagnose(f.path()).expect("a known signature must be recognised");
        assert!(d.contains("PREDATES this node"), "{d}");
        assert!(
            d.contains("#2214"),
            "the operator needs the change to look up: {d}"
        );
        assert!(
            d.contains("build-rootfs.sh"),
            "a diagnosis without a runnable action is half a diagnosis: {d}"
        );
    }

    /// Specificity: the kernel panic accompanies every init death, so a precise
    /// cause must win over it. Without this ordering the module would always
    /// report "PID 1 exited", which the operator can already see.
    #[test]
    fn a_specific_cause_beats_the_generic_panic() {
        let f = console(
            "nucleus-guest-init error: missing approval secret\n\
             Kernel panic - not syncing: Attempted to kill init!\n",
        );
        let d = diagnose(f.path()).unwrap();
        assert!(d.contains("PREDATES this node"));
        assert!(!d.contains("The lines immediately above"));
    }

    /// The generic signature still fires when nothing more specific is present —
    /// otherwise ordering would have made it dead code.
    #[test]
    fn the_generic_panic_is_reported_when_it_is_all_there_is() {
        let f = console("[  1.5] Kernel panic - not syncing: Attempted to kill init!\n");
        let d = diagnose(f.path()).unwrap();
        assert!(d.contains("PID 1 exited"));
    }

    /// A healthy or unknown console must yield nothing, so the caller's own
    /// message stands. Guessing would be worse than silence.
    #[test]
    fn an_unrecognised_console_produces_no_diagnosis() {
        let f = console("[  1.4] Run /init as init process\nfetched identity: ok\n");
        assert!(diagnose(f.path()).is_none());
        assert!(diagnose(Path::new("/nonexistent/firecracker.log")).is_none());
    }

    /// Non-vacuity for the whole table. A signature whose text drifts out of the
    /// guest's actual output stops matching silently, and this module would
    /// quietly return to being useless — the exact failure it exists to fix,
    /// one level up.
    #[test]
    fn the_matcher_still_recognises_its_own_signatures() {
        for s in SIGNATURES {
            let f = console(&format!("prelude\n{}\n", s.marker));
            let d = diagnose(f.path())
                .unwrap_or_else(|| panic!("signature `{}` no longer matches", s.marker));
            assert!(!d.is_empty());
        }
        assert!(SIGNATURES.len() >= 4, "the table has shrunk unexpectedly");
    }
}
