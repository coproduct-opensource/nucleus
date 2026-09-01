//! Where the guest tool-proxy's startup time goes.
//!
//! # The gap this closes
//!
//! `nucleus verify --tier2` reports ~7.7 s to create a pod. #2175 decomposed
//! that on the NODE side and found the answer is not on the node side:
//!
//! ```text
//!   0.38 s  host prep
//!   1.45 s  guest kernel to "Run /init as init process"
//!   ~0.1 s  guest-init (identity + task token over vsock)
//!   ~6.1 s  guest tool-proxy startup   <-- 79% of the wall clock
//! ```
//!
//! and said so plainly: *"that interior is currently unattributable because the
//! guest proxy runs with an error-only log filter and prints nothing.
//! Attributing (and then shrinking) that interior is the next increment."*
//! This module is that increment.
//!
//! Between `main()` and `TcpListener::bind` there are ~670 lines of
//! initialisation — sandbox proof, spec load, audit log, web-fetch client,
//! attestation verifier, policy load, node client — and not one of them timed
//! itself. A captured guest console confirms the silence: the kernel reaches
//! `/init` at 1.404 s, guest-init logs its last line at 1.511 s, and then
//! nothing is printed until the proxy is already serving.
//!
//! # Why a future wrapper rather than spans
//!
//! The node's [`boot_trace`](../../nucleus-node/src/boot_trace.rs) layer reads
//! `#[instrument]` spans out of its own subscriber. That does not reach here:
//! the tool-proxy is a different process in a different VM, and its output
//! reaches the host only as console text in `firecracker.log`. So this records
//! milestones in-process and emits ONE line before binding.
//!
//! [`Startup::timed`] wraps a future instead of bracketing it with two
//! statements, for a reason beyond taste: `main.rs` sits exactly on its
//! line-ratchet ceiling, so an instrumentation that cost two lines per call site
//! could not land at all. Wrapping costs zero.
//!
//! # Streaming, because the interesting case is a stall
//!
//! Each phase prints as it completes (`nucleus-startup-phase`), and the summary
//! (`nucleus-startup-trace`) prints before binding. The summary alone is not
//! enough: the first real boot with this module produced NO output at all,
//! because the proxy never reached `bind` — and a profiler that only speaks on
//! the success path is silent in precisely the case you built it for. The last
//! phase line printed names the last thing that finished; the stall is the next
//! one.
//!
//! # Reconciliation, kept honest
//!
//! The report prints `unaccounted = total - sum(milestones)`, following the same
//! rule #2175 set for the node: a profiler that always sums to 100% has stopped
//! being able to tell you it missed something. A large `unaccounted` here means
//! the expensive work is in a call nobody wrapped yet — which is a finding, not
//! a rounding error.

use std::time::Instant;

use crate::attestation::AttestationConfig;
use crate::Args;

/// Assemble the attestation verifier's config from the CLI args.
///
/// Extracted from `main` because `main.rs` is on its line-ratchet ceiling and
/// this instrumentation had to buy its own headroom — which is what the ratchet
/// is for. It is pure argument-shaping with no I/O, so it moves without
/// changing behaviour, and it belongs beside the startup path rather than
/// inside a 4900-line `main`.
pub(crate) fn attestation_config(args: &Args) -> AttestationConfig {
    let mut config = if args.require_attestation {
        AttestationConfig::required()
    } else {
        AttestationConfig::default()
    };
    if let Some(ref hashes) = args.allowed_kernel_hashes {
        config = config.with_kernel_hashes(hashes);
    }
    if let Some(ref hashes) = args.allowed_rootfs_hashes {
        config = config.with_rootfs_hashes(hashes);
    }
    if let Some(ref hashes) = args.allowed_config_hashes {
        config = config.with_config_hashes(hashes);
    }
    // C9 floor (>L0 ⇒ required)
    config.with_min_assurance(args.min_assurance)
}

/// How many approvals a declassification needs (`NUCLEUS_DECLASSIFY_THRESHOLD`).
///
/// Extracted alongside `attestation_config` for the same reason: `main.rs` is on
/// its line ratchet, so instrumentation has to pay for itself. Defaults to 1 on
/// an unset or unparseable value.
pub(crate) fn declassify_threshold() -> usize {
    std::env::var("NUCLEUS_DECLASSIFY_THRESHOLD")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1)
}

/// One timed initialisation step.
struct Milestone {
    name: &'static str,
    millis: u128,
}

/// Records how long each phase of tool-proxy startup took.
pub(crate) struct Startup {
    start: Instant,
    milestones: Vec<Milestone>,
}

impl Startup {
    /// Start the clock. Call as the first statement of `main`.
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            milestones: Vec::new(),
        }
    }

    /// Await `fut`, recording how long it took under `name`.
    ///
    /// Returns the future's output unchanged, so wrapping a call site is a
    /// pure edit-in-place — no extra statement, no rebinding.
    pub(crate) async fn timed<F: std::future::Future>(
        &mut self,
        name: &'static str,
        fut: F,
    ) -> F::Output {
        let t = Instant::now();
        let out = fut.await;
        let millis = t.elapsed().as_millis();
        // Emit as each phase COMPLETES, not only in the summary. A trace that
        // prints once at the end cannot diagnose a hang: if startup stalls, the
        // summary never runs and the console stays empty — which is exactly what
        // happened on the first real boot with this module, and is the whole
        // failure mode it exists to investigate. Streaming the milestones means
        // the LAST line printed names the phase that completed, so the stall is
        // in the one after it.
        println!(
            "nucleus-startup-phase {name}={millis}ms at={}ms",
            self.start.elapsed().as_millis()
        );
        self.milestones.push(Milestone { name, millis });
        out
    }

    /// The breakdown, as one line on the console the host captures.
    ///
    /// Emitted with `println!` rather than `tracing`, deliberately: the guest
    /// proxy runs under an error-only filter, so an `info!` here would be
    /// swallowed and this module would reproduce the exact problem it exists to
    /// fix. The host parses `firecracker.log` for console text already.
    pub(crate) fn report(&self) {
        let total = self.start.elapsed().as_millis();
        let summed: u128 = self.milestones.iter().map(|m| m.millis).sum();
        let parts: Vec<String> = self
            .milestones
            .iter()
            .map(|m| format!("{}={}ms", m.name, m.millis))
            .collect();
        println!(
            "nucleus-startup-trace total={}ms unaccounted={}ms {}",
            total,
            total.saturating_sub(summed),
            parts.join(" ")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn timed_returns_the_future_output_unchanged() {
        // The wrapper must be transparent, or instrumenting a call site would
        // change behaviour rather than only observe it.
        let mut s = Startup::new();
        let v = s.timed("x", async { 41 + 1 }).await;
        assert_eq!(v, 42);
        assert_eq!(s.milestones.len(), 1);
        assert_eq!(s.milestones[0].name, "x");
    }

    #[tokio::test]
    async fn a_slow_step_is_attributed_to_itself() {
        // Non-vacuity: the recorder must be able to tell a slow step from a
        // fast one, otherwise a uniform "everything is 0ms" report would look
        // just as plausible as a real measurement.
        let mut s = Startup::new();
        s.timed("fast", async {}).await;
        s.timed(
            "slow",
            tokio::time::sleep(std::time::Duration::from_millis(40)),
        )
        .await;
        let fast = s
            .milestones
            .iter()
            .find(|m| m.name == "fast")
            .unwrap()
            .millis;
        let slow = s
            .milestones
            .iter()
            .find(|m| m.name == "slow")
            .unwrap()
            .millis;
        assert!(slow >= 35, "slow step recorded as {slow}ms");
        assert!(slow > fast, "slow ({slow}ms) must exceed fast ({fast}ms)");
    }

    #[test]
    fn unaccounted_is_reported_not_hidden() {
        // A recorder with no milestones must attribute the whole elapsed time
        // to `unaccounted` rather than to nothing at all.
        let s = Startup::new();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let total = s.start.elapsed().as_millis();
        let summed: u128 = s.milestones.iter().map(|m| m.millis).sum();
        assert_eq!(summed, 0);
        assert!(total >= 4, "elapsed {total}ms");
        // `report()` would print unaccounted == total here, which is the signal
        // that nothing on the path is wrapped yet.
    }
}
