//! Boot-time attestation that a pod's egress confinement is actually in force.
//!
//! # The gap this closes
//!
//! The headline guarantee is non-interference. For the largest surface — an
//! already-running shell — the IFC label cannot follow the process past `exec`:
//! `curl`, `/dev/tcp` and `nc` never reach `NetEffect::fetch`. Containment for
//! that surface is the netns/iptables default-deny backstop and nothing else,
//! which `ifc_ops::bash_exec_floor_gates_the_spawn_not_the_reach` states plainly.
//!
//! The host applies those rules and checks the `iptables` commands SUCCEEDED
//! (`net::apply_default_deny`, `net::ensure_iptables_rule` both propagate a
//! non-zero exit). But a command returning 0 is not traffic being dropped. An
//! nftables backend translating differently, a missing conntrack module, or a
//! netns that is not the one the VM ended up in each produce a pod nucleus
//! reports healthy and describes as confined, while the shell reaches the
//! internet. Every command returned 0.
//!
//! `nucleus-egress-probe` already observed this from inside a real guest — but
//! only when `scripts/check-egress-probe.sh` ran it, in `quickstart-boot.yml`,
//! against a pod CI booted. Nothing verified it for the pod you launch. The
//! probe binary is already in every rootfs; only the composition was missing.
//!
//! # Fail closed
//!
//! A missing verdict is a failure, not a pass. That is the whole point: the
//! defect being fixed is a control that is green because nothing can make it
//! red, and "we could not tell" resolving to "fine" would rebuild it exactly.

use std::path::Path;

use nucleus_spec::PodSpec;

use crate::net::{self, IdentityGrant};

/// Set to `1` to downgrade a failed attestation to a warning.
///
/// Named, not silent. An operator on a host where the probe genuinely cannot
/// run needs a way through, but a quiet downgrade would recreate the gap this
/// module exists to close — so taking it is recorded at `warn` with the pod id.
pub(crate) const OVERRIDE_ENV: &str = "NUCLEUS_ALLOW_UNATTESTED_EGRESS";

const PASS: &str = "NUCLEUS_EGRESS_PROBE: PASS";
const FAIL: &str = "NUCLEUS_EGRESS_PROBE: FAIL";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// The guest demonstrated that egress is confined.
    Proved,
    /// The guest ran the probe and egress was NOT confined.
    Refused(String),
    /// No verdict in the console. Fails closed.
    Absent,
    /// The pod's own policy permits broad public egress, so there is nothing to
    /// prove. Not a pass — a different question.
    NotApplicable,
}

/// Whether this pod is one whose confinement we can meaningfully assert.
///
/// Reuses `decide_identity_grant` rather than inventing a second notion of
/// "confined". That predicate already decides whether a pod is confined enough
/// to be handed an identity; the set of pods that may hold an identity and the
/// set that must prove their fence holds should not be allowed to drift apart.
/// A pod with `allow: ["0.0.0.0/0"]` is `Denied` there and `NotApplicable` here
/// — it is legitimately able to reach the probe's targets, so a FAIL from it
/// would be a true report about a pod that never claimed confinement.
fn attestation_applies(spec: &PodSpec) -> bool {
    matches!(
        net::decide_identity_grant(spec.spec.network.as_ref()),
        IdentityGrant::Granted
    )
}

/// Pure parse of a captured console into a verdict.
pub(crate) fn verdict(console: &str, applies: bool) -> Verdict {
    if !applies {
        return Verdict::NotApplicable;
    }
    // FAIL is checked FIRST. A console can carry both if the probe ran more than
    // once, and between "it proved confinement" and "it observed an escape" the
    // escape is the one that matters.
    if let Some(line) = console.lines().find(|l| l.contains(FAIL)) {
        return Verdict::Refused(line.trim().chars().take(200).collect());
    }
    if console.contains(PASS) {
        return Verdict::Proved;
    }
    Verdict::Absent
}

/// Read the pod's console and require an attestation.
pub(crate) async fn attest(pod_dir: &Path, spec: &PodSpec, pod_id: &str) -> Result<(), String> {
    let applies = attestation_applies(spec);
    let log = pod_dir.join("firecracker.log");

    // The guest SPAWNS the probe and does not wait for it, so the verdict lands
    // on the console asynchronously — measured at ~0.31s while the host's own
    // health wait is ~0.7s, so it is normally already there. Poll rather than
    // read once: a single read that happened to win the race would fail a
    // correctly-confined pod, and this gate fails closed, so a lost race would
    // be an outage rather than a warning.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let mut v = Verdict::Absent;
    loop {
        let console = tokio::fs::read_to_string(&log).await.unwrap_or_default();
        v = verdict(&console, applies);
        if v != Verdict::Absent || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let problem = match v {
        Verdict::Proved => {
            tracing::info!(
                target: "confinement",
                pod = %pod_id,
                "egress confinement attested by the guest"
            );
            return Ok(());
        }
        Verdict::NotApplicable => {
            tracing::info!(
                target: "confinement",
                pod = %pod_id,
                "egress attestation not applicable: this pod's policy permits broad \
                 public egress, so there is no fence to prove"
            );
            return Ok(());
        }
        Verdict::Refused(line) => format!(
            "the guest observed that egress is NOT confined: {line}. The pod was \
             not started. This is the netns/iptables backstop failing to apply, \
             not a policy decision"
        ),
        Verdict::Absent => ("the guest produced no egress attestation. Expected a \
             `NUCLEUS_EGRESS_PROBE:` line on the console. Treated as a failure \
             rather than a pass: the control this replaces was trusted precisely \
             because nothing could make it red")
            .to_string(),
    };

    if std::env::var(OVERRIDE_ENV).is_ok_and(|v| v == "1") {
        tracing::warn!(
            target: "confinement",
            pod = %pod_id,
            %problem,
            "{OVERRIDE_ENV}=1 — starting a pod whose egress confinement was NOT \
             attested. The shell surface is unverified on this pod."
        );
        return Ok(());
    }
    Err(problem)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFINED: &str = "[  1.2] Run /init as init process\nNUCLEUS_EGRESS_PROBE: PASS\n";

    #[test]
    fn a_proving_console_passes() {
        assert_eq!(verdict(CONFINED, true), Verdict::Proved);
    }

    /// The case the module exists for: the guest says the fence is open.
    #[test]
    fn an_observed_escape_is_refused() {
        let c = "NUCLEUS_EGRESS_PROBE: FAIL: connected to 1.1.1.1:443\n";
        match verdict(c, true) {
            Verdict::Refused(line) => assert!(line.contains("1.1.1.1"), "{line}"),
            other => panic!("an observed escape must be refused, got {other:?}"),
        }
    }

    /// Silence must not read as success. Without this the whole module would be
    /// the same trusted-because-unobservable control it replaces.
    #[test]
    fn a_console_with_no_verdict_fails_closed() {
        assert_eq!(
            verdict("[  1.2] Run /init as init process\n", true),
            Verdict::Absent
        );
        assert_eq!(verdict("", true), Verdict::Absent);
    }

    /// A console carrying both must resolve to the escape. A probe that ran
    /// twice, or a PASS from an earlier boot still in the log, must not be able
    /// to out-vote an observed escape.
    #[test]
    fn an_escape_outranks_a_pass_in_the_same_console() {
        let c = "NUCLEUS_EGRESS_PROBE: PASS\nNUCLEUS_EGRESS_PROBE: FAIL: reached 8.8.8.8:53\n";
        assert!(matches!(verdict(c, true), Verdict::Refused(_)));
    }

    /// Non-vacuity for `applies`: a pod that never claimed confinement is not
    /// failed for being unable to prove it. Without this the gate would refuse
    /// legitimate `allow: ["0.0.0.0/0"]` pods.
    #[test]
    fn a_pod_that_permits_public_egress_is_not_asked_to_prove_a_fence() {
        assert_eq!(verdict("", false), Verdict::NotApplicable);
        // …and the same console that would fail an applicable pod does not fail
        // this one, so `applies` is doing real work rather than decorating.
        assert_eq!(
            verdict("NUCLEUS_EGRESS_PROBE: FAIL: reached 1.1.1.1", false),
            Verdict::NotApplicable
        );
    }
}

/// Health, then attestation — the single gate a pod passes to be called up.
///
/// Named `gate` and not `health_then_attest` for a dull reason worth recording:
/// the longer name pushed the call site in `main.rs` past rustfmt's width, and
/// the resulting second line broke the file's line ceiling.
///
/// One function so the two can never drift apart: a caller cannot get liveness
/// without confinement by forgetting the second call, which is exactly how the
/// original gap would grow back.
pub(crate) async fn gate(
    addr: std::net::SocketAddr,
    pod_dir: &Path,
    spec: &PodSpec,
    pod_id: uuid::Uuid,
) -> Result<(), crate::ApiError> {
    // `wait_for_proxy_health` moved into `guest_diagnosis` (#2355), which also
    // enriches a timeout with the guest console's actual cause. Both halves read
    // the same console: one to explain why the pod never came up, this one to
    // require it proved its fence.
    crate::guest_diagnosis::wait_for_proxy_health(addr, &pod_dir.join("firecracker.log")).await?;
    attest(pod_dir, spec, &pod_id.to_string())
        .await
        .map_err(crate::ApiError::Driver)
}
