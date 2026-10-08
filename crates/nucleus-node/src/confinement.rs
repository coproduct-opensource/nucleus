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
    let v = loop {
        let console = tokio::fs::read_to_string(&log).await.unwrap_or_default();
        let v = verdict(&console, applies);
        if v != Verdict::Absent || std::time::Instant::now() >= deadline {
            break v;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };

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
        Verdict::Absent => absent_problem(),
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

/// What an absent verdict is reported as.
///
/// The commonest cause is not a broken probe but a guest that predates it: every
/// published release through 2.2.0 ships a guest-init that never runs it, so a
/// node from this tree refuses every confined pod on such a rootfs. The
/// refusal stands — the probe is the only evidence the fence drops traffic —
/// but the operator is told which change to look up and how to get a guest that
/// has it, in the capability table's words rather than a second copy of them.
fn absent_problem() -> String {
    use nucleus_spec::tier2_artifacts::{GuestCapability, REBUILD_THE_GUEST};
    format!(
        "the guest produced no egress attestation. Expected a \
         `NUCLEUS_EGRESS_PROBE:` line on the console. Treated as a failure rather \
         than a pass: the control this replaces was trusted precisely because \
         nothing could make it red. If the guest rootfs predates the probe: {}. \
         {REBUILD_THE_GUEST}",
        GuestCapability::EgressAttestation.change()
    )
}

/// What a pod's guest reported about its children's filesystem (#2696 P3c),
/// as the node reports it in the pod's posture.
///
/// Reported, not required: `GuestCapability::WorkloadLandlock` is
/// `Demand::Optional`, so a guest that predates it is not refused. But it is
/// not called confined either: no verdict reads as `Unreported`, which the
/// posture spells as not enforced. "Could not tell" is never "confined"
/// (ADR 0007 A-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WorkloadFilesystem {
    /// The guest's own `NUCLEUS_WORKLOAD_LANDLOCK:` verdict.
    Reported(nucleus_spec::guest_layout::WorkloadLandlockVerdict),
    /// No verdict on the console: an older guest, or one that failed before
    /// the tool-proxy decided.
    Unreported,
}

impl WorkloadFilesystem {
    /// Pure parse of a captured console.
    pub(crate) fn from_console(console: &str) -> Self {
        match nucleus_spec::guest_layout::WorkloadLandlockVerdict::parse(console) {
            Some(v) => Self::Reported(v),
            None => Self::Unreported,
        }
    }

    /// Whether the guest's children are held to the Landlock ruleset.
    pub(crate) fn enforced(&self) -> bool {
        use nucleus_spec::guest_layout::WorkloadLandlockVerdict as V;
        match self {
            Self::Reported(V::Enforced { .. }) => true,
            Self::Reported(V::Waived { .. } | V::Refused { .. } | V::NotApplied)
            | Self::Unreported => false,
        }
    }

    /// The posture the pod listing shows, stating enforced or not first.
    pub(crate) fn posture(&self) -> String {
        use nucleus_spec::guest_layout::WorkloadLandlockVerdict as V;
        match self {
            Self::Reported(V::Enforced { abi }) => format!("landlock enforced (ABI {abi})"),
            Self::Reported(V::Waived { kernel }) => {
                format!("landlock NOT enforced: waived by the operator; the kernel offers {kernel}")
            }
            Self::Reported(V::Refused { kernel }) => format!(
                "landlock NOT enforced: the kernel offers {kernel}, so the guest refuses its \
                 workload and commands"
            ),
            Self::Reported(V::NotApplied) => {
                "landlock NOT enforced: not applied under this containment".to_string()
            }
            Self::Unreported => format!(
                "landlock NOT enforced: the guest reported no verdict. If it predates the \
                 confinement: {}",
                nucleus_spec::tier2_artifacts::GuestCapability::WorkloadLandlock.change()
            ),
        }
    }
}

/// Read the pod's console for the guest's filesystem verdict and log it. The
/// tool-proxy prints it before it serves health, so once the health wait has
/// passed it is already there or it is not coming.
async fn report_workload_filesystem(pod_dir: &Path, pod_id: &str) -> WorkloadFilesystem {
    let console = tokio::fs::read_to_string(pod_dir.join("firecracker.log"))
        .await
        .unwrap_or_default();
    let fs = WorkloadFilesystem::from_console(&console);
    if fs.enforced() {
        tracing::info!(target: "confinement", pod = %pod_id, posture = %fs.posture(), "workload filesystem");
    } else {
        tracing::warn!(target: "confinement", pod = %pod_id, posture = %fs.posture(), "workload filesystem");
    }
    fs
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
    vmm: &mut crate::vmm_process::VmmProcess,
) -> Result<WorkloadFilesystem, crate::ApiError> {
    // `wait_for_proxy_health` moved into `guest_diagnosis` (#2355), which also
    // enriches a timeout with the guest console's actual cause. Both halves read
    // the same console: one to explain why the pod never came up, this one to
    // require it proved its fence. The VMM goes in so a dead guest ends the wait
    // instead of running it out (#2904).
    let console = pod_dir.join("firecracker.log");
    crate::guest_diagnosis::wait_for_proxy_health(addr, &console, vmm).await?;
    attest(pod_dir, spec, &pod_id.to_string())
        .await
        .map_err(crate::ApiError::Driver)?;
    Ok(report_workload_filesystem(pod_dir, &pod_id.to_string()).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFINED: &str = "[  1.2] Run /init as init process\nNUCLEUS_EGRESS_PROBE: PASS\n";

    #[test]
    fn a_proving_console_passes() {
        assert_eq!(verdict(CONFINED, true), Verdict::Proved);
    }

    /// #2696 P3c: the posture says enforced only for the guest's own
    /// `enforced` verdict. Silence (an older guest), a waiver and a refusal
    /// all read as NOT enforced, and say which.
    #[test]
    fn only_an_enforced_verdict_reports_the_workload_filesystem_as_confined() {
        use nucleus_spec::guest_layout::WorkloadLandlockVerdict as V;
        let enforced = WorkloadFilesystem::from_console(&format!(
            "{CONFINED}[proxy] {}\n",
            V::Enforced { abi: 2 }.line()
        ));
        assert!(enforced.enforced());
        assert_eq!(enforced.posture(), "landlock enforced (ABI 2)");

        let silent = WorkloadFilesystem::from_console(CONFINED);
        assert_eq!(silent, WorkloadFilesystem::Unreported);
        assert!(!silent.enforced());
        assert!(
            silent.posture().starts_with("landlock NOT enforced"),
            "{}",
            silent.posture()
        );

        for v in [
            V::Waived {
                kernel: "no Landlock".into(),
            },
            V::Refused {
                kernel: "Landlock ABI 1".into(),
            },
            V::NotApplied,
        ] {
            let fs = WorkloadFilesystem::from_console(&v.line());
            assert!(!fs.enforced(), "{v:?}");
            assert!(fs.posture().starts_with("landlock NOT enforced"), "{v:?}");
        }
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

    /// The 2.2.0 guest (the pin until 2.3.0) booted by a node from this tree: no verdict,
    /// because its guest-init predates #2365. Still a refusal, and now one that
    /// says which change the guest lacks and how to build one that has it.
    #[test]
    fn an_absent_verdict_names_the_guest_skew_and_still_refuses() {
        let msg = absent_problem();
        assert!(msg.contains("NUCLEUS_EGRESS_PROBE:"), "{msg}");
        assert!(msg.contains("#2365"), "{msg}");
        assert!(msg.contains("build-rootfs.sh"), "{msg}");
        assert!(
            !msg.contains(OVERRIDE_ENV),
            "the fix for an old guest is a new guest, not the override: {msg}"
        );
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
