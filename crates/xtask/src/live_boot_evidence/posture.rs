//! The posture the guest reported, read back from the bundle.
//!
//! The probes' verdicts are read from the workload's stdout and stderr, and
//! only after `nucleus-audit verify-logs` has tied those exact bytes to the
//! signed receipt: a verdict line is evidence only when its bytes are. The
//! Landlock verdict is printed by the guest's supervisor, not the workload, so
//! it comes from the guest console, and the summary says so.
//!
//! A posture holds only when every line it requires is PRESENT and no line it
//! forbids is. A probe that never ran prints nothing, and nothing is a FAIL,
//! never a pass (the shape of the boot job's own steps).

use super::verdict::Verdict;
use serde::Serialize;

/// Where a posture line is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The workload's stdout and stderr, verified against the receipt.
    VerifiedWorkloadLogs,
    /// The guest console (`firecracker.log`): unsigned.
    GuestConsole,
}

/// One posture, as the probes print it.
pub struct Posture {
    pub name: &'static str,
    pub source: Source,
    /// Every one of these must appear.
    pub requires: &'static [&'static str],
    /// None of these may appear.
    pub forbids: &'static [&'static str],
}

/// The postures the live boot appraises.
pub const POSTURES: &[Posture] = &[
    Posture {
        // FM-5: identity variables, inherited fds, groups, read-only root,
        // the syscall filter and PID 1's invisibility, as the workload sees them.
        name: "fm5",
        source: Source::VerifiedWorkloadLogs,
        requires: &["NUCLEUS_WORKLOAD_PROBE: PASS"],
        forbids: &["NUCLEUS_WORKLOAD_PROBE: FAIL"],
    },
    Posture {
        name: "seccomp",
        source: Source::VerifiedWorkloadLogs,
        requires: &["NUCLEUS_SYSCALL_FILTER_PROBE: PASS"],
        forbids: &["NUCLEUS_SYSCALL_FILTER_PROBE: FAIL"],
    },
    Posture {
        // Non-root, PID 1 invisible (`hidepid=invisible`), its environ refused.
        name: "hidepid",
        source: Source::VerifiedWorkloadLogs,
        requires: &["NUCLEUS_RUN_CHILD_PROBE: PASS"],
        forbids: &["NUCLEUS_RUN_CHILD_PROBE: FAIL"],
    },
    Posture {
        // The default-deny backstop, with its positive control live.
        name: "egress_backstop",
        source: Source::VerifiedWorkloadLogs,
        requires: &[
            "NUCLEUS_EGRESS_PROBE: PASS",
            "NUCLEUS_EGRESS_CHECK: positive-control socketpair round-trip ok",
        ],
        forbids: &["NUCLEUS_EGRESS_PROBE: FAIL"],
    },
    Posture {
        // An active attacker, every stage attempted, its control live.
        name: "adversary_contained",
        source: Source::VerifiedWorkloadLogs,
        requires: &[
            "NUCLEUS_ADVERSARY: CONTAINED",
            "NUCLEUS_ADVERSARY_CONTROL: live",
            "NUCLEUS_ADVERSARY_STAGE pid1-secret-theft: attempted=yes",
            "NUCLEUS_ADVERSARY_STAGE rootfs-tamper: attempted=yes",
            "NUCLEUS_ADVERSARY_STAGE exfil: attempted=yes",
        ],
        forbids: &["NUCLEUS_ADVERSARY: BREACH"],
    },
    Posture {
        // `NUCLEUS_WORKLOAD_LANDLOCK: enforced abi=<n>`. Anything else the
        // supervisor can say (waived, refused, not_applied) is not enforcement.
        name: "landlock",
        source: Source::GuestConsole,
        requires: &["NUCLEUS_WORKLOAD_LANDLOCK: enforced abi="],
        forbids: &[
            "NUCLEUS_WORKLOAD_LANDLOCK: waived",
            "NUCLEUS_WORKLOAD_LANDLOCK: refused",
            "NUCLEUS_WORKLOAD_LANDLOCK: not_applied",
        ],
    },
];

/// The Landlock line's prefix: a guest that predates it prints none at all,
/// which is "could not look", not a failed posture.
const LANDLOCK_PREFIX: &str = "NUCLEUS_WORKLOAD_LANDLOCK:";

/// One posture's verdict and the lines that decided it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observed {
    pub name: &'static str,
    pub source: Source,
    #[serde(flatten)]
    pub verdict: Verdict,
    /// The text's lines that carry any of the posture's needles.
    pub lines: Vec<String>,
}

/// Judge one posture against `text`.
pub fn judge(posture: &Posture, text: &str) -> Observed {
    let lines: Vec<String> = text
        .lines()
        .filter(|l| {
            posture
                .requires
                .iter()
                .chain(posture.forbids)
                .any(|n| l.contains(n))
                || (posture.name == "landlock" && l.contains(LANDLOCK_PREFIX))
        })
        .map(|l| l.trim().to_string())
        .collect();
    let forbidden: Vec<&str> = posture
        .forbids
        .iter()
        .copied()
        .filter(|n| text.contains(n))
        .collect();
    let missing: Vec<&str> = posture
        .requires
        .iter()
        .copied()
        .filter(|n| !text.contains(n))
        .collect();
    let verdict = if !forbidden.is_empty() {
        Verdict::Fail(format!("reported {}", forbidden.join(", ")))
    } else if missing.is_empty() {
        Verdict::Pass(format!(
            "all {} required lines present",
            posture.requires.len()
        ))
    } else if posture.name == "landlock" && !text.contains(LANDLOCK_PREFIX) {
        Verdict::CouldNotRun(
            "the guest printed no NUCLEUS_WORKLOAD_LANDLOCK verdict (a guest before #3273)".into(),
        )
    } else {
        Verdict::Fail(format!("missing {}", missing.join(", ")))
    };
    Observed {
        name: posture.name,
        source: posture.source,
        verdict,
        lines,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posture(name: &str) -> &'static Posture {
        POSTURES.iter().find(|p| p.name == name).unwrap()
    }

    const ALL: &str = "NUCLEUS_WORKLOAD_PROBE: PASS\n\
        NUCLEUS_SYSCALL_FILTER_PROBE: PASS\n\
        NUCLEUS_RUN_CHILD_PROBE: PASS\n\
        NUCLEUS_EGRESS_CHECK: positive-control socketpair round-trip ok\n\
        NUCLEUS_EGRESS_PROBE: PASS\n\
        NUCLEUS_ADVERSARY_STAGE pid1-secret-theft: attempted=yes blocked=yes\n\
        NUCLEUS_ADVERSARY_STAGE rootfs-tamper: attempted=yes blocked=yes\n\
        NUCLEUS_ADVERSARY_STAGE exfil: attempted=yes blocked=yes\n\
        NUCLEUS_ADVERSARY_CONTROL: live\n\
        NUCLEUS_ADVERSARY: CONTAINED\n\
        [ 1.2] NUCLEUS_WORKLOAD_LANDLOCK: enforced abi=2\n";

    #[test]
    fn every_posture_passes_on_a_log_that_reports_it() {
        for p in POSTURES {
            assert!(
                matches!(judge(p, ALL).verdict, Verdict::Pass(_)),
                "{}: {:?}",
                p.name,
                judge(p, ALL)
            );
        }
    }

    /// A-19: a probe that never ran prints nothing, and that is red.
    #[test]
    fn a_missing_posture_line_is_a_fail_not_a_pass() {
        for p in POSTURES.iter().filter(|p| p.name != "landlock") {
            for needle in p.requires {
                let without: String = ALL
                    .lines()
                    .filter(|l| !l.contains(needle))
                    .map(|l| format!("{l}\n"))
                    .collect();
                assert!(
                    matches!(judge(p, &without).verdict, Verdict::Fail(_)),
                    "{} without {needle}",
                    p.name
                );
            }
        }
        assert!(matches!(
            judge(posture("fm5"), "").verdict,
            Verdict::Fail(_)
        ));
    }

    #[test]
    fn a_forbidden_line_beats_a_present_pass() {
        let breached = format!("{ALL}NUCLEUS_ADVERSARY: BREACH:exfil\n");
        assert!(matches!(
            judge(posture("adversary_contained"), &breached).verdict,
            Verdict::Fail(_)
        ));
        let both = format!("{ALL}NUCLEUS_WORKLOAD_PROBE: FAIL: fd leak\n");
        assert!(matches!(
            judge(posture("fm5"), &both).verdict,
            Verdict::Fail(_)
        ));
    }

    #[test]
    fn landlock_absent_could_not_run_but_any_other_verdict_fails() {
        let silent = "NUCLEUS_WORKLOAD_PROBE: PASS\n";
        assert!(matches!(
            judge(posture("landlock"), silent).verdict,
            Verdict::CouldNotRun(_)
        ));
        for line in [
            "NUCLEUS_WORKLOAD_LANDLOCK: waived abi 1",
            "NUCLEUS_WORKLOAD_LANDLOCK: refused no landlock",
            "NUCLEUS_WORKLOAD_LANDLOCK: not_applied",
            "NUCLEUS_WORKLOAD_LANDLOCK: garbled",
        ] {
            assert!(
                matches!(judge(posture("landlock"), line).verdict, Verdict::Fail(_)),
                "{line}"
            );
        }
    }
}
