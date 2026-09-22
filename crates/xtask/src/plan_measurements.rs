//! `cargo xtask plan-measurements` — a declared measurement that a real run has already
//! beaten is not a measurement.
//!
//! `.gatehouse/pipeline.writ` declares a `measuredMs` per gate, and `ci.timeoutMeasured_b`
//! holds each gate's timeout to between two and ten times it. The kernel proves that relation
//! and the proof is real — but **both of its sides are declarations**. Nothing compares either
//! to what the builder actually did, so a declaration can be overtaken by reality while
//! `admissible` still proves, and the 2x floor is then a statement about a number that no
//! longer describes the gate.
//!
//! That is not hypothetical, and the record is one day long.
//!
//! - `test-audit` declared `900000` as an ANCHOR borrowed from test-core, because the gate had
//!   never once executed.
//! - It ran four times (701925, 707056, 725281, 776241 ms) and `776241` was declared as "the
//!   worst run seen here", which is the rule the writ states for itself.
//! - **A fifth run took 1493565 ms, less than two hours later.** `2 x 1493565 = 2987130`
//!   against a declared timeout of `2700000`: the floor was violated, and `admissible` went on
//!   proving, because the kernel was comparing 2700000 to 776241 and neither number had moved.
//!
//! It was found by reading a log by hand at a moment of someone's choosing. Nothing would have
//! found it otherwise. This is the falsifier for that.
//!
//! # The method it audits is a high-water mark, and that is the point
//!
//! The writ's rule — "the worst run seen HERE" — only ever ratchets up, so it is beaten by
//! definition the first time conditions exceed anything seen before. Measured over the
//! builder's own events on 2026-09-22, min-to-max spread per gate:
//!
//! ```text
//!   text-gates  26.8x        clippy     16.6x        test-core  13.8x
//!   fmt          6.0x        ci-spec     3.6x
//! ```
//!
//! With spreads like those, a high-water mark is a record rather than a statistic, and the
//! gates that look stable are the ones that have already been beaten many times and ratcheted.
//! A new gate has a low record and is overtaken as soon as the lane gets busy. So the
//! declaration cannot be made correct by being more careful when writing it; what it can have
//! is something that notices the moment it stops being true.
//!
//! # One check, deliberately
//!
//! **Has any observed run beaten the `measuredMs` its gate declares?** That is all.
//!
//! The 2x-10x band is NOT re-checked here. `ci.timeoutMeasured_b` already decides it, and a
//! second copy of a rule is a second thing to drift — the failure this family of gates exists
//! to refuse. It is also unnecessary: if no run beats `measuredMs` and the kernel holds
//! `timeout >= 2 x measuredMs`, then `timeout >= 2 x observed` follows. The kernel keeps its
//! fact; this supplies the one it cannot reach.
//!
//! # `decided` is the only filter, and no roll-up join is needed
//!
//! Each event carries `decided`. The 60 `decided: false` rows in the measured population are
//! runs that never really ran — preparation failed, and `measured_ms` is 1. They are dropped.
//!
//! Held-versus-failed is deliberately NOT distinguished, and the reason is worth stating
//! because the opposite mistake is in this repository's record: reading a FAILING run's 288800
//! ms as evidence that test-audit takes 288800 ms to pass. Failing runs understate — they are a
//! lower bound on a passing run, not an upper one. For a maximum, including them can only make
//! this check more conservative, never more permissive, so joining the log against the roll-up
//! to recover the verdict would buy nothing. The top attempts are printed so that a maximum
//! driven by one pathological failure is visible rather than merely enforced.
//!
//! # Could not look is not a pass
//!
//! A gate the events say nothing about is reported `NotObserved` and never silently counted as
//! holding — `lean-build` is declared and has never run on the lane, and that must read
//! differently from a gate that ran and stayed inside its number. If NOTHING was observed the
//! run reds as vacuous, because a filter that matches nothing would otherwise be the quietest
//! possible pass.
//!
//! # What this does not claim
//!
//! It reads the builder's log, so it runs where that log is — a lane-side check, not one of the
//! seven tree-side gates. It cannot be required, and a repository with no access to the events
//! cannot run it at all. It also does not propose a replacement number: it says a declaration
//! has been overtaken and by how much, and choosing the new one is a judgement about the
//! operating regime the lane does not yet bound.

use std::collections::BTreeMap;
use std::path::Path;

/// One `gate_measured` line. Derived, never restated: the builder writes these and this struct
/// is the only description of them here.
#[derive(Debug, serde::Deserialize)]
struct MeasuredEvent {
    gate: String,
    measured_ms: u64,
    decided: bool,
    attempt: String,
}

/// One gate as `.gatehouse/plan-gates.json` elaborates it. The committed elaboration is used
/// rather than the writ because it is already the machine-readable copy and a gate in CI
/// already proves the two agree.
#[derive(Debug, serde::Deserialize)]
struct PlanGate {
    name: String,
    measured_ms: u64,
}

/// What the evidence says about one gate's declaration.
///
/// Three cases, and `NotObserved` is spelled rather than folded into `Held`: "no run beat it"
/// and "no run happened" are different facts and only one of them is reassuring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Every decided run finished inside the declared measurement.
    Held { runs: usize, worst: u64 },
    /// A decided run beat the declaration. The gate's timeout may now be under
    /// `timeoutMeasured_b`'s floor with `admissible` still proving.
    Overtaken {
        runs: usize,
        worst: u64,
        by: u64,
        attempt: String,
    },
    /// The events say nothing about this gate. Never a pass.
    NotObserved,
}

/// What a whole run of this check concluded.
///
/// Three cases, because there are three facts and only two of them are about the plan. An
/// unreadable event log and a declaration beaten by a real run are BOTH failures of the
/// process and neither is a pass, but they call for opposite actions: one means raise
/// `measuredMs`, the other means go and look at why the log could not be read. Collapsing them
/// into one non-zero exit is how a monitor learns to cry violation when it simply could not
/// see, and a monitor that does that gets ignored.
///
/// This is the convention `xtask self-pin` already uses, and mapping it to an exit code happens
/// in `main` rather than by exiting from inside [`check`], so the tests can still call it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Every observed gate stayed inside its declaration. Exit 0.
    Clean,
    /// A decided run beat a declaration. A FINDING about the plan. Exit 1.
    Overtaken(String),
    /// The check could not be carried out. Never a pass, and never a finding either. Exit 2.
    CouldNotLook(String),
}

/// Decide each declared gate's standing against the observed runs.
///
/// Pure over its two inputs so the falsifier below can drive it without a builder.
#[must_use]
pub fn standings(
    declared: &BTreeMap<String, u64>,
    events: &[(String, u64, bool, String)],
) -> BTreeMap<String, Standing> {
    let mut out = BTreeMap::new();
    for (gate, &measured) in declared {
        let mut runs = 0usize;
        let mut worst = 0u64;
        let mut worst_attempt = String::new();
        for (g, ms, decided, attempt) in events {
            if g != gate || !decided {
                continue;
            }
            runs += 1;
            if *ms > worst {
                worst = *ms;
                worst_attempt.clone_from(attempt);
            }
        }
        let standing = if runs == 0 {
            Standing::NotObserved
        } else if worst > measured {
            Standing::Overtaken {
                runs,
                worst,
                by: worst - measured,
                attempt: worst_attempt,
            }
        } else {
            Standing::Held { runs, worst }
        };
        out.insert(gate.clone(), standing);
    }
    out
}

fn read_events(path: &Path) -> Result<Vec<(String, u64, bool, String)>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        // A line that is not a measurement is not an error: the log interleaves several event
        // types and plain text. A line that IS one and will not parse would be, so this only
        // skips what does not claim to be a measurement.
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("event").and_then(serde_json::Value::as_str) != Some("gate_measured") {
            continue;
        }
        let ev: MeasuredEvent = serde_json::from_value(value)
            .map_err(|e| format!("a gate_measured line did not parse: {e}"))?;
        out.push((ev.gate, ev.measured_ms, ev.decided, ev.attempt));
    }
    Ok(out)
}

fn read_declared(path: &Path) -> Result<BTreeMap<String, u64>, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let gates: Vec<PlanGate> =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(gates.into_iter().map(|g| (g.name, g.measured_ms)).collect())
}

/// Run the check. See [`Outcome`]: the three cases are distinguished here and mapped to exit
/// codes by the caller.
pub fn check(events_path: &Path, plan_path: &Path) -> Outcome {
    let events = match read_events(events_path) {
        Ok(e) => e,
        // Reading the subject is not auditing it. This is `CouldNotLook`, not a finding about
        // any declaration -- nothing has been compared yet.
        Err(why) => return Outcome::CouldNotLook(why),
    };
    let declared = match read_declared(plan_path) {
        Ok(d) => d,
        Err(why) => return Outcome::CouldNotLook(why),
    };
    if declared.is_empty() {
        return Outcome::CouldNotLook(format!(
            "{} declared no gates — nothing to audit",
            plan_path.display()
        ));
    }
    let standings = standings(&declared, &events);

    let mut overtaken = 0usize;
    let mut observed = 0usize;
    for (gate, standing) in &standings {
        let declared_ms = declared[gate];
        match standing {
            Standing::Held { runs, worst } => {
                observed += 1;
                let headroom = declared_ms.saturating_sub(*worst);
                println!(
                    "  ok    {gate}: {runs} decided run(s), worst {worst} ms against {declared_ms} declared ({headroom} ms of headroom)"
                );
            }
            Standing::Overtaken {
                runs,
                worst,
                by,
                attempt,
            } => {
                observed += 1;
                overtaken += 1;
                println!(
                    "  FAIL  {gate}: declared {declared_ms} ms, but a decided run took {worst} ms — beaten by {by} ms across {runs} run(s)"
                );
                println!("          the run that beat it: {attempt}");
                println!(
                    "          2 x {worst} = {} — compare with this gate's declared timeout; if the timeout is below it, `timeoutMeasured_b`'s floor is violated and `admissible` is still proving",
                    worst.saturating_mul(2)
                );
            }
            Standing::NotObserved => {
                println!(
                    "  --    {gate}: no decided run in these events — not measured here, which is not the same as holding"
                );
            }
        }
    }

    // Non-vacuity. A filter that matched nothing is the quietest possible pass.
    if observed == 0 {
        // The text here always said this was "could not look"; for one evening the exit code
        // said "finding" anyway. The words were right and the type was wrong.
        return Outcome::CouldNotLook(format!(
            "no decided run was observed for ANY of the {} declared gate(s) — the events are empty, filtered out, or the wrong file",
            declared.len()
        ));
    }
    if overtaken > 0 {
        return Outcome::Overtaken(format!(
            "{overtaken} declaration(s) overtaken by a real run — raise `measuredMs` in .gatehouse/pipeline.writ and re-check the timeout against `timeoutMeasured_b`"
        ));
    }
    println!(
        "OK: {observed} gate(s) observed across {} decided run(s); no declared measurement has been beaten",
        events.iter().filter(|(_, _, d, _)| *d).count()
    );
    Outcome::Clean
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(gate: &str, ms: u64, decided: bool) -> (String, u64, bool, String) {
        (gate.into(), ms, decided, format!("gate-{gate}-abc-{ms}"))
    }

    fn declared(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs.iter().map(|(n, m)| ((*n).into(), *m)).collect()
    }

    /// A-19, on the real defect rather than a fixture. Commit `9bea9df0` of nucleus declared
    /// `test-audit` at 776241 ms; a decided run of 1493565 ms exists in the builder's log. This
    /// check must red on exactly that pair, and it is the reason the check exists.
    #[test]
    fn the_declaration_that_shipped_and_was_beaten_within_two_hours_reds() {
        let d = declared(&[("test-audit", 776_241)]);
        let events = [
            ev("test-audit", 701_925, true),
            ev("test-audit", 707_056, true),
            ev("test-audit", 725_281, true),
            ev("test-audit", 776_241, true),
            ev("test-audit", 1_493_565, true),
        ];
        let s = standings(&d, &events);
        assert_eq!(
            s["test-audit"],
            Standing::Overtaken {
                runs: 5,
                worst: 1_493_565,
                by: 717_324,
                attempt: "gate-test-audit-abc-1493565".into(),
            },
            "the run that broke timeoutMeasured_b's floor must be named"
        );
    }

    /// And green once the declaration is corrected, which is the other half of A-19.
    #[test]
    fn the_corrected_declaration_holds_against_the_same_runs() {
        let d = declared(&[("test-audit", 1_493_565)]);
        let events = [
            ev("test-audit", 776_241, true),
            ev("test-audit", 1_493_565, true),
        ];
        assert_eq!(
            standings(&d, &events)["test-audit"],
            Standing::Held {
                runs: 2,
                worst: 1_493_565
            },
            "equal to the declaration is inside it; the rule is 'the worst seen', not 'more than'"
        );
    }

    /// The 60 `decided: false` rows carry `measured_ms: 1` — runs that never ran, because
    /// preparation failed. Counting them would understate every worst case.
    #[test]
    fn an_undecided_run_is_not_a_measurement() {
        let d = declared(&[("fmt", 1_000)]);
        let events = [ev("fmt", 9_999_999, false), ev("fmt", 500, true)];
        assert_eq!(
            standings(&d, &events)["fmt"],
            Standing::Held {
                runs: 1,
                worst: 500
            },
            "a run that never launched must not beat a declaration"
        );
    }

    /// `lean-build` is declared and has never run on the lane. That must not read as holding.
    #[test]
    fn a_gate_with_no_runs_is_not_observed_rather_than_held() {
        let d = declared(&[("lean-build", 145_000)]);
        let events = [ev("fmt", 10, true)];
        assert_eq!(standings(&d, &events)["lean-build"], Standing::NotObserved);
    }

    /// The inversion that would make this gate useless: if "no events" read as a pass, the
    /// check would be green against an empty file, which is the quietest way for a gate to
    /// detect nothing. `check` reds on it; this pins the shape `check` reads.
    #[test]
    fn nothing_observed_at_all_is_not_a_pass() {
        let d = declared(&[("fmt", 1), ("clippy", 1)]);
        let s = standings(&d, &[]);
        assert!(
            s.values().all(|v| *v == Standing::NotObserved),
            "an empty event set must leave every gate unobserved, never held"
        );
        assert_eq!(
            s.values()
                .filter(|v| matches!(v, Standing::Held { .. }))
                .count(),
            0
        );
    }

    /// The distinction this check got wrong for one evening: an unreadable subject is NOT a
    /// finding about any declaration. It exited 1 -- the same code as "a declaration was
    /// beaten" -- while its own message called it "could not look", so a monitor built on it
    /// raised a measurement alarm whenever the log was merely missing.
    #[test]
    fn an_unreadable_event_log_is_could_not_look_not_a_finding() {
        let plan = std::env::temp_dir().join("pm-test-plan-unreadable.json");
        std::fs::write(&plan, r#"[{"name":"fmt","measured_ms":1}]"#).unwrap();
        let out = check(Path::new("/nonexistent/events.jsonl"), &plan);
        assert!(
            matches!(out, Outcome::CouldNotLook(_)),
            "a missing event log must not be reported as an overtaken declaration, got {out:?}"
        );
    }

    /// Same for the vacuity guard. Nothing observed is nothing LOOKED AT, and the caller must
    /// be able to tell that from a real overtaking without parsing prose.
    #[test]
    fn nothing_observed_is_could_not_look_not_a_finding() {
        let plan = std::env::temp_dir().join("pm-test-plan-vacuous.json");
        let events = std::env::temp_dir().join("pm-test-events-empty.jsonl");
        std::fs::write(&plan, r#"[{"name":"fmt","measured_ms":1}]"#).unwrap();
        std::fs::write(&events, "").unwrap();
        assert!(matches!(check(&events, &plan), Outcome::CouldNotLook(_)));
    }

    /// And the finding is still a finding, so the three cases are genuinely distinguished
    /// rather than all collapsed the other way.
    #[test]
    fn a_beaten_declaration_is_overtaken_and_a_clean_one_is_clean() {
        let plan = std::env::temp_dir().join("pm-test-plan-beaten.json");
        let events = std::env::temp_dir().join("pm-test-events-beaten.jsonl");
        std::fs::write(&plan, r#"[{"name":"fmt","measured_ms":1000}]"#).unwrap();
        std::fs::write(
            &events,
            "{\"event\":\"gate_measured\",\"gate\":\"fmt\",\"measured_ms\":5000,\"decided\":true,\"attempt\":\"a\"}\n",
        )
        .unwrap();
        assert!(matches!(check(&events, &plan), Outcome::Overtaken(_)));

        std::fs::write(
            &events,
            "{\"event\":\"gate_measured\",\"gate\":\"fmt\",\"measured_ms\":900,\"decided\":true,\"attempt\":\"a\"}\n",
        )
        .unwrap();
        assert_eq!(check(&events, &plan), Outcome::Clean);
    }

    /// Only the named gate's runs count toward its worst case.
    #[test]
    fn a_slow_run_of_another_gate_does_not_beat_this_ones_declaration() {
        let d = declared(&[("fmt", 1_000), ("clippy", 5_000_000)]);
        let events = [ev("clippy", 4_000_000, true), ev("fmt", 900, true)];
        assert_eq!(
            standings(&d, &events)["fmt"],
            Standing::Held {
                runs: 1,
                worst: 900
            }
        );
    }
}
