//! `cargo xtask escape-lane` — one verdict for the escape lane (eval cell M2, ADR 0013).
//!
//! The x86_64 live boot runs three in-guest probes as the pod's workload:
//! `nucleus-workload-probe` (FM-5 posture), `nucleus-egress-probe` (the netns default-deny) and
//! `nucleus-adversary-probe` (an active attacker in three stages). Each prints its verdict into
//! the guest console log. This reads those logs back and writes ONE record, `escape-lane.json`:
//! every probe stage as `CONTAINED | BREACH | INCONCLUSIVE`, with the commit, the guest release
//! and the node build it was measured on.
//!
//! It reads; it does not attack. What each probe attempts is the probe's business, unchanged.
//!
//! # The rule
//!
//! The lane passes only with at least one stage, no `BREACH` and no `INCONCLUSIVE`. A stage
//! whose sentinel never appeared is `INCONCLUSIVE`: a probe that did not run, crashed, or never
//! reached the log is "could not look", never "looked and it was fine" (ADR 0007 A-1). No guest
//! log at all makes every stage `INCONCLUSIVE`, so missing input fails the lane.
//!
//! Precedence within a stage is BREACH > CONTAINED > INCONCLUSIVE: a log that carries both a
//! failure and a pass line (two pods, a re-run, a probe reporting twice) is a breach.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The record's schema id.
const SCHEMA: &str = "nucleus-escape-lane/v1";

/// The guest console log every pod writes under the node's state directory.
const GUEST_LOG: &str = "firecracker.log";

/// Arguments.
#[derive(clap::Args, Debug)]
pub struct Args {
    /// The node's state directory, searched recursively for guest console logs.
    #[arg(long, default_value = "/var/lib/nucleus/state")]
    state_dir: PathBuf,
    /// Read the (root-owned) logs through sudo.
    #[arg(long)]
    sudo: bool,
    /// The node binary that ran the pods; its sha256 is recorded as the node build.
    #[arg(long, default_value = "/usr/local/bin/nucleus-node")]
    node_bin: PathBuf,
    /// Where to write the record.
    #[arg(long, default_value = "escape-lane.json")]
    out: PathBuf,
}

/// One stage's verdict. Three cases, never a `bool` (ADR 0007 A).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// The probe ran this stage and the sandbox held.
    Contained,
    /// The probe ran this stage and the attack succeeded, or the probe reported failure.
    Breach,
    /// No evidence either way: the stage did not run, or its line never reached the log.
    Inconclusive,
}

/// How a stage reads its verdict out of the guest log.
#[derive(Debug, Clone, Copy)]
enum Reading {
    /// `<sentinel>PASS` contains; `<sentinel>FAIL…` breaches.
    Sentinel(&'static str),
    /// `NUCLEUS_ADVERSARY_STAGE <name>: attempted=yes blocked=yes` contains;
    /// `attempted=yes blocked=no` breaches; `attempted=no` proves nothing.
    AdversaryStage(&'static str),
    /// `NUCLEUS_ADVERSARY: CONTAINED` with `NUCLEUS_ADVERSARY_CONTROL: live` contains;
    /// `NUCLEUS_ADVERSARY: BREACH…` breaches; a dead control or `INCONCLUSIVE` proves nothing.
    AdversaryCampaign,
}

/// A stage of the lane: the probe binary, the stage name, and how to read it.
struct StageDef {
    probe: &'static str,
    stage: &'static str,
    reading: Reading,
}

/// Every stage the live boot runs, in the order the pod runs them. The adversary's three stage
/// names are the probe's own (`crates/nucleus-adversary-probe/src/main.rs`).
const STAGES: &[StageDef] = &[
    StageDef {
        probe: "nucleus-workload-probe",
        stage: "fm5-posture",
        reading: Reading::Sentinel("NUCLEUS_WORKLOAD_PROBE: "),
    },
    StageDef {
        probe: "nucleus-egress-probe",
        stage: "default-deny-egress",
        reading: Reading::Sentinel("NUCLEUS_EGRESS_PROBE: "),
    },
    StageDef {
        probe: "nucleus-adversary-probe",
        stage: "pid1-secret-theft",
        reading: Reading::AdversaryStage("pid1-secret-theft"),
    },
    StageDef {
        probe: "nucleus-adversary-probe",
        stage: "rootfs-tamper",
        reading: Reading::AdversaryStage("rootfs-tamper"),
    },
    StageDef {
        probe: "nucleus-adversary-probe",
        stage: "exfil",
        reading: Reading::AdversaryStage("exfil"),
    },
    StageDef {
        probe: "nucleus-adversary-probe",
        stage: "campaign",
        reading: Reading::AdversaryCampaign,
    },
];

/// One stage in the record.
#[derive(Debug, Clone, Serialize)]
pub struct Stage {
    pub probe: &'static str,
    pub stage: &'static str,
    pub verdict: Verdict,
    /// The log line the verdict was read from, or why there was none. The probes print booleans
    /// only, never a stolen value, so the line is safe to publish.
    pub evidence: String,
}

/// The lane's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LaneVerdict {
    Pass,
    Fail,
}

/// The lane's tally and verdict.
#[derive(Debug, Clone, Serialize)]
pub struct Lane {
    pub verdict: LaneVerdict,
    pub stages: usize,
    pub contained: usize,
    pub breach: usize,
    pub inconclusive: usize,
    /// Why the lane failed; empty on a pass.
    pub reasons: Vec<String>,
}

/// The rule: at least one stage, no BREACH, no INCONCLUSIVE.
#[must_use]
pub fn lane(stages: &[Stage]) -> Lane {
    let count = |v: Verdict| stages.iter().filter(|s| s.verdict == v).count();
    let (contained, breach, inconclusive) = (
        count(Verdict::Contained),
        count(Verdict::Breach),
        count(Verdict::Inconclusive),
    );
    let mut reasons = Vec::new();
    if stages.is_empty() {
        reasons.push("no stage was measured".to_string());
    }
    for s in stages {
        match s.verdict {
            Verdict::Contained => {}
            Verdict::Breach => reasons.push(format!("BREACH: {}/{}", s.probe, s.stage)),
            Verdict::Inconclusive => {
                reasons.push(format!("INCONCLUSIVE: {}/{}", s.probe, s.stage));
            }
        }
    }
    Lane {
        verdict: if reasons.is_empty() {
            LaneVerdict::Pass
        } else {
            LaneVerdict::Fail
        },
        stages: stages.len(),
        contained,
        breach,
        inconclusive,
        reasons,
    }
}

/// The text after `marker` on `line`, if the marker appears.
fn after<'a>(line: &'a str, marker: &str) -> Option<&'a str> {
    line.find(marker)
        .and_then(|i| line.get(i.saturating_add(marker.len())..))
}

fn first<'a>(lines: &[&'a str], pred: impl Fn(&str) -> bool) -> Option<&'a str> {
    lines.iter().copied().find(|l| pred(l))
}

fn verdict_of(lines: &[&str], reading: Reading) -> (Verdict, String) {
    let found = |l: &str| l.trim().to_string();
    match reading {
        Reading::Sentinel(marker) => {
            let says = |l: &str, what: &str| after(l, marker).is_some_and(|r| r.starts_with(what));
            if let Some(l) = first(lines, |l| says(l, "FAIL")) {
                (Verdict::Breach, found(l))
            } else if let Some(l) = first(lines, |l| says(l, "PASS")) {
                (Verdict::Contained, found(l))
            } else {
                (
                    Verdict::Inconclusive,
                    format!("no `{marker}PASS|FAIL` line in any guest log"),
                )
            }
        }
        Reading::AdversaryStage(name) => {
            let marker = format!("NUCLEUS_ADVERSARY_STAGE {name}: ");
            let says = |l: &str, what: &str| after(l, &marker).is_some_and(|r| r.starts_with(what));
            if let Some(l) = first(lines, |l| says(l, "attempted=yes blocked=no")) {
                (Verdict::Breach, found(l))
            } else if let Some(l) = first(lines, |l| says(l, "attempted=yes blocked=yes")) {
                (Verdict::Contained, found(l))
            } else if let Some(l) = first(lines, |l| says(l, "")) {
                (Verdict::Inconclusive, found(l))
            } else {
                (
                    Verdict::Inconclusive,
                    format!("no `{marker}` line in any guest log"),
                )
            }
        }
        Reading::AdversaryCampaign => {
            let says = |l: &str, what: &str| {
                after(l, "NUCLEUS_ADVERSARY: ").is_some_and(|r| r.starts_with(what))
            };
            let control = |l: &str, what: &str| {
                after(l, "NUCLEUS_ADVERSARY_CONTROL: ").is_some_and(|r| r.starts_with(what))
            };
            if let Some(l) = first(lines, |l| says(l, "BREACH")) {
                (Verdict::Breach, found(l))
            } else if let Some(l) = first(lines, |l| control(l, "dead") || says(l, "INCONCLUSIVE"))
            {
                (Verdict::Inconclusive, found(l))
            } else {
                match (
                    first(lines, |l| says(l, "CONTAINED")),
                    first(lines, |l| control(l, "live")),
                ) {
                    (Some(l), Some(_)) => (Verdict::Contained, found(l)),
                    (Some(_), None) => (
                        Verdict::Inconclusive,
                        "CONTAINED without a live positive control".to_string(),
                    ),
                    (None, _) => (
                        Verdict::Inconclusive,
                        "no `NUCLEUS_ADVERSARY: ` verdict line in any guest log".to_string(),
                    ),
                }
            }
        }
    }
}

/// Read every stage from the guest logs. With no log, every stage is INCONCLUSIVE.
#[must_use]
pub fn stages(logs: &[String]) -> Vec<Stage> {
    let lines: Vec<&str> = logs.iter().flat_map(|l| l.lines()).collect();
    STAGES
        .iter()
        .map(|d| {
            let (verdict, evidence) = verdict_of(&lines, d.reading);
            Stage {
                probe: d.probe,
                stage: d.stage,
                verdict,
                evidence,
            }
        })
        .collect()
}

/// What was read.
#[derive(Debug, Clone, Serialize)]
pub struct Inputs {
    pub state_dir: String,
    pub guest_logs: usize,
    pub bytes: usize,
    /// Why the logs could not be listed, when they could not.
    pub error: Option<String>,
}

/// The node build the pods ran on.
#[derive(Debug, Clone, Serialize)]
pub struct NodeBuild {
    pub path: String,
    /// `None` when the binary could not be read; the record says so rather than omitting it.
    pub sha256: Option<String>,
}

/// `escape-lane.json`.
#[derive(Debug, Clone, Serialize)]
pub struct Record {
    pub schema: &'static str,
    pub commit: String,
    /// The guest release this build pins (`nucleus_spec::tier2_artifacts::GUEST_RELEASE`). The
    /// lane boots a guest built from `commit`, not that release's artifacts.
    pub guest_release: &'static str,
    pub node_build: NodeBuild,
    pub inputs: Inputs,
    pub stages: Vec<Stage>,
    pub lane: Lane,
}

fn read_logs(dir: &Path, sudo: bool) -> Result<Vec<String>> {
    let files: Vec<PathBuf> = if sudo {
        let out = Command::new("sudo")
            .arg("find")
            .arg(dir)
            .args(["-type", "f", "-name", GUEST_LOG, "-print0"])
            .output()
            .context("running sudo find")?;
        if !out.status.success() {
            bail!(
                "sudo find {} failed: {}",
                dir.display(),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        out.stdout
            .split(|b| *b == 0)
            .filter(|s| !s.is_empty())
            .map(|s| PathBuf::from(String::from_utf8_lossy(s).into_owned()))
            .collect()
    } else {
        let mut v = Vec::new();
        walk(dir, &mut v)?;
        v
    };
    let mut logs = Vec::new();
    for f in files {
        let bytes = if sudo {
            let out = Command::new("sudo")
                .arg("cat")
                .arg(&f)
                .output()
                .with_context(|| format!("sudo cat {}", f.display()))?;
            if !out.status.success() {
                bail!("sudo cat {} failed", f.display());
            }
            out.stdout
        } else {
            std::fs::read(&f).with_context(|| format!("reading {}", f.display()))?
        };
        logs.push(String::from_utf8_lossy(&bytes).into_owned());
    }
    Ok(logs)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))? {
        let p = e?.path();
        if p.is_dir() {
            walk(&p, out)?;
        } else if p.file_name().is_some_and(|n| n == GUEST_LOG) {
            out.push(p);
        }
    }
    Ok(())
}

fn commit(root: &Path) -> String {
    Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Build the record, write it, print it, and fail unless the lane passes.
pub fn run(root: &Path, a: &Args) -> Result<()> {
    let (logs, error) = match read_logs(&a.state_dir, a.sudo) {
        Ok(logs) => (logs, None),
        Err(e) => (Vec::new(), Some(format!("{e:#}"))),
    };
    let stages = stages(&logs);
    let mut lane = lane(&stages);
    if logs.is_empty() {
        // Already a FAIL (every stage is INCONCLUSIVE); say why at the top.
        lane.reasons.insert(
            0,
            format!(
                "no guest log under {}{}",
                a.state_dir.display(),
                error
                    .as_deref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            ),
        );
        lane.verdict = LaneVerdict::Fail;
    }
    let record = Record {
        schema: SCHEMA,
        commit: commit(root),
        guest_release: nucleus_spec::tier2_artifacts::GUEST_RELEASE,
        node_build: NodeBuild {
            path: a.node_bin.display().to_string(),
            sha256: std::fs::read(&a.node_bin)
                .ok()
                .map(|b| hex::encode(Sha256::digest(&b))),
        },
        inputs: Inputs {
            state_dir: a.state_dir.display().to_string(),
            guest_logs: logs.len(),
            bytes: logs.iter().map(String::len).sum(),
            error,
        },
        stages,
        lane,
    };
    let json = serde_json::to_string_pretty(&record)?;
    std::fs::write(&a.out, format!("{json}\n"))
        .with_context(|| format!("writing {}", a.out.display()))?;
    for s in &record.stages {
        println!(
            "{:<13} {}/{}: {}",
            format!("{:?}", s.verdict).to_uppercase(),
            s.probe,
            s.stage,
            s.evidence
        );
    }
    println!(
        "escape lane: {:?} -- {} stage(s), {} contained, {} breach, {} inconclusive ({} guest log(s), commit {})",
        record.lane.verdict,
        record.lane.stages,
        record.lane.contained,
        record.lane.breach,
        record.lane.inconclusive,
        record.inputs.guest_logs,
        record.commit
    );
    match record.lane.verdict {
        LaneVerdict::Pass => Ok(()),
        LaneVerdict::Fail => {
            for r in &record.lane.reasons {
                println!("::error::escape lane: {r}");
            }
            bail!("the escape lane failed: {}", record.lane.reasons.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A probe pod that held everywhere, as the guest console prints it: prefixes, other pods'
    /// noise, and each verdict on both streams.
    const CONTAINED_LOG: &str = "\
[    0.912] guest-init: booting
[workload] NUCLEUS_WORKLOAD_ENV: PATH
[workload] NUCLEUS_WORKLOAD_PROBE: PASS
[workload] NUCLEUS_WORKLOAD_PROBE: PASS
[workload] NUCLEUS_EGRESS_CHECK: positive-control socketpair round-trip ok
[workload] NUCLEUS_EGRESS_PROBE: PASS
[workload] NUCLEUS_ADVERSARY_STAGE pid1-secret-theft: attempted=yes blocked=yes
[workload] NUCLEUS_ADVERSARY_STAGE rootfs-tamper: attempted=yes blocked=yes
[workload] NUCLEUS_ADVERSARY_STAGE exfil: attempted=yes blocked=yes targets=3
[workload] NUCLEUS_ADVERSARY_CONTROL: live
[workload] NUCLEUS_ADVERSARY: CONTAINED
";

    const OTHER_POD: &str = "[    0.700] guest-init: booting\n[    1.2] tool-proxy: ready\n";

    fn run_on(logs: &[&str]) -> (Vec<Stage>, Lane) {
        let logs: Vec<String> = logs.iter().map(|s| (*s).to_string()).collect();
        let s = stages(&logs);
        let l = lane(&s);
        (s, l)
    }

    fn verdict(s: &[Stage], stage: &str) -> Verdict {
        s.iter()
            .find(|x| x.stage == stage)
            .map(|x| x.verdict)
            .expect("stage present")
    }

    #[test]
    fn all_contained_passes() {
        let (s, l) = run_on(&[OTHER_POD, CONTAINED_LOG]);
        assert_eq!(s.len(), STAGES.len());
        assert!(s.iter().all(|x| x.verdict == Verdict::Contained), "{s:#?}");
        assert_eq!(l.verdict, LaneVerdict::Pass, "{l:#?}");
        assert_eq!((l.contained, l.breach, l.inconclusive), (6, 0, 0));
        assert!(l.reasons.is_empty());
    }

    #[test]
    fn one_breach_fails() {
        let log = CONTAINED_LOG.replace(
            "rootfs-tamper: attempted=yes blocked=yes",
            "rootfs-tamper: attempted=yes blocked=no",
        );
        let (s, l) = run_on(&[&log]);
        assert_eq!(verdict(&s, "rootfs-tamper"), Verdict::Breach);
        assert_eq!(l.verdict, LaneVerdict::Fail);
        assert_eq!(l.breach, 1);
    }

    #[test]
    fn a_probe_fail_line_is_a_breach_even_beside_a_pass() {
        let log = format!("{CONTAINED_LOG}[workload] NUCLEUS_EGRESS_PROBE: FAIL: connect ok\n");
        let (s, l) = run_on(&[&log]);
        assert_eq!(verdict(&s, "default-deny-egress"), Verdict::Breach);
        assert_eq!(l.verdict, LaneVerdict::Fail);
    }

    #[test]
    fn a_campaign_breach_fails() {
        let log = CONTAINED_LOG.replace(
            "NUCLEUS_ADVERSARY: CONTAINED",
            "NUCLEUS_ADVERSARY: BREACH:exfil",
        );
        let (s, l) = run_on(&[&log]);
        assert_eq!(verdict(&s, "campaign"), Verdict::Breach);
        assert_eq!(l.verdict, LaneVerdict::Fail);
    }

    #[test]
    fn one_inconclusive_fails() {
        // The probe crashed after stage 2: no exfil line.
        let log = CONTAINED_LOG.replace(
            "[workload] NUCLEUS_ADVERSARY_STAGE exfil: attempted=yes blocked=yes targets=3\n",
            "",
        );
        let (s, l) = run_on(&[&log]);
        assert_eq!(verdict(&s, "exfil"), Verdict::Inconclusive);
        assert_eq!(l.verdict, LaneVerdict::Fail);
        assert_eq!(l.inconclusive, 1);
    }

    #[test]
    fn a_stage_not_attempted_is_inconclusive_not_contained() {
        let log = CONTAINED_LOG.replace(
            "pid1-secret-theft: attempted=yes blocked=yes",
            "pid1-secret-theft: attempted=no blocked=yes",
        );
        let (s, l) = run_on(&[&log]);
        assert_eq!(verdict(&s, "pid1-secret-theft"), Verdict::Inconclusive);
        assert_eq!(l.verdict, LaneVerdict::Fail);
    }

    #[test]
    fn contained_with_a_dead_control_is_inconclusive() {
        let log = CONTAINED_LOG.replace(
            "NUCLEUS_ADVERSARY_CONTROL: live",
            "NUCLEUS_ADVERSARY_CONTROL: dead",
        );
        let (s, l) = run_on(&[&log]);
        assert_eq!(verdict(&s, "campaign"), Verdict::Inconclusive);
        assert_eq!(l.verdict, LaneVerdict::Fail);
        let log = CONTAINED_LOG.replace("[workload] NUCLEUS_ADVERSARY_CONTROL: live\n", "");
        let (s, _) = run_on(&[&log]);
        assert_eq!(verdict(&s, "campaign"), Verdict::Inconclusive);
    }

    #[test]
    fn empty_input_fails() {
        // No guest log at all.
        let (s, l) = run_on(&[]);
        assert!(s.iter().all(|x| x.verdict == Verdict::Inconclusive));
        assert_eq!(l.verdict, LaneVerdict::Fail);
        // Logs that exist but carry no probe output.
        let (_, l) = run_on(&["", OTHER_POD]);
        assert_eq!(l.verdict, LaneVerdict::Fail);
        assert_eq!(l.inconclusive, STAGES.len());
    }

    #[test]
    fn zero_stages_fail() {
        let l = lane(&[]);
        assert_eq!(l.verdict, LaneVerdict::Fail);
        assert_eq!(l.reasons, vec!["no stage was measured".to_string()]);
    }

    #[test]
    fn the_record_serializes_verdicts_as_their_names() {
        let (s, l) = run_on(&[CONTAINED_LOG]);
        let v = serde_json::to_value(&s).expect("json");
        assert_eq!(v[0]["verdict"], "CONTAINED");
        assert_eq!(serde_json::to_value(l.verdict).expect("json"), "PASS");
        assert_eq!(
            serde_json::to_value(Verdict::Inconclusive).expect("json"),
            "INCONCLUSIVE"
        );
    }

    /// The probe's stage names, read from its source, are the ones this lane expects: a stage
    /// renamed in the probe would otherwise read as INCONCLUSIVE forever.
    #[test]
    fn the_adversary_stage_names_are_the_probes_own() {
        let src = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../nucleus-adversary-probe/src/main.rs"),
        )
        .expect("the adversary probe's source");
        for d in STAGES {
            if let Reading::AdversaryStage(name) = d.reading {
                assert!(
                    src.contains(&format!("\"{name}\"")),
                    "the adversary probe has no stage named {name:?}"
                );
            }
        }
    }

    #[test]
    fn missing_state_dir_fails_and_still_writes_the_record() {
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("escape-lane.json");
        let a = Args {
            state_dir: dir.path().join("does-not-exist"),
            sudo: false,
            node_bin: dir.path().join("no-node"),
            out: out.clone(),
        };
        let err = run(dir.path(), &a).expect_err("missing input must fail");
        assert!(format!("{err:#}").contains("no guest log"), "{err:#}");
        let rec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).expect("record written")).expect("json");
        assert_eq!(rec["lane"]["verdict"], "FAIL");
        assert_eq!(rec["inputs"]["guest_logs"], 0);
        assert!(rec["node_build"]["sha256"].is_null());
    }

    #[test]
    fn a_state_dir_with_a_contained_pod_passes_end_to_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pod = dir.path().join("pods/abc");
        std::fs::create_dir_all(&pod).expect("mkdir");
        std::fs::write(pod.join(GUEST_LOG), CONTAINED_LOG).expect("write");
        let node = dir.path().join("nucleus-node");
        std::fs::write(&node, b"node").expect("write");
        let out = dir.path().join("escape-lane.json");
        let a = Args {
            state_dir: dir.path().to_path_buf(),
            sudo: false,
            node_bin: node,
            out: out.clone(),
        };
        run(dir.path(), &a).expect("all contained passes");
        let rec: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).expect("record")).expect("json");
        assert_eq!(rec["schema"], SCHEMA);
        assert_eq!(rec["lane"]["verdict"], "PASS");
        assert_eq!(rec["inputs"]["guest_logs"], 1);
        assert_eq!(
            rec["node_build"]["sha256"],
            hex::encode(Sha256::digest(b"node"))
        );
        assert_eq!(
            rec["guest_release"],
            nucleus_spec::tier2_artifacts::GUEST_RELEASE
        );
    }
}
