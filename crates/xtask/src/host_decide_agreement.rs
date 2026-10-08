//! `cargo xtask host-decide-agreement` — how often does the host's shadow
//! decision agree with the one the guest enforced? (ADR 0014, #2702 M3.)
//!
//! The host's decision service runs in SHADOW mode (`nucleus-node/src/host_decide.rs`):
//! it decides every tool call the guest decides and compares. ADR 0014 makes the
//! host authoritative once that comparison clears a measured threshold, so the
//! number has to come from somewhere other than a hand `grep`. This reads it from
//! what live boots already leave behind: each `live-boot-evidence` bundle
//! (`quickstart-boot.yml`, artifact `live-boot-evidence-x86_64`) carries the
//! node's JSON log, in which the node prints, per pod:
//!
//! * `host-decide shadow listening` when the pod's decision channel opens, and
//! * `host-decide shadow tally at teardown` with the pod's counts, when it closes.
//!
//! A bundle may also carry the pod's `host-decide-disagreements.jsonl`; when it
//! does, each disagreement is classified (host stricter, guest stricter, or both
//! refusing for different reasons). No bundle carries it today, so a disagreement
//! without its record is counted as **unclassified**, never as a class.
//!
//! # What this refuses to do (ADR 0007 A)
//!
//! * A bundle whose log cannot be read, or carries a tally this cannot parse, is
//!   `could not read` (A-2) — never a run with zero disagreements.
//! * A bundle with no decision channel at all is `no shadow`, and contributes
//!   nothing to the rate (A-5: absence is a third value).
//! * A pod whose channel opened but whose tally never printed is `unreported`,
//!   not an agreement.
//! * With no compared decision anywhere, the rate is "could not measure", never
//!   100 %.
//!
//! Usage: download the bundles (`gh run download <run> -n live-boot-evidence-x86_64
//! -D <dir>/<run>`), then `cargo xtask host-decide-agreement <dir>/<run>...`.
//! Each directory is one run, labelled by its name. Exit status: 0 when every
//! bundle was read and at least one decision was compared; 1 when any bundle
//! could not be read; 2 when nothing was compared.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The node log inside a bundle (`live_boot_evidence`'s name for it).
const NODE_LOG: &str = "node.log";
/// The node's per-pod disagreement record (`host_decide::DISAGREEMENT_LOG`).
const DISAGREEMENT_LOG: &str = "host-decide-disagreements.jsonl";
/// The node's message when a pod's decision channel opens.
const LISTENING: &str = "host-decide shadow listening";
/// The node's message carrying a pod's final counts.
const TEARDOWN: &str = "host-decide shadow tally at teardown";

/// One pod's final counts, as the node printed them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Tally {
    pub agree: u64,
    pub disagree: u64,
    /// Channels the host closed because the guest broke the protocol, or the
    /// pod's policy was gone. A fault's decision was never compared.
    pub faults: u64,
}

impl Tally {
    /// Parse the node's `TallySnapshot { agree: N, disagree: N, faults: N }`.
    ///
    /// Exactly that shape: a missing, extra or reordered field is an error, so
    /// a node that changes the spelling makes this fail rather than read zeros
    /// (ADR 0007 I-2, B-4).
    pub fn parse(text: &str) -> Result<Self> {
        let inner = text
            .trim()
            .strip_prefix("TallySnapshot {")
            .and_then(|s| s.strip_suffix('}'))
            .with_context(|| format!("not a TallySnapshot: {text:?}"))?;
        let fields: Vec<&str> = inner.split(',').map(str::trim).collect();
        let [agree, disagree, faults] = fields.as_slice() else {
            bail!("a TallySnapshot has exactly three fields: {text:?}");
        };
        let field = |name: &str, raw: &str| -> Result<u64> {
            let value = raw
                .strip_prefix(name)
                .and_then(|s| s.strip_prefix(": "))
                .with_context(|| format!("expected `{name}: <n>` in {text:?}"))?;
            value
                .parse::<u64>()
                .with_context(|| format!("`{name}` is not a count in {text:?}"))
        };
        Ok(Tally {
            agree: field("agree", agree)?,
            disagree: field("disagree", disagree)?,
            faults: field("faults", faults)?,
        })
    }

    fn add(&mut self, other: Tally) {
        self.agree += other.agree;
        self.disagree += other.disagree;
        self.faults += other.faults;
    }
}

/// An outcome as the node's disagreement record spells it
/// (`host_decide::outcome_code`).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Allowed,
    ApprovalRequired,
    Denied(String),
}

impl Outcome {
    fn parse(code: &str) -> Result<Self> {
        match code {
            "allowed" => Ok(Outcome::Allowed),
            "approval_required" => Ok(Outcome::ApprovalRequired),
            other => match other.strip_prefix("denied:") {
                Some(reason) if !reason.is_empty() => Ok(Outcome::Denied(reason.to_string())),
                _ => bail!("not an outcome code: {code:?}"),
            },
        }
    }

    /// How much the outcome withholds: a denial more than a held approval,
    /// which is more than an allow.
    fn strictness(&self) -> u8 {
        match self {
            Outcome::Allowed => 0,
            Outcome::ApprovalRequired => 1,
            Outcome::Denied(_) => 2,
        }
    }
}

/// Why a host and a guest outcome differ. The flip criterion treats these
/// differently, so they are never summed into one number first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The host withholds more than the guest enforced.
    HostStricter,
    /// The host would have allowed what the guest refused — the host's verdict
    /// is the wider one. Enforcing it would grant more.
    GuestStricter,
    /// Both refuse, for different reasons: the receipt would name another cause.
    DifferingReason,
}

/// Classify one disagreement. `None` for a pair that is not a disagreement.
fn classify(guest: &Outcome, host: &Outcome) -> Option<Class> {
    if guest == host {
        return None;
    }
    match host.strictness().cmp(&guest.strictness()) {
        std::cmp::Ordering::Greater => Some(Class::HostStricter),
        std::cmp::Ordering::Less => Some(Class::GuestStricter),
        std::cmp::Ordering::Equal => Some(Class::DifferingReason),
    }
}

/// Per-class counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Classes {
    pub host_stricter: u64,
    pub guest_stricter: u64,
    pub differing_reason: u64,
}

impl Classes {
    fn count(&mut self, c: Class) {
        match c {
            Class::HostStricter => self.host_stricter += 1,
            Class::GuestStricter => self.guest_stricter += 1,
            Class::DifferingReason => self.differing_reason += 1,
        }
    }

    fn total(&self) -> u64 {
        self.host_stricter + self.guest_stricter + self.differing_reason
    }

    fn add(&mut self, other: Classes) {
        self.host_stricter += other.host_stricter;
        self.guest_stricter += other.guest_stricter;
        self.differing_reason += other.differing_reason;
    }
}

/// What one bundle says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reading {
    /// The node opened at least one decision channel.
    Measured {
        /// Pods whose channel opened.
        listening: u64,
        /// Pods whose final counts were printed.
        reported: u64,
        /// The sum of those counts.
        tally: Tally,
        /// Disagreements classified from the record file.
        classes: Classes,
    },
    /// The node opened no decision channel: nothing was shadowed.
    NoShadow,
    /// The bundle could not be read; nothing about it is known.
    CouldNotRead(String),
}

#[derive(Deserialize)]
struct LogLine {
    fields: Option<LogFields>,
}

#[derive(Deserialize)]
struct LogFields {
    message: Option<String>,
    tally: Option<String>,
}

#[derive(Deserialize)]
struct DisagreementRecord {
    guest: String,
    host: String,
}

/// Read one node log. Only lines that start with `{` are the node's; anything
/// else on its stderr (an `iptables` complaint) is not, and is skipped. A `{`
/// line that is not JSON, or that names a host-decide message without the
/// fields it must carry, fails the whole read.
fn read_log(text: &str) -> Result<(u64, u64, Tally)> {
    let (mut listening, mut reported, mut tally) = (0u64, 0u64, Tally::default());
    for (n, line) in text.lines().enumerate() {
        if !line.starts_with('{') {
            if line.contains("host-decide") {
                bail!("line {}: a host-decide line that is not JSON", n + 1);
            }
            continue;
        }
        let parsed: LogLine =
            serde_json::from_str(line).with_context(|| format!("line {}: not JSON", n + 1))?;
        let Some(fields) = parsed.fields else {
            continue;
        };
        match fields.message.as_deref() {
            Some(LISTENING) => listening += 1,
            Some(TEARDOWN) => {
                let raw = fields
                    .tally
                    .with_context(|| format!("line {}: teardown without a tally", n + 1))?;
                tally.add(Tally::parse(&raw).with_context(|| format!("line {}", n + 1))?);
                reported += 1;
            }
            Some(_) | None => {}
        }
    }
    Ok((listening, reported, tally))
}

fn read_disagreements(text: &str) -> Result<Classes> {
    let mut classes = Classes::default();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let r: DisagreementRecord =
            serde_json::from_str(line).with_context(|| format!("record {}", n + 1))?;
        let (guest, host) = (Outcome::parse(&r.guest)?, Outcome::parse(&r.host)?);
        let class = classify(&guest, &host)
            .with_context(|| format!("record {}: a disagreement with equal outcomes", n + 1))?;
        classes.count(class);
    }
    Ok(classes)
}

/// Read one bundle directory.
pub fn read_bundle(dir: &Path) -> Reading {
    let log = match std::fs::read_to_string(dir.join(NODE_LOG)) {
        Ok(t) => t,
        Err(e) => return Reading::CouldNotRead(format!("{NODE_LOG}: {e}")),
    };
    let (listening, reported, tally) = match read_log(&log) {
        Ok(r) => r,
        Err(e) => return Reading::CouldNotRead(format!("{NODE_LOG}: {e:#}")),
    };
    if listening == 0 && reported == 0 {
        return Reading::NoShadow;
    }
    let classes = match std::fs::read_to_string(dir.join(DISAGREEMENT_LOG)) {
        Ok(t) => match read_disagreements(&t) {
            Ok(c) => c,
            Err(e) => return Reading::CouldNotRead(format!("{DISAGREEMENT_LOG}: {e:#}")),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Classes::default(),
        Err(e) => return Reading::CouldNotRead(format!("{DISAGREEMENT_LOG}: {e}")),
    };
    Reading::Measured {
        listening,
        reported,
        tally,
        classes,
    }
}

/// The corpus, summed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Summary {
    pub runs_measured: u64,
    pub runs_no_shadow: u64,
    pub runs_unreadable: Vec<String>,
    pub listening: u64,
    pub reported: u64,
    pub tally: Tally,
    pub classes: Classes,
}

impl Summary {
    pub fn of<'a>(readings: impl IntoIterator<Item = (&'a str, &'a Reading)>) -> Self {
        let mut s = Summary::default();
        for (label, r) in readings {
            match r {
                Reading::Measured {
                    listening,
                    reported,
                    tally,
                    classes,
                } => {
                    s.runs_measured += 1;
                    s.listening += listening;
                    s.reported += reported;
                    s.tally.add(*tally);
                    s.classes.add(*classes);
                }
                Reading::NoShadow => s.runs_no_shadow += 1,
                Reading::CouldNotRead(why) => s.runs_unreadable.push(format!("{label}: {why}")),
            }
        }
        s
    }

    /// Decisions the host compared.
    pub fn compared(&self) -> u64 {
        self.tally.agree + self.tally.disagree
    }

    /// Disagreements no record classified.
    pub fn unclassified(&self) -> u64 {
        self.tally.disagree.saturating_sub(self.classes.total())
    }

    /// The agreement rate over compared decisions, in hundredths of a
    /// percent, or `None` when nothing was compared — "could not measure",
    /// never 100 %. Integer arithmetic: no cast can round a disagreement away.
    pub fn rate_basis_points(&self) -> Option<u64> {
        let compared = u128::from(self.compared());
        let agree = u128::from(self.tally.agree);
        (compared > 0)
            .then(|| u64::try_from(agree * 10_000 / compared).ok())
            .flatten()
    }

    /// The exit status `run` reports. See the module docs.
    pub fn exit_code(&self) -> i32 {
        if !self.runs_unreadable.is_empty() {
            1
        } else if self.compared() == 0 {
            2
        } else {
            0
        }
    }
}

pub fn run(dirs: &[PathBuf]) -> Result<i32> {
    if dirs.is_empty() {
        bail!("name at least one live-boot-evidence bundle directory");
    }
    let readings: Vec<(String, Reading)> = dirs
        .iter()
        .map(|d| {
            let label = d
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| d.display().to_string());
            (label, read_bundle(d))
        })
        .collect();
    for (label, r) in &readings {
        match r {
            Reading::Measured {
                listening,
                reported,
                tally,
                classes: _,
            } => println!(
                "{label}: pods {listening} (reported {reported}), agree {}, disagree {}, not compared (faults) {}",
                tally.agree, tally.disagree, tally.faults
            ),
            Reading::NoShadow => println!("{label}: no shadow channel"),
            Reading::CouldNotRead(why) => println!("{label}: COULD NOT READ — {why}"),
        }
    }
    let s = Summary::of(readings.iter().map(|(l, r)| (l.as_str(), r)));
    println!();
    println!(
        "runs: {} measured, {} with no shadow channel, {} unreadable",
        s.runs_measured,
        s.runs_no_shadow,
        s.runs_unreadable.len()
    );
    println!(
        "pods: {} listening, {} reported, {} unreported",
        s.listening,
        s.reported,
        s.listening.saturating_sub(s.reported)
    );
    println!(
        "decisions compared: {} (agree {}, disagree {}); not compared (host faults): {}",
        s.compared(),
        s.tally.agree,
        s.tally.disagree,
        s.tally.faults
    );
    match s.rate_basis_points() {
        Some(bp) => println!(
            "agreement: {}/{} = {}.{:02}% (rounded down)",
            s.tally.agree,
            s.compared(),
            bp / 100,
            bp % 100
        ),
        None => println!("agreement: could not measure (no decision was compared)"),
    }
    println!(
        "disagreements: host stricter {}, guest stricter {}, differing reason {}, unclassified (no record) {}",
        s.classes.host_stricter,
        s.classes.guest_stricter,
        s.classes.differing_reason,
        s.unclassified()
    );
    println!(
        "not visible here: decisions the guest could not put to the host (its HostUnavailable count is in the guest's /v1/health only)"
    );
    for u in &s.runs_unreadable {
        println!("unreadable: {u}");
    }
    Ok(s.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listening(pod: &str) -> String {
        format!(
            r#"{{"timestamp":"t","level":"INFO","fields":{{"message":"{LISTENING}","pod":"{pod}"}},"target":"nucleus_node::host_decide"}}"#
        )
    }

    fn teardown(agree: u64, disagree: u64, faults: u64) -> String {
        format!(
            r#"{{"timestamp":"t","level":"INFO","fields":{{"message":"{TEARDOWN}","pod_dir":"/p","tally":"TallySnapshot {{ agree: {agree}, disagree: {disagree}, faults: {faults} }}"}},"target":"nucleus_node::pod_boot_identity"}}"#
        )
    }

    fn bundle(log: &str, disagreements: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(NODE_LOG), log).expect("write log");
        if let Some(d) = disagreements {
            std::fs::write(dir.path().join(DISAGREEMENT_LOG), d).expect("write record");
        }
        dir
    }

    /// The shape a real bundle carries (run 37806146438): two pods, one
    /// compared, one faulted at teardown, stderr noise between.
    #[test]
    fn a_real_shaped_log_is_counted() {
        let log = [
            listening("a"),
            "iptables: Bad rule (does a matching rule exist in that chain?).".into(),
            teardown(1, 0, 0),
            listening("b"),
            teardown(0, 0, 1),
        ]
        .join("\n");
        let dir = bundle(&log, None);
        assert_eq!(
            read_bundle(dir.path()),
            Reading::Measured {
                listening: 2,
                reported: 2,
                tally: Tally {
                    agree: 1,
                    disagree: 0,
                    faults: 1
                },
                classes: Classes::default(),
            }
        );
    }

    /// A-2: a tally this cannot parse makes the bundle unreadable. Reading it
    /// as zeros would turn a node that changed its spelling into a clean run.
    #[test]
    fn an_unparsable_tally_is_could_not_read_not_zero() {
        let bad = teardown(1, 0, 0).replace("agree: 1", "agree: one");
        let dir = bundle(&[listening("a"), bad].join("\n"), None);
        assert!(matches!(read_bundle(dir.path()), Reading::CouldNotRead(_)));
        for shape in [
            "TallySnapshot { agree: 1, disagree: 0 }",
            "TallySnapshot { agree: 1, disagree: 0, faults: 0, extra: 1 }",
            "TallySnapshot { disagree: 0, agree: 1, faults: 0 }",
            "Tally { agree: 1, disagree: 0, faults: 0 }",
        ] {
            assert!(Tally::parse(shape).is_err(), "{shape}");
        }
    }

    /// A missing log is unreadable, not a run with no shadow.
    #[test]
    fn a_missing_log_is_could_not_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(read_bundle(dir.path()), Reading::CouldNotRead(_)));
    }

    /// A-5: a run that never opened a channel contributes nothing, and a corpus
    /// of them has no rate.
    #[test]
    fn no_comparison_is_could_not_measure_not_full_agreement() {
        let dir = bundle(&teardown(0, 0, 0).replace(TEARDOWN, "unrelated"), None);
        let r = read_bundle(dir.path());
        assert_eq!(r, Reading::NoShadow);
        let s = Summary::of([("run", &r)]);
        assert_eq!(s.rate_basis_points(), None);
        assert_eq!(s.exit_code(), 2);
        // Faults alone compare nothing either.
        let dir = bundle(&[listening("a"), teardown(0, 0, 1)].join("\n"), None);
        let r = read_bundle(dir.path());
        let s = Summary::of([("run", &r)]);
        assert_eq!(s.rate_basis_points(), None);
        assert_eq!(s.exit_code(), 2);
    }

    /// A pod whose channel opened but whose tally never printed is unreported,
    /// and is not folded into agreement.
    #[test]
    fn an_unreported_pod_is_counted_apart() {
        let dir = bundle(
            &[listening("a"), listening("b"), teardown(3, 0, 0)].join("\n"),
            None,
        );
        let r = read_bundle(dir.path());
        let s = Summary::of([("run", &r)]);
        assert_eq!((s.listening, s.reported), (2, 1));
        assert_eq!(s.compared(), 3);
    }

    /// Disagreements are classified from the record; one without a record is
    /// unclassified rather than assigned a class.
    #[test]
    fn disagreements_are_classified_or_left_unclassified() {
        let records = [
            r#"{"guest":"allowed","host":"denied:flow_refused"}"#,
            r#"{"guest":"approval_required","host":"allowed"}"#,
            r#"{"guest":"denied:not_granted","host":"denied:budget_exhausted"}"#,
        ]
        .join("\n");
        let dir = bundle(
            &[listening("a"), teardown(10, 4, 0)].join("\n"),
            Some(&records),
        );
        let r = read_bundle(dir.path());
        let s = Summary::of([("run", &r)]);
        assert_eq!(
            s.classes,
            Classes {
                host_stricter: 1,
                guest_stricter: 1,
                differing_reason: 1
            }
        );
        assert_eq!(s.unclassified(), 1);
        assert_eq!(s.exit_code(), 0);
    }

    /// A record whose outcomes are equal, or spelled in a way the node never
    /// writes, makes the bundle unreadable rather than miscounted.
    #[test]
    fn a_malformed_record_is_could_not_read() {
        for bad in [
            r#"{"guest":"allowed","host":"allowed"}"#,
            r#"{"guest":"allowed","host":"refused"}"#,
            r#"{"guest":"allowed","host":"denied:"}"#,
        ] {
            let dir = bundle(&[listening("a"), teardown(0, 1, 0)].join("\n"), Some(bad));
            assert!(
                matches!(read_bundle(dir.path()), Reading::CouldNotRead(_)),
                "{bad}"
            );
        }
    }

    /// One unreadable bundle reds the whole corpus, whatever the others say.
    #[test]
    fn one_unreadable_bundle_reds_the_corpus() {
        let good = bundle(&[listening("a"), teardown(5, 0, 0)].join("\n"), None);
        let missing = tempfile::tempdir().expect("tempdir");
        let (g, m) = (read_bundle(good.path()), read_bundle(missing.path()));
        let s = Summary::of([("good", &g), ("missing", &m)]);
        assert_eq!(s.rate_basis_points(), Some(10_000));
        assert_eq!(s.exit_code(), 1);
    }
}
