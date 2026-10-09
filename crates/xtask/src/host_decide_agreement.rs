//! `cargo xtask host-decide-agreement` — how often does the host's shadow
//! decision agree with the one the guest enforced? (ADR 0014, #2702 M3.)
//!
//! The host's decision service runs in SHADOW mode (`nucleus-node/src/host_decide.rs`):
//! it decides every tool call the guest decides and compares. ADR 0014 makes the
//! host authoritative once that comparison clears a measured threshold, so the
//! number has to come from somewhere other than a hand `grep`. This reads it from
//! what live boots already leave behind: each `live-boot-evidence` bundle
//! (`quickstart-boot.yml`, artifact `live-boot-evidence-x86_64`) carries
//!
//! * the node's JSON log, in which the node prints, per pod,
//!   `host-decide shadow listening` when the pod's decision channel opens, and
//!   [`TEARDOWN_MESSAGE`] with the pod's counts when it closes. A node from
//!   ADR 0014 S1 on prints the counts as numeric fields, with the comparisons by
//!   operation and outcome pair, the `Decide`s never reported on, and the
//!   host's service time; an older node printed one `TallySnapshot` string,
//!   which is still read, and whose missing detail is reported as missing;
//! * the pods' `host-decide-disagreements.jsonl`, concatenated, from which each
//!   disagreement is classified (host stricter, guest stricter, or both refusing
//!   for different reasons). A disagreement without its record is
//!   **unclassified**, never assigned a class;
//! * each pod's guest console, on which a guest from S1 on prints its own
//!   telemetry (`HostDecideTelemetry`): its tally, every `HostUnavailable` by
//!   kind, and the round trip of each `Decide`. A console without that line is
//!   "guest telemetry absent" (guests 2.4.0–2.7.0), never zero;
//! * from ADR 0014 S2 on, the coverage pod's call log. A run that carries it is
//!   held to the coverage set (`host_decide_telemetry::COVERAGE`): every
//!   operation in it must have at least one compared decision in that run, and
//!   one that has none is named. A run without the log predates S2 and is
//!   reported as "coverage not run", not as covered.
//!
//! # What this refuses to do (ADR 0007 A)
//!
//! * A bundle whose log cannot be read, or carries a teardown line this cannot
//!   parse, or whose pairs and counts disagree, is `could not read` (A-2) —
//!   never a run with zero disagreements. So is a console whose telemetry line
//!   does not parse.
//! * A bundle with no decision channel at all is `no shadow`, and contributes
//!   nothing to the rate (A-5: absence is a third value).
//! * A pod whose channel opened but whose tally never printed is `unreported`,
//!   not an agreement.
//! * With no compared decision anywhere, the rate is "could not measure", never
//!   100 %. A node whose shadow listener never started reads this way.
//!
//! Usage: download the bundles (`gh run download <run> -n live-boot-evidence-x86_64
//! -D <dir>/<run>`), then `cargo xtask host-decide-agreement <dir>/<run>...`.
//! Each directory is one run, labelled by its name. Exit status: 1 when any
//! bundle could not be read, any disagreement is unclassified, any is guest
//! stricter (ADR 0014 §10 bounds that class at zero: enforcing the host's
//! answer would grant more), any is host stricter with no listed honest source
//! (`HostStricterSource`, also bounded at zero), or a run with a coverage pod compared nothing for
//! an operation in the coverage set;
//! otherwise 2 when nothing was compared ("could not measure"); otherwise 0.

use anyhow::{Context, Result, bail};
use nucleus_spec::host_decide_telemetry::{
    GuestTelemetry, HostTeardown, LatencyHistogram, OutcomePair, TEARDOWN_MESSAGE,
    UnavailableByKind, coverage_names,
};
use nucleus_spec::live_boot::Files;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The node's message when a pod's decision channel opens.
const LISTENING: &str = "host-decide shadow listening";

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
    /// Parse an older node's `TallySnapshot { agree: N, disagree: N, faults: N }`.
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
    /// The host withholds more than the guest enforced, for the reason named.
    HostStricter(HostStricterSource),
    /// The host would have allowed what the guest refused — the host's verdict
    /// is the wider one. Enforcing it would grant more.
    GuestStricter,
    /// Both refuse, for different reasons: the receipt would name another cause.
    DifferingReason,
}

/// Why the host withheld more. ADR 0014 §10 tolerates a host-stricter
/// disagreement only when it is attributed to a listed honest source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStricterSource {
    /// The host refused for the flow (`denied:flow_refused`) where the guest
    /// did not. The host's label is the join of what the host itself observed
    /// (§3: initial taint, delivered responses, every `Observe`), one label for
    /// the pod, while the guest's graph refines taint per node. So the host's
    /// label is never below the guest's, and a flow refusal the guest did not
    /// make is the host's label being higher: an attributed source, §3.
    ///
    /// This is ADR 0014 S3's settlement of S2's first live finding (a tainted
    /// write the guest held for `approval_required` and the host refused): the
    /// host is right. A write is not an action-bound sink, so no approval
    /// declassifies its flow (`ACTION_BOUND_SINKS`); the guest's approval came
    /// from its exposure gate, reached only because its own graph did not see
    /// the write as tainted.
    HostTaint,
    /// Anything else. §10 bounds these at zero.
    Unattributed,
}

impl HostStricterSource {
    fn of(host: &Outcome) -> Self {
        match host {
            Outcome::Denied(reason) if reason == "flow_refused" => HostStricterSource::HostTaint,
            Outcome::Denied(_) | Outcome::ApprovalRequired | Outcome::Allowed => {
                HostStricterSource::Unattributed
            }
        }
    }
}

/// Classify one disagreement. `None` for a pair that is not a disagreement.
fn classify(guest: &Outcome, host: &Outcome) -> Option<Class> {
    if guest == host {
        return None;
    }
    match host.strictness().cmp(&guest.strictness()) {
        std::cmp::Ordering::Greater => Some(Class::HostStricter(HostStricterSource::of(host))),
        std::cmp::Ordering::Less => Some(Class::GuestStricter),
        std::cmp::Ordering::Equal => Some(Class::DifferingReason),
    }
}

/// Per-class counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Classes {
    pub host_stricter: u64,
    /// Of `host_stricter`, the ones attributed to the host's taint (§3).
    pub host_taint: u64,
    pub guest_stricter: u64,
    pub differing_reason: u64,
}

impl Classes {
    fn count(&mut self, c: Class) {
        match c {
            Class::HostStricter(HostStricterSource::HostTaint) => {
                self.host_stricter += 1;
                self.host_taint += 1;
            }
            Class::HostStricter(HostStricterSource::Unattributed) => self.host_stricter += 1,
            Class::GuestStricter => self.guest_stricter += 1,
            Class::DifferingReason => self.differing_reason += 1,
        }
    }

    fn total(&self) -> u64 {
        self.host_stricter + self.guest_stricter + self.differing_reason
    }

    fn add(&mut self, other: Classes) {
        self.host_stricter += other.host_stricter;
        self.host_taint += other.host_taint;
        self.guest_stricter += other.guest_stricter;
        self.differing_reason += other.differing_reason;
    }
}

/// The comparisons on one operation, by the pair of outcomes they ended in.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OperationCounts {
    /// `(guest, host)` → decisions.
    pub pairs: BTreeMap<(String, String), u64>,
}

impl OperationCounts {
    /// Decisions compared on this operation.
    pub fn compared(&self) -> u64 {
        self.pairs.values().sum()
    }

    /// Of those, the ones the two kernels agreed on.
    pub fn agree(&self) -> u64 {
        self.pairs
            .iter()
            .filter(|((guest, host), _)| guest == host)
            .map(|(_, n)| n)
            .sum()
    }
}

/// What the host said beyond its three counts. Only a node from ADR 0014 S1 on
/// says it; a pod whose node did not is counted in `pods_without_detail`, so
/// "not reported" never reads as zero.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostDetail {
    /// Pods whose teardown line carried no detail (an older node).
    pub pods_without_detail: u64,
    /// `Decide`s answered and never reported on, from the pods with detail.
    pub unreported: u64,
    /// Comparisons by operation, from the pods with detail.
    pub operations: BTreeMap<String, OperationCounts>,
    /// The host's service time per `Decide`, from the pods with detail.
    pub service: LatencyHistogram,
}

impl HostDetail {
    fn pairs(&mut self, pairs: &[OutcomePair]) {
        for p in pairs {
            *self
                .operations
                .entry(p.operation.clone())
                .or_default()
                .pairs
                .entry((p.guest.clone(), p.host.clone()))
                .or_insert(0) += p.count;
        }
    }

    fn add(&mut self, other: &HostDetail) {
        self.pods_without_detail += other.pods_without_detail;
        self.unreported += other.unreported;
        for (op, counts) in &other.operations {
            let mine = self.operations.entry(op.clone()).or_default();
            for (pair, n) in &counts.pairs {
                *mine.pairs.entry(pair.clone()).or_insert(0) += n;
            }
        }
        self.service.merge(&other.service);
    }
}

/// What the guests' consoles said. A console without a telemetry line is
/// counted as absent, not as a guest that compared nothing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GuestSide {
    /// Consoles in the bundle.
    pub consoles: u64,
    /// Of those, the ones with no telemetry line (a guest before S1).
    pub absent: u64,
    /// The guests' own counts of what the host compared.
    pub agree: u64,
    pub disagree: u64,
    /// Decisions the guests could not put to the host, by why.
    pub unavailable: UnavailableByKind,
    /// The guests' `Decide` round trips.
    pub round_trip: LatencyHistogram,
}

impl GuestSide {
    fn telemetry(&mut self, t: &GuestTelemetry) {
        self.agree += t.agree();
        self.disagree += t.disagree();
        self.unavailable.add(t.unavailable());
        self.round_trip.merge(t.round_trip());
    }

    fn add(&mut self, other: &GuestSide) {
        self.consoles += other.consoles;
        self.absent += other.absent;
        self.agree += other.agree;
        self.disagree += other.disagree;
        self.unavailable.add(&other.unavailable);
        self.round_trip.merge(&other.round_trip);
    }
}

/// Whether a run was held to the coverage set, and what it lacked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    /// The bundle has no coverage pod: it predates S2.
    NotRun,
    /// The run had a coverage pod. `missing` lists each operation in the set
    /// with no compared decision in this run; empty means covered.
    Checked { missing: Vec<String> },
}

impl Coverage {
    fn of(ran: bool, host: &HostDetail) -> Self {
        if !ran {
            return Coverage::NotRun;
        }
        let missing = coverage_names()
            .into_iter()
            .filter(|op| host.operations.get(*op).is_none_or(|c| c.compared() == 0))
            .map(str::to_string)
            .collect();
        Coverage::Checked { missing }
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
        /// The host's detail, where its node printed it.
        host: HostDetail,
        /// The guests' consoles.
        guest: GuestSide,
        /// Whether the run was held to the coverage set.
        coverage: Coverage,
    },
    /// The node opened no decision channel: nothing was shadowed. What the
    /// guests' consoles say is still read: a guest that could not reach the
    /// host counts `connect` there.
    NoShadow { guest: GuestSide },
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
    /// An older node's `TallySnapshot` string.
    tally: Option<String>,
    agree: Option<u64>,
    disagree: Option<u64>,
    faults: Option<u64>,
    unreported: Option<u64>,
    pairs: Option<String>,
    service: Option<String>,
}

#[derive(Deserialize)]
struct DisagreementRecord {
    guest: String,
    host: String,
}

/// One teardown line's counts and, from a node that printed it, its detail.
fn teardown(fields: LogFields) -> Result<(Tally, HostDetail)> {
    let LogFields {
        message: _,
        tally,
        agree,
        disagree,
        faults,
        unreported,
        pairs,
        service,
    } = fields;
    match (tally, pairs) {
        (None, Some(pairs)) => {
            let need = |name: &str, v: Option<u64>| v.with_context(|| format!("no `{name}`"));
            let t = HostTeardown::from_fields(
                need("agree", agree)?,
                need("disagree", disagree)?,
                need("faults", faults)?,
                need("unreported", unreported)?,
                &pairs,
                service.as_deref().context("no `service`")?,
            )
            .map_err(anyhow::Error::msg)?;
            let mut detail = HostDetail {
                unreported: t.unreported,
                service: t.service.clone(),
                ..HostDetail::default()
            };
            detail.pairs(&t.pairs);
            Ok((
                Tally {
                    agree: t.agree,
                    disagree: t.disagree,
                    faults: t.faults,
                },
                detail,
            ))
        }
        (Some(legacy), None) => Ok((
            Tally::parse(&legacy)?,
            HostDetail {
                pods_without_detail: 1,
                ..HostDetail::default()
            },
        )),
        (Some(_), Some(_)) => bail!("a teardown with both a tally string and pairs"),
        (None, None) => bail!("teardown without a tally"),
    }
}

/// Read one node log. Only lines that start with `{` are the node's; anything
/// else on its stderr (an `iptables` complaint) is not, and is skipped. A `{`
/// line that is not JSON, or that names a host-decide message without the
/// fields it must carry, fails the whole read.
fn read_log(text: &str) -> Result<(u64, u64, Tally, HostDetail)> {
    let (mut listening, mut reported, mut tally) = (0u64, 0u64, Tally::default());
    let mut detail = HostDetail::default();
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
            Some(TEARDOWN_MESSAGE) => {
                let (t, d) = teardown(fields).with_context(|| format!("line {}", n + 1))?;
                tally.add(t);
                detail.add(&d);
                reported += 1;
            }
            Some(_) | None => {}
        }
    }
    Ok((listening, reported, tally, detail))
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

/// The consoles a bundle may carry, by their bundle names.
fn consoles(files: &Files) -> [&str; 3] {
    [
        files.guest_console.as_str(),
        files.effect_console.as_str(),
        files.coverage_console.as_str(),
    ]
}

/// Read every console the bundle carries. A console the bundle does not carry
/// is not counted at all (an older collector copied only one).
fn read_consoles(dir: &Path, files: &Files) -> Result<GuestSide> {
    let mut side = GuestSide::default();
    for name in consoles(files) {
        let bytes = match std::fs::read(dir.join(name)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| name.to_string()),
        };
        side.consoles += 1;
        match GuestTelemetry::last_on_console(&String::from_utf8_lossy(&bytes))
            .map_err(anyhow::Error::msg)
            .with_context(|| name.to_string())?
        {
            Some(t) => side.telemetry(&t),
            None => side.absent += 1,
        }
    }
    Ok(side)
}

/// Read one bundle directory.
pub fn read_bundle(dir: &Path) -> Reading {
    let files = Files::standard();
    let log = match std::fs::read_to_string(dir.join(&files.node_log)) {
        Ok(t) => t,
        Err(e) => return Reading::CouldNotRead(format!("{}: {e}", files.node_log)),
    };
    let (listening, reported, tally, host) = match read_log(&log) {
        Ok(r) => r,
        Err(e) => return Reading::CouldNotRead(format!("{}: {e:#}", files.node_log)),
    };
    let guest = match read_consoles(dir, &files) {
        Ok(g) => g,
        Err(e) => return Reading::CouldNotRead(format!("{e:#}")),
    };
    if listening == 0 && reported == 0 {
        return Reading::NoShadow { guest };
    }
    let record = &files.host_decide_disagreements;
    let classes = match std::fs::read_to_string(dir.join(record)) {
        Ok(t) => match read_disagreements(&t) {
            Ok(c) => c,
            Err(e) => return Reading::CouldNotRead(format!("{record}: {e:#}")),
        },
        // No record: every disagreement the tally names stays unclassified,
        // which the exit status reds.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Classes::default(),
        Err(e) => return Reading::CouldNotRead(format!("{record}: {e}")),
    };
    let ran = match std::fs::metadata(dir.join(&files.coverage_calls)) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Reading::CouldNotRead(format!("{}: {e}", files.coverage_calls)),
    };
    let coverage = Coverage::of(ran, &host);
    Reading::Measured {
        listening,
        reported,
        tally,
        classes,
        host,
        guest,
        coverage,
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
    pub host: HostDetail,
    pub guest: GuestSide,
    /// Runs held to the coverage set.
    pub coverage_checked: u64,
    /// `run: operation` for every operation a checked run never compared.
    pub coverage_missing: Vec<String>,
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
                    host,
                    guest,
                    coverage,
                } => {
                    match coverage {
                        Coverage::NotRun => {}
                        Coverage::Checked { missing } => {
                            s.coverage_checked += 1;
                            s.coverage_missing
                                .extend(missing.iter().map(|op| format!("{label}: {op}")));
                        }
                    }
                    s.runs_measured += 1;
                    s.listening += listening;
                    s.reported += reported;
                    s.tally.add(*tally);
                    s.classes.add(*classes);
                    s.host.add(host);
                    s.guest.add(guest);
                }
                Reading::NoShadow { guest } => {
                    s.runs_no_shadow += 1;
                    s.guest.add(guest);
                }
                Reading::CouldNotRead(why) => s.runs_unreadable.push(format!("{label}: {why}")),
            }
        }
        s
    }

    /// Decisions the host compared.
    pub fn compared(&self) -> u64 {
        self.tally.agree + self.tally.disagree
    }

    /// Host-stricter disagreements no listed honest source explains (§10: 0).
    pub fn unattributed_host_stricter(&self) -> u64 {
        self.classes
            .host_stricter
            .saturating_sub(self.classes.host_taint)
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

    /// The exit status `run` reports. See the module docs. An unclassified
    /// disagreement is red: the flip criterion bounds it at zero, and a
    /// disagreement nobody can attribute is one nobody can judge.
    pub fn exit_code(&self) -> i32 {
        if !self.runs_unreadable.is_empty()
            || self.unclassified() > 0
            || self.classes.guest_stricter > 0
            || self.unattributed_host_stricter() > 0
            || !self.coverage_missing.is_empty()
        {
            1
        } else if self.compared() == 0 {
            2
        } else {
            0
        }
    }
}

fn latency(h: &LatencyHistogram) -> String {
    match (h.percentile_us(500), h.percentile_us(990)) {
        (Some(p50), Some(p99)) => format!("p50 ≤ {p50} µs, p99 ≤ {p99} µs over {}", h.count()),
        _ => "no measurement".to_string(),
    }
}

fn print_summary(s: &Summary) {
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
        "decisions compared: {} (agree {}, disagree {})",
        s.compared(),
        s.tally.agree,
        s.tally.disagree,
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
        "disagreements: host stricter {} (host taint, §3: {}; unattributed: {}), guest stricter {}, differing reason {}, unclassified (no record) {}",
        s.classes.host_stricter,
        s.classes.host_taint,
        s.unattributed_host_stricter(),
        s.classes.guest_stricter,
        s.classes.differing_reason,
        s.unclassified()
    );
    let without = s.host.pods_without_detail;
    let detail_note = if without == 0 {
        String::new()
    } else {
        format!(" ({without} pods' nodes predate S1 and reported neither)")
    };
    println!(
        "not compared, host side: faults {}, Decides never reported {}{detail_note}",
        s.tally.faults, s.host.unreported
    );
    if s.guest.consoles == s.guest.absent {
        println!(
            "not compared, guest side: guest telemetry absent ({} consoles, none printed it)",
            s.guest.consoles
        );
    } else {
        let kinds: Vec<String> = s
            .guest
            .unavailable
            .by_kind()
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(k, n)| format!("{k} {n}"))
            .collect();
        println!(
            "not compared, guest side: {} [{}] from {} of {} consoles; guest telemetry absent on {}",
            s.guest.unavailable.total(),
            if kinds.is_empty() {
                "none".to_string()
            } else {
                kinds.join(", ")
            },
            s.guest.consoles - s.guest.absent,
            s.guest.consoles,
            s.guest.absent
        );
        println!(
            "guest's own count: agree {}, disagree {}",
            s.guest.agree, s.guest.disagree
        );
    }
    println!("host service time per Decide: {}", latency(&s.host.service));
    println!(
        "guest round trip per Decide: {}",
        if s.guest.consoles == s.guest.absent {
            "guest telemetry absent".to_string()
        } else {
            latency(&s.guest.round_trip)
        }
    );
    if s.host.operations.is_empty() {
        println!("per operation: not reported{detail_note}");
    } else {
        println!("per operation (guest outcome -> host outcome: decisions):");
        for (op, counts) in &s.host.operations {
            println!(
                "  {op}: compared {}, agree {}",
                counts.compared(),
                counts.agree()
            );
            for ((guest, host), n) in &counts.pairs {
                println!("    {guest} -> {host}: {n}");
            }
        }
    }
    println!(
        "coverage: {} of {} measured runs had a coverage pod (the others predate S2: coverage not run); set: {}",
        s.coverage_checked,
        s.runs_measured,
        coverage_names().join(", ")
    );
    for m in &s.coverage_missing {
        println!("COVERAGE MISSING (no compared decision) {m}");
    }
    if s.unattributed_host_stricter() > 0 {
        println!(
            "HOST STRICTER UNATTRIBUTED {}: no listed honest source explains it (§10 bounds this at 0)",
            s.unattributed_host_stricter()
        );
    }
    if s.classes.guest_stricter > 0 {
        println!(
            "GUEST STRICTER {}: the host would have allowed what the guest refused (§10 bounds this at 0)",
            s.classes.guest_stricter
        );
    }
    for u in &s.runs_unreadable {
        println!("unreadable: {u}");
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
                host,
                guest,
                coverage: _,
            } => println!(
                "{label}: pods {listening} (reported {reported}), agree {}, disagree {}, faults {}, unreported {}, guest telemetry on {} of {} consoles",
                tally.agree,
                tally.disagree,
                tally.faults,
                if host.pods_without_detail > 0 {
                    "not reported".to_string()
                } else {
                    host.unreported.to_string()
                },
                guest.consoles - guest.absent,
                guest.consoles
            ),
            Reading::NoShadow { guest } => println!(
                "{label}: no shadow channel (could not measure); guest-side not compared {}",
                guest.unavailable.total()
            ),
            Reading::CouldNotRead(why) => println!("{label}: COULD NOT READ — {why}"),
        }
    }
    let s = Summary::of(readings.iter().map(|(l, r)| (l.as_str(), r)));
    print_summary(&s);
    Ok(s.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_spec::host_decide_telemetry::HostUnavailable;

    fn files() -> Files {
        Files::standard()
    }

    fn listening(pod: &str) -> String {
        format!(
            r#"{{"timestamp":"t","level":"INFO","fields":{{"message":"{LISTENING}","pod":"{pod}"}},"target":"nucleus_node::host_decide"}}"#
        )
    }

    /// An older node's teardown line (run 37806146438's shape).
    fn legacy_teardown(agree: u64, disagree: u64, faults: u64) -> String {
        format!(
            r#"{{"timestamp":"t","level":"INFO","fields":{{"message":"{TEARDOWN_MESSAGE}","pod_dir":"/p","tally":"TallySnapshot {{ agree: {agree}, disagree: {disagree}, faults: {faults} }}"}},"target":"nucleus_node::pod_boot_identity"}}"#
        )
    }

    /// A node from S1 on: numeric counts, pairs and service time as JSON text.
    fn teardown(pairs: &[(&str, &str, &str, u64)], faults: u64, unreported: u64) -> String {
        let (mut agree, mut disagree) = (0, 0);
        let pairs: Vec<OutcomePair> = pairs
            .iter()
            .map(|(op, g, h, n)| {
                if g == h {
                    agree += n;
                } else {
                    disagree += n;
                }
                OutcomePair {
                    operation: (*op).into(),
                    guest: (*g).into(),
                    host: (*h).into(),
                    count: *n,
                }
            })
            .collect();
        let mut service = LatencyHistogram::default();
        for _ in 0..agree + disagree + unreported {
            service.record(std::time::Duration::from_micros(120));
        }
        let line = serde_json::json!({
            "timestamp": "t", "level": "INFO", "target": "nucleus_node::host_decide",
            "fields": {
                "message": TEARDOWN_MESSAGE, "pod_dir": "/p",
                "agree": agree, "disagree": disagree, "faults": faults,
                "unreported": unreported,
                "pairs": serde_json::to_string(&pairs).unwrap(),
                "service": serde_json::to_string(&service).unwrap(),
            }
        });
        line.to_string()
    }

    fn bundle(log: &str, disagreements: Option<&str>) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(&files().node_log), log).expect("write log");
        if let Some(d) = disagreements {
            std::fs::write(dir.path().join(&files().host_decide_disagreements), d)
                .expect("write record");
        }
        dir
    }

    fn console(dir: &Path, name: &str, text: &str) {
        std::fs::write(dir.join(name), text).expect("write console");
    }

    /// The shape an older bundle carries (run 37806146438): two pods, one
    /// compared, one faulted at teardown, stderr noise between. Its missing
    /// detail is reported as missing, not as zero.
    #[test]
    fn a_legacy_log_is_counted_and_its_missing_detail_is_named() {
        let log = [
            listening("a"),
            "iptables: Bad rule (does a matching rule exist in that chain?).".into(),
            legacy_teardown(1, 0, 0),
            listening("b"),
            legacy_teardown(0, 0, 1),
        ]
        .join("\n");
        let dir = bundle(&log, None);
        let r = read_bundle(dir.path());
        let Reading::Measured {
            listening,
            reported,
            tally,
            classes,
            host,
            guest,
            coverage,
        } = &r
        else {
            panic!("{r:?}")
        };
        assert_eq!((*listening, *reported), (2, 2));
        assert_eq!(
            *tally,
            Tally {
                agree: 1,
                disagree: 0,
                faults: 1
            }
        );
        assert_eq!(*classes, Classes::default());
        assert_eq!(host.pods_without_detail, 2);
        assert!(host.operations.is_empty());
        assert_eq!(guest.consoles, 0);
        assert_eq!(*coverage, Coverage::NotRun);
    }

    /// S1: a node's per-operation pairs, unreported Decides and service time
    /// are read, and the counts derive from the pairs.
    #[test]
    fn an_s1_teardown_is_read_by_operation() {
        let log = [
            listening("a"),
            teardown(
                &[
                    ("read_files", "allowed", "allowed", 3),
                    ("read_files", "denied:not_granted", "denied:not_granted", 1),
                    ("web_fetch", "allowed", "allowed", 1),
                ],
                0,
                1,
            ),
        ]
        .join("\n");
        let dir = bundle(&log, Some(""));
        let s = Summary::of([("run", &read_bundle(dir.path()))]);
        assert_eq!(s.compared(), 5);
        assert_eq!(s.host.pods_without_detail, 0);
        assert_eq!(s.host.unreported, 1);
        assert_eq!(s.host.operations["read_files"].compared(), 4);
        assert_eq!(s.host.operations["web_fetch"].agree(), 1);
        assert_eq!(s.host.service.count(), 6);
        assert_eq!(s.exit_code(), 0);
    }

    /// A-2: a tally this cannot parse makes the bundle unreadable. Reading it
    /// as zeros would turn a node that changed its spelling into a clean run.
    #[test]
    fn an_unparsable_tally_is_could_not_read_not_zero() {
        let bad = legacy_teardown(1, 0, 0).replace("agree: 1", "agree: one");
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
        // An S1 line whose pairs and counts disagree, or that lacks a field.
        let good = teardown(&[("read_files", "allowed", "allowed", 2)], 0, 0);
        for bad in [
            good.replace("\"agree\":2", "\"agree\":3"),
            good.replace(",\"unreported\":0", ""),
            good.replace("\"service\":", "\"servic\":"),
        ] {
            let dir = bundle(&[listening("a"), bad.clone()].join("\n"), None);
            assert!(
                matches!(read_bundle(dir.path()), Reading::CouldNotRead(_)),
                "{bad}"
            );
        }
    }

    /// A missing log is unreadable, not a run with no shadow.
    #[test]
    fn a_missing_log_is_could_not_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(matches!(read_bundle(dir.path()), Reading::CouldNotRead(_)));
    }

    /// A-5: a run that never opened a channel contributes nothing, and a corpus
    /// of them has no rate. This is what a node built with its shadow listener
    /// disabled leaves (ADR 0014 S1's falsifier): no listening line, no
    /// teardown, and a guest that counted every decision as `connect`.
    #[test]
    fn no_comparison_is_could_not_measure_not_full_agreement() {
        let dir = bundle(
            &legacy_teardown(0, 0, 0).replace(TEARDOWN_MESSAGE, "unrelated"),
            None,
        );
        let mut unreachable = UnavailableByKind::default();
        for _ in 0..3 {
            unreachable.count(HostUnavailable::Connect);
        }
        let t = GuestTelemetry::new(0, 0, unreachable, LatencyHistogram::default());
        console(dir.path(), &files().guest_console, &t.console_line());
        let r = read_bundle(dir.path());
        assert!(matches!(r, Reading::NoShadow { .. }), "{r:?}");
        let s = Summary::of([("run", &r)]);
        assert_eq!(s.rate_basis_points(), None);
        assert_eq!(s.guest.unavailable.connect, 3);
        assert_eq!(s.exit_code(), 2);
        // Faults alone compare nothing either.
        let dir = bundle(&[listening("a"), legacy_teardown(0, 0, 1)].join("\n"), None);
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
            &[listening("a"), listening("b"), legacy_teardown(3, 0, 0)].join("\n"),
            None,
        );
        let r = read_bundle(dir.path());
        let s = Summary::of([("run", &r)]);
        assert_eq!((s.listening, s.reported), (2, 1));
        assert_eq!(s.compared(), 3);
    }

    /// Disagreements are classified from the record; one without a record is
    /// unclassified rather than assigned a class, and reds the corpus.
    #[test]
    fn disagreements_are_classified_or_left_unclassified() {
        let records = [
            r#"{"guest":"allowed","host":"denied:flow_refused"}"#,
            r#"{"guest":"approval_required","host":"allowed"}"#,
            r#"{"guest":"denied:not_granted","host":"denied:budget_exhausted"}"#,
        ]
        .join("\n");
        let dir = bundle(
            &[listening("a"), legacy_teardown(10, 4, 0)].join("\n"),
            Some(&records),
        );
        let r = read_bundle(dir.path());
        let s = Summary::of([("run", &r)]);
        assert_eq!(
            s.classes,
            Classes {
                host_stricter: 1,
                host_taint: 1,
                guest_stricter: 1,
                differing_reason: 1
            }
        );
        assert_eq!(s.unclassified(), 1);
        assert_eq!(s.exit_code(), 1);
    }

    /// ADR 0014 S3: a host-stricter disagreement is attributed to the host's
    /// taint only for a flow refusal; any other is unattributed, and red.
    #[test]
    fn a_host_stricter_disagreement_is_red_unless_attributed() {
        let judged = |guest: &str, host: &str| {
            let log = [
                listening("a"),
                teardown(&[("write_files", guest, host, 1)], 0, 0),
            ]
            .join("\n");
            let record = format!(r#"{{"guest":"{guest}","host":"{host}"}}"#);
            let dir = bundle(&log, Some(&record));
            Summary::of([("run", &read_bundle(dir.path()))])
        };
        // S2's live finding, run 37835337702.
        let s = judged("approval_required", "denied:flow_refused");
        assert_eq!(
            (s.classes.host_taint, s.unattributed_host_stricter()),
            (1, 0)
        );
        assert_eq!(s.exit_code(), 0);

        let s = judged("allowed", "denied:not_granted");
        assert_eq!(
            (s.classes.host_taint, s.unattributed_host_stricter()),
            (0, 1)
        );
        assert_eq!(s.exit_code(), 1);
    }

    /// ADR 0014 §10 bounds guest-stricter at zero, so one is red on its own,
    /// with every disagreement classified. Live run 37833208274's coverage pod
    /// carried DLC labels the host did not read, and its six read as exit 0.
    #[test]
    fn a_guest_stricter_disagreement_is_red() {
        let judged = |guest: &str, host: &str| {
            let log = [
                listening("a"),
                teardown(
                    &[
                        ("read_files", "allowed", "allowed", 5),
                        ("glob_search", guest, host, 1),
                    ],
                    0,
                    0,
                ),
            ]
            .join("\n");
            let record = format!(r#"{{"guest":"{guest}","host":"{host}"}}"#);
            let dir = bundle(&log, Some(&record));
            Summary::of([("run", &read_bundle(dir.path()))])
        };
        let s = judged("denied:not_granted", "allowed");
        assert_eq!((s.classes.guest_stricter, s.unclassified()), (1, 0));
        assert_eq!(s.exit_code(), 1);

        let s = judged("allowed", "denied:flow_refused");
        assert_eq!((s.classes.host_stricter, s.unclassified()), (1, 0));
        assert_eq!(s.exit_code(), 0, "attributed host stricter is not red");
    }

    /// ADR 0014 S1's falsifier: a bundle whose tally says `disagree > 0` with
    /// its record file withheld is red; with the record restored it is green.
    #[test]
    fn a_withheld_record_reds_and_the_restored_record_greens() {
        let log = [
            listening("a"),
            teardown(
                &[
                    ("read_files", "allowed", "allowed", 5),
                    ("write_files", "allowed", "denied:flow_refused", 1),
                ],
                0,
                0,
            ),
        ]
        .join("\n");
        let withheld = bundle(&log, None);
        let s = Summary::of([("run", &read_bundle(withheld.path()))]);
        assert_eq!(s.unclassified(), 1);
        assert_eq!(s.exit_code(), 1, "a disagreement nobody can attribute");
        let restored = bundle(
            &log,
            Some(r#"{"guest":"allowed","host":"denied:flow_refused"}"#),
        );
        let s = Summary::of([("run", &read_bundle(restored.path()))]);
        assert_eq!(s.classes.host_stricter, 1);
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
            let dir = bundle(
                &[listening("a"), legacy_teardown(0, 1, 0)].join("\n"),
                Some(bad),
            );
            assert!(
                matches!(read_bundle(dir.path()), Reading::CouldNotRead(_)),
                "{bad}"
            );
        }
    }

    /// One unreadable bundle reds the whole corpus, whatever the others say.
    #[test]
    fn one_unreadable_bundle_reds_the_corpus() {
        let good = bundle(&[listening("a"), legacy_teardown(5, 0, 0)].join("\n"), None);
        let missing = tempfile::tempdir().expect("tempdir");
        let (g, m) = (read_bundle(good.path()), read_bundle(missing.path()));
        let s = Summary::of([("good", &g), ("missing", &m)]);
        assert_eq!(s.rate_basis_points(), Some(10_000));
        assert_eq!(s.exit_code(), 1);
    }

    /// A console without a telemetry line (a 2.4.0–2.7.0 guest) is "absent",
    /// counted apart from a guest that printed zeros; a printed line is summed
    /// with the others; a line that does not parse makes the bundle unreadable.
    #[test]
    fn guest_telemetry_is_read_absent_is_not_zero() {
        let log = [listening("a"), legacy_teardown(2, 0, 0)].join("\n");
        let dir = bundle(&log, None);
        console(dir.path(), &files().guest_console, "[ 0.1] booted\n");
        let mut kinds = UnavailableByKind::default();
        kinds.count(HostUnavailable::Timeout);
        let mut rt = LatencyHistogram::default();
        rt.record(std::time::Duration::from_micros(400));
        rt.record(std::time::Duration::from_micros(400));
        let t = GuestTelemetry::new(2, 0, kinds, rt);
        console(
            dir.path(),
            &files().effect_console,
            &format!("[ 0.1] booted\n[ 0.9] {}\n", t.console_line()),
        );
        let s = Summary::of([("run", &read_bundle(dir.path()))]);
        assert_eq!((s.guest.consoles, s.guest.absent), (2, 1));
        assert_eq!((s.guest.agree, s.guest.unavailable.timeout), (2, 1));
        assert_eq!(s.guest.round_trip.count(), 2);

        let none = bundle(&log, None);
        console(none.path(), &files().guest_console, "[ 0.1] booted\n");
        let s = Summary::of([("run", &read_bundle(none.path()))]);
        assert_eq!((s.guest.consoles, s.guest.absent), (1, 1));
        assert_eq!(s.guest.round_trip.count(), 0);

        let garbled = bundle(&log, None);
        console(
            garbled.path(),
            &files().guest_console,
            "NUCLEUS-HOST-DECIDE-TELEMETRY {\"agree\":1}\n",
        );
        assert!(matches!(
            read_bundle(garbled.path()),
            Reading::CouldNotRead(_)
        ));
    }

    fn every_operation(skip: &str) -> Vec<(&'static str, &'static str, &'static str, u64)> {
        coverage_names()
            .into_iter()
            .filter(|op| *op != skip)
            .flat_map(|op| {
                [
                    (op, "allowed", "allowed", 1),
                    (op, "denied:not_granted", "denied:not_granted", 1),
                ]
            })
            .collect()
    }

    /// ADR 0014 S2: a run with a coverage pod must compare every operation in
    /// the set at least once. One the traffic never reached reds, by name; a
    /// run without a coverage pod is "not run", not covered and not red.
    #[test]
    fn coverage_names_the_operation_a_run_never_compared() {
        let covered = bundle(
            &[listening("a"), teardown(&every_operation(""), 0, 0)].join("\n"),
            Some(""),
        );
        std::fs::write(covered.path().join(&files().coverage_calls), "[]").unwrap();
        let s = Summary::of([("run", &read_bundle(covered.path()))]);
        assert_eq!((s.coverage_checked, s.coverage_missing.len()), (1, 0));
        assert_eq!(s.exit_code(), 0);

        let no_glob = bundle(
            &[
                listening("a"),
                teardown(&every_operation("glob_search"), 0, 0),
            ]
            .join("\n"),
            Some(""),
        );
        std::fs::write(no_glob.path().join(&files().coverage_calls), "[]").unwrap();
        let s = Summary::of([("run", &read_bundle(no_glob.path()))]);
        assert_eq!(s.coverage_missing, vec!["run: glob_search".to_string()]);
        assert_eq!(s.exit_code(), 1);

        let before_s2 = bundle(
            &[
                listening("a"),
                teardown(&every_operation("glob_search"), 0, 0),
            ]
            .join("\n"),
            Some(""),
        );
        let s = Summary::of([("run", &read_bundle(before_s2.path()))]);
        assert_eq!((s.coverage_checked, s.exit_code()), (0, 0));
    }
}
