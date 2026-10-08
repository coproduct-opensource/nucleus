//! `cargo xtask egress-census` — what network egress do live-boot pods make
//! today, and through which path? (ADR 0015, milestone M4, #2698 / #2702.)
//!
//! ADR 0015 moves mediated-set rows 5 (in-shell egress), 6 (DNS) and 10 (netns
//! raw socket) behind one host egress proxy. Its latency budget and its refusal
//! defaults have to be argued from what pods actually send, so this reads that
//! from what live boots already leave behind: each `live-boot-evidence` bundle
//! (`quickstart-boot.yml`, artifact `live-boot-evidence-x86_64`) carries
//!
//! * `spec.json`: the execution pod's admitted spec, read as a
//!   [`nucleus_spec::PodSpec`] (ADR 0007 F-2: the one `Deserialize`, not a
//!   restated shape), for what the pod DECLARED;
//! * `guest-console.log`: the guest kernel's command line (the resolver the
//!   guest was told) and the probes' lines, for what the guest ATTEMPTED
//!   directly and what came of it;
//! * `host-effects.jsonl`: the host's signed authorization journal, for egress
//!   the HOST performed for the pod;
//!
//! and, since E1 (ADR 0015's first step):
//!
//! * `fence-execution.iptables` and `fence-effect.iptables`: each pod's filter
//!   table with its packet counters, snapshotted before teardown and read by
//!   [`nucleus_spec::egress_fence::read`]: what the fence dropped by class of
//!   destination, what it accepted, and the DNS packets the guest sent;
//! * `effect-console.log`: the credentialed pod's guest console;
//! * `eval-cell.json` ([`EvalCellRun`]), `eval-cell-spec.json`,
//!   `eval-cell-console.log` and `fence-eval-cell.iptables`: the honest eval
//!   cell, or the node's refusal of it.
//!
//! # What this refuses to do (ADR 0007 A)
//!
//! * A bundle missing any of the first three files, or holding a file this
//!   cannot parse (a counter snapshot of a shape [`egress_fence::read`] does not
//!   know included), is `could not read` (A-2) — never a pod that made no
//!   egress.
//! * An E1 measurement whose file is withheld, an eval cell the node refused,
//!   or an "eval cell" whose spec is not labelled one, is `could not measure`
//!   for that run, named with its reason, and never read as zero packets.
//! * A console with no egress-probe verdict is `probe absent`, and contributes
//!   no attempts (A-5): the absence of a refusal line is not a refusal.
//! * A destination the probe reached is `reached`, whatever else the console
//!   says about it; a refusal is recorded with the kernel's own reason, never
//!   folded into one "blocked".
//!
//! Usage: download the bundles (`gh run download <run> -n
//! live-boot-evidence-x86_64 -D <dir>/<run>`), then `cargo xtask egress-census
//! <dir>/<run>...`. Each directory is one run, labelled by its name. Exit
//! status: 0 when every bundle was read and every measurement made; 2 when no
//! bundle was read, or any read bundle could not measure something; otherwise
//! 1 when any bundle could not be read.

use anyhow::{Context, Result, bail};
use nucleus_spec::PodSpec;
use nucleus_spec::egress_fence::{self, FenceCounters};
use nucleus_spec::isolation_profile::IsolationProfile;
use nucleus_spec::live_boot::{EvalCellRun, Files};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The journal's name, for error messages.
const HOST_EFFECTS: &str = "host-effects.jsonl";

/// `nucleus-egress-probe`'s lines (`crates/nucleus-egress-probe/src/main.rs`).
const DENIED_CONNECT: &str = "NUCLEUS_EGRESS_CHECK: denied-connect ";
const PROBE_VERDICT: &str = "NUCLEUS_EGRESS_PROBE: ";
const PROBE_REACHED: &str = "SUCCEEDED";
/// `nucleus-adversary-probe`'s exfiltration stage.
const EXFIL_STAGE: &str = "NUCLEUS_ADVERSARY_STAGE exfil: ";

/// What a direct connect from the guest came to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Attempt {
    /// The connect failed, with the kernel's reason as the probe printed it
    /// (`connection timed out` is the fence's DROP; `Network is unreachable`
    /// would be no route).
    Refused(String),
    /// The connect succeeded: the fence did not hold for this destination.
    Reached,
}

/// What the egress probe left on the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// No `NUCLEUS_EGRESS_PROBE:` verdict at all: nothing is known.
    Absent,
    /// The probe ran; each destination it tried, once.
    Ran(BTreeMap<String, Attempt>),
}

/// One host-performed effect, from the host's journal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostEgress {
    pub operation: String,
    /// `scheme://host[:port]`, the path dropped.
    pub origin: String,
}

/// What a pod's spec declares it may reach. Named fields, not a tuple (ADR 0007 E-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Declared {
    /// `network.allow` entries.
    pub allow: usize,
    /// `network.dns_allow` entries.
    pub dns_allow: usize,
    /// `credentialed_egress` upstreams.
    pub credentialed: usize,
}

impl Declared {
    fn add(&mut self, other: Declared) {
        self.allow += other.allow;
        self.dns_allow += other.dns_allow;
        self.credentialed += other.credentialed;
    }
}

/// An E1 measurement, or why this run could not make it. Never a zero standing
/// in for "not recorded" (ADR 0007 A-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Measure<T> {
    Measured(T),
    CouldNotMeasure(String),
}

impl<T> Measure<T> {
    fn get(&self) -> Option<&T> {
        match self {
            Measure::Measured(t) => Some(t),
            Measure::CouldNotMeasure(_) => None,
        }
    }

    fn why(&self) -> Option<&str> {
        match self {
            Measure::Measured(_) => None,
            Measure::CouldNotMeasure(why) => Some(why),
        }
    }
}

/// What the credentialed pod's guest console says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectGuest {
    pub resolver: Option<String>,
    pub probe: Probe,
}

/// The honest eval cell, admitted and measured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalCell {
    pub resolver: Option<String>,
    pub exit_code: Option<i32>,
    pub fence: FenceCounters,
}

/// One run's census.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Census {
    pub profile: IsolationProfile,
    pub declared: Declared,
    /// The `dns=` the guest kernel was told, or `None` when the command line
    /// carries no `nucleus.net`.
    pub resolver: Option<String>,
    pub probe: Probe,
    /// The adversary probe's exfiltration stage line, verbatim after the tag.
    pub exfil: Option<String>,
    pub host: Vec<HostEgress>,
    /// The execution pod's fence counters.
    pub fence_execution: Measure<FenceCounters>,
    /// The credentialed (effect) pod's fence counters.
    pub fence_effect: Measure<FenceCounters>,
    /// The credentialed pod's guest.
    pub effect_guest: Measure<EffectGuest>,
    /// The eval cell.
    pub eval_cell: Measure<EvalCell>,
}

impl Census {
    /// Every measurement this run could not make, by name.
    pub fn could_not_measure(&self) -> Vec<(&'static str, &str)> {
        [
            ("execution pod's fence counters", self.fence_execution.why()),
            ("credentialed pod's fence counters", self.fence_effect.why()),
            ("credentialed pod's guest", self.effect_guest.why()),
            ("eval cell", self.eval_cell.why()),
        ]
        .into_iter()
        .filter_map(|(what, why)| why.map(|why| (what, why)))
        .collect()
    }
}

#[derive(Deserialize)]
struct Signed {
    authorization: Authorization,
}

#[derive(Deserialize)]
struct Authorization {
    operation: String,
    subject: String,
}

/// The origin of a URL: everything before the first `/` after `://`.
fn origin(subject: &str) -> Result<String> {
    let (scheme, rest) = subject
        .split_once("://")
        .with_context(|| format!("host-effect subject is not a URL: {subject:?}"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if scheme.is_empty() || authority.is_empty() {
        bail!("host-effect subject has no origin: {subject:?}");
    }
    Ok(format!("{scheme}://{authority}"))
}

/// Read the host journal. Every line must parse.
pub fn read_host_effects(text: &str) -> Result<Vec<HostEgress>> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let signed: Signed = serde_json::from_str(line)
            .with_context(|| format!("{HOST_EFFECTS} line {} does not parse", n + 1))?;
        out.push(HostEgress {
            operation: signed.authorization.operation,
            origin: origin(&signed.authorization.subject)?,
        });
    }
    Ok(out)
}

/// Read the console: the resolver, the probe's attempts and the exfil stage.
pub fn read_console(text: &str) -> Result<(Option<String>, Probe, Option<String>)> {
    let resolver = text
        .lines()
        .find_map(|l| l.split_once("Command line: ").map(|(_, c)| c))
        .and_then(|cmdline| {
            cmdline
                .split_whitespace()
                .find_map(|arg| arg.strip_prefix("nucleus.net="))
        })
        .map(|net| {
            net.split(',')
                .find_map(|kv| kv.strip_prefix("dns="))
                .map(str::to_string)
                .with_context(|| format!("nucleus.net carries no dns=: {net:?}"))
        })
        .transpose()?;

    let mut verdict = false;
    let mut attempts: BTreeMap<String, Attempt> = BTreeMap::new();
    let mut exfil = None;
    for line in text.lines() {
        if let Some((_, rest)) = line.split_once(DENIED_CONNECT) {
            // `<addr> REFUSED (<reason>) (ok)`: exactly that shape, or the
            // bundle is unreadable (I-2) — a reworded line must not read as
            // a refusal.
            let (addr, tail) = rest
                .split_once(" REFUSED (")
                .with_context(|| format!("denied-connect line has no REFUSED: {line:?}"))?;
            let reason = tail
                .strip_suffix(") (ok)")
                .with_context(|| format!("denied-connect line is not `(…) (ok)`: {line:?}"))?;
            // Reached is never overwritten by a refusal of the same address.
            attempts
                .entry(addr.to_string())
                .or_insert_with(|| Attempt::Refused(reason.to_string()));
        }
        if let Some((_, rest)) = line.split_once(PROBE_VERDICT) {
            verdict = true;
            // `FAIL: … egress to <addr> SUCCEEDED …`
            if let Some((_, after)) = rest.split_once("egress to ")
                && let Some((addr, _)) = after.split_once(&format!(" {PROBE_REACHED}"))
            {
                attempts.insert(addr.to_string(), Attempt::Reached);
            }
        }
        if exfil.is_none()
            && let Some((_, rest)) = line.split_once(EXFIL_STAGE)
        {
            exfil = Some(rest.trim().to_string());
        }
    }
    let probe = if verdict {
        Probe::Ran(attempts)
    } else {
        Probe::Absent
    };
    Ok((resolver, probe, exfil))
}

fn read_file(dir: &Path, name: &str) -> Result<String> {
    let path = dir.join(name);
    std::fs::read_to_string(&path).with_context(|| format!("cannot read {}", path.display()))
}

/// A file an E1 measurement needs: `None` when the bundle does not hold it
/// (withheld, or from before E1), an error when it is there and cannot be read.
fn optional_file(dir: &Path, name: &str) -> Result<Option<String>> {
    let path = dir.join(name);
    match std::fs::read_to_string(&path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

fn withheld(name: &str) -> String {
    format!("{name} is not in the bundle")
}

/// A pod's fence counters: withheld is could-not-measure, unparseable is an error.
fn read_fence(dir: &Path, name: &str) -> Result<Measure<FenceCounters>> {
    Ok(match optional_file(dir, name)? {
        None => Measure::CouldNotMeasure(withheld(name)),
        Some(text) => {
            Measure::Measured(egress_fence::read(&text).with_context(|| name.to_string())?)
        }
    })
}

fn read_spec(text: &str, name: &str) -> Result<PodSpec> {
    serde_json::from_str(text).with_context(|| format!("{name} is not a PodSpec"))
}

/// The eval cell: its outcome, then (when admitted) its spec, console and fence.
fn read_eval_cell(dir: &Path, files: &Files) -> Result<Measure<EvalCell>> {
    let Some(text) = optional_file(dir, &files.eval_cell)? else {
        return Ok(Measure::CouldNotMeasure(withheld(&files.eval_cell)));
    };
    let run: EvalCellRun = serde_json::from_str(&text)
        .with_context(|| format!("{} is not an eval-cell run", files.eval_cell))?;
    let exit_code = match run {
        EvalCellRun::Refused { status, reason } => {
            return Ok(Measure::CouldNotMeasure(format!(
                "the node refused the eval cell (HTTP {status}): {}",
                reason.trim()
            )));
        }
        EvalCellRun::Admitted { pod: _, exit_code } => exit_code,
    };
    let Some(spec) = optional_file(dir, &files.eval_cell_spec)? else {
        return Ok(Measure::CouldNotMeasure(withheld(&files.eval_cell_spec)));
    };
    let profile = IsolationProfile::of(&read_spec(&spec, &files.eval_cell_spec)?)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    match profile {
        IsolationProfile::EvalCell => {}
        IsolationProfile::Standard => {
            return Ok(Measure::CouldNotMeasure(format!(
                "{} is labelled {profile}, so the pod it ran is not an eval cell",
                files.eval_cell_spec
            )));
        }
    }
    let Some(console) = optional_file(dir, &files.eval_cell_console)? else {
        return Ok(Measure::CouldNotMeasure(withheld(&files.eval_cell_console)));
    };
    let (resolver, _, _) = read_console(&console)?;
    Ok(match read_fence(dir, &files.fence_eval_cell)? {
        Measure::CouldNotMeasure(why) => Measure::CouldNotMeasure(why),
        Measure::Measured(fence) => Measure::Measured(EvalCell {
            resolver,
            exit_code,
            fence,
        }),
    })
}

/// One bundle's census, or why it could not be read.
pub fn read_bundle(dir: &Path) -> Result<Census> {
    let files = Files::standard();
    let spec = read_spec(&read_file(dir, &files.spec)?, &files.spec)?;
    let profile = IsolationProfile::of(&spec).map_err(|e| anyhow::anyhow!("{e}"))?;
    let network = spec.spec.network.as_ref();
    let declared = Declared {
        allow: network.map_or(0, |n| n.allow.len()),
        dns_allow: network.map_or(0, |n| n.dns_allow.len()),
        credentialed: spec.spec.credentialed_egress.len(),
    };
    let (resolver, probe, exfil) = read_console(&read_file(dir, &files.guest_console)?)?;
    let host = read_host_effects(&read_file(dir, &files.host_effects)?)?;
    let effect_guest = match optional_file(dir, &files.effect_console)? {
        None => Measure::CouldNotMeasure(withheld(&files.effect_console)),
        Some(text) => {
            let (resolver, probe, _) =
                read_console(&text).with_context(|| files.effect_console.clone())?;
            Measure::Measured(EffectGuest { resolver, probe })
        }
    };
    Ok(Census {
        profile,
        declared,
        resolver,
        probe,
        exfil,
        host,
        fence_execution: read_fence(dir, &files.fence_execution)?,
        fence_effect: read_fence(dir, &files.fence_effect)?,
        effect_guest,
        eval_cell: read_eval_cell(dir, &files)?,
    })
}

/// The exit status: 2 when nothing was read or anything read could not be
/// measured, else 1 when any bundle could not be read, else 0. "Could not
/// measure" is never 0 (ADR 0015 E1).
pub fn status(read: &[(String, Census)], unreadable: &[(String, String)]) -> i32 {
    if read.is_empty() || read.iter().any(|(_, c)| !c.could_not_measure().is_empty()) {
        2
    } else if unreadable.is_empty() {
        0
    } else {
        1
    }
}

/// Read every bundle, print the census, and return the exit status.
pub fn run(bundles: &[PathBuf]) -> Result<i32> {
    let mut read: Vec<(String, Census)> = Vec::new();
    let mut unreadable: Vec<(String, String)> = Vec::new();
    for dir in bundles {
        let label = dir
            .file_name()
            .map_or_else(|| dir.display().to_string(), |n| n.to_string_lossy().into());
        match read_bundle(dir) {
            Ok(c) => read.push((label, c)),
            Err(e) => unreadable.push((label, format!("{e:#}"))),
        }
    }
    print!("{}", render(&read, &unreadable));
    Ok(status(&read, &unreadable))
}

/// The report. A pure function of what was read, so the tests pin it.
pub fn render(read: &[(String, Census)], unreadable: &[(String, String)]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "bundles read: {}   could not read: {}",
        read.len(),
        unreadable.len()
    );
    for (label, why) in unreadable {
        let _ = writeln!(out, "  could not read {label}: {why}");
    }
    let mut profiles: BTreeMap<&str, usize> = BTreeMap::new();
    let mut declared = Declared::default();
    let mut resolvers: BTreeMap<String, usize> = BTreeMap::new();
    let mut probe_absent = 0usize;
    let mut attempts: BTreeMap<(String, Attempt), usize> = BTreeMap::new();
    let mut exfil: BTreeMap<String, usize> = BTreeMap::new();
    let mut host: BTreeMap<HostEgress, usize> = BTreeMap::new();
    for (_, c) in read {
        *profiles.entry(c.profile.name()).or_default() += 1;
        declared.add(c.declared);
        *resolvers
            .entry(
                c.resolver
                    .clone()
                    .unwrap_or_else(|| "(no nucleus.net)".into()),
            )
            .or_default() += 1;
        match &c.probe {
            Probe::Absent => probe_absent += 1,
            Probe::Ran(map) => {
                for (addr, a) in map {
                    *attempts.entry((addr.clone(), a.clone())).or_default() += 1;
                }
            }
        }
        *exfil
            .entry(c.exfil.clone().unwrap_or_else(|| "(no exfil stage)".into()))
            .or_default() += 1;
        for h in &c.host {
            *host.entry(h.clone()).or_default() += 1;
        }
    }
    let _ = writeln!(out, "execution pod profile: {profiles:?}");
    let _ = writeln!(
        out,
        "declared egress (summed over runs): network.allow {}, network.dns_allow {}, credentialed upstreams {}",
        declared.allow, declared.dns_allow, declared.credentialed
    );
    let _ = writeln!(out, "resolver the guest was told (runs): {resolvers:?}");
    let _ = writeln!(
        out,
        "direct connects from the guest (egress probe; runs where the probe left no verdict: {probe_absent}):"
    );
    for ((addr, a), n) in &attempts {
        let what = match a {
            Attempt::Refused(reason) => format!("refused ({reason})"),
            Attempt::Reached => "REACHED".to_string(),
        };
        let _ = writeln!(out, "  {addr:<22} {what:<40} runs {n}");
    }
    let _ = writeln!(out, "adversary probe exfil stage (runs): {exfil:?}");
    let _ = writeln!(out, "host-performed egress (host journal, effects):");
    for (h, n) in &host {
        let _ = writeln!(out, "  {:<10} {:<32} {n}", h.operation, h.origin);
    }
    render_fences(&mut out, read);
    render_effect_guest(&mut out, read);
    render_eval_cells(&mut out, read);
    let missing: Vec<_> = read
        .iter()
        .flat_map(|(label, c)| {
            c.could_not_measure()
                .into_iter()
                .map(move |(what, why)| (label, what, why))
        })
        .collect();
    let _ = writeln!(out, "could not measure: {}", missing.len());
    for (label, what, why) in missing {
        let _ = writeln!(out, "  could not measure {label}: {what}: {why}");
    }
    let _ = writeln!(
        out,
        "not measured by this reader: latency and throughput of any egress path (ADR 0015 E2)"
    );
    out
}

/// One line of a fence's counters.
fn fence_line(f: &FenceCounters) -> String {
    let FenceCounters {
        dns,
        dropped,
        accepted,
    } = f;
    format!(
        "dropped {} (floor {}, spec deny {}, unlisted {}, into namespace {}); \
         accepted listed {}, resolver {}, established {}; dns sent udp {}, tcp {}",
        f.dropped_total(),
        dropped.floor,
        dropped.spec_deny,
        dropped.unlisted,
        dropped.into_namespace,
        accepted.listed,
        accepted.resolver,
        accepted.established,
        dns.udp,
        dns.tcp
    )
}

/// The fence counters per pod, summed over the runs that measured them, and
/// each run's dropped packets.
fn render_fences(out: &mut String, read: &[(String, Census)]) {
    use std::fmt::Write as _;
    let _ = writeln!(
        out,
        "fence counters (guest traffic: FORWARD and INPUT; summed over the runs that measured them):"
    );
    type Pick = fn(&Census) -> Option<&FenceCounters>;
    let pods: [(&str, Pick); 3] = [
        ("execution pod", |c| c.fence_execution.get()),
        ("credentialed pod", |c| c.fence_effect.get()),
        ("eval cell", |c| c.eval_cell.get().map(|e| &e.fence)),
    ];
    for (name, pick) in pods {
        let mut sum = FenceCounters::none();
        let mut runs = 0usize;
        for f in read.iter().filter_map(|(_, c)| pick(c)) {
            sum.add(f);
            runs += 1;
        }
        if runs == 0 {
            let _ = writeln!(out, "  {name:<16} measured in 0 of {} runs", read.len());
        } else {
            let _ = writeln!(
                out,
                "  {name:<16} measured in {runs} of {} runs: {}",
                read.len(),
                fence_line(&sum)
            );
        }
    }
    let _ = writeln!(
        out,
        "dropped packets per run (execution / credentialed / eval cell):"
    );
    for (label, c) in read {
        let cell = |f: Option<&FenceCounters>| {
            f.map_or_else(
                || "-".to_string(),
                |f| f.dropped_total().packets.to_string(),
            )
        };
        let _ = writeln!(
            out,
            "  {label:<24} {} / {} / {}",
            cell(pods[0].1(c)),
            cell(pods[1].1(c)),
            cell(pods[2].1(c))
        );
    }
}

fn render_effect_guest(out: &mut String, read: &[(String, Census)]) {
    use std::fmt::Write as _;
    let mut resolvers: BTreeMap<String, usize> = BTreeMap::new();
    let mut probe_ran = 0usize;
    let mut runs = 0usize;
    for g in read.iter().filter_map(|(_, c)| c.effect_guest.get()) {
        runs += 1;
        *resolvers
            .entry(
                g.resolver
                    .clone()
                    .unwrap_or_else(|| "(no nucleus.net)".into()),
            )
            .or_default() += 1;
        match g.probe {
            Probe::Absent => {}
            Probe::Ran(_) => probe_ran += 1,
        }
    }
    let _ = writeln!(
        out,
        "credentialed pod's guest (console read in {runs} of {} runs): resolver {resolvers:?}, egress probe ran in {probe_ran}",
        read.len()
    );
}

fn render_eval_cells(out: &mut String, read: &[(String, Census)]) {
    use std::fmt::Write as _;
    let mut exits: BTreeMap<String, usize> = BTreeMap::new();
    let mut resolvers: BTreeMap<String, usize> = BTreeMap::new();
    for e in read.iter().filter_map(|(_, c)| c.eval_cell.get()) {
        *exits
            .entry(
                e.exit_code
                    .map_or_else(|| "no exit code".into(), |c| c.to_string()),
            )
            .or_default() += 1;
        *resolvers
            .entry(
                e.resolver
                    .clone()
                    .unwrap_or_else(|| "(no nucleus.net)".into()),
            )
            .or_default() += 1;
    }
    let runs: usize = exits.values().sum();
    let _ = writeln!(
        out,
        "eval cell admitted and measured in {runs} of {} runs: exit codes {exits:?}, resolver {resolvers:?}",
        read.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    const CMDLINE: &str = "[    0.000000] Command line: console=ttyS0 nucleus.net=192.168.241.2/30,gw=192.168.241.1,dns=1.1.1.1 ipv6.disable=1\n";

    #[test]
    fn a_refusal_is_recorded_with_its_reason_once_per_destination() {
        let console = format!(
            "{CMDLINE}NUCLEUS_EGRESS_CHECK: denied-connect 1.1.1.1:443 REFUSED (connection timed out) (ok)\n\
             [    1.4] [workload] NUCLEUS_EGRESS_CHECK: denied-connect 1.1.1.1:443 REFUSED (connection timed out) (ok)\n\
             NUCLEUS_EGRESS_PROBE: PASS\n"
        );
        let (resolver, probe, _) = read_console(&console).unwrap();
        assert_eq!(resolver.as_deref(), Some("1.1.1.1"));
        let Probe::Ran(map) = probe else {
            panic!("probe ran")
        };
        assert_eq!(map.len(), 1, "a line printed twice is one attempt");
        assert_eq!(
            map["1.1.1.1:443"],
            Attempt::Refused("connection timed out".into())
        );
    }

    #[test]
    fn a_reached_destination_is_never_read_as_refused() {
        let console = format!(
            "{CMDLINE}NUCLEUS_EGRESS_CHECK: denied-connect 8.8.8.8:53 REFUSED (connection timed out) (ok)\n\
             NUCLEUS_EGRESS_PROBE: FAIL: egress to 1.1.1.1:443 SUCCEEDED — the netns default-deny OUTPUT policy is NOT applied\n\
             NUCLEUS_EGRESS_CHECK: denied-connect 1.1.1.1:443 REFUSED (connection timed out) (ok)\n"
        );
        let (_, probe, _) = read_console(&console).unwrap();
        let Probe::Ran(map) = probe else {
            panic!("probe ran")
        };
        assert_eq!(map["1.1.1.1:443"], Attempt::Reached);
    }

    #[test]
    fn no_probe_verdict_is_absent_not_zero_attempts() {
        let (_, probe, _) = read_console(CMDLINE).unwrap();
        assert_eq!(probe, Probe::Absent);
    }

    #[test]
    fn a_reworded_refusal_line_is_unreadable() {
        let console = format!(
            "{CMDLINE}NUCLEUS_EGRESS_CHECK: denied-connect 1.1.1.1:443 BLOCKED\nNUCLEUS_EGRESS_PROBE: PASS\n"
        );
        assert!(read_console(&console).is_err());
    }

    #[test]
    fn a_host_journal_line_that_does_not_parse_is_unreadable() {
        let good = r#"{"authorization":{"operation":"web_fetch","subject":"http://127.0.0.1:38941/echo"},"signature":"00"}"#;
        assert_eq!(
            read_host_effects(good).unwrap(),
            vec![HostEgress {
                operation: "web_fetch".into(),
                origin: "http://127.0.0.1:38941".into()
            }]
        );
        assert!(read_host_effects(&format!("{good}\n{{\"torn\":")).is_err());
        assert!(
            read_host_effects(r#"{"authorization":{"operation":"x","subject":"nourl"}}"#).is_err()
        );
    }

    #[test]
    fn a_missing_file_is_could_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let err = read_bundle(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("cannot read"), "{err:#}");
        assert_eq!(run(&[dir.path().to_path_buf()]).unwrap(), 2);
    }

    #[test]
    fn the_report_names_what_it_could_not_measure() {
        let dir = tempfile::tempdir().unwrap();
        let run_dir = dir.path().join("run-1");
        bundle(&run_dir);
        for name in [
            &files().fence_execution,
            &files().effect_console,
            &files().eval_cell,
        ] {
            std::fs::remove_file(run_dir.join(name)).unwrap();
        }
        let census = read_bundle(&run_dir).unwrap();
        let report = render(&[("run-1".into(), census)], &[]);
        assert!(report.contains("could not measure: 3"), "{report}");
        assert!(
            report.contains("could not measure run-1: execution pod's fence counters"),
            "{report}"
        );
        assert!(
            report.contains("could not measure run-1: eval cell"),
            "{report}"
        );
        assert!(report.contains("not measured by this reader: latency"));
    }

    fn files() -> Files {
        Files::standard()
    }

    /// A fence as the node writes it: the probe's two connects and three DNS
    /// packets dropped as unlisted.
    const FENCE: &str = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [5:300]\n:OUTPUT DROP [0:0]\n\
        [3:180] -A FORWARD -p udp -m udp --dport 53 -m comment --comment \"nucleus-fence:dns-udp\"\n\
        [1:60] -A FORWARD -p tcp -m tcp --dport 53 -m comment --comment \"nucleus-fence:dns-tcp\"\n\
        [0:0] -A FORWARD -d 169.254.0.0/16 -m comment --comment \"nucleus-fence:floor\" -j DROP\n\
        COMMIT\n";

    fn spec(profile: Option<&str>) -> String {
        let labels = profile.map_or_else(String::new, |p| {
            format!(
                r#","metadata":{{"labels":{{"{}":"{p}"}}}}"#,
                nucleus_spec::isolation_profile::PROFILE_LABEL
            )
        });
        format!(
            r#"{{"apiVersion":"nucleus/v1","kind":"Pod"{labels},"spec":{{"network":{{"allow":[],"deny":[]}}}}}}"#
        )
    }

    /// A whole E1 bundle in `dir`, every measurement present.
    fn bundle(dir: &Path) {
        let f = files();
        std::fs::create_dir_all(dir).unwrap();
        let console = format!(
            "{CMDLINE}NUCLEUS_EGRESS_CHECK: denied-connect 1.1.1.1:443 REFUSED (connection timed out) (ok)\nNUCLEUS_EGRESS_PROBE: PASS\n"
        );
        let run = EvalCellRun::Admitted {
            pod: "p".into(),
            exit_code: Some(0),
        };
        for (name, body) in [
            (&f.spec, spec(None)),
            (&f.guest_console, console),
            (&f.host_effects, String::new()),
            (&f.fence_execution, FENCE.into()),
            (&f.fence_effect, FENCE.into()),
            (&f.effect_console, CMDLINE.into()),
            (&f.eval_cell, serde_json::to_string(&run).unwrap()),
            (&f.eval_cell_spec, spec(Some("eval-cell"))),
            (&f.eval_cell_console, CMDLINE.into()),
            (&f.fence_eval_cell, FENCE.into()),
        ] {
            std::fs::write(dir.join(name), body).unwrap();
        }
    }

    fn census_of(dir: &Path) -> (Census, i32) {
        let census = read_bundle(dir).unwrap();
        let code = run(&[dir.to_path_buf()]).unwrap();
        (census, code)
    }

    #[test]
    fn a_whole_bundle_measures_every_pod_and_exits_zero() {
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path());
        let (census, code) = census_of(dir.path());
        assert_eq!(census.could_not_measure(), vec![]);
        let fence = census.fence_execution.get().unwrap();
        assert_eq!(fence.dropped.unlisted.packets, 5);
        assert_eq!(fence.dns.udp.packets, 3);
        assert_eq!(
            census
                .eval_cell
                .get()
                .unwrap()
                .fence
                .dropped_total()
                .packets,
            5
        );
        assert_eq!(code, 0);
    }

    /// ADR 0015 E1's red: a withheld counter file is "could not measure" and
    /// exit 2, never a fence that dropped nothing.
    #[test]
    fn a_withheld_counter_file_is_could_not_measure_never_zero_drops() {
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path());
        std::fs::remove_file(dir.path().join(&files().fence_execution)).unwrap();
        let (census, code) = census_of(dir.path());
        assert_eq!(
            census.fence_execution,
            Measure::CouldNotMeasure("fence-execution.iptables is not in the bundle".into())
        );
        assert_eq!(code, 2);
        let report = render(&[("r".into(), census)], &[]);
        assert!(
            report
                .lines()
                .any(|l| l.trim_start().starts_with("r ") && l.ends_with(" - / 5 / 5")),
            "the run's execution drops print as -, not 0: {report}"
        );
    }

    #[test]
    fn a_counter_file_of_an_unknown_shape_is_could_not_read() {
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path());
        let untagged = FENCE.replace(" -m comment --comment \"nucleus-fence:floor\"", "");
        std::fs::write(dir.path().join(&files().fence_effect), untagged).unwrap();
        let err = read_bundle(dir.path()).unwrap_err();
        assert!(format!("{err:#}").contains("no fence tag"), "{err:#}");
    }

    #[test]
    fn a_refused_or_mislabelled_eval_cell_is_could_not_measure() {
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path());
        let refused = EvalCellRun::Refused {
            status: 400,
            reason: "the node is not attested".into(),
        };
        std::fs::write(
            dir.path().join(&files().eval_cell),
            serde_json::to_string(&refused).unwrap(),
        )
        .unwrap();
        let (census, code) = census_of(dir.path());
        assert_eq!(
            census.eval_cell,
            Measure::CouldNotMeasure(
                "the node refused the eval cell (HTTP 400): the node is not attested".into()
            )
        );
        assert_eq!(code, 2);

        bundle(dir.path());
        std::fs::write(dir.path().join(&files().eval_cell_spec), spec(None)).unwrap();
        let (census, code) = census_of(dir.path());
        assert!(
            census
                .eval_cell
                .why()
                .is_some_and(|w| w.contains("not an eval cell")),
            "{:?}",
            census.eval_cell
        );
        assert_eq!(code, 2);
    }

    #[test]
    fn a_withheld_credentialed_console_is_could_not_measure() {
        let dir = tempfile::tempdir().unwrap();
        bundle(dir.path());
        std::fs::remove_file(dir.path().join(&files().effect_console)).unwrap();
        let (census, code) = census_of(dir.path());
        assert!(census.effect_guest.why().is_some());
        assert_eq!(code, 2);
    }
}
