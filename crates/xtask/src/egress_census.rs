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
//!   the HOST performed for the pod.
//!
//! # What this refuses to do (ADR 0007 A)
//!
//! * A bundle missing any of those three files, or holding a line this cannot
//!   parse, is `could not read` (A-2) — never a pod that made no egress.
//! * A console with no egress-probe verdict is `probe absent`, and contributes
//!   no attempts (A-5): the absence of a refusal line is not a refusal.
//! * A destination the probe reached is `reached`, whatever else the console
//!   says about it; a refusal is recorded with the kernel's own reason, never
//!   folded into one "blocked".
//! * What no artifact records (DNS queries, packets the fence dropped, the
//!   credentialed pod's own guest) is printed as "could not measure", every
//!   run, so a reader of the output cannot take silence for zero.
//!
//! Usage: download the bundles (`gh run download <run> -n
//! live-boot-evidence-x86_64 -D <dir>/<run>`), then `cargo xtask egress-census
//! <dir>/<run>...`. Each directory is one run, labelled by its name. Exit
//! status: 0 when every bundle was read; 1 when any bundle could not be read;
//! 2 when no bundle was read at all.

use anyhow::{Context, Result, bail};
use nucleus_spec::PodSpec;
use nucleus_spec::isolation_profile::IsolationProfile;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The bundle's file names (`live_boot_evidence`'s `collection.json` `files`).
const SPEC: &str = "spec.json";
const CONSOLE: &str = "guest-console.log";
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

/// One bundle's census, or why it could not be read.
pub fn read_bundle(dir: &Path) -> Result<Census> {
    let spec: PodSpec = serde_json::from_str(&read_file(dir, SPEC)?)
        .with_context(|| format!("{SPEC} is not a PodSpec"))?;
    let profile = IsolationProfile::of(&spec).map_err(|e| anyhow::anyhow!("{e}"))?;
    let network = spec.spec.network.as_ref();
    let declared = Declared {
        allow: network.map_or(0, |n| n.allow.len()),
        dns_allow: network.map_or(0, |n| n.dns_allow.len()),
        credentialed: spec.spec.credentialed_egress.len(),
    };
    let (resolver, probe, exfil) = read_console(&read_file(dir, CONSOLE)?)?;
    let host = read_host_effects(&read_file(dir, HOST_EFFECTS)?)?;
    Ok(Census {
        profile,
        declared,
        resolver,
        probe,
        exfil,
        host,
    })
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
    Ok(if read.is_empty() {
        2
    } else if unreadable.is_empty() {
        0
    } else {
        1
    })
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
    let _ = writeln!(
        out,
        "could not measure: DNS queries (no resolver is started without dns_allow, and none logs queries); \
         packets the fence dropped (the chain has no counters or log target in the bundle); \
         the credentialed pod's guest (its console is not in the bundle)"
    );
    if !profiles.contains_key(IsolationProfile::EvalCell.name()) {
        let _ = writeln!(
            out,
            "could not measure: eval cells (no bundle's execution pod is one)"
        );
    }
    out
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
        let report = render(&[], &[]);
        assert!(report.contains("could not measure: DNS queries"));
        assert!(report.contains("could not measure: eval cells"));
    }
}
